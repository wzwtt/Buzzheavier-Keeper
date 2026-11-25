#!/usr/bin/env python3
"""
BuzzHeavier Download Link Resolver (curl-cffi edition)
Fast, lightweight link resolver and downloader for BuzzHeavier files using TLS fingerprint impersonation.

Anti-Cloudflare design notes (v3 — two-tier):
- Tier 1 (fast): curl_cffi with the *latest* browser fingerprint alias ("chrome"),
  a runtime-validated fingerprint rotation list, thread-local warmed sessions and
  classified challenge detection (status codes, HTML markers, cf-mitigated header).
- Tier 2 (fallback): when Cloudflare persists after ~3 fingerprint rotations on a
  datacenter IP, the link is resolved with a stealth browser (patchright — an
  undetected Playwright fork — driving the system Chrome/Edge, no browser download
  needed on GitHub runners). The browser auto-solves the managed challenge; its
  cookies (cf_clearance/__cf_bm) are then injected back into the curl_cffi session so
  the REST of the batch keeps running at curl speed.
- Optional HTTP/SOCKS proxy support (--proxy / BH_PROXY env) as a second remedy for
  datacenter IP scoring.
"""

import sys
import os
import re
import json
import argparse
import io
import time
import random
import threading
import queue
import atexit
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Optional, List, Tuple

# Ensure UTF-8 output across all platforms (especially Windows)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    from curl_cffi import requests
except ImportError:
    print("[!] Error: 'curl_cffi' is required for fast TLS impersonation.")
    print("    Install it using: pip install curl_cffi")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    from patchright.sync_api import sync_playwright as _sync_playwright
    _BROWSER_LIB = "patchright"
except ImportError:
    try:
        from playwright.sync_api import sync_playwright as _sync_playwright
        _BROWSER_LIB = "playwright"
    except ImportError:
        _sync_playwright = None
        _BROWSER_LIB = None


BASE_URL = "https://buzzheavier.com"
WARMUP_URL = "https://buzzheavier.com/"

# ---------------------------------------------------------------------------
# Impersonation target management
# ---------------------------------------------------------------------------

# Preferred rotation order: newest Chromium first (best Cloudflare reputation),
# then a couple of non-Chromium profiles as last-resort identity switches.
PREFERRED_TARGETS = [
    "chrome",        # alias -> always newest Chrome profile shipped with curl_cffi
    "chrome152", "chrome151", "chrome146", "chrome145", "chrome142",
    "chrome136", "chrome133a", "chrome131", "chrome124",
    "safari184", "safari184_ios", "firefox147", "firefox144",
]

_SUPPORTED_TARGETS_CACHE: Optional[set] = None


def get_supported_impersonate_targets() -> Optional[set]:
    """Returns the set of impersonate targets supported by the installed curl_cffi, or None if it cannot be introspected."""
    global _SUPPORTED_TARGETS_CACHE
    if _SUPPORTED_TARGETS_CACHE is not None:
        return _SUPPORTED_TARGETS_CACHE
    targets = None
    try:
        from curl_cffi.requests.impersonate import BrowserTypeLiteral
        import typing
        targets = set(typing.get_args(BrowserTypeLiteral))
    except Exception:
        targets = None
    if not targets:
        try:
            from curl_cffi.consts import BrowserType  # older curl_cffi versions
            targets = set(BrowserType.__members__.keys())
        except Exception:
            targets = None
    _SUPPORTED_TARGETS_CACHE = targets
    return targets


def build_candidate_targets(primary: Optional[str]) -> List[str]:
    """Builds a validated fingerprint rotation list for the installed curl_cffi version."""
    candidates: List[str] = []
    if primary:
        candidates.append(primary)
    for alt in PREFERRED_TARGETS:
        if alt not in candidates:
            candidates.append(alt)

    supported = get_supported_impersonate_targets()
    if supported:
        valid = [t for t in candidates if t in supported]
        # If the requested primary is unsupported, silently fall back to valid ones
        return valid or ["chrome"]

    # Without introspection (very old curl_cffi), keep the list but callers
    # handle per-target failures gracefully.
    return candidates


def parse_file_id(input_val: str) -> str:
    """Extract file ID from raw ID or full BuzzHeavier URL."""
    input_val = input_val.strip()
    match = re.search(r'(?:https?://(?:buzzheavier\.com|bzzhr\.to)/)?([a-zA-Z0-9]{8,16})', input_val)
    if match:
        return match.group(1)
    cleaned = re.sub(r'[^a-zA-Z0-9]', '', input_val)
    # Only accept IDs within the same length window as the URL capture, so junk
    # lines (watermarks, notes, stray text) are rejected instead of being turned
    # into bogus file IDs like "AI".
    if cleaned and 8 <= len(cleaned) <= 16:
        return cleaned
    raise ValueError(f"Could not extract a valid file ID from: {input_val}")


# ---------------------------------------------------------------------------
# Response classification (Cloudflare challenge / rate limit / transient)
# ---------------------------------------------------------------------------

CF_MARKERS = (
    "just a moment...",
    "attention required! | cloudflare",
    "cf-chl-bypass",
    "cf-turnstile",
    "checking your browser before accessing",
    "enable javascript and cookies to continue",
    "ddos protection by cloudflare",
)

TRANSIENT_STATUS = (403, 408, 409, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 525, 527)


def classify_response(resp) -> str:
    """Classifies a response as 'ok' / 'not_found' / 'challenge' / 'rate_limited' / 'transient' / 'other'."""
    status = resp.status_code
    if status in (404, 410):
        return "not_found"

    # Cloudflare explicitly tells us it served a challenge/managed block
    try:
        cf_mitigated = (resp.headers.get("cf-mitigated") or "").lower()
    except Exception:
        cf_mitigated = ""
    if cf_mitigated in ("challenge", "block"):
        return "challenge"

    if status in (403, 429):
        return "rate_limited" if status == 429 else "challenge"

    if status in (500, 502, 503, 504, 520, 521, 522, 523, 524):
        return "transient"

    text = ""
    try:
        text = (resp.text or "")[:8192].lower()
    except Exception:
        pass
    if text and any(marker in text for marker in CF_MARKERS):
        return "challenge"

    if status == 200:
        return "ok"
    if status in (204, 206, 301, 302, 303, 307, 308):
        return "ok"
    if status in TRANSIENT_STATUS:
        return "transient"
    return "other"


def is_cloudflare_challenge(status_code: int, html_text: str, headers: Optional[Dict[str, str]] = None) -> bool:
    """Backwards-compatible challenge check (kept for external callers/tests)."""
    if status_code in (403, 429, 503):
        return True
    if headers and (headers.get("cf-mitigated") or "").lower() in ("challenge", "block"):
        return True
    if not html_text:
        return False
    lower = html_text.lower()
    return any(marker in lower for marker in CF_MARKERS)


# ---------------------------------------------------------------------------
# Session management (thread-local pool + warm-up)
# ---------------------------------------------------------------------------

_thread_ctx = threading.local()

PROXY_ENV_VARS = ("BH_PROXY", "BUZZHEAVIER_PROXY", "PROXY_URL")


def get_proxy_from_env() -> Optional[str]:
    for var in PROXY_ENV_VARS:
        val = os.environ.get(var)
        if val and val.strip():
            return val.strip()
    return None


def proxies_dict(proxy_url: Optional[str]) -> Optional[Dict[str, str]]:
    if not proxy_url:
        return None
    return {"http": proxy_url, "https": proxy_url}


def make_session(impersonate: str, proxy_url: Optional[str] = None, warm_up: bool = True, timeout: int = 20,
                 cookies: Optional[List[Dict[str, Any]]] = None, user_agent: Optional[str] = None):
    """Creates an impersonated session, optionally 'warming it up' on the homepage so
    that Cloudflare bot-management cookies (__cf_bm) are already in the jar.
    `cookies`/`user_agent` (typically harvested from the stealth browser fallback)
    seed the jar with the solved cf_clearance cookie and keep the UA consistent,
    which Cloudflare's clearance validation requires."""
    session = requests.Session(impersonate=impersonate, proxies=proxies_dict(proxy_url))
    if user_agent:
        session.headers.update({"User-Agent": user_agent})
    if cookies:
        for c in cookies:
            try:
                domain = (c.get("domain") or "buzzheavier.com").lstrip(".")
                session.cookies.set(c["name"], c["value"], domain=domain,
                                    path=c.get("path") or "/", secure=bool(c.get("secure")))
            except Exception:
                pass
    if warm_up:
        try:
            session.get(WARMUP_URL, timeout=timeout)
        except Exception:
            pass  # warm-up is best-effort; the real request will still be retried
    return session


def get_thread_session(primary_impersonate: str, proxy_url: Optional[str], timeout: int = 20):
    """Returns a long-lived session for the current worker thread, creating and warming it up on first use."""
    session = getattr(_thread_ctx, "session", None)
    if session is None:
        session = make_session(primary_impersonate, proxy_url=proxy_url, timeout=timeout)
        _thread_ctx.session = session
    return session


def reset_thread_session(primary_impersonate: str, proxy_url: Optional[str], timeout: int = 20,
                         cookies: Optional[List[Dict[str, Any]]] = None, user_agent: Optional[str] = None):
    """Discards the current thread session (e.g. after repeated challenges) and returns a fresh
    warmed one, optionally seeded with cookies harvested from the stealth browser fallback."""
    _thread_ctx.session = make_session(primary_impersonate, proxy_url=proxy_url, timeout=timeout,
                                       warm_up=(cookies is None), cookies=cookies, user_agent=user_agent)
    return _thread_ctx.session


def upgrade_thread_session_with_cookies(args, cookies: List[Dict[str, Any]], user_agent: str):
    """Replaces the current thread's curl_cffi session with one seeded by the stealth browser's
    cookies (cf_clearance / __cf_bm) so subsequent links run on the fast path again."""
    try:
        reset_thread_session(args.impersonate, getattr(args, "resolved_proxy", None),
                             timeout=getattr(args, "timeout", 20), cookies=cookies, user_agent=user_agent)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Stealth browser fallback (patchright / playwright driving system Chrome or Edge)
#
# When Cloudflare keeps challenging the datacenter IP after the fingerprint
# rotation, the link is resolved with a real (stealth-patched) browser which
# auto-solves the managed challenge, then the harvested cookies are injected
# back into curl_cffi for the rest of the batch.
#
# Playwright's sync API is bound to the thread that started it, so the browser
# runs on a dedicated daemon thread and work is submitted via a queue.
# ---------------------------------------------------------------------------

BROWSER_CHANNELS = ("chrome", "msedge")  # system browsers, no download needed
CHALLENGE_TITLE_MARKERS = ("just a moment", "请稍候", "请稍后", "正在验证", "attention required",
                           "checking your browser", "ddos protection")
BROWSER_PROFILE_DIR = os.path.join(".temp", "bh_browser_profile")


def browser_lib_available() -> bool:
    return _BROWSER_LIB is not None


def browser_fallback_enabled(args) -> bool:
    return browser_lib_available() and not getattr(args, "no_browser_fallback", False)


def is_block_error(e: BaseException) -> bool:
    """True if the exception indicates a Cloudflare challenge / rate-limit (not a dead link)."""
    s = str(e).lower()
    return s.startswith("challenge") or s.startswith("rate_limited") or "cloudflare challenge" in s


class BrowserSession:
    """Singleton wrapper around a persistent stealth-browser context running on its own thread."""

    _instance: Optional["BrowserSession"] = None
    _instance_lock = threading.Lock()

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._task_q: "queue.Queue" = queue.Queue()
        self._context = None          # playwright BrowserContext (lives on the browser thread)
        self._playwright = None       # playwright driver (lives on the browser thread)
        self._launch_error: Optional[str] = None
        self._poisoned = False
        self.channel: Optional[str] = None
        self.user_agent: Optional[str] = None
        # Cloudflare's managed challenges do NOT reliably auto-solve in headless mode
        # (verified experimentally); the fallback therefore runs HEADFUL by default.
        # CI needs a virtual display: wrap with `xvfb-run -a` (preinstalled on GitHub runners).
        self.headless = os.environ.get("BH_BROWSER_HEADLESS", "0").lower() in ("1", "true", "yes")
        # Cache of the last solved challenge cookies so OTHER threads/links can reuse
        # them on the curl fast path without re-launching the browser.
        self.last_cookies: Optional[List[Dict[str, Any]]] = None
        self.last_user_agent: Optional[str] = None
        # Channel rotation state (chrome <-> msedge on relaunch)
        self._channel_idx = 0
        self._relaunched_for_challenge = False

    @classmethod
    def get(cls) -> "BrowserSession":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    # ---- task runner ------------------------------------------------------

    def _ensure_thread(self):
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._run_loop, name="bh-browser", daemon=True)
            self._thread.start()

    def _run_loop(self):
        while True:
            fn, result_q = self._task_q.get()
            if fn is None:  # shutdown sentinel
                self._close_all()
                result_q.put(("ok", True))
                return
            try:
                result_q.put(("ok", fn()))
            except Exception as e:  # noqa: BLE001 — propagate to caller
                result_q.put(("err", e))

    def submit(self, fn, timeout: float):
        """Runs fn on the browser thread and returns its result (or raises its exception)."""
        if self._poisoned:
            raise TimeoutError("Browser fallback unavailable after a previous timeout.")
        self._ensure_thread()
        result_q: "queue.Queue" = queue.Queue(maxsize=1)
        self._task_q.put((fn, result_q))
        try:
            status, payload = result_q.get(timeout=timeout)
        except queue.Empty:
            # The job may still hold the browser thread; mark as unusable for this process.
            self._poisoned = True
            raise TimeoutError(f"Browser fallback timed out after {timeout:.0f}s")
        if status == "err":
            raise payload
        return payload

    # ---- browser lifecycle (must be called on the browser thread) --------

    def _ensure_context(self):
        if self._context is not None:
            return self._context
        if self._launch_error:
            raise RuntimeError(f"Browser launch previously failed: {self._launch_error}")
        pw = _sync_playwright().start()
        last_err = None
        ordered = list(BROWSER_CHANNELS[self._channel_idx:]) + list(BROWSER_CHANNELS[:self._channel_idx])
        for channel in ordered:
            try:
                kwargs: Dict[str, Any] = {
                    "user_data_dir": os.path.abspath(BROWSER_PROFILE_DIR),
                    "channel": channel,
                    "headless": self.headless,
                }
                if not self.headless:
                    kwargs["no_viewport"] = True
                ctx = pw.chromium.launch_persistent_context(**kwargs)
                self._playwright, self._context = pw, ctx
                self.channel = channel
                return ctx
            except Exception as e:  # noqa: BLE001 — try next channel
                last_err = e
        self._launch_error = (f"No usable system Chromium browser (tried {list(BROWSER_CHANNELS)}): {last_err}")
        try:
            pw.stop()
        except Exception:
            pass
        raise RuntimeError(self._launch_error)

    def _close_all(self):
        for closer in (lambda: self._context.close(), lambda: self._playwright.stop()):
            try:
                closer()
            except Exception:
                pass
        self._context, self._playwright = None, None

    def restart(self):
        """Must run ON the browser thread: closes the context and rotates to the next
        browser channel, so the next _ensure_context relaunches with a fresh identity."""
        self._close_all()
        self._launch_error = None
        self._channel_idx = (self._channel_idx + 1) % len(BROWSER_CHANNELS)

    # ---- challenge helpers ------------------------------------------------

    @staticmethod
    def _try_click_turnstile(page) -> bool:
        """Best-effort click on the Turnstile checkbox for interactive challenges.
        Cloudflare renders the widget inside nested cross-origin iframes, so every
        frame in the page is scanned (Playwright's frame list is recursive)."""
        try:
            for frame in page.frames:
                fu = frame.url or ""
                if "challenges.cloudflare.com" not in fu:
                    continue
                for sel in ("input[type=checkbox]", "label", "[id^='turnstile']"):
                    try:
                        loc = frame.locator(sel)
                        if loc.count() > 0:
                            loc.first.click(timeout=2000)
                            return True
                    except Exception:
                        continue
        except Exception:
            pass
        # Fallback: click the widget container on the host page (its centre is
        # roughly where the checkbox renders).
        try:
            for sel in (".cf-turnstile", "iframe[src*='challenges.cloudflare.com']"):
                loc = page.locator(sel)
                if loc.count() > 0:
                    loc.first.click(timeout=2000)
                    return True
        except Exception:
            pass
        return False

    def _page_is_challenged(self, page) -> Optional[str]:
        """Returns the challenge-ish page title, or None if the page looks clean."""
        try:
            title = (page.title() or "")
        except Exception:
            return "just a moment"
        if any(m in title.lower() for m in CHALLENGE_TITLE_MARKERS):
            return title
        try:
            content = page.content().lower()
        except Exception:
            content = ""
        if any(m in content for m in CF_MARKERS + ("请稍候", "正在验证")):
            return title or "just a moment"
        return None

    def _wait_challenge_clear(self, page, timeout: float = 45.0) -> bool:
        """Waits until the interstitial goes away. Managed challenges auto-solve;
        interactive ones need the Turnstile checkbox clicked — the widget can render
        seconds AFTER the page load, so the click is retried periodically instead of
        being attempted exactly once at t=0."""
        deadline = time.time() + timeout
        next_click_at = time.time() + 1.0   # give the widget a moment to render first
        clicks = 0
        while time.time() < deadline:
            if self._page_is_challenged(page) is None:
                return True
            if time.time() >= next_click_at and clicks < 12:
                if self._try_click_turnstile(page):
                    clicks += 1
                    next_click_at = time.time() + 2.5  # let the widget verify
                else:
                    next_click_at = time.time() + 1.5
            time.sleep(0.7)
        return False


def _shutdown_browser():
    try:
        bs = BrowserSession._instance
        if bs and bs._thread and bs._thread.is_alive():
            result_q: "queue.Queue" = queue.Queue(maxsize=1)
            bs._task_q.put((None, result_q))
            try:
                result_q.get(timeout=5)
            except Exception:
                pass
    except Exception:
        pass


atexit.register(_shutdown_browser)


def _browser_resolve_job(bs: "BrowserSession", file_id: str, timeout_s: float) -> Tuple[Dict[str, Any], List[Dict[str, Any]], str]:
    """Runs ON the browser thread: opens the file page, waits out any Cloudflare
    challenge, and resolves the token + CDN URL with an in-page fetch (so the request
    carries the real browser fingerprint and cookies; the Node-side HTTP client is
    NOT good enough — verified experimentally, it gets 403'd). Returns (result, cookies, UA).

    Robustness: up to two navigation attempts (fresh page each time); after a cleared
    challenge, one reload if the htmx button has not appeared yet; waiting is sliced so
    the overall budget stays below the caller's submit() timeout (exceeding it would
    poison the whole browser session for the process)."""
    ctx = bs._ensure_context()
    page_url = f"{BASE_URL}/{file_id}"
    btn_re = re.compile(r'<a[^>]*hx-get=["\']([^"\']*download[^"\']*)["\'][^>]*>(.*?)</a>', re.DOTALL | re.IGNORECASE)

    html = ""
    hx_m = None
    last_title = ""
    nav_deadline = time.time() + max(20.0, timeout_s - 10.0)
    page = None
    won = False

    try:
        for nav in range(2):
            page = ctx.new_page()
            nav_status = None
            try:
                resp = page.goto(page_url, timeout=max(5000, int((timeout_s - 10) * 1000)))
                nav_status = resp.status if resp else None
            except Exception:
                # Navigation failure: discard this page (fresh page on the next attempt)
                try:
                    page.close()
                except Exception:
                    pass
                page = None
                continue

            reloaded = False
            cleared_since = None
            while time.time() < nav_deadline:
                remaining = nav_deadline - time.time()
                if not bs._wait_challenge_clear(page, timeout=min(10.0, max(2.0, remaining))):
                    last_title = bs._page_is_challenged(page) or (page.title() or "")
                    continue  # keep waiting in slices until the overall deadline
                if cleared_since is None:
                    cleared_since = time.time()
                # A dead link stays dead: bail immediately instead of polling a 404
                # page (which can never grow a download button) until the deadline.
                if nav_status in (404, 410):
                    raise RuntimeError(
                        f"File not found (HTTP {nav_status}). File ID '{file_id}' may be invalid or deleted."
                    )
                try:
                    html = page.content()
                except Exception:
                    html = ""
                hx_m = btn_re.search(html)
                if hx_m:
                    won = True
                    break
                # Dead-document detection: after challenge clearance a 404 page has
                # no download button and never will; the initial goto status was 403
                # (the challenge itself), so recognise it by the page title instead.
                try:
                    page_title = (page.title() or "").strip().lower()
                except Exception:
                    page_title = ""
                if page_title in ("404", "not found", "404 not found", "error 404", "file not found"):
                    raise RuntimeError(
                        f"File not found (404 page). File ID '{file_id}' may be invalid or deleted."
                    )
                # Challenge cleared but no button yet: one reload after a grace period
                if not reloaded and time.time() - cleared_since > 4.0:
                    reloaded = True
                    try:
                        page.reload(timeout=max(5000, int((timeout_s - 10) * 1000)))
                    except Exception:
                        pass
                    continue
                time.sleep(0.6)

            if won:
                break
            # this page lost: close it before trying a fresh navigation
            try:
                page.close()
            except Exception:
                pass
            page = None
            if nav == 0 and time.time() >= nav_deadline:
                break

        if not won or page is None:
            raise RuntimeError(
                "Cloudflare challenge did not auto-clear in the stealth browser "
                f"(title={last_title[:60]!r}, channel={bs.channel})."
            )

        cookies = ctx.cookies()
        ua = page.evaluate("navigator.userAgent")
        bs.user_agent = ua

        result: Dict[str, Any] = {
            "file_id": file_id,
            "page_url": page_url,
            "file_name": None,
            "file_size": None,
            "token_link": None,
            "token": None,
            "direct_cdn_url": None,
            "fingerprint": f"browser:{bs.channel}",
        }

        title_m = re.search(r"<title>([^<]+)</title>", html, re.IGNORECASE)
        if title_m:
            t = title_m.group(1).strip()
            if t not in ("Buzzheavier", "Just a moment...", "buzzheavier.com"):
                result["file_name"] = t
        hx_get = hx_m.group(1)
        btn_text = hx_m.group(2)

        size_m = re.search(r"([0-9.]+\s*(?:B|KB|MB|GB|TB))", btn_text, re.IGNORECASE)
        if size_m:
            result["file_size"] = size_m.group(1).strip()

        token_link = f"{BASE_URL}{hx_get}" if hx_get.startswith("/") else hx_get
        result["token_link"] = token_link
        token_m = re.search(r"[?&]t=([^&]+)", hx_get)
        if token_m:
            result["token"] = token_m.group(1)

        # Simulate the htmx click with an in-page same-origin fetch (real browser TLS + cookies).
        # Reading the custom hx-redirect response header is allowed for same-origin requests.
        fetch_out = page.evaluate(
            """async (u) => {
                try {
                    const r = await fetch(u, {headers: {'HX-Request': 'true'}});
                    const cd = r.headers.get('content-disposition') || '';
                    return {status: r.status,
                            hxRedirect: r.headers.get('hx-redirect'),
                            location: r.headers.get('location'),
                            contentDisposition: cd};
                } catch (err) {
                    return {status: 0, error: String(err)};
                }
            }""",
            token_link,
        )
        if (fetch_out or {}).get("status") in (403, 429, 503):
            raise RuntimeError(f"challenge during browser token step (HTTP {fetch_out['status']})")
        direct = (fetch_out or {}).get("hxRedirect") or (fetch_out or {}).get("location")
        if not _looks_like_cdn(direct):
            raise RuntimeError("No direct CDN redirect found (browser path).")
        result["direct_cdn_url"] = direct

        if not result["file_name"]:
            cd = (fetch_out or {}).get("contentDisposition", "")
            cd_m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd)
            if cd_m:
                result["file_name"] = cd_m.group(1).strip()
        return result, cookies, ua
    finally:
        if page is not None:
            try:
                page.close()
            except Exception:
                pass


def try_cached_cookie_fast_path(file_id: str, args) -> Optional[Dict[str, Any]]:
    """If the stealth browser has already solved a challenge earlier in this run,
    reuse its cached cookies on a curl_cffi session before spinning the browser up again."""
    bs = BrowserSession.get()
    cookies, ua = bs.last_cookies, bs.last_user_agent
    if not cookies or not ua:
        return None
    try:
        session = make_session(args.impersonate, proxy_url=getattr(args, "resolved_proxy", None),
                               warm_up=False, cookies=cookies, user_agent=ua)
        return resolve_buzzheavier_link(
            file_id,
            impersonate=args.impersonate,
            timeout=getattr(args, "timeout", 20),
            max_retries=0,
            retry_delay=getattr(args, "retry_delay", 2.0),
            session=session,
            proxy_url=getattr(args, "resolved_proxy", None),
        )
    except Exception:
        return None


def attempt_browser_fallback(file_id: str, args, want_last_byte: bool, want_first_byte: bool) -> Dict[str, Any]:
    """Resolves one link via the stealth browser and injects the harvested cookies into
    the calling thread's curl_cffi session so later links run on the fast path again.

    If the challenge does not clear with the current browser channel, the session is
    restarted ONCE on the other channel (chrome <-> msedge) before giving up — the
    second browser identity solves challenges the first one could not."""
    bs = BrowserSession.get()
    timeout = float(getattr(args, "browser_timeout", 120))

    def job():
        return _browser_resolve_job(bs, file_id, timeout)

    try:
        result, cookies, ua = bs.submit(job, timeout=timeout + 30)
    except RuntimeError as e:
        if "did not auto-clear" not in str(e) or bs._relaunched_for_challenge or len(BROWSER_CHANNELS) < 2:
            raise
        # Rotate to the other system browser and try once more with a fresh identity.
        bs._relaunched_for_challenge = True
        print(f"    [*] Challenge stuck on channel={bs.channel}; restarting the browser on the alternate channel...")
        bs.submit(lambda: bs.restart(), timeout=30)
        result, cookies, ua = bs.submit(job, timeout=timeout + 30)
        bs._relaunched_for_challenge = False

    # Persist the challenge-solving cookies for the remainder of the batch
    # (other threads may reuse them via try_cached_cookie_fast_path too).
    bs.last_cookies, bs.last_user_agent = cookies, ua
    upgrade_thread_session_with_cookies(args, cookies, ua)
    print(f"    [*] Browser fallback resolved the link (channel={bs.channel}, UA={ua.split(')')[0][:40]}...); "
          f"challenge cookies injected into the fast-path session.")
    return result


def browser_ping_byte(url: str, args, last: bool = True) -> bytes:
    """Keep-alive byte ping via a curl_cffi session seeded with the stealth browser's
    challenge cookies. If no cookies are cached yet, the browser first visits the
    homepage to solve a challenge (the Node-side HTTP client gets 403'd, so the
    ping itself must run through curl_cffi with the transferred cookies)."""
    bs = BrowserSession.get()
    timeout = float(getattr(args, "browser_timeout", 120))
    proxy_url = getattr(args, "resolved_proxy", None)

    if not (bs.last_cookies and bs.last_user_agent):
        def warm_job():
            ctx = bs._ensure_context()
            page = ctx.new_page()
            try:
                page.goto(WARMUP_URL, timeout=max(5000, int((timeout - 10) * 1000)))
                bs._wait_challenge_clear(page, timeout=max(5.0, timeout - 10.0))
                return ctx.cookies(), page.evaluate("navigator.userAgent")
            finally:
                try:
                    page.close()
                except Exception:
                    pass

        cookies, ua = bs.submit(warm_job, timeout=timeout + 30)
        bs.last_cookies, bs.last_user_agent = cookies, ua
        upgrade_thread_session_with_cookies(args, cookies, ua)

    session = make_session(args.impersonate, proxy_url=proxy_url, warm_up=False,
                           cookies=bs.last_cookies, user_agent=bs.last_user_agent)
    if last:
        return download_last_byte(url, impersonate=args.impersonate, max_retries=1,
                                  retry_delay=0.5, session=session, proxy_url=proxy_url)
    return download_first_byte(url, impersonate=args.impersonate, max_retries=1,
                               retry_delay=0.5, session=session, proxy_url=proxy_url)


# ---------------------------------------------------------------------------
# Link resolution
# ---------------------------------------------------------------------------

XHR_HEADERS = {
    "HX-Request": "true",
    "Referer": BASE_URL,
    "HX-Current-URL": BASE_URL,
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}

CDN_URL_RE = re.compile(r'^https?://[a-z0-9.-]*buzzheavier\.com/.+', re.IGNORECASE)


def _looks_like_cdn(url: str) -> bool:
    return bool(url) and bool(CDN_URL_RE.match(url)) and ("/d/" in url or "download" in url)


def backoff_seconds(attempt: int, base: float, kind: str) -> float:
    """Exponential backoff with jitter; rate-limits (429) get a doubled cool-down."""
    wait = base * (2 ** max(0, attempt - 1))
    if kind == "rate_limited":
        wait *= 2
    wait = min(wait, 60.0)
    return wait + random.uniform(0.5, 1.5)


def resolve_buzzheavier_link(
    file_id: str,
    impersonate: Optional[str] = "chrome",
    timeout: int = 20,
    max_retries: int = 3,
    retry_delay: float = 2.0,
    session: Optional[Any] = None,
    proxy_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Resolves the BuzzHeavier download link and direct CDN stream URL using curl_cffi.

    Strategy:
      - Reuse the caller's (warm) session on the first attempt.
      - On failures, rotate to the next supported browser fingerprint on a FRESH
        warmed session (clean cookies, clean TLS identity).
      - Follow htmx responses (hx-get chains) until an HX-Redirect to the CDN is found.
    """
    page_url = f"{BASE_URL}/{file_id}"
    result = {
        "file_id": file_id,
        "page_url": page_url,
        "file_name": None,
        "file_size": None,
        "token_link": None,
        "token": None,
        "direct_cdn_url": None,
        "fingerprint": None,
    }

    candidate_targets = build_candidate_targets(impersonate)
    last_error = None

    for attempt in range(max_retries + 1):
        target = candidate_targets[attempt % len(candidate_targets)]

        if attempt > 0:
            kind = "rate_limited" if (last_error or "").startswith("rate_limited") else "challenge"
            wait_time = backoff_seconds(attempt, retry_delay, kind)
            print(f"    [*] Cloudflare challenge or transient issue detected. Retrying in {wait_time:.1f}s (attempt {attempt}/{max_retries}) using impersonate='{target}'...")
            time.sleep(wait_time)

        # Attempt 0 reuses the caller's warm session; later attempts start fresh
        # with the rotated fingerprint so we get a new TLS identity and cookie jar.
        if attempt == 0 and session is not None:
            current_session = session
        else:
            current_session = make_session(target, proxy_url=proxy_url, timeout=timeout)
            # Remember a successful session so it can become the new thread session
            setattr(current_session, "_bh_target", target)
        result["fingerprint"] = target

        # ---------------------------------------------------------------
        # 1. Fetch the file landing page
        # ---------------------------------------------------------------
        try:
            r = current_session.get(page_url, timeout=timeout)
        except Exception as e:
            last_error = f"Request error: {e}"
            continue

        page_class = classify_response(r)
        if page_class == "not_found":
            raise RuntimeError(f"File not found (404). File ID '{file_id}' may be invalid or deleted.")
        if page_class in ("challenge", "rate_limited", "transient"):
            last_error = f"{'rate_limited' if page_class == 'rate_limited' else 'challenge'} on landing page (HTTP {r.status_code})"
            continue
        if r.status_code != 200:
            last_error = f"Unexpected HTTP {r.status_code} from landing page."
            continue

        html = r.text

        # ---------------------------------------------------------------
        # 2. Parse title and locate the htmx download endpoint
        # ---------------------------------------------------------------
        if BeautifulSoup:
            soup = BeautifulSoup(html, "html.parser")
            if soup.title and soup.title.string:
                t = soup.title.string.strip()
                if t not in ("Buzzheavier", "Just a moment...", "buzzheavier.com"):
                    result["file_name"] = t
            btn = soup.find("a", attrs={"hx-get": re.compile(r"download")})
            hx_get = btn.get("hx-get") if btn else None
            btn_text = btn.get_text() if btn else ""
        else:
            title_m = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
            if title_m:
                result["file_name"] = title_m.group(1).strip()
            btn_m = re.search(r'<a[^>]*hx-get=["\']([^"\']*download[^"\']*)["\'][^>]*>(.*?)</a>', html, re.DOTALL | re.IGNORECASE)
            if btn_m:
                hx_get = btn_m.group(1)
                btn_text = btn_m.group(2)
            else:
                hx_get = None
                btn_text = ""

        if not hx_get:
            page_class_retry = classify_response(r)
            if page_class_retry in ("challenge", "rate_limited", "transient"):
                last_error = f"{'rate_limited' if page_class_retry == 'rate_limited' else 'challenge'} on landing page (HTTP {r.status_code})"
            else:
                last_error = "Could not find download link on page. File might be protected or removed."
            continue

        size_m = re.search(r'([0-9.]+\s*(?:B|KB|MB|GB|TB))', btn_text, re.IGNORECASE)
        if size_m:
            result["file_size"] = size_m.group(1).strip()

        token_link = f"{BASE_URL}{hx_get}" if hx_get.startswith("/") else hx_get
        result["token_link"] = token_link
        token_m = re.search(r'[?&]t=([^&]+)', hx_get)
        if token_m:
            result["token"] = token_m.group(1)

        # ---------------------------------------------------------------
        # 3. Simulate the htmx click; follow hx-get chains until HX-Redirect
        # ---------------------------------------------------------------
        htmx_headers = dict(XHR_HEADERS)
        htmx_headers["Referer"] = page_url
        htmx_headers["HX-Current-URL"] = page_url

        current_url = token_link
        direct_cdn = None
        htmx_failed_class = None

        for hop in range(4):
            try:
                r_htmx = current_session.get(current_url, headers=htmx_headers, allow_redirects=False, timeout=timeout)
            except Exception as e:
                htmx_failed_class = "transient"
                last_error = f"HTMX redirect request error: {e}"
                break

            htmx_class = classify_response(r_htmx)
            if htmx_class in ("challenge", "rate_limited", "transient"):
                htmx_failed_class = htmx_class
                last_error = f"{'rate_limited' if htmx_class == 'rate_limited' else 'challenge'} during token redirect (HTTP {r_htmx.status_code})"
                break
            if htmx_class == "not_found":
                htmx_failed_class = "not_found"
                last_error = f"Download endpoint returned HTTP {r_htmx.status_code} (token may have expired)."
                break

            # A redirect to the CDN endpoint is the final answer
            hx_redirect = r_htmx.headers.get("hx-redirect")
            location = r_htmx.headers.get("location")

            for candidate_url in (hx_redirect, location):
                if candidate_url and _looks_like_cdn(candidate_url):
                    direct_cdn = candidate_url
                    break

            if direct_cdn:
                break

            # A same-origin redirect / nested hx-get means we must click again
            next_url = None
            if r_htmx.status_code in (301, 302, 303, 307, 308) and location:
                next_url = location if location.startswith("http") else f"{BASE_URL}{location}"
            elif hx_redirect and hx_redirect.startswith("/"):
                next_url = f"{BASE_URL}{hx_redirect}"

            if not next_url:
                frag_m = re.search(r'hx-get=["\']([^"\']+download[^"\']*)["\']', r_htmx.text or "", re.IGNORECASE)
                if frag_m:
                    next_url = frag_m.group(1) if frag_m.group(1).startswith("http") else f"{BASE_URL}{frag_m.group(1)}"

            if next_url and next_url != current_url:
                current_url = next_url
                continue

            htmx_failed_class = "other"
            last_error = "HTMX response contained no direct CDN redirect."
            break

        if direct_cdn:
            result["direct_cdn_url"] = direct_cdn
            # Verify file name from Content-Disposition if not found yet
            if not result["file_name"]:
                try:
                    head_resp = current_session.head(direct_cdn, timeout=timeout)
                    cd = head_resp.headers.get("content-disposition", "")
                    cd_m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd)
                    if cd_m:
                        result["file_name"] = cd_m.group(1).strip()
                except Exception:
                    pass
            # Persist the winning session for reuse by the next link in this thread
            if hasattr(current_session, "_bh_target"):
                _thread_ctx.session = current_session
            return result

        if htmx_failed_class == "not_found":
            # Token may have expired; retrying the whole flow regenerates it
            last_error = "Download endpoint returned 404 (token may have expired)."
            continue
        if htmx_failed_class is None:
            last_error = last_error or "Could not obtain direct CDN URL."
        continue

    raise RuntimeError(last_error or "Cloudflare challenge encountered. Please retry or verify the link.")


def download_first_byte(url: str, impersonate: str = "chrome", max_retries: int = 2,
                        retry_delay: float = 1.5, session: Optional[Any] = None,
                        proxy_url: Optional[str] = None) -> bytes:
    """Downloads and returns the first 1 byte from the direct CDN URL with retry."""
    for attempt in range(max_retries + 1):
        if attempt > 0:
            time.sleep(retry_delay * attempt + random.uniform(0.2, 0.5))
        current = session if (attempt == 0 and session is not None) else make_session(
            impersonate, proxy_url=proxy_url, warm_up=(attempt > 0))
        try:
            # stream=True + explicit close: if the server ignores the Range header
            # and answers 200 with the full body, we avoid downloading it all.
            resp = current.get(url, headers={"Range": "bytes=0-0"}, stream=True, timeout=15)
            cls = classify_response(resp)
            if cls == "ok" and resp.status_code in (200, 206):
                for chunk in resp.iter_content(chunk_size=8):
                    if chunk:
                        return chunk[:1]
                    break
                resp.close()
                if resp.status_code == 206:
                    return b""  # empty 206 body: nothing to inspect
                continue
            if cls == "not_found":
                resp.close()
                return b""
            resp.close()

            # Fallback: stream and grab the first byte
            r = current.get(url, stream=True, timeout=15)
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=1):
                if chunk:
                    r.close()
                    return chunk[:1]
            r.close()
        except Exception:
            continue
    return b""


def download_last_byte(url: str, impersonate: str = "chrome", max_retries: int = 2,
                       retry_delay: float = 1.5, session: Optional[Any] = None,
                       proxy_url: Optional[str] = None) -> bytes:
    """Downloads and returns the last 1 byte from the direct CDN URL with retry."""
    for attempt in range(max_retries + 1):
        if attempt > 0:
            time.sleep(retry_delay * attempt + random.uniform(0.2, 0.5))
        current = session if (attempt == 0 and session is not None) else make_session(
            impersonate, proxy_url=proxy_url, warm_up=(attempt > 0))
        try:
            # HTTP Range suffix request: bytes=-1 requests the last 1 byte.
            # stream=True + explicit close protects against servers that ignore
            # the Range header and return the full body.
            resp = current.get(url, headers={"Range": "bytes=-1"}, stream=True, timeout=15)
            cls = classify_response(resp)
            if cls == "ok" and resp.status_code in (200, 206):
                content = bytearray()
                for chunk in resp.iter_content(chunk_size=65536):
                    if chunk:
                        content.extend(chunk)
                        if len(content) > 1:
                            break  # got enough bytes; abort the transfer
                resp.close()
                if resp.status_code == 206:
                    return bytes(content[-1:]) if content else b""
                if content:
                    # Server ignored Range (200, full body): we only buffered the
                    # first chunk, which is NOT the last byte -> try exact offset.
                    pass
                else:
                    continue
            elif cls == "not_found":
                resp.close()
                return b""
            else:
                resp.close()

            # Fallback: query Content-Length and request exact last byte offset
            head = current.head(url, timeout=15)
            total_size = int(head.headers.get("content-length", 0))
            if total_size > 0:
                resp = current.get(url, headers={"Range": f"bytes={total_size - 1}-{total_size - 1}"}, stream=True, timeout=15)
                if resp.status_code in (200, 206):
                    data = b""
                    for chunk in resp.iter_content(chunk_size=8):
                        if chunk:
                            data = chunk
                            break
                    resp.close()
                    if data:
                        return data[-1:]
                resp.close()
        except Exception:
            continue
    return b""


def download_file(url: str, output_path: Optional[str] = None, impersonate: str = "chrome",
                  proxy_url: Optional[str] = None, session: Optional[Any] = None):
    """Downloads the file from the direct CDN URL with progress display."""
    current = session or make_session(impersonate, proxy_url=proxy_url, warm_up=False)
    print("[*] Starting download from CDN...")
    r = current.get(url, stream=True)
    r.raise_for_status()
    if not output_path:
        cd = r.headers.get("content-disposition", "")
        cd_m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd)
        if cd_m:
            output_path = cd_m.group(1).strip()
        else:
            output_path = "downloaded_file"

    total_size = int(r.headers.get("content-length", 0))
    downloaded = 0
    first_byte_logged = False
    print(f"[*] Saving to: {output_path}")
    with open(output_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=65536):
            if chunk:
                if not first_byte_logged:
                    first_b = chunk[:1]
                    val = first_b[0]
                    char_repr = repr(chr(val)) if 32 <= val <= 126 else repr(first_b)
                    print(f"[*] First 1 byte received: {first_b} (Hex: 0x{val:02x}, Dec: {val}, Repr: {char_repr})")
                    first_byte_logged = True
                f.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    percent = (downloaded / total_size) * 100
                    print(f"\r    Progress: {downloaded}/{total_size} bytes ({percent:.1f}%)", end="", flush=True)
                else:
                    print(f"\r    Downloaded: {downloaded} bytes", end="", flush=True)
    print("\n[+] Download complete!")


def parse_shard_spec(spec: Optional[str]) -> Tuple[int, int]:
    """Parses shard specification string in format 'X/Y' (e.g. '1/5') or returns (1, 1)."""
    if not spec:
        return 1, 1
    m = re.match(r"^(\d+)[/:](\d+)$", spec.strip())
    if not m:
        raise ValueError(f"Invalid shard format: '{spec}'. Expected format 'X/Y' (e.g. '1/5').")
    shard_idx = int(m.group(1))
    total_shards = int(m.group(2))
    if total_shards < 1:
        raise ValueError(f"Total shards must be >= 1, got {total_shards}.")
    if shard_idx < 1 or shard_idx > total_shards:
        raise ValueError(f"Shard index {shard_idx} out of bounds for total shards {total_shards} (must be 1..{total_shards}).")
    return shard_idx, total_shards


def process_single_item(idx: int, total: int, line: str, args, log_lock: Optional[threading.Lock] = None,
                        fresh_session: bool = False) -> Dict[str, Any]:
    """Processes a single link/ID with full resolution, byte pings, and downloads."""
    file_id = parse_file_id(line)
    retries = getattr(args, "retries", 10)
    retry_delay = getattr(args, "retry_delay", 2.0)
    proxy_url = getattr(args, "resolved_proxy", None)
    timeout = getattr(args, "timeout", 20)

    def log(msg: str):
        if log_lock:
            with log_lock:
                print(msg)
        else:
            print(msg)

    if fresh_session:
        # Prefer re-seeding with the browser's challenge cookies (if any were solved
        # earlier in this run) over a completely fresh identity.
        bs = BrowserSession.get()
        if browser_fallback_enabled(args) and bs.last_cookies and bs.last_user_agent:
            session = reset_thread_session(args.impersonate, proxy_url, timeout=timeout,
                                            cookies=bs.last_cookies, user_agent=bs.last_user_agent)
        else:
            session = reset_thread_session(args.impersonate, proxy_url, timeout=timeout)
    else:
        session = get_thread_session(args.impersonate, proxy_url, timeout=timeout)

    browser_ready = browser_fallback_enabled(args)
    method = "curl"

    if getattr(args, "browser_only", False) and browser_ready:
        log("    [*] --browser-only: resolving directly via stealth browser...")
        data = attempt_browser_fallback(file_id, args, bool(args.last_byte), bool(args.first_byte))
        method = "browser"
        session = get_thread_session(args.impersonate, proxy_url, timeout=timeout)
    else:
        # Fast path. With the browser fallback available we fail fast into it
        # instead of burning through the whole fingerprint rotation (all-403).
        fast_retries = min(retries, 2) if browser_ready else retries
        try:
            data = resolve_buzzheavier_link(
                file_id,
                impersonate=args.impersonate,
                timeout=timeout,
                max_retries=fast_retries,
                retry_delay=retry_delay,
                session=session,
                proxy_url=proxy_url,
            )
        except RuntimeError as e:
            if browser_ready and is_block_error(e):
                # If the browser already solved a challenge earlier in this run, retry
                # the fast path with its cached cookies before spinning it up again.
                cached = try_cached_cookie_fast_path(file_id, args)
                if cached is not None:
                    data = cached
                    method = "browser-cookies"
                    log("    [*] Recovered with cached challenge cookies (no browser relaunch needed).")
                    session = get_thread_session(args.impersonate, proxy_url, timeout=timeout)
                else:
                    log("    [*] Persistent Cloudflare challenge. Falling back to stealth browser (" + _BROWSER_LIB + ")...")
                    data = attempt_browser_fallback(file_id, args, bool(args.last_byte), bool(args.first_byte))
                    method = "browser"
                    # The thread session was upgraded with challenge cookies; refresh handle.
                    session = get_thread_session(args.impersonate, proxy_url, timeout=timeout)
            else:
                raise

    # Internal byte values possibly produced by the browser fallback
    browser_last = data.pop("_last_byte", None) if isinstance(data, dict) else None
    browser_first = data.pop("_first_byte", None) if isinstance(data, dict) else None

    file_name = data.get('file_name') or line
    file_size = data.get('file_size') or "N/A"
    log(f"    File     : {file_name} ({file_size})")

    byte_info = "-"
    if args.last_byte:
        b = browser_last
        if b is None:
            b = download_last_byte(
                data["direct_cdn_url"],
                impersonate=args.impersonate,
                max_retries=retries,
                retry_delay=retry_delay,
                session=session,
                proxy_url=proxy_url,
            )
        if not b and browser_ready:
            log("    [*] Byte ping failed on fast path; retrying via stealth browser...")
            b = browser_ping_byte(data["direct_cdn_url"], args, last=True)
        if b:
            val = b[0]
            char_repr = repr(chr(val)) if 32 <= val <= 126 else repr(b)
            byte_info = f"0x{val:02x} ({char_repr})"
            log(f"    Last Byte: {b} (Hex: 0x{val:02x}, Repr: {char_repr}) -> SUCCESS")
        else:
            raise RuntimeError("Failed to fetch last byte from CDN")

    if args.first_byte:
        b = browser_first
        if b is None:
            b = download_first_byte(
                data["direct_cdn_url"],
                impersonate=args.impersonate,
                max_retries=retries,
                retry_delay=retry_delay,
                session=session,
                proxy_url=proxy_url,
            )
        if not b and browser_ready:
            b = browser_ping_byte(data["direct_cdn_url"], args, last=False)
        if b:
            val = b[0]
            char_repr = repr(chr(val)) if 32 <= val <= 126 else repr(b)
            byte_info = f"0x{val:02x} ({char_repr})"
            log(f"    First Byte: {b} (Hex: 0x{val:02x}, Repr: {char_repr}) -> SUCCESS")

    if args.download:
        if method == "browser":
            log("    [*] Direct CDN URL resolved via browser; use it with your download manager:")
            log(f"        {data['direct_cdn_url']}")
        else:
            download_file(data["direct_cdn_url"], output_path=args.output, impersonate=args.impersonate,
                          proxy_url=proxy_url, session=session)

    return {
        "idx": idx,
        "link": line,
        "file_id": file_id,
        "name": file_name,
        "size": file_size,
        "byte": byte_info,
        "method": method,
        "status": "✅ OK",
        "success": True,
        "error": None,
    }


def process_batch(file_path: str, args):
    """Processes a list of links/IDs from a file with deduplication, sharding, pacing, and recovery retry pass."""
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    with open(file_path, "r", encoding="utf-8") as f:
        raw_lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not raw_lines:
        print(f"[!] No valid links found in {file_path}")
        return

    # Deduplicate while preserving order; skip non-link junk lines (notes,
    # watermarks, stray text) instead of turning them into bogus file IDs.
    seen_ids = set()
    unique_lines: List[str] = []
    skipped_invalid = 0
    for line in raw_lines:
        try:
            fid = parse_file_id(line)
        except Exception:
            print(f"[!] Skipping invalid line (not a BuzzHeavier link/ID): {line[:60]}")
            skipped_invalid += 1
            continue
        if fid not in seen_ids:
            seen_ids.add(fid)
            unique_lines.append(line)

    if skipped_invalid:
        print(f"[!] {skipped_invalid} invalid line(s) skipped.")
    if not unique_lines:
        print("[!] No valid links found after filtering.")
        return
    if len(unique_lines) < len(raw_lines) - skipped_invalid:
        print(f"[*] Deduplicated {len(raw_lines) - skipped_invalid} link lines -> {len(unique_lines)} unique links (removed {len(raw_lines) - skipped_invalid - len(unique_lines)} duplicates).")

    # Shard partitioning
    shard_str = getattr(args, "shard", None)
    shard_idx, total_shards = parse_shard_spec(shard_str)

    # Assign items via round-robin modulo: orig_idx (1-indexed)
    shard_items: List[Tuple[int, str]] = [
        (orig_idx, line)
        for orig_idx, line in enumerate(unique_lines, 1)
        if (orig_idx - 1) % total_shards == (shard_idx - 1)
    ]

    workers = max(1, getattr(args, "workers", 1))
    pace_delay = getattr(args, "delay", 1.0)
    retries = getattr(args, "retries", 3)
    retry_delay = getattr(args, "retry_delay", 2.0)

    print("=" * 60)
    if total_shards > 1:
        print(f"  BATCH PROCESSING (SHARD {shard_idx}/{total_shards}): {len(shard_items)} of {len(unique_lines)} LINK(S)")
    else:
        print(f"  BATCH PROCESSING: {len(shard_items)} LINK(S)")
    print(f"  Pacing: {pace_delay}s delay | Workers: {workers} | Retries: {retries} | Retry Backoff: {retry_delay}s")
    print(f"  Fingerprint: {args.impersonate} (rotation list: {', '.join(build_candidate_targets(args.impersonate))})")
    if browser_fallback_enabled(args):
        print(f"  Browser fallback: enabled via {_BROWSER_LIB} (channel auto: {'/'.join(BROWSER_CHANNELS)})")
    else:
        print(f"  Browser fallback: disabled or unavailable ({'not installed' if not browser_lib_available() else 'flag'})")
    if getattr(args, "resolved_proxy", None):
        print(f"  Proxy: configured ({len(args.resolved_proxy)} chars, value hidden)")
    print("=" * 60)

    results: Dict[int, Dict[str, Any]] = {}
    failed_items: List[Tuple[int, str]] = []
    log_lock = threading.Lock()

    def log(msg: str):
        with log_lock:
            print(msg)

    # Pass 1: Process items
    if workers > 1:
        def worker_task(sub_idx: int, orig_idx: int, line: str):
            jitter = random.uniform(0.1, 0.5)
            time.sleep(jitter)
            log(f"\n[{sub_idx}/{len(shard_items)}] (Link #{orig_idx}) Target: {line}")
            try:
                res = process_single_item(orig_idx, len(unique_lines), line, args, log_lock=log_lock)
                return orig_idx, res, None
            except Exception as e:
                log(f"    [FAIL] Error: {e}")
                err_dict = {
                    "idx": orig_idx,
                    "link": line,
                    "file_id": parse_file_id(line) if 'buzzheavier' in line or len(line) <= 16 else line,
                    "name": line,
                    "size": "N/A",
                    "byte": "-",
                    "status": f"❌ {e}",
                    "success": False,
                    "error": str(e),
                }
                return orig_idx, err_dict, (orig_idx, line)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(worker_task, sub_idx, orig_idx, line)
                for sub_idx, (orig_idx, line) in enumerate(shard_items, 1)
            ]
            for future in as_completed(futures):
                orig_idx, res, fail_entry = future.result()
                results[orig_idx] = res
                if fail_entry:
                    failed_items.append(fail_entry)
    else:
        # Sequential processing
        for sub_idx, (orig_idx, line) in enumerate(shard_items, 1):
            if sub_idx > 1 and pace_delay > 0:
                jitter = random.uniform(-0.2, 0.3)
                time.sleep(max(0.1, pace_delay + jitter))

            print(f"\n[{sub_idx}/{len(shard_items)}] (Link #{orig_idx}) Target: {line}")
            try:
                res = process_single_item(orig_idx, len(unique_lines), line, args)
                results[orig_idx] = res
            except Exception as e:
                print(f"    [FAIL] Error: {e}")
                results[orig_idx] = {
                    "idx": orig_idx,
                    "link": line,
                    "file_id": parse_file_id(line) if 'buzzheavier' in line or len(line) <= 16 else line,
                    "name": line,
                    "size": "N/A",
                    "byte": "-",
                    "status": f"❌ {e}",
                    "success": False,
                    "error": str(e),
                }
                failed_items.append((orig_idx, line))

    # Pass 2: Automatic retry pass for failed links (fresh session identity)
    no_retry_pass = getattr(args, "no_retry_pass", False)
    if failed_items and not no_retry_pass:
        print("\n" + "=" * 60)
        print(f"  RETRY PASS: Re-attempting {len(failed_items)} failed link(s) after 5s cool-down (fresh session)...")
        print("=" * 60)
        time.sleep(5.0)

        recovered_count = 0
        still_failed: List[Tuple[int, str]] = []
        for orig_idx, line in failed_items:
            if pace_delay > 0:
                jitter = random.uniform(-0.2, 0.3)
                time.sleep(max(0.1, pace_delay + jitter))

            print(f"\n[Retry Pass: Link #{orig_idx}] Target: {line}")
            try:
                res = process_single_item(orig_idx, len(unique_lines), line, args, fresh_session=True)
                results[orig_idx] = res
                recovered_count += 1
                print("    -> [RECOVERED] Successfully resolved on retry pass!")
            except Exception as e:
                print(f"    -> [FAIL] Still failed on retry pass: {e}")
                results[orig_idx]["status"] = f"❌ {e}"
                results[orig_idx]["error"] = str(e)
                still_failed.append((orig_idx, line))

        failed_items = still_failed
        print(f"\n[*] Retry pass finished: {recovered_count} recovered, {len(failed_items)} remaining failed.")

    report_rows = [results[k] for k in sorted(results.keys())]
    succeeded = sum(1 for r in report_rows if r.get("success", False))
    failed = len(report_rows) - succeeded
    success_rate = (succeeded / len(report_rows) * 100.0) if report_rows else 0.0

    print("\n" + "=" * 60)
    shard_label = f"SHARD {shard_idx}/{total_shards} " if total_shards > 1 else ""
    print(f"  {shard_label}BATCH SUMMARY: {succeeded}/{len(shard_items)} succeeded ({success_rate:.1f}%), {failed} failed.")
    print("=" * 60)

    # Export JSON if requested
    output_json = getattr(args, "output_json", None)
    if output_json:
        out_dir = os.path.dirname(output_json)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        summary_payload = {
            "shard_index": shard_idx,
            "total_shards": total_shards,
            "total_unique_links": len(unique_lines),
            "shard_items_count": len(shard_items),
            "succeeded": succeeded,
            "failed": failed,
            "success_rate": round(success_rate, 2),
            "items": report_rows,
            "failed_items": [r for r in report_rows if not r.get("success", False)]
        }
        with open(output_json, "w", encoding="utf-8") as jf:
            json.dump(summary_payload, jf, indent=2, ensure_ascii=False)
        print(f"[+] Exported results to JSON: {output_json}")

    # Export failed items file if requested
    failed_file = getattr(args, "failed_file", None)
    if failed_file:
        out_dir = os.path.dirname(failed_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        failed_rows = [r for r in report_rows if not r.get("success", False)]
        with open(failed_file, "w", encoding="utf-8") as ff:
            for fr in failed_rows:
                ff.write(f"{fr['link']}  # {fr.get('status', 'Failed')}\n")
        if failed_rows:
            print(f"[+] Written {len(failed_rows)} failed link(s) to: {failed_file}")

    # Write summary to GitHub Actions if running in CI
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        try:
            with open(summary_file, "a", encoding="utf-8") as sf:
                title_suffix = f" — Shard {shard_idx}/{total_shards}" if total_shards > 1 else ""
                sf.write(f"### 🐝 BuzzHeavier Keep-Alive Report{title_suffix}\n\n")
                sf.write("| Metric | Value |\n")
                sf.write("|---|---|\n")
                sf.write(f"| **Assigned Links** | {len(shard_items)} |\n")
                sf.write(f"| **✅ Succeeded** | {succeeded} |\n")
                sf.write(f"| **❌ Failed / Dead** | {failed} |\n")
                sf.write(f"| **📈 Success Rate** | {success_rate:.1f}% |\n\n")

                failed_list = [r for r in report_rows if not r.get("success", False)]
                if failed_list:
                    sf.write("#### ⚠️ Dead / Failed Links\n\n")
                    sf.write("| # | Link | Error Reason |\n")
                    sf.write("|---|------|--------------|\n")
                    for fl in failed_list:
                        sf.write(f"| {fl['idx']} | {fl['link']} | {fl['status']} |\n")
                    sf.write("\n")

                success_list = [r for r in report_rows if r.get("success", False)]
                if success_list:
                    sf.write(f"<details><summary><b>📁 View Active Links ({len(success_list)})</b></summary>\n\n")
                    sf.write("| # | File Name | Size | Last Byte | Status |\n")
                    sf.write("|---|-----------|------|-----------|--------|\n")
                    for sl in success_list:
                        sf.write(f"| {sl['idx']} | {sl['name']} | {sl['size']} | `{sl['byte']}` | {sl['status']} |\n")
                    sf.write("\n</details>\n\n")
        except Exception as e:
            print(f"[!] Warning: Unable to write to GITHUB_STEP_SUMMARY: {e}")

    # Exit code determination
    soft_fail = getattr(args, "soft_fail", False)
    max_fail_rate = getattr(args, "max_fail_rate", None)
    if failed > 0:
        if soft_fail:
            print(f"[!] Notice: {failed} link(s) failed or dead. Workflow continuing due to --soft-fail.")
        elif max_fail_rate is not None and (failed / len(shard_items)) <= max_fail_rate:
            print(f"[!] Notice: Failure rate {(failed / len(shard_items)):.1%} is within allowable threshold ({max_fail_rate:.1%}). Continuing.")
        else:
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="BuzzHeavier Download Link Resolver using curl-cffi (fast & lightweight)."
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="BuzzHeavier file URL, file ID, or links file (e.g. yebbjo1kfx3b or links.txt)"
    )
    parser.add_argument(
        "-f", "--file",
        help="Path to text file containing links or IDs (one per line)"
    )
    parser.add_argument(
        "-b", "--first-byte",
        action="store_true",
        help="Download and print the first 1 byte from the file"
    )
    parser.add_argument(
        "-l", "--last-byte",
        action="store_true",
        help="Download and print the last 1 byte from the file"
    )
    parser.add_argument(
        "-d", "--download",
        action="store_true",
        help="Directly download the file after resolving the link"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output filename when downloading"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )
    parser.add_argument(
        "--impersonate",
        default="chrome",
        help="Browser TLS fingerprint to impersonate (default: 'chrome' = newest profile; rotated automatically on retries)"
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Max retries per link upon Cloudflare challenges or transient errors (default: 3)"
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=2.0,
        help="Base delay in seconds for exponential backoff on retries (default: 2.0)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay in seconds between successive links in batch mode to prevent rate limiting (default: 1.0)"
    )
    parser.add_argument(
        "--proxy",
        default=None,
        help="HTTP/SOCKS proxy URL for all requests (also via env BH_PROXY). Recommended on datacenter IPs like GitHub Actions."
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="Request timeout in seconds (default: 20)"
    )
    parser.add_argument(
        "--no-retry-pass",
        action="store_true",
        help="Disable automatic secondary retry pass for failed links in batch mode"
    )
    parser.add_argument(
        "--shard",
        help="Shard specification in format 'X/Y' (e.g. '1/5' for runner 1 of 5)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of concurrent worker threads per runner (default: 1)"
    )
    parser.add_argument(
        "--output-json",
        help="Path to export batch check results as JSON"
    )
    parser.add_argument(
        "--failed-file",
        help="Path to write failed/dead links for pruning"
    )
    parser.add_argument(
        "--soft-fail",
        action="store_true",
        help="Do not return exit code 1 if dead or failed links are encountered"
    )
    parser.add_argument(
        "--max-fail-rate",
        type=float,
        default=None,
        help="Maximum failure rate (0.0 - 1.0) allowed before exiting with code 1"
    )
    parser.add_argument(
        "--no-browser-fallback",
        action="store_true",
        help="Disable the stealth browser fallback (curl_cffi fast path only)"
    )
    parser.add_argument(
        "--browser-only",
        action="store_true",
        help="Resolve directly via the stealth browser (skips the curl_cffi fast path)"
    )
    parser.add_argument(
        "--browser-timeout",
        type=int,
        default=120,
        help="Overall timeout in seconds for one stealth-browser fallback attempt (default: 120)"
    )

    args = parser.parse_args()

    # Resolve proxy: CLI flag overrides environment variable
    args.resolved_proxy = args.proxy or get_proxy_from_env()

    # Check if batch mode via --file or positional file path
    batch_file = args.file
    if not batch_file and args.input and os.path.isfile(args.input):
        batch_file = args.input

    if batch_file:
        process_batch(batch_file, args)
        return

    target_input = args.input
    if not target_input:
        target_input = input("Enter BuzzHeavier file link or file ID: ").strip()

    if not target_input:
        print("[!] Error: No input provided.")
        sys.exit(1)

    try:
        file_id = parse_file_id(target_input)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    if not args.json:
        print(f"[*] Target File ID: {file_id}")
        print(f"[*] Resolving via curl-cffi (impersonating {args.impersonate})...")

    session = get_thread_session(args.impersonate, args.resolved_proxy, timeout=args.timeout)
    browser_ready = browser_fallback_enabled(args)

    if args.browser_only and browser_ready:
        print("[*] --browser-only: resolving directly via stealth browser...")
        try:
            data = attempt_browser_fallback(file_id, args, bool(args.last_byte), bool(args.first_byte))
        except Exception as e:
            if args.json:
                print(json.dumps({"error": str(e)}))
            else:
                print(f"[!] Failed to resolve link: {e}")
            sys.exit(1)
        session = get_thread_session(args.impersonate, args.resolved_proxy, timeout=args.timeout)
    else:
        fast_retries = min(args.retries, 2) if browser_ready else args.retries
        try:
            data = resolve_buzzheavier_link(
                file_id,
                impersonate=args.impersonate,
                timeout=args.timeout,
                max_retries=fast_retries,
                retry_delay=args.retry_delay,
                session=session,
                proxy_url=args.resolved_proxy,
            )
        except Exception as e:
            if browser_ready and is_block_error(e):
                cached = try_cached_cookie_fast_path(file_id, args)
                if cached is not None:
                    data = cached
                    print("[*] Recovered with cached challenge cookies (no browser relaunch needed).")
                else:
                    print("[*] Persistent Cloudflare challenge. Falling back to stealth browser (" + _BROWSER_LIB + ")...")
                    try:
                        data = attempt_browser_fallback(file_id, args, bool(args.last_byte), bool(args.first_byte))
                    except Exception as e2:
                        if args.json:
                            print(json.dumps({"error": str(e2)}))
                        else:
                            print(f"[!] Failed to resolve link: {e2}")
                        sys.exit(1)
                # The thread session may have been upgraded with challenge cookies.
                session = get_thread_session(args.impersonate, args.resolved_proxy, timeout=args.timeout)
            else:
                if args.json:
                    print(json.dumps({"error": str(e)}))
                else:
                    print(f"[!] Failed to resolve link: {e}")
                sys.exit(1)

    browser_last = data.pop("_last_byte", None) if isinstance(data, dict) else None
    browser_first = data.pop("_first_byte", None) if isinstance(data, dict) else None

    # If first-byte requested, fetch it
    first_byte_data = None
    if args.first_byte and data.get("direct_cdn_url"):
        b = browser_first
        if b is None:
            b = download_first_byte(
                data["direct_cdn_url"],
                impersonate=args.impersonate,
                max_retries=args.retries,
                retry_delay=args.retry_delay,
                session=session,
                proxy_url=args.resolved_proxy,
            )
        if not b and browser_ready:
            b = browser_ping_byte(data["direct_cdn_url"], args, last=False)
        if b:
            val = b[0]
            char_repr = repr(chr(val)) if 32 <= val <= 126 else repr(b)
            first_byte_data = {
                "raw": str(b),
                "hex": f"0x{val:02x}",
                "decimal": val,
                "binary": bin(val),
                "repr": char_repr
            }
            data["first_byte"] = first_byte_data

    # If last-byte requested, fetch it
    last_byte_data = None
    if args.last_byte and data.get("direct_cdn_url"):
        b = browser_last
        if b is None:
            b = download_last_byte(
                data["direct_cdn_url"],
                impersonate=args.impersonate,
                max_retries=args.retries,
                retry_delay=args.retry_delay,
                session=session,
                proxy_url=args.resolved_proxy,
            )
        if not b and browser_ready:
            b = browser_ping_byte(data["direct_cdn_url"], args, last=True)
        if b:
            val = b[0]
            char_repr = repr(chr(val)) if 32 <= val <= 126 else repr(b)
            last_byte_data = {
                "raw": str(b),
                "hex": f"0x{val:02x}",
                "decimal": val,
                "binary": bin(val),
                "repr": char_repr
            }
            data["last_byte"] = last_byte_data

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print("\n" + "=" * 55)
        print("          BUZZHEAVIER DOWNLOAD DETAILS           ")
        print("=" * 55)
        if data["file_name"]:
            print(f"  File Name   : {data['file_name']}")
        if data["file_size"]:
            print(f"  File Size   : {data['file_size']}")
        print(f"  File Page   : {data['page_url']}")
        print(f"  Token (t=)  : {data['token']}")
        print("-" * 55)
        print("  Tokenized Link (t=):")
        print(f"  {data['token_link']}")
        print("-" * 55)
        if data["direct_cdn_url"]:
            print("  Direct CDN Stream URL (Ready for download):")
            print(f"  {data['direct_cdn_url']}")
        print("=" * 55)

    if args.first_byte and first_byte_data:
        print("\n" + "=" * 55)
        print("            FIRST 1 BYTE DOWNLOADED              ")
        print("=" * 55)
        print(f"  Raw Byte : {first_byte_data['raw']}")
        print(f"  Hex      : {first_byte_data['hex']}")
        print(f"  Decimal  : {first_byte_data['decimal']}")
        print(f"  Binary   : {first_byte_data['binary']}")
        print(f"  Repr     : {first_byte_data['repr']}")
        print("=" * 55)

    if args.last_byte and last_byte_data:
        print("\n" + "=" * 55)
        print("             LAST 1 BYTE DOWNLOADED              ")
        print("=" * 55)
        print(f"  Raw Byte : {last_byte_data['raw']}")
        print(f"  Hex      : {last_byte_data['hex']}")
        print(f"  Decimal  : {last_byte_data['decimal']}")
        print(f"  Binary   : {last_byte_data['binary']}")
        print(f"  Repr     : {last_byte_data['repr']}")
        print("=" * 55)

    if args.download and data["direct_cdn_url"]:
        download_file(data["direct_cdn_url"], output_path=args.output, impersonate=args.impersonate,
                      proxy_url=args.resolved_proxy, session=session)


if __name__ == "__main__":
    main()
