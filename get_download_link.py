#!/usr/bin/env python3
"""
BuzzHeavier Download Link Resolver (curl-cffi edition)
Fast, lightweight link resolver and downloader for BuzzHeavier files using TLS fingerprint impersonation.

Anti-Cloudflare design notes (v2):
- Uses the *latest* browser fingerprint via aliases ("chrome") and rotates among
  recently-pinned targets that are validated against the installed curl_cffi version.
- Persists browser sessions (cookies incl. Cloudflare __cf_bm) across attempts and links
  via a thread-local session pool, with a homepage "warm-up" so the first file-page hit
  never looks like a cold, cookieless bot visit.
- Detects Cloudflare challenges reliably: status codes, response HTML markers AND the
  `cf-mitigated: challenge` response header.
- Retries with exponential backoff + jitter; rate-limits (429) get doubled cool-downs.
- Optional HTTP/SOCKS proxy support (--proxy / BH_PROXY env) — recommended when running
  from datacenter IPs such as GitHub Actions runners, which Cloudflare scores poorly.
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
    if cleaned:
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


def make_session(impersonate: str, proxy_url: Optional[str] = None, warm_up: bool = True, timeout: int = 20):
    """Creates an impersonated session, optionally 'warming it up' on the homepage so
    that Cloudflare bot-management cookies (__cf_bm) are already in the jar."""
    session = requests.Session(impersonate=impersonate, proxies=proxies_dict(proxy_url))
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


def reset_thread_session(primary_impersonate: str, proxy_url: Optional[str], timeout: int = 20):
    """Discards the current thread session (e.g. after repeated challenges) and returns a fresh warmed one."""
    _thread_ctx.session = make_session(primary_impersonate, proxy_url=proxy_url, timeout=timeout)
    return _thread_ctx.session


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
        session = reset_thread_session(args.impersonate, proxy_url, timeout=timeout)
    else:
        session = get_thread_session(args.impersonate, proxy_url, timeout=timeout)

    data = resolve_buzzheavier_link(
        file_id,
        impersonate=args.impersonate,
        timeout=timeout,
        max_retries=retries,
        retry_delay=retry_delay,
        session=session,
        proxy_url=proxy_url,
    )
    file_name = data.get('file_name') or line
    file_size = data.get('file_size') or "N/A"
    log(f"    File     : {file_name} ({file_size})")

    byte_info = "-"
    if args.last_byte:
        b = download_last_byte(
            data["direct_cdn_url"],
            impersonate=args.impersonate,
            max_retries=retries,
            retry_delay=retry_delay,
            session=session,
            proxy_url=proxy_url,
        )
        if b:
            val = b[0]
            char_repr = repr(chr(val)) if 32 <= val <= 126 else repr(b)
            byte_info = f"0x{val:02x} ({char_repr})"
            log(f"    Last Byte: {b} (Hex: 0x{val:02x}, Repr: {char_repr}) -> SUCCESS")
        else:
            raise RuntimeError("Failed to fetch last byte from CDN")

    if args.first_byte:
        b = download_first_byte(
            data["direct_cdn_url"],
            impersonate=args.impersonate,
            max_retries=retries,
            retry_delay=retry_delay,
            session=session,
            proxy_url=proxy_url,
        )
        if b:
            val = b[0]
            char_repr = repr(chr(val)) if 32 <= val <= 126 else repr(b)
            byte_info = f"0x{val:02x} ({char_repr})"
            log(f"    First Byte: {b} (Hex: 0x{val:02x}, Repr: {char_repr}) -> SUCCESS")

    if args.download:
        download_file(data["direct_cdn_url"], output_path=args.output, impersonate=args.impersonate,
                      proxy_url=proxy_url, session=session)

    return {
        "idx": idx,
        "link": line,
        "file_id": file_id,
        "name": file_name,
        "size": file_size,
        "byte": byte_info,
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

    # Deduplicate while preserving order
    seen_ids = set()
    unique_lines: List[str] = []
    for line in raw_lines:
        try:
            fid = parse_file_id(line)
        except Exception:
            fid = line
        if fid not in seen_ids:
            seen_ids.add(fid)
            unique_lines.append(line)

    if len(unique_lines) < len(raw_lines):
        print(f"[*] Deduplicated {len(raw_lines)} links -> {len(unique_lines)} unique links (removed {len(raw_lines) - len(unique_lines)} duplicates).")

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

    try:
        data = resolve_buzzheavier_link(
            file_id,
            impersonate=args.impersonate,
            timeout=args.timeout,
            max_retries=args.retries,
            retry_delay=args.retry_delay,
            session=session,
            proxy_url=args.resolved_proxy,
        )
    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"[!] Failed to resolve link: {e}")
        sys.exit(1)

    # If first-byte requested, fetch it
    first_byte_data = None
    if args.first_byte and data.get("direct_cdn_url"):
        b = download_first_byte(
            data["direct_cdn_url"],
            impersonate=args.impersonate,
            max_retries=args.retries,
            retry_delay=args.retry_delay,
            session=session,
            proxy_url=args.resolved_proxy,
        )
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
        b = download_last_byte(
            data["direct_cdn_url"],
            impersonate=args.impersonate,
            max_retries=args.retries,
            retry_delay=args.retry_delay,
            session=session,
            proxy_url=args.resolved_proxy,
        )
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
