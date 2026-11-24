# BuzzHeavier Keeper & Link Resolver 🐝

A fast, lightweight Python tool and automated GitHub Action to resolve direct download links, extract CDN endpoints, and keep BuzzHeavier files active without consuming excessive bandwidth.

---

## ⚡ Features

- **🚀 Ultra-Fast Resolution:** Uses `curl-cffi` with browser TLS fingerprint impersonation (always the newest `chrome` profile, e.g. Chrome 152) to bypass Cloudflare protection in ~1 second without running heavy headless browsers.
- **🎭 Stealth-Browser Fallback (the big one):** When Cloudflare keeps challenging after ~2 fingerprint rotations (typical for datacenter IPs like GitHub Actions runners), the link is automatically resolved with **[patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright)** — an undetected Playwright fork — driving the **system Chrome/Edge** (preinstalled on GitHub runners, zero browser download). The browser auto-solves the managed challenge; the resulting `cf_clearance` cookie + matching User-Agent are then **injected into the curl_cffi session**, so the rest of the batch keeps running at curl speed (verified: the transferred cookie carries the whole fast path incl. cross-origin CDN Range pings). If no challenge appears, the browser never launches.
- **🔄 Resilient Retry & Anti-Blocking Logic:** Detects Cloudflare challenges via status codes, HTML markers **and the `cf-mitigated: challenge` response header**, then retries with exponential backoff + jitter (doubled cool-down on HTTP 429). Each retry switches to a **fresh warmed session** with a **different, validated browser fingerprint** (`chrome` → `chrome152` → `chrome151` → `chrome146` → … targets are checked against the installed `curl_cffi` version at runtime, so no more crashes on unsupported fingerprints).
- **🔥 Session Warm-Up & Reuse:** Worker threads keep a long-lived, cookie-carrying session (including Cloudflare's `__cf_bm` bot-management cookie) and hit the homepage first, so file-page requests never look like cold, cookieless bot visits. Failed items are retried in a second pass re-seeded with the solved challenge cookies.
- **🧦 Optional Proxy Support:** Route all requests through an HTTP/SOCKS proxy (`--proxy` flag or `BH_PROXY` env / `PROXY_URL` secret). Strongly recommended when running from datacenter IPs (e.g. GitHub Actions runners), which Cloudflare scores badly.
- **⏱️ Smart Batch Pacing & Recovery Pass:** Introduces configurable pacing delay between links (default `1.0s`) to prevent triggering rate limits on large batches (100+ links), plus an automatic secondary retry pass for any links that experienced temporary hiccups.
- **🛡️ Bandwidth-Friendly Keep-Alive:** Uses HTTP Range requests (`Range: bytes=-1`) to download only the **last 1 byte** of large files (e.g. 15GB+ files) to ping the CDN and keep links alive with virtually zero bandwidth usage.
- **🔗 Dual Link Extraction:**
  - **Tokenized Link:** `https://buzzheavier.com/<id>/download?t=...` (HMAC-SHA256 signed URL).
  - **Direct CDN Stream URL:** `https://ts.buzzheavier.com/d/<id>?v=...` (High-speed direct stream URL for tools like `curl`, `aria2`, `IDM`).
- **📋 Batch Processing:** Process multiple links from a text file (`links.txt`).
- **🤖 Automated GitHub Action:** Daily scheduled workflow that automatically checks every link in `links.txt` and logs results to GitHub Actions Step Summary.
- **🔍 Byte Inspection:** Verify stream health by downloading and inspecting the first 1 byte (`-b`), last 1 byte (`-l`), or full file (`-d`).


---

## 📦 Installation

Ensure you have Python 3.10+ installed:

```bash
git clone https://github.com/AnCry1596/Buzzheavier-Keeper.git
cd Buzzheavier-Keeper
pip install -r requirements.txt
```

---

## 💻 Usage

### 1. Resolve Single Link or File ID
```bash
python get_download_link.py yebbjo1kfx3b
# or with full URL
python get_download_link.py https://buzzheavier.com/yebbjo1kfx3b
```

### 2. Download Only the Last 1 Byte (`-l`)
Ping the CDN and download just the last 1 byte of the file:
```bash
python get_download_link.py yebbjo1kfx3b -l
```

### 3. Download Only the First 1 Byte (`-b`)
Inspect the first byte (e.g., file header or UTF-8 BOM):
```bash
python get_download_link.py yebbjo1kfx3b -b
```

### 4. Download Both First and Last Byte
```bash
python get_download_link.py yebbjo1kfx3b -b -l
```

### 5. Download Full File (`-d`)
Stream the entire file to disk with a progress display:
```bash
python get_download_link.py yebbjo1kfx3b -d
```

### 6. Batch Keep-Alive (`links.txt`)
Ping the last byte of every link listed in `links.txt`:
```bash
python get_download_link.py links.txt -l
```

#### Advanced Batch & Scaling Options:
| Flag | Default | Description |
|---|---|---|
| `--delay <seconds>` | `1.0` | Pacing delay between batch links to prevent Cloudflare rate limits |
| `--proxy <url>` | env `BH_PROXY` | HTTP/SOCKS proxy URL used for all requests (e.g. `http://user:pass@host:port` or `socks5://host:port`) |
| `--timeout <seconds>` | `20` | Request timeout per HTTP call |
| `--no-browser-fallback` | off | Disable the stealth browser fallback (curl_cffi fast path only) |
| `--browser-only` | off | Resolve directly via the stealth browser (skips the curl_cffi fast path) |
| `--browser-timeout <seconds>` | `120` | Overall timeout for one stealth-browser fallback attempt |
| `--shard <X/Y>` | `1/1` | Run shard `X` out of `Y` total shards (e.g. `1/5` for runner 1 of 5) |
| `--workers <count>` | `1` | Number of concurrent worker threads within each runner |
| `--retries <count>` | `3` | Max retries per link upon Cloudflare challenges or network hiccups |
| `--retry-delay <seconds>` | `2.0` | Base delay for exponential backoff on retries |
| `--output-json <path>` | `None` | Export structured check results to a JSON file |
| `--failed-file <path>` | `None` | Export list of failed/dead links (404/expired) for pruning |
| `--soft-fail` | `false` | Return exit code 0 even if dead or failed links are encountered |
| `--max-fail-rate <0.0-1.0>` | `None` | Maximum failure rate allowed before returning exit code 1 |
| `--no-retry-pass` | `false` | Disable automatic secondary retry pass for failed items |

Example with sharding and rate limit tuning:
```bash
# Check shard 1 of 5 runners with soft-fail and JSON output
python get_download_link.py links.txt -l --shard 1/5 --delay 1.0 --output-json shard_1.json --soft-fail
```


### 7. Output as JSON (`--json`)
For integration into automated scripts:
```bash
python get_download_link.py yebbjo1kfx3b --json
```

---

## ⚙️ Automated GitHub Action (Large-Scale Daily Keep-Alive)

The repository includes a distributed GitHub Actions workflow in [`.github/workflows/daily_check.yml`](.github/workflows/daily_check.yml) optimized for large collections of links (800 to 5,000+ links).

### 🚀 Architecture Highlights:
- **⚡ Parallel Matrix Sharding (5x–10x Speedup):** Automatically partitions `links.txt` across **5 parallel runner jobs** (configurable from 1 to 10 via manual trigger).
- **🌐 Distributed Multi-IP Requests:** Each GitHub Action runner executes on an independent VM with a distinct public IP address, eliminating Cloudflare rate limits and IP blocking.
- **🎭 Stealth-Browser Fallback on every shard:** Persistent challenges are auto-solved with patchright + the runner's preinstalled Chrome under `xvfb-run` (Cloudflare managed challenges do not reliably auto-solve headless — verified experimentally), then solved cookies carry the rest of the shard at curl speed.
- **🎲 Randomized Start Jitter:** Each shard sleeps a random 0–90s before starting so the runner fleet doesn't hit Cloudflare as a synchronized burst from adjacent Azure IP ranges.
- **🧵 Non-Overlapping Runs:** A concurrency group prevents schedule/push/manual runs from stacking up.
- **🛡️ Soft-Fail & Dead Link Isolation:** Dead/expired links (HTTP 404) are isolated into a downloadable `dead-links-report` workflow artifact instead of crashing the entire keep-alive workflow.
- **📊 Consolidated Step Summary:** A final reporting job aggregates all shard outputs and publishes an overview dashboard with success rates, failed link tables, and collapsible sections.

### 🧦 Beating Cloudflare on GitHub-Hosted Runners

GitHub runner IPs belong to a few well-known Azure datacenter ranges that Cloudflare scores poorly, so challenges can still appear even with perfect TLS fingerprints. This repo now handles them end-to-end:

1. **First line — fingerprints & session hygiene** (built-in, always on): newest `chrome` alias, warmed cookie-carrying sessions, classified retry with backoff.
2. **Second line — stealth-browser fallback** (built-in, automatic): after ~2 failed rotations the shard switches to patchright + system Chrome under `xvfb-run`, auto-solves the managed challenge, and transfers `cf_clearance` + UA back to curl_cffi so subsequent links stay fast.
3. **Optional third line — residential proxy:** if the browser fallback is still not enough for your workload, add a cheap residential/ISP proxy: **Settings → Secrets and variables → Actions → New repository secret**, name it `PROXY_URL`, value e.g. `http://user:pass@proxy.example.com:8080`. Traffic is only a few KB per link per run, so a single static plan is plenty.

### How It Works:
1. Add your file links to `links.txt` (one link per line):
   ```text
   https://buzzheavier.com/1z8c4seiafor
   https://buzzheavier.com/yebbjo1kfx3b
   ```
2. Commit and push your changes to GitHub.
3. The workflow runs **every day at 03:00 UTC** (and on every push to `links.txt`).
4. You can also trigger it manually from the **Actions** tab with custom shard counts (1, 3, 5, 8, 10), delay, worker threads, and soft-fail settings.
5. Review the run dashboard and download `dead_links.txt` to remove expired files as needed.

---

## ⚠️ Disclaimers

> [!IMPORTANT]
> **Please read this disclaimer carefully before using this software.**

1. **Educational & Personal Use Only:**
   This project is developed solely for educational, research, and personal file management purposes. It demonstrates HTTP protocol range requests, TLS fingerprinting, and automated workflow integrations.

2. **No Affiliation:**
   This project is an independent open-source tool and is **not** affiliated, associated, authorized, endorsed by, or in any way officially connected with BuzzHeavier (`buzzheavier.com`), its parent company, or any of its subsidiaries.

3. **Fair Use & Bandwidth Consideration:**
   This tool is intentionally designed to minimize server load and bandwidth consumption by utilizing standard HTTP Range requests (`bytes=-1` / 1 byte) rather than repeatedly downloading complete files. Users are advised to respect reasonable request rates and avoid abusive flooding.

4. **Terms of Service & Compliance:**
   Users are solely responsible for ensuring that their use of this software complies with the Terms of Service of the respective hosting platform and all applicable local, national, and international laws.

5. **No Warranty / Limitation of Liability:**
   This software is provided "as is", without warranty of any kind, express or implied. The author(s) and contributor(s) shall not be held liable for any claims, damages, account suspensions, or other liabilities arising from the use or misuse of this codebase.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

> AI生成
