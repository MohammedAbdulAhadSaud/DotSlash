# DotSlash../

A professional-grade path traversal and local file inclusion (LFI) scanner written in Python 3, built for bug bounty hunting and authorized penetration testing. Designed to integrate into recon pipelines via stdin piping, with concurrent multi-host support and structured reporting.

> **Important:** This tool is for authorized use only. Only run against targets you own or have explicit written permission to test — such as assets listed in-scope under a published bug bounty or VDP program. Unauthorized scanning is illegal under the CFAA, Computer Misuse Act, and equivalent laws worldwide.

---

## Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Payload Classes](#payload-classes)
- [CVE Coverage](#cve-coverage)
- [Detection Engine](#detection-engine)
- [Output and Reports](#output-and-reports)
- [Bug Bounty Usage Guide](#bug-bounty-usage-guide)
- [Examples](#examples)
- [Limitations](#limitations)
- [Legal Disclaimer](#legal-disclaimer)

---

## Overview

PathScan automates the discovery and verification of path traversal vulnerabilities across all common injection surfaces. It crawls target applications to discover parameters automatically (solving the core problem where most scanners miss endpoints unless you manually specify them), then fuzzes each parameter with a library of 5,061 unique payload vectors across 13 classified attack categories.

The tool was built to reduce manual enumeration work during bug bounty hunting, particularly for finding file-read primitives that are commonly under-reported because they require knowing obscure encoding bypasses or specific CVE-targeted paths.

---

## Features

**Input modes**
- Single URL via `-u`
- Bulk URL list via `-l`
- Stdin piping — chains directly with `gau`, `katana`, `httpx`, `waybackurls`

**Automatic discovery**
- HTML crawler with BFS traversal — follows links, parses forms, extracts parameters
- JavaScript endpoint extraction — scrapes `fetch()`, `axios` calls, and quoted API paths
- OpenAPI/Swagger spec import via `--openapi`
- Force-append mode — tests common file parameter names on URLs with no existing query string

**Injection surfaces**
- Query string parameters
- POST body (form-encoded and JSON)
- Route parameters (`{id}`, `{filename}` style)
- HTTP headers (`X-File-Path`, `X-Original-URL`, `X-Rewrite-URL`, etc.)
- Cookies
- Multipart file upload fields
- Referer header

**Detection**
- Tier-1 fast byte matching — checks raw response bytes before running any regex
- Tier-2 secret extraction — triggered only after a Tier-1 hit; extracts AWS keys, JWT tokens, GitHub tokens, DB credentials, private keys, and more
- Error oracle — detects verbose filesystem errors logged as potential path disclosure
- Blind timing oracle — flags responses exceeding 4.5 seconds as LOW confidence signals
- Baseline diffing — detects structural content anomalies when oracle matching fails

**Infrastructure**
- Per-domain exponential backoff with WAF detection (Cloudflare, Akamai, Imperva, ModSecurity, F5, Fortinet, Sucuri, Fastly, Barracuda)
- Randomized User-Agent per request from a 16-agent pool
- Anti-WAF stealth headers injected on every request (`X-Forwarded-For`, `X-Real-IP`, etc.)
- Domain-distributed thread scheduling — round-robins across hosts to avoid hammering one target
- Resume/checkpoint support via `--checkpoint`
- Burp Suite proxy integration via `--proxy`

**Reports**
- JSON (machine-readable, CI/CD compatible)
- Markdown (submission-ready for HackerOne/Bugcrowd)
- HTML (self-contained dark-mode report with collapsible findings and copy-ready PoC blocks)

---

## Installation

**Requirements:** Python 3.8+

```bash
git clone https://github.com/yourname/pathscan.git
cd pathscan
pip install requests beautifulsoup4
```

`beautifulsoup4` is optional but recommended — without it the crawler falls back to regex-based HTML parsing.

---

## Usage

```
python3 pathscan_final.py [options] --i-have-authorization
```

### Arguments

| Flag | Description |
|---|---|
| `-u URL` | Single target URL |
| `-l FILE` | File with one URL per line |
| `--force-append` | Test common file params on URLs with no query string |
| `--cookies STR` | Cookie string: `"session=abc; token=xyz"` |
| `--auth STR` | Authorization header value: `"Bearer TOKEN"` |
| `--headers JSON` | Extra headers as JSON: `'{"X-Api-Key":"abc"}'` |
| `--proxy URL` | HTTP proxy: `http://127.0.0.1:8080` |
| `-t N` | Thread pool size (default: 20) |
| `--rps N` | Global requests-per-second cap (default: unlimited) |
| `--max-pages N` | Crawler page limit (default: 80) |
| `--openapi FILE` | OpenAPI/Swagger JSON spec |
| `--checkpoint FILE` | Save/resume progress |
| `--blind-timing` | Enable timing oracle (>4.5s = LOW confidence hit) |
| `--skip-crawl` | Fuzz only the provided URLs, no crawling |
| `--skip-cve` | Skip CVE-specific probes |
| `--cve-only` | Run only CVE probes, skip generic fuzzing |
| `-o FILE` | Output file — format auto-detected from extension (`.json`/`.md`/`.html`) |
| `--out-json FILE` | JSON report path |
| `--out-md FILE` | Markdown report path |
| `--out-html FILE` | HTML report path |
| `--i-have-authorization` | Required flag confirming authorization |

---

## Payload Classes

PathScan generates 5,061 unique payload vectors across 13 classified categories.

| Class | Count | Description |
|---|---|---|
| 1 | 54 | Standard relative traversal (`../../../etc/passwd`) |
| 2 | 18 | Windows cross-compatible (`..\..\windows\win.ini`) |
| 3 | 30 | Absolute path override (`/etc/passwd`, `file:///etc/passwd`) |
| 4 | 20 | Non-recursive strip bypass (`....//....//etc/passwd`) |
| 5 | 13 | Split dot injection (`..././..././etc/passwd`) |
| 6 | 12 | Multi-layer deep nesting (depths 12–30 + path truncation) |
| 7 | 64 | Single URL encoding + IIS `%u` Unicode + full-width chars |
| 8 | 25 | Double URL encoding (`%252e%252e%252f`) |
| 9 | 20 | Overlong UTF-8 (`..%c0%af`, `..%c1%9c`, `..%e0%80%af`) |
| 10 | 66 | Null byte injection (`../../../etc/passwd%00.jpg`) |
| A | 337 | Arbitrary file read targets: `.env`, `wp-config.php`, `.git/config`, PHP wrappers, K8s tokens, cloud credentials |
| B-2 | 130 | Extension enforcement bypass (null byte + extension, extension-only) |
| 11 | 4272 | Start-of-path prefix bypass — static (33 common base paths) + dynamic auto-detection from original parameter value |

**Class 11 explained:** Some applications validate that a file path starts with a known directory (e.g. `/var/www/images/`) before using it. Class 11 satisfies that prefix check, then traverses out — e.g. `/var/www/images/../../../etc/passwd`. When the scanner detects an original parameter value that is an absolute path (like `filename=/var/www/images/1.jpg`), it extracts the base directory and generates tailored bypass payloads dynamically, covering base paths not in the static list.

---

## CVE Coverage

The scanner includes 15+ CVE-specific probe sets with verified detection logic per vulnerability. Each probe uses the exact path patterns and verification functions known to work for that CVE.

| CVE | Product | Description |
|---|---|---|
| CVE-2024-21626 | runc | Container escape via `/proc/self/cwd` traversal |
| CVE-2021-41773 | Apache 2.4.49 | URL-encoded path traversal via CGI |
| CVE-2021-42013 | Apache 2.4.50 | Double-encoded bypass (incomplete 41773 patch) |
| CVE-2024-38475 | Apache mod_rewrite / SonicWall SMA100 | URL mapping bypass enabling session DB exfiltration |
| CVE-2020-3452 | Cisco ASA / Firepower | Unauthorized file read via `+CSCOE+` endpoints |
| CVE-2019-19781 | Citrix ADC / NetScaler | Directory traversal targeting `smb.conf` |
| CVE-2024-27199 | JetBrains TeamCity | Auth bypass via `/../res/` path traversal |
| CVE-2023-28432 | MinIO | Information disclosure — exposes `MINIO_SECRET_KEY` |
| CVE-2024-38819 | Spring Framework | WebMvc.fn / WebFlux.fn static resource traversal |
| CVE-2025-41242 | Spring MVC | Path traversal on non-compliant servlet containers |
| CVE-2025-64446 | Fortinet FortiWeb | Auth bypass + traversal via `/api/v2.0/` |
| CVE-2018-13379 | Fortinet FortiGate | SSL VPN session file read |
| CVE-2025-30208 | Vite dev server | Arbitrary file read via `@fs` alias bypass |
| CVE-2024-10811 / 13159 | Ivanti EPM | Absolute path traversal, CVSS 9.8 |
| CVE-2023-32235 | Ghost CMS | Traversal via `/assets/built/../../` |
| NGINX-ALIAS | Nginx | Off-by-slash alias misconfiguration (ubiquitous) |
| IIS-TILDE-ENUM | IIS | 8.3 short filename enumeration |

---

## Detection Engine

**Tier 1 — Byte matching (fast)**

Before running any regex, the scanner checks raw response bytes for known file signatures:

```
b"root:x:0:0:"          # /etc/passwd
b"[fonts]"              # windows/win.ini
b"AWS_ACCESS_KEY_ID="   # .env / credentials
b"-----BEGIN RSA PRIVATE KEY-----"
b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"  # K8s JWT
```

A Tier-1 match triggers a finding immediately without further processing.

**Tier 2 — Secret extraction (only after Tier-1 hit)**

Runs 22 regex patterns to extract actionable credentials from confirmed responses:

- AWS access keys and secret keys
- GitHub tokens (`ghp_`, `ghs_`, `gho_`)
- JWT tokens
- Stripe live/test keys
- Slack tokens
- SendGrid API keys
- Database connection strings (MySQL, PostgreSQL, MongoDB, Redis)
- Private key blocks (RSA, EC, OpenSSH, DSA)
- SSH authorized keys
- Azure and GCP credentials
- Generic password and secret key patterns

**Error oracle**

Separately monitors for 30+ verbose error signatures (`java.io.FileNotFoundException`, `ENOENT`, `Warning: file_get_contents(`, etc.) and logs them as potential path disclosure, even when no file content is returned.

---

## Output and Reports

All three report formats are written after every scan.

**JSON** — structured findings array with full metadata, suitable for CI/CD integration or importing into other tools.

**Markdown** — formatted for direct submission to bug bounty platforms. Includes a summary table, per-finding PoC HTTP request blocks, evidence snippets, and remediation notes.

**HTML** — self-contained dark-mode report. Collapsible finding cards, severity badges, CVE labels, copy-ready reproduction requests, and extracted secret display. No external dependencies.

---

## Bug Bounty Usage Guide

**Before running anything**, read the program's policy page and confirm:

- Automated scanning is explicitly permitted (some programs say manual only)
- The target domain is in scope
- There are no rate-limit restrictions you would violate

**Recommended settings for real targets:**

```bash
python3 pathscan_final.py \
  -u "https://target.example.com" \
  --cookies "session=YOUR_COOKIE" \
  --rps 2 \
  -t 3 \
  --max-pages 50 \
  --skip-cve \
  --checkpoint target.ckpt \
  --proxy http://127.0.0.1:8080 \
  -o target_report.html \
  --i-have-authorization
```

Keep `--rps` low (2–3) and threads low (3–5). Most programs will invalidate your report or ban your account if you cause measurable load on their infrastructure.

**After finding something**, do not submit the tool output directly. Programs reject automated scanner reports. Instead:

1. Manually reproduce the exact request with curl or Burp Repeater to confirm
2. Write a clear report showing the vulnerable endpoint, the exact HTTP request, the response proving exploitation, and the impact
3. Assess actual severity — reading `/etc/passwd` is typically Medium unless you can chain it to credentials, source code, or RCE

---

## Examples

```bash
# PortSwigger Web Security Academy labs
python3 pathscan_final.py \
  -u "https://YOUR-LAB-ID.web-security-academy.net" \
  --cookies "session=TOKEN" \
  --rps 3 -t 3 \
  --i-have-authorization

# Pipe from gau (fetch known URLs from web archives)
gau target.com | python3 pathscan_final.py -t 15 --i-have-authorization

# Pipe from katana (active crawler)
katana -u https://target.com -silent | python3 pathscan_final.py --i-have-authorization

# Pipe from httpx (filter live hosts from a subdomain list)
cat subdomains.txt | httpx -silent | python3 pathscan_final.py \
  --force-append -t 20 --i-have-authorization

# CVE probe pass only (fast, low noise)
python3 pathscan_final.py -l targets.txt --cve-only --i-have-authorization

# With an OpenAPI spec and Burp proxy
python3 pathscan_final.py -u https://api.target.com \
  --openapi swagger.json \
  --proxy http://127.0.0.1:8080 \
  --checkpoint api_scan.ckpt \
  -t 5 --rps 2 \
  --i-have-authorization

# Resume an interrupted scan
python3 pathscan_final.py -u https://target.com \
  --checkpoint scan.ckpt \
  --i-have-authorization

# Blind timing oracle for applications with no visible output
python3 pathscan_final.py -u "https://target.com/load?template=main" \
  --blind-timing \
  --i-have-authorization
```

---

## Limitations

- Class 11 (prefix bypass) generates a large payload set (~4,200 vectors). On broad crawls with many endpoints, scan time increases significantly. Use `--skip-crawl` with a specific URL to target a known vulnerable endpoint directly.
- The blind timing oracle produces LOW confidence signals only. Timing-based detection has a higher false positive rate depending on server load and network conditions.
- This tool does not exploit vulnerabilities — it detects and reports them. File exfiltration, RCE chaining, and post-exploitation are out of scope.
- The crawler does not handle JavaScript-heavy single-page applications well. For React/Vue/Angular apps, extract API endpoints manually from browser DevTools network tab or use `--openapi` with the app's API spec.
- WAF bypass is not guaranteed. Sophisticated WAFs may block payloads even with encoding variants and stealth headers. Manual testing with Burp remains necessary for hardened targets.

---

## Legal Disclaimer

This tool is provided for educational purposes and authorized security testing only. The author is not responsible for any misuse. You are solely responsible for ensuring you have permission to test any target before running this tool against it. Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), and equivalent legislation in your jurisdiction.
