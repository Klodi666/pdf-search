#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 GOV RECON PRO v2.0
 Advanced Public Information & OSINT Reconnaissance Framework
================================================================================
 Public-information OSINT only. Respect rate limits, robots.txt, ToS, and law.
 No exploitation, no auth bypass, no CAPTCHA bypass, no brute force.
================================================================================
"""

import os
import re
import sys
import csv
import json
import time
import html
import socket
import hashlib
import threading
import datetime
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ------------------------------------------------------------------ OPTIONAL DEPS
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except Exception:
    HAS_BS4 = False

try:
    import dns.resolver
    HAS_DNS = True
except Exception:
    HAS_DNS = False

try:
    import whois as whois_lib
    HAS_WHOIS = True
except Exception:
    HAS_WHOIS = False

try:
    import fitz  # PyMuPDF
    HAS_FITZ = True
except Exception:
    HAS_FITZ = False

try:
    import ssl as ssl_lib
    HAS_SSL = True
except Exception:
    HAS_SSL = False

if HAS_REQUESTS:
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass

# ------------------------------------------------------------------ COLOR / UI
IS_TTY = sys.stdout.isatty()

class C:
    G    = "\033[92m"
    DG   = "\033[32m"
    R    = "\033[91m"
    Y    = "\033[93m"
    CY   = "\033[96m"
    M    = "\033[95m"
    W    = "\033[97m"
    GR   = "\033[90m"
    B    = "\033[1m"
    RS   = "\033[0m"

    @staticmethod
    def off():
        for k in ("G", "DG", "R", "Y", "CY", "M", "W", "GR", "B", "RS"):
            setattr(C, k, "")

if not IS_TTY:
    C.off()

def hr(ch="─", n=70, col=None):
    print((col or C.DG) + ch * n + C.RS)

def log(msg, tag="*", col=None):
    print(f"{col or C.G}[{tag}]{C.RS} {msg}")

def ok(msg):   log(msg, "+", C.G)
def warn(msg): log(msg, "!", C.Y)
def err(msg):  log(msg, "x", C.R)
def info(msg): log(msg, "i", C.CY)
def dbg(msg):
    if STATE["settings"].get("debug"):
        log(msg, "d", C.GR)

# ------------------------------------------------------------------ GLOBAL STATE
OUT_DIR = os.path.abspath("gov_recon_output")

STATE = {
    "settings": {
        "workers": 10,
        "timeout": 15,
        "retries": 2,
        "rate_limit": 0.0,
        "max_pdf_mb": 25,
        "verify_ssl": False,
        "cache": True,
        "debug": False,
        "user_agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"),
    },
    "results": {},
    "history": [],
    "pdf_urls": [],
    "session_file": os.path.join(OUT_DIR, "session.json"),
    "history_file": os.path.join(OUT_DIR, "history.json"),
    "running": True,
}

_CACHE = {}
_CACHE_LOCK = threading.Lock()
_RL_LOCK = threading.Lock()
_LAST_REQ = [0.0]

# ------------------------------------------------------------------ HELPERS
def ensure_dirs():
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(os.path.join(OUT_DIR, "pdfs"), exist_ok=True)
    os.makedirs(os.path.join(OUT_DIR, "reports"), exist_ok=True)

def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def safe_name(s):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(s))[:120] or "out"

def safe_input(prompt, default=None):
    try:
        v = input(prompt).strip()
        return v if v else (default if default is not None else "")
    except EOFError:
        return default if default is not None else ""
    except KeyboardInterrupt:
        print()
        return ""

def ask_int(prompt, default, lo=1, hi=200):
    v = safe_input(prompt, str(default))
    try:
        n = int(v)
        return max(lo, min(hi, n))
    except Exception:
        return default

def ask_yes(prompt, default=False):
    v = safe_input(prompt, "y" if default else "n").lower()
    return v in ("y", "yes", "1", "true")

def normalize_url(u):
    u = (u or "").strip()
    if not u:
        return None
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    try:
        p = urllib.parse.urlparse(u)
        if not p.netloc:
            return None
        return urllib.parse.urlunparse(p)
    except Exception:
        return None

def dedupe(seq):
    seen = set()
    out = []
    for x in seq:
        k = x if isinstance(x, str) else json.dumps(x, sort_keys=True, default=str)
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out

def progress(done, total, prefix="", width=28):
    total = max(total, 1)
    frac = min(1.0, done / total)
    filled = int(width * frac)
    bar = "█" * filled + "░" * (width - filled)
    sys.stdout.write(f"\r  {C.CY}{prefix} {bar} {done}/{total} ({frac*100:5.1f}%){C.RS}")
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")

def rate_gate():
    rl = STATE["settings"].get("rate_limit", 0.0) or 0.0
    if rl <= 0:
        return
    with _RL_LOCK:
        now = time.time()
        wait = _LAST_REQ[0] + rl - now
        if wait > 0:
            time.sleep(wait)
        _LAST_REQ[0] = time.time()

# ------------------------------------------------------------------ HTTP LAYER
_SESSION = None
_SESSION_LOCK = threading.Lock()

def get_session():
    global _SESSION
    if not HAS_REQUESTS:
        return None
    with _SESSION_LOCK:
        if _SESSION is None:
            s = requests.Session()
            retries = STATE["settings"].get("retries", 2)
            try:
                retry = Retry(
                    total=retries, connect=retries, read=retries,
                    backoff_factor=0.4,
                    status_forcelist=[429, 500, 502, 503, 504],
                    allowed_methods=frozenset(["GET", "HEAD"]),
                )
                adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
                s.mount("http://", adapter)
                s.mount("https://", adapter)
            except Exception:
                pass
            s.headers.update({
                "User-Agent": STATE["settings"]["user_agent"],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.8",
            })
            _SESSION = s
        return _SESSION

def http_get(url, method="GET", timeout=None, allow_redirects=True,
             stream=False, headers=None, use_cache=True):
    if not HAS_REQUESTS:
        err("requests library missing — run: pip install requests")
        return None
    t = timeout or STATE["settings"]["timeout"]

    ck = (method.upper(), url)
    if use_cache and STATE["settings"].get("cache"):
        with _CACHE_LOCK:
            hit = _CACHE.get(ck)
        if hit and (time.time() - hit[0] < 300):
            return hit[1]

    rate_gate()
    s = get_session()
    try:
        r = s.request(
            method.upper(), url,
            timeout=t,
            allow_redirects=allow_redirects,
            stream=stream,
            headers=headers or {},
            verify=STATE["settings"].get("verify_ssl", False),
        )
        if use_cache and STATE["settings"].get("cache") and not stream:
            with _CACHE_LOCK:
                if len(_CACHE) > 500:
                    _CACHE.clear()
                _CACHE[ck] = (time.time(), r)
        return r
    except Exception as e:
        dbg(f"HTTP fail {url}: {e}")
        return None

def html_to_text(content):
    if not content:
        return ""
    if HAS_BS4:
        try:
            soup = BeautifulSoup(content, "html.parser")
            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()
            return re.sub(r"\s+", " ", soup.get_text(" ")).strip()
        except Exception:
            pass
    txt = re.sub(r"(?is)<script.*?</script>", " ", content)
    txt = re.sub(r"(?is)<style.*?</style>", " ", txt)
    txt = re.sub(r"(?s)<[^>]+>", " ", txt)
    txt = html.unescape(txt)
    return re.sub(r"\s+", " ", txt).strip()

def extract_links(base, content):
    links = []
    if not content:
        return links
    if HAS_BS4:
        try:
            soup = BeautifulSoup(content, "html.parser")
            for a in soup.find_all("a", href=True):
                links.append(urllib.parse.urljoin(base, a["href"].strip()))
            return dedupe(links)
        except Exception:
            pass
    for m in re.finditer(r'href\s*=\s*["\']([^"\']+)["\']', content, re.I):
        links.append(urllib.parse.urljoin(base, m.group(1).strip()))
    return dedupe(links)

def content_type(resp):
    try:
        return (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    except Exception:
        return ""

# ------------------------------------------------------------------ MATCHING
def find_matches(text, keywords, case_sensitive=False, context=80, exact=False):
    if not text:
        return []
    hay = text if case_sensitive else text.lower()
    hits = []
    for kw in keywords:
        if not kw:
            continue
        needle = kw if case_sensitive else kw.lower()
        start = 0
        count = 0
        while True:
            idx = hay.find(needle, start)
            if idx < 0:
                break
            if exact:
                before = hay[idx-1] if idx > 0 else " "
                after = hay[idx+len(needle)] if idx+len(needle) < len(hay) else " "
                if before.isalnum() or after.isalnum():
                    start = idx + 1
                    continue
            a = max(0, idx - context)
            b = min(len(text), idx + len(needle) + context)
            snippet = re.sub(r"\s+", " ", text[a:b]).strip()
            hits.append({"keyword": kw, "position": idx, "context": snippet})
            count += 1
            if count >= 5:
                break
            start = idx + len(needle)
    return hits

def keyword_logic(record_text, include, exclude, mode):
    t = record_text.lower()
    if exclude:
        for x in exclude:
            if x and x.lower() in t:
                return False
    if not include:
        return True
    if mode == "and":
        return all(k.lower() in t for k in include if k)
    return any(k.lower() in t for k in include if k)

# ------------------------------------------------------------------ PARALLEL RUNNER
def run_parallel(items, fn, workers=None, prefix="scan"):
    workers = workers or STATE["settings"]["workers"]
    total = len(items)
    if total == 0:
        return
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(fn, it): it for it in items}
        for f in as_completed(futs):
            it = futs[f]
            try:
                res = f.result()
            except Exception as e:
                dbg(f"worker error: {e}")
                res = None
            done += 1
            progress(done, total, prefix)
            yield it, res

# ------------------------------------------------------------------ SAVE UTILS
def save_list(module, records):
    if records is None:
        return
    STATE["results"].setdefault(module, [])
    STATE["results"][module].extend(records)

def save_json_file(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception as e:
        err(f"JSON save failed: {e}")
        return False

def save_csv_file(path, rows, fields):
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)
        return True
    except Exception as e:
        err(f"CSV save failed: {e}")
        return False

def save_txt_file(path, lines):
    try:
        with open(path, "w", encoding="utf-8") as f:
            for ln in lines:
                f.write(str(ln) + "\n")
        return True
    except Exception as e:
        err(f"TXT save failed: {e}")
        return False

# ================================================================================
#  SEARCH ENGINE REGISTRY
# ================================================================================
ENGINES_REGISTRY = {
    # ---------------- GENERAL ----------------
    "google": {
        "name": "Google", "category": "general",
        "url": "https://www.google.com/search?q={q}&num=20&start={s}",
        "parser": "google",
    },
    "bing": {
        "name": "Bing", "category": "general",
        "url": "https://www.bing.com/search?q={q}&count=30&first={s}",
        "parser": "bing",
    },
    "duckduckgo": {
        "name": "DuckDuckGo", "category": "general",
        "url": "https://html.duckduckgo.com/html/?q={q}&s={s}",
        "parser": "ddg",
    },
    "yahoo": {
        "name": "Yahoo", "category": "general",
        "url": "https://search.yahoo.com/search?p={q}&b={s}",
        "parser": "yahoo",
    },
    "brave": {
        "name": "Brave", "category": "general",
        "url": "https://search.brave.com/search?q={q}&offset={s}",
        "parser": "generic_links",
    },
    "startpage": {
        "name": "Startpage", "category": "general",
        "url": "https://www.startpage.com/sp/search?query={q}",
        "parser": "generic_links",
    },
    "yandex": {
        "name": "Yandex", "category": "general",
        "url": "https://yandex.com/search/?text={q}&lr={s}",
        "parser": "generic_links",
    },
    "baidu": {
        "name": "Baidu", "category": "general",
        "url": "https://www.baidu.com/s?wd={q}&pn={s}",
        "parser": "generic_links",
    },
    "ecosia": {
        "name": "Ecosia", "category": "general",
        "url": "https://www.ecosia.org/search?q={q}&p={s}",
        "parser": "generic_links",
    },
    "qwant": {
        "name": "Qwant", "category": "general",
        "url": "https://api.qwant.com/v3/search/web?q={q}&count=10&locale=en_US&offset={s}&device=desktop",
        "parser": "qwant_json",
    },
    "ask": {
        "name": "Ask", "category": "general",
        "url": "https://www.ask.com/web?q={q}&page={s}",
        "parser": "generic_links",
    },
    "aol": {
        "name": "AOL", "category": "general",
        "url": "https://search.aol.com/aol/search?q={q}&b={s}",
        "parser": "generic_links",
    },
    "sogou": {
        "name": "Sogou", "category": "general",
        "url": "https://www.sogou.com/web?query={q}&page={s}",
        "parser": "generic_links",
    },
    "so360": {
        "name": "360 Search", "category": "general",
        "url": "https://www.so.com/s?q={q}&pn={s}",
        "parser": "generic_links",
    },
    "seznam": {
        "name": "Seznam", "category": "general",
        "url": "https://search.seznam.cz/?q={q}&from={s}",
        "parser": "generic_links",
    },
    "rambler": {
        "name": "Rambler", "category": "general",
        "url": "https://nova.rambler.ru/search?query={q}&page={s}",
        "parser": "generic_links",
    },
    "goo": {
        "name": "Goo", "category": "general",
        "url": "https://search.goo.ne.jp/web.jsp?MT={q}&from={s}",
        "parser": "generic_links",
    },
    "coccoc": {
        "name": "CocCoc", "category": "general",
        "url": "https://coccoc.com/search?query={q}&page={s}",
        "parser": "generic_links",
    },
    "dogpile": {
        "name": "Dogpile", "category": "general",
        "url": "https://www.dogpile.com/serp?q={q}&page={s}",
        "parser": "generic_links",
    },
    "metacrawler": {
        "name": "MetaCrawler", "category": "general",
        "url": "https://www.metacrawler.com/serp?q={q}&page={s}",
        "parser": "generic_links",
    },
    "webcrawler": {
        "name": "WebCrawler", "category": "general",
        "url": "https://www.webcrawler.com/search/web?q={q}&page={s}",
        "parser": "generic_links",
    },
    "lycos": {
        "name": "Lycos", "category": "general",
        "url": "https://search.lycos.com/web/?q={q}&page={s}",
        "parser": "generic_links",
    },
    "info_com": {
        "name": "Info.com", "category": "general",
        "url": "https://www.info.com/serp?q={q}&page={s}",
        "parser": "generic_links",
    },

    # ---------------- PRIVACY ----------------
    "mojeek": {
        "name": "Mojeek", "category": "privacy",
        "url": "https://www.mojeek.com/search?q={q}&s={s}",
        "parser": "generic_links",
    },
    "marginalia": {
        "name": "Marginalia", "category": "privacy",
        "url": "https://search.marginalia.nu/search?query={q}&page={s}",
        "parser": "generic_links",
    },
    "swisscows": {
        "name": "Swisscows", "category": "privacy",
        "url": "https://swisscows.com/en/web?query={q}",
        "parser": "generic_links",
    },
    "metager": {
        "name": "MetaGer", "category": "privacy",
        "url": "https://metager.org/meta/meta.ger3?eingabe={q}&focus=web&pag={s}",
        "parser": "generic_links",
    },
    "yep": {
        "name": "Yep", "category": "privacy",
        "url": "https://yep.com/web?q={q}",
        "parser": "generic_links",
    },
    "lukol": {
        "name": "Lukol", "category": "privacy",
        "url": "https://www.lukol.com/s.php?q={q}",
        "parser": "generic_links",
    },
    "wiby": {
        "name": "Wiby", "category": "privacy",
        "url": "https://wiby.me/?q={q}",
        "parser": "generic_links",
    },
    "gibiru": {
        "name": "Gibiru", "category": "privacy",
        "url": "https://gibiru.com/results.html?q={q}",
        "parser": "generic_links",
    },

    # ---------------- CODE ----------------
    "grep_app": {
        "name": "grep.app", "category": "code",
        "url": "https://grep.app/api/search?q={q}",
        "parser": "grep_app_json",
    },
    "github": {
        "name": "GitHub", "category": "code",
        "url": "https://github.com/search?q={q}&type=code",
        "parser": "generic_links",
        "note": "code search needs GitHub auth token; repos/issues work",
    },
    "searchcode": {
        "name": "searchcode", "category": "code",
        "url": "https://searchcode.com/?q={q}",
        "parser": "searchcode",
    },
    "sourcegraph": {
        "name": "Sourcegraph", "category": "code",
        "url": "https://sourcegraph.com/search?q={q}&patternType=standard",
        "parser": "generic_links",
    },
    "stackoverflow": {
        "name": "StackOverflow", "category": "code",
        "url": "https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=relevance&q={q}&site=stackoverflow",
        "parser": "stackexchange_json",
    },
    "gitlab": {
        "name": "GitLab", "category": "code",
        "url": "https://gitlab.com/search?search={q}",
        "parser": "generic_links",
    },

    # ---------------- ACADEMIC ----------------
    "arxiv": {
        "name": "arXiv", "category": "academic",
        "url": "http://export.arxiv.org/api/query?search_query=all:{q}&start={s}&max_results=10",
        "parser": "arxiv_xml",
    },
    "semanticscholar": {
        "name": "Semantic Scholar", "category": "academic",
        "url": "https://api.semanticscholar.org/graph/v1/paper/search?query={q}&limit=10&fields=title,url,abstract,year",
        "parser": "semanticscholar_json",
    },
    "pubmed": {
        "name": "PubMed", "category": "academic",
        "url": "https://pubmed.ncbi.nlm.nih.gov/?term={q}&page={s}",
        "parser": "pubmed",
    },
    "base": {
        "name": "BASE", "category": "academic",
        "url": "https://www.base-search.net/Search/Results?lookfor={q}",
        "parser": "generic_links",
    },
    "core": {
        "name": "CORE", "category": "academic",
        "url": "https://core.ac.uk/search?q={q}",
        "parser": "generic_links",
    },
    "scholar": {
        "name": "Google Scholar", "category": "academic",
        "url": "https://scholar.google.com/scholar?q={q}&start={s}",
        "parser": "generic_links",
    },
    "refseek": {
        "name": "Refseek", "category": "academic",
        "url": "https://www.refseek.com/search?q={q}",
        "parser": "generic_links",
    },
    "paperswithcode": {
        "name": "PapersWithCode", "category": "academic",
        "url": "https://paperswithcode.com/search?q={q}",
        "parser": "generic_links",
    },
    "science_gov": {
        "name": "Science.gov", "category": "academic",
        "url": "https://www.science.gov/search?q={q}",
        "parser": "generic_links",
    },

    # ---------------- FILES ----------------
    "filepursuit": {
        "name": "FilePursuit", "category": "files",
        "url": "https://filepursuit.com/pursuit?q={q}&type=all",
        "parser": "generic_links",
    },
    "archive_org": {
        "name": "Archive.org", "category": "files",
        "url": "https://archive.org/advancedsearch.php?q={q}&fl[]=identifier&fl[]=title&rows=10&output=json",
        "parser": "archive_org_json",
    },
    "documentcloud": {
        "name": "DocumentCloud", "category": "files",
        "url": "https://api.documentcloud.org/api/documents/search/?q={q}",
        "parser": "documentcloud_json",
    },
    "scribd": {
        "name": "Scribd", "category": "files",
        "url": "https://www.scribd.com/search?query={q}",
        "parser": "generic_links",
    },

    # ---------------- IMAGES ----------------
    "google_images": {
        "name": "Google Images", "category": "images",
        "url": "https://www.google.com/search?q={q}&tbm=isch",
        "parser": "generic_links",
    },
    "yandex_images": {
        "name": "Yandex Images", "category": "images",
        "url": "https://yandex.com/images/search?text={q}",
        "parser": "generic_links",
    },
    "bing_images": {
        "name": "Bing Images", "category": "images",
        "url": "https://www.bing.com/images/search?q={q}",
        "parser": "generic_links",
    },
    "tineye": {
        "name": "TinEye", "category": "images",
        "url": "https://tineye.com/search?url={q}",
        "parser": "generic_links",
        "note": "q must be an image URL",
    },

    # ---------------- ARCHIVES ----------------
    "web_archive": {
        "name": "Wayback Machine", "category": "archives",
        "url": "http://web.archive.org/cdx/search/cdx?url={q}&output=json&limit=30",
        "parser": "cdx_json",
        "note": "q must be a domain or URL",
    },
    "archive_ph": {
        "name": "archive.today", "category": "archives",
        "url": "https://archive.ph/search/?q={q}",
        "parser": "generic_links",
    },

    # ---------------- SOCIAL ----------------
    "reddit": {
        "name": "Reddit", "category": "social",
        "url": "https://old.reddit.com/search.json?q={q}&limit=25",
        "parser": "reddit_json",
    },
    "wikipedia": {
        "name": "Wikipedia", "category": "social",
        "url": "https://en.wikipedia.org/w/api.php?action=opensearch&search={q}&limit=20&format=json",
        "parser": "wikipedia_json",
    },
    "youtube": {
        "name": "YouTube", "category": "social",
        "url": "https://www.youtube.com/results?search_query={q}",
        "parser": "youtube",
    },
    "boardreader": {
        "name": "Boardreader", "category": "social",
        "url": "https://boardreader.com/s/{q}.html",
        "parser": "generic_links",
    },

    # ---------------- OSINT / SECURITY ----------------
    "crtsh": {
        "name": "crt.sh", "category": "osint",
        "url": "https://crt.sh/?q={q}&output=json",
        "parser": "crtsh_json",
        "note": "certificate transparency for host/domain in q",
    },
    "urlscan": {
        "name": "urlscan.io", "category": "osint",
        "url": "https://urlscan.io/api/v1/search/?q={q}",
        "parser": "urlscan_json",
    },
    "publicwww": {
        "name": "PublicWWW", "category": "osint",
        "url": "https://publicwww.com/websites/{q}/",
        "parser": "generic_links",
    },
    "nvd": {
        "name": "NVD (CVE)", "category": "osint",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={q}&resultsPerPage=20",
        "parser": "nvd_json",
    },
    "exploit_db": {
        "name": "Exploit-DB", "category": "osint",
        "url": "https://www.exploit-db.com/search?q={q}",
        "parser": "generic_links",
    },
    "vulners": {
        "name": "Vulners", "category": "osint",
        "url": "https://vulners.com/search?query={q}",
        "parser": "generic_links",
    },
}

CATEGORIES = ["general", "privacy", "code", "academic",
              "files", "images", "archives", "social", "osint"]

def _engines_by_category(cat):
    return [k for k, v in ENGINES_REGISTRY.items() if v["category"] == cat]

# ------------------------------------------------------------------ PARSERS
def _clean_urls(results, base_url):
    try:
        engine_host = urllib.parse.urlparse(base_url).netloc.lower()
    except Exception:
        engine_host = ""
    skip_ext = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                ".ico", ".woff", ".woff2", ".ttf", ".webp")
    out = []
    seen = set()
    for r in results or []:
        u = r.get("url", "")
        if not u:
            continue
        try:
            p = urllib.parse.urlparse(u)
            host = p.netloc.lower()
            if not host:
                continue
            if host == engine_host:
                continue
            if p.path.lower().endswith(skip_ext):
                continue
            clean = urllib.parse.urlunparse(p._replace(fragment=""))
            if clean in seen:
                continue
            seen.add(clean)
            out.append({**r, "url": clean})
        except Exception:
            continue
    return out

def _parse_html_results(style, content, base_url):
    results = []
    if not content:
        return results
    if not HAS_BS4:
        for m in re.finditer(r'https?://[^\s"\'<>]+', content):
            results.append({"url": m.group(0), "title": "", "snippet": ""})
        return results
    try:
        soup = BeautifulSoup(content, "html.parser")
        if style == "bing":
            for it in soup.select("li.b_algo"):
                a = it.select_one("h2 a")
                if a and a.get("href"):
                    snip = it.select_one(".b_caption p")
                    results.append({
                        "url": a["href"],
                        "title": a.get_text(" ", strip=True),
                        "snippet": snip.get_text(" ", strip=True) if snip else "",
                    })
        elif style == "ddg":
            for it in soup.select("div.result"):
                a = it.select_one("a.result__a")
                if not a or not a.get("href"):
                    continue
                href = a["href"]
                if "uddg=" in href:
                    try:
                        q = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
                        href = q.get("uddg", [href])[0]
                    except Exception:
                        pass
                snip = it.select_one(".result__snippet")
                results.append({
                    "url": href,
                    "title": a.get_text(" ", strip=True),
                    "snippet": snip.get_text(" ", strip=True) if snip else "",
                })
        elif style == "google":
            for a in soup.select("a[href]"):
                h = a["href"]
                if h.startswith("/url?q="):
                    try:
                        real = urllib.parse.parse_qs(
                            urllib.parse.urlparse(h).query
                        ).get("q", [""])[0]
                        if real.startswith("http"):
                            results.append({
                                "url": real,
                                "title": a.get_text(" ", strip=True),
                                "snippet": "",
                            })
                    except Exception:
                        pass
        elif style == "yahoo":
            for it in soup.select("div.algo"):
                a = it.select_one("h3 a")
                if a and a.get("href") and a["href"].startswith("http"):
                    snip = it.select_one(".compText p")
                    results.append({
                        "url": a["href"],
                        "title": a.get_text(" ", strip=True),
                        "snippet": snip.get_text(" ", strip=True) if snip else "",
                    })
        elif style == "searchcode":
            for it in soup.select("div.result"):
                a = it.select_one("a")
                if a and a.get("href"):
                    h = a["href"]
                    if not h.startswith("http"):
                        h = urllib.parse.urljoin(base_url, h)
                    results.append({
                        "url": h,
                        "title": a.get_text(" ", strip=True),
                        "snippet": "",
                    })
        elif style == "pubmed":
            for a in soup.select("a.docsum-title"):
                h = a.get("href", "")
                if h:
                    if h.startswith("/"):
                        h = "https://pubmed.ncbi.nlm.nih.gov" + h
                    results.append({
                        "url": h,
                        "title": a.get_text(" ", strip=True),
                        "snippet": "",
                    })
        elif style == "youtube":
            m = re.search(r"var ytInitialData\s*=\s*(\{.*?\});", content, re.S)
            if m:
                try:
                    data = json.loads(m.group(1))

                    def walk(obj):
                        if isinstance(obj, dict):
                            if "videoId" in obj and "title" in obj:
                                vid = obj["videoId"]
                                title = ""
                                t = obj.get("title", {})
                                if isinstance(t, dict):
                                    runs = t.get("runs") or []
                                    if runs:
                                        title = runs[0].get("text", "")
                                    elif "simpleText" in t:
                                        title = t["simpleText"]
                                if vid and title:
                                    results.append({
                                        "url": f"https://www.youtube.com/watch?v={vid}",
                                        "title": title,
                                        "snippet": "",
                                    })
                            for v in obj.values():
                                walk(v)
                        elif isinstance(obj, list):
                            for v in obj:
                                walk(v)

                    walk(data)
                except Exception:
                    pass
            if not results:
                for mm in re.finditer(
                    r'"videoId":"([A-Za-z0-9_-]{11})".{0,400}?"text":"([^"]+)"',
                    content,
                ):
                    vid, title = mm.group(1), mm.group(2)
                    results.append({
                        "url": f"https://www.youtube.com/watch?v={vid}",
                        "title": title,
                        "snippet": "",
                    })
        else:  # generic_links
            for a in soup.find_all("a", href=True):
                h = a["href"].strip()
                if h.startswith("//"):
                    h = "https:" + h
                elif h.startswith("/"):
                    h = urllib.parse.urljoin(base_url, h)
                if not h.startswith("http"):
                    continue
                results.append({
                    "url": h,
                    "title": a.get_text(" ", strip=True) or h,
                    "snippet": "",
                })
    except Exception as e:
        dbg(f"html parse fail ({style}): {e}")
    return results

def _parse_results(parser_name, content, base_url, engine_key):
    results = []
    try:
        if parser_name in ("bing", "ddg", "google", "yahoo", "generic_links",
                           "searchcode", "pubmed", "youtube"):
            results = _parse_html_results(parser_name, content, base_url)

        elif parser_name == "qwant_json":
            data = json.loads(content)
            items = (data.get("data", {}).get("result", {}) or {}).get("items", {}) or {}
            if isinstance(items, dict):
                for sec_key, sec in items.items():
                    if not isinstance(sec, dict):
                        continue
                    for r in (sec.get("items") or []):
                        if isinstance(r, dict) and r.get("url"):
                            results.append({
                                "url": r["url"],
                                "title": r.get("title", "") or r.get("name", ""),
                                "snippet": r.get("desc", "") or "",
                            })

        elif parser_name == "grep_app_json":
            data = json.loads(content)
            hits = (data.get("hits", {}) or {}).get("hits", []) or []
            for h in hits:
                repo = (h.get("repo") or {}).get("raw", "")
                path = (h.get("path") or {}).get("raw", "")
                if repo and path:
                    results.append({
                        "url": f"https://github.com/{repo}/blob/HEAD/{path}",
                        "title": path,
                        "snippet": "",
                    })

        elif parser_name == "stackexchange_json":
            data = json.loads(content)
            for item in data.get("items", []) or []:
                results.append({
                    "url": item.get("link", ""),
                    "title": item.get("title", ""),
                    "snippet": re.sub(r"<[^>]+>", "",
                                      item.get("body", "") or "")[:200],
                })

        elif parser_name == "arxiv_xml":
            for m in re.finditer(r"<entry>(.*?)</entry>", content, re.S):
                entry = m.group(1)
                t = re.search(r"<title>(.*?)</title>", entry, re.S)
                l = re.search(r"<id>(.*?)</id>", entry, re.S)
                s = re.search(r"<summary>(.*?)</summary>", entry, re.S)
                if l:
                    results.append({
                        "url": l.group(1).strip(),
                        "title": re.sub(r"\s+", " ", t.group(1)).strip() if t else "",
                        "snippet": re.sub(r"\s+", " ", s.group(1)).strip()[:200] if s else "",
                    })

        elif parser_name == "semanticscholar_json":
            data = json.loads(content)
            for p in data.get("data", []) or []:
                url = p.get("url") or (
                    "https://www.semanticscholar.org/paper/" + (p.get("paperId") or "")
                )
                results.append({
                    "url": url,
                    "title": p.get("title", ""),
                    "snippet": (p.get("abstract") or "")[:200],
                })

        elif parser_name == "archive_org_json":
            data = json.loads(content)
            for d in data.get("response", {}).get("docs", []) or []:
                ident = d.get("identifier")
                if ident:
                    results.append({
                        "url": f"https://archive.org/details/{ident}",
                        "title": d.get("title", "") or ident,
                        "snippet": "",
                    })

        elif parser_name == "documentcloud_json":
            data = json.loads(content)
            for d in data.get("results", []) or []:
                if d.get("canonical_url"):
                    results.append({
                        "url": d["canonical_url"],
                        "title": d.get("title", ""),
                        "snippet": "",
                    })

        elif parser_name == "cdx_json":
            try:
                rows = json.loads(content)
                if isinstance(rows, list) and len(rows) > 1:
                    for row in rows[1:]:
                        if isinstance(row, list) and len(row) > 2:
                            orig = row[2]
                            ts_ = row[1]
                            results.append({
                                "url": f"https://web.archive.org/web/{ts_}/{orig}",
                                "title": orig,
                                "snippet": f"captured {ts_}",
                            })
            except Exception:
                pass

        elif parser_name == "reddit_json":
            data = json.loads(content)
            for ch in (data.get("data", {}).get("children", []) or []):
                d = ch.get("data", {})
                url = d.get("url") or ""
                permalink = d.get("permalink") or ""
                if url and "reddit.com" not in url:
                    results.append({
                        "url": url,
                        "title": d.get("title", ""),
                        "snippet": (d.get("selftext", "") or "")[:200],
                    })
                elif permalink:
                    results.append({
                        "url": "https://www.reddit.com" + permalink,
                        "title": d.get("title", ""),
                        "snippet": (d.get("selftext", "") or "")[:200],
                    })

        elif parser_name == "wikipedia_json":
            data = json.loads(content)
            titles = data[1] if len(data) > 1 else []
            urls = data[3] if len(data) > 3 else []
            for t, u in zip(titles, urls):
                results.append({"url": u, "title": t, "snippet": ""})

        elif parser_name == "crtsh_json":
            data = json.loads(content)
            for row in (data or []):
                nv = str(row.get("name_value", "")).split("\n")[0].strip()
                if nv:
                    results.append({
                        "url": f"https://{nv}",
                        "title": nv,
                        "snippet": "cert id " + str(row.get("id", "")),
                    })

        elif parser_name == "urlscan_json":
            data = json.loads(content)
            for r in data.get("results", []) or []:
                page = r.get("page", {}) or {}
                url = page.get("url")
                if url:
                    results.append({
                        "url": url,
                        "title": page.get("title", "") or url,
                        "snippet": "",
                    })

        elif parser_name == "nvd_json":
            data = json.loads(content)
            for v in data.get("vulnerabilities", []) or []:
                cve = v.get("cve", {})
                cid = cve.get("id")
                if cid:
                    desc = ""
                    for d in cve.get("descriptions", []) or []:
                        if d.get("lang") == "en":
                            desc = d.get("value", "")
                            break
                    results.append({
                        "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                        "title": cid,
                        "snippet": desc[:200],
                    })
    except Exception as e:
        dbg(f"parse {parser_name} fail: {e}")

    return _clean_urls(results, base_url)

def _engine_worker(engine_key, query, start, depth):
    meta = ENGINES_REGISTRY.get(engine_key)
    if not meta:
        return engine_key, []
    url = meta["url"].format(q=urllib.parse.quote_plus(query), s=start)
    r = http_get(url, timeout=25, allow_redirects=True)
    if r is None:
        return engine_key, []
    if r.status_code >= 400:
        return engine_key, []
    results = _parse_results(meta["parser"], r.text, url, engine_key)
    return engine_key, results

# ================================================================================
#  MODULE 1 — ADVANCED WEB SEARCH (multi-engine)
# ================================================================================
def export_quick(module, rows, fields):
    try:
        p = os.path.join(OUT_DIR, f"{module}_{stamp()}.csv")
        save_csv_file(p, rows, fields)
        info(f"CSV: {p}")
    except Exception:
        pass

def _print_engine_menu():
    hr("═")
    print(f"{C.B}{C.G}  [1] ADVANCED WEB SEARCH — MULTI-ENGINE HACKER CONSOLE{C.RS}")
    hr("═")
    print(f"  {C.B}Categories & engines:{C.RS}")
    for i, cat in enumerate(CATEGORIES, 1):
        keys = _engines_by_category(cat)
        preview = ", ".join(keys[:8]) + ("..." if len(keys) > 8 else "")
        print(f"  {C.G}[{i}]{C.RS} {C.W}{cat:<9}{C.RS} ({len(keys):>2}): "
              f"{C.GR}{preview}{C.RS}")
    print(f"  {C.G}[a]{C.RS} ALL engines (every category)")
    print(f"  {C.G}[c]{C.RS} Custom — pick engine keys manually")
    print(f"  {C.G}[0]{C.RS} Back")
    hr("─")

def _resolve_engine_selection(choice):
    choice = (choice or "").strip().lower()
    if choice in ("", "a"):
        return list(ENGINES_REGISTRY.keys())
    if choice == "0":
        return []
    if choice.isdigit() and 1 <= int(choice) <= len(CATEGORIES):
        return _engines_by_category(CATEGORIES[int(choice) - 1])
    if choice == "c":
        raw = safe_input("  Engine keys (comma): ").strip()
        selected = [k.strip() for k in raw.split(",") if k.strip() in ENGINES_REGISTRY]
        bad = [k.strip() for k in raw.split(",")
               if k.strip() and k.strip() not in ENGINES_REGISTRY]
        if bad:
            warn(f"Unknown engine keys skipped: {', '.join(bad)}")
        return selected
    return []

def module_web_search():
    _print_engine_menu()
    choice = safe_input("  Choose category [a]: ", "a").strip().lower()
    selected = _resolve_engine_selection(choice)
    if not selected:
        warn("No engines selected.")
        return

    query = safe_input("  Query / operators (site: filetype: intitle: inurl: \"exact\"): ")
    if not query:
        warn("Empty query.")
        return

    total_engines = len(selected)
    default_depth = 1 if total_engines > 15 else 2
    depth = ask_int(f"  Depth / pages per engine [{default_depth}]: ",
                    default_depth, 1, 5)
    default_workers = min(20, max(STATE["settings"]["workers"], total_engines))
    workers = ask_int(f"  Workers [{default_workers}]: ",
                      default_workers, 1, 60)
    dom_filter = safe_input("  Domain filter (regex, blank=none): ")
    ext_filter = safe_input("  Extension filter (e.g. pdf,docx; blank=none): ")

    print()
    info(f"Engines ({total_engines}): {', '.join(selected)}")
    info(f"Depth: {depth}   Workers: {workers}   Requests: ~{total_engines * depth}")
    warn("Only public search results. Some engines may block or rate-limit automated queries.")
    if total_engines > 15:
        warn("Large engine set — expect some engines to fail (blocked/CAPTCHA).")
    if not ask_yes("  Continue? [Y/n]: ", True):
        return

    tasks = []
    for e in selected:
        for d in range(depth):
            tasks.append((e, query, d * 10, depth))

    info(f"Dispatching {len(tasks)} requests across {total_engines} engines...")
    agg = {}
    engine_stats = {e: 0 for e in selected}
    engine_errors = {e: 0 for e in selected}

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = [ex.submit(_engine_worker, *t) for t in tasks]
        done = 0
        for f in as_completed(futs):
            try:
                e, results = f.result()
            except Exception as exx:
                e, results = "?", []
                dbg(f"engine error: {exx}")
            if e not in engine_stats:
                continue
            if not results:
                engine_errors[e] += 1
            for rank, r in enumerate(results):
                u = r["url"]
                if u not in agg:
                    agg[u] = {
                        "url": u, "engines": set(),
                        "title": "", "snippet": "", "rank": 999,
                    }
                agg[u]["engines"].add(e)
                agg[u]["rank"] = min(agg[u]["rank"], rank)
                if not agg[u]["title"] and r.get("title"):
                    agg[u]["title"] = r["title"]
                if not agg[u]["snippet"] and r.get("snippet"):
                    agg[u]["snippet"] = r["snippet"]
                engine_stats[e] += 1
            done += 1
            progress(done, len(tasks), "search")

    results = []
    for u, meta in agg.items():
        if dom_filter:
            try:
                if not re.search(dom_filter, urllib.parse.urlparse(u).netloc, re.I):
                    continue
            except Exception:
                pass
        if ext_filter:
            exts = [x.strip().lower().lstrip(".")
                    for x in ext_filter.split(",") if x.strip()]
            path = urllib.parse.urlparse(u).path.lower()
            if not any(path.endswith("." + x) for x in exts):
                continue
        results.append({
            "url": u,
            "title": meta["title"],
            "snippet": meta["snippet"],
            "engines": sorted(meta["engines"]),
            "engine_hits": len(meta["engines"]),
            "rank": meta["rank"],
        })

    results.sort(key=lambda r: (-r["engine_hits"], r["rank"]))
    for i, r in enumerate(results, 1):
        r["position"] = i

    print()
    info(f"Unique results: {len(results)}")
    print(f"  {C.B}Engine breakdown:{C.RS}")
    working = 0
    for e in selected:
        hits = engine_stats.get(e, 0)
        errs = engine_errors.get(e, 0)
        col = C.G if hits > 0 else (C.Y if errs else C.GR)
        if hits > 0:
            working += 1
        mark = "✔" if hits > 0 else "✘"
        print(f"   {col}[{mark}]{C.RS} {e:<16} hits: {hits:>4}   failed reqs: {errs}")
    print(f"  {C.GR}Live engines: {working} / {total_engines}{C.RS}")

    print()
    print(f"  {C.B}Top results:{C.RS}")
    for r in results[:60]:
        print(f"  {C.G}{r['position']:>3}.{C.RS} {C.W}{r['url']}{C.RS}")
        if r["title"]:
            print(f"       {C.CY}{r['title'][:110]}{C.RS}")
        print(f"       {C.GR}engines: {', '.join(r['engines'])}{C.RS}")
    if len(results) > 60:
        print(f"  {C.GR}... {len(results) - 60} more (saved to report){C.RS}")

    save_list("web_search", results)
    STATE["history"].append({
        "time": ts(), "module": "web_search", "query": query,
        "engines": selected, "results": len(results),
    })
    ok(f"Saved {len(results)} results to session.")
    export_quick("web_search", results,
                 ["position", "url", "title", "engines", "engine_hits", "rank"])

# ================================================================================
#  SHARED KEYWORD SCANNER (used by modules 2 and 3)
# ================================================================================
def scan_one_url(url, keywords, cfg):
    rec = {
        "url": url, "status": None, "content_type": "", "final_url": url,
        "matches": [], "pdf_links": [], "error": "", "chars": 0,
    }
    r = http_get(url, timeout=cfg["timeout"], allow_redirects=True)
    if r is None:
        rec["error"] = "request failed"
        return rec
    rec["status"] = r.status_code
    rec["final_url"] = r.url
    rec["content_type"] = content_type(r)

    text = ""
    if "html" in rec["content_type"] or "xml" in rec["content_type"] or not rec["content_type"]:
        text = html_to_text(r.text)
        links = extract_links(r.url, r.text)
        rec["pdf_links"] = [l for l in links if l.lower().split("?")[0].endswith(".pdf")]
        if cfg.get("pdf_text") and rec["pdf_links"] and HAS_FITZ:
            for pl in rec["pdf_links"][:cfg.get("pdf_max", 3)]:
                ptext = fetch_pdf_text(pl, cfg["timeout"])
                if ptext:
                    text += " " + ptext
    elif "pdf" in rec["content_type"]:
        if HAS_FITZ and cfg.get("pdf_text"):
            text = fetch_pdf_text(url, cfg["timeout"]) or ""

    rec["chars"] = len(text)
    if keywords:
        rec["matches"] = find_matches(
            text, keywords,
            case_sensitive=cfg["case_sensitive"],
            context=cfg["context"],
            exact=cfg["exact"],
        )
    return rec

def fetch_pdf_text(url, timeout):
    if not HAS_FITZ:
        return ""
    try:
        r = http_get(url, timeout=timeout, stream=True)
        if r is None or r.status_code >= 400:
            return ""
        max_b = STATE["settings"]["max_pdf_mb"] * 1024 * 1024
        data = b""
        for chunk in r.iter_content(8192):
            data += chunk
            if len(data) > max_b:
                break
        if not data.startswith(b"%PDF"):
            return ""
        doc = fitz.open(stream=data, filetype="pdf")
        txt = []
        for page in doc:
            txt.append(page.get_text())
            if len(txt) > 40:
                break
        doc.close()
        return "\n".join(txt)
    except Exception as e:
        dbg(f"PDF text fail {url}: {e}")
        return ""

def run_keyword_scan(urls, keywords, cfg, module_key):
    urls = dedupe([normalize_url(u) for u in urls if normalize_url(u)])
    if not urls:
        warn("No valid URLs.")
        return []
    if not keywords:
        warn("No keywords.")
        return []

    info(f"Scanning {len(urls)} URLs for {len(keywords)} keyword(s) "
         f"with {cfg['workers']} workers...")
    results = []

    def work(u):
        return scan_one_url(u, keywords, cfg)

    for url, rec in run_parallel(urls, work, cfg["workers"], "scan"):
        if rec is None:
            rec = {"url": url, "error": "worker failure", "matches": []}
        results.append(rec)
        if rec.get("matches"):
            print(f"\n  {C.G}[MATCH]{C.RS} {C.W}{rec['url']}{C.RS} "
                  f"({rec['status']})")
            for m in rec["matches"]:
                print(f"    {C.Y}kw:{C.RS} {m['keyword']}")
                print(f"    {C.GR}ctx:{C.RS} ...{m['context'][:160]}...")
        elif rec.get("error"):
            print(f"\n  {C.R}[FAIL]{C.RS} {url} — {rec['error']}")

    hit = [r for r in results if r.get("matches")]
    miss = [r for r in results if not r.get("matches")]

    print()
    hr("─")
    info(f"URLs with matches: {len(hit)} / {len(results)}")
    info(f"URLs without matches: {len(miss)}")

    save_list(module_key, results)

    p1 = os.path.join(OUT_DIR, f"{module_key}_matches_{stamp()}.json")
    p2 = os.path.join(OUT_DIR, f"{module_key}_nomatch_{stamp()}.json")
    save_json_file(p1, hit)
    save_json_file(p2, miss)
    ok(f"Matches JSON:  {p1}")
    ok(f"No-match JSON: {p2}")

    flat = []
    for r in hit:
        for m in r["matches"]:
            flat.append({
                "url": r["url"], "status": r.get("status"),
                "keyword": m["keyword"], "context": m["context"],
            })
    if flat:
        pc = os.path.join(OUT_DIR, f"{module_key}_matches_{stamp()}.csv")
        save_csv_file(pc, flat, ["url", "status", "keyword", "context"])
        ok(f"Matches CSV:   {pc}")

    STATE["history"].append({
        "time": ts(), "module": module_key,
        "urls": len(urls), "keywords": keywords, "matches": len(flat),
    })
    return results

# ================================================================================
#  MODULE 2 — URL FILE SCANNER
# ================================================================================
def module_url_file_scan():
    hr("═")
    print(f"{C.B}{C.G}  [2] URL FILE SCANNER{C.RS}")
    hr("═")
    path = safe_input("  Path to TXT file with URLs: ")
    if not path or not os.path.isfile(path):
        err("File not found.")
        return
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            raw = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except Exception as e:
        err(f"Cannot read file: {e}")
        return

    urls = [normalize_url(u) for u in raw]
    urls = dedupe([u for u in urls if u])
    info(f"Loaded {len(urls)} valid URLs (of {len(raw)} lines).")

    kw_raw = safe_input("  Keywords (comma separated): ")
    keywords = [k.strip() for k in kw_raw.split(",") if k.strip()]
    if not keywords:
        warn("No keywords — will only fetch content.")
    case_s = ask_yes("  Case-sensitive? [y/N]: ", False)
    exact = ask_yes("  Whole-word / exact phrase match? [y/N]: ", False)
    ctx = ask_int("  Context characters [80]: ", 80, 10, 500)
    workers = ask_int(f"  Workers [{STATE['settings']['workers']}]: ",
                      STATE["settings"]["workers"], 1, 50)
    timeout = ask_int(f"  Timeout sec [{STATE['settings']['timeout']}]: ",
                      STATE["settings"]["timeout"], 3, 120)
    pdf_text = ask_yes("  Extract text from PDF links found? [y/N]: ", False)

    cfg = {
        "workers": workers, "timeout": timeout,
        "case_sensitive": case_s, "exact": exact,
        "context": ctx, "pdf_text": pdf_text, "pdf_max": 3,
    }

    warn("Ensure you are authorized to scan these targets.")
    if not ask_yes("  Continue? [y/N]: ", False):
        return
    run_keyword_scan(urls, keywords, cfg, "url_file_scan")

# ================================================================================
#  MODULE 3 — MULTIPLE KEYWORD SEARCH
# ================================================================================
def module_multi_keyword():
    hr("═")
    print(f"{C.B}{C.G}  [3] MULTIPLE KEYWORD SEARCH{C.RS}")
    hr("═")
    urls_raw = safe_input("  URLs (comma separated) OR file path: ")
    urls = []
    if os.path.isfile(urls_raw):
        try:
            with open(urls_raw, "r", encoding="utf-8", errors="ignore") as f:
                urls = [ln.strip() for ln in f if ln.strip()]
        except Exception as e:
            err(f"Cannot read file: {e}")
            return
    else:
        urls = [u.strip() for u in urls_raw.split(",") if u.strip()]
    urls = dedupe([normalize_url(u) for u in urls if normalize_url(u)])
    if not urls:
        warn("No valid URLs.")
        return

    inc = [k.strip() for k in safe_input("  Include keywords (comma): ").split(",") if k.strip()]
    exc = [k.strip() for k in safe_input("  Exclude keywords (comma): ").split(",") if k.strip()]
    mode = safe_input("  Logic [or/and] (default or): ", "or").lower()
    if mode not in ("or", "and"):
        mode = "or"

    case_s = ask_yes("  Case-sensitive? [y/N]: ", False)
    exact = ask_yes("  Whole-word / exact phrase? [y/N]: ", False)
    ctx = ask_int("  Context characters [100]: ", 100, 10, 500)
    workers = ask_int(f"  Workers [{STATE['settings']['workers']}]: ",
                      STATE["settings"]["workers"], 1, 50)
    timeout = ask_int(f"  Timeout sec [{STATE['settings']['timeout']}]: ",
                      STATE["settings"]["timeout"], 3, 120)

    cfg = {
        "workers": workers, "timeout": timeout,
        "case_sensitive": case_s, "exact": exact,
        "context": ctx, "pdf_text": False, "pdf_max": 0,
    }

    warn("Only public resources are fetched. Respect target ToS.")
    if not ask_yes("  Continue? [y/N]: ", False):
        return

    info(f"Fetching {len(urls)} URLs with logic='{mode}'...")
    pages = []

    def work(u):
        return scan_one_url(u, [], cfg)

    for u, rec in run_parallel(urls, work, workers, "fetch"):
        if rec:
            pages.append(rec)

    grouped = {}
    all_hits = []
    for p in pages:
        text = p.get("_text") or ""
        if not text:
            r = http_get(p["final_url"], timeout=timeout)
            if r is not None and r.status_code < 400:
                text = html_to_text(r.text)
        if not keyword_logic(text, inc, exc, mode):
            continue
        hits = find_matches(text, inc, case_s, ctx, exact)
        for h in hits:
            h["url"] = p["url"]
            all_hits.append(h)
            grouped.setdefault(h["keyword"], []).append(h)

    print()
    hr("─")
    for kw, hits in grouped.items():
        print(f"\n  {C.G}{C.B}{kw}{C.RS}  ({len(hits)} hits)")
        for h in hits[:8]:
            print(f"    {C.W}{h['url']}{C.RS}")
            print(f"    {C.GR}...{h['context'][:150]}...{C.RS}")

    if not grouped:
        warn("No matches found.")

    save_list("multi_keyword", all_hits)
    p = os.path.join(OUT_DIR, f"multi_keyword_{stamp()}.json")
    save_json_file(p, {"grouped": grouped, "all": all_hits})
    ok(f"Saved: {p}")
    if all_hits:
        pc = os.path.join(OUT_DIR, f"multi_keyword_{stamp()}.csv")
        save_csv_file(pc, all_hits, ["keyword", "url", "context"])
        ok(f"CSV:   {pc}")

    STATE["history"].append({
        "time": ts(), "module": "multi_keyword",
        "urls": len(urls), "include": inc, "exclude": exc,
        "matches": len(all_hits),
    })

# ================================================================================
#  MODULE 4 — SUBDOMAIN DISCOVERY
# ================================================================================
def crt_sh_subdomains(domain):
    out = set()
    try:
        r = http_get(f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json",
                     timeout=30)
        if r is not None and r.status_code == 200:
            data = json.loads(r.text)
            for row in data:
                for name in str(row.get("name_value", "")).split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith("." + domain) or name == domain:
                        out.add(name)
    except Exception as e:
        dbg(f"crt.sh fail: {e}")
    return out

def hackertarget_subdomains(domain):
    out = set()
    try:
        r = http_get(f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}",
                     timeout=30)
        if r is not None and r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.splitlines():
                if "," in line:
                    out.add(line.split(",")[0].strip().lower())
    except Exception as e:
        dbg(f"hackertarget fail: {e}")
    return out

def resolve_host(host):
    try:
        return sorted(set(socket.gethostbyname_ex(host)[2]))
    except Exception:
        return []

def module_subdomain_discovery():
    hr("═")
    print(f"{C.B}{C.G}  [4] SUBDOMAIN DISCOVERY (PASSIVE){C.RS}")
    hr("═")
    domain = safe_input("  Root domain (e.g. example.gov): ").strip().lower()
    domain = re.sub(r"^https?://", "", domain).strip("/").split("/")[0]
    if not domain or "." not in domain:
        err("Invalid domain.")
        return

    warn("Passive sources only: Certificate Transparency + public DNS APIs.")
    if not ask_yes("  Continue? [y/N]: ", False):
        return

    info("Querying Certificate Transparency (crt.sh)...")
    ct = crt_sh_subdomains(domain)
    ok(f"crt.sh: {len(ct)} unique names")

    info("Querying public hostsearch API...")
    ht = hackertarget_subdomains(domain)
    ok(f"hostsearch: {len(ht)} unique names")

    all_subs = dedupe(sorted(ct | ht))
    all_subs = [s for s in all_subs if s.endswith(domain)]

    if not all_subs:
        warn("No subdomains discovered.")
        return

    info(f"Resolving {len(all_subs)} hosts...")
    results = []

    def work(h):
        ips = resolve_host(h)
        return {"subdomain": h, "ips": ips, "resolved": bool(ips)}

    for host, rec in run_parallel(all_subs, work, STATE["settings"]["workers"], "dns"):
        if rec:
            results.append(rec)

    resolved = [r for r in results if r["resolved"]]
    print()
    info(f"Resolved: {len(resolved)} / {len(results)}")
    for r in resolved[:80]:
        print(f"  {C.G}•{C.RS} {C.W}{r['subdomain']:<45}{C.RS} "
              f"{C.DG}{', '.join(r['ips'][:3])}{C.RS}")

    save_list("subdomains", results)

    base = os.path.join(OUT_DIR, f"subdomains_{safe_name(domain)}_{stamp()}")
    save_txt_file(base + ".txt", [r["subdomain"] for r in results])
    save_csv_file(base + ".csv", results, ["subdomain", "resolved", "ips"])
    save_json_file(base + ".json", results)
    ok(f"Saved: {base}.txt / .csv / .json")

    STATE["history"].append({
        "time": ts(), "module": "subdomains",
        "domain": domain, "found": len(results), "resolved": len(resolved),
    })

# ================================================================================
#  MODULE 5 — DNS & WHOIS
# ================================================================================
def dns_query(domain, rtype):
    out = []
    if HAS_DNS:
        try:
            ans = dns.resolver.resolve(domain, rtype, lifetime=8)
            for r in ans:
                out.append(str(r).strip())
        except Exception as e:
            dbg(f"DNS {rtype} {domain}: {e}")
    return out

def whois_lookup(domain):
    if HAS_WHOIS:
        try:
            w = whois_lib.whois(domain)
            if w:
                return {k: (str(v) if not isinstance(v, list) else [str(x) for x in v])
                        for k, v in dict(w).items() if v}
        except Exception as e:
            dbg(f"whois lib fail: {e}")
    try:
        def query(server, q):
            with socket.create_connection((server, 43), timeout=10) as s:
                s.sendall((q + "\r\n").encode())
                buf = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                return buf.decode("utf-8", "ignore")

        raw = query("whois.iana.org", domain)
        ref = re.search(r"refer:\s*(\S+)", raw)
        if ref:
            raw = query(ref.group(1), domain)
        data = {}
        for line in raw.splitlines():
            if ":" in line and not line.startswith("%"):
                k, v = line.split(":", 1)
                data.setdefault(k.strip().lower(), []).append(v.strip())
        return data
    except Exception as e:
        dbg(f"whois socket fail: {e}")
    return {}

def module_dns_whois():
    hr("═")
    print(f"{C.B}{C.G}  [5] DNS & WHOIS LOOKUP{C.RS}")
    hr("═")
    domain = safe_input("  Domain (e.g. example.gov): ").strip().lower()
    domain = re.sub(r"^https?://", "", domain).strip("/").split("/")[0]
    if not domain:
        err("Invalid domain.")
        return

    rec = {"domain": domain, "records": {}, "whois": {}}
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    if not HAS_DNS:
        warn("dnspython not installed — A record via socket only. "
             "Install: pip install dnspython")

    for t in types:
        vals = dns_query(domain, t)
        if t == "A" and not vals:
            vals = resolve_host(domain)
        rec["records"][t] = vals
        if vals:
            print(f"  {C.G}{t:<6}{C.RS} {', '.join(vals[:5])}")
        else:
            print(f"  {C.GR}{t:<6} (none){C.RS}")

    info("Querying WHOIS (public data)...")
    w = whois_lookup(domain)
    rec["whois"] = w
    keys_show = ["registrar", "creation_date", "expiration_date", "updated_date",
                 "name_servers", "status", "org", "country"]
    for k in keys_show:
        if k in w:
            v = w[k]
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v[:4])
            print(f"  {C.G}{k:<16}{C.RS} {str(v)[:100]}")

    save_list("dns_whois", [rec])
    p = os.path.join(OUT_DIR, f"dns_whois_{safe_name(domain)}_{stamp()}.json")
    save_json_file(p, rec)
    ok(f"Saved: {p}")

    STATE["history"].append({"time": ts(), "module": "dns_whois", "domain": domain})

# ================================================================================
#  MODULE 6 — HTTP HEADER ANALYSIS
# ================================================================================
SECURITY_HEADERS = [
    "X-Frame-Options", "Content-Security-Policy",
    "Strict-Transport-Security", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection",
]

def module_header_analysis():
    hr("═")
    print(f"{C.B}{C.G}  [6] HTTP HEADER ANALYSIS{C.RS}")
    hr("═")
    url = normalize_url(safe_input("  URL: "))
    if not url:
        err("Invalid URL.")
        return

    r = http_get(url)
    if r is None:
        err("Request failed.")
        return

    print()
    info(f"Status: {r.status_code}  {r.reason}")
    info(f"Final URL: {r.url}")
    if r.history:
        print(f"  {C.Y}Redirects:{C.RS}")
        for h in r.history:
            print(f"    {h.status_code} → {h.url}")

    print()
    print(f"  {C.B}Response Headers{C.RS}")
    hr("·", 70, C.GR)
    for k, v in r.headers.items():
        print(f"  {C.G}{k:<28}{C.RS} {v[:140]}")

    print()
    print(f"  {C.B}Security Headers{C.RS}")
    hr("·", 70, C.GR)
    present, missing = [], []
    for h in SECURITY_HEADERS:
        val = r.headers.get(h)
        if val:
            print(f"  {C.G}[✔]{C.RS} {h}: {val[:90]}")
            present.append(h)
        else:
            print(f"  {C.R}[✘]{C.RS} {h}")
            missing.append(h)

    rec = {
        "url": url, "status": r.status_code, "final_url": r.url,
        "headers": dict(r.headers),
        "present_security": present, "missing_security": missing,
        "redirects": [h.url for h in r.history],
    }
    save_list("headers", [rec])
    p = os.path.join(OUT_DIR, f"headers_{stamp()}.json")
    save_json_file(p, rec)
    ok(f"Saved: {p}")
    STATE["history"].append({"time": ts(), "module": "headers", "url": url})

# ================================================================================
#  MODULE 7 — ROBOTS.TXT & SITEMAP SCANNER
# ================================================================================
def parse_sitemap(url, depth=0, seen=None, max_depth=3):
    seen = seen or set()
    if url in seen or depth > max_depth:
        return []
    seen.add(url)
    r = http_get(url, timeout=25)
    if r is None or r.status_code >= 400:
        return []
    content = r.text or ""
    locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", content, re.I | re.S)
    out = []
    is_index = "<sitemapindex" in content.lower()
    for loc in locs:
        loc = html.unescape(loc.strip())
        if is_index:
            out.extend(parse_sitemap(loc, depth + 1, seen, max_depth))
        else:
            out.append(loc)
    return out

def module_robots_sitemap():
    hr("═")
    print(f"{C.B}{C.G}  [7] ROBOTS.TXT & SITEMAP SCANNER{C.RS}")
    hr("═")
    url = normalize_url(safe_input("  Base URL: "))
    if not url:
        err("Invalid URL.")
        return
    p = urllib.parse.urlparse(url)
    base = f"{p.scheme}://{p.netloc}"

    robots_url = base + "/robots.txt"
    info(f"Fetching {robots_url}")
    r = http_get(robots_url)
    sitemaps = []
    disallow = []
    if r is not None and r.status_code == 200:
        print()
        print(f"  {C.B}robots.txt{C.RS}")
        hr("·", 70, C.GR)
        for line in r.text.splitlines()[:80]:
            print(f"  {C.GR}{line}{C.RS}")
            m = re.match(r"(?i)^sitemap:\s*(\S+)", line.strip())
            if m:
                sitemaps.append(m.group(1))
            m2 = re.match(r"(?i)^disallow:\s*(\S+)", line.strip())
            if m2 and m2.group(1) != "/":
                disallow.append(m2.group(1))
    else:
        warn("robots.txt not accessible.")

    if not sitemaps:
        sitemaps = [base + "/sitemap.xml"]
        info("No Sitemap directive — trying /sitemap.xml")

    all_urls = []
    for sm in dedupe(sitemaps):
        info(f"Parsing sitemap: {sm}")
        found = parse_sitemap(sm)
        ok(f"  {len(found)} URLs from {sm}")
        all_urls.extend(found)

    all_urls = dedupe(all_urls)
    print()
    info(f"Total unique URLs discovered: {len(all_urls)}")
    for u in all_urls[:40]:
        print(f"  {C.G}•{C.RS} {u[:120]}")
    if len(all_urls) > 40:
        print(f"  {C.GR}... {len(all_urls) - 40} more{C.RS}")

    rec = {"base": base, "robots_url": robots_url, "sitemaps": sitemaps,
           "disallow": disallow, "urls": all_urls}
    save_list("robots_sitemap", [rec])
    b = os.path.join(OUT_DIR, f"sitemap_{safe_name(p.netloc)}_{stamp()}")
    save_txt_file(b + ".txt", all_urls)
    save_json_file(b + ".json", rec)
    ok(f"Saved: {b}.txt / .json")
    STATE["history"].append({"time": ts(), "module": "sitemap", "base": base,
                             "urls": len(all_urls)})

# ================================================================================
#  MODULE 8 — PDF & DOCUMENT INTELLIGENCE
# ================================================================================
def download_pdf(url, dest_dir, max_mb=None):
    max_mb = max_mb or STATE["settings"]["max_pdf_mb"]
    max_b = max_mb * 1024 * 1024
    r = http_get(url, stream=True, timeout=40)
    if r is None:
        return None, "request failed"
    if r.status_code >= 400:
        return None, f"HTTP {r.status_code}"
    ct = content_type(r)
    if "pdf" not in ct and not url.lower().split("?")[0].endswith(".pdf"):
        return None, f"not pdf ({ct})"
    data = b""
    try:
        for chunk in r.iter_content(16384):
            data += chunk
            if len(data) > max_b:
                return None, f"exceeds {max_mb}MB limit"
    except Exception as e:
        return None, f"download error: {e}"
    if not data.startswith(b"%PDF"):
        return None, "invalid PDF signature"
    sha = hashlib.sha256(data).hexdigest()
    name = sha[:16] + "_" + safe_name(
        os.path.basename(urllib.parse.urlparse(url).path) or "doc.pdf")
    if not name.lower().endswith(".pdf"):
        name += ".pdf"
    path = os.path.join(dest_dir, name)
    if os.path.exists(path):
        return path, "already exists"
    try:
        with open(path, "wb") as f:
            f.write(data)
    except Exception as e:
        return None, f"write error: {e}"
    return path, sha

def pdf_metadata(path):
    if not HAS_FITZ:
        return {}
    try:
        doc = fitz.open(path)
        meta = doc.metadata or {}
        meta["pages"] = doc.page_count
        doc.close()
        return meta
    except Exception:
        return {}

def module_pdf_intelligence():
    hr("═")
    print(f"{C.B}{C.G}  [8] PDF & DOCUMENT INTELLIGENCE{C.RS}")
    hr("═")
    if not HAS_FITZ:
        warn("PyMuPDF not installed — text extraction disabled.")
        warn("Install: pip install pymupdf")

    url = normalize_url(safe_input("  Page URL to scan for PDFs: "))
    if not url:
        err("Invalid URL.")
        return

    r = http_get(url)
    if r is None:
        err("Request failed.")
        return

    links = extract_links(r.url, r.text)
    pdfs = dedupe([l for l in links if l.lower().split("?")[0].endswith(".pdf")])
    info(f"Found {len(pdfs)} PDF link(s) on page.")
    for p_ in pdfs[:40]:
        print(f"  {C.G}•{C.RS} {p_}")

    if not pdfs:
        return

    kw_raw = safe_input("  Keywords to search inside PDFs (comma, blank=skip): ")
    keywords = [k.strip() for k in kw_raw.split(",") if k.strip()]
    do_download = ask_yes("  Download PDFs for analysis? [y/N]: ", False)
    max_mb = ask_int(f"  Max PDF size MB [{STATE['settings']['max_pdf_mb']}]: ",
                     STATE["settings"]["max_pdf_mb"], 1, 500)

    pdf_dir = os.path.join(OUT_DIR, "pdfs")
    results = []

    def work(u):
        rec = {"url": u, "status": None, "size": None, "sha256": None,
               "metadata": {}, "matches": [], "path": None, "error": ""}
        rr = http_get(u, stream=True)
        if rr is None:
            rec["error"] = "request failed"
            return rec
        rec["status"] = rr.status_code
        rec["size"] = rr.headers.get("Content-Length")
        rec["content_type"] = content_type(rr)
        if do_download and rr.status_code < 400:
            path, res = download_pdf(u, pdf_dir, max_mb)
            if path:
                rec["path"] = path
                rec["sha256"] = res if res != "already exists" else None
                rec["metadata"] = pdf_metadata(path)
                if keywords and HAS_FITZ:
                    try:
                        doc = fitz.open(path)
                        text = "\n".join(pg.get_text() for pg in doc)
                        doc.close()
                        rec["matches"] = find_matches(text, keywords, False, 80, False)
                    except Exception as e:
                        rec["error"] = str(e)
            else:
                rec["error"] = res
        return rec

    for u, rec in run_parallel(pdfs, work, STATE["settings"]["workers"], "pdf"):
        if not rec:
            continue
        results.append(rec)
        tag = C.G if not rec["error"] else C.R
        print(f"\n  {tag}[{'OK' if not rec['error'] else 'FAIL'}]{C.RS} {u}")
        if rec["status"]:
            print(f"    status: {rec['status']}  size: {rec['size']}  "
                  f"type: {rec.get('content_type')}")
        if rec["sha256"]:
            print(f"    sha256: {rec['sha256']}")
        if rec["metadata"]:
            m = rec["metadata"]
            print(f"    title:  {m.get('title', '')}")
            print(f"    author: {m.get('author', '')}")
            print(f"    pages:  {m.get('pages', '')}")
        for mt in rec["matches"][:5]:
            print(f"    {C.Y}kw:{C.RS} {mt['keyword']} — ...{mt['context'][:100]}...")

    save_list("pdf_intel", results)
    p = os.path.join(OUT_DIR, f"pdf_intel_{stamp()}.json")
    save_json_file(p, results)
    ok(f"Saved: {p}")

    if do_download:
        hashes = [r["sha256"] for r in results if r["sha256"]]
        dups = {h for h in hashes if hashes.count(h) > 1}
        if dups:
            warn(f"Duplicate documents detected by SHA-256: {len(dups)}")
            for d in dups:
                print(f"  {C.Y}dup:{C.RS} {d}")

    STATE["history"].append({"time": ts(), "module": "pdf_intel",
                             "url": url, "pdfs": len(pdfs)})

# ================================================================================
#  MODULE 9 — TECHNOLOGY DETECTION
# ================================================================================
TECH_HEADER_SIGS = {
    "server": [
        ("nginx", "Nginx"), ("apache", "Apache HTTP Server"),
        ("iis", "Microsoft IIS"), ("cloudflare", "Cloudflare"),
        ("openresty", "OpenResty"), ("litespeed", "LiteSpeed"),
        ("caddy", "Caddy"), ("gunicorn", "Gunicorn"),
    ],
    "x-powered-by": [
        ("php", "PHP"), ("asp.net", "ASP.NET"), ("express", "Express.js"),
        ("servlet", "Java Servlet"), ("next.js", "Next.js"),
    ],
    "via": [("cloudfront", "Amazon CloudFront"), ("varnish", "Varnish")],
    "x-generator": [("wordpress", "WordPress"), ("drupal", "Drupal")],
}

TECH_HTML_SIGS = [
    ("wp-content", "WordPress"), ("wp-includes", "WordPress"),
    ("/sites/default/files", "Drupal"), ("joomla", "Joomla"),
    ("_next/", "Next.js"), ("__nuxt__", "Nuxt.js"),
    ("ng-version", "Angular"), ("data-reactroot", "React"),
    ("jquery", "jQuery"), ("bootstrap", "Bootstrap"),
    ("vue.js", "Vue.js"), ("shopify", "Shopify"),
    ("googletagmanager", "Google Tag Manager"),
    ("google-analytics", "Google Analytics"),
    ("cdn.jsdelivr", "jsDelivr"), ("font-awesome", "Font Awesome"),
    ("cloudflare", "Cloudflare"), ("recaptcha", "Google reCAPTCHA"),
    ("wix.com", "Wix"), ("squarespace", "Squarespace"),
]

def module_tech_detect():
    hr("═")
    print(f"{C.B}{C.G}  [9] TECHNOLOGY DETECTION{C.RS}")
    hr("═")
    url = normalize_url(safe_input("  URL: "))
    if not url:
        err("Invalid URL.")
        return

    r = http_get(url)
    if r is None:
        err("Request failed.")
        return

    found = {}
    hl = {k.lower(): (v or "").lower() for k, v in r.headers.items()}
    for hk, sigs in TECH_HEADER_SIGS.items():
        val = hl.get(hk, "")
        for needle, name in sigs:
            if needle in val:
                found.setdefault(name, []).append(f"header:{hk}")

    body = (r.text or "").lower()
    for needle, name in TECH_HTML_SIGS:
        if needle in body:
            found.setdefault(name, []).append("html")

    print()
    if found:
        info(f"Detected {len(found)} technologies:")
        for name, src in sorted(found.items()):
            print(f"  {C.G}[+]{C.RS} {C.W}{name:<22}{C.RS} "
                  f"{C.GR}({', '.join(sorted(set(src)))}){C.RS}")
    else:
        warn("No technologies detected from public signals.")

    rec = {"url": url, "technologies": {k: sorted(set(v)) for k, v in found.items()},
           "server": r.headers.get("Server", ""),
           "powered_by": r.headers.get("X-Powered-By", "")}
    save_list("tech", [rec])
    p = os.path.join(OUT_DIR, f"tech_{stamp()}.json")
    save_json_file(p, rec)
    ok(f"Saved: {p}")
    STATE["history"].append({"time": ts(), "module": "tech", "url": url,
                             "found": list(found.keys())})

# ================================================================================
#  MODULE 10 — SSL CERTIFICATE ANALYSIS
# ================================================================================
def get_cert_info(host, port=443):
    if not HAS_SSL:
        return {}
    try:
        ctx = ssl_lib.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_lib.CERT_NONE
        with socket.create_connection((host, port), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {"cert": cert or {}, "cipher": cipher, "tls": version}
    except Exception as e:
        dbg(f"ssl fail: {e}")
        return {}

def module_ssl_analysis():
    hr("═")
    print(f"{C.B}{C.G}  [10] SSL CERTIFICATE ANALYSIS{C.RS}")
    hr("═")
    host = safe_input("  Host (e.g. example.gov): ").strip().lower()
    host = re.sub(r"^https?://", "", host).strip("/").split("/")[0].split(":")[0]
    if not host:
        err("Invalid host.")
        return

    info(f"Connecting to {host}:443 ...")
    data = get_cert_info(host)
    if not data:
        err("Could not retrieve certificate.")
        return

    cert = data.get("cert", {})
    print()
    print(f"  {C.B}TLS{C.RS}")
    hr("·", 70, C.GR)
    print(f"  {C.G}{'Protocol':<16}{C.RS} {data.get('tls')}")
    cipher = data.get("cipher") or ()
    if cipher:
        print(f"  {C.G}{'Cipher':<16}{C.RS} {cipher[0]}")
        print(f"  {C.G}{'Bits':<16}{C.RS} {cipher[2] if len(cipher) > 2 else '?'}")

    print()
    print(f"  {C.B}Subject / Issuer{C.RS}")
    hr("·", 70, C.GR)

    def flat(name):
        out = []
        for part in name or ():
            for k, v in part:
                out.append(f"{k}={v}")
        return ", ".join(out)

    print(f"  {C.G}{'Subject':<16}{C.RS} {flat(cert.get('subject'))}")
    print(f"  {C.G}{'Issuer':<16}{C.RS} {flat(cert.get('issuer'))}")

    nbf = cert.get("notBefore")
    naf = cert.get("notAfter")
    print(f"  {C.G}{'Valid from':<16}{C.RS} {nbf}")
    print(f"  {C.G}{'Valid until':<16}{C.RS} {naf}")

    remaining = None
    if naf:
        try:
            exp = datetime.datetime.strptime(naf, "%b %d %H:%M:%S %Y %Z")
            delta = exp - datetime.datetime.utcnow()
            remaining = delta.days
            col = C.G if remaining > 30 else (C.Y if remaining > 7 else C.R)
            print(f"  {C.G}{'Remaining':<16}{C.RS} {col}{remaining} day(s){C.RS}")
        except Exception:
            pass

    sans = []
    for t, v in cert.get("subjectAltName", ()) or ():
        if t.lower() == "dns":
            sans.append(v)
    if sans:
        print(f"  {C.G}{'SANs':<16}{C.RS} {', '.join(sans[:10])}")

    rec = {"host": host, "tls": data.get("tls"), "cipher": cipher,
           "subject": flat(cert.get("subject")), "issuer": flat(cert.get("issuer")),
           "not_before": nbf, "not_after": naf,
           "remaining_days": remaining, "sans": sans}
    save_list("ssl", [rec])
    p = os.path.join(OUT_DIR, f"ssl_{safe_name(host)}_{stamp()}.json")
    save_json_file(p, rec)
    ok(f"Saved: {p}")
    STATE["history"].append({"time": ts(), "module": "ssl", "host": host})

# ================================================================================
#  MODULE 11 — VERIFY PDF URLs
# ================================================================================
def module_verify_pdfs():
    hr("═")
    print(f"{C.B}{C.G}  [11] VERIFY PDF URLs{C.RS}")
    hr("═")

    urls = []
    if STATE["pdf_urls"]:
        info(f"{len(STATE['pdf_urls'])} PDF URL(s) already in session.")
        if ask_yes("  Use session PDF URLs? [Y/n]: ", True):
            urls = list(STATE["pdf_urls"])

    if not urls:
        src = safe_input("  URL list file OR single URL: ").strip()
        if not src:
            err("Nothing to verify.")
            return
        if os.path.isfile(src):
            try:
                with open(src, "r", encoding="utf-8", errors="ignore") as f:
                    urls = [ln.strip() for ln in f if ln.strip()]
            except Exception as e:
                err(f"Cannot read: {e}")
                return
        else:
            urls = [src]

    urls = dedupe([normalize_url(u) for u in urls if normalize_url(u)])
    if not urls:
        warn("No valid URLs.")
        return

    results = []

    def work(u):
        rec = {"url": u, "status": None, "content_type": "", "size": None,
               "is_pdf": False, "error": ""}
        r = http_get(u, method="HEAD")
        if r is None or r.status_code >= 400:
            r = http_get(u, stream=True)
        if r is None:
            rec["error"] = "request failed"
            return rec
        rec["status"] = r.status_code
        rec["content_type"] = content_type(r)
        rec["size"] = r.headers.get("Content-Length")
        rec["is_pdf"] = ("pdf" in rec["content_type"]
                         or u.lower().split("?")[0].endswith(".pdf"))
        return rec

    for u, rec in run_parallel(urls, work, STATE["settings"]["workers"], "verify"):
        if not rec:
            continue
        results.append(rec)
        col = C.G if rec["is_pdf"] and (rec["status"] or 0) < 400 else C.Y
        print(f"  {col}[{rec['status']}]{C.RS} {u[:100]}  "
              f"{C.GR}{rec['content_type']}{C.RS}")

    good = [r for r in results if r["is_pdf"] and (r["status"] or 0) < 400]
    bad = [r for r in results if r not in good]
    print()
    info(f"Valid PDFs: {len(good)}   Invalid/other: {len(bad)}")

    save_list("pdf_verify", results)
    p = os.path.join(OUT_DIR, f"pdf_verify_{stamp()}.json")
    save_json_file(p, results)
    ok(f"Saved: {p}")

    for r in good:
        if r["url"] not in STATE["pdf_urls"]:
            STATE["pdf_urls"].append(r["url"])

    STATE["history"].append({"time": ts(), "module": "verify_pdfs",
                             "checked": len(results), "valid": len(good)})

# ================================================================================
#  MODULE 12 — DOWNLOAD PDFs
# ================================================================================
def module_download_pdfs():
    hr("═")
    print(f"{C.B}{C.G}  [12] DOWNLOAD PDFs{C.RS}")
    hr("═")

    urls = list(STATE["pdf_urls"])
    if urls:
        info(f"{len(urls)} PDF URL(s) in session.")
    else:
        warn("No PDF URLs in session. Add them or run verification first.")

    src = safe_input("  Extra URL/file (blank=session only): ").strip()
    if src:
        if os.path.isfile(src):
            try:
                with open(src, "r", encoding="utf-8", errors="ignore") as f:
                    urls.extend(ln.strip() for ln in f if ln.strip())
            except Exception as e:
                err(f"Cannot read: {e}")
        else:
            urls.append(src)

    urls = dedupe([normalize_url(u) for u in urls if normalize_url(u)])
    if not urls:
        warn("Nothing to download.")
        return

    max_mb = ask_int(f"  Max file size MB [{STATE['settings']['max_pdf_mb']}]: ",
                     STATE["settings"]["max_pdf_mb"], 1, 500)
    workers = ask_int(f"  Workers [{min(4, STATE['settings']['workers'])}]: ",
                      min(4, STATE["settings"]["workers"]), 1, 16)

    warn("Only download public documents you are authorized to retrieve.")
    if not ask_yes("  Continue? [y/N]: ", False):
        return

    pdf_dir = os.path.join(OUT_DIR, "pdfs")
    results = []

    def work(u):
        path, res = download_pdf(u, pdf_dir, max_mb)
        return {"url": u, "path": path, "result": res}

    for u, rec in run_parallel(urls, work, workers, "download"):
        if not rec:
            continue
        results.append(rec)
        if rec["path"]:
            print(f"  {C.G}[+] {C.RS}{rec['path']}")
        else:
            print(f"  {C.R}[x] {C.RS}{u} — {rec['result']}")

    save_list("pdf_download", results)
    ok(f"Downloaded/skipped: {len(results)}")
    p = os.path.join(OUT_DIR, f"pdf_download_{stamp()}.json")
    save_json_file(p, results)
    ok(f"Saved: {p}")
    STATE["history"].append({"time": ts(), "module": "download_pdfs",
                             "count": len(results)})

# ================================================================================
#  MODULE 13 — VIEW SEARCH RESULTS
# ================================================================================
def module_view_results():
    hr("═")
    print(f"{C.B}{C.G}  [13] VIEW SEARCH RESULTS{C.RS}")
    hr("═")
    if not STATE["results"]:
        warn("No results in current session.")
        return
    for module, records in STATE["results"].items():
        print(f"  {C.G}{module:<20}{C.RS} {len(records)} record(s)")
    print()
    which = safe_input("  Module name (blank = summary only): ").strip()
    if not which:
        return
    recs = STATE["results"].get(which)
    if recs is None:
        err("Unknown module.")
        return
    for i, r in enumerate(recs[:50], 1):
        print(f"\n  {C.G}[{i}]{C.RS} "
              f"{json.dumps(r, indent=2, default=str)[:1200]}")
    if len(recs) > 50:
        print(f"\n  {C.GR}... {len(recs) - 50} more records{C.RS}")

# ================================================================================
#  MODULE 14 — EXPORT REPORTS
# ================================================================================
HTML_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>GOV RECON PRO v2.0 — Report</title>
<style>
body{background:#050a05;color:#7CFC7C;font-family:Consolas,monospace;padding:20px;}
h1,h2{color:#39FF14;text-shadow:0 0 8px #39FF14;}
table{border-collapse:collapse;width:100%;margin:12px 0;}
th,td{border:1px solid #1f3d1f;padding:6px 8px;text-align:left;font-size:12px;}
th{background:#0d1f0d;color:#39FF14;}
tr:nth-child(even){background:#0a160a;}
input{background:#0a160a;color:#7CFC7C;border:1px solid #1f3d1f;padding:6px;width:300px;}
.small{color:#4c7a4c;font-size:11px;}
</style></head><body>
<h1>&gt;&gt; GOV RECON PRO v2.0 — RECON REPORT</h1>
<div class="small">Generated: __GENERATED__</div>
<p>Filter: <input id="f" onkeyup="filterRows()" placeholder="type to filter tables..."></p>
__BODY__
<script>
function filterRows(){
  var v=document.getElementById('f').value.toLowerCase();
  document.querySelectorAll('table').forEach(function(t){
    t.querySelectorAll('tbody tr').forEach(function(r){
      r.style.display = r.innerText.toLowerCase().indexOf(v)>-1 ? '' : 'none';
    });
  });
}
</script>
</body></html>"""

def _html_table(rows, fields):
    out = ["<table><thead><tr>"]
    for f in fields:
        out.append("<th>%s</th>" % html.escape(str(f)))
    out.append("</tr></thead><tbody>")
    for r in rows:
        out.append("<tr>")
        for f in fields:
            out.append("<td>%s</td>" % html.escape(str(r.get(f, ""))[:400]))
        out.append("</tr>")
    out.append("</tbody></table>")
    return "".join(out)

def build_html_report():
    parts = []
    parts.append("<h2>Session Summary</h2>")
    total_records = sum(len(v) for v in STATE["results"].values())
    parts.append("<p>Modules with data: %d &nbsp;|&nbsp; Total records: %d</p>"
                 % (len(STATE["results"]), total_records))

    for module, records in STATE["results"].items():
        if not records:
            continue
        parts.append("<h2>%s (%d)</h2>" % (html.escape(module), len(records)))
        if isinstance(records[0], dict):
            fields = []
            for r in records[:20]:
                for k in r.keys():
                    if k not in fields:
                        fields.append(k)
            parts.append(_html_table(records, fields[:12]))
        else:
            parts.append("<pre>%s</pre>" % html.escape(str(records[:50])))

    if STATE["history"]:
        parts.append("<h2>History</h2>")
        parts.append(_html_table(
            STATE["history"],
            ["time", "module", "query", "urls", "results", "matches"]))

    return HTML_TEMPLATE.replace("__GENERATED__", ts()).replace(
        "__BODY__", "\n".join(parts))

def module_export_reports():
    hr("═")
    print(f"{C.B}{C.G}  [14] EXPORT REPORTS{C.RS}")
    hr("═")
    if not STATE["results"] and not STATE["history"]:
        warn("Nothing to export.")
        return

    print("  1. JSON")
    print("  2. CSV")
    print("  3. HTML")
    print("  4. TXT")
    print("  5. ALL")
    ch = safe_input("  Choice [5]: ", "5")

    base = os.path.join(OUT_DIR, "reports", f"report_{stamp()}")

    if ch in ("1", "5"):
        p = base + ".json"
        save_json_file(p, {"generated": ts(), "results": STATE["results"],
                           "history": STATE["history"]})
        ok(f"JSON:  {p}")

    if ch in ("2", "5"):
        p = base + ".csv"
        try:
            with open(p, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["module", "record"])
                for m, recs in STATE["results"].items():
                    for r in recs:
                        w.writerow([m, json.dumps(r, default=str)])
            ok(f"CSV:   {p}")
        except Exception as e:
            err(f"CSV failed: {e}")

    if ch in ("3", "5"):
        p = base + ".html"
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write(build_html_report())
            ok(f"HTML:  {p}")
        except Exception as e:
            err(f"HTML failed: {e}")

    if ch in ("4", "5"):
        p = base + ".txt"
        lines = [f"GOV RECON PRO v2.0 — Report — {ts()}", "=" * 60]
        for m, recs in STATE["results"].items():
            lines.append(f"\n[{m}] {len(recs)} record(s)")
            for r in recs[:200]:
                lines.append(json.dumps(r, default=str)[:400])
        lines.append("\n[HISTORY]")
        for h in STATE["history"]:
            lines.append(json.dumps(h, default=str))
        save_txt_file(p, lines)
        ok(f"TXT:   {p}")

# ================================================================================
#  MODULE 15 — SEARCH HISTORY
# ================================================================================
def module_history():
    hr("═")
    print(f"{C.B}{C.G}  [15] SEARCH HISTORY{C.RS}")
    hr("═")
    print("  1. View history")
    print("  2. Clear history")
    print("  3. Save session now")
    print("  4. Load session")
    ch = safe_input("  Choice: ")

    if ch == "1":
        if not STATE["history"]:
            warn("History empty.")
            return
        for i, h in enumerate(STATE["history"], 1):
            print(f"  {C.G}{i:>3}.{C.RS} {h.get('time')}  "
                  f"{C.CY}{h.get('module')}{C.RS}  "
                  f"{ {k: v for k, v in h.items() if k not in ('time', 'module')} }")

    elif ch == "2":
        if ask_yes("  Really clear history? [y/N]: ", False):
            STATE["history"].clear()
            ok("History cleared.")

    elif ch == "3":
        save_session()

    elif ch == "4":
        load_session()

# ================================================================================
#  MODULE 16 — PERFORMANCE SETTINGS
# ================================================================================
def module_settings():
    hr("═")
    print(f"{C.B}{C.G}  [16] PERFORMANCE SETTINGS{C.RS}")
    hr("═")
    s = STATE["settings"]
    print(f"  1. Workers            : {s['workers']}")
    print(f"  2. Timeout (sec)      : {s['timeout']}")
    print(f"  3. Retries            : {s['retries']}")
    print(f"  4. Rate limit (sec)   : {s['rate_limit']}")
    print(f"  5. Max PDF size (MB)  : {s['max_pdf_mb']}")
    print(f"  6. Verify SSL         : {s['verify_ssl']}")
    print(f"  7. Response cache     : {s['cache']}")
    print(f"  8. Debug logging      : {s['debug']}")
    print("  0. Back")
    ch = safe_input("  Change which? ")
    if ch == "1":
        s["workers"] = ask_int("  Workers: ", s["workers"], 1, 100)
    elif ch == "2":
        s["timeout"] = ask_int("  Timeout: ", s["timeout"], 3, 180)
    elif ch == "3":
        s["retries"] = ask_int("  Retries: ", s["retries"], 0, 10)
    elif ch == "4":
        v = safe_input("  Rate limit (0 = off): ", str(s["rate_limit"]))
        try:
            s["rate_limit"] = max(0.0, float(v))
        except Exception:
            pass
    elif ch == "5":
        s["max_pdf_mb"] = ask_int("  Max PDF MB: ", s["max_pdf_mb"], 1, 500)
    elif ch == "6":
        s["verify_ssl"] = ask_yes("  Verify SSL? [y/N]: ", s["verify_ssl"])
    elif ch == "7":
        s["cache"] = ask_yes("  Enable cache? [Y/n]: ", s["cache"])
    elif ch == "8":
        s["debug"] = ask_yes("  Debug logging? [y/N]: ", s["debug"])
    else:
        return
    ok("Settings updated.")

# ================================================================================
#  MODULE 17 — HELP & DEPENDENCIES
# ================================================================================
def module_help():
    hr("═")
    print(f"{C.B}{C.G}  [17] HELP & DEPENDENCIES{C.RS}")
    hr("═")
    deps = [
        ("requests", HAS_REQUESTS, "HTTP engine (REQUIRED)"),
        ("beautifulsoup4", HAS_BS4, "HTML parsing (recommended)"),
        ("dnspython", HAS_DNS, "DNS record lookup (recommended)"),
        ("python-whois", HAS_WHOIS, "WHOIS lookups (optional)"),
        ("PyMuPDF", HAS_FITZ, "PDF text extraction (optional)"),
    ]
    print(f"  {C.B}Dependency status{C.RS}")
    hr("·", 70, C.GR)
    missing = []
    for name, has, desc in deps:
        mark = f"{C.G}[✔]{C.RS}" if has else f"{C.R}[✘]{C.RS}"
        print(f"  {mark} {name:<16} {C.GR}{desc}{C.RS}")
        if not has:
            missing.append(name)

    if missing:
        print()
        warn("Install missing packages with:")
        print(f"  {C.CY}pip install requests beautifulsoup4 dnspython "
              f"python-whois pymupdf{C.RS}")

    print()
    print(f"  {C.B}Search engine coverage (Option 1){C.RS}")
    hr("·", 70, C.GR)
    for cat in CATEGORIES:
        keys = _engines_by_category(cat)
        print(f"  {C.G}{cat:<10}{C.RS} {len(keys)} engines: {', '.join(keys)}")

    print()
    print(f"  {C.B}Usage notes{C.RS}")
    hr("·", 70, C.GR)
    print("  • Only scan public information you are authorized to access.")
    print("  • Respect robots.txt, rate limits, and site terms of service.")
    print("  • No exploitation, no auth bypass, no brute force.")
    print("  • Some engines require API keys or block scraped queries "
          "(e.g. Shodan, Censys, VT, Kagi).")
    print("  • Output directory:", OUT_DIR)
    print("  • Version: 2.0")
    print("  • Python :", sys.version.split()[0])

# ================================================================================
#  SESSION MANAGEMENT
# ================================================================================
def save_session():
    data = {"saved": ts(), "settings": STATE["settings"],
            "results": STATE["results"], "history": STATE["history"],
            "pdf_urls": STATE["pdf_urls"]}
    if save_json_file(STATE["session_file"], data):
        ok(f"Session saved: {STATE['session_file']}")

def load_session():
    if not os.path.isfile(STATE["session_file"]):
        warn("No saved session found.")
        return
    try:
        with open(STATE["session_file"], "r", encoding="utf-8") as f:
            data = json.load(f)
        STATE["settings"].update(data.get("settings", {}))
        STATE["results"] = data.get("results", {})
        STATE["history"] = data.get("history", [])
        STATE["pdf_urls"] = data.get("pdf_urls", [])
        ok(f"Session loaded ({len(STATE['results'])} modules).")
    except Exception as e:
        err(f"Load failed: {e}")

def autosave_loop():
    while STATE["running"]:
        time.sleep(120)
        if STATE["running"] and (STATE["results"] or STATE["history"]):
            try:
                save_session()
            except Exception:
                pass

# ================================================================================
#  UI
# ================================================================================
BANNER = r"""
 ██████╗  ██████╗ ██╗   ██╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔════╝ ██╔═══██╗██║   ██║    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║  ███╗██║   ██║╚██╗ ██╔╝    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║   ██║██║   ██║ ╚████╔╝     ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚██████╔╝╚██████╔╝  ╚██╔╝      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝  ╚═════╝    ╚═╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                P R O   v 2 . 0   //   O S I N T   F R A M E W O R K
"""

def boot_sequence():
    if os.environ.get("GOVRECON_NO_BOOT") == "1":
        return
    print(C.G + BANNER + C.RS)
    steps = [
        "loading kernel modules ......... OK",
        "initializing http engine ....... OK",
        "mounting recon workspace ....... OK",
        "loading signature database ..... OK",
        "arming passive collectors ...... OK",
        "operator identity: anonymous",
    ]
    for s in steps:
        sys.stdout.write(f"{C.DG}[boot]{C.RS} {s}")
        sys.stdout.flush()
        time.sleep(0.04)
        print()
    print(f"{C.DG}[boot]{C.RS} {C.G}system ready — awaiting operator input{C.RS}\n")

def show_menu():
    print()
    hr("═")
    print(f"{C.B}{C.G}   GOV RECON PRO v2.0 — MAIN CONSOLE{C.RS}")
    hr("═")
    items = [
        ("1",  "Advanced Web Search (multi-engine)"),
        ("2",  "Scan URLs from Text File"),
        ("3",  "Multiple Keyword Search"),
        ("4",  "Subdomain Discovery"),
        ("5",  "DNS & WHOIS Lookup"),
        ("6",  "HTTP Header Analysis"),
        ("7",  "Robots.txt & Sitemap Scanner"),
        ("8",  "PDF & Document Intelligence"),
        ("9",  "Technology Detection"),
        ("10", "SSL Certificate Analysis"),
        ("11", "Verify PDF URLs"),
        ("12", "Download PDFs"),
        ("13", "View Search Results"),
        ("14", "Export Reports"),
        ("15", "Search History / Session"),
        ("16", "Performance Settings"),
        ("17", "Help & Dependencies"),
        ("0",  "Exit"),
    ]
    for k, v in items:
        print(f"  {C.G}[{k:>2}]{C.RS} {v}")
    hr("═")

MENU = {
    "1": module_web_search,
    "2": module_url_file_scan,
    "3": module_multi_keyword,
    "4": module_subdomain_discovery,
    "5": module_dns_whois,
    "6": module_header_analysis,
    "7": module_robots_sitemap,
    "8": module_pdf_intelligence,
    "9": module_tech_detect,
    "10": module_ssl_analysis,
    "11": module_verify_pdfs,
    "12": module_download_pdfs,
    "13": module_view_results,
    "14": module_export_reports,
    "15": module_history,
    "16": module_settings,
    "17": module_help,
}

# ================================================================================
#  MAIN
# ================================================================================
def main():
    ensure_dirs()
    print(f"{C.G}┌────────────────────────────────────────────────────────────┐{C.RS}")
    print(f"{C.G}│{C.RS}  GOV RECON PRO v2.0  —  PUBLIC INFORMATION OSINT          {C.G}│{C.RS}")
    print(f"{C.G}│{C.RS}  Authorized use only. Respect ToS, robots.txt, and law.   {C.G}│{C.RS}")
    print(f"{C.G}└────────────────────────────────────────────────────────────┘{C.RS}")

    boot_sequence()

    if not HAS_REQUESTS:
        err("The 'requests' library is required. Install: pip install requests")
        sys.exit(1)

    t = threading.Thread(target=autosave_loop, daemon=True)
    t.start()

    while True:
        try:
            show_menu()
            ch = safe_input(
                f"{C.G}└─[gov-recon@{socket.gethostname()}]─> {C.RS}")
            if ch in ("0", "q", "quit", "exit"):
                break
            fn = MENU.get(ch)
            if not fn:
                warn("Invalid option.")
                continue
            print()
            fn()
        except KeyboardInterrupt:
            print()
            warn("Interrupted — preserving collected results...")
            try:
                save_session()
            except Exception:
                pass
            break
        except Exception as e:
            err(f"Unhandled error: {e}")
            dbg(str(e))
            if STATE["settings"].get("debug"):
                import traceback
                traceback.print_exc()

    STATE["running"] = False
    if STATE["results"] or STATE["history"]:
        try:
            save_session()
        except Exception:
            pass

    print()
    hr("═")
    print(f"{C.G}  [!] Session terminated. Collected intel saved to:{C.RS}")
    print(f"      {OUT_DIR}")
    print(f"{C.G}  [!] Stay legal, stay ethical.{C.RS}")
    hr("═")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Aborted.")
        sys.exit(0)