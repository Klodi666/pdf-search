
#!/usr/bin/env python3
"""
PDF FINDER PRO - Python 3

Features:
- Search 13 public search engines
- Search multiple pages and query variations
- Find PDF links on search-result pages
- Scan a text file containing URLs
- Verify PDF URLs
- Download PDFs with a size limit
- Export JSON, CSV, HTML, or all formats
- Choose the output folder and filename
- Preserve collected results after Ctrl+C
- Log errors to pdf_finder_output/debug.log

Install:
    python3 -m pip install requests beautifulsoup4
"""

import csv
import hashlib
import html
import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import (
    urljoin, urlparse, parse_qs, unquote
)

import requests
from bs4 import BeautifulSoup


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "PDF FINDER PRO"

OUTPUT_DIR = Path("pdf_finder_output")
DOWNLOAD_DIR = OUTPUT_DIR / "downloads"
LOG_FILE = OUTPUT_DIR / "debug.log"

REQUEST_TIMEOUT = 20
MAX_PAGE_BYTES = 5 * 1024 * 1024
MAX_PDF_BYTES = 100 * 1024 * 1024

DEFAULT_PAGES = 3
DEFAULT_DELAY = 0.8

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

SEARCH_ENGINES = [
    "Bing",
    "DuckDuckGo",
    "Brave",
    "Yahoo",
    "Startpage",
    "Ecosia",
    "Qwant",
    "Naver",
    "Seznam",
    "Perplexity",
    "Kagi",
    "Yandex",
    "Baidu",
]

# Public HTML search pages. These are not official APIs.
# Page layouts and availability can change at any time.
ENGINE_CONFIG = {
    "Bing": {
        "url": "https://www.bing.com/search",
        "param": "q",
        "page_param": "first",
        "page_start": 1,
        "page_step": 10,
        "selectors": ["li.b_algo h2 a", "li.b_algo a"],
    },
    "DuckDuckGo": {
        "url": "https://html.duckduckgo.com/html/",
        "param": "q",
        "selectors": ["a.result__a", "a.result-link"],
        "alternates": ["https://lite.duckduckgo.com/lite/"],
    },
    "Brave": {
        "url": "https://search.brave.com/search",
        "param": "q",
        "page_param": "offset",
        "page_start": 0,
        "page_step": 1,
        "selectors": [
            "a.heading-serpresult",
            "a.snippet-title",
            "div.snippet a[href]",
        ],
    },
    "Yahoo": {
        "url": "https://search.yahoo.com/search",
        "param": "p",
        "page_param": "b",
        "page_start": 1,
        "page_step": 10,
        "selectors": ["h3 a", "div.algo a"],
    },
    "Startpage": {
        "url": "https://www.startpage.com/sp/search",
        "param": "query",
        "page_param": "page",
        "page_start": 1,
        "page_step": 1,
        "selectors": ["a.result-link", "a.w-gl__result-title"],
    },
    "Ecosia": {
        "url": "https://www.ecosia.org/search",
        "param": "q",
        "page_param": "p",
        "page_start": 0,
        "page_step": 1,
        "selectors": ["a.result-title", "main a[href]"],
    },
    "Qwant": {
        "url": "https://www.qwant.com/",
        "param": "q",
        "page_param": "page",
        "page_start": 1,
        "page_step": 1,
        "selectors": ["a[href]"],
    },
    "Naver": {
        "url": "https://search.naver.com/search.naver",
        "param": "query",
        "page_param": "start",
        "page_start": 1,
        "page_step": 10,
        "selectors": ["a.link_tit", "a.title_link"],
    },
    "Seznam": {
        "url": "https://search.seznam.cz/",
        "param": "q",
        "page_param": "page",
        "page_start": 1,
        "page_step": 1,
        "selectors": ["h3 a"],
    },
    "Perplexity": {
        "url": "https://www.perplexity.ai/search",
        "param": "q",
        "selectors": ["a[href]"],
    },
    "Kagi": {
        "url": "https://kagi.com/search",
        "param": "q",
        "selectors": [
            "a.__sri_title_link",
            "div.search-result a[href]",
        ],
    },
    "Yandex": {
        "url": "https://yandex.com/search/",
        "param": "text",
        "page_param": "p",
        "page_start": 0,
        "page_step": 1,
        "selectors": ["a.Link", "a.OrganicTitle-Link"],
    },
    "Baidu": {
        "url": "https://www.baidu.com/s",
        "param": "wd",
        "page_param": "pn",
        "page_start": 0,
        "page_step": 10,
        "selectors": ["h3 a"],
    },
}

SEARCH_HOSTS = {
    "bing.com",
    "duckduckgo.com",
    "brave.com",
    "yahoo.com",
    "startpage.com",
    "ecosia.org",
    "qwant.com",
    "naver.com",
    "seznam.cz",
    "perplexity.ai",
    "kagi.com",
    "yandex.com",
    "yandex.ru",
    "baidu.com",
}

PDF_PATTERN = re.compile(r"\.pdf(?:$|[?#&])", re.IGNORECASE)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    encoding="utf-8",
)

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})


# ============================================================
# CONSOLE HELPERS
# ============================================================

def banner():
    print("=" * 72)
    print("                         PDF FINDER PRO")
    print("                  Public web PDF search utility")
    print("=" * 72)
    print("Respect website terms and request limits.")
    print("Press Ctrl+C during an operation to stop it.")
    print("Collected results can then be saved.")
    print()


def safe_input(prompt, default=""):
    try:
        value = input(prompt)
        return value.strip() if value.strip() else default
    except (KeyboardInterrupt, EOFError):
        print("\nInput cancelled.")
        return default


def ask_yes_no(prompt, default=False):
    suffix = " [Y/n]: " if default else " [y/N]: "
    answer = safe_input(prompt + suffix).lower()

    if not answer:
        return default

    return answer in ("y", "yes", "1", "true")


def ask_int(prompt, default, minimum=1, maximum=100):
    value = safe_input(f"{prompt} [{default}]: ", str(default))

    try:
        return max(minimum, min(maximum, int(value)))
    except (TypeError, ValueError):
        return default


# ============================================================
# URL HELPERS
# ============================================================

def normalize_url(url):
    if not url:
        return ""

    url = unquote(str(url).strip())

    if url.startswith("//"):
        url = "https:" + url

    try:
        parsed = urlparse(url)
    except ValueError:
        return ""

    if parsed.scheme.lower() not in ("http", "https"):
        return ""

    if not parsed.netloc:
        return ""

    return url


def hostname(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def is_pdf_url(url):
    if not url:
        return False

    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    return bool(
        PDF_PATTERN.search(parsed.path)
        or ".pdf" in parsed.query.lower()
    )


def unwrap_redirect(url):
    """Unwrap common search-engine redirect URLs."""
    url = normalize_url(url)

    if not url:
        return ""

    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
    except ValueError:
        return url

    for key in (
        "url", "u", "target", "uddg",
        "redirect", "dest", "destination"
    ):
        for value in query.get(key, []):
            candidate = normalize_url(value)

            if candidate and hostname(candidate) not in SEARCH_HOSTS:
                return candidate

    # Decode Bing's commonly used a1-prefixed redirect parameter.
    if "bing.com" in hostname(url):
        for value in query.get("u", []):
            if value.startswith("a1"):
                try:
                    import base64

                    decoded = base64.urlsafe_b64decode(
                        value[2:] + "=="
                    ).decode("utf-8", errors="ignore")

                    candidate = normalize_url(decoded)

                    if candidate:
                        return candidate

                except Exception:
                    pass

    return url


def allowed_domain(url, domain_filter):
    """Apply an optional comma-separated domain allowlist."""
    if not domain_filter:
        return True

    host = hostname(url)

    if not host:
        return False

    domains = [
        item.strip().lower().lstrip(".")
        for item in domain_filter.split(",")
        if item.strip()
    ]

    return any(
        host == domain or host.endswith("." + domain)
        for domain in domains
    )


def result_key(row):
    value = row.get("pdf_url") or row.get("source_url") or ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ============================================================
# HTTP HELPERS
# ============================================================

def fetch_page(url, params=None, max_bytes=MAX_PAGE_BYTES):
    """Fetch a web page with a timeout and a maximum response size."""
    try:
        with session.get(
            url,
            params=params,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            stream=True,
        ) as response:
            response.raise_for_status()

            content_type = response.headers.get(
                "Content-Type", ""
            ).lower()

            chunks = []
            total = 0

            for chunk in response.iter_content(65536):
                if not chunk:
                    continue

                total += len(chunk)

                if total > max_bytes:
                    logging.warning("Response size limit reached: %s", url)
                    break

                chunks.append(chunk)

            raw = b"".join(chunks)
            encoding = response.encoding or "utf-8"

            page = raw.decode(encoding, errors="replace")

            return response.url, page, content_type

    except KeyboardInterrupt:
        raise

    except Exception as exc:
        logging.warning("Fetch failed for %s: %s", url, exc)
        return "", "", ""


# ============================================================
# SEARCH ENGINE FUNCTIONS
# ============================================================

def extract_search_links(engine, page_html, page_url, query):
    """Extract external links from a search engine HTML page."""
    soup = BeautifulSoup(page_html, "html.parser")
    config = ENGINE_CONFIG.get(engine, {})
    anchors = []

    for selector in config.get("selectors", []):
        try:
            anchors.extend(soup.select(selector))
        except Exception:
            pass

    if not anchors:
        anchors = soup.find_all("a", href=True)

    results = []
    seen = set()

    for anchor in anchors:
        href = (anchor.get("href") or "").strip()

        if not href:
            continue

        if href.startswith(("#", "javascript:", "mailto:")):
            continue

        absolute = unwrap_redirect(urljoin(page_url, href))

        if not absolute:
            continue

        host = hostname(absolute)

        if not host:
            continue

        if any(
            host == item or host.endswith("." + item)
            for item in SEARCH_HOSTS
        ):
            continue

        if absolute in seen:
            continue

        seen.add(absolute)

        title = anchor.get_text(" ", strip=True) or absolute

        results.append({
            "query": query,
            "engine": engine,
            "title": title[:500],
            "source_url": absolute,
        })

    return results


def search_engine(engine, query, page_number=0):
    """Search a configured public HTML page."""
    config = ENGINE_CONFIG[engine]

    params = {config["param"]: query}

    page_param = config.get("page_param")

    if page_param:
        params[page_param] = (
            config.get("page_start", 0)
            + page_number * config.get("page_step", 1)
        )

    endpoints = [config["url"]]
    endpoints.extend(config.get("alternates", []))

    for endpoint in endpoints:
        final_url, page, _ = fetch_page(endpoint, params=params)

        if not page:
            continue

        found = extract_search_links(
            engine, page, final_url or endpoint, query
        )

        if found:
            return found

    return []


def search_bing(query, page_number=0):
    return search_engine("Bing", query, page_number)


def search_duckduckgo(query, page_number=0):
    return search_engine("DuckDuckGo", query, page_number)


def search_brave(query, page_number=0):
    return search_engine("Brave", query, page_number)


def search_yahoo(query, page_number=0):
    return search_engine("Yahoo", query, page_number)


def search_startpage(query, page_number=0):
    return search_engine("Startpage", query, page_number)


def search_ecosia(query, page_number=0):
    return search_engine("Ecosia", query, page_number)


def search_qwant(query, page_number=0):
    return search_engine("Qwant", query, page_number)


def search_naver(query, page_number=0):
    return search_engine("Naver", query, page_number)


def search_seznam(query, page_number=0):
    return search_engine("Seznam", query, page_number)


def search_perplexity(query, page_number=0):
    return search_engine("Perplexity", query, page_number)


def search_kagi(query, page_number=0):
    return search_engine("Kagi", query, page_number)


def search_yandex(query, page_number=0):
    return search_engine("Yandex", query, page_number)


def search_baidu(query, page_number=0):
    return search_engine("Baidu", query, page_number)


SEARCH_FUNCTIONS = {
    "Bing": search_bing,
    "DuckDuckGo": search_duckduckgo,
    "Brave": search_brave,
    "Yahoo": search_yahoo,
    "Startpage": search_startpage,
    "Ecosia": search_ecosia,
    "Qwant": search_qwant,
    "Naver": search_naver,
    "Seznam": search_seznam,
    "Perplexity": search_perplexity,
    "Kagi": search_kagi,
    "Yandex": search_yandex,
    "Baidu": search_baidu,
}


# ============================================================
# PDF EXTRACTION
# ============================================================

def make_result(
    pdf_url,
    source_url,
    title,
    query="",
    engine="",
):
    return {
        "title": title or pdf_url,
        "pdf_url": pdf_url,
        "source_url": source_url or pdf_url,
        "query": query,
        "engine": engine,
        "discovered_at": datetime.now().isoformat(timespec="seconds"),
        "verified": "",
        "content_type": "",
        "download_path": "",
    }


def extract_pdf_links(page_url, page_html):
    """Extract PDF links from anchors and embedded resources."""
    soup = BeautifulSoup(page_html, "html.parser")
    found = []
    seen = set()

    for tag in soup.find_all(
        ["a", "iframe", "embed", "object", "source"]
    ):
        href = (
            tag.get("href")
            or tag.get("src")
            or tag.get("data")
            or ""
        ).strip()

        if not href:
            continue

        absolute = normalize_url(urljoin(page_url, href))

        if not absolute or not is_pdf_url(absolute):
            continue

        if absolute in seen:
            continue

        seen.add(absolute)

        title = tag.get_text(" ", strip=True)

        if not title:
            title = Path(urlparse(absolute).path).name or absolute

        found.append({
            "title": title[:500],
            "pdf_url": absolute,
            "source_url": page_url,
        })

    return found


def scrape_page_for_pdfs(
    page_url,
    query="",
    engine="",
    domain_filter="",
):
    if not allowed_domain(page_url, domain_filter):
        return []

    if is_pdf_url(page_url):
        return [
            make_result(
                page_url,
                page_url,
                Path(urlparse(page_url).path).name or page_url,
                query,
                engine,
            )
        ]

    final_url, page, content_type = fetch_page(page_url)

    if not page:
        return []

    if "pdf" in content_type:
        url = final_url or page_url

        return [
            make_result(
                url,
                page_url,
                Path(urlparse(url).path).name or "document.pdf",
                query,
                engine,
            )
        ]

    results = []

    for item in extract_pdf_links(final_url or page_url, page):
        if not allowed_domain(item["pdf_url"], domain_filter):
            continue

        results.append(
            make_result(
                item["pdf_url"],
                item["source_url"],
                item["title"],
                query,
                engine,
            )
        )

    return results


# ============================================================
# SEARCH QUERY BUILDING
# ============================================================

def build_queries(user_query, expand=True):
    user_query = user_query.strip()

    if not user_query:
        return []

    queries = [user_query]

    if expand:
        additions = [
            f"{user_query} filetype:pdf",
            f'"{user_query}" PDF',
        ]

        for query in additions:
            if query not in queries:
                queries.append(query)

    return queries


# ============================================================
# DEDUPLICATION
# ============================================================

def deduplicate_results(results):
    unique = []
    seen = set()

    for result in results:
        key = result_key(result)

        if key not in seen:
            seen.add(key)
            unique.append(result)

    return unique


# ============================================================
# MAIN SEARCH PROCESS
# ============================================================

def search_and_scrape(
    user_query,
    engines,
    pages_per_query=DEFAULT_PAGES,
    expand_queries=True,
    scrape_pages=True,
    domain_filter="",
    delay=DEFAULT_DELAY,
):
    all_results = []
    seen = set()
    queries = build_queries(user_query, expand_queries)

    print("\nStarting search...")
    print("Engines:", ", ".join(engines))
    print("Queries:", len(queries))
    print("Pages per query per engine:", pages_per_query)
    print()

    try:
        for query in queries:
            for engine in engines:
                search_function = SEARCH_FUNCTIONS.get(engine)

                if not search_function:
                    continue

                print(f"\n[SEARCH] {engine}: {query}")
                logging.info(
                    "Searching engine=%s query=%s", engine, query
                )

                for page_number in range(pages_per_query):
                    search_results = search_function(query, page_number)

                    if not search_results:
                        print(
                            f"  Page {page_number + 1}: "
                            "no links (possibly blocked)"
                        )
                        time.sleep(delay)
                        continue

                    print(
                        f"  Page {page_number + 1}: "
                        f"{len(search_results)} web links"
                    )

                    for item in search_results:
                        source_url = item["source_url"]

                        if not allowed_domain(
                            source_url, domain_filter
                        ):
                            continue

                        if is_pdf_url(source_url):
                            candidates = [
                                make_result(
                                    source_url,
                                    source_url,
                                    item.get("title", source_url),
                                    query,
                                    engine,
                                )
                            ]

                        elif scrape_pages:
                            candidates = scrape_page_for_pdfs(
                                source_url,
                                query=query,
                                engine=engine,
                                domain_filter=domain_filter,
                            )

                        else:
                            candidates = []

                        for result in candidates:
                            key = result_key(result)

                            if key not in seen:
                                seen.add(key)
                                all_results.append(result)
                                print(
                                    "    [PDF] "
                                    + result["pdf_url"][:150]
                                )

                        if scrape_pages:
                            time.sleep(delay)

                    time.sleep(delay)

    except KeyboardInterrupt:
        print(
            "\n\nCtrl+C received. Search stopped; "
            "keeping collected results."
        )
        logging.info("Search interrupted by user")

    except Exception as exc:
        print(f"\nSearch error: {exc}")
        logging.exception("Unexpected search error")

    finally:
        print(
            f"\nSearch stopped. Collected "
            f"{len(all_results)} PDF result(s)."
        )

    return all_results


# ============================================================
# URL LIST SCANNER
# ============================================================

def scan_url_file(domain_filter="", delay=DEFAULT_DELAY):
    path_input = safe_input(
        "Path to text file containing URLs: "
    ).strip().strip('"')

    if not path_input:
        print("No file path supplied.")
        return []

    path = Path(path_input).expanduser()

    if not path.is_file():
        print(f"File not found: {path}")
        return []

    try:
        with path.open("r", encoding="utf-8-sig") as file:
            urls = [
                line.strip()
                for line in file
                if line.strip()
                and not line.strip().startswith("#")
            ]

    except OSError as exc:
        print(f"Could not read file: {exc}")
        return []

    results = []
    seen = set()

    try:
        for index, raw_url in enumerate(urls, start=1):
            url = normalize_url(raw_url)

            if not url:
                print(f"[SKIP] Invalid URL on line {index}: {raw_url}")
                continue

            print(f"[{index}/{len(urls)}] Scanning {url}")

            found = scrape_page_for_pdfs(
                url,
                query="URL list scan",
                engine="URL list",
                domain_filter=domain_filter,
            )

            for result in found:
                key = result_key(result)

                if key not in seen:
                    seen.add(key)
                    results.append(result)
                    print("  [PDF]", result["pdf_url"])

            time.sleep(delay)

    except KeyboardInterrupt:
        print("\nScan interrupted. Keeping collected results.")

    print(f"\nCollected {len(results)} PDF result(s).")
    return results


# ============================================================
# VERIFY PDF LINKS
# ============================================================

def verify_pdf_url(url):
    """Try HEAD first, then a small ranged GET."""
    try:
        response = session.head(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        status_code = response.status_code
        content_type = response.headers.get("Content-Type", "")
        response.close()

        if status_code < 400:
            return "OK", content_type

    except KeyboardInterrupt:
        raise

    except Exception as exc:
        logging.info("HEAD verification failed for %s: %s", url, exc)

    try:
        response = session.get(
            url,
            headers={"Range": "bytes=0-1023"},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            stream=True,
        )

        status_code = response.status_code
        content_type = response.headers.get("Content-Type", "")
        response.close()

        if status_code < 400:
            return "OK", content_type

        return f"HTTP {status_code}", content_type

    except KeyboardInterrupt:
        raise

    except Exception as exc:
        return f"ERROR: {exc}", ""


def verify_results(results):
    if not results:
        print("No results to verify.")
        return results

    print(f"\nVerifying {len(results)} PDF URL(s)...")

    try:
        for index, result in enumerate(results, start=1):
            url = result.get("pdf_url", "")

            if not url:
                continue

            print(f"[{index}/{len(results)}] {url}")

            status, content_type = verify_pdf_url(url)

            result["verified"] = status
            result["content_type"] = content_type

            print(f"  Status: {status}; type: {content_type}")

    except KeyboardInterrupt:
        print("\nVerification interrupted. Keeping completed checks.")

    return results


# ============================================================
# DOWNLOAD PDF FILES
# ============================================================

def download_pdf(result, download_dir=DOWNLOAD_DIR):
    url = result.get("pdf_url", "")

    if not url:
        return False

    download_dir = Path(download_dir)
    download_dir.mkdir(parents=True, exist_ok=True)

    filename = unquote(Path(urlparse(url).path).name)

    if not filename or filename in (".", ".."):
        filename = "document.pdf"

    if not filename.lower().endswith(".pdf"):
        filename += ".pdf"

    filename = re.sub(
        r'[<>:"/\\|?*\x00-\x1f]',
        "_",
        filename,
    )[:180]

    target = download_dir / filename

    if target.exists():
        target = download_dir / (
            f"{target.stem}_"
            f"{hashlib.sha1(url.encode()).hexdigest()[:8]}"
            f"{target.suffix}"
        )

    temp_target = target.with_suffix(target.suffix + ".part")
    total = 0

    try:
        with session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            stream=True,
        ) as response:
            response.raise_for_status()

            content_type = response.headers.get(
                "Content-Type", ""
            ).lower()

            if "text/html" in content_type:
                print("  Download skipped: server returned HTML.")
                return False

            with temp_target.open("wb") as file:
                for chunk in response.iter_content(65536):
                    if not chunk:
                        continue

                    total += len(chunk)

                    if total > MAX_PDF_BYTES:
                        raise ValueError(
                            "PDF exceeds download size limit"
                        )

                    file.write(chunk)

        with temp_target.open("rb") as file:
            signature = file.read(1024)

        if b"%PDF-" not in signature:
            temp_target.unlink(missing_ok=True)
            print("  Download skipped: file does not look like a PDF.")
            return False

        temp_target.replace(target)
        result["download_path"] = str(target.resolve())

        print(f"  Saved PDF: {target}")
        return True

    except KeyboardInterrupt:
        temp_target.unlink(missing_ok=True)
        raise

    except Exception as exc:
        logging.warning("Download failed for %s: %s", url, exc)
        print(f"  Download failed: {exc}")
        temp_target.unlink(missing_ok=True)
        return False


def download_results(results):
    if not results:
        print("No results to download.")
        return results

    print(f"\nDownloading {len(results)} PDF(s)...")

    try:
        for index, result in enumerate(results, start=1):
            print(
                f"[{index}/{len(results)}] "
                f"{result.get('pdf_url', '')}"
            )
            download_pdf(result)

    except KeyboardInterrupt:
        print("\nDownload interrupted. Completed downloads are kept.")

    return results


# ============================================================
# EXPORT RESULTS
# ============================================================

def prepare_export_rows(results):
    return [
        item.copy() if isinstance(item, dict)
        else {"result": str(item)}
        for item in results
    ]


def export_json(rows, target):
    with target.open("w", encoding="utf-8") as file:
        json.dump(
            rows,
            file,
            indent=2,
            ensure_ascii=False,
            default=str,
        )


def export_csv(rows, target):
    columns = list(dict.fromkeys(
        key for row in rows for key in row.keys()
    )) or ["result"]

    with target.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=columns,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def export_html(rows, target):
    columns = list(dict.fromkeys(
        key for row in rows for key in row.keys()
    )) or ["result"]

    with target.open("w", encoding="utf-8") as file:
        file.write("""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PDF Finder Results</title>
<style>
body {font-family:Arial,sans-serif;margin:24px;color:#222}
h1 {font-size:24px}
table {border-collapse:collapse;width:100%;font-size:14px}
th,td {border:1px solid #ddd;padding:9px;text-align:left;
vertical-align:top;overflow-wrap:anywhere}
th {background:#eee}
tr:nth-child(even) {background:#fafafa}
</style>
</head>
<body>
<h1>PDF Finder Results</h1>
""")

        file.write(f"<p>Total results: {len(rows)}</p>")
        file.write("<table><thead><tr>")

        for column in columns:
            file.write(
                f"<th>{html.escape(str(column))}</th>"
            )

        file.write("</tr></thead><tbody>")

        for row in rows:
            file.write("<tr>")

            for column in columns:
                value = row.get(column, "")
                value = "" if value is None else str(value)

                if (
                    column == "pdf_url"
                    and value.startswith(("http://", "https://"))
                ):
                    escaped_url = html.escape(value, quote=True)
                    display = html.escape(value)

                    cell = (
                        f'<a href="{escaped_url}" target="_blank" '
                        f'rel="noopener noreferrer">{display}</a>'
                    )
                else:
                    cell = html.escape(value)

                file.write(f"<td>{cell}</td>")

            file.write("</tr>")

        file.write("</tbody></table></body></html>")


def save_results_interactive(results):
    if not results:
        print("\nNo results were collected, so there is nothing to save.")
        return []

    print("\n" + "=" * 60)
    print("SAVE SEARCH RESULTS")
    print("=" * 60)
    print(f"Results available: {len(results)}")

    folder_input = safe_input(
        f"Folder path (Enter = {OUTPUT_DIR}): ",
        str(OUTPUT_DIR),
    ).strip().strip('"')

    folder = Path(folder_input or OUTPUT_DIR).expanduser()

    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"Could not create folder: {exc}")
        return []

    filename_input = safe_input(
        "Filename without extension (Enter = pdf_results): ",
        "pdf_results",
    ).strip().strip('"')

    filename = Path(filename_input or "pdf_results").name
    filename = Path(filename).stem or "pdf_results"

    print("\nChoose output format:")
    print("  1. JSON")
    print("  2. CSV")
    print("  3. HTML")
    print("  4. All formats")

    choices = safe_input(
        "Enter choice(s), e.g. 1,3 (Enter = all): ",
        "4",
    )

    format_map = {
        "1": "json",
        "2": "csv",
        "3": "html",
    }

    selected = set()

    for choice in choices.split(","):
        choice = choice.strip()

        if choice == "4":
            selected = {"json", "csv", "html"}
            break

        if choice in format_map:
            selected.add(format_map[choice])

    if not selected:
        print("No valid format selected.")
        return []

    rows = prepare_export_rows(results)

    exporters = {
        "json": export_json,
        "csv": export_csv,
        "html": export_html,
    }

    saved_files = []

    for fmt in ("json", "csv", "html"):
        if fmt not in selected:
            continue

        target = folder / f"{filename}.{fmt}"

        try:
            exporters[fmt](rows, target)
            saved_files.append(target.resolve())
            print(f"[SAVED] {target.resolve()}")

        except (OSError, TypeError, ValueError) as exc:
            logging.exception("Export failed for %s", target)
            print(f"[ERROR] Could not save {target}: {exc}")

    if saved_files:
        print(f"\nSaved {len(saved_files)} result file(s).")

    return saved_files


# ============================================================
# DISPLAY RESULTS
# ============================================================

def print_results(results, limit=30):
    if not results:
        print("\nNo PDF results found.")
        return

    print("\n" + "=" * 72)
    print(f"RESULTS: {len(results)} PDF link(s)")
    print("=" * 72)

    for index, result in enumerate(results[:limit], start=1):
        print(f"\n{index}. {result.get('title', '(no title)')}")
        print(f"   PDF:    {result.get('pdf_url', '')}")
        print(f"   Source: {result.get('source_url', '')}")

        if result.get("engine"):
            print(f"   Engine: {result['engine']}")

        if result.get("verified"):
            print(f"   Status: {result['verified']}")

    if len(results) > limit:
        print(f"\n... and {len(results) - limit} more result(s).")


# ============================================================
# ENGINE SELECTION
# ============================================================

def choose_engines():
    print("\nAvailable search engines:")

    for index, engine in enumerate(SEARCH_ENGINES, start=1):
        print(f"  {index:2}. {engine}")

    all_number = len(SEARCH_ENGINES) + 1
    print(f"  {all_number:2}. All engines")

    choice = safe_input(
        f"Choose engines (e.g. 1,2 or {all_number} for all) "
        f"[{all_number}]: ",
        str(all_number),
    )

    if choice.strip() == str(all_number):
        return SEARCH_ENGINES.copy()

    selected = []

    for part in choice.split(","):
        part = part.strip()

        if part.isdigit():
            number = int(part)

            if 1 <= number <= len(SEARCH_ENGINES):
                engine = SEARCH_ENGINES[number - 1]

                if engine not in selected:
                    selected.append(engine)

    return selected or SEARCH_ENGINES.copy()


# ============================================================
# WEB SEARCH WORKFLOW
# ============================================================

def run_web_search():
    query = safe_input("\nEnter search query: ")

    if not query:
        print("Search query cannot be empty.")
        return []

    engines = choose_engines()

    pages = ask_int(
        "Search pages per query per engine",
        DEFAULT_PAGES,
        1,
        20,
    )

    expand = ask_yes_no(
        "Expand the query automatically?",
        True,
    )

    scrape = ask_yes_no(
        "Open search result pages and extract PDF links?",
        True,
    )

    domain_filter = safe_input(
        "Optional allowed domains, comma-separated "
        "(Enter = any domain): "
    )

    delay_text = safe_input(
        f"Delay between requests in seconds [{DEFAULT_DELAY}]: ",
        str(DEFAULT_DELAY),
    )

    try:
        delay = max(0.0, min(10.0, float(delay_text)))
    except ValueError:
        delay = DEFAULT_DELAY

    results = search_and_scrape(
        user_query=query,
        engines=engines,
        pages_per_query=pages,
        expand_queries=expand,
        scrape_pages=scrape,
        domain_filter=domain_filter,
        delay=delay,
    )

    return deduplicate_results(results)


# ============================================================
# MAIN MENU
# ============================================================

def main():
    banner()
    current_results = []

    while True:
        print("\nMAIN MENU")
        print("-" * 40)
        print("1. Search web for PDF documents")
        print("2. Scan URLs from a text file")
        print("3. Verify current PDF links")
        print("4. Download current PDFs")
        print("5. Show current results")
        print("6. Save current results")
        print("7. Clear current results")
        print("0. Exit")

        choice = safe_input("\nChoose an option: ")

        if choice == "1":
            new_results = run_web_search()

            current_results.extend(new_results)
            current_results = deduplicate_results(current_results)

            print(f"\nTotal unique results: {len(current_results)}")

            if current_results:
                print_results(current_results)

                if ask_yes_no("Save results now?", True):
                    save_results_interactive(current_results)

        elif choice == "2":
            domain_filter = safe_input(
                "Optional allowed domains, comma-separated "
                "(Enter = any domain): "
            )

            new_results = scan_url_file(
                domain_filter=domain_filter
            )

            current_results.extend(new_results)
            current_results = deduplicate_results(current_results)

            if current_results and ask_yes_no(
                "Save results now?", True
            ):
                save_results_interactive(current_results)

        elif choice == "3":
            current_results = verify_results(current_results)

            if current_results and ask_yes_no(
                "Save updated results?", True
            ):
                save_results_interactive(current_results)

        elif choice == "4":
            if not current_results:
                print("No current results to download.")
                continue

            download_results(current_results)

            if ask_yes_no(
                "Save results with download paths?", True
            ):
                save_results_interactive(current_results)

        elif choice == "5":
            print_results(current_results, limit=100)

        elif choice == "6":
            save_results_interactive(current_results)

        elif choice == "7":
            if ask_yes_no("Clear all current results?", False):
                current_results.clear()
                print("Results cleared.")

        elif choice == "0":
            if current_results and ask_yes_no(
                "Save current results before exiting?", True
            ):
                save_results_interactive(current_results)

            print("\nGoodbye.")
            return

        else:
            print("Invalid option. Please choose from the menu.")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print("\n\nProgram interrupted.")

    except Exception as exc:
        logging.exception("Fatal application error")
        print(f"\nUnexpected error: {exc}")

    finally:
        try:
            session.close()
        except Exception:
            pass

        print(f"\nDebug log: {LOG_FILE.resolve()}")
