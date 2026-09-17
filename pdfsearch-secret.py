#!/usr/bin/env python3

import os
import re
import sys
import time
import random
from urllib.parse import quote, urlparse, parse_qs, unquote

import requests
from bs4 import BeautifulSoup


# ============================================================
# TERMINAL / UI
# ============================================================

try:
    from colorama import Fore, Style, init

    init(autoreset=True)

    GREEN = Fore.GREEN
    CYAN = Fore.CYAN
    BLUE = Fore.BLUE
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE

    DIM = Style.DIM
    RESET = Style.RESET_ALL

except ImportError:
    GREEN = ""
    CYAN = ""
    BLUE = ""
    YELLOW = ""
    RED = ""
    MAGENTA = ""
    WHITE = ""
    DIM = ""
    RESET = ""


BANNER = f"""
{CYAN}
 ██████╗ ███████╗██╗███╗   ██╗████████╗
 ██╔══██╗██╔════╝██║████╗  ██║╚══██╔══╝
 ██████╔╝█████╗  ██║██╔██╗ ██║   ██║
 ██╔═══╝ ██╔══╝  ██║██║╚██╗██║   ██║
 ██║     ███████╗██║██║ ╚████║   ██║
 ╚═╝     ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
{GREEN}
       P U B L I C   D O C U M E N T   R E C O N
{DIM}
       PDF / FOIA / ARCHIVE / GOVERNMENT SEARCH
{RESET}
"""


def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")


def line(char="─", length=72):
    print(f"{DIM}{char * length}{RESET}")


def section(title):
    print()
    print(f"{CYAN}┌{'─' * 70}┐")
    print(f"│ {WHITE}{title:<68}{CYAN}│")
    print(f"└{'─' * 70}┘{RESET}")


def status(label, message, color=GREEN):
    print(
        f"{DIM}[{RESET}{color}{label}{RESET}{DIM}] "
        f"{WHITE}{message}{RESET}"
    )


def engine_start(name):
    print(
        f"  {CYAN}├─{RESET} "
        f"{WHITE}{name:<14}{RESET}"
        f"{DIM} scanning...{RESET}"
    )


def engine_done(name, count):
    print(
        f"  {GREEN}└─{RESET} "
        f"{WHITE}{name:<14}{RESET}"
        f"{GREEN} {count} PDF links{RESET}"
    )


def engine_error(name, message):
    print(
        f"  {RED}└─{RESET} "
        f"{WHITE}{name:<14}{RESET}"
        f"{RED} ERROR: {message}{RESET}"
    )


# ============================================================
# CONFIGURATION
# ============================================================

DOWNLOAD_PDFS = False

# Number of result pages per search engine
MAX_PAGES = 3

OUTPUT_FILE = "pdf_results.txt"
DOWNLOAD_FOLDER = "downloads"

REQUEST_TIMEOUT = 15

DELAY_MIN = 0.8
DELAY_MAX = 1.8

# Enable / disable search engines
ENABLE_BING = True
ENABLE_DDG = True
ENABLE_YAHOO = True
ENABLE_BRAVE = True
ENABLE_STARTPAGE = True


HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/140.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,"
        "application/xml;q=0.9,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}


# ============================================================
# QUERY EXPANSION
# ============================================================

def build_queries(keyword):
    return [
        # General
        f"{keyword} filetype:pdf",
        f'{keyword} "report" filetype:pdf',
        f'{keyword} "research" filetype:pdf',
        f"{keyword} site:gov filetype:pdf",
        f"{keyword} site:edu filetype:pdf",
        f"{keyword} inurl:pdf",
        f"{keyword} intitle:pdf",

        # Declassified
        f'{keyword} "declassified" filetype:pdf',
        f'{keyword} "declassified document" filetype:pdf',
        f'{keyword} "formerly classified" filetype:pdf',
        f'{keyword} "unclassified" filetype:pdf',
        f'{keyword} "FOIA" filetype:pdf',
        f'{keyword} "FOIA release" filetype:pdf',
        f'{keyword} "released" "declassified" filetype:pdf',
        f'{keyword} "historical records" filetype:pdf',
        f'{keyword} "historical document" filetype:pdf',
        f'{keyword} "government archive" filetype:pdf',
        f'{keyword} "public records" filetype:pdf',

        # Intelligence
        f'{keyword} "intelligence assessment" filetype:pdf',
        f'{keyword} "intelligence report" filetype:pdf',
        f'{keyword} "intelligence analysis" filetype:pdf',
        f'{keyword} "memorandum" filetype:pdf',
        f'{keyword} "national security" filetype:pdf',
        f'{keyword} "security assessment" filetype:pdf',

        # CIA
        f"{keyword} site:cia.gov filetype:pdf",
        f'{keyword} site:cia.gov "declassified" filetype:pdf',
        f'{keyword} site:cia.gov "unclassified" filetype:pdf',
        f'{keyword} site:cia.gov "FOIA" filetype:pdf',
        f'{keyword} site:cia.gov "historical" filetype:pdf',

        # NSA
        f"{keyword} site:nsa.gov filetype:pdf",
        f'{keyword} site:nsa.gov "declassified" filetype:pdf',
        f'{keyword} site:nsa.gov "unclassified" filetype:pdf',
        f'{keyword} site:nsa.gov "FOIA" filetype:pdf',
        f'{keyword} site:nsa.gov "historical" filetype:pdf',

        # Defense
        f"{keyword} site:defense.gov filetype:pdf",
        f"{keyword} site:army.mil filetype:pdf",
        f"{keyword} site:navy.mil filetype:pdf",
        f"{keyword} site:af.mil filetype:pdf",
        f"{keyword} site:marines.mil filetype:pdf",
        f"{keyword} site:spaceforce.mil filetype:pdf",

        # Archives
        f"{keyword} site:archives.gov filetype:pdf",
        f'{keyword} site:archives.gov "declassified" filetype:pdf',
        f'{keyword} site:archives.gov "FOIA" filetype:pdf',

        # Government
        f'{keyword} site:gov "declassified" filetype:pdf',
        f'{keyword} site:gov "unclassified" filetype:pdf',
        f'{keyword} site:gov "formerly classified" filetype:pdf',
        f'{keyword} site:gov "FOIA" filetype:pdf',
    ]


# ============================================================
# URL CLEANING
# ============================================================

def clean_url(url):
    if not url:
        return None

    url = unquote(url.strip())

    # Remove quotes and HTML artifacts
    url = url.strip("\"'<>")

    # Google redirect
    if "/url?q=" in url:
        try:
            url = url.split("/url?q=", 1)[1].split("&", 1)[0]
        except Exception:
            return None

    # DuckDuckGo redirect
    if "uddg=" in url:
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)

            if "uddg" in query:
                url = query["uddg"][0]

        except Exception:
            return None

    # Generic redirect parameter
    if "url=" in url and not url.startswith(
        ("http://", "https://")
    ):
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)

            if "url" in query:
                url = query["url"][0]

        except Exception:
            pass

    # Remove HTML escaped characters
    url = url.replace("&amp;", "&")

    if url.startswith("http://") or url.startswith("https://"):
        return url

    return None


# ============================================================
# PDF DETECTION
# ============================================================

def is_pdf_url(url):
    if not url:
        return False

    lower = url.lower()

    return any(
        marker in lower
        for marker in (
            ".pdf",
            "filetype=pdf",
            "format=pdf",
            "/pdf/",
            "document.pdf",
        )
    )


# ============================================================
# GENERIC LINK EXTRACTION
# ============================================================

def extract_links(html):
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")

    links = []

    for tag in soup.find_all("a", href=True):
        href = tag.get("href")

        url = clean_url(href)

        if url and is_pdf_url(url):
            links.append(url)

    return links


# ============================================================
# BRAVE-SPECIFIC EXTRACTION
# ============================================================

def extract_brave_links(html):
    """
    Brave's HTML structure can change.
    Use several extraction methods instead of one selector.
    """

    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")

    results = []

    # --------------------------------------------------------
    # Strategy 1 - known / possible result containers
    # --------------------------------------------------------

    selectors = [
        "div.snippet",
        "div[data-type='web']",
        "div[class*='snippet']",
        "div[class*='result']",
        "article",
    ]

    for selector in selectors:

        try:
            containers = soup.select(selector)
        except Exception:
            containers = []

        for container in containers:

            for a in container.find_all(
                "a",
                href=True
            ):

                href = a.get("href")

                url = clean_url(href)

                if url and is_pdf_url(url):
                    results.append(url)

    # --------------------------------------------------------
    # Strategy 2 - all links
    # --------------------------------------------------------

    if not results:

        for a in soup.find_all(
            "a",
            href=True
        ):

            href = a.get("href")

            url = clean_url(href)

            if url and is_pdf_url(url):
                results.append(url)

    # --------------------------------------------------------
    # Strategy 3 - raw HTML PDF URLs
    # --------------------------------------------------------

    if not results:

        pattern = re.compile(
            r'https?://[^\s"\'<>]+?\.pdf(?:\?[^\s"\'<>]*)?',
            re.IGNORECASE
        )

        matches = pattern.findall(html)

        for match in matches:

            url = clean_url(match)

            if url:
                results.append(url)

    return results


# ============================================================
# HTTP SESSION
# ============================================================

SESSION = requests.Session()

SESSION.headers.update(HEADERS)


def fetch(url):
    try:

        response = SESSION.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        response.raise_for_status()

        return response.text

    except requests.RequestException as exc:

        print(
            f"    {RED}↳ {exc}{RESET}"
        )

        return ""

    except Exception as exc:

        print(
            f"    {RED}↳ {exc}{RESET}"
        )

        return ""


# ============================================================
# BING
# ============================================================

def search_bing(query):

    results = []

    engine_start("BING")

    encoded = quote(query)

    for page in range(MAX_PAGES):

        offset = page * 10

        url = (
            "https://www.bing.com/search"
            f"?q={encoded}"
            f"&first={offset}"
        )

        html = fetch(url)

        if html:

            results.extend(
                extract_links(html)
            )

        time.sleep(
            random.uniform(
                DELAY_MIN,
                DELAY_MAX
            )
        )

    engine_done(
        "BING",
        len(results)
    )

    return results


# ============================================================
# DUCKDUCKGO
# ============================================================

def search_ddg(query):

    results = []

    engine_start("DUCKDUCKGO")

    encoded = quote(query)

    for page in range(MAX_PAGES):

        offset = page * 30

        url = (
            "https://html.duckduckgo.com/html/"
            f"?q={encoded}"
            f"&s={offset}"
        )

        html = fetch(url)

        if html:

            results.extend(
                extract_links(html)
            )

        time.sleep(
            random.uniform(
                DELAY_MIN,
                DELAY_MAX
            )
        )

    engine_done(
        "DUCKDUCKGO",
        len(results)
    )

    return results


# ============================================================
# YAHOO
# ============================================================

def search_yahoo(query):

    results = []

    engine_start("YAHOO")

    encoded = quote(query)

    for page in range(MAX_PAGES):

        offset = page * 10

        url = (
            "https://search.yahoo.com/search"
            f"?p={encoded}"
            f"&b={offset}"
        )

        html = fetch(url)

        if html:

            results.extend(
                extract_links(html)
            )

        time.sleep(
            random.uniform(
                DELAY_MIN,
                DELAY_MAX
            )
        )

    engine_done(
        "YAHOO",
        len(results)
    )

    return results


# ============================================================
# BRAVE
# ============================================================

def search_brave(query):

    results = []

    engine_start("BRAVE")

    encoded = quote(query)

    brave_blocked = False

    for page in range(MAX_PAGES):

        if brave_blocked:
            break

        offset = page * 10

        url = (
            "https://search.brave.com/search"
            f"?source=web"
            f"&q={encoded}"
            f"&offset={offset}"
        )

        try:

            response = SESSION.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )

            if response.status_code != 200:

                engine_error(
                    "BRAVE",
                    f"HTTP {response.status_code}"
                )

                continue

            html = response.text

            lower_html = html.lower()

            # Detect common challenge / blocking pages.
            blocked_terms = [
                "captcha",
                "access denied",
                "verify you are human",
                "unusual traffic",
            ]

            if any(
                term in lower_html
                for term in blocked_terms
            ):

                engine_error(
                    "BRAVE",
                    "search page returned a challenge"
                )

                brave_blocked = True

                break

            page_results = extract_brave_links(html)

            results.extend(page_results)

        except requests.RequestException as exc:

            engine_error(
                "BRAVE",
                str(exc)
            )

        except Exception as exc:

            engine_error(
                "BRAVE",
                str(exc)
            )

        time.sleep(
            random.uniform(
                DELAY_MIN,
                DELAY_MAX
            )
        )

    engine_done(
        "BRAVE",
        len(results)
    )

    return results


# ============================================================
# STARTPAGE
# ============================================================

def search_startpage(query):

    results = []

    engine_start("STARTPAGE")

    encoded = quote(query)

    for page in range(MAX_PAGES):

        offset = page * 10

        url = (
            "https://www.startpage.com/sp/search"
            f"?q={encoded}"
            f"&start={offset}"
        )

        html = fetch(url)

        if html:

            results.extend(
                extract_links(html)
            )

        time.sleep(
            random.uniform(
                DELAY_MIN,
                DELAY_MAX
            )
        )

    engine_done(
        "STARTPAGE",
        len(results)
    )

    return results


# ============================================================
# DEDUPLICATION
# ============================================================

def clean_links(links):

    seen = set()

    cleaned = []

    for link in links:

        if not link:
            continue

        link = link.strip()

        link = link.rstrip("/")

        if link not in seen:

            seen.add(link)

            cleaned.append(link)

    return cleaned


# ============================================================
# CLASSIFICATION
# ============================================================

def classify_document(url):

    lower = url.lower()

    domains = {
        "cia.gov": "CIA",
        "nsa.gov": "NSA",
        "defense.gov": "DOD",
        "army.mil": "US ARMY",
        "navy.mil": "US NAVY",
        "af.mil": "US AIR FORCE",
        "marines.mil": "US MARINES",
        "spaceforce.mil": "US SPACE FORCE",
        "archives.gov": "NATIONAL ARCHIVES",
    }

    for domain, name in domains.items():

        if domain in lower:
            return name

    if "declassified" in lower:
        return "DECLASSIFIED"

    if ".gov" in lower:
        return "US GOVERNMENT"

    if ".edu" in lower:
        return "EDUCATIONAL"

    return "PUBLIC PDF"


# ============================================================
# TAGGING
# ============================================================

def document_tags(url):

    lower = url.lower()

    tags = []

    checks = [
        ("declass", "DECLASSIFIED"),
        ("unclassified", "UNCLASSIFIED"),
        ("foia", "FOIA"),
        ("archive", "ARCHIVE"),
        ("historical", "HISTORICAL"),
        ("intelligence", "INTELLIGENCE"),
        ("memorandum", "MEMORANDUM"),
        ("memo", "MEMORANDUM"),
        ("report", "REPORT"),
        ("assessment", "ASSESSMENT"),
    ]

    for keyword, tag in checks:

        if keyword in lower:

            if tag not in tags:
                tags.append(tag)

    return ", ".join(tags)


# ============================================================
# DOWNLOAD
# ============================================================

def download_file(url, index):

    try:

        os.makedirs(
            DOWNLOAD_FOLDER,
            exist_ok=True
        )

        parsed = urlparse(url)

        filename = os.path.basename(
            parsed.path
        )

        if not filename:
            filename = "document.pdf"

        filename = unquote(filename)

        filename = re.sub(
            r"[^a-zA-Z0-9._-]",
            "_",
            filename
        )

        if not filename.lower().endswith(".pdf"):
            filename += ".pdf"

        filename = f"{index:04d}_{filename}"

        path = os.path.join(
            DOWNLOAD_FOLDER,
            filename
        )

        response = SESSION.get(
            url,
            timeout=30,
            allow_redirects=True
        )

        response.raise_for_status()

        content_type = response.headers.get(
            "Content-Type",
            ""
        ).lower()

        signature = response.content[:5]

        if (
            "pdf" not in content_type
            and signature != b"%PDF-"
        ):

            print(
                f"    {YELLOW}[SKIP]{RESET} "
                f"Not a PDF: {url}"
            )

            return False

        with open(
            path,
            "wb"
        ) as file:

            file.write(
                response.content
            )

        print(
            f"    {GREEN}[DOWNLOADED]{RESET} "
            f"{filename}"
        )

        return True

    except Exception as exc:

        print(
            f"    {RED}[DOWNLOAD ERROR]{RESET} "
            f"{exc}"
        )

        return False


# ============================================================
# SAVE RESULTS
# ============================================================

def save_results(keyword, links):

    try:

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                "PUBLIC DOCUMENT RECON\n"
            )

            file.write(
                "=" * 72 + "\n\n"
            )

            file.write(
                f"Keyword: {keyword}\n"
            )

            file.write(
                f"Results: {len(links)}\n\n"
            )

            for index, link in enumerate(
                links,
                1
            ):

                file.write(
                    f"[{index}] "
                    f"{classify_document(link)}\n"
                )

                tags = document_tags(link)

                if tags:

                    file.write(
                        f"Tags: {tags}\n"
                    )

                file.write(
                    f"URL: {link}\n"
                )

                file.write(
                    "-" * 72 + "\n"
                )

        status(
            "OK",
            f"Results saved -> {OUTPUT_FILE}",
            GREEN
        )

    except Exception as exc:

        status(
            "ERR",
            f"Could not save results: {exc}",
            RED
        )


# ============================================================
# RESULT DISPLAY
# ============================================================

def display_results(links):

    section("SEARCH RESULTS")

    if not links:

        print(
            f"\n  {RED}No PDF results found.{RESET}\n"
        )

        return

    for index, link in enumerate(
        links,
        1
    ):

        doc_type = classify_document(link)

        tags = document_tags(link)

        print(
            f"\n{CYAN}[{index:03d}]{RESET} "
            f"{GREEN}{doc_type}{RESET}"
        )

        if tags:

            print(
                f"     {YELLOW}TAG:{RESET} "
                f"{tags}"
            )

        print(
            f"     {DIM}{link}{RESET}"
        )

    print()


# ============================================================
# ENGINE MANAGER
# ============================================================

def search_all_engines(query):

    all_links = []

    if ENABLE_BING:

        try:
            all_links.extend(
                search_bing(query)
            )
        except Exception as exc:
            engine_error(
                "BING",
                str(exc)
            )

    if ENABLE_DDG:

        try:
            all_links.extend(
                search_ddg(query)
            )
        except Exception as exc:
            engine_error(
                "DUCKDUCKGO",
                str(exc)
            )

    if ENABLE_YAHOO:

        try:
            all_links.extend(
                search_yahoo(query)
            )
        except Exception as exc:
            engine_error(
                "YAHOO",
                str(exc)
            )

    if ENABLE_BRAVE:

        try:
            all_links.extend(
                search_brave(query)
            )
        except Exception as exc:
            engine_error(
                "BRAVE",
                str(exc)
            )

    if ENABLE_STARTPAGE:

        try:
            all_links.extend(
                search_startpage(query)
            )
        except Exception as exc:
            engine_error(
                "STARTPAGE",
                str(exc)
            )

    return all_links


# ============================================================
# MAIN
# ============================================================

def main():

    clear_screen()

    print(BANNER)

    line()

    print(
        f"{DIM}[*] Mode:{RESET} "
        f"{GREEN}PUBLIC DOCUMENT RECON{RESET}"
    )

    print(
        f"{DIM}[*] Sources:{RESET} "
        f"Bing / DuckDuckGo / Yahoo / Brave / Startpage"
    )

    print(
        f"{DIM}[*] PDF download:{RESET} "
        f"{GREEN if DOWNLOAD_PDFS else YELLOW}"
        f"{'ENABLED' if DOWNLOAD_PDFS else 'DISABLED'}"
        f"{RESET}"
    )

    line()

    try:

        keyword = input(
            f"\n{CYAN}┌─[ TARGET ]{RESET}\n"
            f"{CYAN}└──> {RESET}"
        ).strip()

    except KeyboardInterrupt:

        print(
            f"\n\n{YELLOW}[!] Interrupted.{RESET}"
        )

        return

    if not keyword:

        print(
            f"\n{RED}[!] Empty target.{RESET}"
        )

        return

    queries = build_queries(keyword)

    section(
        "RECONNAISSANCE INITIALIZED"
    )

    print(
        f"  {DIM}Target:{RESET} "
        f"{GREEN}{keyword}{RESET}"
    )

    print(
        f"  {DIM}Query matrix:{RESET} "
        f"{CYAN}{len(queries)} queries{RESET}"
    )

    print(
        f"  {DIM}Pagination:{RESET} "
        f"{MAX_PAGES} pages/engine"
    )

    all_links = []

    start_time = time.time()

    try:

        for number, query in enumerate(
            queries,
            1
        ):

            print()

            print(
                f"{MAGENTA}"
                f"╔══ QUERY "
                f"{number:02d}/{len(queries):02d} "
                f"══════════════════════════════════════╗"
                f"{RESET}"
            )

            print(
                f"{DIM}{query}{RESET}"
            )

            print(
                f"{MAGENTA}"
                f"╚══════════════════════════════════════════════════════════════╝"
                f"{RESET}"
            )

            # Search all enabled engines
            query_links = search_all_engines(query)

            all_links.extend(query_links)

            # Live result count
            print(
                f"\n  {CYAN}[*]{RESET} "
                f"Query results: "
                f"{GREEN}{len(query_links)}{RESET}"
            )

    except KeyboardInterrupt:

        print(
            f"\n\n{YELLOW}"
            "[!] Search interrupted by user."
            f"{RESET}"
        )

    # ========================================================
    # DEDUPLICATE
    # ========================================================

    final_links = clean_links(all_links)

    elapsed = time.time() - start_time

    # ========================================================
    # SUMMARY
    # ========================================================

    section(
        "RECON COMPLETE"
    )

    print(
        f"  {GREEN}✓{RESET} "
        f"Unique PDF URLs: "
        f"{CYAN}{len(final_links)}{RESET}"
    )

    print(
        f"  {GREEN}✓{RESET} "
        f"Queries processed: "
        f"{CYAN}{len(queries)}{RESET}"
    )

    print(
        f"  {GREEN}✓{RESET} "
        f"Raw links collected: "
        f"{CYAN}{len(all_links)}{RESET}"
    )

    print(
        f"  {GREEN}✓{RESET} "
        f"Elapsed: "
        f"{CYAN}{elapsed:.1f}s{RESET}"
    )

    # ========================================================
    # DISPLAY
    # ========================================================

    display_results(
        final_links
    )

    # ========================================================
    # DOWNLOAD
    # ========================================================

    if DOWNLOAD_PDFS and final_links:

        section(
            "PDF DOWNLOAD QUEUE"
        )

        for index, link in enumerate(
            final_links,
            1
        ):

            download_file(
                link,
                index
            )

            time.sleep(
                random.uniform(
                    0.5,
                    1.2
                )
            )

    # ========================================================
    # SAVE
    # ========================================================

    save_results(
        keyword,
        final_links
    )

    print()

    line()

    print(
        f"{GREEN}"
        f"  [ SYSTEM ONLINE ] "
        f"PUBLIC DOCUMENT RECON FINISHED"
        f"{RESET}"
    )

    line()

    print()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(
            f"\n\n{YELLOW}"
            "[!] Session terminated."
            f"{RESET}"
        )

        sys.exit(0)

    except Exception as exc:

        print(
            f"\n\n{RED}"
            f"[FATAL ERROR] {exc}"
            f"{RESET}"
        )

        sys.exit(1)