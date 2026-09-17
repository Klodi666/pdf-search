import requests
from bs4 import BeautifulSoup
import time
import random
import re
import os

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# =============================
# CONFIG
# =============================
DOWNLOAD_PDFS = False   # set True if you want auto-download
MAX_PAGES = 3           # pagination depth per engine
OUTPUT_FILE = "pdf_results.txt"
DOWNLOAD_FOLDER = "downloads"


# =============================
# QUERY EXPANSION
# =============================
def build_queries(keyword):
    return [
        f"{keyword} filetype:pdf",
        f"{keyword} \"report\" filetype:pdf",
        f"{keyword} \"research\" filetype:pdf",
        f"{keyword} site:gov filetype:pdf",
        f"{keyword} site:edu filetype:pdf",
        f"{keyword} inurl:pdf",
        f"{keyword} intitle:pdf"
    ]


# =============================
# CLEAN URLS
# =============================
def clean_url(url):
    if not url:
        return None

    if "/url?q=" in url:
        url = url.split("/url?q=")[1].split("&")[0]

    if url.startswith("http"):
        return url

    return None


# =============================
# VALIDATE PDF
# =============================
def is_pdf(url):
    return url and ".pdf" in url.lower()


# =============================
# EXTRACT LINKS
# =============================
def extract_links(html):
    soup = BeautifulSoup(html, "html.parser")
    links = []

    for a in soup.find_all("a", href=True):
        url = clean_url(a["href"])
        if url and is_pdf(url):
            links.append(url)

    return links


# =============================
# ENGINE REQUEST WRAPPER
# =============================
def fetch(url):
    try:
        return requests.get(url, headers=HEADERS, timeout=10).text
    except:
        return ""


# =============================
# BING
# =============================
def search_bing(query):
    print("[+] Bing")
    results = []

    for page in range(MAX_PAGES):
        offset = page * 10
        url = f"https://www.bing.com/search?q={query}&first={offset}"
        html = fetch(url)
        results += extract_links(html)
        time.sleep(random.uniform(1, 2))

    return results


# =============================
# DUCKDUCKGO
# =============================
def search_ddg(query):
    print("[+] DuckDuckGo")
    results = []

    for page in range(MAX_PAGES):
        url = f"https://duckduckgo.com/html/?q={query}&s={page*30}"
        html = fetch(url)
        results += extract_links(html)
        time.sleep(random.uniform(1, 2))

    return results


# =============================
# YAHOO
# =============================
def search_yahoo(query):
    print("[+] Yahoo")
    results = []

    for page in range(MAX_PAGES):
        url = f"https://search.yahoo.com/search?p={query}&b={page*10}"
        html = fetch(url)
        results += extract_links(html)
        time.sleep(random.uniform(1, 2))

    return results


# =============================
# BRAVE
# =============================
def search_brave(query):
    print("[+] Brave")
    results = []

    for page in range(MAX_PAGES):
        url = f"https://search.brave.com/search?q={query}&offset={page*10}"
        html = fetch(url)
        results += extract_links(html)
        time.sleep(random.uniform(1, 2))

    return results


# =============================
# STARTPAGE
# =============================
def search_startpage(query):
    print("[+] Startpage")
    results = []

    for page in range(MAX_PAGES):
        url = f"https://www.startpage.com/sp/search?q={query}&start={page*10}"
        html = fetch(url)
        results += extract_links(html)
        time.sleep(random.uniform(1, 2))

    return results


# =============================
# CLEAN DUPLICATES
# =============================
def clean(links):
    return list(set(links))


# =============================
# DOWNLOAD PDF
# =============================
def download_file(url):
    try:
        if not os.path.exists(DOWNLOAD_FOLDER):
            os.makedirs(DOWNLOAD_FOLDER)

        filename = url.split("/")[-1].split("?")[0]
        path = os.path.join(DOWNLOAD_FOLDER, filename)

        r = requests.get(url, headers=HEADERS, timeout=10)

        with open(path, "wb") as f:
            f.write(r.content)

        print(f"[DOWNLOADED] {filename}")

    except:
        pass


# =============================
# FORMAT OUTPUT
# =============================
def format_link(url):
    return f"URL:{url}"


# =============================
# MAIN
# =============================
def main():
    keyword = input("Enter keyword: ")

    queries = build_queries(keyword)

    all_links = []

    for q in queries:
        print(f"\n[QUERY] {q}")

        all_links += search_bing(q)
        all_links += search_ddg(q)
        all_links += search_yahoo(q)
        all_links += search_brave(q)
        all_links += search_startpage(q)

    final = clean(all_links)

    print(f"\n[+] FOUND {len(final)} PDF FILES:\n")

    for link in final:
        print(format_link(link))

        if DOWNLOAD_PDFS:
            download_file(link)

    with open(OUTPUT_FILE, "w") as f:
        for link in final:
            f.write(format_link(link) + "\n")

    print("\n[+] DONE → saved to pdf_results.txt")


if __name__ == "__main__":
    main()