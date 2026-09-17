PDF Recon & OSINT Toolkit

A collection of Python command-line tools designed to aggregate, filter, classify, and optionally download public PDF documents, research papers, government archives, and declassified records across multiple search engines.
Features

    Multi-Engine Aggregation: Queries Bing, DuckDuckGo, Yahoo, Brave, and Startpage simultaneously.

    Query Matrix Expansion: Automatically expands target keywords with targeted filters (filetype:pdf, site:gov, site:edu, site:cia.gov, etc.).

    Smart URL Cleaning: Handles redirects and tracking wrappers to extract direct PDF links.

    Document Classification & Tagging (pdfsearch-secret.py): Automatically flags records based on domain identifiers (e.g., CIA, NSA, DOD, National Archives) and scans URLs for intelligence/FOIA metadata tags.

    Automated Downloader: Optional batch-download capability with verification checks to ensure retrieved payloads are valid PDF files.

    Output Logging: Dumps clean, structured results directly to a text file (pdf_results.txt).

Scripts Included

    pdfsearch-secret.py: The advanced reconnaissance script featuring a stylized terminal interface (colorama), extensive government/intelligence query expansion matrices, automated domain classification, metadata tagging, and robust anti-bot/error handling.

    pdfsearch.py: A lightweight, minimalist implementation ideal for quick queries and straightforward script execution.

Requirements

    Python 3.x

    requests

    beautifulsoup4

    colorama (Required for the advanced terminal UI in pdfsearch-secret.py)
    
    Installation

    Clone the repository:
    
    git clone https://github.com/Klodi666/pdf-recon-toolkit.git
    cd pdf-recon-toolkit
    
    pip install requests beautifulsoup4 colorama
    
    python pdfsearch.py
    
    Disclaimer

These tools are designed for open-source intelligence (OSINT), academic research, and public record discovery. Ensure that your usage complies with the terms of service of the queried search engines and applicable local laws.
