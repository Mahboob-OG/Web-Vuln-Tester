#!/usr/bin/env python3
"""
Simple directory brute-forcer (wordlist-based)
Usage:
    python dir_bruteforce.py https://example.com wordlist.txt
If no wordlist is provided, a small built-in list is used.
"""

import sys
import os
from urllib.parse import urljoin, urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# small default wordlist (you can expand with a file)
DEFAULT_WORDS = [
    "admin", "login", "dashboard", "robots.txt", "sitemap.xml",
    "uploads", "images", "backup", "test", "api", "config", "wp-admin",
    "index.php", "index.html", "secret", "private"
]

def make_session():
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.2, status_forcelist=(500,502,503,504))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.headers.update({"User-Agent":"WebVulnTester/1.0"})
    return s

def load_wordlist(path):
    if not path:
        return DEFAULT_WORDS
    if not os.path.exists(path):
        print(f"[!] Wordlist file not found: {path}. Using small default list.")
        return DEFAULT_WORDS
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def scan(target, words):
    session = make_session()
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}/"
    found = []
    print(f"[+] Brute-forcing {base} ({len(words)} entries)")
    for w in words:
        path = w if w.startswith("/") else f"/{w}"
        url = urljoin(base, path.lstrip("/"))
        try:
            r = session.get(url, timeout=8, allow_redirects=False)
            status = r.status_code
            # consider 200, 301, 302, 401, 403 interesting
            if status in (200, 301, 302, 401, 403):
                print(f"    [+] {url} -> {status}")
                found.append((url, status))
            else:
                # small progress indicator for others -- optional
                print(f"    [-] {url} -> {status}", end="\r")
        except requests.RequestException as e:
            print(f"    [!] Error requesting {url}: {e}")
    print("\n[+] Done.")
    return found

def main():
    if len(sys.argv) < 2:
        print("Usage: python dir_bruteforce.py https://target [wordlist.txt]")
        sys.exit(1)
    target = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else None
    words = load_wordlist(wordlist)
    scan(target, words)

if __name__ == "__main__":
    main()
