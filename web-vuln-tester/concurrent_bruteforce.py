#!/usr/bin/env python3
"""
concurrent_bruteforce.py - Threaded directory brute-force with JSON option
Usage:
  python concurrent_bruteforce.py https://example.com
  python concurrent_bruteforce.py https://example.com --wordlist wl.txt --workers 15 --json
"""
import sys, argparse, json
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
from pathlib import Path

DEFAULT_WORDS = [
    "admin","login","dashboard","robots.txt","sitemap.xml","uploads","images",
    "backup","test","api","config","wp-admin","index.php","index.html","secret","private"
]

def make_session():
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.2, status_forcelist=(500,502,503,504))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.headers.update({"User-Agent":"WebVulnTester/1.0 (+https://github.com/yourname)"})
    return s

def load_wordlist(path):
    if not path:
        return DEFAULT_WORDS
    p = Path(path)
    if not p.exists():
        print(f"[!] Wordlist file not found: {path}. Using default list.")
        return DEFAULT_WORDS
    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def probe_url(session, url, timeout=6):
    try:
        r = session.get(url, timeout=timeout, allow_redirects=False)
        return url, r.status_code
    except requests.RequestException:
        return url, None

def brute_force(target, words, max_workers=10):
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}/"
    session = make_session()
    found = []
    tasks = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for w in words:
            path = w if w.startswith("/") else f"/{w}"
            url = urljoin(base, path.lstrip("/"))
            tasks.append(ex.submit(probe_url, session, url))
        for fut in as_completed(tasks):
            url, status = fut.result()
            if status in (200,301,302,401,403):
                found.append({"url": url, "status": status})
    return found

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target URL (include http:// or https://)")
    parser.add_argument("--wordlist", "-w", help="Optional wordlist file")
    parser.add_argument("--json", action="store_true", help="Emit JSON result")
    parser.add_argument("--workers", type=int, default=10, help="Max concurrent workers")
    args = parser.parse_args()
    words = load_wordlist(args.wordlist)
    start = time.time()
    found = brute_force(args.target, words, max_workers=args.workers)
    elapsed = time.time() - start
    if args.json:
        print(json.dumps({"target": args.target, "elapsed": elapsed, "found": found}, indent=2))
    else:
        print(f"Finished in {elapsed:.2f}s - {len(found)} interesting paths found.")
        for p in found:
            print(f"{p['url']} -> {p['status']}")

if __name__ == "__main__":
    main()
