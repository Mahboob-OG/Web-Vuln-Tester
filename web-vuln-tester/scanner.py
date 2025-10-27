#!/usr/bin/env python3
"""
scanner.py - Basic WebVulnTester (text + JSON) with cookie security checks
Usage:
  python scanner.py https://example.com
  python scanner.py https://example.com --json
"""
import sys
import json
import argparse
from urllib.parse import urljoin, urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "WebVulnTester/1.0 (+https://github.com/yourname)"}

def make_session(retries=3, backoff_factor=0.3, status_forcelist=(500,502,503,504)):
    s = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(["GET","POST","HEAD","OPTIONS"])
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update(HEADERS)
    return s

SESSION = make_session()

def fetch(url, data=None, method="get", timeout=20):
    try:
        if method == "post":
            r = SESSION.post(url, data=data, timeout=timeout)
        else:
            r = SESSION.get(url, params=data, timeout=timeout)
        return r
    except requests.exceptions.ReadTimeout:
        return None
    except requests.RequestException:
        return None

def fetch_robots(base_url):
    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    r = fetch(robots_url, timeout=12)
    if r and r.status_code == 200:
        return r.text[:2000]
    if parsed.scheme == "https":
        fallback = f"http://{parsed.netloc}/robots.txt"
        r2 = fetch(fallback, timeout=12)
        if r2 and r2.status_code == 200:
            return r2.text[:2000]
    return None

def find_forms(html, base_url):
    soup = BeautifulSoup(html or "", "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = []
        for inp in form.find_all(["input","textarea","select"]):
            inputs.append({
                "name": inp.get("name"),
                "type": inp.get("type"),
                "value": inp.get("value"),
            })
        forms.append({
            "action": urljoin(base_url, action) if action else base_url,
            "method": method,
            "inputs": inputs
        })
    return forms

def check_cookies(resp):
    """
    Return a list of cookie objects and list of cookie issues.
    Each cookie object: {name, attrs}
    cookie_issues: list of {cookie, issue}
    """
    cookies = []
    issues = []
    # requests.Response.cookies only contains parsed cookies (not attributes)
    # So parse Set-Cookie headers to get attributes
    sc = resp.headers.get("Set-Cookie")
    if not sc:
        # maybe multiple cookies; requests merges them; try raw header retrieval
        headers = resp.raw.headers if hasattr(resp, 'raw') else {}
        sc = headers.get('Set-Cookie') if headers else None
    # Simpler: use requests.utils.dict_from_cookiejar for names, but attributes must be parsed
    # We'll attempt to parse multiple Set-Cookie occurrences
    raw_headers = []
    # Using resp.headers.get_all is not portable; use resp.raw if possible
    try:
        # requests' raw may be urllib3 response
        if hasattr(resp.raw, "headers"):
            for k, v in resp.raw.headers.items():
                if k.lower() == "set-cookie":
                    raw_headers.append(v)
    except Exception:
        pass
    # fallback: try resp.headers (may join cookies)
    if not raw_headers and "set-cookie" in (k.lower() for k in resp.headers.keys()):
        # collect all Set-Cookie-like values (best-effort)
        for k, v in resp.headers.items():
            if k.lower() == "set-cookie":
                raw_headers.append(v)

    # If nothing: return empty
    if not raw_headers:
        return cookies, issues

    for hdr in raw_headers:
        # each hdr may contain a cookie string like "name=value; Path=/; Secure; HttpOnly; SameSite=Lax"
        parts = [p.strip() for p in hdr.split(";")]
        if not parts:
            continue
        name_part = parts[0]
        if "=" in name_part:
            name = name_part.split("=", 1)[0]
        else:
            name = name_part
        attrs = {}
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=",1)
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[p.strip().lower()] = True
        cookies.append({"name": name, "attrs": attrs})
        # check common issues
        if "secure" not in attrs:
            issues.append({"cookie": name, "issue": "Missing Secure flag (sent over HTTPS can be intercepted over non-HTTPS)"})
        if "httponly" not in attrs:
            issues.append({"cookie": name, "issue": "Missing HttpOnly flag (accessible to JavaScript)"})
        if "samesite" not in attrs:
            issues.append({"cookie": name, "issue": "Missing SameSite attribute (no CSRF mitigation guidance)"})
    return cookies, issues

# small built-in bruteforce list
DEFAULT_WORDS = ["admin","login","dashboard","robots.txt","sitemap.xml","uploads","images","backup","test","api","config","wp-admin","index.php","index.html","secret","private"]

def brute_dirs(target, words=None):
    import requests
    from urllib.parse import urljoin, urlparse
    if words is None:
        words = DEFAULT_WORDS
    session = make_session(retries=2, backoff_factor=0.2)
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}/"
    found = []
    for w in words:
        path = w if w.startswith("/") else f"/{w}"
        url = urljoin(base, path.lstrip("/"))
        try:
            r = session.get(url, timeout=8, allow_redirects=False)
            status = r.status_code
            if status in (200,301,302,401,403):
                found.append({"url": url, "status": status})
        except requests.RequestException:
            continue
    return found

def test_xss_on_form(form):
    findings = []
    payload = "<script>alert('xss')</script>"
    data = {}
    for inp in form["inputs"]:
        if inp["name"]:
            data[inp["name"]] = payload
    r = fetch(form["action"], data=data, method=form["method"])
    if r and payload in (r.text or ""):
        findings.append({"type":"reflected-xss","action":form["action"],"method":form["method"],"payload":payload})
    return findings

def test_sqli_on_form(form):
    findings = []
    sqli_payloads = ["' OR '1'='1","' OR 1=1--",'" OR "1"="1']
    errors = ["sql syntax","mysql","syntax error","database error","ORA-"]
    for payload in sqli_payloads:
        data = {}
        for inp in form["inputs"]:
            if inp["name"]:
                data[inp["name"]] = payload
        r = fetch(form["action"], data=data, method=form["method"])
        if r and any(err in (r.text or "").lower() for err in errors):
            findings.append({"type":"sqli","action":form["action"],"method":form["method"],"payload":payload})
            break
    return findings

def scan_target(target):
    out = {
        "target": target,
        "final_url": None,
        "status_code": None,
        "content_type": None,
        "security_headers": {},
        "robots_txt": None,
        "forms": [],
        "vulnerabilities": [],
        "bruteforce": [],
        "cookies": [],
        "cookie_issues": []
    }
    if not urlparse(target).scheme:
        target = "http://" + target
    r = fetch(target)
    if not r:
        return out
    out["final_url"] = r.url
    out["status_code"] = r.status_code
    out["content_type"] = r.headers.get("Content-Type")
    for h in ["Content-Security-Policy","X-Content-Type-Options","X-Frame-Options","X-XSS-Protection","Strict-Transport-Security","Referrer-Policy"]:
        out["security_headers"][h] = r.headers.get(h)
    out["robots_txt"] = fetch_robots(target)
    forms = find_forms(r.text, r.url)
    out["forms"] = forms
    for form in forms:
        out["vulnerabilities"].extend(test_xss_on_form(form))
        out["vulnerabilities"].extend(test_sqli_on_form(form))
    # bruteforce (light default)
    out["bruteforce"] = brute_dirs(target)
    # cookie checks
    cookies, issues = check_cookies(r)
    out["cookies"] = cookies
    out["cookie_issues"] = issues
    return out

def pretty_print(result):
    if not result.get("final_url"):
        print("[!] No response from target (or fetch failed).")
        return
    print(f"[+] Scanning: {result['target']}")
    print("=== BASIC RESPONSE INFO ===")
    print(f"URL: {result['final_url']}")
    print(f"Status Code: {result['status_code']}")
    print(f"Content-Type: {result['content_type']}")
    print()
    print("=== SECURITY-RELATED HEADERS ===")
    for k,v in result["security_headers"].items():
        print(f"{k}: {v}")
    print()
    print("=== robots.txt ===")
    print(result["robots_txt"] or "robots.txt not found (status: no response)")
    print()
    print("=== FORMS FOUND ===")
    if not result["forms"]:
        print("No forms found on the page.")
    else:
        for i,f in enumerate(result["forms"],1):
            print(f"[Form #{i}] {f['method'].upper()} -> {f['action']}")
            for inp in f["inputs"]:
                print(f"    - {inp['name']} (type={inp['type']})")
    print()
    if result["vulnerabilities"]:
        print("=== VULNERABILITIES FOUND ===")
        for v in result["vulnerabilities"]:
            print(f" - {v['type']} on {v.get('action')} (payload: {v.get('payload')})")
    else:
        print("=== VULNERABILITIES FOUND ===\nNone detected.")
    print()
    print("=== COOKIE CHECKS ===")
    if result["cookies"]:
        for c in result["cookies"]:
            print(f" - {c['name']} -> attrs={c['attrs']}")
    else:
        print("No cookies set.")
    if result["cookie_issues"]:
        print("=== COOKIE ISSUES ===")
        for it in result["cookie_issues"]:
            print(f" - {it['cookie']}: {it['issue']}")
    print()
    print("=== BRUTE-FORCE RESULTS ===")
    if result["bruteforce"]:
        for f in result["bruteforce"]:
            print(f" - {f['url']} -> {f['status']}")
    else:
        print("No interesting paths found.")
    print()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()
    res = scan_target(args.target)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        pretty_print(res)

if __name__ == "__main__":
    main()
