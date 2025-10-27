Web Application Vulnerability Tester - README (Plain Text)
----------------------------------------------------------

Project: Web Application Vulnerability Tester
A Python + Flask based tool that scans websites for common security vulnerabilities
such as missing HTTP headers, unprotected cookies, exposed directories, and expired
SSL certificates. This project demonstrates fundamentals of ethical hacking,
secure coding, and automated vulnerability assessment.

Features:
---------
- Automated Security Scanning:
  * Analyzes HTTP responses for essential security headers
  * Detects missing protections like X-Frame-Options, Strict-Transport-Security,
    and Content-Security-Policy
  * Checks for insecure cookies (missing HttpOnly, Secure, or SameSite flags)
  * Identifies form inputs that may lead to data exposure

- Directory & File Brute-Forcing:
  * Concurrent scanning for common sensitive directories such as:
    /admin, /config, /backup, /uploads, /api, /private
  * Detects exposed files like robots.txt, .env, or sitemap.xml

- Comprehensive Reporting:
  * Generates clean, styled HTML reports summarizing vulnerabilities
  * Includes a one-pager checklist report with a quick security rating
  * Exportable for academic or professional use

- Performance:
  * Multi-threaded directory discovery for speed
  * Lightweight, modular codebase for easy modification

Tech Stack:
-----------
- Language: Python 3.13
- Framework: Flask
- Libraries: requests, beautifulsoup4, urllib3, reportlab (if used)
- Output Formats: HTML, JSON, Console

Project Structure:
------------------
web-vuln-tester/
|
├── app.py                   # Flask web interface
├── scanner.py               # Main vulnerability scanner
├── dir_bruteforce.py        # Directory brute-forcing module
├── concurrent_bruteforce.py # Optimized concurrent scanning
├── one_pager.py             # One-pager checklist report generator
|
├── templates/               # HTML templates for web interface
├── static/                  # CSS, JS, and assets for reports
├── reports/                 # Generated HTML reports
|
├── requirements.txt         # Dependency list
└── README.txt               # Project documentation (this file)

Installation & Setup:
---------------------
1) Clone the repository:
   git clone https://github.com/<your-username>/web-vuln-tester.git
   cd web-vuln-tester

2) Create a virtual environment:
   python -m venv venv

   Activate it:
   - Windows (PowerShell):
     .\venv\Scripts\Activate.ps1
   - Linux/Mac:
     source venv/bin/activate

3) Install dependencies:
   pip install -r requirements.txt

Usage:
------
- Run the scanner from the command line:
  python scanner.py https://example.com

- Run the Flask web interface:
  python app.py
  Then open your browser and go to:
  http://127.0.0.1:5000/

- Generate the one-pager security checklist (auto-detects the latest JSON report):
  python one_pager.py

Sample Console Output:
----------------------
[+] Scanning: https://example.com
=== BASIC RESPONSE INFO ===
Status Code: 200
Content-Type: text/html

=== SECURITY-RELATED HEADERS ===
Content-Security-Policy: None
X-Frame-Options: None
X-XSS-Protection: None
Strict-Transport-Security: None

=== DIRECTORY BRUTE-FORCE ===
/index.html -> 200
/admin -> 404
/config -> 404

Reports:
--------
- Full HTML report: saved under the reports/ folder (report_<target>_<timestamp>.html)
- JSON scan data: saved as scan_<target>_<timestamp>.json
- One-pager checklist: reports/onepager_checklist_*.html (A4-friendly)

Example Checklist Summary (one-pager):
--------------------------------------
Check                    Status
Content Security Policy  ❌ Missing
X-Frame-Options          ❌ Missing
Secure Cookies           ✅ Present
SSL Certificate Valid    ✅ Yes
robots.txt Found         ❌ No
Directory Exposure       ⚠️ Possible

Security Rating Example: 72%
Recommendation: Add missing headers, enforce HTTPS, and review exposed directories.

Future Enhancements:
--------------------
- XSS and SQL Injection detection modules
- Subdomain enumeration
- Automatic SSL expiry alerts
- Integration with OWASP ZAP or Nmap
- Cloud dashboard for continuous monitoring

Disclaimer:
-----------
WARNING: Use this tool only for educational and authorized testing.
Scanning or testing websites without explicit permission is illegal and unethical.
The author is not responsible for misuse of this software.

License:
--------
This project is available under the MIT License.

Author:
-------
Mahboob Alam
BCA Student — The Heritage Academy
Email: mahboobalam10a@gmail.com

Support:
--------
If you find this project useful, please give it a star on GitHub!
