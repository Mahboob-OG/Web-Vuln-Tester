# Web-Vuln-Tester


# 🛡️ Web Application Vulnerability Tester

A lightweight, Python-based tool that scans web applications for common security vulnerabilities such as missing security headers, unprotected cookies, exposed directories, and expired SSL certificates.  
Built using **Flask**, **Requests**, and **BeautifulSoup**, it’s designed for **educational and ethical** use.

---

## 🚀 Features

✅ **Automated Security Scanning**
- Checks essential HTTP security headers  
- Validates SSL/TLS certificate expiration  
- Detects unsafe cookies (`Secure`, `HttpOnly`, `SameSite`)  
- Identifies HTML forms and potential input points  

✅ **Directory & File Discovery**
- Performs brute-force testing for common sensitive directories (`/admin`, `/config`, `/backup`, etc.)  
- Finds exposed files like `robots.txt`, `.env`, and `sitemap.xml`

✅ **Detailed Reports**
- Generates clean, styled **HTML reports** for each scan  
- Includes a **One-Pager Checklist Report** with a security score  
- Exportable for academic or professional submissions  

✅ **Fast & Lightweight**
- Uses concurrent requests for faster brute-forcing  
- Runs entirely offline — no external dependencies after setup  

## 📂 Project Structure

web-vuln-tester/
│
├── app.py # Flask web interface
├── scanner.py # Main vulnerability scanning logic
├── concurrent_bruteforce.py # Directory brute-forcing module
├── one_pager.py # Generates one-pager checklist report
│
├── templates/ # HTML templates for Flask app
├── static/ # CSS/JS/Images for styling reports
│
├── reports/ # Generated scan reports
├── requirements.txt # Dependencies list
└── README.md # Project documentation


---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository
bash :

git clone https://github.com/<your-username>/web-vuln-tester.git
cd web-vuln-tester

2️⃣ Create a Virtual Environment
python -m venv venv


Activate it:

Windows (PowerShell):

.\venv\Scripts\Activate.ps1


Linux/Mac:

source venv/bin/activate

3️⃣ Install Dependencies
pip install -r requirements.txt

🧪 Usage
▶️ Run from Command Line
python scanner.py https://example.com

▶️ Run the Web Interface
python app.py


Then open your browser and go to:

http://127.0.0.1:5000/

▶️ Generate One-Pager Checklist
python one_pager.py

📊 Sample Output

Example console output:

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

