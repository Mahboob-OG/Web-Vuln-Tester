#!/usr/bin/env python3
"""
app.py — with History Page (lists past reports)
"""

import subprocess, os, json, html
from datetime import datetime
from flask import Flask, render_template_string, request, redirect, url_for, send_from_directory

app = Flask(__name__)
BASE_DIR = os.path.dirname(__file__)
REPORT_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

# ==========
# TEMPLATE (Dashboard + History page)
# ==========
TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>WebVulnTester — Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { padding:20px; background:#f5f7fb; color:#222; }
    .card { box-shadow: 0 6px 18px rgba(40,50,80,0.06); }
    pre{ background:#0b0b0b;color:#eaeaea;padding:14px;border-radius:6px;overflow:auto; max-height:420px;}
    .badge-high { background:#e55353; color:#fff; }
    .badge-medium { background:#f0ad4e; color:#fff; }
    .badge-low { background:#5cb85c; color:#fff; }
    .muted-small { color:#666; font-size:0.9rem; }
    @media print { .no-print, form, .btn { display:none!important; } }
  </style>
</head>
<body>
<div class="container">

  <!-- NAVBAR -->
  <nav class="mb-4 d-flex justify-content-between align-items-center">
    <div><h2 class="m-0">WebVulnTester</h2></div>
    <div class="no-print">
      <a href="{{ url_for('index') }}" class="btn btn-outline-primary btn-sm me-2">Home</a>
      <a href="{{ url_for('history') }}" class="btn btn-primary btn-sm">History</a>
    </div>
  </nav>

  {% block content %}{% endblock %}

</div>
</body>
</html>
"""

# ==========
# HISTORY PAGE TEMPLATE
# ==========
HISTORY_TEMPLATE = r"""
{% extends TEMPLATE %}
{% block content %}
<div class="card p-3">
  <h4 class="mb-3">📜 Scan History</h4>
  {% if scans %}
  <table class="table table-striped align-middle">
    <thead>
      <tr><th>Target</th><th>Date</th><th>HTML Report</th><th>JSON</th><th>Score</th></tr>
    </thead>
    <tbody>
      {% for s in scans %}
        <tr>
          <td>{{ s.target }}</td>
          <td>{{ s.time }}</td>
          <td>
            {% if s.html_url %}
              <a href="{{ s.html_url }}" target="_blank" class="btn btn-sm btn-outline-primary">View</a>
            {% else %}-{% endif %}
          </td>
          <td>
            {% if s.json_url %}
              <a href="{{ s.json_url }}" class="btn btn-sm btn-outline-secondary">Download</a>
            {% else %}-{% endif %}
          </td>
          <td><span class="badge bg-secondary">{{ s.score }}</span></td>
        </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No reports found yet. Run a scan to generate your first report!</p>
  {% endif %}
</div>
{% endblock %}
"""

# ==========
# Utility functions
# ==========

def parse_report_filename(fname):
    """Extract readable info from file name"""
    base = fname.replace("report_", "").replace("scan_", "")
    parts = base.split("_")
    if len(parts) >= 3:
        target = parts[0].replace("https", "").replace("http", "").strip("_")
        date_str = "_".join(parts[-2:]).replace(".html", "").replace(".json", "")
    else:
        target = base
        date_str = ""
    try:
        time_fmt = datetime.strptime(date_str, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        time_fmt = date_str
    return target, time_fmt


def get_scan_history():
    """List JSON and HTML reports from the reports folder"""
    files = os.listdir(REPORT_DIR)
    scans = []
    for fname in files:
        if not (fname.endswith(".html") or fname.endswith(".json")):
            continue
        target, time_fmt = parse_report_filename(fname)
        score = ""
        html_url = None
        json_url = None

        if fname.endswith(".html"):
            html_url = url_for("download_report", filename=fname)
        elif fname.endswith(".json"):
            json_url = url_for("download_json", filename=fname)
            try:
                with open(os.path.join(REPORT_DIR, fname), "r", encoding="utf-8") as f:
                    data = json.load(f)
                    score = data.get("__score__", "")
            except Exception:
                pass

        scans.append({
            "target": target,
            "time": time_fmt,
            "html_url": html_url,
            "json_url": json_url,
            "score": score or "-"
        })

    # Sort by date (newest first)
    scans.sort(key=lambda x: x["time"], reverse=True)
    return scans


# ==========
# ROUTES
# ==========
@app.route("/history")
def history():
    scans = get_scan_history()
    return render_template_string(HISTORY_TEMPLATE, TEMPLATE=TEMPLATE, scans=scans)


@app.route("/reports/<path:filename>")
def download_report(filename):
    return send_from_directory(REPORT_DIR, filename, as_attachment=False)

@app.route("/download_json/<path:filename>")
def download_json(filename):
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


@app.route("/")
def index():
    return render_template_string(TEMPLATE, TEMPLATE=TEMPLATE)


if __name__ == "__main__":
    app.run(debug=False, port=5000)
