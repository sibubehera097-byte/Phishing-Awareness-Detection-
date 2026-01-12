from flask import Flask, render_template, request
import requests
import sqlite3
import validators
from datetime import datetime

app = Flask(__name__)

# =========================
# CONFIGURATION
# =========================
VIRUSTOTAL_API_KEY = "7a5795658f7de898028a0191ab9324c75dfa8de9058cf21c38000bb35fbd0dbc7a5795658f7de898028a0191ab9324c75dfa8de9058cf21c38000bb35fbd0dbc"

# =========================
# DATABASE SETUP
# =========================
def init_db():
    conn = sqlite3.connect("phishing.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_type TEXT,
            content TEXT,
            score INTEGER,
            result TEXT,
            date TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# =========================
# PHISHING KEYWORDS
# =========================
PHISHING_KEYWORDS = [
    "urgent", "verify", "click here", "account suspended",
    "login now", "update password", "limited time"
]

# =========================
# VIRUSTOTAL URL CHECK
# =========================
def check_url_virustotal(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    submit_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(submit_url, headers=headers, data={"url": url})

    if response.status_code != 200:
        return 0, "VirusTotal check failed"

    analysis_id = response.json()["data"]["id"]

    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    report = requests.get(report_url, headers=headers).json()

    stats = report["data"]["attributes"]["stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    score = malicious * 20 + suspicious * 10
    return score, "VirusTotal analysis completed"

# =========================
# EMAIL CONTENT ANALYSIS
# =========================
def analyze_email(text):
    score = 0
    reasons = []

    text_lower = text.lower()

    for word in PHISHING_KEYWORDS:
        if word in text_lower:
            score += 10
            reasons.append(f"Suspicious keyword detected: '{word}'")

    if "http://" in text_lower:
        score += 10
        reasons.append("Unsecured (HTTP) link detected")

    return score, reasons

# =========================
# SAVE TO DATABASE
# =========================
def save_result(input_type, content, score, result):
    conn = sqlite3.connect("phishing.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (input_type, content, score, result, date)
        VALUES (?, ?, ?, ?, ?)
    """, (input_type, content, score, result, datetime.now()))
    conn.commit()
    conn.close()

# =========================
# MAIN ROUTE
# =========================
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    score = 0
    reasons = []

    if request.method == "POST":
        user_input = request.form.get("user_input")

        # URL CHECK
        if validators.url(user_input):
            vt_score, vt_msg = check_url_virustotal(user_input)
            score += vt_score
            reasons.append(vt_msg)
            input_type = "URL"

        # EMAIL CHECK
        else:
            email_score, email_reasons = analyze_email(user_input)
            score += email_score
            reasons.extend(email_reasons)
            input_type = "Email"

        # FINAL RESULT
        if score <= 30:
            result = "SAFE"
        elif score <= 60:
            result = "SUSPICIOUS"
        else:
            result = "PHISHING"

        save_result(input_type, user_input, score, result)

    return render_template("index.html",
                           result=result,
                           score=score,
                           reasons=reasons)

if __name__ == "__main__":
    app.run(debug=True)

