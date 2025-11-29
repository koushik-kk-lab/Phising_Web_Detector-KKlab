# features_backend/app.py
from flask import Flask, request, jsonify, render_template, send_file
import joblib
import os
import sys
import re
from urllib.parse import urlparse
from datetime import datetime
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# External libs used by some helpers
import whois
import dns.resolver
import ssl, socket
import requests
from bs4 import BeautifulSoup

# ---- PATHS ----
CURRENT_FILE = os.path.abspath(__file__)
PROJECT_ROOT = os.path.dirname(os.path.dirname(CURRENT_FILE))
FEATURES_PATH = os.path.join(PROJECT_ROOT, "features")
if FEATURES_PATH not in sys.path:
    sys.path.insert(0, FEATURES_PATH)

from url_features import get_features

app = Flask(__name__, template_folder=os.path.join(PROJECT_ROOT, "templates"))

# Load model
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "phish_rf.pkl")
model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None
if model is None:
    print("⚠ Model not found: place phish_rf.pkl in models/")

# ---------------- Helpers ----------------

def check_domain_age(domain):
    try:
        info = whois.whois(domain)
        created = info.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return None
        return (datetime.now() - created).days
    except:
        return None

def dns_analysis(domain):
    result = {"ip": None, "mx_records": []}
    try:
        answers = dns.resolver.resolve(domain, 'A', lifetime=3)
        if answers:
            result["ip"] = answers[0].to_text()
    except:
        pass
    try:
        mx = dns.resolver.resolve(domain, 'MX', lifetime=3)
        for r in mx:
            result["mx_records"].append(str(r.exchange).rstrip("."))
    except:
        pass
    return result

def ssl_expiry(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(4)
            s.connect((domain, 443))
            cert = s.getpeercert()
            if "notAfter" in cert:
                exp_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                return (exp_date - datetime.now()).days
        return None
    except:
        return None

def ip_reputation(ip):
    if not ip: return ("unknown", 0)
    bad_ranges = ["45.", "146.70.", "185.", "198.144."]
    for p in bad_ranges:
        if ip.startswith(p):
            return ("suspicious", 40)
    return ("normal", 0)

def html_phishing_scan(url):
    findings = []
    try:
        r = requests.get(url, timeout=4, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.text, "html.parser")
        if soup.find("input", {"type": "password"}):
            findings.append("Password field detected — possible fake login page")
        for tag in soup.find_all("script"):
            src = (tag.get("src") or "").lower()
            if any(x in src for x in ["track", "steal", "collect"]):
                findings.append("Suspicious external script: " + src)
    except:
        pass
    return findings

# ---------------- PDF report generator ----------------
def generate_pdf_report(report: dict):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    w, h = letter
    x = 40
    y = h - 40
    c.setFont("Helvetica-Bold", 16)
    c.drawString(x, y, "Phishing Scan Report")
    y -= 28
    c.setFont("Helvetica", 11)
    lines = [
        f"URL: {report.get('url')}",
        f"Prediction: {report.get('prediction')} ({report.get('color')})",
        f"Threat Score: {report.get('score')}%",
        f"Domain: {report.get('domain_info', {}).get('domain', '')}",
        f"IP: {report.get('domain_info', {}).get('ip', '')}",
        f"MX: {', '.join(report.get('domain_info', {}).get('mx_records', []))}",
        f"SSL days left: {report.get('domain_info', {}).get('ssl_days', 'N/A')}",
        f"Domain age (days): {report.get('domain_info', {}).get('age_days', 'N/A')}"
    ]
    for L in lines:
        y -= 18
        c.drawString(x, y, L)
    y -= 22
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x, y, "Reasons:")
    c.setFont("Helvetica", 11)
    for r in report.get("reasons", []):
        y -= 16
        # wrap if needed
        if len(r) > 100:
            pieces = [r[i:i+100] for i in range(0, len(r), 100)]
            for p in pieces:
                y -= 14
                c.drawString(x+8, y, p)
        else:
            c.drawString(x+8, y, "- " + r)
        if y < 60:
            c.showPage()
            y = h - 40
    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer

# ---------------- Routes ----------------

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json() or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL missing"}), 400
    if model is None:
        return jsonify({"error": "Model not loaded"}), 500

    parsed = urlparse(url)
    domain = parsed.netloc.lower().replace("www.", "")
    if ":" in domain:
        domain = domain.split(":")[0]

    reasons = []
    risk_score = 0

    # Safe checks
    if url.startswith("file://") or domain in ["localhost", "127.0.0.1"]:
        out = {"prediction":"Legitimate","color":"green","score":0,"reasons":[],"domain_info":{"domain":domain}}
        out["url"] = url
        return jsonify(out)

    if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))", domain):
        out = {"prediction":"Legitimate","color":"green","score":0,"reasons":[],"domain_info":{"domain":domain}}
        out["url"] = url
        return jsonify(out)

    # Trusted global domains
    TRUSTED_PATTERN = r"(google|youtube|gmail|amazon|facebook|linkedin|apple|github|microsoft|paypal|wikipedia|netflix)\.com$"
    if re.search(TRUSTED_PATTERN, domain):
        out = {"prediction":"Legitimate","color":"green","score":0,"reasons":["Trusted global domain"],"domain_info":{"domain":domain}}
        out["url"] = url
        return jsonify(out)

    # Typosquatting checks
    typos = ["paypa1","g00gle","amaz0n","faceb00k","micros0ft","netfIix"]
    for t in typos:
        if t in domain:
            reasons.append(f"Typosquatting detected: {t}")
            risk_score += 40

    # Risky TLDs
    risky_tlds = [".xyz", ".top", ".gq", ".tk", ".ml", ".zip", ".click", ".live", ".work", ".shop"]
    for t in risky_tlds:
        if domain.endswith(t):
            reasons.append(f"Risky TLD: {t}")
            risk_score += 30

    # Suspicious keywords
    bad_words = ["verify","update","bank","secure","reset","otp","login","confirm","credential"]
    for w in bad_words:
        if w in url.lower():
            reasons.append(f"Suspicious keyword in URL: {w}")
            risk_score += 20

    # Too many subdomains
    if domain.count(".") >= 4:
        reasons.append("Many subdomains")
        risk_score += 20

    # Encoded/obfuscated
    if "%" in url or "@" in url or "\\" in url:
        reasons.append("Encoded/obfuscated URL")
        risk_score += 25

    # WHOIS age
    age = check_domain_age(domain)
    if age is not None:
        if age < 30:
            reasons.append("Very new domain (<30 days)")
            risk_score += 25
        elif age < 180:
            reasons.append("New domain (<6 months)")
            risk_score += 10

    # DNS & IP reputation
    dns_info = dns_analysis(domain)
    ip = dns_info.get("ip")
    if ip:
        rep, boost = ip_reputation(ip)
        if rep != "normal":
            reasons.append(f"Suspicious hosting IP: {ip}")
            risk_score += boost

    # SSL expiry
    ssl_days = ssl_expiry(domain)
    if ssl_days is not None:
        if ssl_days < 0:
            reasons.append("SSL certificate expired")
            risk_score += 30
        elif ssl_days < 15:
            reasons.append("SSL certificate expiring soon (<15 days)")
            risk_score += 10

    # HTML page scan
    html_findings = html_phishing_scan(url)
    for f in html_findings:
        reasons.append(f)
        risk_score += 20

    # ML decision
    try:
        features = [get_features(url)]
        pred = model.predict(features)[0]
        if pred == 1:
            reasons.append("ML model predicted phishing")
            risk_score += 40
        else:
            reasons.append("ML model predicted safe")
            risk_score -= 10
    except Exception as e:
        # don't fail hard if ML raises
        print("ML error:", e)

    # final score clamp
    risk_score = max(0, min(100, risk_score))

    if risk_score <= 20:
        prediction = "Legitimate"
        color = "green"
    elif risk_score <= 60:
        prediction = "Suspicious"
        color = "orange"
    else:
        prediction = "Phishing"
        color = "red"

    domain_info = {
        "domain": domain,
        "ip": ip,
        "mx_records": dns_info.get("mx_records", []),
        "ssl_days": ssl_days,
        "age_days": age
    }

    out = {
        "url": url,
        "prediction": prediction,
        "color": color,
        "score": risk_score,
        "reasons": reasons,
        "domain_info": domain_info
    }
    return jsonify(out)

# ---------------- PDF endpoint ----------------
@app.route("/report", methods=["POST"])
def report():
    """
    Accepts same JSON as /predict output and returns a PDF file.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    pdf_buf = generate_pdf_report(data)
    return send_file(pdf_buf, mimetype="application/pdf", as_attachment=True, download_name="phish_report.pdf")


if __name__ == "__main__":
    app.run(debug=True)
