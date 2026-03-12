from flask import Flask, request, render_template
import pickle
import re
import urllib.parse
import socket
import whois
from datetime import datetime

from url_features import extract_features, BRANDS, PHISHING_KEYWORDS, SUSPICIOUS_TLDS

app = Flask(__name__)

# Load ML model + feature extractor (replaces old TF-IDF vectorizer)
model      = pickle.load(open("phishing_model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))


# ─────────────────────────────────────────────────
# URL Cleaning
# ─────────────────────────────────────────────────
def clean_url(url: str) -> str:
    return url.strip()


# ─────────────────────────────────────────────────
# Indicator Detection  (human-readable warnings)
# ─────────────────────────────────────────────────
def extract_indicators(url: str) -> list[str]:
    indicators = []
    u = url.lower().strip()

    if not u.startswith(('http://', 'https://')):
        parsed = urllib.parse.urlparse('http://' + u)
    else:
        parsed = urllib.parse.urlparse(u)

    hostname = parsed.hostname or ''
    path     = parsed.path or ''
    domain   = re.sub(r'^www\.', '', hostname)
    labels   = domain.split('.') if domain else []
    tld      = labels[-1] if labels else ''
    sld      = labels[-2] if len(labels) >= 2 else ''
    full     = re.sub(r'https?://', '', u)

    # HTTPS
    if not u.startswith('https'):
        indicators.append("No HTTPS — connection is not encrypted")

    # @ symbol
    if '@' in full:
        indicators.append("URL contains '@' — browser ignores everything before it")

    # IP address as host
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        indicators.append("IP address used instead of domain name")

    # Subdomain depth
    sub_count = max(0, len(labels) - 2)
    if sub_count >= 3:
        indicators.append(f"Excessive subdomain depth ({sub_count} levels)")
    elif sub_count == 2:
        indicators.append("Multiple subdomains detected")

    # URL length
    if len(url) > 100:
        indicators.append(f"Unusually long URL ({len(url)} chars)")
    elif len(url) > 75:
        indicators.append(f"Long URL ({len(url)} chars)")

    # Hyphen in SLD (paypal-login.com style)
    if '-' in sld:
        indicators.append(f"Hyphen in domain name: '{sld}' — common phishing pattern")

    # Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        indicators.append(f"Suspicious free TLD: '.{tld}'")

    # Phishing keywords
    for kw in PHISHING_KEYWORDS:
        if kw in full:
            indicators.append(f"Phishing keyword in URL: '{kw}'")

    # Brand impersonation — only flag if brand is NOT the actual SLD
    for brand in BRANDS:
        if brand in full:
            if brand != sld:
                indicators.append(f"Brand impersonation detected: '{brand}' (not the real domain)")
            # Brand appears in subdomain of a different domain
            if len(labels) > 2 and brand in '.'.join(labels[:-2]):
                indicators.append(f"'{brand}' appears in subdomain — likely spoofing")

    # Punycode / IDN homograph
    if 'xn--' in hostname:
        indicators.append("Punycode/IDN domain — possible homograph attack")

    # Hex / percent encoding
    if re.search(r'%[0-9a-f]{2}', full):
        indicators.append("Percent-encoded characters — possible URL obfuscation")

    # Double slash in path (redirect trick)
    if '//' in path:
        indicators.append("Double slash in path — possible open redirect")

    # Non-standard port
    if parsed.port and parsed.port not in (80, 443):
        indicators.append(f"Non-standard port: {parsed.port}")

    # Too many dots (beyond normal subdomain)
    if full.count('.') > 5:
        indicators.append(f"Excessive dots in URL ({full.count('.')})")

    # Excessive hyphens
    if full.count('-') > 4:
        indicators.append(f"Many hyphens in URL ({full.count('-')}) — obfuscation pattern")

    return indicators


# ─────────────────────────────────────────────────
# Domain Intelligence
# ─────────────────────────────────────────────────
def get_domain_info(url: str) -> dict:
    info = {"ip": "Unknown", "registrar": "Unknown", "age": "Unknown"}

    try:
        if not url.startswith("http"):
            url = "http://" + url

        parsed = urllib.parse.urlparse(url)
        domain = re.sub(r'^www\.', '', parsed.netloc or '')

        info["ip"] = socket.gethostbyname(domain)

        w = whois.whois(domain)

        if w.registrar:
            info["registrar"] = w.registrar

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age = datetime.now() - creation
            info["age"] = age.days // 365

    except Exception as e:
        print("Domain lookup error:", e)

    return info


# ─────────────────────────────────────────────────
# Risk Scoring  (weighted, ML-informed)
# ─────────────────────────────────────────────────
def calculate_risk(prediction_label: int, confidence: float,
                   indicators: list, domain_info: dict,
                   url: str) -> tuple[int, str]:
    """
    Returns (risk_score 0-100, risk_label).
    Combines ML output + rule-based indicators with proper weights
    so neither alone dominates.
    """
    score = 0
    u = url.lower()

    # ── 1. ML model contribution (max 45 pts) ──────────────────
    if prediction_label == 1:          # model says phishing
        # Scale by confidence: 50% conf → 22 pts,  99% conf → 45 pts
        score += int(45 * min(confidence / 100, 1.0))
    else:
        # Model says legit but with low confidence → small penalty
        if confidence < 60:
            score += 5

    # ── 2. High-certainty rule signals (fixed pts each) ─────────
    RULE_WEIGHTS = {
        "IP address used":            20,
        "Punycode":                   18,
        "Hyphen in domain name":      12,
        "Suspicious free TLD":        12,
        "Brand impersonation":        15,
        "brand' appears in subdomain": 15,
        "No HTTPS":                    8,
        "Excessive subdomain":         8,
        "Multiple subdomains":         5,
        "@":                          10,
        "Percent-encoded":             6,
        "Double slash":                6,
        "Non-standard port":           6,
        "Phishing keyword":            5,  # per keyword (handled below)
        "Unusually long URL":          5,
        "Long URL":                    3,
        "Excessive dots":              4,
        "Many hyphens":                4,
    }

    keyword_count = 0
    for ind in indicators:
        for key, pts in RULE_WEIGHTS.items():
            if key.lower() in ind.lower():
                if key == "Phishing keyword":
                    keyword_count += 1
                else:
                    score += pts
                break

    # Phishing keywords: first one = 5 pts, diminishing returns
    score += min(keyword_count * 5, 20)

    # ── 3. Domain age penalty ────────────────────────────────────
    if domain_info["age"] != "Unknown":
        age = int(domain_info["age"])
        if age < 1:
            score += 15
        elif age < 2:
            score += 8
        elif age < 3:
            score += 4

    # ── 4. Hard overrides ────────────────────────────────────────
    # If IP is used AND model says phishing → near-certain phishing
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}', u.replace('http://', '').replace('https://', '')):
        score = max(score, 75)

    # Punycode is almost always an attack
    if 'xn--' in u:
        score = max(score, 70)

    # ── 5. Clamp ─────────────────────────────────────────────────
    score = min(score, 100)
    score = max(score, 0)

    # ── 6. Label ─────────────────────────────────────────────────
    if score >= 65:
        label = "HIGH 🔴"
    elif score >= 35:
        label = "MEDIUM 🟡"
    else:
        label = "LOW 🟢"

    return score, label


# ─────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    url = request.form["url"].strip()

    # Feature extraction → ML prediction
    features = vectorizer.transform([url])
    pred_arr  = model.predict(features)
    prob_arr  = model.predict_proba(features)

    prediction_label = int(pred_arr[0])
    confidence = round(float(prob_arr[0][prediction_label]) * 100, 2)

    # Rule-based indicators
    indicators = extract_indicators(url)

    # Domain intelligence (IP, registrar, age)
    domain_info = get_domain_info(url)

    # Risk score
    risk_score, risk = calculate_risk(
        prediction_label, confidence, indicators, domain_info, url
    )

    security_score = 100 - risk_score

    # Human-readable verdict
    if risk_score >= 65:
        result = "Phishing URL ⚠️"
    elif risk_score >= 35:
        result = "Suspicious URL"
    else:
        result = "Legitimate URL ✅"

    return render_template(
        "index.html",
        url=url,
        prediction=result,
        confidence=confidence,
        risk=risk,
        indicators=indicators,
        domain_info=domain_info,
        security_score=security_score,
    )


if __name__ == "__main__":
    app.run(debug=True)