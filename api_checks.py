import re
import requests
import streamlit as st
 
# =====================================================
# API KEYS — loaded from Streamlit secrets only
# NEVER hardcode keys here
# =====================================================
 
VIRUSTOTAL_API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
GOOGLE_SAFE_BROWSING_API_KEY = st.secrets["GOOGLE_SAFE_BROWSING_API_KEY"]
NEWS_API_KEY = st.secrets["NEWS_API_KEY"]
NUMVERIFY_API_KEY = st.secrets.get("NUMVERIFY_API_KEY", "")
 
# =====================================================
# OCR CLEANER
# =====================================================
 
def clean_ocr_text(text):
 
    text = text.lower()
 
    fixes = {
        "@@": "@",
        " gmaicom": "@gmail.com",
        " gmaiicom": "@gmail.com",
        " gmialcom": "@gmail.com",
        " gmalcom": "@gmail.com",
        " gmailcom": "@gmail.com",
        " gmai1.com": "@gmail.com",
        " at ": "@",
        " dot ": ".",
        " texl ": " text ",
        " homa ": " home "
    }
 
    for wrong, correct in fixes.items():
        text = text.replace(wrong, correct)
 
    return text
 
# =====================================================
# EMAIL EXTRACTION
# =====================================================
 
def extract_emails(text):
 
    text = clean_ocr_text(text)
 
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
 
    emails = re.findall(pattern, text)
 
    cleaned = []
 
    for email in emails:
        email = email.strip().replace(" ", "")
        if ".com" in email or ".in" in email:
            cleaned.append(email)
 
    return list(set(cleaned))
 
# =====================================================
# PHONE EXTRACTION
# =====================================================
 
def extract_phone_numbers(text):
 
    phones = re.findall(
        r'(?:\+91[-\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}',
        text
    )
 
    cleaned = []
 
    for phone in phones:
        digits = re.sub(r'\D', '', phone)
        if len(digits) >= 7:
            cleaned.append(phone)
 
    return list(set(cleaned))
 
# =====================================================
# PHONE ANALYSIS
# =====================================================
 
def analyze_phone_number(phone):
 
    digits = re.sub(r"\D", "", phone)
    risk = 0
    reasons = []
 
    if len(digits) < 10:
        risk += 40
        reasons.append("Invalid or short phone number")
 
    if digits.startswith("555"):
        risk += 60
        reasons.append("Fake/test style number detected")
 
    repeated_patterns = [
        "0000000000", "1111111111", "2222222222",
        "3333333333", "4444444444", "5555555555",
        "6666666666", "7777777777", "8888888888",
        "9999999999", "1234567890"
    ]
 
    if digits[-10:] in repeated_patterns:
        risk += 50
        reasons.append("Suspicious repeated digit pattern")
 
    api_result = check_phone_api(phone)
 
    if isinstance(api_result, dict):
        if api_result.get("valid") is False:
            risk += 50
            reasons.append("Phone number failed API validation")
        if api_result.get("line_type") == "voip":
            risk += 30
            reasons.append("VOIP number detected")
 
    return {
        "phone": phone,
        "risk_score": min(risk, 100),
        "api_result": api_result,
        "reasons": reasons
    }
 
# =====================================================
# PHONE API CHECK (NUMVERIFY)
# =====================================================
 
def check_phone_api(phone):
 
    try:
        if not NUMVERIFY_API_KEY:
            return {"status": "no_key"}
 
        digits = re.sub(r"\D", "", phone)
 
        url = (
            f"http://apilayer.net/api/validate"
            f"?access_key={NUMVERIFY_API_KEY}"
            f"&number={digits}"
        )
 
        response = requests.get(url, timeout=10)
 
        if response.status_code == 200:
            data = response.json()
            return {
                "valid": data.get("valid", False),
                "country": data.get("country_name", "Unknown"),
                "location": data.get("location", "Unknown"),
                "carrier": data.get("carrier", "Unknown"),
                "line_type": data.get("line_type", "Unknown")
            }
 
        return {"status": "failed"}
 
    except Exception as e:
        return {"error": str(e)}
 
# =====================================================
# URL EXTRACTION
# =====================================================
 
def extract_urls(text):
 
    urls = re.findall(
        r'(https?://[^\s]+|www\.[^\s]+)',
        text
    )
 
    cleaned = []
 
    for url in urls:
        url = url.strip()
        if len(url) > 5:
            cleaned.append(url)
 
    return list(set(cleaned))
 
# =====================================================
# EMAIL INTELLIGENCE ENGINE
# (EmailRep removed — heuristic-only scoring)
# =====================================================
 
def analyze_email_intelligence(email):
 
    risk = 0
    reasons = []
 
    domain = email.split("@")[-1].lower()
 
    # Free providers used by scammers
    free_providers = [
        "gmail.com", "yahoo.com", "hotmail.com",
        "outlook.com", "protonmail.com", "ymail.com",
        "aol.com", "icloud.com"
    ]
 
    if domain in free_providers:
        risk += 35
        reasons.append("Free email provider used")
 
    # Suspicious username patterns
    local = email.split("@")[0].lower()
 
    if any(word in local for word in ["hr", "recruit", "hiring", "interview", "job", "career"]):
        risk += 25
        reasons.append("Suspicious recruiter-style email username")
 
    if re.search(r'\d{4,}', local):
        risk += 15
        reasons.append("Many digits in email username (bot pattern)")
 
    # Company name in email but using free provider = red flag
    if domain in free_providers and any(
        word in local for word in ["company", "corp", "inc", "ltd", "official"]
    ):
        risk += 30
        reasons.append("Claims company identity but uses free email")
 
    return {
        "email": email,
        "api_result": {"status": "heuristic_only"},
        "reasons": reasons,
        "final_email_risk": min(risk, 100)
    }
 
# =====================================================
# VIRUSTOTAL URL CHECK — FIXED URL ID
# =====================================================
 
def check_virustotal_url(url):
 
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
 
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15
        )
 
        if response.status_code != 200:
            return {"status": "failed"}
 
        # FIX: the id comes back as "u-<hash>-<timestamp>", extract just the hash
        raw_id = response.json()["data"]["id"]
        parts = raw_id.split("-")
        url_id = parts[1] if len(parts) >= 2 else raw_id
 
        report = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )
 
        if report.status_code == 200:
            stats = report.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
 
        return {"status": "no_report"}
 
    except Exception as e:
        return {"error": str(e)}
 
# =====================================================
# GOOGLE SAFE BROWSING
# =====================================================
 
def check_google_safe_browsing(url):
 
    try:
        endpoint = (
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        )
 
        payload = {
            "client": {
                "clientId": "scamshield",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
 
        response = requests.post(endpoint, json=payload, timeout=10)
 
        if response.status_code == 200:
            data = response.json()
            if "matches" in data:
                return "unsafe"
            return "safe"
 
        return "error"
 
    except Exception:
        return "error"
 
# =====================================================
# URL SECURITY ENGINE
# =====================================================
 
def run_url_security_checks(url):
 
    vt = check_virustotal_url(url)
    gs = check_google_safe_browsing(url)
 
    risk = 0
    reasons = []
 
    if gs == "unsafe":
        risk += 50
        reasons.append("Unsafe in Google Safe Browsing")
 
    if isinstance(vt, dict):
        if vt.get("malicious", 0) > 0:
            risk += 60
            reasons.append("VirusTotal detected malicious activity")
        if vt.get("suspicious", 0) > 0:
            risk += 30
            reasons.append("VirusTotal marked URL suspicious")
 
    return {
        "url": url,
        "virustotal": vt,
        "google_safe_browsing": gs,
        "risk_score": min(risk, 100),
        "reasons": reasons
    }
 
# =====================================================
# NEWS API
# =====================================================
 
def get_latest_scam_news():
 
    try:
        url = "https://newsapi.org/v2/everything"
 
        params = {
            "q": "job scam OR phishing OR fake recruiter",
            "language": "en",
            "sortBy": "publishedAt",
            "pageSize": 5,
            "apiKey": NEWS_API_KEY
        }
 
        response = requests.get(url, params=params, timeout=10)
 
        if response.status_code == 200:
            data = response.json()
            news = []
            for article in data["articles"]:
                news.append({
                    "title": article["title"],
                    "source": article["source"]["name"],
                    "url": article["url"]
                })
            return news
 
        return []
 
    except Exception:
        return []
 
# =====================================================
# FINAL RISK CALCULATION
# =====================================================
 
def calculate_risk(
    ml_probability,
    email_risk,
    url_risk,
    keyword_risk,
    phone_risk,
    structural_risk=0
):
    risk = 0
 
    # ML MODEL — max ~35 points
    risk += ml_probability * 35
 
    # KEYWORD RISK — max 60 points (capped in backend)
    risk += keyword_risk
 
    # STRUCTURAL RISK — max 40 points (capped in backend)
    risk += structural_risk
 
    # EMAIL RISK — max ~20 points
    risk += min(email_risk * 0.15, 20)
 
    # URL RISK — max 30 points
    risk += min(url_risk, 30)
 
    # PHONE RISK — max ~10 points
    risk += min(phone_risk * 0.1, 10)
 
    return min(risk, 100)