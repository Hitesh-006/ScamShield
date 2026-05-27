
import re
import requests
import streamlit as st
# =====================================================
# API KEYS
# =====================================================

import os

import streamlit as st
VIRUSTOTAL_API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
GOOGLE_SAFE_BROWSING_API_KEY = st.secrets["GOOGLE_SAFE_BROWSING_API_KEY"]
NEWS_API_KEY = st.secrets["NEWS_API_KEY"]
EMAILREP_API_KEY = st.secrets["EMAILREP_API_KEY"]





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

# =====================================================
# PHONE ANALYSIS
# =====================================================

def analyze_phone_number(phone):

    digits = re.sub(r"\D", "", phone)

    risk = 0

    reasons = []

    # ==========================================
    # HEURISTICS
    # ==========================================

    if len(digits) < 10:

        risk += 40

        reasons.append(
            "Invalid or short phone number"
        )

    if digits.startswith("555"):

        risk += 60

        reasons.append(
            "Fake/test style number detected"
        )

    repeated_patterns = [

        "0000000000",
        "1111111111",
        "2222222222",
        "3333333333",
        "4444444444",
        "5555555555",
        "6666666666",
        "7777777777",
        "8888888888",
        "9999999999",
        "1234567890"
    ]

    if digits[-10:] in repeated_patterns:

        risk += 50

        reasons.append(
            "Suspicious repeated digit pattern"
        )

    # ==========================================
    # PHONE API
    # ==========================================

    api_result = check_phone_api(phone)

    if isinstance(api_result, dict):

        if api_result.get("valid") is False:

            risk += 50

            reasons.append(
                "Phone number failed API validation"
            )

        if api_result.get("line_type") == "voip":

            risk += 30

            reasons.append(
                "VOIP number detected"
            )

    return {

        "phone": phone,

        "risk_score": min(risk, 100),

        "api_result": api_result,

        "reasons": reasons
    }



# =====================================================# =====================================================
# PHONE API CHECK (NUMVERIFY)
# =====================================================

NUMVERIFY_API_KEY = "YOUR_NUMVERIFY_API_KEY"

def check_phone_api(phone):

    try:

        digits = re.sub(r"\D", "", phone)

        url = (
            f"http://apilayer.net/api/validate"
            f"?access_key={NUMVERIFY_API_KEY}"
            f"&number={digits}"
        )

        response = requests.get(url)

        if response.status_code == 200:

            data = response.json()

            return {

                "valid": data.get("valid", False),

                "country": data.get("country_name", "Unknown"),

                "location": data.get("location", "Unknown"),

                "carrier": data.get("carrier", "Unknown"),

                "line_type": data.get("line_type", "Unknown")
            }

        return {
            "status": "failed"
        }

    except Exception as e:

        return {
            "error": str(e)
        }
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
# EMAILREP API
# =====================================================

def check_email_api_reputation(email):

    try:

        url = f"https://emailrep.io/{email}"

        headers = {

            "Key": EMAILREP_API_KEY,

            "Accept": "application/json"
        }

        response = requests.get(
            url,
            headers=headers
        )

        if response.status_code == 200:

            data = response.json()

            return {

                "reputation": data.get(
                    "reputation",
                    "unknown"
                ),

                "suspicious": data.get(
                    "suspicious",
                    False
                ),

                "references": data.get(
                    "references",
                    0
                ),

                "blacklisted": data.get(
                    "details",
                    {}
                ).get(
                    "blacklisted",
                    False
                ),

                "malicious_activity": data.get(
                    "details",
                    {}
                ).get(
                    "malicious_activity",
                    False
                ),

                "spam": data.get(
                    "details",
                    {}
                ).get(
                    "spam",
                    False
                ),

                "disposable": data.get(
                    "details",
                    {}
                ).get(
                    "disposable",
                    False
                )

            }

        return {

            "status": "failed"
        }

    except Exception as e:

        return {

            "error": str(e)
        }

# =====================================================
# EMAIL INTELLIGENCE ENGINE
# =====================================================

def analyze_email_intelligence(email):

    risk = 0

    reasons = []

    domain = email.split("@")[-1].lower()

    risky_domains = [

        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "protonmail.com"

    ]

    # ==========================================
    # DOMAIN CHECK
    # ==========================================

    if domain in risky_domains:

        risk += 35

        reasons.append(
            "Free email provider used"
        )

    # ==========================================
    # EMAILREP API
    # ==========================================

    api_result = check_email_api_reputation(email)

    if api_result.get("reputation") == "low":

        risk += 40

        reasons.append(
            "Low reputation email"
        )

    if api_result.get("suspicious"):

        risk += 30

        reasons.append(
            "Suspicious email activity"
        )

    if api_result.get("blacklisted"):

        risk += 50

        reasons.append(
            "Blacklisted email"
        )

    if api_result.get("malicious_activity"):

        risk += 50

        reasons.append(
            "Malicious activity detected"
        )

    if api_result.get("spam"):

        risk += 40

        reasons.append(
            "Spam history detected"
        )

    if api_result.get("disposable"):

        risk += 50

        reasons.append(
            "Disposable email detected"
        )

    return {

        "email": email,

        "api_result": api_result,

        "reasons": reasons,

        "final_email_risk": min(risk, 100)
    }

# =====================================================
# VIRUSTOTAL URL CHECK
# =====================================================

def check_virustotal_url(url):

    try:

        headers = {

            "x-apikey": VIRUSTOTAL_API_KEY
        }

        submit_url = "https://www.virustotal.com/api/v3/urls"

        response = requests.post(
            submit_url,
            headers=headers,
            data={"url": url}
        )

        if response.status_code != 200:

            return {

                "status": "failed"
            }

        url_id = response.json()["data"]["id"]

        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        report = requests.get(
            report_url,
            headers=headers
        )

        if report.status_code == 200:

            stats = report.json()["data"]["attributes"]["last_analysis_stats"]

            return {

                "malicious": stats.get(
                    "malicious",
                    0
                ),

                "suspicious": stats.get(
                    "suspicious",
                    0
                ),

                "harmless": stats.get(
                    "harmless",
                    0
                )
            }

        return {

            "status": "no_report"
        }

    except Exception as e:

        return {

            "error": str(e)
        }

# =====================================================
# GOOGLE SAFE BROWSING
# =====================================================

def check_google_safe_browsing(url):

    try:

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"

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

                "platformTypes": [

                    "ANY_PLATFORM"

                ],

                "threatEntryTypes": [

                    "URL"

                ],

                "threatEntries": [

                    {"url": url}
                ]
            }
        }

        response = requests.post(
            endpoint,
            json=payload
        )

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

        reasons.append(
            "Unsafe in Google Safe Browsing"
        )

    if isinstance(vt, dict):

        if vt.get("malicious", 0) > 0:

            risk += 60

            reasons.append(
                "VirusTotal detected malicious activity"
            )

        if vt.get("suspicious", 0) > 0:

            risk += 30

            reasons.append(
                "VirusTotal marked URL suspicious"
            )

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

        response = requests.get(
            url,
            params=params
        )

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
    structural_risk=0       # NEW — pass from backend.py
):
    risk = 0

    # ===================================
    # ML MODEL — max 35 points
    # (was 60 — too dominant)
    # A 50% ML score gives 17.5 points
    # A 90% ML score gives 31.5 points
    # ===================================
    risk += ml_probability * 35

    # ===================================
    # KEYWORD RISK — max 60 points (capped in backend)
    # Direct, interpretable signal
    # ===================================
    risk += keyword_risk

    # ===================================
    # STRUCTURAL RISK — max 40 points (capped in backend)
    # No company name, too short, etc.
    # ===================================
    risk += structural_risk

    # ===================================
    # EMAIL RISK — max contribution ~20
    # email_risk is sum across all emails (0–100 each)
    # Scale down so 1 risky email = ~15 points
    # ===================================
    risk += min(email_risk * 0.15, 20)

    # ===================================
    # URL RISK — keep as-is (already points-based)
    # ===================================
    risk += min(url_risk, 30)

    # ===================================
    # PHONE RISK — max contribution ~10
    # phone_risk is sum across phones (0–100 each)
    # ===================================
    risk += min(phone_risk * 0.1, 10)

    return min(risk, 100)
