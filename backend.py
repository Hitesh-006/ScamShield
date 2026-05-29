import os
import re
import pandas as pd
import easyocr
from datetime import datetime
from PIL import Image, ImageEnhance

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

from database import save_result

from api_checks import (
    extract_emails,
    extract_urls,
    extract_phone_numbers,
    analyze_email_intelligence,
    analyze_phone_number,
    run_url_security_checks,
    calculate_risk
)

# =====================================================
# GLOBAL MODEL VARIABLES
# =====================================================

model = None
vectorizer = None
reader = easyocr.Reader(['en'], gpu=False)

# =====================================================
# LOAD & TRAIN MODEL
# =====================================================

def load_model():
    global model, vectorizer

    df = pd.read_csv("fake_job_postings.csv")
    df = df.fillna("")

    df["text"] = (
        df["title"] + " " +
        df["company_profile"] + " " +
        df["description"] + " " +
        df["requirements"] + " " +
        df["benefits"]
    )

    X_text = df["text"]
    y = df["fraudulent"].astype(int)

    vectorizer = TfidfVectorizer(
        max_features=5000,
        stop_words="english",
        ngram_range=(1, 3)
    )
    X = vectorizer.fit_transform(X_text)

    model = RandomForestClassifier(
        n_estimators=150,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
        min_samples_leaf=2
    )
    model.fit(X, y)


def ensure_model_loaded():
    global model, vectorizer
    if model is None or vectorizer is None:
        load_model()

# =====================================================
# OCR ENGINE
# =====================================================

def fix_ocr_text(text):
    text = text.lower()
    replacements = {
        "gmalcom": "@gmail.com",
        "gmailcom": "@gmail.com",
        "gmaiicom": "@gmail.com",
        "gmialcom": "@gmail.com",
        "dot com": ".com",
        " at ": "@",
        "texl": "text",
        "homa": "home"
    }
    for wrong, correct in replacements.items():
        text = text.replace(wrong, correct)
    return text


def extract_text_from_image(image_path):
    try:
        if not os.path.exists(image_path):
            return "OCR ERROR: Image not found"

        img = Image.open(image_path).convert("RGB")
        img = img.resize((img.width + 200, img.height + 200))
        img = ImageEnhance.Sharpness(img).enhance(2)
        img = ImageEnhance.Contrast(img).enhance(1.8)

        temp_path = "temp_processed.png"
        img.save(temp_path)

        result = reader.readtext(temp_path, detail=0, paragraph=True)

        if not result:
            return "OCR ERROR: No text detected"

        text = " ".join(result)
        text = re.sub(r'[^\w@₹.,:/()\-\s]+', ' ', text)
        return fix_ocr_text(text)

    except Exception as e:
        return f"OCR ERROR: {str(e)}"

# =====================================================
# KEYWORD ENGINE
# =====================================================

SCAM_KEYWORD_RULES = [

    # Reshipping
    ("handle packages", 35, "Package reshipping scam signal"),
    ("reship", 30, "Package reshipping scam signal"),
    ("forward packages", 30, "Package reshipping scam signal"),
    ("receive packages", 25, "Package reshipping scam signal"),

    # Money mule
    ("transfer funds", 35, "Money mule signal"),
    ("transfer money", 35, "Money mule signal"),
    ("wire transfer", 30, "Money mule signal"),
    ("process payments", 30, "Financial fraud signal"),
    ("financial agent", 30, "Money mule signal"),
    ("payment processor", 25, "Financial fraud signal"),

    # Vague pay
    ("weekly pay", 20, "Vague payment promise"),
    ("daily pay", 20, "Vague payment promise"),
    ("earn from home", 25, "Work-from-home scam signal"),
    ("work from home", 15, "Work-from-home scam signal"),
    ("work remotely", 20, "Remote work scam signal"),
    ("works from home", 20, "Work-from-home scam signal"),
    ("make money online", 25, "Online income scam signal"),
    ("earn money online", 25, "Online income scam signal"),
    ("quick money", 25, "Quick money scam signal"),
    ("earn fast", 25, "Quick money scam signal"),
    ("extra income", 15, "Vague income promise"),
    ("passive income", 15, "Vague income promise"),
    ("paid weekly", 25, "Vague weekly payment promise"),
    ("five hundred dollars", 20, "Vague cash promise"),
    ("carry out remotely", 20, "Remote task scam signal"),

    # No requirements
    ("no experience", 20, "No-experience required (suspicious)"),
    ("no experience required", 25, "No-experience required (suspicious)"),
    ("no qualification", 20, "No qualification required (suspicious)"),
    ("anyone can apply", 25, "Indiscriminate hiring signal"),
    ("minimum age", 20, "Undiscriminate hiring signal"),
    ("18 years", 15, "Age-only qualification signal"),
    ("basic computer skills", 15, "Vague qualification signal"),
    ("any department", 15, "Indiscriminate targeting signal"),

    # Contact via apps
    ("telegram", 30, "Contact via Telegram (scam channel)"),
    ("whatsapp", 25, "Contact via WhatsApp (informal hiring)"),
    ("contact us on", 15, "Informal contact method"),
    ("text us", 15, "Informal contact method"),
    ("kindly text", 30, "Informal contact request"),

    # Urgency
    ("limited slots", 20, "Urgency pressure tactic"),
    ("act now", 20, "Urgency pressure tactic"),
    ("urgent hiring", 15, "Urgency pressure tactic"),
    ("immediate start", 15, "Urgency pressure tactic"),
    ("do not ignore", 20, "Pressure tactic"),
    ("ignore this email", 15, "Pressure / phishing language"),
    ("don't miss", 15, "Urgency pressure tactic"),

    # Fake legitimacy
    ("we found your profile", 20, "Unsolicited outreach signal"),
    ("we have found your profile", 25, "Unsolicited outreach signal"),
    ("your resume had been reviewed", 25, "Unsolicited outreach signal"),
    ("perfect match", 20, "Flattery-based recruitment"),
    ("selected for", 15, "Unsolicited selection claim"),
    ("job-seeker", 15, "Profile scraping signal"),
    ("job seeker", 15, "Profile scraping signal"),
    ("dear applicant", 25, "Generic greeting (mass scam email)"),
    ("hiring dept", 20, "Vague department name"),
    ("contact professor", 15, "Impersonation signal"),

    # Vague pay/benefits
    ("good wage", 15, "Vague wage promise"),
    ("good wages", 15, "Vague wage promise"),
    ("extra benefits", 10, "Vague benefit promise"),
    ("relaxation", 10, "Unprofessional benefit language"),
    ("bi-weekly", 15, "Vague payment schedule"),
    ("direct deposit", 10, "Vague payment method"),

    # Data harvesting
    ("ssn", 30, "SSN collection attempt"),
    ("social security", 30, "SSN collection attempt"),
    ("bank account", 25, "Financial info harvesting"),
    ("bank details", 25, "Financial info harvesting"),
    ("stating your full name", 25, "Personal data harvesting"),
    ("full name", 15, "Personal data harvesting"),
    ("year of study", 20, "Student targeting scam signal"),
    ("further application requirements", 15, "Vague next steps signal"),
    ("work from anywhere", 25, "Remote work scam signal"),
]


def run_keyword_analysis(text):
    text_lower = text.lower()
    total_risk = 0
    detected = []
    seen = set()

    for phrase, points, label in SCAM_KEYWORD_RULES:
        if phrase in text_lower and phrase not in seen:
            seen.add(phrase)
            total_risk += points
            detected.append({
                "phrase": phrase,
                "points": points,
                "label": label
            })

    return min(total_risk, 60), detected

# =====================================================
# STRUCTURAL CHECKS — FIXED (university check now works)
# =====================================================

def run_structural_checks(text):
    risk = 0
    reasons = []
    text_lower = text.lower()

    # Short post
    if len(text.split()) < 60:
        risk += 15
        reasons.append("Job description suspiciously short")

    # No company name
    company_signals = ["inc", "ltd", "llc", "corp", "pvt", "company", "solutions", "technologies"]
    has_company = any(s in text_lower for s in company_signals)
    if not has_company:
        risk += 15
        reasons.append("No company name or type mentioned")

    # Salary without company
    salary_pattern = re.search(r'\$[\d,]+|\d+\s*/\s*(month|week|hr|hour)', text_lower)
    if salary_pattern and not has_company:
        risk += 10
        reasons.append("Salary stated without company context")

    # Personal contact in post
    if re.search(r'(call|text|whatsapp|telegram)\s*(us|me|now|at)', text_lower):
        risk += 20
        reasons.append("Direct personal contact requested in post")

    # US residency = reshipping
    if "united states resident" in text_lower or "us resident" in text_lower:
        risk += 20
        reasons.append("US residency requirement (reshipping scam pattern)")

    # FIX: university impersonation — moved BEFORE return
    university_signals = ["university", "college", "institute", "school", "dean", "professor"]
    if any(s in text_lower for s in university_signals):
        if re.search(r'@gmail\.com|@yahoo\.com|@hotmail\.com', text_lower):
            risk += 40
            reasons.append("Institutional name used but sender has free email (impersonation)")

    return min(risk, 60), reasons   # raised cap from 40 to 60

# =====================================================
# MAIN ANALYSIS ENGINE
# =====================================================

def analyze_job(cleaned_text):
    ensure_model_loaded()

    user_vector = vectorizer.transform([cleaned_text])
    prob = model.predict_proba(user_vector)[0][1]
    ml_score = round(prob * 100, 2)

    emails = extract_emails(cleaned_text)
    urls = extract_urls(cleaned_text)
    phones = extract_phone_numbers(cleaned_text)

    # EMAIL
    email_results = []
    email_risk = 0
    for email in emails:
        result = analyze_email_intelligence(email)
        email_results.append(result)
        email_risk += result["final_email_risk"]

    # URL
    url_results = []
    url_risk = 0
    for url in urls:
        result = run_url_security_checks(url)
        url_results.append(result)
        vt = result["virustotal"]
        if isinstance(vt, dict):
            url_risk += vt.get("malicious", 0) * 15
        if result["google_safe_browsing"] == "unsafe":
            url_risk += 40

    # PHONE
    phone_results = []
    phone_risk = 0
    for phone in phones:
        result = analyze_phone_number(phone)
        phone_results.append(result)
        phone_risk += result["risk_score"]

    # KEYWORDS
    keyword_risk, detected_keyword_objects = run_keyword_analysis(cleaned_text)
    detected_keywords = [f"{k['phrase']} — {k['label']}" for k in detected_keyword_objects]

    # STRUCTURAL
    structural_risk, structural_reasons = run_structural_checks(cleaned_text)

    # FINAL RISK
    risk_score = calculate_risk(
        ml_probability=prob,
        email_risk=email_risk,
        url_risk=url_risk,
        keyword_risk=keyword_risk,
        phone_risk=phone_risk,
        structural_risk=structural_risk
    )

    # VERDICT
    if risk_score >= 60:
        final_result = "SCAM JOB DETECTED"
    elif risk_score >= 35:
        final_result = "SUSPICIOUS JOB"
    else:
        final_result = "LEGITIMATE JOB"

    # SAVE — both CSV and SQLite
    save_to_csv(cleaned_text, ml_score, risk_score, final_result)
    try:
        save_result(cleaned_text, ml_score, risk_score, final_result)
    except Exception:
        pass

    return {
        "ml_score": ml_score,
        "risk_score": round(risk_score, 2),
        "result": final_result,

        "emails": emails,
        "email_results": email_results,

        "urls": urls,
        "url_results": url_results,

        "phones": phones,
        "phone_results": phone_results,

        "detected_keywords": detected_keywords,
        "keyword_risk": keyword_risk,

        "structural_reasons": structural_reasons,
        "structural_risk": structural_risk,

        # Raw values for risk breakdown chart in app.py
        "email_risk_raw": email_risk,
        "url_risk_raw": url_risk,
        "phone_risk_raw": phone_risk,
    }

# =====================================================
# CSV STORAGE — FIXED
# =====================================================

def save_to_csv(text, ml_score, risk_score, result):
    file_name = "live_training_data.csv"

    row = {
        "text": text,
        "ml_score": ml_score,
        "risk_score": risk_score,
        "result": result,
        "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    }

    try:
        if os.path.exists(file_name):
            old = pd.read_csv(file_name)
            new = pd.concat([old, pd.DataFrame([row])], ignore_index=True)
        else:
            new = pd.DataFrame([row])
        new.to_csv(file_name, index=False)
    except Exception as e:
        print(f"CSV save error: {e}")