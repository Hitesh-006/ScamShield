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
# LOAD & TRAIN MODEL (LAZY LOADING)
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
        max_features=4000,
        stop_words="english",
        ngram_range=(1, 2)
    )

    X = vectorizer.fit_transform(X_text)

    model = RandomForestClassifier(
        n_estimators=80,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X, y)


# =====================================================
# SAFE MODEL CHECK
# =====================================================

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

        temp_path = "temp.png"
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

    # ---------------- EMAIL ----------------
    email_results = []
    email_risk = 0

    for email in emails:
        result = analyze_email_intelligence(email)
        email_results.append(result)
        email_risk += result["final_email_risk"]

    # ---------------- URL ----------------
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

    # ---------------- PHONE ----------------
    phone_results = []
    phone_risk = 0

    for phone in phones:
        result = analyze_phone_number(phone)
        phone_results.append(result)
        phone_risk += result["risk_score"]

    # ---------------- KEYWORDS ----------------
    suspicious_keywords = [
        "work from home",
        "weekly pay",
        "telegram",
        "whatsapp",
        "no experience",
        "quick money",
        "earn fast"
    ]

    keyword_risk = 0
    detected_keywords = []

    text_lower = cleaned_text.lower()

    for word in suspicious_keywords:
        if word in text_lower:
            detected_keywords.append(word)
            keyword_risk += 10

    # ---------------- FINAL RISK ----------------
    risk_score = calculate_risk(
        ml_probability=prob,
        email_risk=email_risk,
        url_risk=url_risk,
        keyword_risk=keyword_risk,
        phone_risk=phone_risk
    )

    # ---------------- RESULT ----------------
    if risk_score >= 75:
        final_result = "SCAM JOB DETECTED"
    elif risk_score >= 45:
        final_result = "SUSPICIOUS JOB"
    else:
        final_result = "LEGITIMATE JOB"

    # Save data
    save_to_csv(cleaned_text, ml_score, risk_score, final_result)

    return {
        "ml_score": ml_score,
        "risk_score": risk_score,
        "result": final_result,

        "emails": emails,
        "email_results": email_results,

        "urls": urls,
        "url_results": url_results,

        "phones": phones,
        "phone_results": phone_results,

        "detected_keywords": detected_keywords,
        "keyword_risk": keyword_risk
    }

# =====================================================
# CSV STORAGE
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

    if os.path.exists(file_name):
        old = pd.read_csv(file_name)
        new = pd.concat([old, pd.DataFrame([row])], ignore_index=True)
    else:
        new = pd.DataFrame([row])

    new.to_csv(file_name, index=False)