from email.mime import text

import pandas as pd
import easyocr
import re
import os

from datetime import datetime
from PIL import Image, ImageEnhance
import pillow_avif

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from database import save_result

# =====================================================
# IMPORT API ENGINE (YOUR FINAL API FILE)
# =====================================================

from api_checks import (
    extract_emails,
    extract_urls,
    extract_phone_numbers,
    check_email_api_reputation,
    analyze_email_intelligence,
    analyze_phone_number,
    run_url_security_checks,
    get_latest_scam_news,
    calculate_risk
)

# =====================================================
# LOAD DATASET
# =====================================================

print("\nLoading dataset...\n")

df = pd.read_csv("fake_job_postings.csv")

df = df[
    [
        'title',
        'company_profile',
        'description',
        'requirements',
        'benefits',
        'fraudulent'
    ]
]

df = df.fillna("")
df['fraudulent'] = df['fraudulent'].astype(int)

df['text'] = (
    df['title'] + " " +
    df['company_profile'] + " " +
    df['description'] + " " +
    df['requirements'] + " " +
    df['benefits']
)

df = df[['text', 'fraudulent']]
df = df[df['text'].str.strip() != ""]

# =====================================================
# TF-IDF + MODEL
# =====================================================

vectorizer = TfidfVectorizer(
    max_features=4000,
    stop_words='english',
    ngram_range=(1, 2)
)

X = vectorizer.fit_transform(df['text'])
y = df['fraudulent']

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42
)

model = RandomForestClassifier(
    n_estimators=80,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("BACKEND MODEL READY\n")

# =====================================================
# OCR ENGINE
# =====================================================

reader = easyocr.Reader(['en'], gpu=False)

def fix_ocr_text(text):
    text = text.lower()

    replacements = {
        "gmalcom": "@gmail.com",
        "gmailcom": "@gmail.com",
        "gmaiicom": "@gmail.com",
        "gmialcom": "@gmail.com",
        "dot com": ".com",
        "at": "@",
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

        width, height = img.size
        img = img.resize((width + 200, height + 200))

        img = ImageEnhance.Sharpness(img).enhance(2)
        img = ImageEnhance.Contrast(img).enhance(1.8)

        temp_path = "temp.png"
        img.save(temp_path)

        result = reader.readtext(temp_path, detail=0, paragraph=True)

        if not result:
            return "OCR ERROR: No text detected"

        text = " ".join(result)
        text = re.sub(r'[^A-Za-z0-9@₹.,:/_()\- ]+', ' ', text)

        return fix_ocr_text(text)

    except Exception as e:
        return f"OCR ERROR: {str(e)}"

# =====================================================
# MAIN ANALYSIS ENGINE (FULL API INTEGRATION)
# =====================================================

def analyze_job(cleaned_text):

    user_vector = vectorizer.transform([cleaned_text])

    prob = model.predict_proba(user_vector)[0][1]

    ml_score = round(prob * 100, 2)

    emails = extract_emails(cleaned_text)

    urls = extract_urls(cleaned_text)

    phones = extract_phone_numbers(cleaned_text)

    # =====================================
    # EMAIL ANALYSIS
    # =====================================

    email_results = []

    email_risk = 0

    for email in emails:

        result = analyze_email_intelligence(email)

        email_results.append(result)

        email_risk += result["final_email_risk"]

    # =====================================
    # URL ANALYSIS
    # =====================================

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

    # =====================================
    # PHONE ANALYSIS
    # =====================================

    phone_results = []

    phone_risk = 0

    for phone in phones:

        result = analyze_phone_number(phone)

        phone_results.append(result)

        phone_risk += result["risk_score"]

    # =====================================
    # KEYWORDS
    # =====================================

    suspicious_keywords = [

        "work from home",
        "weekly pay",
        "telegram",
        "whatsapp",
        "no experience",
        "quick money",
        "earn fast"
    ]

    detected_keywords = []

    keyword_risk = 0

    text_lower = cleaned_text.lower()

    for word in suspicious_keywords:

        if word in text_lower:

            detected_keywords.append(word)

            keyword_risk += 10

    # =====================================
    # FINAL RISK
    # =====================================

    risk_score = calculate_risk(
        ml_probability=prob,
        email_risk=email_risk,
        url_risk=url_risk,
        keyword_risk=keyword_risk,
        phone_risk=phone_risk
    )

    # =====================================
    # FINAL LABEL
    # =====================================

    if risk_score >= 75:
        final_result = "SCAM JOB DETECTED"

    elif risk_score >= 45:
        final_result = "SUSPICIOUS JOB"

    else:
        final_result = "LEGITIMATE JOB"
    save_to_csv(

    cleaned_text,

    ml_score,

    risk_score,

    final_result
    )

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
