import pandas as pd
import easyocr
import re
import os
from api_checks import (
    extract_emails,
    extract_urls,
    check_email_reputation,
    extract_phone_numbers,
    calculate_risk)

from PIL import Image
import pillow_avif

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# =========================================
# LOAD DATASET
# =========================================

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

# Combine text columns
df['text'] = (
    df['title'] + " " +
    df['company_profile'] + " " +
    df['description'] + " " +
    df['requirements'] + " " +
    df['benefits']
)

df = df[['text', 'fraudulent']]

df = df[df['text'].str.strip() != ""]

# =========================================
# TF-IDF
# =========================================

print("Creating vectors...\n")

vectorizer = TfidfVectorizer(
    max_features=8000,
    stop_words='english',
    ngram_range=(1, 2)
)

X = vectorizer.fit_transform(df['text'])

y = df['fraudulent']

# =========================================
# SPLIT
# =========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# =========================================
# MODEL
# =========================================

print("Training model...\n")

model = RandomForestClassifier(
    n_estimators=150,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)


# =========================================
# OCR READER
# =========================================

reader = easyocr.Reader(['en'])
# =====================================
# OCR TEXT CORRECTION
# =====================================

def fix_ocr_text(text):

    text = text.lower()

    # Common OCR mistakes
    replacements = {

        " gmalcom ": "@gmail.com ",
        " gmailcom ": "@gmail.com ",
        " gmaiicom ": "@gmail.com ",
        " gmialcom ": "@gmail.com ",
        "egmalcom": "@gmail.com",
        "gmalcom": "@gmail.com",

        " dot com ": ".com ",
        " dotcom ": ".com ",

        " at ": "@",

        " www ": "www.",

    }

    for wrong, correct in replacements.items():

        text = text.replace(wrong, correct)

    return text

# =========================================
# MAIN LOOP
# =========================================

while True:

    print("\n==============================")
    print(" AI JOB SCAM DETECTOR ")
    print("==============================")

    print("\n1. Image Input")
    print("2. Text Input")
    print("3. Exit")

    choice = input("\nEnter choice: ")

    cleaned_text = ""

    print("MODEL READY\n")

    # =============================
    # IMAGE INPUT
    # =============================
    if choice == "1":

        image_path = input("\nEnter image name:\n")

        try:
            if image_path.lower().endswith(".avif"):
                print("\nConverting AVIF to PNG...\n")

                img = Image.open(image_path)
                converted_path = "converted_image.png"
                img.save(converted_path)

                image_path = converted_path
                print("Conversion Complete")

            result = reader.readtext(image_path, detail=0)
            extracted_text = " ".join(result)

            cleaned_text = re.sub( r'[^A-Za-z0-9@₹.,:/_-]+',' ',extracted_text)

            cleaned_text = fix_ocr_text(cleaned_text)
            print("\nEXTRACTED TEXT:\n")
            print(cleaned_text)

        except Exception as e:
            print("\nERROR PROCESSING IMAGE")
            print(e)
            continue

    # =============================
    # TEXT INPUT
    # =============================
    elif choice == "2":

        cleaned_text = input("\nEnter job description:\n")

        if len(cleaned_text.strip()) == 0:
            print("\nPlease enter valid text")
            continue

    # =============================
    # EXIT
    # =============================
    elif choice == "3":
        print("\nExiting program...")
        break

    else:
        print("\nInvalid choice")
        continue

    # =============================
    # KEYWORD RISK
    # =============================
    scam_keywords = [
        "work from home",
        "weekly pay",
        "text this number",
        "no experience",
        "$25 per hour",
    ]

    keyword_risk = 0

    for word in scam_keywords:
        if word.lower() in cleaned_text.lower():
            keyword_risk += 10

    # =============================
    # ML PREDICTION
    # =============================
    user_vector = vectorizer.transform([cleaned_text])
    prob = model.predict_proba(user_vector)[0][1]

    ml_score = prob * 100

    print("\nML Scam Probability:", round(ml_score, 2), "%")

    # =============================
    # SECURITY CHECKS (FIXED POSITION)
    # =============================
    emails = extract_emails(cleaned_text)
    urls = extract_urls(cleaned_text)
    phones = extract_phone_numbers(cleaned_text)

    

    print("\n==============================")
    print(" SECURITY ANALYSIS ")
    print("==============================")

    print("\nEmails Found:", emails)
    print("URLs Found:", urls)
    print("\nPhone Numbers Found:")
    print(phones)

    suspicious_domain = False

    for email in emails:

        result = check_email_reputation(email)

        print("\nEmail Check:", email)
        print("Status:", result)

        if result == "Suspicious Email Domain":
            suspicious_domain = True

    # =============================
    # FINAL RISK SCORE
    # =============================
    risk_score = calculate_risk(
    ml_probability=prob,
    suspicious_domain=suspicious_domain,
    suspicious_url=(len(urls) > 0),
    suspicious_phone=(len(phones) > 0),
    keyword_risk=keyword_risk)

    print("\n==============================")
    print(" FINAL RISK SCORE ")
    print("==============================")

    print("\nRisk Score:", risk_score)

    # =============================
    # FINAL CLASSIFICATION
    # =============================
    print("\n==============================")
    print(" FINAL RESULT ")
    print("==============================")

    if risk_score >= 75:
        print("\nSCAM JOB DETECTED")

    elif risk_score >= 45:
        print("\nSUSPICIOUS JOB")

    else:
        print("\nLEGITIMATE JOB")