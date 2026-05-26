import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# -------------------------------
# LOAD DATA
# -------------------------------
df = pd.read_csv("fake_job_postings.csv")

# Select relevant columns
df = df[['title', 'company_profile', 'description', 'requirements', 'benefits', 'fraudulent']]

# IMPORTANT: keep all rows
df = df.fillna("")

# Convert label
df['fraudulent'] = df['fraudulent'].astype(int)

# Combine text
df['text'] = (
    df['title'] + " " +
    df['company_profile'] + " " +
    df['description'] + " " +
    df['requirements'] + " " +
    df['benefits']
)

df = df[['text', 'fraudulent']]

# Remove empty rows
df = df[df['text'].str.strip() != ""]

# -------------------------------
# DEBUG CHECK
# -------------------------------
print("\nClass distribution:")
print(df['fraudulent'].value_counts())

# -------------------------------
# TF-IDF
# -------------------------------
vectorizer = TfidfVectorizer(
    max_features=8000,
    stop_words='english',
    ngram_range=(1, 2)
)

X = vectorizer.fit_transform(df['text'])
y = df['fraudulent']

# -------------------------------
# SPLIT
# -------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# -------------------------------
# MODEL
# -------------------------------
model = RandomForestClassifier(
    n_estimators=150,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# -------------------------------
# EVALUATION
# -------------------------------
y_pred = model.predict(X_test)
print("\nAccuracy:", accuracy_score(y_test, y_pred))

# -------------------------------
# PREDICTION LOOP
# -------------------------------
while True:
    user_input = input("\nEnter job description (or type 'exit'): ")

    if user_input.lower() == "exit":
        break

    if len(user_input.strip()) == 0:
        print("Please enter valid text")
        continue

    user_vector = vectorizer.transform([user_input])

    # Probability
    prob = model.predict_proba(user_vector)[0][1]

    print("Scam Probability:", round(prob, 3))

    # Balanced decision logic
    if prob > 0.6:
        print("Scam Job Detected")
    elif prob > 0.4:
        print("Suspicious Job (Needs Review)")
    else:
        print("Legitimate Job")

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# -------------------------------
# LOAD DATA
# -------------------------------
df = pd.read_csv("fake_job_postings.csv")

# Select relevant columns
df = df[['title', 'company_profile', 'description', 'requirements', 'benefits', 'fraudulent']]

# IMPORTANT: keep all rows
df = df.fillna("")

# Convert label
df['fraudulent'] = df['fraudulent'].astype(int)

# Combine text
df['text'] = (
    df['title'] + " " +
    df['company_profile'] + " " +
    df['description'] + " " +
    df['requirements'] + " " +
    df['benefits']
)

df = df[['text', 'fraudulent']]

# Remove empty rows
df = df[df['text'].str.strip() != ""]

# -------------------------------
# DEBUG CHECK
# -------------------------------
print("\nClass distribution:")
print(df['fraudulent'].value_counts())

# -------------------------------
# TF-IDF
# -------------------------------
vectorizer = TfidfVectorizer(
    max_features=8000,
    stop_words='english',
    ngram_range=(1, 2)
)

X = vectorizer.fit_transform(df['text'])
y = df['fraudulent']

# -------------------------------
# SPLIT
# -------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# -------------------------------
# MODEL
# -------------------------------
model = RandomForestClassifier(
    n_estimators=150,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# -------------------------------
# EVALUATION
# -------------------------------
y_pred = model.predict(X_test)
print("\nAccuracy:", accuracy_score(y_test, y_pred))

# -------------------------------
# PREDICTION LOOP
# -------------------------------
while True:
    user_input = input("\nEnter job description (or type 'exit'): ")

    if user_input.lower() == "exit":
        break

    if len(user_input.strip()) == 0:
        print("Please enter valid text")
        continue

    user_vector = vectorizer.transform([user_input])

    # Probability
    prob = model.predict_proba(user_vector)[0][1]

    print("Scam Probability:", round(prob, 3))

    # Balanced decision logic
    if prob > 0.6:
        print("Scam Job Detected")
    elif prob > 0.4:
        print("Suspicious Job (Needs Review)")
    else:
        print("Legitimate Job")

