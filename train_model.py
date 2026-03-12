import pandas as pd
import pickle
import re

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report


# -----------------------------
# URL Cleaning Function
# -----------------------------
def clean_url(url):

    url = url.lower()

    url = re.sub(r"https?://", "", url)
    url = re.sub(r"www\.", "", url)

    return url


# -----------------------------
# Load Dataset
# -----------------------------
# Dataset format:
# url,label
# google.com,1
# paypal-login-update.xyz,0

data = pd.read_csv("phishing_dataset.csv")

print("Dataset Loaded")
print(data.head())


# -----------------------------
# Preprocess URLs
# -----------------------------
data["url"] = data["url"].apply(clean_url)


# -----------------------------
# Features & Labels
# -----------------------------
X = data["url"]
y = data["label"]


# -----------------------------
# Train Test Split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)


# -----------------------------
# TF-IDF Vectorizer
# -----------------------------
vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2,5)
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)


# -----------------------------
# Train Model
# -----------------------------
model = LogisticRegression()

model.fit(X_train_vec, y_train)


# -----------------------------
# Model Evaluation
# -----------------------------
y_pred = model.predict(X_test_vec)

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))


# -----------------------------
# Save Model
# -----------------------------
pickle.dump(model, open("phishing_model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("\nModel saved successfully")