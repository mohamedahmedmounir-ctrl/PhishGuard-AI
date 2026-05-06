"""
PhishGuard AI - Model Training Script
======================================
Trains a Naive Bayes classifier on phishing email data using TF-IDF vectorization.

How it works:
1. Load CSV dataset (text + label columns)
2. Preprocess text (lowercase, remove punctuation, strip stopwords)
3. Vectorize using TF-IDF (converts text to numeric feature matrix)
4. Split data into train/test sets (80/20)
5. Train Multinomial Naive Bayes model
6. Evaluate: accuracy, confusion matrix, classification report
7. Save model + vectorizer as .pkl files for Flask app to load
"""

import os
import re
import pickle
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, confusion_matrix,
    classification_report, roc_auc_score
)
from sklearn.pipeline import Pipeline

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET    = os.path.join(BASE_DIR, "dataset", "phishing_emails.csv")
MODEL_DIR  = os.path.join(BASE_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
VEC_PATH   = os.path.join(MODEL_DIR, "vectorizer.pkl")


# ── Text preprocessing ─────────────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    "urgent", "verify", "suspend", "account", "password", "click", "prize",
    "winner", "limited", "immediately", "confirm", "update", "bank", "free",
    "offer", "claim", "expire", "warning", "alert", "lottery", "congratulations",
    "bitcoin", "gift", "reward", "selected", "compliance", "illegal", "threatened",
    "security", "breach", "stolen", "paypal", "apple", "amazon", "microsoft",
    "government", "irs", "invoice", "payment", "credit"
]

def preprocess_text(text: str) -> str:
    """Clean and normalize email text for TF-IDF vectorization."""
    text = str(text).lower()
    text = re.sub(r'http\S+|www\S+', ' url_token ', text)   # replace URLs
    text = re.sub(r'\b[\w.-]+@[\w.-]+\.\w+\b', ' email_token ', text)  # emails
    text = re.sub(r'\b\d+\b', ' num_token ', text)           # numbers
    text = re.sub(r'[^a-z\s_]', ' ', text)                   # punctuation
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def extract_keyword_features(text: str) -> dict:
    """Count known phishing keywords in text (used for scoring later)."""
    lower = text.lower()
    hits  = [kw for kw in PHISHING_KEYWORDS if kw in lower]
    return {
        "keyword_count": len(hits),
        "keywords_found": hits,
        "has_url": bool(re.search(r'http\S+|www\S+', text, re.I)),
        "has_urgency": any(w in lower for w in ["urgent", "immediately", "now", "warning", "alert"])
    }


# ── Training ───────────────────────────────────────────────────────────────────
def train():
    print("=" * 60)
    print("  PhishGuard AI — Model Training")
    print("=" * 60)

    # 1. Load data
    df = pd.read_csv(DATASET)
    print(f"\n[+] Loaded {len(df)} samples")
    print(f"    Phishing : {(df['label'] == 1).sum()}")
    print(f"    Legit    : {(df['label'] == 0).sum()}")

    # 2. Preprocess
    df["clean_text"] = df["text"].apply(preprocess_text)

    # 3. Split
    X_train, X_test, y_train, y_test = train_test_split(
        df["clean_text"], df["label"],
        test_size=0.2, random_state=42, stratify=df["label"]
    )
    print(f"\n[+] Train: {len(X_train)} | Test: {len(X_test)}")

    # 4. Vectorizer — TF-IDF with unigrams + bigrams
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),     # unigrams & bigrams capture phrase patterns
        sublinear_tf=True,       # log-scale TF reduces impact of very frequent terms
        strip_accents="unicode",
        analyzer="word",
        min_df=1
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec  = vectorizer.transform(X_test)

    # 5. Train model (Naive Bayes — fast, effective for text classification)
    model = MultinomialNB(alpha=0.1)   # alpha=smoothing to avoid zero probabilities
    model.fit(X_train_vec, y_train)

    # 6. Evaluate
    y_pred     = model.predict(X_test_vec)
    y_prob     = model.predict_proba(X_test_vec)[:, 1]
    accuracy   = accuracy_score(y_test, y_pred)
    auc        = roc_auc_score(y_test, y_prob) if len(set(y_test)) > 1 else 0.0
    cm         = confusion_matrix(y_test, y_pred)
    report     = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])

    print(f"\n[+] Accuracy : {accuracy * 100:.2f}%")
    print(f"[+] AUC-ROC  : {auc:.4f}")
    print("\n[+] Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
    print("\n[+] Classification Report:")
    print(report)

    # 7. Save artifacts
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(VEC_PATH, "wb") as f:
        pickle.dump(vectorizer, f)

    print(f"[+] Model saved     → {MODEL_PATH}")
    print(f"[+] Vectorizer saved→ {VEC_PATH}")
    print("\n✅  Training complete!\n")
    return model, vectorizer


if __name__ == "__main__":
    train()
