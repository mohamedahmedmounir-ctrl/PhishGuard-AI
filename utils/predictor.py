"""
PhishGuard AI — Predictor
==========================
Loads trained model/vectorizer and combines ML prediction with
heuristic feature extraction for a final risk score.
"""

import os
import re
import pickle
from typing import Dict, Any

from utils.feature_extractor import extract_email_features, get_highlighted_text

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")
VEC_PATH   = os.path.join(BASE_DIR, "model", "vectorizer.pkl")

_model      = None
_vectorizer = None


def _load_model():
    """Lazy-load model + vectorizer once (cached for subsequent calls)."""
    global _model, _vectorizer
    if _model is None:
        if not os.path.exists(MODEL_PATH) or not os.path.exists(VEC_PATH):
            raise FileNotFoundError(
                "Model not found. Please run: python model/train_model.py"
            )
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        with open(VEC_PATH, "rb") as f:
            _vectorizer = pickle.load(f)


def preprocess(text: str) -> str:
    """Same preprocessing pipeline used during training."""
    text = text.lower()
    text = re.sub(r'http\S+|www\S+', ' url_token ', text)
    text = re.sub(r'\b[\w.-]+@[\w.-]+\.\w+\b', ' email_token ', text)
    text = re.sub(r'\b\d+\b', ' num_token ', text)
    text = re.sub(r'[^a-z\s_]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def predict_email(text: str) -> Dict[str, Any]:
    """
    Predict whether an email is phishing using the trained ML model
    combined with heuristic feature analysis.

    Returns:
        verdict       : "phishing" | "legitimate"
        ml_confidence : ML model's confidence (0–100%)
        risk_score    : blended final risk score (0–100%)
        threat_level  : "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        recommendation: actionable security advice
        features      : extracted heuristic features
        highlighted   : HTML text with keywords marked
    """
    _load_model()

    # ── ML prediction ─────────────────────────────────────────────────────────
    clean   = preprocess(text)
    vec     = _vectorizer.transform([clean])
    proba   = _model.predict_proba(vec)[0]   # [P(legit), P(phish)]
    ml_phish_prob = float(proba[1])           # probability of phishing

    # ── Heuristic feature extraction ──────────────────────────────────────────
    features = extract_email_features(text)

    # ── Blend ML + heuristics ─────────────────────────────────────────────────
    # Weighted average: 70% ML, 30% rule-based risk multiplier
    blended_risk = (ml_phish_prob * 0.70) + (features['risk_multiplier'] * 0.30)
    risk_score   = round(blended_risk * 100, 1)
    ml_conf      = round(ml_phish_prob * 100, 1)

    # ── Verdict ───────────────────────────────────────────────────────────────
    verdict      = "phishing" if risk_score >= 50 else "legitimate"
    threat_level, recommendation = _get_threat_info(risk_score, verdict)

    # ── Highlighted HTML ──────────────────────────────────────────────────────
    highlighted = get_highlighted_text(text, features['keyword_matches'])

    return {
        "verdict":        verdict,
        "ml_confidence":  ml_conf,
        "risk_score":     risk_score,
        "threat_level":   threat_level,
        "recommendation": recommendation,
        "features":       features,
        "highlighted":    highlighted
    }


def _get_threat_info(risk_score: float, verdict: str):
    """Map risk score to threat level and security recommendation."""
    if risk_score >= 80:
        return ("CRITICAL",
                "🚨 High-confidence phishing. Do not reply, click any links, or "
                "provide personal information. Report to your IT/security team immediately.")
    elif risk_score >= 60:
        return ("HIGH",
                "⚠ Very likely phishing. Treat with extreme suspicion. Verify "
                "sender identity through official channels before taking any action.")
    elif risk_score >= 40:
        return ("MEDIUM",
                "⚠ Suspicious indicators detected. Exercise caution. If unexpected, "
                "contact the sender through a known official channel to verify.")
    elif risk_score >= 20:
        return ("LOW",
                "✅ Likely legitimate but has minor indicators. Verify sender "
                "before clicking links or downloading attachments.")
    else:
        return ("SAFE",
                "✅ Email appears legitimate. Always stay vigilant and verify "
                "unexpected requests for sensitive information.")
