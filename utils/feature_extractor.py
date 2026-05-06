"""
PhishGuard AI — Feature Extractor
===================================
Extracts cybersecurity-relevant features from email text.
These features supplement the ML model's TF-IDF prediction.
"""

import re
from typing import Dict, List, Any

# High-confidence phishing signal words/phrases
PHISHING_KEYWORDS: List[str] = [
    "urgent", "immediately", "verify", "suspend", "suspended", "confirm",
    "account", "password", "click here", "limited time", "expires",
    "winner", "won", "prize", "free gift", "congratulations", "selected",
    "lottery", "claim", "reward", "guaranteed", "100%", "risk free",
    "act now", "don't delay", "final notice", "last chance",
    "paypal", "apple id", "microsoft account", "icloud", "google account",
    "bank account", "credit card", "social security", "ssn",
    "irs", "government", "legal action", "lawsuit", "arrested",
    "bitcoin", "cryptocurrency", "wire transfer", "gift card",
    "update your information", "verify your identity", "confirm your details",
    "suspicious activity", "unauthorized access", "security alert",
    "account compromised", "account hacked", "data breach"
]

# Urgency / pressure language
URGENCY_WORDS: List[str] = [
    "urgent", "immediately", "asap", "right now", "right away",
    "within 24 hours", "within 48 hours", "expires today", "last chance",
    "final warning", "act now", "don't delay", "respond now"
]

# Impersonation targets
BRAND_IMPERSONATION: List[str] = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "chase", "wells fargo", "bank of america", "citibank",
    "irs", "fedex", "ups", "dhl", "usps"
]


def extract_email_features(text: str) -> Dict[str, Any]:
    """
    Extract phishing indicator features from email text.

    Returns a dict with:
      - keyword_matches   : list of matched phishing keywords
      - keyword_count     : number of unique keyword matches
      - has_urgency       : urgency/pressure language detected
      - has_url           : contains hyperlink
      - has_ip_url        : URL with IP address (major red flag)
      - url_count         : number of URLs in text
      - has_suspicious_url: URL uses suspicious TLD or free hosting
      - brand_impersonation: detected brand being impersonated
      - asks_credentials  : requesting sensitive data
      - has_monetary      : mentions money/financial incentives
      - exclamation_count : number of ! (aggressive punctuation)
      - caps_ratio        : ratio of uppercase letters (shouting)
      - risk_multiplier   : weighted risk contribution (0.0–1.0)
    """
    lower = text.lower()

    # ── Keyword matching ──────────────────────────────────────────────────────
    keyword_matches = [kw for kw in PHISHING_KEYWORDS if kw in lower]

    # ── URL analysis ──────────────────────────────────────────────────────────
    url_pattern = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+'
        r'|www\.[^\s<>"{}|\\^`\[\]]+',
        re.IGNORECASE
    )
    urls = url_pattern.findall(text)
    has_ip_url = any(re.search(r'https?://\d{1,3}(\.\d{1,3}){3}', u) for u in urls)

    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.cc', '.pw',
                       '.top', '.click', '.link', '.info', '.biz', '.online']
    has_suspicious_url = any(
        any(tld in u.lower() for tld in suspicious_tlds) or
        'bit.ly' in u.lower() or 'tinyurl' in u.lower() or
        re.search(r'https?://[^/]+\.(tk|ml|ga|cf|gq)', u, re.I)
        for u in urls
    )

    # ── Urgency / pressure ────────────────────────────────────────────────────
    has_urgency = any(w in lower for w in URGENCY_WORDS)

    # ── Brand impersonation ───────────────────────────────────────────────────
    brands_found = [b for b in BRAND_IMPERSONATION if b in lower]

    # ── Credential harvesting signals ─────────────────────────────────────────
    credential_patterns = [
        r'(enter|provide|submit|confirm|verify).*(password|credential|login|username)',
        r'(banking|credit card|account).*(number|detail|info)',
        r'(social security|ssn|passport|date of birth)',
        r'click.*link.*(verify|confirm|validate)'
    ]
    asks_credentials = any(re.search(p, lower) for p in credential_patterns)

    # ── Financial lure ────────────────────────────────────────────────────────
    monetary_patterns = [
        r'\$\d+', r'\d+,\d+ (dollar|usd)', r'(win|won|earn|receive|claim).{0,30}(money|\$|cash)',
        r'(prize|reward|gift card|voucher|lottery)'
    ]
    has_monetary = any(re.search(p, lower) for p in monetary_patterns)

    # ── Aggressive formatting ─────────────────────────────────────────────────
    exclamation_count = text.count('!')
    letters = [c for c in text if c.isalpha()]
    caps_ratio = sum(1 for c in letters if c.isupper()) / len(letters) if letters else 0.0

    # ── Composite risk multiplier ─────────────────────────────────────────────
    # Each factor contributes a weighted amount to an overall 0–1 risk score
    risk = 0.0
    risk += min(len(keyword_matches) * 0.06, 0.35)   # keywords (max 35%)
    risk += 0.20 if has_ip_url else 0.0               # IP URL is very suspicious
    risk += 0.12 if has_suspicious_url else 0.0
    risk += 0.10 if has_urgency else 0.0
    risk += 0.10 if asks_credentials else 0.0
    risk += 0.08 if has_monetary else 0.0
    risk += 0.05 if brands_found else 0.0
    risk += min(exclamation_count * 0.01, 0.05)
    risk += min(caps_ratio * 0.10, 0.05)
    risk = min(risk, 1.0)

    return {
        "keyword_matches":     keyword_matches,
        "keyword_count":       len(keyword_matches),
        "has_urgency":         has_urgency,
        "has_url":             len(urls) > 0,
        "has_ip_url":          has_ip_url,
        "url_count":           len(urls),
        "has_suspicious_url":  has_suspicious_url,
        "brand_impersonation": brands_found,
        "asks_credentials":    asks_credentials,
        "has_monetary":        has_monetary,
        "exclamation_count":   exclamation_count,
        "caps_ratio":          round(caps_ratio, 3),
        "risk_multiplier":     round(risk, 3)
    }


def get_highlighted_text(text: str, keyword_matches: List[str]) -> str:
    """
    Return the original text with phishing keywords wrapped in <mark> tags
    for frontend highlighting.
    """
    highlighted = text
    # Sort by length descending to avoid partial replacements
    for kw in sorted(keyword_matches, key=len, reverse=True):
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        highlighted = pattern.sub(
            lambda m: f'<mark class="phish-highlight">{m.group()}</mark>',
            highlighted
        )
    return highlighted
