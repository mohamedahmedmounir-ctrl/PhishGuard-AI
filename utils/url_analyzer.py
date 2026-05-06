"""
PhishGuard AI — URL Analyzer
==============================
Rule-based + heuristic analysis of URLs for phishing indicators.
No external API calls required; fully offline analysis.

Cybersecurity features analyzed:
  1. Protocol (HTTPS vs HTTP)
  2. URL length (longer = more suspicious)
  3. Number of dots (subdomain abuse)
  4. IP address in host
  5. Suspicious TLDs (.tk, .ml, etc.)
  6. Known URL shorteners
  7. Hyphen count in domain
  8. Digit count in domain
  9. Suspicious path keywords (login, verify, secure, update)
  10. @ symbol in URL (tricks browser into using different host)
  11. Double slash redirect patterns
  12. Subdomain depth
  13. Brand/keyword spoofing
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Tuple


# Free / abused TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.pw', '.cc',
    '.top', '.click', '.link', '.info', '.biz', '.online',
    '.site', '.website', '.host', '.space', '.fun', '.party'
}

# Popular URL shorteners
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc', 'cutt.ly', 'rb.gy'
}

# Sensitive path keywords that shouldn't appear in URLs
SUSPICIOUS_PATH_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update',
    'confirm', 'validate', 'credential', 'password', 'recover',
    'reset', 'banking', 'paypal', 'amazon', 'apple', 'microsoft'
]

# Brands often spoofed in phishing URLs
SPOOFED_BRANDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix',
    'facebook', 'instagram', 'twitter', 'linkedin', 'dropbox',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc'
]


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Perform comprehensive phishing analysis on a URL.
    Returns a structured dict with all features and a final risk score.
    """
    # Ensure URL has a scheme for urlparse to work correctly
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
    except Exception:
        return {"error": "Invalid URL format", "risk_score": 100, "verdict": "phishing"}

    host   = parsed.netloc.lower()
    path   = parsed.path.lower()
    scheme = parsed.scheme.lower()
    full   = url.lower()

    features: Dict[str, Any] = {}
    risk_points = 0          # accumulate risk (higher = more suspicious)
    findings: List[str] = [] # human-readable explanations

    # ── 1. Protocol ───────────────────────────────────────────────────────────
    features['uses_https'] = (scheme == 'https')
    if scheme != 'https':
        risk_points += 15
        findings.append("⚠ Uses HTTP instead of HTTPS — connection is unencrypted")

    # ── 2. URL length ─────────────────────────────────────────────────────────
    url_length = len(url)
    features['url_length'] = url_length
    if url_length > 75:
        pts = min(20, int((url_length - 75) / 10) * 4)
        risk_points += pts
        findings.append(f"⚠ URL is unusually long ({url_length} chars) — may be obfuscated")

    # ── 3. Dot count ──────────────────────────────────────────────────────────
    dot_count = host.count('.')
    features['dot_count'] = dot_count
    if dot_count > 3:
        risk_points += min(15, (dot_count - 3) * 5)
        findings.append(f"⚠ Excessive subdomains ({dot_count} dots) — classic spoofing tactic")

    # ── 4. IP address in host ─────────────────────────────────────────────────
    ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$'
    has_ip = bool(re.match(ip_pattern, host.split(':')[0]))
    features['has_ip_address'] = has_ip
    if has_ip:
        risk_points += 30
        findings.append("🚨 Host is a raw IP address — legitimate sites use domain names")

    # ── 5. Suspicious TLD ─────────────────────────────────────────────────────
    tld = '.' + host.split('.')[-1] if '.' in host else ''
    features['tld'] = tld
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    features['suspicious_tld'] = is_suspicious_tld
    if is_suspicious_tld:
        risk_points += 20
        findings.append(f"⚠ Uses free/abused TLD '{tld}' — popular with phishers")

    # ── 6. URL shortener ─────────────────────────────────────────────────────
    is_shortener = any(s in host for s in URL_SHORTENERS)
    features['is_url_shortener'] = is_shortener
    if is_shortener:
        risk_points += 15
        findings.append("⚠ URL shortener detected — hides the real destination")

    # ── 7. Hyphen count in domain ─────────────────────────────────────────────
    domain_part = host.split('/')[0]
    hyphen_count = domain_part.count('-')
    features['hyphen_count'] = hyphen_count
    if hyphen_count > 1:
        risk_points += min(10, hyphen_count * 3)
        findings.append(f"⚠ Domain contains {hyphen_count} hyphens — often used in fake domains")

    # ── 8. Digits in domain ───────────────────────────────────────────────────
    digit_count = sum(c.isdigit() for c in domain_part)
    features['digit_count_in_domain'] = digit_count
    if digit_count > 3:
        risk_points += 8
        findings.append(f"⚠ Domain contains {digit_count} digits — unusual for legitimate sites")

    # ── 9. Suspicious path keywords ───────────────────────────────────────────
    path_hits = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path]
    features['suspicious_path_keywords'] = path_hits
    if path_hits:
        risk_points += min(20, len(path_hits) * 7)
        findings.append(f"⚠ Path contains sensitive keywords: {', '.join(path_hits)}")

    # ── 10. @ symbol in URL ───────────────────────────────────────────────────
    has_at = '@' in url
    features['has_at_symbol'] = has_at
    if has_at:
        risk_points += 25
        findings.append("🚨 @ symbol in URL — browser ignores everything before @ (redirect trick)")

    # ── 11. Double slash in path ──────────────────────────────────────────────
    has_redirect = '//' in path
    features['has_double_slash'] = has_redirect
    if has_redirect:
        risk_points += 10
        findings.append("⚠ Double slash in path — possible open redirect")

    # ── 12. Brand spoofing ────────────────────────────────────────────────────
    spoofed = [b for b in SPOOFED_BRANDS if b in host or b in path]
    # Only flag if brand is NOT the actual domain (e.g., 'paypal' in host but host isn't paypal.com)
    confirmed_spoofs = []
    for brand in spoofed:
        # Legitimate: paypal.com, apple.com — Spoof: paypal-secure.tk, apple-id.verify.com
        if not host.endswith(f'{brand}.com') and not host.endswith(f'www.{brand}.com'):
            confirmed_spoofs.append(brand)
    features['brand_spoofing'] = confirmed_spoofs
    if confirmed_spoofs:
        risk_points += 25
        findings.append(f"🚨 Brand impersonation detected: {', '.join(confirmed_spoofs)}")

    # ── 13. Entropy / randomness in domain ───────────────────────────────────
    domain_name = host.split('.')[0] if '.' in host else host
    entropy = _shannon_entropy(domain_name)
    features['domain_entropy'] = round(entropy, 3)
    if entropy > 3.8:
        risk_points += 10
        findings.append("⚠ Domain name looks randomly generated (high entropy)")

    # ── Final scoring ─────────────────────────────────────────────────────────
    risk_score = min(risk_points, 100)
    verdict, threat_level, recommendation = _classify_risk(risk_score)

    return {
        "url":             url,
        "risk_score":      risk_score,
        "verdict":         verdict,
        "threat_level":    threat_level,
        "recommendation":  recommendation,
        "findings":        findings,
        "features":        features,
        "feature_summary": _build_summary(features)
    }


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy to detect random-looking domain names."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def _classify_risk(score: int) -> Tuple[str, str, str]:
    """Map numeric risk score to verdict, threat level, and recommendation."""
    if score >= 70:
        return (
            "phishing",
            "CRITICAL",
            "🚨 Do NOT visit this URL. It shows multiple phishing indicators. "
            "Do not enter credentials, click links, or download files."
        )
    elif score >= 40:
        return (
            "suspicious",
            "HIGH",
            "⚠ Exercise extreme caution. This URL has suspicious characteristics. "
            "Verify through official channels before proceeding."
        )
    elif score >= 20:
        return (
            "suspicious",
            "MEDIUM",
            "⚠ Some risk indicators detected. Proceed with caution and verify "
            "the site's legitimacy before entering any personal information."
        )
    else:
        return (
            "safe",
            "LOW",
            "✅ URL appears safe. Always verify the domain matches the service "
            "you intend to visit."
        )


def _build_summary(features: Dict) -> List[Dict]:
    """Build a human-friendly feature checklist for the UI."""
    checks = [
        {
            "label": "HTTPS Encryption",
            "value": "Yes" if features.get('uses_https') else "No",
            "safe":  features.get('uses_https', False)
        },
        {
            "label": "IP Address Host",
            "value": "Detected" if features.get('has_ip_address') else "None",
            "safe":  not features.get('has_ip_address', False)
        },
        {
            "label": "Suspicious TLD",
            "value": features.get('tld', 'N/A') if features.get('suspicious_tld') else "Clean",
            "safe":  not features.get('suspicious_tld', False)
        },
        {
            "label": "URL Shortener",
            "value": "Detected" if features.get('is_url_shortener') else "None",
            "safe":  not features.get('is_url_shortener', False)
        },
        {
            "label": "Brand Spoofing",
            "value": ", ".join(features.get('brand_spoofing', [])) or "None",
            "safe":  not features.get('brand_spoofing', [])
        },
        {
            "label": "URL Length",
            "value": str(features.get('url_length', 0)) + " chars",
            "safe":  features.get('url_length', 0) <= 75
        },
        {
            "label": "@ Redirect Trick",
            "value": "Detected" if features.get('has_at_symbol') else "None",
            "safe":  not features.get('has_at_symbol', False)
        },
        {
            "label": "Domain Entropy",
            "value": str(features.get('domain_entropy', 0)),
            "safe":  features.get('domain_entropy', 0) <= 3.8
        },
    ]
    return checks
