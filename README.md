# ⬡ PhishGuard AI

> **AI-powered phishing detection system** — Classify phishing emails and analyze suspicious URLs using Machine Learning, NLP, and cybersecurity heuristics.

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3+-000000?style=flat&logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3+-F7931E?style=flat&logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## 📋 Overview

PhishGuard AI checks emails and links for phishing. Paste an email or a URL and it returns a verdict, a 0–100% risk score, a threat level and the reasons behind it, combining a machine-learning text classifier with 13 URL security checks. Everything runs locally: nothing you paste is sent to a third party.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Email Detection** | Paste email text → ML + NLP predicts Phishing / Legitimate |
| **URL Analysis** | 13 cybersecurity heuristics check every URL for phishing indicators |
| **Risk Scoring** | Blended 0–100% risk score with threat levels (CRITICAL / HIGH / MEDIUM / LOW) |
| **Keyword Highlighting** | Suspicious phrases highlighted directly in email text |
| **Detection History** | Persistent log of all scans with timestamps |
| **Export Reports** | Download scan history as CSV |
| **Dark Cyberpunk UI** | Professional dashboard with animated grid and threat gauge |

---

## 🗂 Project Structure

```
PhishGuard-AI/
│
├── app.py                    # Flask application + REST API routes
├── requirements.txt
├── README.md
│
├── model/
│   ├── train_model.py        # Model training + evaluation script
│   ├── phishing_model.pkl    # Trained Naive Bayes classifier (generated)
│   └── vectorizer.pkl        # TF-IDF vectorizer (generated)
│
├── dataset/
│   └── phishing_emails.csv   # Training data (text, label)
│
├── utils/
│   ├── feature_extractor.py  # Email NLP feature extraction
│   ├── url_analyzer.py       # URL heuristic analysis (13 features)
│   └── predictor.py          # ML inference + blended scoring
│
├── templates/
│   └── index.html            # Single-page dashboard
│
├── static/
│   ├── style.css             # Cyberpunk dark theme
│   └── script.js             # Frontend logic + API calls
│
└── logs/
    └── detection_logs.json   # Auto-generated scan history
```

---

## 🚀 Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/mohamedahmedmounir-ctrl/PhishGuard-AI.git
cd PhishGuard-AI
```

### 2. Create a virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Train the ML model
```bash
python model/train_model.py
```
This generates `model/phishing_model.pkl` and `model/vectorizer.pkl`.

### 5. Run the application
```bash
python app.py
```

### 6. Open in browser
```
http://localhost:5000
```

---

## 📊 Dataset Format

The CSV file must have exactly two columns:

```csv
text,label
"Congratulations! You have won a prize...",1
"Hi team, the meeting is tomorrow at 3pm.",0
```

- `label = 1` → Phishing
- `label = 0` → Legitimate

You can replace the sample dataset with real phishing datasets from:
- [Kaggle Phishing Email Dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset)
- [Enron Email Dataset](https://www.cs.cmu.edu/~enron/)
- [PhishingCorpus](https://monkey.org/~jose/phishing/)

---

## 🔬 How the ML Model Works

```
Email Text
    │
    ▼
Preprocessing
  - Lowercase
  - Replace URLs → url_token
  - Replace emails → email_token
  - Remove numbers/punctuation
    │
    ▼
TF-IDF Vectorization
  - 5000 features
  - Unigrams + Bigrams
  - Sublinear TF scaling
    │
    ▼
Naive Bayes Classifier
  - MultinomialNB (alpha=0.1)
  - Outputs: P(phishing), P(legitimate)
    │
    ▼
Heuristic Blending
  Final Score = 70% × ML confidence + 30% × rule-based risk
    │
    ▼
Verdict + Threat Level + Recommendation
```

### Why Naive Bayes?
- **Fast**: Trains in milliseconds, predicts in microseconds
- **Effective**: Works well with high-dimensional sparse text (TF-IDF)
- **Interpretable**: Probabilities are meaningful
- **Generalizes well**: Even with small datasets via Laplace smoothing

---

## 🔍 URL Analysis Features

| Feature | Why It Matters |
|---|---|
| HTTPS check | Phishing sites often skip SSL |
| IP address host | Legitimate sites use domain names, not IPs |
| URL length | Obfuscated phishing URLs are very long |
| Subdomain depth (dot count) | Attackers abuse subdomains to spoof brands |
| Suspicious TLDs (.tk, .ml, .ga) | Free TLDs are popular with phishers |
| URL shorteners | Hide the real malicious destination |
| @ symbol | Tricks browser into using different host |
| Brand spoofing | PayPal → paypal-secure.tk |
| Domain entropy | Random-looking domains = auto-generated |
| Hyphens in domain | Fake domains use many hyphens |
| Sensitive path keywords | /login, /verify, /password in URL path |

---

## 🛠 Technologies Used

- **Python 3.9+** — Backend logic
- **Flask** — Web framework + REST API
- **scikit-learn** — ML (Naive Bayes, TF-IDF)
- **Pandas / NumPy** — Data processing
- **HTML5 / CSS3 / JavaScript** — Frontend (no frameworks)
- **JSON** — Log storage (easily upgradeable to SQLite)

---

## 🔐 Security Practices

- Input sanitization + length limits on all endpoints
- No `eval()` or dynamic code execution
- Error handling prevents stack traces from leaking to client
- Max request body size enforced (1 MB)
- Null byte stripping on all inputs

---

## 🚀 Future Improvements

- [ ] Train on larger real-world phishing datasets (50,000+ samples)
- [ ] Add BERT/DistilBERT transformer model for higher accuracy
- [ ] Gmail API integration — scan inbox directly
- [ ] VirusTotal API for URL reputation lookup
- [ ] Browser extension (Chrome/Firefox)
- [ ] SQLite database for scalable log storage
- [ ] Admin dashboard with charts (Chart.js)
- [ ] QR code phishing detection
- [ ] Docker deployment

---

---

*An educational security project. It is not a production security system; the model is trained on a small starter dataset.*
