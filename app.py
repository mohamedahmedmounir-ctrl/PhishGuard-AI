"""
PhishGuard AI — Flask Application
====================================
Main backend server. Exposes REST API endpoints consumed by the
single-page frontend (templates/index.html).

Routes:
  GET  /              → serve dashboard
  POST /analyze/email → email phishing prediction
  POST /analyze/url   → URL phishing analysis
  GET  /logs          → return detection history (JSON)
  GET  /stats         → return aggregate statistics
  GET  /export        → download detection logs as CSV
"""

import os
import re
import json
import csv
import io
from datetime import datetime

from flask import (
    Flask, render_template, request, jsonify,
    send_file, abort
)

# ── Utility imports ────────────────────────────────────────────────────────────
from utils.predictor    import predict_email
from utils.url_analyzer import analyze_url

# ── App setup ──────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024   # 1 MB max request body

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_PATH = os.path.join(BASE_DIR, "logs", "detection_logs.json")
os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)


def load_logs():
    """Load existing detection logs from JSON file."""
    if not os.path.exists(LOG_PATH):
        return []
    try:
        with open(LOG_PATH, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []


def save_log(entry: dict):
    """Append a detection result to the JSON log file."""
    logs = load_logs()
    logs.insert(0, entry)          # newest first
    logs = logs[:500]              # keep last 500 entries max
    try:
        with open(LOG_PATH, "w") as f:
            json.dump(logs, f, indent=2)
    except IOError as e:
        app.logger.error(f"Failed to save log: {e}")


def sanitize_input(text: str, max_len: int = 10000) -> str:
    """
    Basic input sanitization:
    - Strip leading/trailing whitespace
    - Truncate to max_len characters
    - Remove null bytes
    """
    if not isinstance(text, str):
        return ""
    text = text.replace('\x00', '')   # remove null bytes
    text = text.strip()
    return text[:max_len]


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


@app.route("/analyze/email", methods=["POST"])
def analyze_email():
    """
    Analyze email text for phishing.
    Expected JSON body: { "text": "..." }
    Returns: prediction result dict
    """
    data = request.get_json(silent=True)
    if not data or "text" not in data:
        return jsonify({"error": "Missing 'text' field in request body"}), 400

    email_text = sanitize_input(data["text"])
    if len(email_text) < 10:
        return jsonify({"error": "Email text is too short to analyze"}), 400

    try:
        result = predict_email(email_text)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        app.logger.exception("Email analysis error")
        return jsonify({"error": "Internal analysis error"}), 500

    # Persist log entry
    log_entry = {
        "id":           _next_id(),
        "type":         "email",
        "input":        email_text[:200] + ("…" if len(email_text) > 200 else ""),
        "verdict":      result["verdict"],
        "risk_score":   result["risk_score"],
        "threat_level": result["threat_level"],
        "timestamp":    datetime.utcnow().isoformat() + "Z"
    }
    save_log(log_entry)

    return jsonify(result)


@app.route("/analyze/url", methods=["POST"])
def analyze_url_route():
    """
    Analyze a URL for phishing indicators.
    Expected JSON body: { "url": "..." }
    Returns: URL analysis result dict
    """
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field in request body"}), 400

    url = sanitize_input(data["url"], max_len=2000)
    if len(url) < 4:
        return jsonify({"error": "URL is too short"}), 400

    # Basic URL validation
    if not re.match(r'^(https?://|www\.|\S+\.\S+)', url, re.I):
        return jsonify({"error": "Input does not appear to be a valid URL"}), 400

    try:
        result = analyze_url(url)
    except Exception as e:
        app.logger.exception("URL analysis error")
        return jsonify({"error": "Internal analysis error"}), 500

    # Persist log entry
    log_entry = {
        "id":           _next_id(),
        "type":         "url",
        "input":        url[:200],
        "verdict":      result["verdict"],
        "risk_score":   result["risk_score"],
        "threat_level": result["threat_level"],
        "timestamp":    datetime.utcnow().isoformat() + "Z"
    }
    save_log(log_entry)

    return jsonify(result)


@app.route("/logs")
def get_logs():
    """Return detection history as JSON (last 100 entries)."""
    logs = load_logs()[:100]
    return jsonify(logs)


@app.route("/stats")
def get_stats():
    """Return aggregate statistics for the dashboard."""
    logs = load_logs()
    total     = len(logs)
    phishing  = sum(1 for l in logs if l.get("verdict") in ("phishing", "suspicious"))
    legit     = total - phishing
    avg_risk  = round(
        sum(l.get("risk_score", 0) for l in logs) / total, 1
    ) if total else 0
    # Threat level breakdown
    levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
    for l in logs:
        lvl = l.get("threat_level", "SAFE")
        if lvl in levels:
            levels[lvl] += 1

    return jsonify({
        "total_scans":     total,
        "phishing_count":  phishing,
        "legitimate_count": legit,
        "avg_risk_score":  avg_risk,
        "threat_levels":   levels
    })


@app.route("/export")
def export_logs():
    """Export detection logs as a downloadable CSV file."""
    logs = load_logs()
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["id", "type", "input", "verdict", "risk_score", "threat_level", "timestamp"],
        extrasaction="ignore"
    )
    writer.writeheader()
    writer.writerows(logs)
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"phishguard_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    )


def _next_id() -> int:
    """Generate a simple incrementing ID based on current log size."""
    return len(load_logs()) + 1


# ── Dev server entrypoint ─────────────────────────────────────────────────────
if __name__ == "__main__":
    # Ensure model is trained before starting
    model_exists = os.path.exists(os.path.join(BASE_DIR, "model", "phishing_model.pkl"))
    if not model_exists:
        print("[!] Model not found. Training now...")
        from model.train_model import train
        train()

    print("[+] PhishGuard AI starting on http://localhost:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
