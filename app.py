"""Aplikasi Flask untuk Phishing URL Detector."""

from flask import Flask, jsonify, render_template, request

from detector import analyze_url

app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyze")
def analyze_form():
    """Endpoint untuk form HTML."""
    url = request.form.get("url", "")
    try:
        result = analyze_url(url).to_dict()
        return render_template("index.html", result=result, url=url)
    except ValueError as exc:
        return render_template("index.html", error=str(exc), url=url), 400


@app.post("/api/analyze")
def analyze_api():
    """Endpoint JSON. Body: {"url": "https://contoh.com"}"""
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(analyze_url(str(data.get("url", ""))).to_dict())
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # debug=False secara default agar aman; set FLASK_DEBUG=1 saat development.
    app.run(host="127.0.0.1", port=5000)
