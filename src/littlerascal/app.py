"""Flask web application with intentionally vulnerable patterns for Endor Labs scanning"""

import os

from flask import Flask, jsonify, render_template_string, request
from jinja2 import Environment

from littlerascal.utils import fetch_url, render_template

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super-secret-key-do-not-use-in-prod")


@app.route("/")
def index():
    return jsonify({"status": "ok", "version": "0.1.0"})


@app.route("/greet/<name>")
def greet(name):
    """SSTI risk: user input directly in template string."""
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


@app.route("/render", methods=["POST"])
def render():
    """Render user-provided Jinja2 template (CVE-2024-22195 - XSS via xmlattr)."""
    template_str = request.get_data(as_text=True)
    return render_template(template_str)


@app.route("/fetch")
def fetch():
    """Fetch a URL via requests - potential SSRF."""
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "url parameter required"}), 400
    result = fetch_url(url)
    return jsonify({"content": result})


@app.route("/redirect")
def redirect_url():
    """Fetch with redirect following (urllib3 CVE-2023-45803 - body not stripped)."""
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "url parameter required"}), 400
    result = fetch_url(url)
    return jsonify({"content": result})


def create_app():
    return app


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
