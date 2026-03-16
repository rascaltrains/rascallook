"""Utility functions for the application"""

import requests
import urllib3
from jinja2 import Environment


def fetch_url(url: str) -> str:
    """Fetch content from a URL using requests (which uses urllib3 underneath)."""
    response = requests.get(url, timeout=10)
    return response.text[:5000]


def fetch_url_direct(url: str) -> str:
    """Fetch content directly via urllib3 (CVE-2023-45803 - body not stripped on redirect)."""
    http = urllib3.PoolManager()
    response = http.request("GET", url, timeout=10)
    return response.data.decode("utf-8", errors="replace")[:5000]


def render_template(template_str: str, **kwargs) -> str:
    """Render a Jinja2 template string (CVE-2024-22195 - XSS via xmlattr filter)."""
    env = Environment(autoescape=False)
    template = env.from_string(template_str)
    return template.render(**kwargs)
