import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app  # noqa: E402


@pytest.fixture()
def client():
    app.config["TESTING"] = True
    return app.test_client()


def test_index_page(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"Phishing URL Detector" in r.data


def test_health(client):
    assert client.get("/health").get_json() == {"status": "ok"}


def test_api_analyze_ok(client):
    r = client.post("/api/analyze", json={"url": "http://192.168.1.1/login"})
    data = r.get_json()
    assert r.status_code == 200
    assert data["parts"]["host_is_ip"] is True
    assert data["score"] >= 30


def test_api_analyze_empty(client):
    r = client.post("/api/analyze", json={"url": ""})
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_api_analyze_bad_body(client):
    r = client.post("/api/analyze", data="bukan json", content_type="text/plain")
    assert r.status_code == 400


def test_form_analyze(client):
    r = client.post("/analyze", data={"url": "https://example.com"})
    assert r.status_code == 200
    assert b"/100" in r.data


def test_form_escapes_html(client):
    r = client.post("/analyze", data={"url": "http://x.com/<script>alert(1)</script>"})
    assert b"<script>alert(1)</script>" not in r.data
