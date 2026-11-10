import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detector import analyze_url, is_ip_host, registered_domain  # noqa: E402


def rules(url):
    return {f["rule"] for f in analyze_url(url).findings}


def test_safe_url_is_low_risk():
    r = analyze_url("https://www.wikipedia.org")
    assert r.level == "low"
    assert r.score < 30


def test_url_without_scheme_is_normalized():
    r = analyze_url("example.com")
    assert r.normalized_url.startswith("http://")
    assert "no_https" in rules("example.com")


def test_ip_host_detected():
    assert "ip_host" in rules("http://192.168.1.10/login")
    assert analyze_url("http://192.168.1.10/login").parts["host_is_ip"] is True


@pytest.mark.parametrize("host", ["127.0.0.1", "3232235777", "0xC0A80101", "::1"])
def test_is_ip_host_variants(host):
    assert is_ip_host(host)


def test_domain_not_ip():
    assert not is_ip_host("example.com")


def test_at_symbol_detected():
    assert "at_symbol" in rules("http://google.com@evil.example.xyz/")


def test_brand_impersonation():
    assert "brand_impersonation" in rules("https://paypal-secure-login.example.com")


def test_official_brand_domain_not_flagged():
    assert "brand_impersonation" not in rules("https://www.paypal.com/signin")


def test_leet_brand_impersonation():
    assert "brand_impersonation" in rules("https://paypa1.com")  # 1 -> l


def test_indonesian_domain_suffix():
    assert registered_domain("login.bca.co.id") == "bca.co.id"
    assert "brand_impersonation" not in rules("https://www.bca.co.id")


def test_suspicious_tld_and_keywords():
    found = rules("http://verify-account-login.xyz/update")
    assert {"suspicious_tld", "keywords", "hyphens"} <= found


def test_many_subdomains():
    assert "many_subdomains" in rules("https://a.b.c.d.example.com")


def test_punycode_detected():
    assert "punycode" in rules("http://xn--pple-43d.com")


def test_embedded_url_redirect():
    assert "embedded_url" in rules("https://example.com/r?u=http://evil.com")


def test_shortener_detected():
    assert "shortener" in rules("https://bit.ly/abc123")


def test_odd_port():
    assert "odd_port" in rules("http://example.com:8080/")


def test_high_risk_composite_url():
    r = analyze_url("http://192.168.0.1:8080/secure/login/verify-account?next=http://x.tk")
    assert r.level == "high"
    assert r.score <= 100


def test_score_is_capped_at_100():
    r = analyze_url(
        "http://user@paypal-login-secure-verify.account-update.xyz:8080/"
        "login/verify/password/update//?a=1&b=2&c=3&d=4&e=5&f=6&u=http://x.tk"
    )
    assert r.score == 100


@pytest.mark.parametrize("bad", ["", "   ", "http://", "http://[::1"])
def test_invalid_input_raises(bad):
    with pytest.raises(ValueError):
        analyze_url(bad)


def test_too_long_url_rejected():
    with pytest.raises(ValueError):
        analyze_url("http://a.com/" + "a" * 2100)


def test_result_to_dict_has_disclaimer():
    d = analyze_url("https://example.com").to_dict()
    assert "indikasi" in d["disclaimer"]
    assert {"score", "level", "findings", "parts"} <= d.keys()
