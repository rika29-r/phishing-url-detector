"""Phishing URL Detector - modul analisis heuristik.

Hasil analisis hanya berupa INDIKASI risiko berdasarkan pola URL,
bukan kepastian bahwa sebuah situs adalah phishing.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field, asdict
from urllib.parse import urlsplit, unquote

# ---------------------------------------------------------------------------
# Konstanta & pola regex
# ---------------------------------------------------------------------------

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "s.id", "tiny.cc", "rb.gy",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work",
    "zip", "mov", "icu", "buzz", "cam", "rest", "country", "monster",
}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "update",
    "secure", "security", "banking", "confirm", "password", "wallet",
    "suspend", "unlock", "billing", "payment", "invoice", "recover",
]

# Merek yang sering ditiru (brand -> domain resmi yang sah).
BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.co.id"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com"},
    "netflix": {"netflix.com"},
    "tokopedia": {"tokopedia.com"},
    "shopee": {"shopee.co.id", "shopee.com"},
    "gojek": {"gojek.com"},
    "bca": {"bca.co.id", "klikbca.com"},
    "bni": {"bni.co.id"},
    "bri": {"bri.co.id"},
    "mandiri": {"bankmandiri.co.id"},
    "dana": {"dana.id"},
    "ovo": {"ovo.id"},
}

# Second-level suffix umum agar registered domain lebih akurat tanpa library eksternal.
MULTI_PART_SUFFIXES = {
    "co.id", "go.id", "ac.id", "or.id", "web.id", "sch.id", "my.id",
    "co.uk", "org.uk", "com.au", "co.jp", "com.sg", "com.my",
}

RE_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
RE_HEX_ENCODED = re.compile(r"%[0-9a-fA-F]{2}")
RE_DECIMAL_IP = re.compile(r"^\d{8,10}$")
RE_HEX_IP = re.compile(r"^0x[0-9a-fA-F]+$")
RE_DOUBLE_SLASH_PATH = re.compile(r"//")
LEET_MAP = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"}
RE_DIGIT_IN_WORD = re.compile(r"(?<=[a-z])[01345](?=[a-z]|$)", re.IGNORECASE)
RE_EMBEDDED_URL = re.compile(r"https?(://|%3a%2f%2f)", re.IGNORECASE)
RE_NON_ASCII = re.compile(r"[^\x00-\x7f]")


# ---------------------------------------------------------------------------
# Struktur data hasil
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule: str
    description: str
    points: int


@dataclass
class AnalysisResult:
    url: str
    normalized_url: str
    score: int
    level: str
    label: str
    parts: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    disclaimer: str = (
        "Hasil ini hanya indikasi berdasarkan pola URL, bukan kepastian "
        "bahwa situs tersebut phishing atau aman."
    )

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Fungsi bantu
# ---------------------------------------------------------------------------

def normalize_url(raw: str) -> str:
    """Bersihkan spasi dan tambahkan skema bila tidak ada."""
    url = raw.strip()
    if not RE_SCHEME.match(url):
        url = "http://" + url
    return url


def is_ip_host(host: str) -> bool:
    """True jika host berupa IP (IPv4/IPv6, desimal, atau heksadesimal)."""
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(RE_DECIMAL_IP.match(host) or RE_HEX_IP.match(host))


def registered_domain(host: str) -> str:
    """Perkirakan registered domain (mis. login.bca.co.id -> bca.co.id)."""
    labels = host.lower().split(".")
    if len(labels) <= 2:
        return host.lower()
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _risk_level(score: int) -> tuple[str, str]:
    if score >= 60:
        return "high", "Risiko Tinggi"
    if score >= 30:
        return "medium", "Risiko Sedang"
    return "low", "Risiko Rendah"


# ---------------------------------------------------------------------------
# Analisis utama
# ---------------------------------------------------------------------------

def analyze_url(raw_url: str) -> AnalysisResult:
    """Analisis sebuah URL dan kembalikan skor risiko beserta temuan."""
    if not raw_url or not raw_url.strip():
        raise ValueError("URL tidak boleh kosong.")
    if len(raw_url) > 2048:
        raise ValueError("URL terlalu panjang (maksimal 2048 karakter).")

    url = normalize_url(raw_url)
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"URL tidak valid: {exc}") from exc

    if not host:
        raise ValueError("URL tidak valid: host tidak ditemukan.")

    findings: list[Finding] = []

    def add(rule: str, description: str, points: int) -> None:
        findings.append(Finding(rule, description, points))

    scheme = parsed.scheme.lower()
    path = unquote(parsed.path or "")
    query = unquote(parsed.query or "")
    ip_host = is_ip_host(host)

    # --- 1. Struktur dasar URL ------------------------------------------
    if scheme != "https":
        add("no_https", "Tidak memakai HTTPS (koneksi tidak terenkripsi).", 10)

    if len(url) > 100:
        add("long_url", f"URL sangat panjang ({len(url)} karakter).", 10)
    elif len(url) > 75:
        add("long_url", f"URL cukup panjang ({len(url)} karakter).", 5)

    if "@" in parsed.netloc:
        add("at_symbol", "Ada simbol '@' pada bagian host; teks sebelum '@' "
            "diabaikan browser dan sering dipakai untuk menipu.", 20)

    if port and port not in (80, 443):
        add("odd_port", f"Memakai port non-standar ({port}).", 10)

    if RE_DOUBLE_SLASH_PATH.search(path):
        add("double_slash", "Terdapat '//' di dalam path URL.", 5)

    # --- 2. Penggunaan IP sebagai domain --------------------------------
    if ip_host:
        add("ip_host", "Domain berupa alamat IP, bukan nama domain.", 30)

    # --- 3. Analisis domain ---------------------------------------------
    if not ip_host:
        labels = host.split(".")
        reg_domain = registered_domain(host)
        subdomain_count = max(len(labels) - len(reg_domain.split(".")), 0)

        if subdomain_count >= 3:
            add("many_subdomains", f"Terlalu banyak subdomain ({subdomain_count}).", 15)
        elif subdomain_count == 2:
            add("many_subdomains", "Subdomain berlapis (2 level).", 5)

        tld = labels[-1]
        if tld in SUSPICIOUS_TLDS:
            add("suspicious_tld", f"TLD '.{tld}' sering disalahgunakan.", 10)

        if host in SHORTENERS or reg_domain in SHORTENERS:
            add("shortener", "Memakai layanan pemendek URL; tujuan asli tersembunyi.", 15)

        if host.count("-") >= 2:
            add("hyphens", f"Banyak tanda hubung pada domain ({host.count('-')}).", 10)
        elif "-" in reg_domain.split(".")[0]:
            add("hyphens", "Ada tanda hubung pada nama domain utama.", 5)

        if sum(ch.isdigit() for ch in host) >= 4:
            add("digits_in_host", "Banyak angka pada nama domain.", 5)

        if host.startswith("xn--") or ".xn--" in host:
            add("punycode", "Memakai Punycode (kemungkinan homograph/IDN).", 20)

        if RE_NON_ASCII.search(host):
            add("non_ascii_host", "Domain memuat karakter non-ASCII.", 20)

        if shannon_entropy(labels[0]) > 3.8 and len(labels[0]) >= 12:
            add("high_entropy", "Nama domain tampak acak (entropi tinggi).", 10)

        # Peniruan merek
        main_label = reg_domain.split(".")[0]
        # Ganti angka yang menyerupai huruf (0->o, 1->l, 3->e, 4->a, 5->s) di antara huruf.
        leet = RE_DIGIT_IN_WORD.sub(lambda m: LEET_MAP[m.group(0)], main_label)
        for brand, official in BRANDS.items():
            if reg_domain in official:
                continue
            if brand in host or (brand in leet and leet != main_label):
                add("brand_impersonation",
                    f"Memuat nama merek '{brand}' tetapi bukan domain resminya "
                    f"({reg_domain}).", 25)
                break

    # --- 4. Pola & karakter mencurigakan --------------------------------
    keyword_pool = f"{host}{path}{query}".lower()
    hits = sorted({kw for kw in PHISHING_KEYWORDS if kw in keyword_pool})
    if len(hits) >= 3:
        add("keywords", f"Banyak kata kunci sensitif: {', '.join(hits)}.", 15)
    elif hits:
        add("keywords", f"Kata kunci sensitif: {', '.join(hits)}.", 7 * len(hits))

    encoded_count = len(RE_HEX_ENCODED.findall(url))
    if encoded_count >= 5:
        add("encoding", f"Banyak karakter ter-encode ({encoded_count} kali %XX).", 10)

    if RE_EMBEDDED_URL.search(path + "?" + parsed.query):
        add("embedded_url", "Ada URL lain di dalam path/query (kemungkinan redirect).", 15)

    if parsed.query.count("&") >= 5:
        add("many_params", "Terlalu banyak parameter query.", 5)

    if parsed.fragment and len(parsed.fragment) > 30:
        add("long_fragment", "Fragment URL tidak wajar panjangnya.", 5)

    if re.search(r"\.(exe|scr|apk|bat|msi|zip|js|vbs)$", path, re.IGNORECASE):
        add("risky_file", "URL mengarah ke file yang dapat dieksekusi/diunduh.", 15)

    # --- Skor akhir ------------------------------------------------------
    score = min(sum(f.points for f in findings), 100)
    level, label = _risk_level(score)

    parts = {
        "scheme": scheme,
        "host": host,
        "registered_domain": host if ip_host else registered_domain(host),
        "port": port,
        "path": parsed.path or "/",
        "query": parsed.query,
        "fragment": parsed.fragment,
        "host_is_ip": ip_host,
        "length": len(url),
    }

    return AnalysisResult(
        url=raw_url.strip(),
        normalized_url=url,
        score=score,
        level=level,
        label=label,
        parts=parts,
        findings=[asdict(f) for f in sorted(findings, key=lambda f: -f.points)],
    )
