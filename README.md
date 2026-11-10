# 🛡️ Phishing URL Detector

Aplikasi web sederhana berbasis **Python, Flask, dan Regex** yang menganalisis struktur sebuah URL dan memberikan **skor risiko (0–100)** beserta alasan di balik skor tersebut.

> ⚠️ **Catatan penting:** hasil analisis hanyalah **indikasi** berdasarkan pola URL, **bukan kepastian** bahwa sebuah situs adalah phishing (atau aman). URL tidak pernah dikunjungi; hanya teksnya yang dianalisis.

## Fitur

- **Memeriksa struktur URL**: skema (HTTP/HTTPS), host, domain utama, port, path, query, fragment, dan panjang URL.
- **Mendeteksi IP sebagai domain**: IPv4/IPv6, serta bentuk desimal (`3232235777`) dan heksadesimal (`0xC0A80101`).
- **Memeriksa karakter dan pola mencurigakan**:
  - simbol `@`, port non-standar, `//` di path
  - subdomain berlapis, banyak tanda hubung/angka, TLD yang sering disalahgunakan (`.xyz`, `.tk`, dll.)
  - Punycode / karakter non-ASCII (serangan homograph)
  - peniruan merek, termasuk trik huruf-angka (`paypa1.com`)
  - kata kunci sensitif (`login`, `verify`, `password`, ...)
  - URL pemendek (bit.ly, dll.), URL tertanam (redirect), karakter ter-encode berlebihan
  - nama domain acak (entropi Shannon tinggi), file berbahaya (`.exe`, `.apk`, ...)
- **Hasil analisis risiko**: skor, level (Rendah / Sedang / Tinggi), dan daftar temuan beserta bobotnya.
- **Antarmuka web** dan **REST API JSON**.

## Struktur Project

```
phishing-url-detector/
├── app.py              # aplikasi Flask (web + API)
├── detector.py         # logika analisis (regex + aturan skor)
├── templates/index.html
├── static/style.css
├── tests/              # unit test (pytest)
├── requirements.txt
└── LICENSE
```

## Cara Menjalankan

```bash
git clone https://github.com/<username>/phishing-url-detector.git
cd phishing-url-detector

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python app.py
```

Buka <http://127.0.0.1:5000>.

## Penggunaan API

```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://192.168.1.10/login"}'
```

Contoh respons (dipersingkat):

```json
{
  "score": 47,
  "level": "medium",
  "label": "Risiko Sedang",
  "parts": { "scheme": "http", "host": "192.168.1.10", "host_is_ip": true },
  "findings": [
    { "rule": "ip_host", "description": "Domain berupa alamat IP, bukan nama domain.", "points": 30 },
    { "rule": "no_https", "description": "Tidak memakai HTTPS (koneksi tidak terenkripsi).", "points": 10 },
    { "rule": "keywords", "description": "Kata kunci sensitif: login.", "points": 7 }
  ],
  "disclaimer": "Hasil ini hanya indikasi ..."
}
```

| Endpoint | Metode | Deskripsi |
|---|---|---|
| `/` | GET | Halaman web |
| `/analyze` | POST | Form HTML |
| `/api/analyze` | POST | Analisis JSON (`{"url": "..."}`) |
| `/health` | GET | Pemeriksaan status |

## Contoh Hasil

| URL | Skor | Level |
|---|---|---|
| `https://www.wikipedia.org` | 0 | Rendah |
| `http://192.168.1.10/login` | 47 | Sedang |
| `https://paypa1.com/verify-account` | 39 | Sedang |
| `http://bca-klik-login.xyz/secure/update` | 70 | Tinggi |

## Cara Kerja Skor

Setiap aturan yang cocok menambah poin (maksimal total 100):

| Skor | Level |
|---|---|
| 0 – 29 | 🟢 Rendah |
| 30 – 59 | 🟠 Sedang |
| 60 – 100 | 🔴 Tinggi |

Bobot tiap aturan dapat disesuaikan di `detector.py`.

## Pengujian

```bash
pytest -v
```

## Keterbatasan

- Pendekatan **heuristik**: bisa terjadi *false positive* (situs sah ditandai) dan *false negative* (phishing lolos).
- Tidak memeriksa isi halaman, sertifikat SSL, umur domain, WHOIS, atau reputasi/blacklist.
- Daftar merek, TLD, dan suffix domain bersifat terbatas dan dapat diperluas.

## Ide Pengembangan

- Integrasi blacklist (mis. Google Safe Browsing, PhishTank)
- Cek umur domain (WHOIS) dan validitas sertifikat SSL
- Model machine learning dengan dataset URL phishing
- Ekstensi browser, Docker, dan CI (GitHub Actions)

## Lisensi

[MIT](LICENSE)
