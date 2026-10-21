<div align="center">

# 🛡️ DIOSINT
### Next-Gen Cyber Intelligence & OSINT Reconnaissance Framework

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-purple.svg?style=for-the-badge)](https://github.com)
[![Status](https://img.shields.io/badge/Status-Active%20Development-orange.svg?style=for-the-badge)]()

*Diosint, modern siber güvenlik araştırmacıları ve analistler için tasarlanmış asenkron, zengin arayüzlü ve modüler bir Açık Kaynak İstihbaratı (OSINT) platformudur.*

</div>

---

> [!WARNING]
> **YASAL UYARI / LEGAL DISCLAIMER:**  
> Bu araç **yalnızca eğitim, savunma ve yetkili güvenlik araştırmaları** için tasarlanmıştır. İzniniz olmayan sistemler üzerinde kullanılması yasa dışıdır. Detaylar için lütfen [DISCLAIMER.md](DISCLAIMER.md) dosyasını inceleyin.

---

## ✨ Özellikler (Key Capabilities)

- 🔍 **Username Reconnaissance:** 40'tan fazla popüler platformda eş zamanlı (asenkron `httpx`) profil varlığı tespiti ve GitHub API derin profillemesi.
- 🌐 **IP & Network Intelligence:** IP geolocation, Autonomous System (ASN), ISP, PTR ters DNS ve proxy/barındırma tespiti.
- 🔐 **Passive Subdomain Discovery:** `crt.sh` (Certificate Transparency) ve DNS loglarından hedef sunucuya dokunmadan pasif alt alan adı tespiti.
- 🖼️ **Image & EXIF Forensic:** Fotoğraflardan cihaz bilgisi, lens parametreleri, yazılım ve gömülü GPS koordinatlarını çözümleme.
- 📧 **Email & Breach Intelligence:** RFC 5322 e-posta doğrulaması, MX kayıt denetimi ve HaveIBeenPwned API sızıntı sorgulaması.
- 🕷️ **Asynchronous Web Scraper:** CMS, sunucu, kütüphaneler, OpenGraph metadataları, güvenlik başlıkları analizi (HSTS, CSP, X-Frame-Options) ve link haritalama.
- 🧅 **Tor & Dark Web Intelligence:** Ahmia motoru üzerinden kamuya açık `.onion` arama ve indeksleme.
- 📍 **GEOINT (Coğrafi İstihbarat):** OpenStreetMap / Nominatim API ile enlem/boylam koordinatlarından adres çözümleme ve Google Haritalar/Uydu linkleme.
- 📊 **Veri İlişkilendirme & Görselleştirme:** Toplanan verilerden `NetworkX` ile düğüm-kenar ilişkisi kurma ve `PyVis` ile interaktif HTML ağ grafikleri oluşturma.
- 📁 **Raporlama Motoru:** Çıktıları otomatik olarak temiz JSON, CSV ve CSS gömülü modern HTML raporları olarak kaydetme.
- 💻 **İki Farklı Çalışma Modu:**
  1. **İnteraktif Terminal Arayüzü (TUI):** Neon mor/pembe Rich konsolu (`terminal_app.py` veya `diosint.bat`).
  2. **Otomasyon & CLI:** CI/CD ve script otomasyonları için Typer tabanlı komut satırı arayüzü (`main.py`).

---

## 📁 Proje Dizin Yapısı

```
Diosint/
├── terminal_app.py       # Zengin Rich neon interaktif menü konsolu
├── main.py               # Typer tabanlı CLI otomasyon arayüzü
├── diosint.bat           # Windows kullanıcıları için çift tıkla-çalıştır başlatıcısı
├── config.py             # Merkezi konfigürasyon ve platform tanımları
├── requirements.txt      # Gerekli bağımlılıklar
├── Dockerfile            # Containerize çalıştırma desteği
├── .env.example          # Örnek API anahtar şablonu
├── ARCHITECTURE.md       # Proje mimarisi ve eğitim notları
├── DISCLAIMER.md         # Yasal sorumluluk reddi metni
├── LICENSE               # MIT Açık Kaynak Lisansı
│
├── modules/              # İstihbarat modülleri
│   ├── username_lookup.py
│   ├── ip_lookup.py
│   ├── subdomain_recon.py
│   ├── metadata_extractor.py
│   ├── scraper.py
│   ├── email_osint.py
│   ├── phone_lookup.py
│   ├── darkweb.py
│   ├── geoint.py
│   └── network_mapper.py
│
├── api_clients/          # Harici API istemcileri
│   ├── shodan_client.py
│   └── virustotal_client.py
│
├── utils/                # Yardımcı araçlar (Rate limiter, proxy, raporlama)
└── reports/              # Üretilen HTML/JSON raporlar (.gitkeep)
```

---

## 🚀 Hızlı Başlangıç (Kurulum)

### 1. Depoyu Klonlayın
```bash
git clone https://github.com/KULLANICI_ADINIZ/diosint.git
cd diosint
```

### 2. Sanal Ortam Oluşturun & Bağımlılıkları Yükleyin
```bash
# Sanal ortam oluşturma
python -m venv venv

# Aktifleştirme (Windows)
venv\Scripts\activate

# Aktifleştirme (Linux / macOS)
source venv/bin/activate

# Kütüphaneleri kurun
pip install -r requirements.txt
```

### 3. API Anahtarlarını Ayarlayın (Opsiyonel)
```bash
# Örnek .env dosyasını kopyalayın
copy .env.example .env    # Windows
cp .env.example .env      # Linux/macOS
```
`.env` dosyasını açıp Shodan, VirusTotal veya HaveIBeenPwned API anahtarlarınızı isteğe bağlı olarak ekleyin.

---

## 🎮 Kullanım

### Seçenek A: İnteraktif Konsol (Tavsiye Edilen)
Windows'ta `diosint.bat` dosyasına çift tıklayabilir veya terminalden çalıştırabilirsiniz:
```bash
python terminal_app.py
```

### Seçenek B: Komut Satırı (CLI)
```bash
# Kullanıcı adı profilleme
python main.py username --target johndoe --output json

# IP ve altyapı istihbaratı
python main.py ip --target 1.1.1.1 --shodan

# E-posta ve sızıntı kontrolü
python main.py email --target target@example.com

# Web sitesi teknoloji ve güvenlik taraması
python main.py scrape --target https://example.com

# Koordinattan adres çözümleme (GEOINT)
python main.py geoint --lat 41.0082 --lon 28.9784
```

---

## 🔒 Güvenlik & Gizlilik

- **API Anahtarları:** `.env` dosyası varsayılan olarak `.gitignore` içerisindedir ve asla Git deposuna gönderilmez.
- **Proxy & Tor Desteği:** `utils/proxy_manager.py` ile anonim istek göndermek için yerel Tor servisi (`socks5h://127.0.0.1:9050`) veya `proxies.txt` listesi kullanılabilir.
- **Veri Saklama:** Oluşturulan tarama raporları yerel `reports/` klasöründe tutulur ve Git deposuna gönderilmez.

---

## 👨‍💻 Geliştirici & Yazar (Author)

**Kayra Divrik**  
- GitHub: [@kayradivrik](https://github.com/kayradivrik) *(veya profil linkiniz)*  
- Proje: **Diosint OSINT & Cyber Reconnaissance Framework**

---

## 📜 Lisans & Yasal Sorumluluk

Bu proje **Kayra Divrik** telif hakkı altında [MIT Lisansı](LICENSE) kapsamında açık kaynak olarak sunulmuştur.  
Kullanıcılar, yazılımı kullanırken yürürlükteki tüm yasalara (TCK Madde 243-244, KVKK, GDPR) uymakla yükümlüdür. Ayrıntılar için [DISCLAIMER.md](DISCLAIMER.md) belgesini okuyunuz.
