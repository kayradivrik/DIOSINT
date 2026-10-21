# ==============================================================================
# DIOSINT - TEKNİK MİMARİ VE SIFIRDAN KODLAMA REHBERİ
# ==============================================================================
# Bu doküman, projeyi sıfırdan kendi başınıza yazabilmeniz, mantığını kavrayabilmeniz
# ve mülakatlarda/portföyünüzde her satırını rahatça açıklayabilmeniz için hazırlanmıştır.

"""
1. GENEL MİMARİ VE ÇALIŞMA MANTIĞI
---------------------------------
OSINT (Açık Kaynak İstihbaratı) araçları temel olarak 3 aşamadan oluşur:
1. Girdi Alma (Hedef: username, ip, domain, email, phone)
2. Asenkron İstekler (Hedef sistemleri boğmadan, hızlı ve paralel sorgulama)
3. Çıktı ve Raporlama (Renkli terminal tablosu + Diske HTML/JSON kayıt)

2. KLASÖR VE DOSYA DÜZENİ (Clean Architecture)
---------------------------------------------
Diosint/
│
├── diosint.bat           --> Windows kullanıcıları için çift tıkla-çalıştır başlatıcısı.
├── terminal_app.py       --> Ana İnteraktif Menü (Rich kütüphanesi ile neon CMD arayüzü).
├── main.py               --> Script/CLI Girişi (Tek satırlık komutla otomasyon yapmak için).
├── config.py             --> Merkezi Ayarlar (40+ platform listesi, timeout, user-agent).
├── requirements.txt      --> Gerekli Python kütüphaneleri.
│
├── modules/              --> Çekirdek İstihbarat Fonksiyonları
│   ├── username_lookup.py --> 40+ sitede profil varlığı ve GitHub API derin profilleme.
│   ├── ip_lookup.py       --> IP-API ve DNS ile ISP, ülke, şehir, ters DNS (PTR) tespiti.
│   ├── scraper.py         --> Hedef sitenin CMS, teknolojileri ve güvenlik başlıklarını kazıma.
│   ├── email_osint.py     --> MX kayıtları ve HIBP sızıntı kontrolü.
│   ├── phone_lookup.py    --> Telefon format temizleme ve uluslararası ülke kodu tespiti.
│   ├── darkweb.py         --> Ahmia motoru üzerinden Tor (.onion) sitelerini tarama.
│   └── geoint.py          --> OpenStreetMap/Nominatim ile koordinattan açık adres çıkarma.
│
├── api_clients/          --> İsteğe Bağlı Harici API Entegrasyonları (Shodan, VirusTotal vb.)
├── utils/                --> Yardımcı Araçlar (Rapor kaydetme, rate limit, proxy vb.)
└── reports/              --> Yapılan taramaların otomatik kaydedildiği klasör (HTML/JSON).


3. KODLARIN ÇALIŞMA SIRASI VE MANTIĞI
------------------------------------

Adım 1: Başlatıcı (diosint.bat)
- CMD karakter kodunu UTF-8 yapar (`chcp 65001`).
- Sanal ortamdaki Python'ı (`venv\Scripts\python.exe`) kullanarak `terminal_app.py` dosyasını çalıştırır.

Adım 2: Terminal Menüsü (terminal_app.py)
- Konsolu temizler (`cls`).
- Rich kütüphanesiyle görseldeki 3 sütunlu mor neon çerçeveyi ekrana basar.
- Kullanıcıdan `Input > ` bekler.
- Girilen numaraya göre ilgili modülün fonksiyonunu çağırır.

Adım 3: Asenkron Sorgulama (Örn: modules/username_lookup.py)
- Neden `asyncio` ve `httpx`?
  Eğer 40 siteyi standart `requests` ile tek tek gezseydik 40 saniye sürerdi.
  `asyncio.gather()` kullanarak 40 siteye AYNI ANDA istek atılır ve işlem 2-3 saniyede biter!
- HTTP Durum Kodları:
  - 200 OK: Kullanıcı profili mevcut.
  - 404 Not Found: Böyle bir profil yok.

Adım 4: Veri Analizi ve Scraping (modules/scraper.py)
- `httpx` ile hedef sayfanın HTML kodunu çeker.
- `BeautifulSoup` kütüphanesi ile HTML'i parçalar.
- Sayfa içindeki `<meta name="generator">` etiketlerine veya script yollarına bakarak WordPress, React, Vue vb. tespiti yapar.
- HTTP Security Headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options` gibi başlıkların varlığına göre 100 üzerinden güvenlik notu (A-F) hesaplar.

Adım 5: Raporlama (utils/output_handler.py)
- Elde edilen veriyi standart Python sözlüğü (`dict`) olarak alır.
- Hem `reports/<tarih>_<hedef>.json` dosyasına ham veri olarak yazar.
- Hem de içine CSS gömülü modern bir HTML şablonuna basarak yönetici raporu üretir.


4. BU PROJEYİ SIFIRDAN KENDİNİZ NASIL YAZARSINIZ? (Adım Adım Yol Haritası)
------------------------------------------------------------------------
1. Adım: Bir sanal ortam açın (`python -m venv venv`) ve aktifleştirin.
2. Adım: Temel kütüphaneleri yükleyin:
   `pip install httpx rich typer beautifulsoup4 dnspython pandas`
3. Adım: `config.py` oluşturup sorgulayacağınız sitelerin URL şablonlarını yazın:
   Örn: `{"Instagram": "https://www.instagram.com/{}/", "GitHub": "https://github.com/{}"}`
4. Adım: İlk modülünüzü yazın (`username_lookup.py`):
   İçinde bir `async def check(client, url)` fonksiyonu olsun, `resp.status_code == 200` ise 'Bulundu' desin.
5. Adım: `terminal_app.py` yazarak `rich.console` ile renkli bir menü yapın ve fonksiyonunuzu bağlayın.
"""
