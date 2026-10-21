"""
scraper.py - Deep Web Technology & Reconnaissance Engine
========================================================
Performs full-stack technology fingerprinting (frontend, backend, CMS, CDN),
SSL/TLS certificate inspection, DNS security posture (SPF/DMARC/MX),
security header auditing, and contact intelligence gathering.
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import DEFAULT_HEADERS, DEFAULT_TIMEOUT
from utils.proxy_manager import proxy_manager
from utils.rate_limiter import global_limiter

console = Console()

# ─── REGEX PATTERNS ──────────────────────────────────────────────────────────

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,7}\b")
PHONE_PATTERN = re.compile(r"""(?:(?:\+|00)[\d\s\-\(\)]{7,15}|0[\d\s\-\(\)]{9,14})""", re.VERBOSE)

SOCIAL_PATTERNS = {
    "Twitter/X": re.compile(r"(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,50})"),
    "Instagram": re.compile(r"instagram\.com/([A-Za-z0-9_.]{1,50})"),
    "LinkedIn":  re.compile(r"linkedin\.com/(?:in|company)/([A-Za-z0-9\-]{1,100})"),
    "GitHub":    re.compile(r"github\.com/([A-Za-z0-9\-]{1,100})"),
    "Facebook":  re.compile(r"facebook\.com/([A-Za-z0-9.]{1,100})"),
    "YouTube":   re.compile(r"youtube\.com/(?:@|c/|user/)?([A-Za-z0-9_\-]{1,100})"),
    "Telegram":  re.compile(r"t\.me/([A-Za-z0-9_]{3,50})"),
    "Discord":   re.compile(r"discord\.(?:gg|com/invite)/([A-Za-z0-9\-]{3,50})"),
}

# ─── FULL-STACK TECHNOLOGY SIGNATURES (50+ Detectors) ────────────────────────

TECH_SIGNATURES = {
    # 1. Frontend Frameworks & Libraries
    "Next.js": {"cat": "Frontend", "patterns": [r"/_next/", r"__NEXT_DATA__", r"next/dist/"]},
    "React": {"cat": "Frontend", "patterns": [r"react", r"react-dom", r"data-reactroot", r"_reactListening"]},
    "Vue.js": {"cat": "Frontend", "patterns": [r"vue(?:\.runtime)?(?:\.min)?\.js", r"v-data-", r"data-v-[a-f0-9]"]},
    "Nuxt.js": {"cat": "Frontend", "patterns": [r"/_nuxt/", r"__NUXT__"]},
    "Angular": {"cat": "Frontend", "patterns": [r"ng-version", r"ng-app", r"ng-controller", r"<app-root"]},
    "Svelte": {"cat": "Frontend", "patterns": [r"svelte-", r"/_app/immutable/"]},
    "Alpine.js": {"cat": "Frontend", "patterns": [r"x-data=", r"x-init=", r"alpine(?:\.min)?\.js"]},
    "HTMX": {"cat": "Frontend", "patterns": [r"hx-get=", r"hx-post=", r"htmx(?:\.min)?\.js"]},
    "jQuery": {"cat": "Frontend", "patterns": [r"jquery(?:\.min)?\.js", r"jQuery\.fn"]},

    # 2. Backend & Server Frameworks (Cookie, Header, HTML)
    "Django": {"cat": "Backend", "patterns": [r"csrftoken", r"name=[\"']csrfmiddlewaretoken[\"']", r"django"]},
    "Laravel": {"cat": "Backend", "patterns": [r"laravel_session", r"XSRF-TOKEN", r"laravel"]},
    "Ruby on Rails": {"cat": "Backend", "patterns": [r"action_dispatch", r"csrf-param[\"'] content=[\"']authenticity_token[\"']"]},
    "ASP.NET": {"cat": "Backend", "patterns": [r"__VIEWSTATE", r"ASP\.NET_SessionId", r"\.aspx", r"x-aspnet-version"]},
    "Express.js": {"cat": "Backend", "patterns": [r"express", r"x-powered-by: express"]},
    "Spring Boot": {"cat": "Backend", "patterns": [r"JSESSIONID", r"spring-boot"]},
    "PHP": {"cat": "Backend", "patterns": [r"PHPSESSID", r"x-powered-by: php", r"\.php\b"]},

    # 3. CMS & E-Commerce
    "WordPress": {"cat": "CMS", "patterns": [r"/wp-content/", r"/wp-includes/", r"wp-json", r'content="WordPress']},
    "WooCommerce": {"cat": "E-Commerce", "patterns": [r"woocommerce", r"wc-block-"]},
    "Shopify": {"cat": "E-Commerce", "patterns": [r"cdn\.shopify\.com", r"Shopify\.theme", r"myshopify\.com"]},
    "Drupal": {"cat": "CMS", "patterns": [r"drupal(?:\.min)?\.js", r'content="Drupal']},
    "Joomla": {"cat": "CMS", "patterns": [r'content="Joomla!', r"/media/jui/"]},
    "Wix": {"cat": "CMS", "patterns": [r"wix\.com", r"X-Wix-", r"static\.parastorage\.com"]},
    "Squarespace": {"cat": "CMS", "patterns": [r"squarespace\.com", r"static1\.squarespace\.com"]},
    "Webflow": {"cat": "CMS", "patterns": [r"assets\.website-files\.com", r'content="Webflow']},
    "Magento": {"cat": "E-Commerce", "patterns": [r"/static/frontend/Magento", r"mage/cookies\.js"]},
    "Ghost": {"cat": "CMS", "patterns": [r"ghost-", r'content="Ghost']},

    # 4. Styling & CSS Frameworks
    "Tailwind CSS": {"cat": "Styling", "patterns": [r"tailwindcss", r"tailwind(?:\.min)?\.css"]},
    "Bootstrap": {"cat": "Styling", "patterns": [r"bootstrap(?:\.bundle)?(?:\.min)?\.css", r"bootstrap(?:\.min)?\.js"]},
    "Bulma": {"cat": "Styling", "patterns": [r"bulma(?:\.min)?\.css"]},
    "Material UI (MUI)": {"cat": "Styling", "patterns": [r"MuiButton-", r"MuiBox-", r"MuiTypography-"]},

    # 5. CDN, Reverse Proxy & Cloud
    "Cloudflare": {"cat": "CDN/Proxy", "patterns": [r"cloudflare", r"cf-ray", r"cf-cache-status"]},
    "AWS CloudFront": {"cat": "CDN/Proxy", "patterns": [r"cloudfront", r"x-amz-cf-id"]},
    "Fastly": {"cat": "CDN/Proxy", "patterns": [r"fastly", r"x-fastly-"]},
    "Vercel": {"cat": "Cloud", "patterns": [r"x-vercel-id", r"vercel\.app"]},
    "Netlify": {"cat": "Cloud", "patterns": [r"x-nf-request-id", r"netlify"]},

    # 6. Analytics & Trackers
    "Google Analytics (GA4)": {"cat": "Analytics", "patterns": [r"googletagmanager\.com/gtag", r"google-analytics\.com/analytics\.js", r"G-[A-Z0-9]{8,}"]},
    "Google Tag Manager": {"cat": "Analytics", "patterns": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"]},
    "Hotjar": {"cat": "Analytics", "patterns": [r"static\.hotjar\.com", r"_hjSettings"]},
    "Facebook Pixel": {"cat": "Analytics", "patterns": [r"connect\.facebook\.net/en_US/fbevents\.js", r"fbq\('init'"]},
    "Yandex Metrica": {"cat": "Analytics", "patterns": [r"mc\.yandex\.ru/metrika", r"ym\([0-9]+"]},
    "Microsoft Clarity": {"cat": "Analytics", "patterns": [r"clarity\.ms/tag/"]},
}


def detect_technologies(html: str, headers: httpx.Headers) -> dict[str, list[str]]:
    """HTML içeriği ve HTTP başlıklarından teknolojileri tespit edip kategorize eder."""
    categorized: dict[str, list[str]] = {}
    combined_headers = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    combined_target = (html + " " + combined_headers)

    # Sunucu başlıkları
    server = headers.get("server")
    if server:
        categorized.setdefault("Web Server", []).append(server)
    powered_by = headers.get("x-powered-by")
    if powered_by:
        categorized.setdefault("Backend", []).append(f"Powered-by: {powered_by}")

    for tech_name, info in TECH_SIGNATURES.items():
        cat = info["cat"]
        for p in info["patterns"]:
            if re.search(p, combined_target, re.IGNORECASE):
                categorized.setdefault(cat, []).append(tech_name)
                break

    # Listeleri tekilleştir
    for cat in categorized:
        categorized[cat] = sorted(list(set(categorized[cat])))

    return categorized


def inspect_ssl_certificate(domain: str) -> dict[str, Any]:
    """Hedef sunucunun SSL/TLS sertifikasını ve protokol sürümünü inceler."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
            tls_version = s.version()

            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            subject_dict = dict(x[0] for x in cert.get("subject", []))
            sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

            return {
                "tls_version": tls_version,
                "issuer": issuer_dict.get("organizationName") or issuer_dict.get("commonName", "Unknown"),
                "subject": subject_dict.get("commonName", domain),
                "expires": cert.get("notAfter", "-"),
                "sans_count": len(sans),
                "sample_sans": sans[:6],
                "valid": True,
            }
    except Exception as e:
        return {"valid": False, "error": str(e)}


async def inspect_dns_security(domain: str) -> dict[str, Any]:
    """Google DoH üzerinden SPF, DMARC ve MX kayıtlarını sorgular."""
    dns_intel = {"spf": "Yok", "dmarc": "Yok", "mx": []}
    async with httpx.AsyncClient(headers=DEFAULT_HEADERS, timeout=6.0) as client:
        try:
            # 1. TXT / SPF
            r_txt = await client.get(f"https://dns.google/resolve?name={domain}&type=TXT")
            if r_txt.status_code == 200:
                answers = r_txt.json().get("Answer", [])
                for a in answers:
                    data = a.get("data", "")
                    if "v=spf1" in data:
                        dns_intel["spf"] = data.strip('"')

            # 2. DMARC
            r_dmarc = await client.get(f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT")
            if r_dmarc.status_code == 200:
                answers = r_dmarc.json().get("Answer", [])
                for a in answers:
                    data = a.get("data", "")
                    if "v=DMARC1" in data:
                        dns_intel["dmarc"] = data.strip('"')

            # 3. MX Records
            r_mx = await client.get(f"https://dns.google/resolve?name={domain}&type=MX")
            if r_mx.status_code == 200:
                answers = r_mx.json().get("Answer", [])
                dns_intel["mx"] = [a.get("data", "").split()[-1].rstrip(".") for a in answers if "data" in a][:4]
        except Exception:
            pass
    return dns_intel


def analyze_security_headers(headers: httpx.Headers) -> dict[str, Any]:
    """HTTP güvenlik başlıklarını puanlar ve denetler."""
    sec_headers = {
        "Strict-Transport-Security (HSTS)": "strict-transport-security" in headers,
        "Content-Security-Policy (CSP)": "content-security-policy" in headers,
        "X-Frame-Options (Clickjacking)": "x-frame-options" in headers,
        "X-Content-Type-Options": "x-content-type-options" in headers,
        "Referrer-Policy": "referrer-policy" in headers,
        "Permissions-Policy": "permissions-policy" in headers,
    }
    present_count = sum(1 for v in sec_headers.values() if v)
    score = int((present_count / len(sec_headers)) * 100)
    grade = "A+" if score == 100 else "A" if score >= 80 else "B" if score >= 50 else "C" if score >= 30 else "F"
    return {"score": score, "grade": grade, "details": sec_headers}


async def scrape_target(target_url: str, *args, depth: int = 1, **kwargs) -> dict[str, Any]:
    """Hedef web sitesinde derinlemesine teknoloji, altyapı ve güvenlik taraması yapar."""
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    parsed = urlparse(target_url)
    domain = parsed.netloc

    console.print(f"\n[bold cyan][*] Derin Web Keşfi Başlatılıyor:[/] [yellow]{target_url}[/]")
    console.print("[dim]Teknolojiler, SSL/TLS, Güvenlik Başlıkları ve DNS analiz ediliyor...[/]\n")

    transport = proxy_manager.build_httpx_transport()
    client_kwargs = dict(headers=DEFAULT_HEADERS, follow_redirects=True)
    if transport:
        client_kwargs["transport"] = transport

    result: dict[str, Any] = {
        "url": target_url,
        "domain": domain,
        "title": "",
        "status_code": None,
        "technologies": {},
        "ssl_cert": {},
        "dns_security": {},
        "security_headers": {},
        "meta": {},
        "emails": [],
        "phones": [],
        "social_links": {},
        "endpoints": {"robots_txt": False, "sitemap_xml": False, "security_txt": False},
        "links": {"internal_count": 0, "external_count": 0},
    }

    # Asenkron görevler: HTTP isteği, SSL denetimi, DNS güvenliği
    ssl_task = asyncio.to_thread(inspect_ssl_certificate, domain)
    dns_task = inspect_dns_security(domain)

    async with httpx.AsyncClient(**client_kwargs) as client:
        await global_limiter.acquire()
        try:
            resp = await client.get(target_url, timeout=DEFAULT_TIMEOUT)
            result["status_code"] = resp.status_code

            html = resp.text
            soup = BeautifulSoup(html, "lxml")

            # 1. Başlık & Meta
            title_tag = soup.find("title")
            result["title"] = title_tag.get_text(strip=True) if title_tag else ""
            desc = soup.find("meta", attrs={"name": "description"}) or soup.find("meta", attrs={"property": "og:description"})
            result["meta"]["description"] = desc.get("content", "").strip() if desc else ""

            # 2. Teknolojiler & Güvenlik Başlıkları
            result["technologies"] = detect_technologies(html, resp.headers)
            result["security_headers"] = analyze_security_headers(resp.headers)

            # 3. İletişim & Sosyal Medya
            result["emails"] = sorted(list(set(EMAIL_PATTERN.findall(html))))[:15]
            raw_phones = PHONE_PATTERN.findall(html)
            result["phones"] = sorted(list(set(p.strip() for p in raw_phones if 7 <= len(p.strip()) <= 18)))[:10]

            socials = {}
            for platform, pattern in SOCIAL_PATTERNS.items():
                matches = list(set(pattern.findall(html)))
                if matches:
                    socials[platform] = matches[:3]
            result["social_links"] = socials

            # 4. Link İstatistikleri
            internal, external = set(), set()
            for a in soup.find_all("a", href=True):
                href = urljoin(target_url, a["href"])
                host = urlparse(href).netloc
                if host == domain:
                    internal.add(href)
                elif host:
                    external.add(host)
            result["links"]["internal_count"] = len(internal)
            result["links"]["external_count"] = len(external)

            # 5. Kritik Sistem Yolları Kontrolü (robots.txt vb.)
            async def _check_path(path_suffix: str) -> bool:
                try:
                    r = await client.get(urljoin(target_url, path_suffix), timeout=5.0)
                    return r.status_code == 200
                except Exception:
                    return False

            r_robots, r_sitemap, r_sec = await asyncio.gather(
                _check_path("/robots.txt"),
                _check_path("/sitemap.xml"),
                _check_path("/.well-known/security.txt"),
            )
            result["endpoints"]["robots_txt"] = r_robots
            result["endpoints"]["sitemap_xml"] = r_sitemap
            result["endpoints"]["security_txt"] = r_sec

        except Exception as e:
            result["error"] = str(e)

    # Paralel tamamlanan SSL ve DNS verilerini ekle
    result["ssl_cert"], result["dns_security"] = await asyncio.gather(ssl_task, dns_task)

    _display_recon_results(result)
    return result


def _display_recon_results(data: dict[str, Any]):
    """Sonuçları Rich tablolarıyla profesyonelce sunar."""
    # 1. Genel Özet Tablosu
    summary_table = Table(title=f"Web İstihbaratı: {data.get('domain')}", border_style="#d946ef")
    summary_table.add_column("Parametre", style="bold #ec4899", width=22)
    summary_table.add_column("Bilgi", style="white")

    summary_table.add_row("Site Başlığı", data.get("title") or "—")
    summary_table.add_row("HTTP Durumu", str(data.get("status_code")))

    ssl_info = data.get("ssl_cert", {})
    if ssl_info.get("valid"):
        ssl_str = f"{ssl_info.get('tls_version')} | Sağlayıcı: {ssl_info.get('issuer')} (Bitiş: {ssl_info.get('expires', '')[:11]})"
    else:
        ssl_str = "[red]SSL Hatası / Yok[/red]"
    summary_table.add_row("SSL/TLS Sertifikası", ssl_str)

    sec_hdr = data.get("security_headers", {})
    summary_table.add_row(
        "Güvenlik Başlık Puanı",
        f"[bold magenta]{sec_hdr.get('grade')}[/bold magenta] ({sec_hdr.get('score', 0)}/100)"
    )

    dns_sec = data.get("dns_security", {})
    summary_table.add_row("SPF Kaydı", dns_sec.get("spf", "Yok"))
    summary_table.add_row("DMARC Politikası", dns_sec.get("dmarc", "Yok"))
    if dns_sec.get("mx"):
        summary_table.add_row("E-posta Sunucuları (MX)", ", ".join(dns_sec["mx"]))

    ep = data.get("endpoints", {})
    ep_str = f"robots.txt: {'[+] Var' if ep.get('robots_txt') else '[-] Yok'} | sitemap.xml: {'[+] Var' if ep.get('sitemap_xml') else '[-] Yok'} | security.txt: {'[+] Var' if ep.get('security_txt') else '[-] Yok'}"
    summary_table.add_row("Sistem Dosyaları", ep_str)

    console.print(summary_table)

    # 2. Tespit Edilen Teknolojiler (Full-Stack)
    techs = data.get("technologies", {})
    if techs:
        tech_table = Table(title="Tespit Edilen Teknoloji Yığını (Tech Stack)", border_style="cyan")
        tech_table.add_column("Kategori", style="bold cyan", width=20)
        tech_table.add_column("Kullanılan Teknolojiler & Kütüphaneler", style="white")

        for cat, items in techs.items():
            tech_table.add_row(cat, ", ".join(items))

        console.print(tech_table)
    else:
        console.print("[yellow][-] Belirgin teknoloji imzası tespit edilemedi.[/yellow]")

    # 3. İletişim & Sosyal Medya
    emails = data.get("emails", [])
    phones = data.get("phones", [])
    socials = data.get("social_links", {})

    if emails or phones or socials:
        contact_table = Table(title="İletişim & Sosyal Ağ İzleri", border_style="green")
        contact_table.add_column("Tip", style="bold green", width=18)
        contact_table.add_column("Bulunan Veriler", style="white")

        if emails:
            contact_table.add_row("E-Posta Adresleri", ", ".join(emails))
        if phones:
            contact_table.add_row("Telefon Numaraları", ", ".join(phones))
        if socials:
            soc_text = " | ".join(f"{k}: {', '.join(v)}" for k, v in socials.items())
            contact_table.add_row("Sosyal Profiller", soc_text)

        console.print(contact_table)

    console.print()
