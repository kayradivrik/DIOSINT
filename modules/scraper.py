"""
modules/scraper.py — Profesyonel Asenkron Web İstihbarat Kazıyıcı
================================================================
- E-postalar, telefonlar, sosyal profiller
- Teknoloji tespiti (CMS, web server, analytics, frameworkler)
- Meta etiketleri ve OpenGraph verileri
- Güvenlik başlıkları analizi (HSTS, CSP, X-Frame-Options vb.)
- İç & Dış link haritalandırması
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from config import DEFAULT_HEADERS, DEFAULT_TIMEOUT, console
from utils.proxy_manager import proxy_manager
from utils.rate_limiter import global_limiter

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,7}\b")
PHONE_PATTERN = re.compile(
    r"""(?:(?:\+|00)[\d\s\-\(\)]{7,15}|0[\d\s\-\(\)]{9,14})""",
    re.VERBOSE,
)

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

TECH_SIGNATURES = {
    "WordPress": [re.compile(r"/wp-content/"), re.compile(r"/wp-includes/"), re.compile(r'name="generator" content="WordPress')],
    "Cloudflare": [re.compile(r"cloudflare", re.I)],
    "Bootstrap": [re.compile(r"bootstrap(?:\.min)?\.css")],
    "Tailwind CSS": [re.compile(r"tailwindcss")],
    "React": [re.compile(r"_react", re.I), re.compile(r"react-dom")],
    "Vue.js": [re.compile(r"vue(?:\.min)?\.js"), re.compile(r"v-data-")],
    "Google Analytics": [re.compile(r"googletagmanager\.com/gtag"), re.compile(r"google-analytics\.com/analytics\.js")],
    "jQuery": [re.compile(r"jquery(?:\.min)?\.js")],
}


def detect_technologies(html: str, headers: httpx.Headers) -> list[str]:
    """Sayfa kaynak kodundan ve HTTP başlıklarından kullanılan teknolojileri tespit eder."""
    techs = set()
    server = headers.get("server")
    if server:
        techs.add(f"Server: {server}")
    powered_by = headers.get("x-powered-by")
    if powered_by:
        techs.add(f"Powered-By: {powered_by}")

    for tech_name, patterns in TECH_SIGNATURES.items():
        if any(p.search(html) for p in patterns):
            techs.add(tech_name)
    return sorted(list(techs))


def analyze_security_headers(headers: httpx.Headers) -> dict[str, Any]:
    """Web sitesinin güvenlik başlıklarını puanlar ve denetler."""
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
    return {
        "score": score,
        "grade": "A" if score >= 80 else "B" if score >= 50 else "C" if score >= 30 else "F",
        "details": sec_headers,
    }


def extract_metadata(soup: BeautifulSoup) -> dict[str, str]:
    """Başlık, açıklama ve OpenGraph meta etiketlerini çıkarır."""
    meta = {}
    title_tag = soup.find("title")
    if title_tag:
        meta["title"] = title_tag.get_text(strip=True)

    for tag in soup.find_all("meta"):
        key = tag.get("name") or tag.get("property")
        content = tag.get("content")
        if key and content:
            meta[key.lower()] = content.strip()
    return meta


async def scrape_target(target_url: str, depth: int = 1) -> dict[str, Any]:
    """
    Belirtilen web sitesinde kapsamlı OSINT araştırması yapar.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    transport = proxy_manager.build_httpx_transport()
    client_kwargs = dict(headers=DEFAULT_HEADERS, follow_redirects=True)
    if transport:
        client_kwargs["transport"] = transport

    parsed_base = urlparse(target_url)
    base_domain = parsed_base.netloc

    result: dict[str, Any] = {
        "url": target_url,
        "domain": base_domain,
        "status_code": None,
        "title": "",
        "meta": {},
        "emails": [],
        "phones": [],
        "social_links": {},
        "technologies": [],
        "security": {},
        "internal_links": [],
        "external_links": [],
    }

    async with httpx.AsyncClient(**client_kwargs) as client:
        await global_limiter.acquire()
        try:
            resp = await client.get(target_url, timeout=DEFAULT_TIMEOUT)
            result["status_code"] = resp.status_code
            if resp.status_code != 200:
                result["error"] = f"HTTP {resp.status_code}"
                return result

            html = resp.text
            soup = BeautifulSoup(html, "lxml")

            # 1. Meta & Başlık
            meta_data = extract_metadata(soup)
            result["title"] = meta_data.get("title", "")
            result["meta"] = {
                "description": meta_data.get("description") or meta_data.get("og:description", ""),
                "keywords": meta_data.get("keywords", ""),
                "og_title": meta_data.get("og:title", ""),
                "og_image": meta_data.get("og:image", ""),
            }

            # 2. İletişim & Sosyal Medya
            result["emails"] = sorted(list(set(EMAIL_PATTERN.findall(html))))
            raw_phones = PHONE_PATTERN.findall(html)
            result["phones"] = sorted(list(set(p.strip() for p in raw_phones if 7 <= len(p.strip()) <= 20)))

            socials = {}
            for platform, pattern in SOCIAL_PATTERNS.items():
                matches = list(set(pattern.findall(html)))
                if matches:
                    socials[platform] = matches
            result["social_links"] = socials

            # 3. Teknoloji & Güvenlik
            result["technologies"] = detect_technologies(html, resp.headers)
            result["security"] = analyze_security_headers(resp.headers)

            # 4. Link Analizi
            internal = set()
            external = set()
            for a in soup.find_all("a", href=True):
                href = urljoin(target_url, a["href"])
                domain = urlparse(href).netloc
                if domain == base_domain:
                    internal.add(href)
                elif domain:
                    external.add(domain)

            result["internal_links"] = list(internal)[:30]
            result["external_links"] = list(external)[:30]

        except Exception as e:
            result["error"] = str(e)

    return result
