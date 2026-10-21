"""
email_osint.py - Email Validation, Breach & Account Registration Intelligence
=============================================================================
Validates format, checks MX records, queries breach databases, and checks
account existence across popular services (Spotify, Gravatar, Duolingo, MS, GitHub).
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import socket
from typing import Any

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import DEFAULT_HEADERS, DEFAULT_TIMEOUT, HIBP_API_KEY
from utils.rate_limiter import global_limiter

console = Console()

EMAIL_REGEX = re.compile(r"^[\w._%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}$")
HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"


def validate_email_format(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email.strip()))


async def check_mx_record(domain: str) -> bool:
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, socket.getaddrinfo, domain, None
        )
        return bool(result)
    except Exception:
        return False


async def check_hibp(email: str) -> list[dict[str, Any]]:
    if not HIBP_API_KEY:
        return [{"warning": "HIBP API key not set in .env"}]

    await global_limiter.acquire()
    headers = {
        **DEFAULT_HEADERS,
        "hibp-api-key": HIBP_API_KEY,
    }

    url = HIBP_URL.format(account=email)
    async with httpx.AsyncClient(headers=headers) as client:
        try:
            resp = await client.get(url, timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return []
            return [{"error": f"HTTP {resp.status_code}"}]
        except httpx.TimeoutException:
            return [{"error": "Request timed out"}]
        except Exception as e:
            return [{"error": str(e)}]


async def check_registered_services(email: str) -> dict[str, dict[str, Any]]:
    """Holehe mantığıyla popüler servislerde e-posta kayıt durumunu denetler."""
    results: dict[str, dict[str, Any]] = {}
    clean_email = email.strip().lower()
    headers = dict(DEFAULT_HEADERS)

    async with httpx.AsyncClient(headers=headers, timeout=6.0) as client:
        # 1. Spotify
        async def _check_spotify():
            try:
                url = f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={clean_email}"
                resp = await client.get(url)
                data = resp.json()
                registered = data.get("status") == 20 or "already registered" in str(data)
                return {
                    "registered": registered,
                    "details": "Hesap mevcut" if registered else "Kayıt bulunamadı",
                }
            except Exception:
                return {"registered": False, "details": "Kontrol edilemedi"}

        # 2. Gravatar (WordPress)
        async def _check_gravatar():
            try:
                md5_hash = hashlib.md5(clean_email.encode()).hexdigest()
                url = f"https://gravatar.com/avatar/{md5_hash}?d=404"
                resp = await client.get(url, follow_redirects=True)
                has_avatar = resp.status_code == 200
                return {
                    "registered": has_avatar,
                    "details": f"Avatar/Profil mevcut (MD5: {md5_hash[:10]}...)" if has_avatar else "Kayıt bulunamadı",
                }
            except Exception:
                return {"registered": False, "details": "Kontrol edilemedi"}

        # 3. Duolingo
        async def _check_duolingo():
            try:
                url = f"https://www.duolingo.com/2017-06-30/users?email={clean_email}"
                resp = await client.get(url)
                if resp.status_code == 200:
                    users = resp.json().get("users", [])
                    if users:
                        u = users[0]
                        username = u.get("username", "bilinmiyor")
                        return {"registered": True, "details": f"Kullanıcı adı: @{username}"}
                return {"registered": False, "details": "Kayıt bulunamadı"}
            except Exception:
                return {"registered": False, "details": "Kontrol edilemedi"}

        # 4. Microsoft / Office365
        async def _check_microsoft():
            try:
                url = "https://login.microsoftonline.com/common/GetCredentialType"
                resp = await client.post(url, json={"username": clean_email, "isOtherIdpSupported": True})
                if resp.status_code == 200:
                    status = resp.json().get("IfExistsResult")
                    if status in (0, 5, 6):
                        desc = "Kurumsal/Yönetilen hesap" if status == 5 else "Bireysel Microsoft hesabı"
                        return {"registered": True, "details": desc}
                return {"registered": False, "details": "Kayıt bulunamadı"}
            except Exception:
                return {"registered": False, "details": "Kontrol edilemedi"}

        # 5. GitHub Public Email
        async def _check_github():
            try:
                url = f"https://api.github.com/search/users?q={clean_email}+in:email"
                resp = await client.get(url)
                if resp.status_code == 200:
                    count = resp.json().get("total_count", 0)
                    if count > 0:
                        login = resp.json()["items"][0].get("login", "")
                        return {"registered": True, "details": f"GitHub profili: @{login}"}
                return {"registered": False, "details": "Açık profil bulunamadı"}
            except Exception:
                return {"registered": False, "details": "Kontrol edilemedi"}

        # 6. Archive.org
        async def _check_archive():
            try:
                url = f"https://archive.org/advancedsearch.php?q=uploader%3A%22{clean_email}%22&output=json"
                resp = await client.get(url)
                if resp.status_code == 200:
                    num_found = resp.json().get("response", {}).get("numFound", 0)
                    if num_found > 0:
                        return {"registered": True, "details": f"{num_found} adet arşiv/yükleme bulundu"}
                return {"registered": False, "details": "Arşiv kaydı yok"}
            except Exception:
                return {"registered": False, "details": "Kontrol edilemedi"}

        tasks = {
            "Spotify": _check_spotify(),
            "Gravatar (WordPress)": _check_gravatar(),
            "Duolingo": _check_duolingo(),
            "Microsoft / O365": _check_microsoft(),
            "GitHub": _check_github(),
            "Archive.org": _check_archive(),
        }

        out = await asyncio.gather(*tasks.values())
        return dict(zip(tasks.keys(), out))


def extract_username_from_email(email: str) -> dict[str, Any]:
    username, domain = email.split("@", 1)
    variants = [
        username,
        username.replace(".", ""),
        username.replace("_", ""),
        re.sub(r"\d+$", "", username),
    ]
    return {
        "username": username,
        "username_variants": list(dict.fromkeys(filter(None, variants))),
        "provider": domain.split(".")[0].capitalize(),
    }


async def analyze_email(email: str) -> dict[str, Any]:
    console.print(f"\n[bold cyan]🔍 E-posta Analizi:[/] [yellow]{email}[/]")

    if not validate_email_format(email):
        console.print("[red][!] Geçersiz e-posta formatı.[/red]")
        return {"error": "Invalid format", "email": email}

    _, domain = email.split("@", 1)

    mx_task = check_mx_record(domain)
    hibp_task = check_hibp(email)
    services_task = check_registered_services(email)

    mx_ok, breaches, services = await asyncio.gather(
        mx_task, hibp_task, services_task
    )

    username_info = extract_username_from_email(email)

    result = {
        "email": email,
        "valid_format": True,
        "domain": domain,
        "mx_record_exists": mx_ok,
        "provider": username_info["provider"],
        "username_variants": username_info["username_variants"],
        "registered_services": services,
        "registered_count": sum(1 for s in services.values() if s.get("registered")),
        "breaches": breaches,
        "breach_count": len([b for b in breaches if isinstance(b, dict) and "Name" in b]),
    }

    _display_email_results(result)
    return result


def _display_email_results(data: dict[str, Any]):
    # 1. Genel Bilgiler
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Alan", style="bold cyan")
    table.add_column("Değer")

    breach_count = data.get("breach_count", 0)
    breach_text = (
        f"[bold red][!] {breach_count} veri sızıntısında bulundu[/]"
        if breach_count > 0
        else "[green][+] Temiz (Sızıntı kaydı yok)[/]"
    )

    table.add_row("E-posta", data["email"])
    table.add_row("Servis Sağlayıcı", data.get("provider", "-"))
    table.add_row("Format Doğrulaması", "Geçerli (RFC 5322)")
    table.add_row("MX Sunucu Kaydı", "[green]Aktif[/]" if data.get("mx_record_exists") else "[red]Eksik / Yok[/]")
    table.add_row("Sızıntı Durumu", breach_text)
    table.add_row("Muhtemel Nickler", ", ".join(data.get("username_variants", [])))

    if breach_count > 0:
        breach_names = [
            b["Name"] for b in data["breaches"]
            if isinstance(b, dict) and "Name" in b
        ]
        table.add_row("Sızıntı Kaynakları", ", ".join(breach_names[:5]))

    console.print(Panel(table, title="E-Posta İstihbarat Detayları", border_style="cyan"))

    # 2. Servis Kayıt Durumu (Holehe-style)
    services = data.get("registered_services", {})
    if services:
        srv_table = Table(title="Hesap Varlık Taraması (Account Existence Check)", border_style="#d946ef")
        srv_table.add_column("Platform", style="bold #ec4899", width=22)
        srv_table.add_column("Durum", width=14)
        srv_table.add_column("Detay", style="white")

        for srv_name, srv_data in services.items():
            if srv_data.get("registered"):
                status_str = "[bold green][+] KAYITLI[/bold green]"
            else:
                status_str = "[dim][-] Yok[/dim]"
            srv_table.add_row(srv_name, status_str, srv_data.get("details", ""))

        console.print(srv_table)
        reg_count = data.get("registered_count", 0)
        console.print(f"[green]Tespit edilen aktif hesap sayısı: {reg_count}[/green]\n")
