"""
subdomain_recon.py - Passive Subdomain Discovery
================================================
Queries public Certificate Transparency (crt.sh) logs and
HackerTarget to enumerate subdomains without touching target servers.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

import httpx
from rich.console import Console
from rich.table import Table

from config import DEFAULT_HEADERS, DEFAULT_TIMEOUT
from utils.rate_limiter import global_limiter

console = Console()


def _sanitize_domain(target: str) -> str:
    domain = target.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.split(":")[0].strip()


async def query_crtsh(domain: str) -> set[str]:
    """crt.sh üzerinden SSL/TLS sertifika kayıtlarını çeker."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains: set[str] = set()

    await global_limiter.acquire()
    async with httpx.AsyncClient(headers=DEFAULT_HEADERS) as client:
        try:
            resp = await client.get(url, timeout=25.0)
            if resp.status_code == 200:
                data = resp.json()
                for item in data:
                    name_value = item.get("name_value", "")
                    for entry in name_value.split("\n"):
                        entry = entry.strip().lower()
                        if entry.startswith("*."):
                            entry = entry[2:]
                        if entry.endswith(f".{domain}") or entry == domain:
                            subdomains.add(entry)
        except Exception:
            pass
    return subdomains


async def query_hackertarget(domain: str) -> set[str]:
    """HackerTarget pasif DNS API sorgusu."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains: set[str] = set()

    await global_limiter.acquire()
    async with httpx.AsyncClient(headers=DEFAULT_HEADERS) as client:
        try:
            resp = await client.get(url, timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.splitlines():
                    if "," in line:
                        host = line.split(",")[0].strip().lower()
                        if host.endswith(domain):
                            subdomains.add(host)
        except Exception:
            pass
    return subdomains


async def discover_subdomains(target: str) -> dict[str, Any]:
    domain = _sanitize_domain(target)
    console.print(f"\n[bold cyan]🔍 Pasif Subdomain Taraması:[/] [yellow]{domain}[/]")
    console.print("[dim]Certificate Transparency (crt.sh) ve DNS logları taranıyor...[/]\n")

    crt_task = asyncio.create_task(query_crtsh(domain))
    ht_task = asyncio.create_task(query_hackertarget(domain))

    crt_subs, ht_subs = await asyncio.gather(crt_task, ht_task)
    all_subs = sorted(list(crt_subs | ht_subs))

    result = {
        "domain": domain,
        "total": len(all_subs),
        "subdomains": all_subs,
        "sources": {
            "crt_sh_count": len(crt_subs),
            "hackertarget_count": len(ht_subs),
        },
    }

    _display_subdomains(domain, all_subs)
    return result


def _display_subdomains(domain: str, subdomains: list[str]):
    if not subdomains:
        console.print(f"[yellow][-] {domain} için açık sertifika kaydı bulunamadı.[/yellow]\n")
        return

    table = Table(
        title=f"Alt Alan Adları (Subdomains) — {domain} ({len(subdomains)} adet)",
        border_style="#d946ef",
    )
    table.add_column("No", style="bold #ec4899", width=6)
    table.add_column("Subdomain", style="white")

    for i, sub in enumerate(subdomains, 1):
        table.add_row(str(i), sub)

    console.print(table)
    console.print(f"\n[green]Toplam {len(subdomains)} benzersiz alt alan adı tespit edildi.[/green]\n")
