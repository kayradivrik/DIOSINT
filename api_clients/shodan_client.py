"""
api_clients/shodan_client.py — Shodan API İstemcisi
====================================================
Shodan, internet'e bağlı cihazları indexleyen bir arama motorudur.
API key: https://account.shodan.io/ adresinden ücretsiz hesap açılabilir.

Eğitim Notu: Shodan ile yalnızca kamuya açık cihazları araştırabilirsiniz.
"""

from __future__ import annotations

from typing import Any

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import DEFAULT_TIMEOUT, SHODAN_API_KEY
from utils.rate_limiter import global_limiter

console = Console()

SHODAN_BASE = "https://api.shodan.io"


async def search_shodan(query: str, limit: int = 10) -> dict[str, Any]:
    """
    Shodan'da arama yapar.
    
    Args:
        query : Shodan sorgu dili (örn. "apache country:TR")
        limit : Döndürülecek maksimum sonuç sayısı
    
    Returns:
        Arama sonuçları
    """
    if not SHODAN_API_KEY:
        console.print("[yellow]⚠️  SHODAN_API_KEY tanımlı değil. .env dosyasını düzenleyin.[/]")
        return {"error": "API key eksik"}

    await global_limiter.acquire()

    params = {
        "key": SHODAN_API_KEY,
        "query": query,
        "minify": "true",
    }

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"{SHODAN_BASE}/shodan/host/search",
                params=params,
                timeout=DEFAULT_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                results = _parse_shodan_results(data, limit)
                _display_shodan_results(query, results, data.get("total", 0))
                return {"query": query, "total": data.get("total", 0), "results": results}
            elif resp.status_code == 401:
                console.print("[red]❌ Shodan API key geçersiz.[/]")
                return {"error": "Geçersiz API key"}
            else:
                return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as e:
            return {"error": str(e)}


async def get_host_info(ip: str) -> dict[str, Any]:
    """Belirli bir IP adresi hakkında Shodan'dan detaylı bilgi alır."""
    if not SHODAN_API_KEY:
        return {"error": "API key eksik"}

    await global_limiter.acquire()

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"{SHODAN_BASE}/shodan/host/{ip}",
                params={"key": SHODAN_API_KEY},
                timeout=DEFAULT_TIMEOUT,
            )
            if resp.status_code == 200:
                return resp.json()
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}


def _parse_shodan_results(data: dict, limit: int) -> list[dict]:
    matches = data.get("matches", [])[:limit]
    return [
        {
            "ip":           m.get("ip_str", ""),
            "port":         m.get("port"),
            "org":          m.get("org", ""),
            "country":      m.get("location", {}).get("country_name", ""),
            "city":         m.get("location", {}).get("city", ""),
            "product":      m.get("product", ""),
            "version":      m.get("version", ""),
            "cpe":          m.get("cpe", []),
            "vulns":        list(m.get("vulns", {}).keys()),
            "timestamp":    m.get("timestamp", ""),
        }
        for m in matches
    ]


def _display_shodan_results(query: str, results: list, total: int):
    table = Table(
        title=f"🔍 Shodan: \"{query}\" — {total} toplam sonuç",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("IP", style="cyan")
    table.add_column("Port", justify="center")
    table.add_column("Ürün")
    table.add_column("Org")
    table.add_column("Ülke")
    table.add_column("CVE'ler", style="red")

    for r in results:
        table.add_row(
            r["ip"],
            str(r["port"]),
            f"{r['product']} {r['version']}".strip() or "—",
            r["org"] or "—",
            r["country"] or "—",
            ", ".join(r["vulns"][:3]) if r["vulns"] else "—",
        )

    console.print(table)
