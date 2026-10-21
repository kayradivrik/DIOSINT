"""
darkweb.py - Tor Hidden Services Search Module
==============================================
Queries Ahmia indexing engine for .onion services.
"""

import httpx
from rich.console import Console
from rich.table import Table
from bs4 import BeautifulSoup

from config import DEFAULT_HEADERS, DEFAULT_TIMEOUT
from utils.proxy_manager import proxy_manager

console = Console()


async def search_darkweb(query: str):
    console.print(f"\n[*] Dark web query: [yellow]{query}[/]")
    url = f"https://ahmia.fi/search/?q={query}"
    
    transport = proxy_manager.build_httpx_transport()
    client_kwargs = {"headers": DEFAULT_HEADERS, "follow_redirects": True}
    if transport:
        client_kwargs["transport"] = transport

    async with httpx.AsyncClient(**client_kwargs) as client:
        try:
            resp = await client.get(url, timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 200:
                return _parse_ahmia_results(resp.text)
            else:
                console.print(f"[red][!] Ahmia returned HTTP {resp.status_code}[/]")
                return []
        except httpx.TimeoutException:
            console.print("[red][!] Request to Tor gateway timed out[/]")
            return []
        except Exception as e:
            console.print(f"[red][!] Connection error: {e}[/]")
            return []


def _parse_ahmia_results(html_text: str):
    soup = BeautifulSoup(html_text, "lxml")
    results = []
    
    for li in soup.select("li.result"):
        title_el = li.select_one("a")
        snippet_el = li.select_one("p")
        if title_el:
            results.append({
                "title": title_el.get_text(strip=True),
                "url": title_el["href"].replace("/search/redirect?search_result=", ""),
                "snippet": snippet_el.get_text(strip=True) if snippet_el else ""
            })
    
    _display_darkweb_results(results)
    return results


def _display_darkweb_results(results: list):
    if not results:
        console.print("[yellow][-] No matching onion indices found.[/]")
        return

    table = Table(title="Tor (.onion) Search Results", show_header=True, header_style="bold magenta")
    table.add_column("Title", style="cyan")
    table.add_column("Onion URL", style="dim")
    
    for r in results[:10]:
        table.add_row(r["title"][:50], r["url"])
    
    console.print(table)
