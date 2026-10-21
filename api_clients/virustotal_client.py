"""
virustotal_client.py - VirusTotal v3 API Client
===============================================
Queries VirusTotal for domains, URLs, IPs, and file hashes.
"""

from typing import Any
import base64
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import DEFAULT_TIMEOUT, VIRUSTOTAL_API_KEY
from utils.rate_limiter import global_limiter

console = Console()
VT_BASE = "https://www.virustotal.com/api/v3"


async def analyze_url(url: str) -> dict[str, Any]:
    """Analyzes a URL using VirusTotal v3 API."""
    if not VIRUSTOTAL_API_KEY:
        console.print("[!] VIRUSTOTAL_API_KEY not configured in .env")
        return {"error": "API key missing"}

    await global_limiter.acquire()
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(headers=headers) as client:
        try:
            resp = await client.get(f"{VT_BASE}/urls/{url_id}", timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 200:
                return _parse_vt_result(resp.json(), url, "url")
            elif resp.status_code == 404:
                return await _submit_url(client, url)
            return {"error": f"HTTP {resp.status_code}"}
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.ConnectError:
            return {"error": "Connection error to VirusTotal"}
        except Exception as e:
            return {"error": str(e)}


async def _submit_url(client: httpx.AsyncClient, url: str) -> dict[str, Any]:
    """Submits a URL to VirusTotal for analysis if not previously scanned."""
    try:
        resp = await client.post(
            f"{VT_BASE}/urls",
            data={"url": url},
            timeout=DEFAULT_TIMEOUT,
        )
        if resp.status_code == 200:
            return {"status": "submitted", "message": "URL submitted. Retry in a few moments."}
        return {"error": f"Submission failed: HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


async def analyze_domain(domain: str) -> dict[str, Any]:
    """Queries reputation and detection data for a domain."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "API key missing"}

    await global_limiter.acquire()
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    async with httpx.AsyncClient(headers=headers) as client:
        try:
            resp = await client.get(
                f"{VT_BASE}/domains/{domain}",
                timeout=DEFAULT_TIMEOUT,
            )
            if resp.status_code == 200:
                result = _parse_vt_result(resp.json(), domain, "domain")
                _display_vt_results(result)
                return result
            return {"error": f"HTTP {resp.status_code}"}
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except Exception as e:
            return {"error": str(e)}


def _parse_vt_result(data: dict, target: str, target_type: str) -> dict[str, Any]:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    
    return {
        "target": target,
        "type": target_type,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation", 0),
        "categories": attrs.get("categories", {}),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "tags": attrs.get("tags", []),
    }


def _display_vt_results(data: dict):
    malicious = data.get("malicious", 0)
    suspicious = data.get("suspicious", 0)

    verdict = (
        "[bold red][!] MALICIOUS[/]" if malicious > 0
        else "[bold yellow][?] SUSPICIOUS[/]" if suspicious > 0
        else "[bold green][+] CLEAN[/]"
    )

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")

    table.add_row("Target", data.get("target", ""))
    table.add_row("Verdict", verdict)
    table.add_row("Malicious Engines", str(malicious))
    table.add_row("Suspicious Engines", str(suspicious))
    table.add_row("Clean Engines", str(data.get("harmless", 0)))
    table.add_row("Reputation Score", str(data.get("reputation", 0)))

    if data.get("tags"):
        table.add_row("Tags", ", ".join(data["tags"]))

    console.print(Panel(table, title="VirusTotal Results", border_style="red" if malicious > 0 else "green"))
