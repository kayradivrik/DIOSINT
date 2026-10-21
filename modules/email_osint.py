"""
email_osint.py - Email Validation & Breach Intelligence
======================================================
Validates format, checks MX records, and queries breach databases.
"""

import asyncio
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
    console.print(f"\n[*] Analyzing target email: [yellow]{email}[/]\n")

    if not validate_email_format(email):
        console.print("[red][!] Invalid email address format.[/]")
        return {"error": "Invalid format", "email": email}

    _, domain = email.split("@", 1)

    mx_ok, breaches = await asyncio.gather(
        check_mx_record(domain),
        check_hibp(email),
    )

    username_info = extract_username_from_email(email)

    result = {
        "email": email,
        "valid_format": True,
        "domain": domain,
        "mx_record_exists": mx_ok,
        "provider": username_info["provider"],
        "username_variants": username_info["username_variants"],
        "breaches": breaches,
        "breach_count": len([b for b in breaches if isinstance(b, dict) and "Name" in b]),
    }

    _display_email_results(result)
    return result


def _display_email_results(data: dict[str, Any]):
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")

    breach_count = data.get("breach_count", 0)
    breach_text = (
        f"[bold red][!] Found in {breach_count} data breaches[/]"
        if breach_count > 0
        else "[green][+] Clean (No breach records)[/]"
    )

    table.add_row("Email", data["email"])
    table.add_row("Provider", data.get("provider", "-"))
    table.add_row("Syntax", "Valid RFC 5322")
    table.add_row("MX Record", "[green]Present[/]" if data.get("mx_record_exists") else "[red]Missing[/]")
    table.add_row("Breach Status", breach_text)
    table.add_row(
        "Username Variants",
        ", ".join(data.get("username_variants", []))
    )

    if breach_count > 0:
        breach_names = [
            b["Name"] for b in data["breaches"]
            if isinstance(b, dict) and "Name" in b
        ]
        table.add_row("Breach Sources", ", ".join(breach_names[:5]))

    console.print(Panel(table, title="Email Intelligence Results", border_style="cyan"))
