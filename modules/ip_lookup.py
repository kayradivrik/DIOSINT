"""
ip_lookup.py - IP & Domain Network Intelligence
================================================
Queries IP geolocation, Autonomous System (ASN), ISP, and PTR reverse DNS.
"""

import asyncio
import socket
from typing import Any

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import DEFAULT_HEADERS, DEFAULT_TIMEOUT
from utils.rate_limiter import global_limiter

console = Console()
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting,query"


async def get_ip_geolocation(ip_or_domain: str) -> dict[str, Any]:
    """Queries geolocation metadata for given IP or domain."""
    await global_limiter.acquire()
    url = IP_API_URL.format(ip=ip_or_domain)
    async with httpx.AsyncClient(headers=DEFAULT_HEADERS) as client:
        try:
            resp = await client.get(url, timeout=DEFAULT_TIMEOUT)
            return resp.json()
        except httpx.TimeoutException:
            return {"status": "fail", "message": "Request timed out"}
        except Exception as e:
            return {"status": "fail", "message": str(e)}


async def get_reverse_dns(ip: str) -> str:
    """Performs PTR reverse DNS lookup on IP address."""
    try:
        loop = asyncio.get_event_loop()
        hostname, *_ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return hostname
    except socket.herror:
        return "None"
    except Exception as e:
        return f"Error: {e}"


async def resolve_domain(domain: str) -> list[str]:
    """Resolves hostname to IPv4/IPv6 addresses."""
    try:
        loop = asyncio.get_event_loop()
        info = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(domain, None),
        )
        return list({item[4][0] for item in info})
    except socket.gaierror:
        return []
    except Exception:
        return []


async def lookup_ip(target: str) -> dict[str, Any]:
    """Entry point for IP intelligence analysis."""
    is_domain = not all(c.isdigit() or c == "." for c in target.strip())
    resolved_ips = []

    if is_domain:
        resolved_ips = await resolve_domain(target)
        lookup_target = resolved_ips[0] if resolved_ips else target
    else:
        lookup_target = target

    geo_data, rev_dns = await asyncio.gather(
        get_ip_geolocation(lookup_target),
        get_reverse_dns(lookup_target),
    )

    result = {
        "target": target,
        "is_domain": is_domain,
        "resolved_ips": resolved_ips,
        "query_ip": lookup_target,
        "reverse_dns": rev_dns,
        "geolocation": geo_data if geo_data.get("status") == "success" else {},
    }

    _display_ip_results(result)
    return result


def _display_ip_results(data: dict[str, Any]) -> None:
    geo = data.get("geolocation", {})

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="white")

    fields = [
        ("Target", data.get("target")),
        ("Country", f"{geo.get('country', '-')} ({geo.get('countryCode', '-')})"),
        ("City", f"{geo.get('city', '-')}, {geo.get('regionName', '-')}"),
        ("Postal Code", geo.get("zip", "-")),
        ("Timezone", geo.get("timezone", "-")),
        ("ISP", geo.get("isp", "-")),
        ("Organization", geo.get("org", "-")),
        ("ASN", geo.get("as", "-")),
        ("Reverse DNS", data.get("reverse_dns", "-")),
        ("Mobile Carrier", "Yes" if geo.get("mobile") else "No"),
        ("Proxy / VPN", "[bold red]YES[/]" if geo.get("proxy") else "No"),
        ("Hosting Datacenter", "Yes" if geo.get("hosting") else "No"),
        ("Coordinates", f"{geo.get('lat', '-')}, {geo.get('lon', '-')}"),
    ]

    for label, value in fields:
        table.add_row(label, str(value) if value else "-")

    console.print(Panel(table, title="Network & IP Geolocation Results", border_style="cyan"))


def to_dict_list(data: dict[str, Any]) -> list[dict]:
    geo = data.get("geolocation", {})
    results = []
    if data.get("target"):
        results.append({
            "source": "ip_lookup",
            "type": "ip",
            "value": data["target"],
            "context": {
                "country": geo.get("country"),
                "city": geo.get("city"),
                "isp": geo.get("isp"),
                "proxy": geo.get("proxy"),
                "reverse_dns": data.get("reverse_dns"),
            },
        })
    return results
