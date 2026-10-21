"""
geoint.py - Geolocation Intelligence Module
===========================================
Reverse geocodes latitude/longitude coordinates to physical address
using OpenStreetMap Nominatim API.
"""

import httpx
from rich.console import Console
from rich.panel import Panel
from config import DEFAULT_HEADERS

console = Console()


async def lookup_coords(lat: str, lon: str):
    console.print(f"\n[*] Resolving coordinates: [yellow]{lat}, {lon}[/]")
    url = f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json"
    
    async with httpx.AsyncClient(headers=DEFAULT_HEADERS) as client:
        try:
            resp = await client.get(url, timeout=10.0)
            data = resp.json()
            address = data.get("display_name", "No address record found")
            
            maps_link = f"https://www.google.com/maps?q={lat},{lon}"
            satellite = f"https://www.google.com/maps/@{lat},{lon},18z/data=!3m1!1e3"
            
            console.print(Panel(
                f"[bold]Resolved Address:[/] {address}\n\n"
                f"[bold]Google Maps:[/] {maps_link}\n"
                f"[bold]Satellite View:[/] {satellite}",
                title="GEOINT Results",
                border_style="green"
            ))
            return data
        except httpx.TimeoutException:
            console.print("[red][!] Nominatim request timed out[/]")
            return {}
        except Exception as e:
            console.print(f"[red][!] Error: {e}[/]")
            return {}
