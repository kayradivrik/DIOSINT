"""
metadata_extractor.py - Image & Media EXIF Forensic Analysis
=============================================================
Extracts EXIF metadata, camera settings, software, and GPS coordinates
from images (JPEG, PNG, TIFF) to assist geolocation intelligence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def _convert_to_degrees(value) -> float | None:
    """EXIF koordinat rasyolarını (DMS) ondalık dereceye (DD) çevirir."""
    try:
        d = float(value[0])
        m = float(value[1])
        s = float(value[2])
        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return None


def _extract_gps(gps_info: dict) -> dict[str, Any]:
    gps_data: dict[str, Any] = {}
    for key, val in gps_info.items():
        sub_name = GPSTAGS.get(key, key)
        gps_data[sub_name] = val

    lat = _convert_to_degrees(gps_data.get("GPSLatitude"))
    lat_ref = gps_data.get("GPSLatitudeRef", "N")
    if lat and lat_ref != "N":
        lat = -lat

    lon = _convert_to_degrees(gps_data.get("GPSLongitude"))
    lon_ref = gps_data.get("GPSLongitudeRef", "E")
    if lon and lon_ref != "E":
        lon = -lon

    result = {}
    if lat is not None and lon is not None:
        result["latitude"] = round(lat, 6)
        result["longitude"] = round(lon, 6)
        result["maps_url"] = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"
        result["earth_url"] = f"https://earth.google.com/web/search/{lat:.6f},{lon:.6f}"

    if "GPSAltitude" in gps_data:
        try:
            result["altitude_meters"] = float(gps_data["GPSAltitude"])
        except Exception:
            pass

    return result


def extract_metadata(file_path: str | Path) -> dict[str, Any]:
    path = Path(file_path)
    if not path.exists():
        console.print(f"[red]Dosya bulunamadı:[/] {file_path}")
        return {"error": "File not found"}

    result: dict[str, Any] = {
        "file_name": path.name,
        "file_size_kb": round(path.stat().st_size / 1024, 2),
        "exif_found": False,
        "metadata": {},
        "gps": {},
    }

    try:
        with Image.open(path) as img:
            result["format"] = img.format
            result["dimensions"] = f"{img.width}x{img.height}"
            result["mode"] = img.mode

            exif = img.getexif()
            if not exif:
                console.print(f"[yellow][-] {path.name} içinde EXIF verisi bulunamadı.[/yellow]")
                return result

            result["exif_found"] = True
            for tag_id, value in exif.items():
                tag_name = TAGS.get(tag_id, tag_id)
                # GPSInfo özel olarak ele alınır
                if tag_name == "GPSInfo" and isinstance(value, dict):
                    result["gps"] = _extract_gps(value)
                elif isinstance(value, (str, int, float)):
                    result["metadata"][str(tag_name)] = str(value).strip()

            # Bazen GPS verisi get_ifd(0x8825) altında saklanır
            if not result["gps"]:
                try:
                    gps_ifd = exif.get_ifd(0x8825)
                    if gps_ifd:
                        result["gps"] = _extract_gps(gps_ifd)
                except Exception:
                    pass

    except Exception as e:
        result["error"] = str(e)
        console.print(f"[red]EXIF ayrıştırma hatası:[/] {e}")
        return result

    _display_metadata(result)
    return result


def _display_metadata(data: dict[str, Any]):
    table = Table(
        title=f"Fotoğraf & EXIF Analizi: {data.get('file_name')}",
        border_style="#d946ef",
    )
    table.add_column("Parametre", style="bold #ec4899", width=22)
    table.add_column("Değer", style="white")

    table.add_row("Format & Çözünürlük", f"{data.get('format')} ({data.get('dimensions')})")
    table.add_row("Dosya Boyutu", f"{data.get('file_size_kb')} KB")

    meta = data.get("metadata", {})
    notable_keys = [
        ("Make", "Cihaz Markası"),
        ("Model", "Cihaz Modeli"),
        ("Software", "İşletim / Yazılım"),
        ("DateTime", "Çekim Tarihi / Saati"),
        ("DateTimeOriginal", "Orijinal Çekim"),
        ("LensModel", "Lens Bilgisi"),
    ]
    for key, label in notable_keys:
        if key in meta:
            table.add_row(label, meta[key])

    console.print(table)

    gps = data.get("gps", {})
    if gps.get("latitude") and gps.get("longitude"):
        gps_text = (
            f"[bold green]Enlem (Lat):[/] {gps['latitude']}\n"
            f"[bold green]Boylam (Lon):[/] {gps['longitude']}\n\n"
            f"[bold cyan]Google Harita:[/] {gps['maps_url']}\n"
            f"[bold cyan]Google Earth:[/] {gps['earth_url']}"
        )
        console.print(Panel(gps_text, title="🛰️ Tespit Edilen GPS Koordinatları", border_style="green"))
    else:
        console.print("[dim][i]Fotoğrafta gömülü GPS konum bilgisi yok.[/i][/dim]\n")
