"""
main.py - OSINT Araci CLI Giris Noktasi
=========================================
Typer tabanli komut satiri arayuzu.
Rich ile renkli, profesyonel terminal ciktilari.

Kullanim:
    python -X utf8 main.py --help
    python -X utf8 main.py username --target johndoe --output json
    python -X utf8 main.py ip --target 8.8.8.8
    python -X utf8 main.py email --target test@example.com
    python -X utf8 main.py scrape --target https://example.com
    python -X utf8 main.py shodan --query "apache country:TR"
    python -X utf8 main.py vt --target google.com
"""

from __future__ import annotations

import sys
import io
import os
import asyncio
from pathlib import Path
from typing import Optional

# Force UTF-8 on Windows terminals
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import typer
from rich.console import Console
from rich.panel import Panel

# ── App Setup ──────────────────────────────────────────────────────────────

app = typer.Typer(
    name="diosint",
    help="Diosint — Enterprise OSINT Platformu",
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()

BANNER = r"""
[bold cyan]
 ____  _           _       _   
|  _ \(_) ___  ___(_)_ __ | |_ 
| | | | |/ _ \/ __| | '_ \| __|
| |_| | | (_) \__ \ | | | | |_ 
|____/|_|\___/|___/_|_| |_|\__|
[/bold cyan]
[dim]  Diosint Intelligence Engine v2.0  |  Enterprise OSINT[/dim]
[bold red]!! YALNIZCA EGITIM & ETIK GUVENLIK ARASTIRMASI ICINDIR !![/bold red]
"""


def print_banner():
    console.print(BANNER)
    from utils.proxy_manager import proxy_manager
    console.print(f"[dim]Proxy: {proxy_manager.status()}[/dim]\n")


def _save_and_notify(data, module_name: str, target: str, output: str):
    if output in ("json", "csv", "both"):
        from utils.output_handler import save_report
        path = save_report(
            data if isinstance(data, list) else [data],
            module_name=module_name,
            target=target,
            fmt=output,
        )
        console.print(f"\n[bold green]Rapor kaydedildi:[/] {path}")


def _is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ── Commands ───────────────────────────────────────────────────────────────

@app.command(name="username", help="Kullanici adini 15+ platformda ara")
def cmd_username(
    target: str = typer.Option(..., "--target", "-t", help="Aranacak kullanici adi"),
    output: str = typer.Option("json", "--output", "-o", help="json | csv | both | none"),
):
    print_banner()
    from modules.username_lookup import lookup_username, display_results, to_dict_list
    results = asyncio.run(lookup_username(target))
    display_results(results)
    if output != "none":
        _save_and_notify(to_dict_list(results), "username", target, output)


@app.command(name="ip", help="IP adresi veya domain analizi")
def cmd_ip(
    target: str = typer.Option(..., "--target", "-t", help="IP adresi veya domain"),
    output: str = typer.Option("json", "--output", "-o", help="Cikti formati"),
    shodan: bool = typer.Option(False, "--shodan", help="Shodan'dan ek bilgi al"),
):
    print_banner()
    from modules.ip_lookup import lookup_ip, to_dict_list
    data = asyncio.run(lookup_ip(target))
    if shodan:
        from api_clients.shodan_client import get_host_info
        console.print("\n[bold]Shodan sorgulanıyor...[/]")
        ip = data.get("resolved_ips", [target])[0] if not _is_ip(target) else target
        data["shodan"] = asyncio.run(get_host_info(ip))
    if output != "none":
        _save_and_notify(to_dict_list(data), "ip", target, output)


@app.command(name="email", help="E-posta OSINT analizi ve sizinti kontrolu")
def cmd_email(
    target: str = typer.Option(..., "--target", "-t", help="E-posta adresi"),
    output: str = typer.Option("json", "--output", "-o", help="Cikti formati"),
):
    print_banner()
    from modules.email_osint import analyze_email
    result = asyncio.run(analyze_email(target))
    if output != "none":
        _save_and_notify(result, "email", target, output)


@app.command(name="phone", help="Telefon numarasi analizi")
def cmd_phone(
    target: str = typer.Option(..., "--target", "-t", help="Telefon numarasi (orn: +905...)"),
    output: str = typer.Option("json", "--output", "-o", help="Cikti formati"),
):
    print_banner()
    from modules.phone_lookup import analyze_phone
    result = analyze_phone(target)
    if output != "none":
        _save_and_notify(result, "phone", target, output)


@app.command(name="scrape", help="Web sitesinin framework, teknoloji, SSL ve iletisim izlerini analiz et")
def cmd_scrape(
    target: str = typer.Option(..., "--target", "-t", help="Hedef URL veya Domain"),
    output: str = typer.Option("json", "--output", "-o", help="Cikti formati"),
):
    print_banner()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    from modules.scraper import scrape_target
    result = asyncio.run(scrape_target(target))
    if output != "none":
        _save_and_notify(result, "web_recon", target, output)


@app.command(name="shodan", help="Shodan'da cihaz/servis ara")
def cmd_shodan(
    query: str = typer.Option(..., "--query", "-q", help="Shodan sorgusu"),
    limit: int = typer.Option(10, "--limit", "-l", help="Sonuc sayisi"),
    output: str = typer.Option("json", "--output", "-o", help="Cikti formati"),
):
    print_banner()
    from api_clients.shodan_client import search_shodan
    result = asyncio.run(search_shodan(query, limit))
    if output != "none" and "error" not in result:
        _save_and_notify(result.get("results", []), "shodan", query, output)


@app.command(name="vt", help="VirusTotal ile URL/domain analizi")
def cmd_virustotal(
    target: str = typer.Option(..., "--target", "-t", help="URL veya domain"),
    target_type: str = typer.Option("domain", "--type", help="domain | url"),
    output: str = typer.Option("json", "--output", "-o", help="Cikti formati"),
):
    print_banner()
    from api_clients.virustotal_client import analyze_url, analyze_domain
    if target_type == "url":
        if not target.startswith("http"):
            target = "https://" + target
        result = asyncio.run(analyze_url(target))
    else:
        result = asyncio.run(analyze_domain(target))
    if output != "none" and "error" not in result:
        _save_and_notify(result, "virustotal", target, output)


@app.command(name="darkweb", help="Dark Web'de (Ahmia) arama yap")
def cmd_darkweb(
    query: str = typer.Option(..., "--query", "-q", help="Aranacak kelime/tag"),
):
    print_banner()
    from modules.darkweb import search_darkweb
    asyncio.run(search_darkweb(query))


@app.command(name="geoint", help="Koordinatlardan adres ve uydu bilgisi al")
def cmd_geoint(
    lat: str = typer.Option(..., "--lat", help="Enlem (Latitude)"),
    lon: str = typer.Option(..., "--lon", help="Boylam (Longitude)"),
):
    print_banner()
    from modules.geoint import lookup_coords
    asyncio.run(lookup_coords(lat, lon))


@app.command(name="map", help="Toplanan verileri ag haritasina donustur")
def cmd_map(
    input_files: list[Path] = typer.Argument(..., help="JSON rapor dosyalari"),
    output_format: str = typer.Option("html", "--format", "-f", help="html | png | both"),
    name: str = typer.Option("network_map", "--name", "-n", help="Cikti dosyasi adi"),
):
    print_banner()
    from modules.network_mapper import (
        build_network, export_interactive_html,
        export_static_graph, print_graph_stats,
    )
    from utils.output_handler import load_report
    all_data = []
    for path in input_files:
        if not path.exists():
            console.print(f"[red]Dosya bulunamadi: {path}[/]")
            continue
        report = load_report(path)
        results = report.get("results", [])
        all_data.extend(results if isinstance(results, list) else [results])
    if not all_data:
        console.print("[red]Islenecek veri bulunamadi.[/]")
        raise typer.Exit(1)
    console.print(f"\n[cyan]{len(all_data)} kayit yuklendi, ag olusturuluyor...[/]")
    G = build_network(all_data)
    print_graph_stats(G)
    if output_format in ("html", "both"):
        export_interactive_html(G, name)
    if output_format in ("png", "both"):
        export_static_graph(G, name)


@app.command(name="subdomains", help="crt.sh ve DNS loglarindan pasif subdomain kesfi")
def cmd_subdomains(
    target: str = typer.Option(..., "--target", "-t", help="Hedef Domain"),
    output: str = typer.Option("json", "--output", "-o", help="Cikti formati"),
):
    print_banner()
    from modules.subdomain_recon import discover_subdomains
    result = asyncio.run(discover_subdomains(target))
    if output != "none":
        _save_and_notify(result, "subdomains", target, output)


@app.command(name="exif", help="Gorsel dosyasindan EXIF ve GPS cikarimi")
def cmd_exif(
    file: Path = typer.Option(..., "--file", "-f", help="Gorsel dosya yolu"),
    output: str = typer.Option("json", "--output", "-o", help="Cikti formati"),
):
    print_banner()
    from modules.metadata_extractor import extract_metadata
    result = extract_metadata(file)
    if output != "none" and result.get("exif_found"):
        _save_and_notify(result, "exif", file.stem, output)


@app.command(name="clean", help="Rapor klasorunu temizle")
def cmd_clean(
    confirm: bool = typer.Option(False, "--yes", "-y", help="Onaysiz temizle"),
):
    from config import REPORTS_DIR
    files = list(REPORTS_DIR.glob("*"))
    if not files:
        console.print("[dim]Temizlenecek rapor yok.[/]")
        return
    if not confirm:
        answer = typer.confirm(f"{len(files)} rapor dosyasi silinecek. Emin misiniz?")
        if not answer:
            raise typer.Abort()
    for f in files:
        f.unlink()
    console.print(f"[green]{len(files)} rapor dosyasi silindi.[/]")


# ── Entry Point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
