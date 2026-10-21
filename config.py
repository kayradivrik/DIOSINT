"""
config.py — Merkezi Konfigürasyon
==================================
API anahtarları ve genel ayarlar .env dosyasından yüklenir.
Asla API anahtarlarınızı bu dosyaya doğrudan yazmayın!
"""

import os
import sys
import io
from pathlib import Path
from dotenv import load_dotenv

# Windows console encoding fix for Unicode & Emojis
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
if sys.platform == "win32":
    # On Windows, wrap standard streams in UTF-8 TextIOWrapper with errors='replace' to never fail with charmap
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        pass
    console = Console(file=sys.stdout, force_terminal=False, highlight=False, legacy_windows=False)
else:
    console = Console()

BASE_DIR = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# ─── API Anahtarları ─────────────────────────────────────────────────────────
SHODAN_API_KEY       = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY   = os.getenv("VIRUSTOTAL_API_KEY", "")
HIBP_API_KEY         = os.getenv("HIBP_API_KEY", "")

# ─── HTTP Ayarları ───────────────────────────────────────────────────────────
DEFAULT_TIMEOUT      = 15           # saniye
DEFAULT_RETRIES      = 3
RATE_LIMIT_DELAY     = 1.5          # istekler arası bekleme (saniye)
MAX_CONCURRENT       = 10           # eş zamanlı async istek sayısı

# ─── Proxy Ayarları ──────────────────────────────────────────────────────────
USE_TOR              = os.getenv("USE_TOR", "false").lower() == "true"
TOR_SOCKS_PROXY      = "socks5h://127.0.0.1:9050"
PROXY_LIST_FILE      = BASE_DIR / "proxies.txt"   # opsiyonel proxy listesi

# ─── User-Agent ──────────────────────────────────────────────────────────────
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

# ─── Kullanıcı adı kontrol edilecek platformlar (40+ Platform, Kategorize) ─────────
USERNAME_PLATFORMS = {
    # Geliştirici & Kodlama
    "GitHub":        {"url": "https://github.com/{username}", "cat": "Geliştirici"},
    "GitLab":        {"url": "https://gitlab.com/{username}", "cat": "Geliştirici"},
    "HackerNews":    {"url": "https://news.ycombinator.com/user?id={username}", "cat": "Geliştirici"},
    "StackOverflow": {"url": "https://stackoverflow.com/users/{username}", "cat": "Geliştirici"},
    "Codeforces":    {"url": "https://codeforces.com/profile/{username}", "cat": "Geliştirici"},
    "LeetCode":      {"url": "https://leetcode.com/{username}", "cat": "Geliştirici"},
    "Dev.to":        {"url": "https://dev.to/{username}", "cat": "Geliştirici"},
    "DockerHub":     {"url": "https://hub.docker.com/u/{username}", "cat": "Geliştirici"},
    "Kaggle":        {"url": "https://www.kaggle.com/{username}", "cat": "Geliştirici"},
    "PyPI":          {"url": "https://pypi.org/user/{username}", "cat": "Geliştirici"},

    # Sosyal Ağlar & İçerik
    "Twitter/X":     {"url": "https://twitter.com/{username}", "cat": "Sosyal Medya"},
    "Reddit":        {"url": "https://www.reddit.com/user/{username}", "cat": "Sosyal Medya"},
    "Instagram":     {"url": "https://www.instagram.com/{username}", "cat": "Sosyal Medya"},
    "TikTok":        {"url": "https://www.tiktok.com/@{username}", "cat": "Sosyal Medya"},
    "YouTube":       {"url": "https://www.youtube.com/@{username}", "cat": "Sosyal Medya"},
    "LinkedIn":      {"url": "https://www.linkedin.com/in/{username}", "cat": "Sosyal Medya"},
    "Pinterest":     {"url": "https://www.pinterest.com/{username}", "cat": "Sosyal Medya"},
    "Tumblr":        {"url": "https://{username}.tumblr.com", "cat": "Sosyal Medya"},
    "Flickr":        {"url": "https://www.flickr.com/people/{username}", "cat": "Sosyal Medya"},
    "Threads":       {"url": "https://www.threads.net/@{username}", "cat": "Sosyal Medya"},

    # Yayıncılık & Blog
    "Medium":        {"url": "https://medium.com/@{username}", "cat": "Yayın & Blog"},
    "Substack":      {"url": "https://{username}.substack.com", "cat": "Yayın & Blog"},
    "WordPress":     {"url": "https://{username}.wordpress.com", "cat": "Yayın & Blog"},
    "Blogger":       {"url": "https://{username}.blogspot.com", "cat": "Yayın & Blog"},
    "Pastebin":      {"url": "https://pastebin.com/u/{username}", "cat": "Yayın & Blog"},

    # Tasarım & Yaratıcılık
    "Behance":       {"url": "https://www.behance.net/{username}", "cat": "Tasarım"},
    "Dribbble":      {"url": "https://dribbble.com/{username}", "cat": "Tasarım"},
    "ArtStation":    {"url": "https://www.artstation.com/{username}", "cat": "Tasarım"},
    "SoundCloud":    {"url": "https://soundcloud.com/{username}", "cat": "Tasarım"},
    "Bandcamp":      {"url": "https://bandcamp.com/{username}", "cat": "Tasarım"},

    # Oyun & Topluluk
    "Steam":         {"url": "https://steamcommunity.com/id/{username}", "cat": "Oyun & Topluluk"},
    "Twitch":        {"url": "https://www.twitch.tv/{username}", "cat": "Oyun & Topluluk"},
    "Chess.com":     {"url": "https://www.chess.com/member/{username}", "cat": "Oyun & Topluluk"},
    "Lichess":       {"url": "https://lichess.org/@/{username}", "cat": "Oyun & Topluluk"},
    "Roblox":        {"url": "https://www.roblox.com/user.aspx?username={username}", "cat": "Oyun & Topluluk"},

    # Güvenlik & Kripto
    "Keybase":       {"url": "https://keybase.io/{username}", "cat": "Güvenlik & Kimlik"},
    "Bugcrowd":      {"url": "https://bugcrowd.com/{username}", "cat": "Güvenlik & Kimlik"},
    "HackerOne":     {"url": "https://hackerone.com/{username}", "cat": "Güvenlik & Kimlik"},
    "TryHackMe":     {"url": "https://tryhackme.com/p/{username}", "cat": "Güvenlik & Kimlik"},
    "HackTheBox":    {"url": "https://app.hackthebox.com/users/{username}", "cat": "Güvenlik & Kimlik"},
}
