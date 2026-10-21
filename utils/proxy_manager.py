"""
utils/proxy_manager.py — Proxy & Tor Yönetimi
==============================================
- .env'deki USE_TOR=true ile Tor ağına yönlendirme
- proxies.txt'ten proxy listesi yükleme
- Proxy döngüsü (round-robin)
"""

import random
from pathlib import Path
from typing import Optional

import httpx

from config import USE_TOR, TOR_SOCKS_PROXY, PROXY_LIST_FILE


class ProxyManager:
    """
    Proxy yöneticisi.
    Önce Tor'u dene, sonra proxy listesini, sonra doğrudan bağlantı.
    """

    def __init__(self):
        self._proxies: list[str] = []
        self._index: int = 0
        self._load_proxies()

    def _load_proxies(self):
        if USE_TOR:
            self._proxies = [TOR_SOCKS_PROXY]
            return

        if Path(PROXY_LIST_FILE).exists():
            with open(PROXY_LIST_FILE, "r") as f:
                self._proxies = [
                    line.strip() for line in f if line.strip()
                ]

    def get_proxy(self) -> Optional[str]:
        """Sıradaki proxy'yi döndür (round-robin)."""
        if not self._proxies:
            return None
        proxy = self._proxies[self._index % len(self._proxies)]
        self._index += 1
        return proxy

    def get_random_proxy(self) -> Optional[str]:
        """Rastgele bir proxy döndür."""
        if not self._proxies:
            return None
        return random.choice(self._proxies)

    def build_httpx_transport(self) -> Optional[httpx.AsyncHTTPTransport]:
        """httpx ile kullanılacak transport objesi."""
        proxy = self.get_proxy()
        if proxy:
            return httpx.AsyncHTTPTransport(proxy=proxy)
        return None

    @property
    def active(self) -> bool:
        return bool(self._proxies)

    def status(self) -> str:
        if USE_TOR:
            return "🧅 Tor ağı aktif"
        if self._proxies:
            return f"🔀 {len(self._proxies)} proxy yüklendi"
        return "🌐 Doğrudan bağlantı"


# Global proxy manager örneği
proxy_manager = ProxyManager()
