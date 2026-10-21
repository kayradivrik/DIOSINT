"""
utils/rate_limiter.py — Akıllı Rate Limiting & Retry
=====================================================
- Her istek arasında bekleme süresi ekler
- tenacity ile otomatik retry mantığı
- robots.txt uyumu kontrolü
"""

import asyncio
import time
import urllib.robotparser
from functools import wraps
from urllib.parse import urlparse

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

import httpx

from config import DEFAULT_RETRIES, RATE_LIMIT_DELAY


# ─── Asenkron Rate Limiter ────────────────────────────────────────────────────

class AsyncRateLimiter:
    """İstekler arasında belirli bir gecikme uygular (async)."""

    def __init__(self, calls_per_second: float = 1.0):
        self.min_interval = 1.0 / calls_per_second
        self._last_call = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            wait = self.min_interval - (now - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()


# Proje genelinde tek bir rate limiter örneği
global_limiter = AsyncRateLimiter(calls_per_second=1.0 / RATE_LIMIT_DELAY)


# ─── Retry Decorator ──────────────────────────────────────────────────────────

def with_retry(func):
    """
    Dekoratör: httpx hatalarında otomatik yeniden deneme.
    Exponential backoff: 1s → 2s → 4s → ...
    """
    @retry(
        stop=stop_after_attempt(DEFAULT_RETRIES),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        reraise=True,
    )
    @wraps(func)
    async def wrapper(*args, **kwargs):
        return await func(*args, **kwargs)
    return wrapper


# ─── Robots.txt Kontrolü ─────────────────────────────────────────────────────

_robots_cache: dict[str, urllib.robotparser.RobotFileParser] = {}


def is_allowed_by_robots(url: str, user_agent: str = "*") -> bool:
    """
    Verilen URL'nin robots.txt tarafından izin verilip verilmediğini kontrol eder.
    Sonuçları önbelleğe alır.
    """
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    if base not in _robots_cache:
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(f"{base}/robots.txt")
        try:
            rp.read()
        except Exception:
            # robots.txt okunamazsa izin var sayılır
            return True
        _robots_cache[base] = rp

    return _robots_cache[base].can_fetch(user_agent, url)
