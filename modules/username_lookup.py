"""
modules/username_lookup.py — Kullanıcı Adı İstihbaratı (Gelişmiş Profilleme)
=============================================================================
Verilen kullanıcı adını 40+ kategorize edilmiş platformda asenkron olarak arar.
GitHub ve diğer zengin API'lerden detaylı profil metadataları (biyografi, takipçi,
isim, organizasyon, avatar, repo sayısı vb.) çıkarır.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional, Any

import httpx
from config import DEFAULT_HEADERS, DEFAULT_TIMEOUT, USERNAME_PLATFORMS, console
from utils.proxy_manager import proxy_manager
from utils.rate_limiter import global_limiter, with_retry


@dataclass
class PlatformResult:
    platform: str
    category: str
    url: str
    found: bool
    status_code: Optional[int] = None
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


async def _fetch_github_metadata(client: httpx.AsyncClient, username: str) -> dict[str, Any]:
    """GitHub public API üzerinden kullanıcı hakkında derinlemesine istihbarat toplar."""
    try:
        api_url = f"https://api.github.com/users/{username}"
        headers = dict(DEFAULT_HEADERS)
        headers["Accept"] = "application/vnd.github.v3+json"
        resp = await client.get(api_url, headers=headers, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "name": data.get("name"),
                "bio": data.get("bio"),
                "company": data.get("company"),
                "location": data.get("location"),
                "blog": data.get("blog"),
                "twitter_username": data.get("twitter_username"),
                "public_repos": data.get("public_repos"),
                "followers": data.get("followers"),
                "following": data.get("following"),
                "created_at": data.get("created_at"),
                "avatar_url": data.get("avatar_url"),
            }
    except Exception:
        pass
    return {}


async def _check_platform(
    client: httpx.AsyncClient,
    platform: str,
    info: dict[str, str],
    username: str,
) -> PlatformResult:
    """Tek bir platformu kontrol eder ve desteklenen platformlarda metadata çeker."""
    url = info["url"].format(username=username)
    category = info.get("cat", "Genel")
    
    await global_limiter.acquire()
    try:
        resp = await client.get(url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
        # 200 dönerse ve belirgin 404 göstergeleri yoksa profili bulundu kabul et
        found = resp.status_code == 200
        
        # Ek kontrol: bazı siteler 200 ile 'User not found' döner
        if found:
            text_lower = resp.text[:1500].lower()
            if any(term in text_lower for term in ["user not found", "page not found", "bu sayfa mevcut değil"]):
                found = False

        meta = {}
        if found and platform.lower() == "github":
            meta = await _fetch_github_metadata(client, username)

        return PlatformResult(
            platform=platform,
            category=category,
            url=url,
            found=found,
            status_code=resp.status_code,
            metadata=meta,
        )
    except httpx.TimeoutException:
        return PlatformResult(platform, category, url, False, error="Zaman Aşımı")
    except httpx.ConnectError:
        return PlatformResult(platform, category, url, False, error="Bağlantı Hatası")
    except Exception as e:
        return PlatformResult(platform, category, url, False, error=str(e))


async def lookup_username(username: str) -> list[PlatformResult]:
    """
    Kullanıcı adını 40+ platformda eş zamanlı ve asenkron olarak arar.
    """
    console.print(f"\n[bold cyan]🔍 Kullanıcı adı taranıyor:[/] [yellow]{username}[/]")
    console.print(f"[dim]Kategorize {len(USERNAME_PLATFORMS)} platform sorgulanıyor...[/]\n")

    transport = proxy_manager.build_httpx_transport()
    client_kwargs = dict(
        headers=DEFAULT_HEADERS,
        follow_redirects=True,
    )
    if transport:
        client_kwargs["transport"] = transport

    async with httpx.AsyncClient(**client_kwargs) as client:
        tasks = [
            _check_platform(client, platform, info, username)
            for platform, info in USERNAME_PLATFORMS.items()
        ]
        results = await asyncio.gather(*tasks)

    return list(results)


def to_dict_list(results: list[PlatformResult]) -> list[dict]:
    """Sonuçları serileştirilebilir sözlük listesine dönüştürür."""
    return [
        {
            "source": "username_lookup",
            "type": "username",
            "platform": r.platform,
            "category": r.category,
            "value": r.url if r.found else "",
            "found": r.found,
            "status_code": r.status_code,
            "error": r.error,
            "metadata": r.metadata,
        }
        for r in results
        if r.found
    ]
