"""
utils/data_cleaner.py — Pandas ile Veri Temizleme & İlişkilendirme
===================================================================
- Farklı kaynaklardan gelen OSINT verilerini birleştirir
- Mükerrer kayıtları temizler
- NetworkX görselleştirmesine hazır veri üretir
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd


# ─── Veri Birleştirme ─────────────────────────────────────────────────────────

def merge_osint_results(results: list[dict[str, Any]]) -> pd.DataFrame:
    """
    Farklı modüllerden gelen sonuçları tek bir DataFrame'e birleştirir.

    Her sonuç sözlüğü şu anahtarları içermelidir:
        source  : str   — veri kaynağı (örn. "username_lookup", "shodan")
        type    : str   — veri tipi   (örn. "ip", "email", "username")
        value   : str   — bulunan değer
        context : dict  — ek bağlam bilgisi (opsiyonel)
    """
    if not results:
        return pd.DataFrame()

    df = pd.DataFrame(results)

    # Zorunlu sütunları garanti et
    for col in ("source", "type", "value", "context"):
        if col not in df.columns:
            df[col] = None

    # Mükerrer kayıtları kaldır (kaynak + tip + değer üçlüsüne göre)
    df = df.drop_duplicates(subset=["source", "type", "value"])

    # Boş değerleri temizle
    df = df.dropna(subset=["value"])
    df["value"] = df["value"].str.strip()
    df = df[df["value"] != ""]

    # Sıralama
    df = df.sort_values(["type", "source"]).reset_index(drop=True)

    return df


# ─── NetworkX İçin Kenar Listesi Oluşturma ───────────────────────────────────

def build_graph_edges(df: pd.DataFrame) -> list[tuple[str, str, dict]]:
    """
    DataFrame'den NetworkX uyumlu kenar listesi (edge list) oluşturur.
    Her düğüm bir OSINT değeri, kenarlar aynı kaynaktan gelen ilişkileri temsil eder.
    """
    edges: list[tuple[str, str, dict]] = []

    if df.empty:
        return edges

    # Aynı kaynaktan gelen değerleri birbirine bağla
    for source, group in df.groupby("source"):
        values = group["value"].tolist()
        for i in range(len(values)):
            for j in range(i + 1, len(values)):
                edges.append((
                    values[i],
                    values[j],
                    {"source": source, "weight": 1},
                ))

    return edges


# ─── IP / Domain Normalizasyonu ──────────────────────────────────────────────

def normalize_ips(series: pd.Series) -> pd.Series:
    """IP adreslerini temizler ve normalleştirir."""
    import ipaddress
    def _normalize(val: str) -> str | None:
        try:
            return str(ipaddress.ip_address(val.strip()))
        except ValueError:
            return None
    return series.apply(_normalize)


def normalize_emails(series: pd.Series) -> pd.Series:
    """E-posta adreslerini küçük harfe çevirir ve formatı doğrular."""
    import re
    pattern = re.compile(r"^[\w._%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}$")
    def _normalize(val: str) -> str | None:
        val = val.strip().lower()
        return val if pattern.match(val) else None
    return series.apply(_normalize)


# ─── Rapor Dışa Aktarma ──────────────────────────────────────────────────────

def export_dataframe(df: pd.DataFrame, path: Path, fmt: str = "json") -> Path:
    """DataFrame'i JSON veya CSV olarak kaydeder."""
    path = Path(path)
    if fmt == "json":
        path = path.with_suffix(".json")
        df.to_json(path, orient="records", indent=2, force_ascii=False)
    elif fmt == "csv":
        path = path.with_suffix(".csv")
        df.to_csv(path, index=False, encoding="utf-8-sig")
    else:
        raise ValueError(f"Desteklenmeyen format: {fmt}")
    return path
