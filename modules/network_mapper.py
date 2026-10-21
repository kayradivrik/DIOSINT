"""
modules/network_mapper.py — OSINT Veri İlişkilendirme & Görselleştirme
=======================================================================
- NetworkX ile düğüm-kenar ağı oluşturur
- pyvis ile interaktif HTML ağı üretir
- Matplotlib ile statik grafik kaydeder
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import networkx as nx
from rich.console import Console

from config import REPORTS_DIR

console = Console()


def build_network(osint_data: list[dict[str, Any]]) -> nx.Graph:
    """
    OSINT sonuçlarından bir NetworkX grafiği oluşturur.
    
    Her 'değer' bir düğüm, ortak kaynaktan gelen değerler 
    birbirine bağlı kenarlardır.
    """
    G = nx.Graph()

    # Düğümleri ekle
    for item in osint_data:
        value = item.get("value", "")
        dtype = item.get("type", "unknown")
        source = item.get("source", "unknown")
        if not value:
            continue
        G.add_node(value, type=dtype, source=source)

    # Aynı kaynaktan gelen değerleri birbirine bağla
    from itertools import combinations
    source_groups: dict[str, list[str]] = {}
    for item in osint_data:
        src = item.get("source", "unknown")
        val = item.get("value", "")
        if val:
            source_groups.setdefault(src, []).append(val)

    for source, values in source_groups.items():
        for a, b in combinations(values, 2):
            if G.has_node(a) and G.has_node(b):
                G.add_edge(a, b, source=source, weight=1)

    return G


def export_interactive_html(G: nx.Graph, filename: str = "network_map") -> Path:
    """
    pyvis ile interaktif HTML ağ haritası üretir.
    Tarayıcıda açılabilir.
    """
    try:
        from pyvis.network import Network
    except ImportError:
        console.print("[yellow]⚠️  pyvis kurulu değil: pip install pyvis[/]")
        return Path()

    net = Network(
        height="750px",
        width="100%",
        bgcolor="#1a1a2e",
        font_color="#e0e0e0",
        notebook=False,
    )
    net.barnes_hut()

    # Renk haritası: veri tipine göre
    COLOR_MAP = {
        "ip":       "#e94560",
        "email":    "#0f3460",
        "username": "#16213e",
        "domain":   "#533483",
        "phone":    "#05c46b",
        "unknown":  "#888888",
    }

    for node, attrs in G.nodes(data=True):
        dtype = attrs.get("type", "unknown")
        net.add_node(
            node,
            label=node,
            color=COLOR_MAP.get(dtype, "#888888"),
            title=f"Tür: {dtype}\nKaynak: {attrs.get('source', '—')}",
            size=20,
        )

    for u, v, attrs in G.edges(data=True):
        net.add_edge(u, v, title=attrs.get("source", ""), width=1.5)

    output_path = REPORTS_DIR / f"{filename}.html"
    net.save_graph(str(output_path))
    console.print(f"[green]✅ İnteraktif ağ haritası kaydedildi:[/] {output_path}")
    return output_path


def export_static_graph(G: nx.Graph, filename: str = "network_map") -> Path:
    """Matplotlib ile statik PNG grafiği kaydeder."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        console.print("[yellow]⚠️  matplotlib kurulu değil[/]")
        return Path()

    if len(G.nodes) == 0:
        console.print("[yellow]⚠️  Görselleştirilecek düğüm yok.[/]")
        return Path()

    fig, ax = plt.subplots(figsize=(14, 10), facecolor="#1a1a2e")
    ax.set_facecolor("#1a1a2e")

    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    TYPE_COLORS = {
        "ip":       "#e94560",
        "email":    "#4fc3f7",
        "username": "#81c784",
        "domain":   "#ce93d8",
        "phone":    "#ffb74d",
        "unknown":  "#90a4ae",
    }

    for dtype, color in TYPE_COLORS.items():
        nodes_of_type = [n for n, d in G.nodes(data=True) if d.get("type") == dtype]
        if nodes_of_type:
            nx.draw_networkx_nodes(
                G, pos,
                nodelist=nodes_of_type,
                node_color=color,
                node_size=800,
                alpha=0.9,
                ax=ax,
            )

    nx.draw_networkx_edges(G, pos, edge_color="#555555", alpha=0.6, ax=ax)
    nx.draw_networkx_labels(
        G, pos,
        font_color="white",
        font_size=8,
        ax=ax,
    )

    plt.title("OSINT Bağlantı Haritası", color="white", fontsize=16, pad=20)
    plt.axis("off")
    plt.tight_layout()

    output_path = REPORTS_DIR / f"{filename}.png"
    plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor="#1a1a2e")
    plt.close()

    console.print(f"[green]✅ Statik grafik kaydedildi:[/] {output_path}")
    return output_path


def print_graph_stats(G: nx.Graph):
    """Grafik istatistiklerini terminale yazdırır."""
    console.print(f"\n[bold cyan]📊 Ağ İstatistikleri[/]")
    console.print(f"  • Düğüm sayısı : [yellow]{G.number_of_nodes()}[/]")
    console.print(f"  • Kenar sayısı  : [yellow]{G.number_of_edges()}[/]")
    if G.number_of_nodes() > 0:
        components = nx.number_connected_components(G)
        console.print(f"  • Bileşen sayısı: [yellow]{components}[/]")
        if G.number_of_nodes() > 1:
            central = max(nx.degree_centrality(G).items(), key=lambda x: x[1])
            console.print(f"  • En merkezi düğüm: [green]{central[0]}[/] (skor: {central[1]:.2f})")
