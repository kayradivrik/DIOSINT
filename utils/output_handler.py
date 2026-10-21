"""
utils/output_handler.py — Profesyonel Raporlama Motoru (HTML, PDF-Ready, JSON, CSV)
==================================================================================
Güvenlik denetimi ve portföy standartlarında temiz, modern HTML raporları üretir.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
from config import REPORTS_DIR


def generate_html_report(data: Any, module_name: str, target: str, timestamp_str: str) -> str:
    """Modern kurumsal siber istihbarat raporu HTML şablonu oluşturur."""
    formatted_json = json.dumps(data, indent=2, ensure_ascii=False)
    
    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>İstihbarat Raporu — {target} [{module_name.upper()}]</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #060608;
            --surface: #0e0e12;
            --surface-border: #22222a;
            --primary: #f97316;
            --text-main: #ffffff;
            --text-muted: #a1a1aa;
            --success: #f97316;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg);
            color: var(--text-main);
            font-family: 'Plus Jakarta Sans', sans-serif;
            padding: 40px 20px;
            line-height: 1.6;
        }}
        .report-container {{
            max-width: 1000px;
            margin: 0 auto;
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--surface-border);
            padding-bottom: 24px;
            margin-bottom: 32px;
        }}
        .logo-box {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .logo-icon {{
            width: 42px;
            height: 42px;
            background: linear-gradient(135deg, #0ea5e9, #6366f1);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            color: white;
            font-size: 20px;
        }}
        .title-box h1 {{
            font-size: 22px;
            font-weight: 700;
            letter-spacing: -0.02em;
        }}
        .title-box p {{
            font-size: 13px;
            color: var(--text-muted);
        }}
        .badge {{
            padding: 6px 14px;
            background: rgba(14, 165, 233, 0.15);
            border: 1px solid var(--primary);
            color: var(--primary);
            border-radius: 999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .metric-card {{
            background: rgba(255,255,255,0.02);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 16px 20px;
        }}
        .metric-label {{
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.05em;
            margin-bottom: 6px;
        }}
        .metric-value {{
            font-size: 18px;
            font-weight: 700;
            color: var(--primary);
            word-break: break-all;
        }}
        .data-section {{
            margin-top: 32px;
        }}
        .data-section h3 {{
            font-size: 16px;
            margin-bottom: 16px;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        pre {{
            background: #050811;
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 20px;
            overflow-x: auto;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: #38bdf8;
            max-height: 500px;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--surface-border);
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="header">
            <div class="logo-box">
                <div class="logo-icon">DI</div>
                <div class="title-box">
                    <h1>DIOSINT — İSTİHBARAT RAPORU</h1>
                    <p>Diosint Intelligence Engine • Otomatik Üretim</p>
                </div>
            </div>
            <div class="badge">{module_name}</div>
        </div>

        <div class="summary-grid">
            <div class="metric-card">
                <div class="metric-label">HEDEF GİRDİ</div>
                <div class="metric-value">{target}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">TARAMA ZAMANI</div>
                <div class="metric-value" style="color:#f8fafc; font-size:15px;">{timestamp_str}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">MODÜL SINIFI</div>
                <div class="metric-value">{module_name.upper()}</div>
            </div>
        </div>

        <div class="data-section">
            <h3>📑 Analiz & Ham İstihbarat Verisi</h3>
            <pre><code>{formatted_json}</code></pre>
        </div>

        <div class="footer">
            <span>Gizlilik Derecesi: TLP:CLEAR / EĞİTİM & ETİK ARAŞTIRMA</span>
            <span>Diosint Intelligence Engine v2.0 Enterprise</span>
        </div>
    </div>
</body>
</html>"""
    return html


def save_report(
    data: list[dict[str, Any]] | dict[str, Any],
    module_name: str,
    target: str,
    fmt: str = "both",
) -> Path:
    """
    Sonuçları reports/ klasörüne JSON, CSV ve profesyonel HTML olarak kaydeder.
    """
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    timestamp_human = now.strftime("%d.%m.%Y %H:%M:%S")
    safe_target = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in target)[:50]
    base_name = f"{module_name}_{safe_target}_{timestamp}"

    # 1. JSON
    json_path = REPORTS_DIR / f"{base_name}.json"
    report = {
        "module": module_name,
        "target": target,
        "timestamp": now.isoformat(),
        "results": data,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # 2. HTML Raporu
    html_path = REPORTS_DIR / f"{base_name}.html"
    html_content = generate_html_report(data, module_name, target, timestamp_human)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    # 3. CSV (Eğer tablo verisiyse)
    if fmt in ("csv", "both"):
        csv_path = REPORTS_DIR / f"{base_name}.csv"
        rows = data if isinstance(data, list) else [data]
        try:
            pd.DataFrame(rows).to_csv(csv_path, index=False, encoding="utf-8-sig")
        except Exception:
            pass

    return html_path
