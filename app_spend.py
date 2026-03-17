"""Cloud Spend tracking module for the Streamlit GUI.

Persists every AI API call (provider, model, tokens, cost, timestamp) to a JSON
file and renders a spend dashboard tab. Supports importing cost CSV exports from
the Anthropic Console and Google Cloud Billing.
"""
from __future__ import annotations

import csv
import io
import json
import os
import time
import streamlit as st
from datetime import datetime
from pathlib import Path

_SPEND_FILE = Path(__file__).parent / "cache" / "cloud_spend.json"
_CONSOLE_COSTS_FILE = Path(__file__).parent / "cache" / "console_costs.json"
_MAX_ENTRIES = 5000

# SEK to USD approximate rate — override via LOGPILOT_SEK_TO_USD env var
_SEK_TO_USD = float(os.environ.get("LOGPILOT_SEK_TO_USD", "0.095"))


def _estimate_cost(model_id: str, input_tokens: int, output_tokens: int,
                   cache_creation: int = 0, cache_read: int = 0) -> float:
    from app_ai import TOKEN_COSTS, CACHE_TOKEN_COSTS
    costs = TOKEN_COSTS.get(model_id, (0, 0))
    base = (input_tokens * costs[0] + output_tokens * costs[1]) / 1_000_000
    cache_costs = CACHE_TOKEN_COSTS.get(model_id)
    if cache_costs and (cache_creation or cache_read):
        base += (cache_creation * cache_costs[0] + cache_read * cache_costs[1]) / 1_000_000
    return base


# --- Local spend persistence ---

def _load_entries() -> list[dict]:
    if not _SPEND_FILE.exists():
        return []
    try:
        data = json.loads(_SPEND_FILE.read_text())
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_entries(entries: list[dict]):
    _SPEND_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SPEND_FILE.write_text(json.dumps(entries[-_MAX_ENTRIES:], indent=2))


def record_spend(provider: str, model_id: str, input_tokens: int, output_tokens: int,
                 source: str = "chat", cache_creation: int = 0, cache_read: int = 0):
    cost = _estimate_cost(model_id, input_tokens, output_tokens, cache_creation, cache_read)
    entry = {
        "ts": time.time(), "provider": provider, "model": model_id,
        "input_tokens": input_tokens, "output_tokens": output_tokens,
        "cache_creation": cache_creation, "cache_read": cache_read,
        "cost": cost, "source": source,
    }
    entries = _load_entries()
    entries.append(entry)
    _save_entries(entries)


# --- Console CSV import (multi-provider) ---

def _load_console_data() -> dict:
    """Load imported console cost data. Returns dict with 'anthropic' and 'google' keys."""
    if not _CONSOLE_COSTS_FILE.exists():
        return {}
    try:
        data = json.loads(_CONSOLE_COSTS_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _save_console_data(data: dict):
    _CONSOLE_COSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CONSOLE_COSTS_FILE.write_text(json.dumps(data, indent=2))


def _detect_csv_provider(content: str) -> str | None:
    """Auto-detect CSV provider from header or content."""
    first_line = content.split("\n", 1)[0].lower()
    # Local spend export (from this app)
    if "timestamp" in first_line and "cache_creation" in first_line:
        return "local"
    if "cost_usd" in first_line and "token_type" in first_line:
        return "anthropic"
    if "service description" in first_line or "service id" in first_line:
        return "google"
    # OpenAI: completions usage export has start_time, model, input_tokens, output_tokens
    if "num_model_requests" in first_line or ("start_time" in first_line and "input_tokens" in first_line):
        return "openai"
    if "organization" in first_line or ("cost" in first_line and "snapshot" in first_line):
        return "openai"
    if "model" in first_line and ("cost" in first_line or "amount" in first_line):
        return "openai"
    return None


def _parse_anthropic_csv(content: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(content))
    rows = []
    for row in reader:
        cost_val = float(row.get("cost_usd", 0) or 0)
        if cost_val == 0:
            continue
        rows.append({
            "date": row.get("usage_date_utc", ""),
            "model": row.get("model", "unknown"),
            "workspace": row.get("workspace", ""),
            "api_key": row.get("api_key", ""),
            "token_type": row.get("token_type", ""),
            "cost_usd": cost_val,
        })
    return rows


def _parse_google_csv(content: str, sek_to_usd: float = _SEK_TO_USD) -> list[dict]:
    """Parse Google Cloud Billing CSV export.

    Google format has columns: Service description, Service ID, Cost (kr), ...
    Cost is in SEK (kronor), converted to USD.
    """
    reader = csv.DictReader(io.StringIO(content))
    rows = []
    for row in reader:
        service = row.get("Service description", "").strip()
        if not service:
            continue
        # Find cost column -- may be "Cost (kr)" or similar
        cost_sek = 0.0
        for key in row:
            if "cost" in key.lower() and "kr" in key.lower():
                try:
                    cost_sek = float(row[key] or 0)
                except ValueError:
                    continue
                break
        if cost_sek == 0:
            continue
        cost_usd = cost_sek * sek_to_usd
        rows.append({
            "service": service,
            "service_id": row.get("Service ID", ""),
            "cost_sek": cost_sek,
            "cost_usd": cost_usd,
        })
    return rows


# OpenAI token pricing per 1M tokens (input, output) in USD
_OPENAI_TOKEN_COSTS = {
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-2024-08-06": (2.50, 10.00),
    "gpt-4o-2024-11-20": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o-mini-2024-07-18": (0.15, 0.60),
    "gpt-4-turbo": (10.00, 30.00),
    "gpt-4": (30.00, 60.00),
    "gpt-3.5-turbo": (0.50, 1.50),
    "gpt-3.5-turbo-0125": (0.50, 1.50),
    "o3": (10.00, 40.00),
    "o3-mini": (1.10, 4.40),
    "o4-mini": (1.10, 4.40),
}


def _openai_estimate_cost(model: str, input_tokens: float, output_tokens: float) -> float:
    """Estimate cost for an OpenAI model from token counts."""
    costs = _OPENAI_TOKEN_COSTS.get(model, (0, 0))
    if costs == (0, 0):
        # Try matching base model name (strip date suffix)
        for key, val in _OPENAI_TOKEN_COSTS.items():
            if model.startswith(key):
                costs = val
                break
    return (input_tokens * costs[0] + output_tokens * costs[1]) / 1_000_000


def _parse_openai_csv(content: str) -> list[dict]:
    """Parse OpenAI platform completions usage CSV export.

    Format: start_time_iso, model, input_tokens, output_tokens, input_cached_tokens,
    num_model_requests, etc. Cost is calculated from tokens.
    """
    reader = csv.DictReader(io.StringIO(content))
    rows = []
    for row in reader:
        model = (row.get("model") or "").strip()
        if not model:
            continue
        input_tok = float(row.get("input_tokens") or 0)
        output_tok = float(row.get("output_tokens") or 0)
        if input_tok == 0 and output_tok == 0:
            continue
        cached_tok = float(row.get("input_cached_tokens") or 0)
        requests = float(row.get("num_model_requests") or 0)
        # Date from ISO field
        date_iso = row.get("start_time_iso", "")
        date = date_iso[:10] if date_iso else ""
        cost = _openai_estimate_cost(model, input_tok, output_tok)
        rows.append({
            "date": date,
            "model": model,
            "input_tokens": int(input_tok),
            "output_tokens": int(output_tok),
            "cached_tokens": int(cached_tok),
            "requests": int(requests),
            "cost_usd": cost,
            "api_key": row.get("api_key_id", ""),
        })
    return rows


# --- Rendering ---

def _render_anthropic_costs(rows: list[dict]):
    total = sum(r["cost_usd"] for r in rows)
    dates = sorted(set(r["date"] for r in rows if r.get("date")))
    period = f"{dates[0]} to {dates[-1]}" if dates else ""

    st.metric("Anthropic", f"${total:.4f}")
    if period:
        st.caption(f"Period: {period}")

    # By model
    model_costs = {}
    for r in rows:
        m = r["model"]
        if m not in model_costs:
            model_costs[m] = {"input": 0.0, "output": 0.0, "cache_write": 0.0, "cache_read": 0.0, "total": 0.0}
        tt = r.get("token_type", "")
        model_costs[m]["total"] += r["cost_usd"]
        if "output" in tt:
            model_costs[m]["output"] += r["cost_usd"]
        elif "cache_write" in tt or "cache_creation" in tt:
            model_costs[m]["cache_write"] += r["cost_usd"]
        elif "cache_read" in tt:
            model_costs[m]["cache_read"] += r["cost_usd"]
        else:
            model_costs[m]["input"] += r["cost_usd"]

    tbl = []
    for model, c in sorted(model_costs.items(), key=lambda x: x[1]["total"], reverse=True):
        row = {"Model": model, "Input": f"${c['input']:.4f}", "Output": f"${c['output']:.4f}",
               "Total": f"${c['total']:.4f}"}
        if c["cache_write"] or c["cache_read"]:
            row["Cache Write"] = f"${c['cache_write']:.4f}"
            row["Cache Read"] = f"${c['cache_read']:.4f}"
        tbl.append(row)
    st.table(tbl)

    # By date
    date_costs = {}
    for r in rows:
        d = r.get("date", "")
        if d:
            date_costs[d] = date_costs.get(d, 0) + r["cost_usd"]
    if len(date_costs) > 1:
        st.caption("Daily cost")
        st.bar_chart(dict(sorted(date_costs.items())))

    # By API key
    key_costs = {}
    for r in rows:
        k = r.get("api_key", "unknown")
        if k:
            key_costs[k] = key_costs.get(k, 0) + r["cost_usd"]
    if len(key_costs) > 1:
        st.caption("By API key")
        st.table([{"API Key": k, "Cost": f"${c:.4f}"} for k, c in
                  sorted(key_costs.items(), key=lambda x: x[1], reverse=True)])


def _render_google_costs(rows: list[dict]):
    total_usd = sum(r["cost_usd"] for r in rows)
    total_sek = sum(r["cost_sek"] for r in rows)

    st.metric("Google Cloud", f"${total_usd:.4f}", f"{total_sek:.2f} kr")

    tbl = []
    for r in rows:
        tbl.append({
            "Service": r["service"],
            "Cost (SEK)": f"{r['cost_sek']:.4f} kr",
            "Cost (USD)": f"${r['cost_usd']:.4f}",
        })
    st.table(tbl)
    st.caption(f"Converted at 1 SEK = {_SEK_TO_USD} USD")


def _render_openai_costs(rows: list[dict]):
    total = sum(r["cost_usd"] for r in rows)
    total_requests = sum(r.get("requests", 0) for r in rows)
    total_input = sum(r.get("input_tokens", 0) for r in rows)
    total_output = sum(r.get("output_tokens", 0) for r in rows)
    dates = sorted(set(r["date"] for r in rows if r.get("date")))
    period = f"{dates[0]} to {dates[-1]}" if dates else ""

    st.metric("OpenAI", f"${total:.4f}")
    if period:
        st.caption(f"Period: {period}")

    # By model
    model_data = {}
    for r in rows:
        m = r["model"]
        if m not in model_data:
            model_data[m] = {"cost": 0.0, "input": 0, "output": 0, "requests": 0}
        model_data[m]["cost"] += r["cost_usd"]
        model_data[m]["input"] += r.get("input_tokens", 0)
        model_data[m]["output"] += r.get("output_tokens", 0)
        model_data[m]["requests"] += r.get("requests", 0)

    tbl = []
    for model, d in sorted(model_data.items(), key=lambda x: x[1]["cost"], reverse=True):
        tbl.append({
            "Model": model,
            "Requests": d["requests"],
            "Input": f"{d['input']:,}",
            "Output": f"{d['output']:,}",
            "Cost": f"${d['cost']:.4f}",
        })
    st.table(tbl)
    st.caption(f"Cost estimated from token counts. {total_requests:,} requests, "
               f"{total_input:,} input / {total_output:,} output tokens.")

    # By date
    date_costs = {}
    for r in rows:
        d = r.get("date", "")
        if d:
            date_costs[d] = date_costs.get(d, 0) + r["cost_usd"]
    if len(date_costs) > 1:
        st.caption("Daily cost")
        st.bar_chart(dict(sorted(date_costs.items())))


def _get_total_spend() -> dict:
    """Get total spend across all sources. Returns dict with totals."""
    console_data = _load_console_data()
    anthropic = sum(r["cost_usd"] for r in console_data.get("anthropic", []))
    google = sum(r["cost_usd"] for r in console_data.get("google", []))
    openai = sum(r["cost_usd"] for r in console_data.get("openai", []))
    local = sum(e["cost"] for e in _load_entries())
    return {"anthropic": anthropic, "google": google, "openai": openai,
            "local": local, "total": anthropic + google + openai + local}


def render_spend_gauge():
    """Render a stylish spend gauge for the sidebar."""
    import plotly.graph_objects as go
    import math

    totals = _get_total_spend()
    total = totals["total"]

    # Dynamic max range
    if total < 5:
        max_val = 10
    elif total < 20:
        max_val = 50
    elif total < 50:
        max_val = 100
    else:
        max_val = math.ceil(total * 1.5 / 10) * 10

    # Needle angle: map value to 180-degree arc (left=180°, right=0°)
    ratio = min(total / max_val, 1.0)
    angle_deg = 180 - ratio * 180
    angle_rad = math.radians(angle_deg)
    needle_len = 0.38
    nx = 0.5 + needle_len * math.cos(angle_rad)
    ny = 0.5 + needle_len * math.sin(angle_rad)

    # Color based on spend ratio
    if ratio < 0.4:
        needle_color = "#00E676"
        glow = "rgba(0,230,118,0.4)"
    elif ratio < 0.7:
        needle_color = "#FFAB00"
        glow = "rgba(255,171,0,0.4)"
    else:
        needle_color = "#FF1744"
        glow = "rgba(255,23,68,0.4)"

    # Build gauge segments as a pie (half-donut)
    n_segments = 60
    seg_colors = []
    for i in range(n_segments):
        r = i / n_segments
        if r < 0.4:
            seg_colors.append("rgba(0,230,118,0.25)")
        elif r < 0.7:
            seg_colors.append("rgba(255,171,0,0.25)")
        else:
            seg_colors.append("rgba(255,23,68,0.25)")
    # Invisible bottom half
    seg_values = [1] * n_segments + [n_segments]

    fig = go.Figure()

    # Gauge arc segments
    fig.add_trace(go.Pie(
        values=seg_values,
        hole=0.65,
        direction="clockwise",
        rotation=180,
        marker={"colors": seg_colors + ["rgba(0,0,0,0)"]},
        textinfo="none",
        hoverinfo="none",
        showlegend=False,
        domain={"x": [0.05, 0.95], "y": [0.05, 0.95]},
    ))

    # Lit-up arc (filled portion)
    lit_segments = max(1, int(ratio * n_segments))
    lit_colors = []
    for i in range(n_segments):
        if i < lit_segments:
            r = i / n_segments
            if r < 0.4:
                lit_colors.append("rgba(0,230,118,0.7)")
            elif r < 0.7:
                lit_colors.append("rgba(255,171,0,0.7)")
            else:
                lit_colors.append("rgba(255,23,68,0.7)")
        else:
            lit_colors.append("rgba(255,255,255,0.04)")

    fig.add_trace(go.Pie(
        values=seg_values,
        hole=0.72,
        direction="clockwise",
        rotation=180,
        marker={"colors": lit_colors + ["rgba(0,0,0,0)"]},
        textinfo="none",
        hoverinfo="none",
        showlegend=False,
        domain={"x": [0.05, 0.95], "y": [0.05, 0.95]},
    ))

    # Needle as a thin triangle shape
    tip_x = nx
    tip_y = ny
    base_offset = 0.015
    perp_angle = angle_rad + math.pi / 2
    bx1 = 0.5 + base_offset * math.cos(perp_angle)
    by1 = 0.48 + base_offset * math.sin(perp_angle)
    bx2 = 0.5 - base_offset * math.cos(perp_angle)
    by2 = 0.48 - base_offset * math.sin(perp_angle)

    fig.add_shape(
        type="path",
        path=f"M {bx1} {by1} L {tip_x} {tip_y} L {bx2} {by2} Z",
        xref="paper", yref="paper",
        fillcolor=needle_color,
        line={"color": needle_color, "width": 0},
    )

    # Center dot
    fig.add_shape(
        type="circle",
        x0=0.47, y0=0.45, x1=0.53, y1=0.51,
        xref="paper", yref="paper",
        fillcolor=needle_color,
        line={"color": needle_color, "width": 0},
    )

    # Value text
    fig.add_annotation(
        x=0.5, y=0.30,
        xref="paper", yref="paper",
        text=f"<b>${total:.2f}</b>",
        font={"size": 22, "color": needle_color, "family": "Arial Black"},
        showarrow=False,
    )

    # Min/max labels
    fig.add_annotation(
        x=0.08, y=0.38, xref="paper", yref="paper",
        text="$0", font={"size": 10, "color": "rgba(255,255,255,0.4)"},
        showarrow=False,
    )
    fig.add_annotation(
        x=0.92, y=0.38, xref="paper", yref="paper",
        text=f"${max_val}", font={"size": 10, "color": "rgba(255,255,255,0.4)"},
        showarrow=False,
    )

    fig.update_layout(
        height=160,
        margin={"t": 5, "b": 0, "l": 0, "r": 0},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#fafafa"},
    )
    st.plotly_chart(fig, use_container_width=True, key="spend_gauge")

    # Provider breakdown with colored dots
    provider_info = [
        ("anthropic", "Anthropic", "#D4A574"),
        ("google", "Google", "#4285F4"),
        ("openai", "OpenAI", "#10A37F"),
        ("local", "Local", "#9E9E9E"),
    ]
    lines = []
    for key, label, color in provider_info:
        val = totals.get(key, 0)
        if val > 0:
            fmt = f"${val:.2f}" if val >= 0.01 else f"${val:.4f}"
            lines.append(f'<span style="color:{color}">●</span> {label} {fmt}')
    if lines:
        st.markdown(
            f'<div style="font-size:12px;line-height:1.6;opacity:0.85">{"<br>".join(lines)}</div>',
            unsafe_allow_html=True,
        )


# --- Main tab ---

def _render_cost_donut(totals: dict):
    """Render a donut chart showing cost per cloud provider."""
    import plotly.graph_objects as go

    labels = []
    values = []
    colors = []
    provider_colors = {
        "Anthropic": "#D4A574",   # warm tan
        "Google": "#4285F4",      # google blue
        "OpenAI": "#10A37F",      # openai green
        "Local (est.)": "#9E9E9E",  # gray
    }
    mapping = [
        ("Anthropic", totals.get("anthropic", 0)),
        ("Google", totals.get("google", 0)),
        ("OpenAI", totals.get("openai", 0)),
        ("Local (est.)", totals.get("local", 0)),
    ]
    for label, val in mapping:
        if val > 0:
            labels.append(label)
            values.append(val)
            colors.append(provider_colors[label])

    if not values:
        return

    text_vals = [f"${v:.2f}" for v in values]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        text=text_vals,
        textinfo="label+text",
        textposition="outside",
        hole=0.55,
        marker={"colors": colors},
        hovertemplate="%{label}: $%{value:.2f}<extra></extra>",
    ))
    total = sum(values)
    fig.update_layout(
        title={"text": "Cost per Provider", "x": 0.5, "font": {"size": 18}},
        annotations=[{
            "text": f"${total:.2f}",
            "x": 0.5, "y": 0.5,
            "font": {"size": 24, "color": "#fafafa"},
            "showarrow": False,
        }],
        height=350,
        margin={"t": 50, "b": 20, "l": 20, "r": 20},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#fafafa"},
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True, key="cost_donut")
    # Text fallback for accessibility
    parts = [f"{l}: ${v:.2f}" for l, v in zip(labels, values)]
    st.caption(f"Total ${total:.2f} — " + ", ".join(parts))


def _import_local_csv(content: str) -> list[dict]:
    """Import local spend entries from a previously exported CSV."""
    if not isinstance(content, str):
        return []
    reader = csv.DictReader(io.StringIO(content))
    entries = []
    for row in reader:
        try:
            entries.append({
                "ts": float(row.get("timestamp", 0)),
                "provider": row.get("provider", ""),
                "model": row.get("model", ""),
                "source": row.get("source", "chat"),
                "input_tokens": int(row.get("input_tokens", 0)),
                "output_tokens": int(row.get("output_tokens", 0)),
                "cache_creation": int(row.get("cache_creation", 0)),
                "cache_read": int(row.get("cache_read", 0)),
                "cost": float(row.get("cost_usd", 0)),
            })
        except (ValueError, TypeError):
            continue
    return entries


def _export_local_csv(entries: list[dict]) -> str:
    """Export local spend entries to CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "date", "provider", "model", "source",
                     "input_tokens", "output_tokens", "cache_creation", "cache_read", "cost_usd"])
    for e in entries:
        dt = datetime.fromtimestamp(e["ts"])
        writer.writerow([
            e["ts"], dt.strftime("%Y-%m-%d %H:%M:%S"),
            e["provider"], e["model"], e.get("source", "chat"),
            e["input_tokens"], e["output_tokens"],
            e.get("cache_creation", 0), e.get("cache_read", 0),
            f"{e['cost']:.6f}",
        ])
    return output.getvalue()


def render_spend_tab():
    """Render the Cloud Spend tab contents."""
    console_data = _load_console_data()
    anthropic_rows = console_data.get("anthropic", [])
    google_rows = console_data.get("google", [])
    openai_rows = console_data.get("openai", [])
    local_entries = _load_entries()

    # --- Totals ---
    anthropic_total = sum(r["cost_usd"] for r in anthropic_rows)
    google_total = sum(r["cost_usd"] for r in google_rows)
    openai_total = sum(r["cost_usd"] for r in openai_rows)
    local_total = sum(e["cost"] for e in local_entries)
    grand_total = anthropic_total + google_total + openai_total + local_total

    # --- 1. Total spend: donut + metrics ---
    totals = {"anthropic": anthropic_total, "google": google_total,
              "openai": openai_total, "local": local_total}

    col_chart, col_metrics = st.columns([1, 1])
    with col_chart:
        if grand_total > 0:
            _render_cost_donut(totals)
        else:
            st.info("No spend data yet. Run an AI analysis or import a CSV to start tracking costs.")

    with col_metrics:
        st.metric("Total Cloud Spend", f"${grand_total:.2f}")
        if anthropic_total:
            st.metric("Anthropic", f"${anthropic_total:.2f}")
        if google_total:
            st.metric("Google", f"${google_total:.2f}")
        if openai_total:
            st.metric("OpenAI", f"${openai_total:.2f}")
        if local_total:
            st.metric("Local (estimated)", f"${local_total:.4f}")

    st.divider()

    # --- 2. Import CSV ---
    with st.expander("Import Spend Data CSV", expanded=False):
        st.caption("Upload cost exports from Anthropic Console, Google Cloud Billing, OpenAI Platform, "
                   "or a previously exported local spend CSV. Format is auto-detected.")
        uploaded_csv = st.file_uploader(
            "Upload cost CSV", type=["csv"], key="console_csv_upload",
            accept_multiple_files=True,
        )
        if uploaded_csv and st.button("Import", key="import_csv_btn"):
            imported = False
            for f in uploaded_csv:
                content = f.getvalue().decode("utf-8")
                provider = _detect_csv_provider(content)
                if provider == "anthropic":
                    rows = _parse_anthropic_csv(content)
                    if rows:
                        console_data["anthropic"] = rows
                        _save_console_data(console_data)
                        imported = True
                elif provider == "google":
                    rows = _parse_google_csv(content)
                    if rows:
                        console_data["google"] = rows
                        _save_console_data(console_data)
                        imported = True
                elif provider == "openai":
                    rows = _parse_openai_csv(content)
                    if rows:
                        console_data["openai"] = rows
                        _save_console_data(console_data)
                        imported = True
                elif provider == "local":
                    entries = _import_local_csv(content)
                    if entries:
                        existing = _load_entries()
                        existing_ts = {e["ts"] for e in existing}
                        new_entries = [e for e in entries if e["ts"] not in existing_ts]
                        if new_entries:
                            existing.extend(new_entries)
                            _save_entries(existing)
                            imported = True
                        else:
                            st.info(f"{f.name}: All entries already exist.")
                else:
                    st.error(f"Could not detect CSV format for {f.name}. "
                             "Supported: Anthropic, Google Cloud, OpenAI, Local export.")
            if imported:
                st.rerun()

    # --- 3. Local spend tracking ---
    local_label = f"Local API Call Tracking — ${local_total:.4f}" if local_entries else "Local API Call Tracking"
    with st.expander(local_label, expanded=not local_entries):
        if not local_entries:
            st.info("No API calls recorded yet. Use the AI analysis or audit features to start tracking.")
        else:
            total_calls = len(local_entries)
            total_input = sum(e["input_tokens"] for e in local_entries)
            total_output = sum(e["output_tokens"] for e in local_entries)
            total_cache_create = sum(e.get("cache_creation", 0) for e in local_entries)
            total_cache_read = sum(e.get("cache_read", 0) for e in local_entries)

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Estimated Spend", f"${local_total:.4f}")
            c2.metric("API Calls", f"{total_calls:,}")
            c3.metric("Input Tokens", f"{total_input:,}")
            c4.metric("Output Tokens", f"{total_output:,}")

            if total_cache_create or total_cache_read:
                cc1, cc2 = st.columns(2)
                cc1.metric("Cache Write Tokens", f"{total_cache_create:,}")
                cc2.metric("Cache Read Tokens", f"{total_cache_read:,}")

            st.divider()

            # By provider
            st.caption("By Provider")
            providers = {}
            for e in local_entries:
                p = e["provider"]
                if p not in providers:
                    providers[p] = {"calls": 0, "cost": 0.0, "input": 0, "output": 0}
                providers[p]["calls"] += 1
                providers[p]["cost"] += e["cost"]
                providers[p]["input"] += e["input_tokens"]
                providers[p]["output"] += e["output_tokens"]

            provider_cols = st.columns(max(len(providers), 1))
            for i, (prov, stats) in enumerate(sorted(providers.items())):
                with provider_cols[i % len(provider_cols)]:
                    label = {"claude": "Anthropic", "gemini": "Google", "openai": "OpenAI"}.get(prov, prov)
                    st.metric(label, f"${stats['cost']:.4f}", f"{stats['calls']} calls")
                    st.caption(f"{stats['input']:,} in / {stats['output']:,} out tokens")

            st.divider()

            # By model
            st.caption("By Model")
            models = {}
            for e in local_entries:
                m = e["model"]
                if m not in models:
                    models[m] = {"calls": 0, "cost": 0.0, "input": 0, "output": 0,
                                 "cache_creation": 0, "cache_read": 0, "provider": e["provider"]}
                models[m]["calls"] += 1
                models[m]["cost"] += e["cost"]
                models[m]["input"] += e["input_tokens"]
                models[m]["output"] += e["output_tokens"]
                models[m]["cache_creation"] += e.get("cache_creation", 0)
                models[m]["cache_read"] += e.get("cache_read", 0)

            rows = []
            for model, stats in sorted(models.items(), key=lambda x: x[1]["cost"], reverse=True):
                row = {
                    "Model": model, "Provider": stats["provider"].capitalize(),
                    "Calls": stats["calls"], "Input": f"{stats['input']:,}",
                    "Output": f"{stats['output']:,}", "Cost": f"${stats['cost']:.4f}",
                }
                if stats["cache_creation"] or stats["cache_read"]:
                    row["Cache W"] = f"{stats['cache_creation']:,}"
                    row["Cache R"] = f"{stats['cache_read']:,}"
                rows.append(row)
            st.table(rows)

            st.divider()

            # Recent calls
            st.caption("Recent Calls")
            recent = local_entries[-20:][::-1]
            recent_rows = []
            for e in recent:
                dt = datetime.fromtimestamp(e["ts"])
                row = {
                    "Time": dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "Provider": e["provider"].capitalize(),
                    "Model": e["model"],
                    "Source": e.get("source", "chat"),
                    "In": f"{e['input_tokens']:,}",
                    "Out": f"{e['output_tokens']:,}",
                    "Cost": f"${e['cost']:.4f}",
                }
                cache_c = e.get("cache_creation", 0)
                cache_r = e.get("cache_read", 0)
                if cache_c or cache_r:
                    row["Cache"] = f"W:{cache_c:,} R:{cache_r:,}"
                recent_rows.append(row)
            st.table(recent_rows)

            st.divider()
            csv_data = _export_local_csv(local_entries)
            btn1, btn2 = st.columns(2)
            with btn1:
                st.download_button("Export Local Spend", data=csv_data,
                                   file_name=f"local_spend_{datetime.now().strftime('%Y-%m-%d')}.csv",
                                   mime="text/csv", use_container_width=True)
            with btn2:
                if st.session_state.get("_confirm_clear_local"):
                    st.warning("Delete all local spend data?")
                    cc1, cc2 = st.columns(2)
                    with cc1:
                        if st.button("Yes, delete", type="primary", use_container_width=True, key="confirm_clear_local"):
                            st.session_state._confirm_clear_local = False
                            _SPEND_FILE.unlink(missing_ok=True)
                            st.rerun()
                    with cc2:
                        if st.button("Cancel", use_container_width=True, key="cancel_clear_local"):
                            st.session_state._confirm_clear_local = False
                            st.rerun()
                elif st.button("Clear Local Spend", type="secondary", use_container_width=True):
                    st.session_state._confirm_clear_local = True
                    st.rerun()

    # --- 4. Console provider details ---
    if anthropic_rows:
        with st.expander(f"Anthropic Console Costs — ${anthropic_total:.2f}"):
            _render_anthropic_costs(anthropic_rows)

    if google_rows:
        with st.expander(f"Google Cloud Costs — ${google_total:.2f}"):
            _render_google_costs(google_rows)

    if openai_rows:
        with st.expander(f"OpenAI Costs — ${openai_total:.4f}"):
            _render_openai_costs(openai_rows)

    if anthropic_rows or google_rows or openai_rows:
        if st.session_state.get("_confirm_clear_console"):
            st.warning("Delete all imported console data?")
            cc1, cc2 = st.columns(2)
            with cc1:
                if st.button("Yes, delete", type="primary", use_container_width=True, key="confirm_clear_console"):
                    st.session_state._confirm_clear_console = False
                    _CONSOLE_COSTS_FILE.unlink(missing_ok=True)
                    st.rerun()
            with cc2:
                if st.button("Cancel", use_container_width=True, key="cancel_clear_console"):
                    st.session_state._confirm_clear_console = False
                    st.rerun()
        elif st.button("Clear imported console data", type="secondary", key="clear_console"):
            st.session_state._confirm_clear_console = True
            st.rerun()
