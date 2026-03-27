"""LogPilot — Overview dashboard: what did we find?"""
from pathlib import Path
from collections import Counter

import streamlit as st

from logpilot.analysis import compare_periods
from app_render import render_what_changed

a = st.session_state.get("analysis")
if a is None:
    st.info("Upload and analyze log files on the **Home** page first.")
    st.stop()

# --- Apply global filters ---
filter_levels = st.session_state.get("filter_levels", [])
filter_sources = st.session_state.get("filter_sources", [])

all_events = a["events"]
if filter_levels or filter_sources:
    filtered_events = [
        e for e in all_events
        if (not filter_levels or e.level in filter_levels)
        and (not filter_sources or (e.system_label or e.file or "") in filter_sources)
    ]
else:
    filtered_events = all_events

# --- Top-N parameter ---
st.title("Overview")
top_n = st.number_input("Top N items", min_value=3, max_value=50, value=10, step=1,
                        help="How many items to show in each list")

# --- Metric cards ---
total_events = len(filtered_events)
file_count = a["file_count"]
error_count = sum(1 for e in filtered_events if e.level in ("ERROR", "SEVERE", "FATAL", "CRITICAL"))

grouped = a.get("grouped") or {}
incident_count = len(grouped.get("groups", []))

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Events", total_events)
c2.metric("Files Analyzed", file_count)
c3.metric("Errors Found", error_count)
c4.metric("Incidents Detected", incident_count)

st.divider()

# --- Severity breakdown ---
st.subheader("Severity Breakdown")
level_counts = Counter(e.level or "UNKNOWN" for e in filtered_events)
severity_order = ["FATAL", "SEVERE", "ERROR", "CRITICAL", "WARNING", "WARN", "INFO", "AUDIT", "DEBUG", "UNKNOWN"]
level_colors = {
    "FATAL": "#DC2626",
    "SEVERE": "#DC2626",
    "ERROR": "#EF4444",
    "CRITICAL": "#EF4444",
    "WARNING": "#F59E0B",
    "WARN": "#F59E0B",
    "INFO": "#7C3AED",
    "AUDIT": "#0891B2",
    "DEBUG": "#94A3B8",
    "UNKNOWN": "#6B7280",
}

max_count = max(level_counts.values()) if level_counts else 1
for level in severity_order:
    count = level_counts.get(level, 0)
    if count == 0:
        continue
    bar_width = int((count / max_count) * 30)
    bar = "█" * bar_width
    color = level_colors.get(level, "#6B7280")
    st.markdown(
        f'<div style="font-family:monospace;margin:2px 0">'
        f'<span style="display:inline-block;width:8em;color:{color};font-weight:bold">{level}</span>'
        f'<span style="display:inline-block;width:5em;text-align:right;margin-right:0.5em">{count}</span>'
        f'<span style="color:{color}">{bar}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

# Show any levels not in the predefined order
for level, count in sorted(level_counts.items(), key=lambda x: -x[1]):
    if level not in severity_order and count > 0:
        bar_width = int((count / max_count) * 30)
        bar = "█" * bar_width
        st.markdown(
            f'<div style="font-family:monospace;margin:2px 0">'
            f'<span style="display:inline-block;width:8em;color:#6B7280;font-weight:bold">{level}</span>'
            f'<span style="display:inline-block;width:5em;text-align:right;margin-right:0.5em">{count}</span>'
            f'<span style="color:#6B7280">{bar}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

st.divider()

# --- Files analyzed ---
st.subheader("Files Analyzed")
file_summary = a.get("file_summary", [])
if file_summary:
    # file_summary is list of (filename, total, errors) tuples
    table_rows = []
    for item in file_summary:
        if isinstance(item, dict):
            fname = item.get("file", "")
            total = item.get("events", 0)
            errors = item.get("errors", 0)
            fmt = item.get("format", "—")
        else:
            fname, total, errors = item[0], item[1], item[2]
            # Try to get format from events for this file
            fmt = next((e.format for e in all_events if e.file == fname and e.format), "—")
        table_rows.append({
            "File": Path(fname).name,
            "Events": total,
            "Errors": errors,
            "Format": fmt or "—",
        })
    st.table(table_rows)
else:
    st.caption("No file summary available.")

st.divider()

# --- Top error codes ---
st.subheader("Top Message Codes")
codes = a.get("summary", {}).get("codes", [])
if codes:
    shown = list(codes)[:int(top_n)]
    max_code_count = shown[0][1] if shown else 1
    for code, count in shown:
        bar_width = int((count / max_code_count) * 25)
        bar = "█" * bar_width
        st.markdown(
            f'<div style="font-family:monospace;margin:2px 0">'
            f'<span style="display:inline-block;width:12em;font-weight:bold">{code}</span>'
            f'<span style="display:inline-block;width:4em;text-align:right;margin-right:0.5em">{count}</span>'
            f'<span style="color:#7C3AED">{bar}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )
else:
    st.caption("No message codes detected.")

st.divider()

# --- Incidents detected ---
st.subheader("Incidents Detected")
groups = grouped.get("groups", [])
if groups:
    for g in groups:
        _conf_raw = g.get("confidence", 0.0)
        confidence = _conf_raw.get("score", 0.5) if isinstance(_conf_raw, dict) else float(_conf_raw or 0)
        if confidence >= 0.75:
            badge_color = "#DC2626"
            badge_label = "HIGH"
        elif confidence >= 0.45:
            badge_color = "#F59E0B"
            badge_label = "MEDIUM"
        else:
            badge_color = "#94A3B8"
            badge_label = "LOW"

        # First event time
        all_g_events = []
        for t in g.get("triggers", []):
            all_g_events.extend(t.get("events", []))
        first_ts = None
        if all_g_events:
            first_ts = getattr(all_g_events[0], "ts", None)

        systems = g.get("systems", [])
        system_count = len(systems) if systems else len({
            e.system_label for t in g.get("triggers", [])
            for e in t.get("events", [])
            if e.system_label
        })

        header_parts = [f"**{g['name']}**"]
        if first_ts:
            header_parts.append(f"First seen: `{first_ts}`")
        if system_count > 0:
            header_parts.append(f"{system_count} system(s) affected")

        st.markdown(
            f'<div style="border:1px solid #334155;border-radius:6px;padding:0.75em;margin-bottom:0.75em">'
            f'<span style="background:{badge_color};color:white;border-radius:4px;padding:2px 6px;'
            f'font-size:0.75em;font-weight:bold;margin-right:0.5em">{badge_label}</span>'
            f'{"  ·  ".join(header_parts)}'
            f'<br><span style="color:#94A3B8;font-size:0.9em">{g.get("narrative","")}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )
else:
    st.caption("No incident groups detected.")

st.divider()

# --- What Changed? ---
what_changed = compare_periods(filtered_events)
if what_changed:
    with st.expander(f"What Changed? ({len(what_changed)} day transitions)"):
        render_what_changed(what_changed)
