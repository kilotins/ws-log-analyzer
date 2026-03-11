"""Report section renderers for the Streamlit GUI."""
from __future__ import annotations

import re as _re
import streamlit as st
from pathlib import Path

from logpilot import render_histogram, precompute_analysis, render_pdf_report, render_csv_report, render_xml_report
from app_constants import LEVEL_COLORS


def _looks_like_splunk(code):
    """Heuristic: does this code block look like a Splunk query?"""
    lower = code.lower()
    return any(kw in lower for kw in ("index=", "sourcetype=", "| timechart", "| stats",
                                       "| table", "| where", "| eval"))


def _split_combined_splunk(code):
    """Split a code block containing multiple -- separated Splunk queries.

    Returns list of {description, query} dicts. If no -- separators found,
    returns a single entry.
    """
    chunks = _re.split(r'^-- +', code, flags=_re.MULTILINE)
    if len(chunks) <= 1:
        return [{"description": "Splunk query", "query": code.strip()}]

    results = []
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        lines = chunk.split("\n", 1)
        desc = lines[0].strip()
        query = lines[1].strip() if len(lines) > 1 else ""
        if query and _looks_like_splunk(query):
            results.append({"description": desc, "query": query})
    return results


def _on_copy_code(code):
    """Copy an error code into the AI query input field."""
    st.session_state.claude_query_input = code


def render_code_row(code, count):
    """Render a message code row with count and a copy-to-query button."""
    cols = st.columns([3, 1])
    with cols[0]:
        st.text(f"  {count:>4}  {code}")
    with cols[1]:
        st.button("Ask AI",
                  key=f"ask_{code}",
                  on_click=_on_copy_code, args=(code,),
                  help=f"Copy {code} to the AI query field below")


def render_summary(s, error_count, file_count, file_summary):
    """Render metrics, top exceptions, codes, levels, and per-file breakdown."""
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Events", s["total_events"])
    m2.metric("Errors", error_count)
    m3.metric("Files", file_count)
    level_counts = dict(s["levels"])
    m4.metric("Warnings", level_counts.get("WARNING", 0))

    if len(file_summary) > 1:
        st.divider()
        st.subheader("Per-File Breakdown")
        for fname, total, errors in file_summary:
            err_note = f" ({errors} errors)" if errors else ""
            st.text(f"  {Path(fname).name}: {total} events{err_note}")

    st.divider()
    exc_col, code_col = st.columns(2)
    with exc_col:
        st.subheader("Top Exceptions")
        if s["exceptions"]:
            for name, count in s["exceptions"]:
                st.text(f"  {count:>4}  {name}")
        else:
            st.caption("None detected")
    with code_col:
        st.subheader("Top Message Codes")
        if s["codes"]:
            for code, count in s["codes"]:
                render_code_row(code, count)
        else:
            st.caption("None detected")

    if s["tags"]:
        st.divider()
        st.subheader("Signal Tags")
        for tag, count in s["tags"]:
            st.text(f"  {count:>4}  {tag}")


def render_likely_causes(causes):
    """Render likely causes section."""
    if causes:
        for c in causes:
            st.markdown(f"**{c['title']}** ({c['count']} event{'s' if c['count'] != 1 else ''})")
            st.markdown(f"*Likely cause:* {c['cause']}")
            for fix in c["fixes"]:
                st.markdown(f"- {fix}")
    else:
        st.caption("No known issue patterns detected.")


def _render_splunk_query(sq, idx):
    """Render a single Splunk query as a numbered card."""
    st.markdown(f"**{idx}. {sq['description']}**")
    st.code(sq["query"], language="spl")


def render_splunk_section(splunk):
    """Render baseline Splunk searches + Claude-enhanced searches from history."""
    st.subheader("Baseline searches")
    if splunk:
        for idx, sq in enumerate(splunk, 1):
            _render_splunk_query(sq, idx)
    else:
        st.caption("No baseline Splunk queries generated.")

    history = st.session_state.claude_history
    entries_with_splunk = [e for e in history if e.get("splunk_queries")]
    if entries_with_splunk:
        st.markdown("---")
        st.subheader("Claude-enhanced searches")
        for h_idx, entry in enumerate(entries_with_splunk):
            st.markdown(f"***{entry['query']}** ({entry['timestamp']})*")
            for q_idx, sq in enumerate(entry["splunk_queries"], 1):
                _render_splunk_query(sq, q_idx)
    else:
        st.markdown("---")
        st.caption("Run an AI analysis to get context-aware Splunk searches.")


def render_hung_threads(hung):
    """Render hung thread drilldown."""
    if not hung:
        st.caption("No hung threads detected.")
        return
    for t in hung:
        st.markdown(f"**{t['thread_name']}** ({t['count']} occurrence{'s' if t['count'] != 1 else ''})")
        ts_parts = []
        if t["first_ts"]:
            ts_parts.append(f"First: {t['first_ts']}")
        if t["last_ts"] and t["last_ts"] != t["first_ts"]:
            ts_parts.append(f"Last: {t['last_ts']}")
        if t["hex_ids"]:
            ts_parts.append(f"Thread IDs: {', '.join('0x' + h for h in t['hex_ids'])}")
        if ts_parts:
            st.text("  " + " | ".join(ts_parts))
        if t["stack_sample"]:
            st.code("\n".join(t["stack_sample"]), language="java")
        st.code(t["splunk_query"], language="spl")


def render_timeline(hist):
    """Render timeline histogram."""
    if hist:
        lines = render_histogram(hist)
        st.code("\n".join(lines))
    else:
        st.caption("No timestamped events.")


def render_incident_timeline(itl):
    """Render an incident timeline using Plotly."""
    if not itl:
        st.caption("No error events with timestamps found.")
        return

    import plotly.graph_objects as go

    trigger = itl["trigger_event"]
    trigger_dt = itl["trigger_dt"]
    window_events = itl["window_events"]

    times = []
    labels = []
    colors = []
    sizes = []
    hovers = []

    level_colors = LEVEL_COLORS

    for w in window_events:
        e = w["event"]
        dt = w["dt"]
        level = e.get("level") or "UNKNOWN"
        is_trigger = (e is trigger)

        times.append(dt)
        code_label = e.get("code") or ""
        exc_label = (e.get("exception") or "").rsplit(".", 1)[-1] if e.get("exception") else ""
        label = f"{level} {code_label} {exc_label}".strip()
        labels.append(label)
        colors.append(level_colors.get(level, "#6c757d"))
        sizes.append(16 if is_trigger else 9)

        offset = w["offset_seconds"]
        sign = "+" if offset >= 0 else ""
        hover = (
            f"<b>{level}</b> {sign}{offset:.1f}s<br>"
            f"Time: {dt.strftime('%H:%M:%S.%f')[:-3]}<br>"
        )
        if code_label:
            hover += f"Code: {code_label}<br>"
        if exc_label:
            hover += f"Exception: {exc_label}<br>"
        if e.get("thread_id"):
            hover += f"Thread: 0x{e['thread_id']}<br>"
        text_preview = (e.get("text") or "")[:120].replace("<", "&lt;")
        if text_preview:
            hover += f"<br>{text_preview}..."
        hovers.append(hover)

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=times,
        y=labels,
        mode="markers",
        marker=dict(color=colors, size=sizes, line=dict(width=1, color="white")),
        hovertext=hovers,
        hoverinfo="text",
    ))

    fig.add_shape(
        type="line",
        x0=trigger_dt, x1=trigger_dt,
        y0=0, y1=1,
        yref="paper",
        line=dict(dash="dash", color="#dc3545", width=1),
    )
    fig.add_annotation(
        x=trigger_dt, y=1, yref="paper",
        text="First error", showarrow=False,
        font=dict(color="#dc3545", size=11),
        yshift=10,
    )

    fig.update_layout(
        title="",
        xaxis_title="Time",
        yaxis_title=None,
        height=max(250, len(set(labels)) * 35 + 100),
        margin=dict(l=10, r=10, t=30, b=40),
        showlegend=False,
        xaxis=dict(type="date"),
        yaxis=dict(autorange="reversed"),
    )

    trigger_code = trigger.get("code") or ""
    trigger_exc = (trigger.get("exception") or "").rsplit(".", 1)[-1]
    trigger_label = f"{trigger.get('level')} {trigger_code} {trigger_exc}".strip()
    st.caption(
        f"Showing {len(window_events)} events within "
        f"±{itl['window_seconds']}s of first error: "
        f"**{trigger_label}** at {trigger_dt.strftime('%H:%M:%S.%f')[:-3]}"
    )
    st.plotly_chart(fig, use_container_width=True)

    # Text fallback for accessibility
    from collections import Counter
    level_counts = Counter(e["event"].get("level", "UNKNOWN") for e in window_events)
    level_parts = [f"{count} {lvl}" for lvl, count in level_counts.most_common()]
    time_start = min(times).strftime("%H:%M:%S")
    time_end = max(times).strftime("%H:%M:%S")
    st.caption(f"Summary: {', '.join(level_parts)} from {time_start} to {time_end}")


_SAMPLES_PAGE_SIZE = 10


_SEVERITY_ORDER = {"FATAL": 0, "SEVERE": 1, "ERROR": 2, "WARNING": 3, "WARN": 4,
                   "INFO": 5, "AUDIT": 6, "DEBUG": 7, "UNKNOWN": 8}


def render_samples(samples):
    """Render sample events sorted by severity, with pagination."""
    if not samples:
        st.caption("No events to display.")
        return

    # Sort by severity (most critical first)
    samples = sorted(samples, key=lambda e: _SEVERITY_ORDER.get(e.get("level") or "UNKNOWN", 8))
    total = len(samples)
    # Determine how many to show
    # Reset pagination when analysis changes
    current_total = len(samples)
    if st.session_state.get("_samples_total") != current_total:
        st.session_state["_samples_show_all"] = False
        st.session_state["_samples_total"] = current_total
    show_all = st.session_state.get("_samples_show_all", False)
    if total > _SAMPLES_PAGE_SIZE and not show_all:
        visible = samples[:_SAMPLES_PAGE_SIZE]
    else:
        visible = samples

    for idx, e in enumerate(visible, start=1):
        header = f"{idx}. {e['level'] or 'UNKNOWN'}"
        if e["code"]:
            header += f" {e['code']}"
        if e["exception"]:
            header += f" -- {e['exception']}"
        if e["ts"]:
            header += f" ({e['ts']})"
        st.markdown(f"**{header}**")
        parts = []
        if e["tags"]:
            parts.append(f"Tags: {', '.join(e['tags'])}")
        if e["thread_id"]:
            parts.append(f"Thread: 0x{e['thread_id']}")
        if e["root_cause"] and e["root_cause"] != e["exception"]:
            parts.append(f"Root cause: {e['root_cause']}")
        if parts:
            st.text("  " + " | ".join(parts))
        st.code(e["text"][:4000], language="text")

    # Show "Show all" button if there are more samples
    if total > _SAMPLES_PAGE_SIZE and not show_all:
        if st.button(f"Show all {total} samples", key="samples_show_all_btn"):
            st.session_state["_samples_show_all"] = True
            st.rerun()


def _apply_event_filters(events, levels, code_prefix, exception_types, time_range):
    """Filter events using AND logic. Returns a new list (never modifies original)."""
    filtered = list(events)

    if levels:
        level_set = set(levels)
        filtered = [e for e in filtered if (e.get("level") or "UNKNOWN") in level_set]

    if code_prefix:
        prefix = code_prefix.strip().upper()
        filtered = [e for e in filtered if e.get("code") and e["code"].upper().startswith(prefix)]

    if exception_types:
        exc_set = set(exception_types)
        filtered = [e for e in filtered if e.get("exception") in exc_set]

    if time_range and len(time_range) == 2:
        t_start, t_end = time_range
        if t_start or t_end:
            from logpilot import parse_ts_datetime
            result = []
            for e in filtered:
                ts = e.get("ts")
                if not ts:
                    continue
                dt = parse_ts_datetime(ts)
                if dt is None:
                    continue
                t = dt.time()
                if t_start and t < t_start:
                    continue
                if t_end and t > t_end:
                    continue
                result.append(e)
            filtered = result

    return filtered


def render_event_filters(events):
    """Render event filter widgets inside an expander. Returns filtered events or None if no filters active."""
    _n_levels = len({e.get("level") or "UNKNOWN" for e in events})
    _n_exc = len({e.get("exception") for e in events if e.get("exception")})
    _filter_label = f"Event Filters — {_n_levels} severity levels, {_n_exc} exception types"
    with st.expander(_filter_label, expanded=False):
        # Collect available values from events
        all_levels = sorted({e.get("level") or "UNKNOWN" for e in events})
        all_exceptions = sorted({e.get("exception") for e in events if e.get("exception")})

        col_level, col_code = st.columns(2)
        with col_level:
            selected_levels = st.multiselect(
                "Severity Levels",
                options=all_levels,
                default=[],
                key="filter_levels",
                help="Show only events with selected severity levels",
            )
        with col_code:
            code_prefix = st.text_input(
                "Code Prefix",
                value="",
                key="filter_code_prefix",
                placeholder="e.g. SRVE, WSVR, CWWK",
                help="Show only events whose message code starts with this prefix",
            )

        col_exc, col_time = st.columns(2)
        with col_exc:
            selected_exceptions = st.multiselect(
                "Exception Types",
                options=all_exceptions,
                default=[],
                key="filter_exceptions",
                help="Show only events with selected exception types",
            )
        with col_time:
            use_time = st.checkbox("Filter by time range", key="filter_use_time")
            time_range = None
            if use_time:
                t_col1, t_col2 = st.columns(2)
                from datetime import time as dt_time
                with t_col1:
                    t_start = st.time_input("Start time", value=dt_time(0, 0), key="filter_time_start")
                with t_col2:
                    t_end = st.time_input("End time", value=dt_time(23, 59, 59), key="filter_time_end")
                time_range = (t_start, t_end)

        has_filters = bool(selected_levels or code_prefix.strip() or selected_exceptions or (use_time and time_range))

        if has_filters:
            filtered = _apply_event_filters(events, selected_levels, code_prefix, selected_exceptions, time_range)
            st.info(f"Showing {len(filtered)} of {len(events)} events after filtering.")
            return filtered

    return None


def render_report_sections(a, log=None, lookup_cache=None, store_cache=None):
    """Render all report sections from persisted analysis dict."""
    from app_ai import render_ask_claude

    st.success(f"Parsed {a['total_events']} events from {a['file_count']} file(s). "
               f"Report saved as `{a['report_name']}`.")

    # --- Event Filters (placed before downloads so filter state is known) ---
    filtered_events = render_event_filters(a["events"])
    _is_filtered = filtered_events is not None
    _filter_note = ""
    if _is_filtered:
        _filter_note = f" (filtered: {len(filtered_events)} of {a['total_events']})"

    if _filter_note:
        st.info(f"Downloads contain the full unfiltered report.{_filter_note}")
    # Generate reports lazily (on-demand at download time)
    events = a["events"]
    _pa = precompute_analysis(events, a.get("top_n", 10), a.get("samples_n", 5), a.get("hist_minutes", 1))

    _fmt_col, _dl_col = st.columns([1, 2])
    with _fmt_col:
        _export_fmt = st.selectbox(
            "Export format",
            ["Markdown", "JSON", "PDF", "CSV", "XML"],
            key="export_format",
            label_visibility="collapsed",
        )
    with _dl_col:
        _base = a["report_name"]
        if _export_fmt == "Markdown":
            _data, _fname, _mime = a["report_md"], _base, "text/markdown"
        elif _export_fmt == "JSON":
            _data, _fname, _mime = a["report_json"], _base.replace(".md", ".json"), "application/json"
        elif _export_fmt == "PDF":
            _data, _fname, _mime = render_pdf_report(events, _analysis=_pa), _base.replace(".md", ".pdf"), "application/pdf"
        elif _export_fmt == "CSV":
            _data, _fname, _mime = render_csv_report(events), _base.replace(".md", ".csv"), "text/csv"
        else:  # XML
            _data, _fname, _mime = render_xml_report(events), _base.replace(".md", ".xml"), "application/xml"
        st.download_button(
            label=f"Export {_export_fmt}",
            data=_data,
            file_name=_fname,
            mime=_mime,
            use_container_width=True,
        )

    st.markdown("---")

    if filtered_events is not None:
        # Memoize filtered analysis by event count to avoid recomputing on every rerun
        _filter_key = f"_fa_{len(filtered_events)}_{id(filtered_events)}"
        fa = st.session_state.get(_filter_key)
        if fa is None:
            fa = precompute_analysis(
                filtered_events,
                top_n=a.get("top_n", 10),
                samples_n=a.get("samples_n", 5),
                hist_minutes=a.get("hist_minutes", 1),
            )
            st.session_state[_filter_key] = fa
        display_summary = fa["summary"]
        display_error_count = sum(1 for e in filtered_events if e.get("level") in ("ERROR", "SEVERE", "FATAL"))
        display_causes = fa["causes"]
        display_splunk = fa["splunk"]
        display_hung = fa["hung"]
        display_hist = fa["hist"]
        display_samples = fa["samples"]
        display_events = filtered_events
        from logpilot import incident_timeline as _itl_fn
        display_itl = _itl_fn(filtered_events)
    else:
        display_summary = a["summary"]
        display_error_count = a["error_count"]
        display_causes = a["causes"]
        display_splunk = a["splunk"]
        display_hung = a["hung"]
        display_hist = a["hist"]
        display_samples = a["samples"]
        display_events = a["events"]
        display_itl = a.get("incident_timeline")

    with st.expander("Summary", expanded=True):
        render_summary(display_summary, display_error_count, a["file_count"], a["file_summary"])

    if display_causes:
        with st.expander(f"Likely Causes & Fixes ({len(display_causes)} detected)"):
            render_likely_causes(display_causes)

    with st.expander("Ask AI for help"):
        render_ask_claude(display_events, log=log, lookup_cache=lookup_cache, store_cache=store_cache)

    # Render AI responses outside the expander to avoid scroll issues with long content
    from app_ai import render_ai_responses
    render_ai_responses()

    claude_splunk_count = sum(len(e.get("splunk_queries", []))
                               for e in st.session_state.claude_history)
    splunk_label = f"Suggested Splunk Searches ({len(display_splunk)} baseline"
    if claude_splunk_count:
        splunk_label += f" + {claude_splunk_count} Claude"
    splunk_label += ")"
    with st.expander(splunk_label):
        render_splunk_section(display_splunk)

    with st.expander(f"Hung Thread Analysis ({len(display_hung)} threads)"):
        render_hung_threads(display_hung)

    # Only show timeline if there's meaningful variation (max/min ratio >= 2)
    _show_timeline = False
    if display_hist:
        counts = [count for _, count, _ in display_hist]
        if counts:
            min_c = min(counts)
            max_c = max(counts)
            _show_timeline = min_c == 0 or (max_c / max(min_c, 1)) >= 2
    if _show_timeline:
        with st.expander("Timeline", expanded=False):
            render_timeline(display_hist)

    itl_label = "Incident Timeline"
    if display_itl:
        n = len(display_itl["window_events"])
        itl_label += f" ({n} events around first error)"
    with st.expander(itl_label):
        render_incident_timeline(display_itl)

    with st.expander(f"Event Samples ({len(display_samples)} shown)"):
        render_samples(display_samples)
