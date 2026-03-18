"""Report section renderers for the Streamlit GUI."""
from __future__ import annotations

import streamlit as st
from pathlib import Path

from logpilot import precompute_analysis, render_pdf_report, render_html_report, per_source_summary
from app_constants import LEVEL_COLORS




def _collect_ai_content() -> dict | None:
    """Collect AI triage and Ask AI responses from session_state for export."""
    ai = {}

    # Incident AI Assistant (current answer — may be triage or symptom-based)
    incident = st.session_state.get("_incident_answer")
    if incident:
        ai["incident"] = incident
        ai["incident_model"] = st.session_state.get("_incident_model", "AI")

    # Conversation history (all providers), excluding the current answer to avoid duplicates
    ask_ai = []
    for provider, hist_key, label in [
        ("Claude", "claude_history", "Claude"),
        ("Gemini", "gemini_history", "Gemini"),
        ("OpenAI", "openai_history", "OpenAI"),
        ("Local", "local_history", "Local AI"),
    ]:
        history = st.session_state.get(hist_key, [])
        for entry in history:
            # Skip if this entry's answer matches the current incident answer
            if incident and entry.get("answer") == incident:
                continue
            ask_ai.append({
                "query": entry.get("query", ""),
                "answer": entry.get("answer", ""),
                "provider": label,
                "timestamp": entry.get("timestamp", ""),
            })

    if ask_ai:
        ai["ask_ai"] = ask_ai

    return ai if ai else None


def render_summary(s, error_count, file_count, file_summary, events=None):
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

    if events is not None:
        source_summary = per_source_summary(events)
        if len(source_summary) > 1:
            st.divider()
            st.subheader("Per-Source Summary")
            _src_table = []
            for src in source_summary:
                _src_table.append({
                    "Source": src["label"],
                    "Format": src["format"],
                    "Events": src["total"],
                    "Errors": src["errors"],
                    "Top Code": src["top_codes"][0][0] if src["top_codes"] else "—",
                    "Top Exception": src["top_exceptions"][0][0] if src["top_exceptions"] else "—",
                })
            st.table(_src_table)

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
                st.text(f"  {count:>4}  {code}")
        else:
            st.caption("None detected")

    if s["tags"]:
        st.divider()
        st.subheader("Signal Tags")
        for tag, count in s["tags"]:
            st.text(f"  {count:>4}  {tag}")


def render_likely_causes(causes):
    """Render likely causes section with incident grouping."""
    if not causes:
        st.caption("No known issue patterns detected.")
        return

    from logpilot.analysis import group_into_incidents
    grouped = group_into_incidents(causes)

    for g in grouped["groups"]:
        total = g["total_count"]
        st.markdown(f"### 🔗 {g['name']} ({total} event{'s' if total != 1 else ''})")
        st.markdown(f"*{g['narrative']}*")

        # Triggers
        for t in g["triggers"]:
            st.markdown(f"**⚡ {t['title']}** ({t['count']} event{'s' if t['count'] != 1 else ''})")
            st.markdown(f"*Likely cause:* {t['cause']}")

        # Effects
        for e in g["effects"]:
            st.markdown(f"**↳ {e['title']}** ({e['count']} event{'s' if e['count'] != 1 else ''})")

        # Collected fixes from triggers
        all_fixes = []
        for t in g["triggers"]:
            all_fixes.extend(t["fixes"])
        if all_fixes:
            st.markdown("**Suggested fixes:**")
            for fix in all_fixes:
                st.markdown(f"- {fix}")
        st.divider()

    # Ungrouped findings
    if grouped["ungrouped"]:
        if grouped["groups"]:
            st.markdown("### Other Findings")
        for c in grouped["ungrouped"]:
            st.markdown(f"**{c['title']}** ({c['count']} event{'s' if c['count'] != 1 else ''})")
            st.markdown(f"*Likely cause:* {c['cause']}")
            for fix in c["fixes"]:
                st.markdown(f"- {fix}")


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


def _severity_bar_chart(times, levels, title_suffix="", trigger_dt=None, height=120):
    """Build a compact stacked bar histogram of events over time, colored by severity.

    Returns a Plotly figure. If *trigger_dt* is given, a vertical marker is drawn.
    """
    import plotly.graph_objects as go
    from datetime import timedelta
    from collections import Counter

    if not times:
        return None

    # Determine bucket width — aim for ~30-50 bars
    t_min, t_max = min(times), max(times)
    span = (t_max - t_min).total_seconds()
    if span <= 0:
        span = 1.0
    bucket_secs = max(1, span / 40)
    bucket_td = timedelta(seconds=bucket_secs)

    # Bucket events by time + severity
    severity_order = ["FATAL", "SEVERE", "ERROR", "WARNING", "WARN", "INFO", "AUDIT", "DEBUG", "UNKNOWN"]
    severity_colors = LEVEL_COLORS

    buckets: dict[int, Counter] = {}
    for t, lvl in zip(times, levels):
        b_idx = int((t - t_min).total_seconds() / bucket_secs)
        if b_idx not in buckets:
            buckets[b_idx] = Counter()
        norm_lvl = lvl if lvl in severity_colors else "UNKNOWN"
        buckets[b_idx][norm_lvl] += 1

    max_bucket = max(buckets.keys()) if buckets else 0
    bucket_starts = [t_min + timedelta(seconds=i * bucket_secs) for i in range(max_bucket + 1)]

    fig = go.Figure()
    for lvl in severity_order:
        counts = [buckets.get(i, Counter()).get(lvl, 0) for i in range(max_bucket + 1)]
        if sum(counts) == 0:
            continue
        fig.add_trace(go.Bar(
            x=bucket_starts,
            y=counts,
            name=lvl,
            marker_color=severity_colors.get(lvl, "#6B7280"),
            hovertemplate=f"{lvl}: %{{y}}<extra></extra>",
            width=bucket_secs * 900,  # width in ms for datetime axis
        ))

    if trigger_dt is not None:
        fig.add_shape(
            type="line",
            x0=trigger_dt, x1=trigger_dt,
            y0=0, y1=1, yref="paper",
            line=dict(dash="dash", color="#DC2626", width=2),
        )
        fig.add_annotation(
            x=trigger_dt, y=1, yref="paper",
            text="First error", showarrow=False,
            font=dict(color="#DC2626", size=10),
            yshift=8,
        )

    fig.update_layout(
        barmode="stack",
        height=height,
        margin=dict(l=10, r=10, t=8, b=30),
        xaxis=dict(type="date", showgrid=False),
        yaxis=dict(showticklabels=False, showgrid=False, title=None),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1,
                    font=dict(size=10)),
        hovermode="x unified",
        plot_bgcolor="rgba(0,0,0,0)",
    )

    return fig


def render_incident_timeline(itl):
    """Render a compact severity histogram around the first error."""
    if not itl:
        st.caption("No error events with timestamps found.")
        return

    from collections import Counter

    trigger = itl["trigger_event"]
    trigger_dt = itl["trigger_dt"]
    window_events = itl["window_events"]

    times = [w["dt"] for w in window_events]
    levels = [w["event"].get("level") or "UNKNOWN" for w in window_events]

    trigger_code = trigger.get("code") or ""
    trigger_exc = (trigger.get("exception") or "").rsplit(".", 1)[-1]
    trigger_label = f"{trigger.get('level')} {trigger_code} {trigger_exc}".strip()
    st.caption(
        f"Showing {len(window_events)} events within "
        f"\u00b1{itl['window_seconds']}s of first error: "
        f"**{trigger_label}** at {trigger_dt.strftime('%H:%M:%S.%f')[:-3]}"
    )

    fig = _severity_bar_chart(times, levels, trigger_dt=trigger_dt, height=130)
    if fig:
        st.plotly_chart(fig, use_container_width=True)

    # Summary line
    level_counts = Counter(levels)
    level_parts = [f"{count} {lvl}" for lvl, count in level_counts.most_common()]
    time_start = min(times).strftime("%H:%M:%S")
    time_end = max(times).strftime("%H:%M:%S")
    st.caption(f"Summary: {', '.join(level_parts)} from {time_start} to {time_end}")


_SAMPLES_PAGE_SIZE = 10


_SEVERITY_ORDER = {"FATAL": 0, "SEVERE": 1, "ERROR": 2, "WARNING": 3, "WARN": 4,
                   "INFO": 5, "AUDIT": 6, "DEBUG": 7, "UNKNOWN": 8}


def render_samples(samples, all_events=None):
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
        if all_events is not None and e.get("ts_utc"):
            if st.button("Show context", key=f"ctx_sample_{idx}"):
                try:
                    ev_idx = all_events.index(e)
                except ValueError:
                    ev_idx = -1
                st.session_state._context_event_idx = ev_idx

    # Show "Show all" button if there are more samples
    if total > _SAMPLES_PAGE_SIZE and not show_all:
        if st.button(f"Show all {total} samples", key="samples_show_all_btn"):
            st.session_state["_samples_show_all"] = True
            st.rerun()


def render_cross_system_timeline(events: list[dict], cascades: list[dict] | None = None):
    """Render stacked bar histograms per system source, colored by severity."""
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    from datetime import datetime, timedelta
    from collections import Counter

    # Filter to events with parseable timestamps
    timed = []
    for e in events:
        ts_utc = e.get("ts_utc")
        if not ts_utc:
            continue
        try:
            dt = datetime.fromisoformat(ts_utc)
        except (ValueError, TypeError):
            continue
        timed.append((e, dt))

    sources = sorted(set(e.get("system_label", "unknown") for e, _ in timed))

    if not timed or len(sources) < 2:
        return

    severity_order = ["FATAL", "SEVERE", "ERROR", "WARNING", "WARN", "INFO", "AUDIT", "DEBUG", "UNKNOWN"]
    severity_colors = LEVEL_COLORS

    # Determine global time range and bucket size
    all_dts = [dt for _, dt in timed]
    t_min, t_max = min(all_dts), max(all_dts)
    span = max((t_max - t_min).total_seconds(), 1.0)
    bucket_secs = max(1, span / 40)
    bucket_td = timedelta(seconds=bucket_secs)

    # One subplot row per source
    fig = make_subplots(
        rows=len(sources), cols=1,
        shared_xaxes=True,
        vertical_spacing=0.04,
        subplot_titles=sources,
    )

    max_bucket = int(span / bucket_secs)
    bucket_starts = [t_min + timedelta(seconds=i * bucket_secs) for i in range(max_bucket + 1)]

    for row_idx, source in enumerate(sources, start=1):
        # Bucket events for this source
        source_events = [(e, dt) for e, dt in timed if e.get("system_label", "unknown") == source]
        buckets: dict[int, Counter] = {}
        for e, dt in source_events:
            b_idx = min(int((dt - t_min).total_seconds() / bucket_secs), max_bucket)
            if b_idx not in buckets:
                buckets[b_idx] = Counter()
            lvl = e.get("level") or "UNKNOWN"
            norm_lvl = lvl if lvl in severity_colors else "UNKNOWN"
            buckets[b_idx][norm_lvl] += 1

        for lvl in severity_order:
            counts = [buckets.get(i, Counter()).get(lvl, 0) for i in range(max_bucket + 1)]
            if sum(counts) == 0:
                continue
            fig.add_trace(go.Bar(
                x=bucket_starts,
                y=counts,
                name=lvl,
                marker_color=severity_colors.get(lvl, "#6B7280"),
                hovertemplate=f"{lvl}: %{{y}}<extra></extra>",
                width=bucket_secs * 900,
                showlegend=(row_idx == 1),  # legend only on first row
                legendgroup=lvl,
            ), row=row_idx, col=1)

    bar_height = max(90, 120 - len(sources) * 5)
    fig.update_layout(
        barmode="stack",
        height=bar_height * len(sources) + 50,
        margin=dict(l=10, r=10, t=25, b=30),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1,
                    font=dict(size=10)),
        hovermode="x unified",
        plot_bgcolor="rgba(0,0,0,0)",
    )

    # Style subplots
    for i in range(1, len(sources) + 1):
        fig.update_yaxes(showticklabels=False, showgrid=False, row=i, col=1)
        fig.update_xaxes(showgrid=False, row=i, col=1)
    fig.update_xaxes(type="date")

    st.plotly_chart(fig, use_container_width=True)


def render_cascade_section(cascades: list[dict]):
    """Render detected cross-system cascade chains."""
    if not cascades:
        return

    st.subheader(f"Cross-System Cascades ({len(cascades)} detected)")
    for i, c in enumerate(cascades):
        conf_pct = int(c.get("confidence", 0) * 100)
        with st.expander(
            f"{c['pattern']} — {c['upstream_source']} → {c['downstream_source']} "
            f"(+{c['delay_seconds']}s, {conf_pct}% confidence)",
            expanded=(i == 0),
        ):
            # Upstream event
            up = c.get("upstream_event", {})
            st.markdown(f"**Upstream** ({c['upstream_source']}): `{up.get('code', '')}` "
                       f"{up.get('exception', '')} — {(up.get('text', '')[:200])}")

            # Downstream events
            for de in c.get("downstream_events", []):
                ev = de.get("event", {})
                st.markdown(f"**→ Downstream** ({ev.get('system_label', '')}, +{de['delay_s']}s): "
                           f"`{ev.get('code', '')}` {ev.get('exception', '')} — {(ev.get('text', '')[:200])}")


def render_context_view(selected_idx: int, events: list[dict], window_seconds: int = 30):
    """Show surrounding events from ALL sources around a selected event."""
    if selected_idx < 0 or selected_idx >= len(events):
        return

    selected = events[selected_idx]
    sel_ts = selected.get("ts_utc")
    if not sel_ts:
        st.warning("Selected event has no timestamp — cannot show context.")
        return

    from datetime import datetime, timedelta, timezone
    try:
        sel_dt = datetime.fromisoformat(sel_ts)
    except ValueError:
        return

    window_start = (sel_dt - timedelta(seconds=window_seconds)).isoformat()
    window_end = (sel_dt + timedelta(seconds=window_seconds)).isoformat()

    context_events = [
        e for e in events
        if e.get("ts_utc") and window_start <= e["ts_utc"] <= window_end
    ]

    st.markdown(f"**Context view** — ±{window_seconds}s around selected event "
               f"({len(context_events)} events from {len(set(e.get('system_label', '') for e in context_events))} sources)")

    # Build table data
    rows = []
    for e in context_events:
        is_selected = (e is selected)
        level = e.get("level", "")
        source = e.get("system_label", "")
        ts_display = e.get("ts", "") or e.get("ts_utc", "")
        code = e.get("code") or ""
        exc = e.get("exception") or ""
        preview = (e.get("text", "")[:100]).replace("\n", " ")

        marker = "→ " if is_selected else "  "
        rows.append({
            "": marker,
            "Time": ts_display[:19] if len(ts_display) > 19 else ts_display,
            "Source": source,
            "Level": level,
            "Code": code,
            "Exception": exc,
            "Preview": preview,
        })

    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)


def _apply_event_filters(events, levels, code_prefix, exception_types, time_range, sources: list[str] | None = None):
    """Filter events using AND logic. Returns a new list (never modifies original)."""
    filtered = list(events)

    if sources:
        filtered = [e for e in filtered if e.get("system_label", "unknown") in sources]

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


def _apply_filters_from_state(events):
    """Read filter widget values from session_state and apply them.

    Returns (is_filtered: bool, filtered_events: list).
    """
    levels = st.session_state.get("filter_levels", [])
    code_prefix = st.session_state.get("filter_code_prefix", "")
    exceptions = st.session_state.get("filter_exceptions", [])
    use_time = st.session_state.get("filter_use_time", False)
    sources = st.session_state.get("filter_sources", [])

    time_range = None
    if use_time:
        t_start = st.session_state.get("filter_time_start")
        t_end = st.session_state.get("filter_time_end")
        if t_start or t_end:
            time_range = (t_start, t_end)

    has_filters = bool(levels or (code_prefix and code_prefix.strip()) or exceptions or (use_time and time_range) or sources)

    if not has_filters:
        return False, events

    filtered = _apply_event_filters(events, levels, code_prefix, exceptions, time_range, sources=sources)
    return True, filtered


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

        all_sources = sorted(set(e.get("system_label", "unknown") for e in events))
        selected_sources = []
        if len(all_sources) > 1:
            selected_sources = st.multiselect(
                "System / Source",
                options=all_sources,
                default=[],
                key="filter_sources",
                help="Show only events from selected log sources",
            )

        has_filters = bool(selected_levels or code_prefix.strip() or selected_exceptions or (use_time and time_range) or selected_sources)

        if has_filters:
            filtered = _apply_event_filters(events, selected_levels, code_prefix, selected_exceptions, time_range, sources=selected_sources)
            st.info(f"Showing {len(filtered)} of {len(events)} events after filtering.")
            return filtered

    return None


def render_report_sections(a, log=None, lookup_cache=None, store_cache=None):
    """Render all report sections from persisted analysis dict.

    Layout order (troubleshooting flow):
      1. Summary — what happened?
      2. AI Cross-System Triage — what does AI think? (multi-source only)
      3. Ask AI — ask follow-up questions
      4. Event Filters — narrow down
      5. Cross-System Timeline — visual overview (multi-source only)
      6. Incident Timeline — zoom on first error
      7. Likely Causes & Fixes — heuristic matches
      8. Event Samples + Cascades — drill into data
      9. Export — download results
    """
    st.success(f"Parsed {a['total_events']} events from {a['file_count']} file(s). "
               f"Report saved as `{a['report_name']}`.")

    # --- Pre-compute filtered data from session_state (before rendering) ---
    # Filter widget values persist in session_state between reruns, so we can
    # apply filters before the widgets are rendered in the layout.
    _is_filtered, display_events = _apply_filters_from_state(a["events"])

    if _is_filtered:
        import hashlib as _hl
        _filter_hash = _hl.md5(str(len(display_events)).encode() + str(sum(hash(e.get("ts", "")) for e in display_events[:100])).encode()).hexdigest()[:12]
        _filter_key = f"_fa_{len(display_events)}_{_filter_hash}"
        fa = st.session_state.get(_filter_key)
        if fa is None:
            fa = precompute_analysis(
                display_events,
                top_n=a.get("top_n", 10),
                samples_n=a.get("samples_n", 5),
                hist_minutes=a.get("hist_minutes", 1),
            )
            st.session_state[_filter_key] = fa
        display_summary = fa["summary"]
        display_error_count = sum(1 for e in display_events if e.get("level") in ("ERROR", "SEVERE", "FATAL"))
        display_causes = fa["causes"]
        display_hung = fa["hung"]
        display_samples = fa["samples"]
        from logpilot import incident_timeline as _itl_fn
        display_itl = _itl_fn(display_events)
    else:
        display_summary = a["summary"]
        display_error_count = a["error_count"]
        display_causes = a["causes"]
        display_hung = a["hung"]
        display_samples = a["samples"]
        display_itl = a.get("incident_timeline")

    # --- 1. Summary ---
    with st.expander("Summary", expanded=True):
        render_summary(display_summary, display_error_count, a["file_count"], a["file_summary"], events=display_events)

    # --- 2. Incident AI Assistant (unified AI analysis) ---
    from app_incident import render_incident_assistant
    with st.expander("Incident AI Assistant"):
        render_incident_assistant(display_events, a, log=log,
                                  lookup_cache=lookup_cache, store_cache=store_cache)

    # --- 4. Event Filters (widgets — values already read above) ---
    render_event_filters(a["events"])

    # --- 5. Cross-System Timeline (multi-source only) ---
    _sources = set(e.get("system_label", "") for e in display_events)
    if len(_sources) >= 2:
        with st.expander(f"Cross-System Timeline ({len(_sources)} sources)"):
            cascades = a.get("cascades", [])
            render_cross_system_timeline(display_events, cascades)

    # --- 6. Incident Timeline ---
    itl_label = "Incident Timeline"
    if display_itl:
        n = len(display_itl["window_events"])
        itl_label += f" ({n} events around first error)"
    with st.expander(itl_label):
        render_incident_timeline(display_itl)

    # --- 7. Likely Causes & Fixes ---
    if display_causes:
        with st.expander(f"Likely Causes & Fixes ({len(display_causes)} detected)"):
            render_likely_causes(display_causes)

    # --- 8. Event Samples + Hung Threads + Cascades ---
    with st.expander(f"Event Samples ({len(display_samples)} shown)"):
        render_samples(display_samples, all_events=display_events)

    if display_hung:
        with st.expander(f"Hung Thread Analysis ({len(display_hung)} threads)"):
            render_hung_threads(display_hung)

    if len(_sources) >= 2:
        render_cascade_section(a.get("cascades", []))

    # Context view (if an event was selected)
    _ctx_idx = st.session_state.get("_context_event_idx", -1)
    if _ctx_idx >= 0:
        render_context_view(_ctx_idx, a["events"])
        if st.button("Close context view"):
            st.session_state._context_event_idx = -1
            st.rerun()

    # --- 9. Export ---
    st.markdown("---")
    events_for_export = display_events if _is_filtered else a["events"]
    _pa = precompute_analysis(events_for_export, a.get("top_n", 10), a.get("samples_n", 5), a.get("hist_minutes", 1))

    if _is_filtered:
        st.info(f"Export contains filtered data ({len(display_events)} of {a['total_events']} events).")

    # Collect AI content from session_state for export
    _ai_content = _collect_ai_content()

    st.subheader("Export Log Analysis Report")
    _ai_note = " + AI analysis" if _ai_content else ""
    _fmt_col, _dl_col = st.columns([1, 2])
    with _fmt_col:
        _export_fmt = st.selectbox(
            "Export format",
            ["PDF", "HTML", "Markdown", "JSON"],
            key="export_format",
            label_visibility="collapsed",
        )
    with _dl_col:
        _base = a["report_name"]
        from logpilot import render_markdown_report, render_json_report
        if _export_fmt == "Markdown":
            _md = render_markdown_report(events_for_export, _analysis=_pa, ai_content=_ai_content)
            _data, _fname, _mime = _md, _base, "text/markdown"
        elif _export_fmt == "JSON":
            _json = render_json_report(events_for_export, _analysis=_pa, ai_content=_ai_content)
            _data, _fname, _mime = _json, _base.replace(".md", ".json"), "application/json"
        elif _export_fmt == "HTML":
            _html = render_html_report(events_for_export, _analysis=_pa, ai_content=_ai_content)
            _data, _fname, _mime = _html, _base.replace(".md", ".html"), "text/html"
        else:  # PDF
            _data, _fname, _mime = render_pdf_report(events_for_export, _analysis=_pa, ai_content=_ai_content), _base.replace(".md", ".pdf"), "application/pdf"
        st.download_button(
            label=f"Export Log Analysis Report ({_export_fmt}){_ai_note}",
            data=_data,
            file_name=_fname,
            mime=_mime,
            use_container_width=True,
        )
