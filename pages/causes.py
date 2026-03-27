"""LogPilot — Causes & Fixes: heuristic-detected likely causes."""
import streamlit as st

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
    # Rebuild causes for filtered events if filtering is active
    from logpilot.heuristics import likely_causes as _likely_causes
    causes = _likely_causes(filtered_events)
else:
    causes = a.get("causes", [])

st.title("Causes & Fixes")

if not causes:
    st.info("No known issue patterns detected in the current log set.")
    st.stop()

from logpilot.heuristics import group_into_incidents, collect_group_evidence

grouped = group_into_incidents(causes)
groups = grouped.get("groups", [])
ungrouped = grouped.get("ungrouped", [])

# Severity badge helper
_SEVERITY_STYLES = {
    "ERROR": ("background:#EF4444;color:white", "ERROR"),
    "FATAL": ("background:#DC2626;color:white", "FATAL"),
    "CRITICAL": ("background:#DC2626;color:white", "CRITICAL"),
    "WARN": ("background:#F59E0B;color:#1e1e1e", "WARN"),
    "WARNING": ("background:#F59E0B;color:#1e1e1e", "WARN"),
    "INFO": ("background:#7C3AED;color:white", "INFO"),
}

def _severity_badge(severity: str) -> str:
    style, label = _SEVERITY_STYLES.get(
        (severity or "").upper(),
        ("background:#94A3B8;color:white", severity or "?"),
    )
    return (
        f'<span style="{style};border-radius:4px;padding:2px 8px;'
        f'font-size:0.75em;font-weight:bold;margin-right:0.5em">{label}</span>'
    )

# --- Primary incident banner ---
for g in groups:
    if g.get("is_primary"):
        st.error(f"**Primary incident: {g['name']}** — {g.get('investigate_first', '')}")
        break

st.caption(f"{len(causes)} heuristic pattern(s) detected — {len(groups)} incident group(s), {len(ungrouped)} standalone finding(s)")
st.divider()

# --- Grouped incidents ---
for g in groups:
    total = g["total_count"]
    rank = g.get("rank", "")
    cascade = g.get("cascade_order", "")
    _conf_raw = g.get("confidence", 0.0)
    confidence = _conf_raw.get("score", 0.5) if isinstance(_conf_raw, dict) else float(_conf_raw or 0)
    conf_pct = int(confidence * 100)

    if g.get("is_primary"):
        label = "root cause"
    elif cascade == "concurrent":
        label = "concurrent"
    else:
        label = "downstream"

    st.markdown(f"### Step {rank} — {g['name']} ({total} events) — {label}")
    st.markdown(f"*{g['narrative']}*")

    directive = g.get("investigate_first", "")
    if directive:
        if g.get("is_primary"):
            st.info(f"**{directive}**")
        elif cascade == "concurrent":
            st.warning(directive)
        else:
            st.caption(directive)

    # Confidence score
    st.caption(f"Confidence: {conf_pct}%")

    # Evidence
    evidence_lines = collect_group_evidence(g)
    if evidence_lines:
        st.code("\n".join(evidence_lines), language=None)

    # Triggers
    for t in g["triggers"]:
        sev = t.get("severity", "")
        st.markdown(
            _severity_badge(sev)
            + f"**{t['title']}** — {t['count']} event{'s' if t['count'] != 1 else ''}",
            unsafe_allow_html=True,
        )
        cause_text = t.get("cause", "")
        if cause_text:
            st.caption(cause_text)

    # Effects
    for e in g["effects"]:
        sev = e.get("severity", "")
        st.markdown(
            "&nbsp;&nbsp;&nbsp;&nbsp;↳ "
            + _severity_badge(sev)
            + f"{e['title']} ({e['count']} event{'s' if e['count'] != 1 else ''})",
            unsafe_allow_html=True,
        )

    # Fixes
    all_fixes = []
    for t in g["triggers"]:
        all_fixes.extend(t.get("fixes", []))
    if all_fixes:
        with st.expander("Suggested fixes"):
            for fix in all_fixes:
                st.markdown(f"- {fix}")

    st.divider()

# --- Ungrouped (standalone) findings ---
if ungrouped:
    if groups:
        st.markdown("### Other Findings")
    for c in ungrouped:
        sev = c.get("severity", "")
        count = c.get("count", 0)
        st.markdown(
            _severity_badge(sev)
            + f"**{c['title']}** — {count} event{'s' if count != 1 else ''}",
            unsafe_allow_html=True,
        )
        cause_text = c.get("cause", "")
        if cause_text:
            st.markdown(f"*Likely cause:* {cause_text}")

        evidence = c.get("evidence", [])
        if evidence:
            with st.expander("Evidence"):
                for ev in evidence:
                    st.text(ev)

        fixes = c.get("fixes", [])
        if fixes:
            with st.expander("Suggested fixes"):
                for fix in fixes:
                    st.markdown(f"- {fix}")

        st.markdown("---")
