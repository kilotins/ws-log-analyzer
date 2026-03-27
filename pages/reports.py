"""LogPilot — Reports: Technical Report, Leadership Brief, Jira Tickets."""
from __future__ import annotations

import hashlib
from datetime import datetime

import streamlit as st

from app_render import (
    render_global_filters,
    _apply_global_filters_from_state,
    _collect_ai_content,
)

# ── Guard: require analysis ───────────────────────────────────────────────────

a = st.session_state.get("analysis")
if a is None:
    st.info("Upload and analyze log files on the **Home** page first.")
    st.stop()

# ── Title ─────────────────────────────────────────────────────────────────────

st.title("Reports")

# ── Apply global filters ──────────────────────────────────────────────────────

render_global_filters(a["events"])
_is_filtered, display_events = _apply_global_filters_from_state(a["events"])

if _is_filtered:
    from logpilot.analysis import precompute_analysis
    _filter_hash = hashlib.sha256(
        str(len(display_events)).encode()
        + str(sum(hash(e.ts or "") for e in display_events[:100])).encode()
    ).hexdigest()[:12]
    _filter_key = f"_fa_{len(display_events)}_{_filter_hash}"
    _old_fa = [k for k in st.session_state if k.startswith("_fa_") and k != _filter_key]
    for _ok in _old_fa[:-4]:
        del st.session_state[_ok]
    fa = st.session_state.get(_filter_key)
    if fa is None:
        fa = precompute_analysis(
            display_events,
            top_n=a.get("top_n", 10),
            samples_n=a.get("samples_n", 5),
            hist_minutes=a.get("hist_minutes", 1),
        )
        st.session_state[_filter_key] = fa
    _pa = fa
else:
    display_events = a["events"]
    _pa = a

if _is_filtered:
    st.info(f"Export contains filtered data ({len(display_events)} of {a['total_events']} events).")

events_for_export = display_events

# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_tech, tab_brief, tab_jira = st.tabs(["Technical Report", "Leadership Brief", "Jira Tickets"])

# ── Tab 1: Technical Report ───────────────────────────────────────────────────

with tab_tech:
    _ai_content = _collect_ai_content()
    _ai_note = " + AI analysis" if _ai_content else ""

    _PRESETS = {
        "Custom": None,
        "Quick Diagnosis": {"onset", "causes", "samples"},
        "Incident Report": {"onset", "causes", "hung", "timeline", "samples", "ai"},
        "Deep Analysis": None,
    }
    _preset = st.selectbox(
        "Report preset",
        list(_PRESETS.keys()),
        key="report_preset",
        help="Quick Diagnosis: causes + samples. Incident Report: full triage. Deep Analysis: everything.",
    )

    from logpilot import REPORT_SECTIONS
    _available: dict[str, str] = {}
    _s = _pa.get("summary", {})
    _itl = _pa.get("incident_timeline")
    if _itl and _itl.get("trigger_dt"):
        _available["onset"] = REPORT_SECTIONS["onset"]
    if len(_pa.get("file_summary", [])) > 1:
        _available["files"] = REPORT_SECTIONS["files"]
    if _s.get("levels"):
        _available["levels"] = REPORT_SECTIONS["levels"]
    if _s.get("codes"):
        _available["codes"] = REPORT_SECTIONS["codes"]
    if _s.get("exceptions"):
        _available["exceptions"] = REPORT_SECTIONS["exceptions"]
    if _s.get("tags"):
        _available["tags"] = REPORT_SECTIONS["tags"]
    if _pa.get("causes"):
        _available["causes"] = REPORT_SECTIONS["causes"]
    if _pa.get("hung"):
        _available["hung"] = REPORT_SECTIONS["hung"]
    _available["timeline"] = REPORT_SECTIONS["timeline"]
    _available["samples"] = REPORT_SECTIONS["samples"]
    _ai_entries: list[dict] = []
    if _ai_content:
        _available["ai"] = REPORT_SECTIONS["ai"]
        if _ai_content.get("incident"):
            _q = _ai_content.get("incident_query", "")
            _model = _ai_content.get("incident_model", "AI")
            _preview = (_q[:50] + "...") if len(_q) > 50 else (_q or "Current analysis")
            _ai_entries.append({"key": "incident", "label": f"{_model}: {_preview}"})

    _selected_sections: set[str] = set()
    _selected_ai: set[str] = set()
    _preset_sections = _PRESETS.get(_preset)
    if _available:
        with st.expander("Report sections", expanded=(_preset == "Custom")):
            _cols = st.columns(3)
            for i, (key, label) in enumerate(_available.items()):
                _default = (key in _preset_sections) if _preset_sections is not None else True
                with _cols[i % 3]:
                    if st.checkbox(label, value=_default, key=f"export_sec_{key}_{_preset}"):
                        _selected_sections.add(key)
            if "ai" in _selected_sections and len(_ai_entries) > 1:
                st.caption("Include AI responses:")
                for ae in _ai_entries:
                    if st.checkbox(ae["label"], value=True, key=f"export_ai_{ae['key']}"):
                        _selected_ai.add(ae["key"])
            elif "ai" in _selected_sections:
                _selected_ai = {ae["key"] for ae in _ai_entries}

    # Filter AI content based on selection
    if _ai_content and _selected_ai and _selected_ai != {ae["key"] for ae in _ai_entries}:
        _filtered_ai: dict = {}
        if "incident" in _selected_ai and _ai_content.get("incident"):
            _filtered_ai["incident"] = _ai_content["incident"]
            _filtered_ai["incident_model"] = _ai_content.get("incident_model", "AI")
            _filtered_ai["incident_query"] = _ai_content.get("incident_query", "")
        _kept_ask = []
        for idx, entry in enumerate(_ai_content.get("ask_ai", [])):
            if f"ask_{idx}" in _selected_ai:
                _kept_ask.append(entry)
        if _kept_ask:
            _filtered_ai["ask_ai"] = _kept_ask
        _ai_content = _filtered_ai or None

    _sections = _selected_sections if _selected_sections != set(_available.keys()) else None

    # Build export (PDF and HTML only)
    from logpilot import render_pdf_report, render_html_report, ReportConfig
    _base = f"report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
    _sec_hash = hashlib.md5(
        str(sorted(_selected_sections)).encode() + str(sorted(_selected_ai)).encode()
    ).hexdigest()[:12]
    _ai_hash = hashlib.md5(str(_ai_content).encode()).hexdigest()[:12] if _ai_content else "none"

    def _build_cfg():
        return ReportConfig(
            events=events_for_export,
            top_n=a.get("top_n", 10),
            samples_n=a.get("samples_n", 5),
            hist_minutes=a.get("hist_minutes", 1),
            analysis=_pa,
            ai_content=_ai_content,
            sections=_sections,
        )

    _col_pdf, _col_html = st.columns(2)

    with _col_pdf:
        _pdf_key = f"_export_PDF_{len(events_for_export)}_{_ai_hash}_{_sec_hash}"
        _cached_pdf = st.session_state.get(_pdf_key)
        if not _cached_pdf:
            _cached_pdf = render_pdf_report(_build_cfg())
            st.session_state[_pdf_key] = _cached_pdf
        st.download_button(
            label=f"Export PDF{_ai_note}",
            data=_cached_pdf,
            file_name=f"{_base}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

    with _col_html:
        _html_key = f"_export_HTML_{len(events_for_export)}_{_ai_hash}_{_sec_hash}"
        _cached_html = st.session_state.get(_html_key)
        if not _cached_html:
            _cached_html = render_html_report(_build_cfg())
            st.session_state[_html_key] = _cached_html
        st.download_button(
            label=f"Export HTML{_ai_note}",
            data=_cached_html,
            file_name=f"{_base}.html",
            mime="text/html",
            use_container_width=True,
        )

# ── Tab 2: Leadership Brief ───────────────────────────────────────────────────

with tab_brief:
    _ai_content_brief = _collect_ai_content()
    _has_analysis = bool(_ai_content_brief and _ai_content_brief.get("incident"))

    if not _has_analysis:
        st.info(
            "Leadership Brief requires an AI incident analysis. "
            "Run the **Incident AI Assistant** on the Overview page first."
        )
    else:
        _ai_model_label = _ai_content_brief.get("incident_model", "AI")
        st.caption(f"AI rewrites the incident analysis for non-technical leadership (via {_ai_model_label})")

        _leadership_brief = st.session_state.get("_leadership_brief")

        if not _leadership_brief:
            _brief_clicked = st.button(
                "Generate Leadership Brief",
                help="Creates a 1-page non-technical summary for management",
                use_container_width=True,
            )
            if _brief_clicked:
                _brief_analysis = _ai_content_brief.get("incident", "")
                from logpilot.ai import build_leadership_brief_prompt
                _brief_prompt = build_leadership_brief_prompt(_brief_analysis)
                _incident_provider = st.session_state.get("_incident_provider", "claude")
                _incident_model_id = st.session_state.get("_incident_model_id", "claude-sonnet-4-6")
                try:
                    from app_ai import call_ai_provider, _log_probe
                    _brief_placeholder = st.empty()
                    _brief_placeholder.info("Generating leadership brief...")
                    _brief_text, _ = call_ai_provider(
                        _incident_provider, _incident_model_id, _brief_prompt, max_tokens=4096
                    )
                    _brief_placeholder.empty()
                    if _brief_text:
                        st.session_state["_leadership_brief"] = _brief_text
                        _log_probe(
                            "Leadership Brief", _incident_provider, _incident_model_id,
                            f"[SYSTEM]\n{_brief_prompt['system']}\n\n[USER]\n{_brief_prompt['user'][:500]}...",
                            _brief_text,
                        )
                        st.rerun()
                except Exception as _brief_err:
                    from app_ai import _sanitize_error
                    st.error(f"Brief generation failed: {_sanitize_error(str(_brief_err))}")
        else:
            st.markdown(_leadership_brief)
            _brief_col1, _brief_col2 = st.columns(2)
            with _brief_col1:
                from report_renderer import render_html as _render_brief_html
                _brief_html = _render_brief_html(
                    _leadership_brief,
                    title="Leadership Incident Brief — LogPilot",
                )
                st.download_button(
                    "Download Brief (HTML)",
                    data=_brief_html,
                    file_name="leadership_brief.html",
                    mime="text/html",
                    use_container_width=True,
                )
            with _brief_col2:
                from logpilot.reports.brief_pdf import render_brief_pdf
                _brief_pdf = render_brief_pdf(
                    _leadership_brief,
                    title="Incident Brief for Leadership",
                )
                st.download_button(
                    "Download Brief (PDF)",
                    data=_brief_pdf,
                    file_name="leadership_brief.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )

            if st.button("Regenerate Brief", use_container_width=True):
                del st.session_state["_leadership_brief"]
                st.rerun()

# ── Tab 3: Jira Tickets ───────────────────────────────────────────────────────

with tab_jira:
    from app_jira import render_jira_tickets
    display_causes = _pa.get("causes", [])
    if display_causes:
        render_jira_tickets(display_causes, _pa)
    else:
        st.info("No incident groups detected. Heuristic analysis needs to find causes before tickets can be generated.")
