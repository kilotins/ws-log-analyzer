"""LogPilot — Events: drill-down filters and event samples."""
from __future__ import annotations

import streamlit as st

from app_render import (
    render_global_filters,
    render_sample_filters,
    render_samples,
    _apply_global_filters_from_state,
    _apply_sample_filters_from_state,
)

# ── Guard: require analysis ───────────────────────────────────────────────────

a = st.session_state.get("analysis")
if a is None:
    st.info("Upload and analyze log files on the **Home** page first.")
    st.stop()

# ── Title ─────────────────────────────────────────────────────────────────────

st.title("Events")

# ── Global filters (source + severity) ───────────────────────────────────────

render_global_filters(a["events"])
_is_filtered, display_events = _apply_global_filters_from_state(a["events"])

if _is_filtered:
    from logpilot.analysis import precompute_analysis
    import hashlib as _hl
    _filter_hash = _hl.sha256(
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
    display_samples = fa["samples"]
else:
    display_samples = a["samples"]

# ── Sample count ──────────────────────────────────────────────────────────────

samples_n = st.number_input(
    "Sample events",
    min_value=1,
    max_value=20,
    value=a.get("samples_n", 5),
    key="events_samples_n",
    help="Number of representative sample events to show",
)
if samples_n != a.get("samples_n", 5):
    from logpilot.analysis import pick_samples
    display_samples = pick_samples(display_events, samples_n)

# ── Drill-down Filters ────────────────────────────────────────────────────────

render_sample_filters(display_events)

# ── Event Samples ─────────────────────────────────────────────────────────────

_sample_filtered, sample_display_events = _apply_sample_filters_from_state(display_events)
if _sample_filtered:
    from logpilot.analysis import precompute_analysis as _pa_fn
    _sf = _pa_fn(
        sample_display_events,
        top_n=a.get("top_n", 10),
        samples_n=samples_n,
        hist_minutes=a.get("hist_minutes", 1),
    )
    drill_samples = _sf["samples"]
else:
    drill_samples = display_samples

with st.expander(f"Event Samples ({len(drill_samples)} shown)", expanded=True):
    render_samples(drill_samples, all_events=display_events)

# Context view (if an event was selected via "Show context" button)
_ctx_idx = st.session_state.get("_context_event_idx", -1)
if _ctx_idx >= 0:
    from app_render import render_context_view
    render_context_view(_ctx_idx, a["events"])
    if st.button("Close context view"):
        st.session_state._context_event_idx = -1
        st.rerun()
