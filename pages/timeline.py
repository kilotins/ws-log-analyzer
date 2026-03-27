"""LogPilot — Timeline: cross-system timeline, incident timeline, cascades."""
import streamlit as st

a = st.session_state.get("analysis")
if a is None:
    st.info("Upload and analyze log files on the **Home** page first.")
    st.stop()

st.title("Timeline")

from app_render import (
    render_cross_system_timeline,
    render_incident_timeline,
    render_cascade_section,
    _apply_global_filters_from_state,
)
from logpilot import incident_timeline, precompute_analysis

# --- Parameters ---
col1, col2 = st.columns(2)
with col1:
    hist_bucket = st.number_input(
        "Histogram bucket (min)", min_value=1, max_value=60, value=1, key="tl_hist_bucket"
    )
with col2:
    timeline_window = st.number_input(
        "Timeline window (sec)", min_value=5, max_value=300, value=30, key="tl_window_sec"
    )

# Apply global severity/source filters from session state
_is_filtered, display_events = _apply_global_filters_from_state(a["events"])

# Recompute incident timeline with the selected window parameter
if _is_filtered or int(timeline_window) != 30 or int(hist_bucket) != 1:
    display_itl = incident_timeline(display_events, window_seconds=int(timeline_window))
else:
    display_itl = a.get("incident_timeline")

cascades = a.get("cascades", [])

# --- Cross-System Timeline ---
_sources = set(e.system_label or "" for e in display_events)
if len(_sources) >= 2:
    st.subheader(f"Cross-System Timeline ({len(_sources)} sources)")
    render_cross_system_timeline(display_events, cascades)
else:
    st.info("Cross-System Timeline requires logs from 2 or more sources.")

st.markdown("---")

# --- Incident Timeline ---
itl_label = "Incident Timeline"
if display_itl:
    n = len(display_itl.get("window_events", []))
    itl_label += f" ({n} events around first error)"
st.subheader(itl_label)
render_incident_timeline(display_itl)

st.markdown("---")

# --- Cross-System Cascades ---
if cascades and len(_sources) >= 2:
    render_cascade_section(cascades)
elif len(_sources) < 2:
    st.info("Cross-System Cascades require logs from 2 or more sources.")
else:
    st.info("No cascade patterns detected.")
