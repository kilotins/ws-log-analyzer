"""LogPilot — Overview dashboard: what did we find?"""
import streamlit as st

a = st.session_state.get("analysis")
if a is None:
    st.info("Upload and analyze log files on the **Home** page first.")
    st.stop()

st.title("Overview")
st.info("Dashboard page — metric cards, severity breakdown, files analyzed, "
        "top error codes, incidents detected, What Changed?")

# TODO: Agent 2 implements this page
# - Metric cards: events, files, errors, incidents
# - Severity breakdown (horizontal bars)
# - Files analyzed (each file: event count, error count, format)
# - Top error codes (most frequent, which files)
# - Incidents detected (incident groups with time, systems, confidence)
# - What Changed? (collapsible day transitions)
# - Top-N items parameter
