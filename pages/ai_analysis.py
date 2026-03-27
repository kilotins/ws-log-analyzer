"""LogPilot — AI Analysis: Incident AI Assistant + Trace to Code."""
import streamlit as st

a = st.session_state.get("analysis")
if a is None:
    st.info("Upload and analyze log files on the **Home** page first.")
    st.stop()

st.title("AI Analysis")

from app import log, _lookup_cache, _store_cache
from app_incident import render_incident_assistant, process_pending_delete

# Process pending AI history deletions BEFORE rendering
process_pending_delete()

events = a.get("events", [])
render_incident_assistant(events, a, log=log, lookup_cache=_lookup_cache, store_cache=_store_cache)
