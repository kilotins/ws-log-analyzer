"""LogPilot — Debug: Application Log and AI Probe."""
import streamlit as st

st.title("Debug")
st.info("Application Log (last 100 lines, filterable) and AI Probe (request/response inspector).")

# TODO: Agent 5 implements this page
# - Application Log sub-section
#   - Level filter (ALL/INFO/WARNING/ERROR)
#   - Show last 100 lines from LOG_FILE
# - AI Probe sub-section
#   - Show all AI calls from session_state._ai_probe_log
#   - Each call: expandable with request/response payload
#   - Clear Probe Log button
# - Import LOG_FILE from app_shared
