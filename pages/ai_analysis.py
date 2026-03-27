"""LogPilot — AI Analysis: Incident AI Assistant + Trace to Code."""
import streamlit as st

a = st.session_state.get("analysis")
if a is None:
    st.info("Upload and analyze log files on the **Home** page first.")
    st.stop()

st.title("AI Analysis")
st.info("Incident AI Assistant, Trace to Code, screenshots, symptoms context, AI history.")

# TODO: Agent 3 implements this page
# - Incident AI Assistant (select incident group, run AI)
# - Trace to Code panel
# - Screenshots sent to AI
# - Symptoms from Home as context
# - AI History per incident
# - Import from app_incident.py: render_incident_assistant
