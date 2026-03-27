"""LogPilot — Jira & Confluence integration."""
import streamlit as st

a = st.session_state.get("analysis")
if a is None:
    st.info("Upload and analyze log files on the **Home** page first.")
    st.stop()

st.title("Jira & Confluence")

from app_jira import render_jira_tickets

render_jira_tickets(a.get("causes", []), a)
