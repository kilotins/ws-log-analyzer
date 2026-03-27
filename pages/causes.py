"""LogPilot — Causes & Fixes: heuristic-detected likely causes."""
import streamlit as st

a = st.session_state.get("analysis")
if a is None:
    st.info("Upload and analyze log files on the **Home** page first.")
    st.stop()

st.title("Causes & Fixes")
st.info("Likely Causes & Fixes — heuristic-detected causes with description, "
        "severity, hit count, and suggested fix.")

# TODO: Agent 2 implements this page
# - Render all causes from a["causes"]
# - Each cause: description, severity, hit count, suggested fix
# - Respect global severity/source filters from session_state
