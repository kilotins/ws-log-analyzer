"""LogPilot — Home page: upload, configure, and analyze."""
import streamlit as st

st.title("Home")
st.info("This page will contain: file upload, screenshot upload, file list, "
        "log format selector, max lines, sample INFO, symptoms, AI model, and Analyze button. "
        "See M72 spec for details.")

# TODO: Agent 1 implements this page
# - Upload log files (drag & drop, zip support)
# - Upload screenshots (for AI context)
# - Files list with status icons
# - Log format selectbox
# - Max lines per file number_input
# - Sample INFO events checkbox
# - Symptoms text_area
# - AI Model selectbox
# - Analyze button (runs parse + precompute_analysis, stores in session_state.analysis)
