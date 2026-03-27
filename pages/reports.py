"""LogPilot — Reports: Technical Report, Leadership Brief, Jira Tickets."""
import streamlit as st

a = st.session_state.get("analysis")
if a is None:
    st.info("Upload and analyze log files on the **Home** page first.")
    st.stop()

st.title("Reports")
st.info("Technical Report (PDF/HTML), Leadership Brief (PDF/HTML), Jira Tickets.")

# TODO: Agent 4 implements this page
# Three sub-sections using st.tabs or st.header:
# 1. Technical Report
#    - Report preset (Technical / Custom)
#    - Section picker (checkboxes)
#    - Export: PDF / HTML buttons
# 2. Leadership Brief
#    - Premium PDF export button
#    - HTML export button
# 3. Jira Tickets
#    - Generated tickets per incident group
#    - Preview & edit
#    - Export CSV / Create in Jira / Publish to Confluence
# - Import from app_render.py, app_jira.py
