"""LogPilot — Settings: license, theme, API keys, integrations, spend."""
import streamlit as st

st.title("Settings")
st.info("License, theme, API keys, local AI, source code, integrations, spend, debug mode.")

# TODO: Agent 1 implements this page
# Sections (in order):
# 1. License key input + status badge
# 2. Theme selector (System/Light/Dark)
# 3. Cloud API Keys (Claude, Gemini, OpenAI) — expander
# 4. Local / Inhouse AI — preset, endpoint, model, test connection
# 5. Link Source Code — path input
# 6. Integrations — Jira URL, token, Confluence config
# 7. Cloud Spend — render_spend_tab()
# 8. Debug mode toggle
# 9. Clear AI cache & history button
# - Import from app_shared, app_ai, app_spend, app_jira
