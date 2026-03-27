"""LogPilot — Debug: Application Log and AI Probe."""
from pathlib import Path

import streamlit as st

# Resolve LOG_FILE: pages/ is one level below the app root
_APP_DIR = Path(__file__).parent.parent
LOGS_DIR = _APP_DIR / "logs"
LOG_FILE = LOGS_DIR / "app.log"

st.title("Debug")

_debug_sub_applog, _debug_sub_probe = st.tabs(["Application Log", "Probe"])

with _debug_sub_applog:
    _log_level_filter = st.selectbox(
        "Filter by level",
        ["ALL", "INFO", "WARNING", "ERROR"],
        key="log_level_filter",
    )
    if LOG_FILE.exists():
        _raw_lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        if _log_level_filter != "ALL":
            _raw_lines = [l for l in _raw_lines if f" {_log_level_filter:<5s}" in l
                          or f" {_log_level_filter} " in l]
        _display_lines = _raw_lines[-100:]
        if _display_lines:
            st.code("\n".join(_display_lines), language="log")
        else:
            st.caption("No matching log entries.")
    else:
        st.info("No application log yet.")

with _debug_sub_probe:
    _probe_log = st.session_state.get("_ai_probe_log", [])
    if _probe_log:
        if st.button("Clear Probe Log", key="clear_probe_log"):
            st.session_state._ai_probe_log = []
            st.rerun()
        for _entry in reversed(_probe_log):
            _ts = _entry.get("ts", "")
            _type = _entry.get("type", "")
            _provider = _entry.get("provider", "")
            _model = _entry.get("model", "")
            _error = _entry.get("error")
            _icon = "!" if _error else ">"
            _header = f"[{_icon}] {_ts}  {_type}  ({_provider} / {_model})"
            if _error:
                _header += f"  ERROR: {_error[:80]}"
            with st.expander(_header, expanded=False):
                _req = _entry.get("request", "")
                _resp = _entry.get("response", "")
                if _req:
                    st.markdown("**Request payload**")
                    st.code(_req[:20000], language="text")
                if _resp:
                    st.markdown("**Response payload**")
                    st.code(_resp[:20000], language="markdown")
                if _error:
                    st.markdown("**Error**")
                    st.code(_error, language="text")
    else:
        st.info("No AI calls recorded yet. Use AI Analysis to see payloads here.")
