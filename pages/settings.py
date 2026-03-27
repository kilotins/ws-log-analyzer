"""LogPilot — Settings: license, theme, API keys, integrations, spend."""
from __future__ import annotations

import streamlit as st

from app import (
    log, _load_json_file, _save_json_file, _THEME_FILE, CACHE_DIR,
    _load_saved_api_key, _save_api_key, _load_saved_gemini_key, _save_gemini_key,
    _load_saved_openai_key, _save_openai_key, _save_local_ai_settings,
    provider_history_manager,
)
from logpilot.license import require_license, validate_token, allowed_providers
from app_ai import AI_MODELS, LOCAL_AI_PRESETS, discover_local_models, clear_all_ai_history
from app_jira import render_jira_sidebar
from app_spend import render_spend_tab

st.title("Settings")

# --- 1. License key ---
if require_license():
    st.subheader("License")
    _LICENSE_FILE = CACHE_DIR / ".license_key"
    if not st.session_state.license_key:
        try:
            if _LICENSE_FILE.exists():
                st.session_state.license_key = _LICENSE_FILE.read_text().strip()
        except Exception:
            pass

    _license_input = st.text_input(
        "License key",
        value=st.session_state.license_key,
        type="password",
        placeholder="LP-1-...",
        help="Required for cloud AI features. Contact eric@item.no for a license.",
    )
    if _license_input != st.session_state.license_key:
        st.session_state.license_key = _license_input
        try:
            _LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
            _LICENSE_FILE.write_text(_license_input)
            _LICENSE_FILE.chmod(0o600)
        except Exception:
            pass
        st.rerun()

    _lic_info = validate_token(st.session_state.license_key)
    if _lic_info and _lic_info.valid:
        if _lic_info.days_left <= 30:
            st.warning(f"**{_lic_info.name}** \u2014 expires in {_lic_info.days_left} days")
        else:
            st.success(f"**{_lic_info.name}** \u2014 {_lic_info.days_left} days remaining")
    elif st.session_state.license_key:
        st.error("Invalid or expired license key")
    else:
        st.caption("No license \u2014 cloud AI features disabled")

    st.divider()

# --- 2. Theme ---
st.subheader("Theme")
_theme_options = {"System default": "system", "Light": "light", "Dark": "dark"}
_current_theme = st.session_state.get("_app_theme", "system")
_theme_label = next((k for k, v in _theme_options.items() if v == _current_theme), "System default")
_selected_theme = st.selectbox(
    "Theme",
    list(_theme_options.keys()),
    index=list(_theme_options.keys()).index(_theme_label),
    key="settings_theme_select",
)
if _theme_options[_selected_theme] != _current_theme:
    st.session_state._app_theme = _theme_options[_selected_theme]
    try:
        _save_json_file(_THEME_FILE, {"theme": _theme_options[_selected_theme]})
    except Exception:
        pass
    import streamlit.config as _stcfg
    if _theme_options[_selected_theme] == "dark":
        _stcfg.set_option("theme.base", "dark")
        _stcfg.set_option("theme.backgroundColor", "#0d1117")
        _stcfg.set_option("theme.secondaryBackgroundColor", "#161b22")
        _stcfg.set_option("theme.textColor", "#e6edf3")
    else:
        _stcfg.set_option("theme.base", "light")
        _stcfg.set_option("theme.backgroundColor", "#FFFFFF")
        _stcfg.set_option("theme.secondaryBackgroundColor", "#F8FAFC")
        _stcfg.set_option("theme.textColor", "#0F172A")
    st.rerun()

st.divider()

# --- 3. Cloud API Keys ---
st.subheader("Cloud API Keys")

if require_license():
    _lic_providers = allowed_providers(st.session_state.get("license_key", ""))
else:
    _lic_providers = ["claude", "gemini", "openai", "local"]

_configured_keys = sum(1 for k in [
    st.session_state.api_key if "claude" in _lic_providers else "",
    st.session_state.gemini_api_key if "gemini" in _lic_providers else "",
    st.session_state.openai_api_key if "openai" in _lic_providers else "",
] if k)
_max_keys = sum(1 for p in ["claude", "gemini", "openai"] if p in _lic_providers)
_keys_label = (
    f"API Keys ({_configured_keys}/{_max_keys} configured)"
    if _configured_keys
    else "API Keys (none configured)"
)

with st.expander(_keys_label, expanded=_configured_keys == 0):
    if "claude" in _lic_providers:
        # Lazy-load from keychain on first visit
        if not st.session_state.api_key:
            st.session_state.api_key = _load_saved_api_key()
        api_key = st.text_input(
            "Anthropic API Key",
            value=st.session_state.api_key,
            type="password",
            placeholder="sk-ant-...",
            help="Required for Claude AI. Get a key at console.anthropic.com/settings/keys",
        )
        if api_key != st.session_state.api_key:
            _save_api_key(api_key)
            st.session_state.api_key = api_key

    if "gemini" in _lic_providers:
        if not st.session_state.gemini_api_key:
            st.session_state.gemini_api_key = _load_saved_gemini_key()
        gemini_key = st.text_input(
            "Gemini API Key",
            value=st.session_state.gemini_api_key,
            type="password",
            placeholder="AIza...",
            help="Required for Gemini AI. Get a key at aistudio.google.com/apikey",
        )
        if gemini_key != st.session_state.gemini_api_key:
            _save_gemini_key(gemini_key)
            st.session_state.gemini_api_key = gemini_key

    if "openai" in _lic_providers:
        if not st.session_state.openai_api_key:
            st.session_state.openai_api_key = _load_saved_openai_key()
        openai_key = st.text_input(
            "OpenAI API Key",
            value=st.session_state.openai_api_key,
            type="password",
            placeholder="sk-...",
            help="Required for OpenAI models. Get a key at platform.openai.com/api-keys",
        )
        if openai_key != st.session_state.openai_api_key:
            _save_openai_key(openai_key)
            st.session_state.openai_api_key = openai_key

    if "gemini" not in _lic_providers or "openai" not in _lic_providers:
        st.caption("Upgrade to Pro to unlock all AI providers. Contact eric@item.no.")

st.divider()

# --- 4. Local / Inhouse AI ---
st.subheader("Local / Inhouse AI")
with st.expander("Local AI settings", expanded=False):
    _prev_preset = st.session_state.get("_local_prev_preset", "")
    _preset_names = list(LOCAL_AI_PRESETS.keys())
    _saved_preset = st.session_state.get("_local_saved_preset", "")
    _preset_index = _preset_names.index(_saved_preset) if _saved_preset in _preset_names else 0
    _preset = st.selectbox(
        "Preset",
        _preset_names,
        index=_preset_index,
        key="settings_local_ai_preset",
        help="Select your local AI server type",
    )
    _preset_cfg = LOCAL_AI_PRESETS[_preset]

    if _preset != _prev_preset and _prev_preset:
        _preset_url = _preset_cfg["base_url"]
        if _preset_url:
            st.session_state.local_ai_endpoint = _preset_url
            st.session_state._local_conn_status = "not_tested"
            st.session_state._local_models = []
    st.session_state._local_prev_preset = _preset

    _local_endpoint = st.text_input(
        "Endpoint URL",
        value=st.session_state.local_ai_endpoint,
        placeholder="http://localhost:1234/v1",
        help="OpenAI-compatible API endpoint",
    )
    if _local_endpoint != st.session_state.local_ai_endpoint:
        st.session_state.local_ai_endpoint = _local_endpoint
        st.session_state._local_conn_status = "not_tested"
        st.session_state._local_models = []
        _save_local_ai_settings(
            _local_endpoint, st.session_state.local_ai_model,
            st.session_state.local_ai_api_key, _preset,
        )

    _btn_col, _status_col = st.columns([1, 2])
    _endpoint = st.session_state.local_ai_endpoint
    _api_key = st.session_state.local_ai_api_key

    with _btn_col:
        _test_clicked = st.button("Test connection", key="settings_local_test_conn",
                                  use_container_width=True)

    if _test_clicked and _endpoint:
        with st.spinner("Connecting..."):
            result = discover_local_models(_endpoint, _api_key)
        st.session_state._local_conn_status = result["status"]
        st.session_state._local_conn_error = result["error"]
        st.session_state._local_models = result["models"]
        if result["models"]:
            if not st.session_state.local_ai_model or st.session_state.local_ai_model not in result["models"]:
                st.session_state.local_ai_model = result["models"][0]
            _save_local_ai_settings(
                _endpoint, st.session_state.local_ai_model, _api_key, _preset,
            )
            st.rerun()

    with _status_col:
        _conn = st.session_state._local_conn_status
        if _conn == "connected":
            n = len(st.session_state._local_models)
            st.success(f"Connected \u2014 {n} model{'s' if n != 1 else ''} found")
        elif _conn == "failed":
            st.error(st.session_state._local_conn_error or "Connection failed")
        elif _conn == "no_models":
            st.warning(st.session_state._local_conn_error or "No models found")
        else:
            st.caption("Not tested")

    _discovered = st.session_state._local_models
    if _discovered:
        _refresh_col, _model_col = st.columns([1, 3])
        with _refresh_col:
            if st.button("Refresh", key="settings_local_refresh_models", use_container_width=True):
                result = discover_local_models(_endpoint, _api_key)
                st.session_state._local_conn_status = result["status"]
                st.session_state._local_conn_error = result["error"]
                st.session_state._local_models = result["models"]
                st.rerun()
        with _model_col:
            _current = st.session_state.local_ai_model
            _idx = _discovered.index(_current) if _current in _discovered else 0
            _selected_model = st.selectbox(
                "Model",
                _discovered,
                index=_idx,
                key="settings_local_model_select",
                label_visibility="collapsed",
            )
            if _selected_model != st.session_state.local_ai_model:
                st.session_state.local_ai_model = _selected_model
                _save_local_ai_settings(_endpoint, _selected_model, _api_key, _preset)
    else:
        _manual_model = st.text_input(
            "Model name",
            value=st.session_state.local_ai_model,
            placeholder="e.g. llama-3.1-8b, mistral-7b, qwen2.5",
            help="Model ID as shown in your local server",
            key="settings_local_model_input",
        )
        if _manual_model != st.session_state.local_ai_model:
            st.session_state.local_ai_model = _manual_model
            _save_local_ai_settings(_endpoint, _manual_model, _api_key, _preset)

    with st.expander("Advanced", expanded=False):
        _local_key = st.text_input(
            "API Key (optional)",
            value=st.session_state.local_ai_api_key,
            placeholder="not-needed",
            help="Most local servers don't require an API key",
            key="settings_local_key_input",
        )
        if _local_key != st.session_state.local_ai_api_key:
            st.session_state.local_ai_api_key = _local_key
            _save_local_ai_settings(
                st.session_state.local_ai_endpoint,
                st.session_state.local_ai_model,
                _local_key,
                _preset,
            )

st.divider()

# --- 5. Link Source Code ---
st.subheader("Source Code (Trace to Code)")
with st.expander("Link source code (optional)", expanded=False):
    _repo = st.text_input(
        "Source code path",
        value=st.session_state.get("_code_repo_path", ""),
        placeholder="/path/to/your/project",
        help="LogPilot will search this directory (READ-ONLY) for code matching stacktraces in your logs",
        key="settings_code_repo_input",
    )
    st.session_state["_code_repo_path"] = _repo
    if _repo:
        from pathlib import Path as _P
        if _P(_repo).is_dir():
            st.success(f"Linked: {_repo}")
        else:
            st.warning("Directory not found")

st.divider()

# --- 6. Integrations (Jira / Confluence) ---
st.subheader("Integrations")
render_jira_sidebar()

st.divider()

# --- 7. Cloud Spend ---
st.subheader("Cloud Spend")
render_spend_tab()

st.divider()

# --- 8. Debug mode ---
st.subheader("Developer")
st.session_state.debug_payload = st.toggle(
    "Debug mode",
    value=st.session_state.debug_payload,
    help="Show Application Log and AI Probe tabs for debugging",
)

# --- 9. Clear AI cache & history ---
if st.session_state.get("_confirm_clear_cache"):
    st.warning("Clear all AI caches and history?")
    _cc1, _cc2 = st.columns(2)
    with _cc1:
        if st.button("Yes, clear", type="primary", use_container_width=True,
                     key="settings_confirm_clear_cache"):
            st.session_state._confirm_clear_cache = False
            clear_all_ai_history()
            log.info("cache Cleared all AI caches and history")
            st.success("AI cache and history cleared")
    with _cc2:
        if st.button("Cancel", use_container_width=True, key="settings_cancel_clear_cache"):
            st.session_state._confirm_clear_cache = False
            st.rerun()
elif st.button(
    "Clear AI cache & history",
    help="Clear all cached AI responses, answers, and conversation history",
):
    st.session_state._confirm_clear_cache = True
    st.rerun()
