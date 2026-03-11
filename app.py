"""Streamlit GUI for the WebSphere Log Analyzer."""
from __future__ import annotations

import logging
import logging.handlers
import os
import streamlit as st
from collections import deque
from datetime import datetime
from pathlib import Path

from wslog import (
    parse_file, render_markdown_report, render_json_report,
    render_pdf_report, render_csv_report, render_xml_report,
    precompute_analysis, incident_timeline,
)

# --- Extracted modules ---
from app_ai import (
    PROVIDER_CONFIG, TOKEN_COSTS, AI_MODELS,
    estimate_cost, call_claude_api, call_gemini_api, call_openai_api,
    AI_RATE_LIMIT_SECONDS, build_ai_request_context,
    extract_splunk_from_response,
    run_claude_analysis, run_gemini_analysis, run_openai_analysis,
    init_provider_config,
)
from app_render import (
    _looks_like_splunk, _split_combined_splunk,
    render_code_row, render_summary, render_report_sections,
    render_splunk_section,
)
from app_constants import CACHE_TTL_SECONDS, MAX_CACHE_ENTRIES as _MAX_CACHE_ENTRIES_DEFAULT, MAX_UPLOAD_MB
from app_realtime import (
    _LEVEL_COLORS, _LEVEL_HIGHLIGHT_RE, _highlight_line,
    _is_safe_rt_path, _rt_poll, _rt_live_view, _RT_BUFFER_SIZE,
)
from app_audit import (
    _AUDIT_MODELS, _AUDIT_SYSTEM_PROMPT, _AUDIT_LIGHT_CSS,
    _AUDIT_FILES_FULL, _AUDIT_FILES_COMPACT,
    _extract_signatures, _collect_audit_sources,
    _run_audit_claude, _run_audit_gemini, _run_audit_openai,
    _run_audit, _COMPACT_MAX_LINES,
)
from app_spend import render_spend_tab

# --- Paths and directories ---
_APP_DIR = Path(__file__).parent
UPLOADS_DIR = _APP_DIR / "uploads"
REPORTS_DIR = _APP_DIR / "reports"
CACHE_DIR = _APP_DIR / "cache"
LOGS_DIR = _APP_DIR / "logs"
UPLOADS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
CACHE_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

LOG_FILE = LOGS_DIR / "app.log"


class _JsonLogFormatter(logging.Formatter):
    """Emit one JSON object per log line."""
    def format(self, record):
        import json as _json
        return _json.dumps({
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "msg": record.getMessage(),
        }, ensure_ascii=False)


def _setup_logging():
    """Configure application logging with rotating file handler."""
    logger = logging.getLogger("wslog_app")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8",
    )
    use_json = os.environ.get("WSLOG_LOG_FORMAT", "").lower() == "json"
    if use_json:
        handler.setFormatter(_JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-5s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
    logger.addHandler(handler)
    return logger


log = _setup_logging()
log.info("startup Application started")

# --- Cache and history files ---
CACHE_FILE = CACHE_DIR / "ai_responses.json"
# Migrate old cache file name
_old_cache = CACHE_DIR / "claude_responses.json"
if _old_cache.exists() and not (CACHE_DIR / "ai_responses.json").exists():
    _old_cache.rename(CACHE_FILE)
HISTORY_FILE = CACHE_DIR / "claude_history.json"
GEMINI_HISTORY_FILE = CACHE_DIR / "gemini_history.json"
OPENAI_HISTORY_FILE = CACHE_DIR / "openai_history.json"


MAX_CACHE_ENTRIES = _MAX_CACHE_ENTRIES_DEFAULT
MAX_HISTORY_ENTRIES = 50


# --- JSON helpers (shared by multiple modules) ---
def _load_json_file(path: Path, default: object) -> object:
    """Load a JSON file, returning default on error."""
    if path.exists():
        try:
            import json
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return default


def _save_json_file(path: Path, data: object) -> None:
    """Save data as JSON atomically (tempfile + rename)."""
    import json, tempfile, os
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=path.parent, suffix=".tmp", delete=False, encoding="utf-8"
        ) as tmp:
            tmp_name = tmp.name
            json.dump(data, tmp, ensure_ascii=False, indent=2)
        os.replace(tmp_name, str(path))
    except Exception:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        raise


_CACHE_TTL_SECONDS = CACHE_TTL_SECONDS


def _load_file_cache():
    import time
    raw = _load_json_file(CACHE_FILE, {})
    now = time.time()
    cleaned = {}
    for k, v in raw.items():
        if isinstance(v, dict) and "ts" in v:
            if now - v["ts"] <= _CACHE_TTL_SECONDS:
                cleaned[k] = v
        else:
            cleaned[k] = {"text": v, "ts": now}
    return cleaned


def _save_file_cache(cache):
    if len(cache) > MAX_CACHE_ENTRIES:
        keys = list(cache.keys())
        for k in keys[:len(keys) - MAX_CACHE_ENTRIES]:
            del cache[k]
    _save_json_file(CACHE_FILE, cache)


def _load_provider_history(path: Path) -> list[dict]:
    """Load provider history from a JSON file."""
    data = _load_json_file(path, [])
    return data if isinstance(data, list) else []


def _save_provider_history(path: Path, history: list[dict]) -> None:
    """Save provider history, keeping only the most recent entries."""
    _save_json_file(path, history[-MAX_HISTORY_ENTRIES:])


_PROVIDER_HISTORY_FILES = {
    "claude": HISTORY_FILE,
    "gemini": GEMINI_HISTORY_FILE,
    "openai": OPENAI_HISTORY_FILE,
}

# Initialize the save_history callbacks in PROVIDER_CONFIG now that history files are set up
init_provider_config({
    "claude": lambda hist: _save_provider_history(HISTORY_FILE, hist),
    "gemini": lambda hist: _save_provider_history(GEMINI_HISTORY_FILE, hist),
    "openai": lambda hist: _save_provider_history(OPENAI_HISTORY_FILE, hist),
})


# --- Cache lookup/store helpers (passed to AI module) ---
def _lookup_cache(cache_key, session_cache, provider_label, user_query):
    """Check session cache then file cache. Returns cached value or None."""
    log.info("cache %s looking up key: %s", provider_label, cache_key[:80])
    cached = session_cache.get(cache_key)
    if cached:
        log.info("cache %s session cache HIT for: %s", provider_label, user_query[:60])
        return cached
    file_cache = _load_file_cache()
    cached = file_cache.get(cache_key)
    if cached:
        text = cached["text"] if isinstance(cached, dict) and "text" in cached else cached
        log.info("cache %s file cache HIT for: %s", provider_label, user_query[:60])
        session_cache[cache_key] = text
        return text
    log.info("cache %s MISS for: %s", provider_label, user_query[:60])
    return None


def _store_cache(cache_key, answer, session_cache):
    """Store answer in both session and file cache."""
    import time
    session_cache[cache_key] = answer
    file_cache = _load_file_cache()
    file_cache[cache_key] = {"text": answer, "ts": time.time()}
    _save_file_cache(file_cache)


# --- Session state defaults ---
_STATE_DEFAULTS = {
    "analysis": None,
    "claude_answer": None,
    "claude_query_label": None,
    "claude_cache": {},
    "claude_history": [],
    "selected_code": None,
    "selected_action": None,
    "api_key": "",
    "gemini_api_key": "",
    "openai_api_key": "",
    "gemini_answer": None,
    "gemini_query_label": None,
    "gemini_cache": {},
    "gemini_history": [],
    "openai_answer": None,
    "openai_query_label": None,
    "openai_cache": {},
    "openai_history": [],
    "debug_payload": False,
    "last_ai_call_ts": 0.0,
    "swedish_chef": False,
    "rt_enabled": False,
    "rt_running": False,
    "rt_paused": False,
    "rt_file": "",
    "rt_offset": 0,
    "rt_buffer": None,
    "_samples_show_all": False,
    "_samples_total": 0,
}

_EXPECTED_STATE_KEYS = set(_STATE_DEFAULTS.keys())

for key, default in _STATE_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = default
if st.session_state.rt_buffer is None:
    st.session_state.rt_buffer = deque(maxlen=_RT_BUFFER_SIZE)

# Session state schema validation — warn on unexpected keys in debug mode
if st.session_state.get("debug_payload"):
    _unexpected_keys = {k for k in st.session_state if k not in _EXPECTED_STATE_KEYS}
    if _unexpected_keys:
        log.warning("session_state Unexpected keys in session state: %s",
                    ", ".join(sorted(_unexpected_keys)))

# Load persisted history on fresh session
for _prov, _hpath in _PROVIDER_HISTORY_FILES.items():
    _hkey = f"{_prov}_history" if _prov != "claude" else "claude_history"
    if not st.session_state[_hkey]:
        st.session_state[_hkey] = _load_provider_history(_hpath)


def get_report_history(limit=20):
    """Return list of (path, mtime) for recent reports, newest first."""
    reports = sorted(REPORTS_DIR.glob("report_*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    return reports[:limit]


# --- Streamlit UI ---
st.set_page_config(page_title="WS Log Analyzer", page_icon="📋", layout="wide")
st.title("WebSphere Log Analyzer")

# --- Sidebar: API key ---
_KEYRING_SERVICE = "ws-log-analyzer"
_KEYRING_USERNAME = "anthropic_api_key"
_KEYRING_GEMINI_USERNAME = "gemini_api_key"
_KEYRING_OPENAI_USERNAME = "openai_api_key"

_KEYS_FILE = CACHE_DIR / ".api_keys.json"


def _load_keychain(username: str, env_var: str) -> str:
    """Load an API key from keyring -> local file -> env var -> empty string."""
    try:
        import keyring
        stored = keyring.get_password(_KEYRING_SERVICE, username)
        if stored:
            return stored
    except Exception:
        pass
    try:
        keys = _load_json_file(_KEYS_FILE, {})
        if isinstance(keys, dict) and keys.get(username):
            return keys[username]
    except Exception:
        pass
    return os.environ.get(env_var, "")


def _save_keychain(username: str, key: str, label: str = "API") -> None:
    """Store or remove an API key in keyring + local file."""
    try:
        import keyring
        if key:
            keyring.set_password(_KEYRING_SERVICE, username, key)
            log.info("settings %s key saved to system keychain", label)
        else:
            keyring.delete_password(_KEYRING_SERVICE, username)
            log.info("settings %s key removed from system keychain", label)
    except Exception as ex:
        log.warning("settings Could not save %s key to keychain: %s", label, ex)
    try:
        keys = _load_json_file(_KEYS_FILE, {})
        if not isinstance(keys, dict):
            keys = {}
        if key:
            keys[username] = key
        else:
            keys.pop(username, None)
        _save_json_file(_KEYS_FILE, keys)
        _KEYS_FILE.chmod(0o600)
        log.info("settings %s key saved to local file", label)
    except Exception as ex:
        log.warning("settings Could not save %s key to local file: %s", label, ex)


def _load_saved_api_key():
    return _load_keychain(_KEYRING_USERNAME, "ANTHROPIC_API_KEY")


def _save_api_key(key):
    _save_keychain(_KEYRING_USERNAME, key, "Claude")


def _load_saved_gemini_key():
    return _load_keychain(_KEYRING_GEMINI_USERNAME, "GEMINI_API_KEY")


def _save_gemini_key(key):
    _save_keychain(_KEYRING_GEMINI_USERNAME, key, "Gemini")


def _load_saved_openai_key():
    return _load_keychain(_KEYRING_OPENAI_USERNAME, "OPENAI_API_KEY")


def _save_openai_key(key):
    _save_keychain(_KEYRING_OPENAI_USERNAME, key, "OpenAI")


# Initialize from saved key on first load
if not st.session_state.api_key:
    st.session_state.api_key = _load_saved_api_key()

with st.sidebar:
    st.header("Settings")

    # Count configured keys for the expander label
    _configured_keys = sum(1 for k in [
        st.session_state.api_key,
        st.session_state.gemini_api_key,
        st.session_state.openai_api_key,
    ] if k)
    _keys_label = f"API Keys ({_configured_keys}/3 configured)" if _configured_keys else "API Keys (none configured)"
    with st.expander(_keys_label, expanded=_configured_keys == 0):
        api_key = st.text_input(
            "Anthropic API Key",
            value=st.session_state.api_key,
            type="password",
            placeholder="sk-ant-...",
            help="Required for Ask Claude. Get a key at console.anthropic.com/settings/keys",
        )
        if api_key != st.session_state.api_key:
            _save_api_key(api_key)
        st.session_state.api_key = api_key

        if not st.session_state.gemini_api_key:
            st.session_state.gemini_api_key = _load_saved_gemini_key()
        gemini_key = st.text_input(
            "Gemini API Key",
            value=st.session_state.gemini_api_key,
            type="password",
            placeholder="AIza...",
            help="Required for Ask Gemini. Get a key at aistudio.google.com/apikey",
        )
        if gemini_key != st.session_state.gemini_api_key:
            _save_gemini_key(gemini_key)
        st.session_state.gemini_api_key = gemini_key

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

    st.markdown("---")
    st.session_state.debug_payload = st.toggle(
        "Enable AI debug payloads",
        value=st.session_state.debug_payload,
        help="Show request/response payloads for Claude and Gemini API calls",
    )
    if st.session_state.get("_confirm_clear_cache"):
        st.warning("Clear all AI caches and history?")
        _cc1, _cc2 = st.columns(2)
        with _cc1:
            if st.button("Yes, clear", type="primary", use_container_width=True, key="confirm_clear_cache"):
                st.session_state._confirm_clear_cache = False
                st.session_state.claude_cache = {}
                st.session_state.claude_answer = None
                st.session_state.claude_query_label = None
                st.session_state.claude_history = []
                st.session_state.gemini_cache = {}
                st.session_state.gemini_answer = None
                st.session_state.gemini_query_label = None
                st.session_state.gemini_history = []
                st.session_state.openai_cache = {}
                st.session_state.openai_answer = None
                st.session_state.openai_query_label = None
                st.session_state.openai_history = []
                CACHE_FILE.unlink(missing_ok=True)
                for _hpath in _PROVIDER_HISTORY_FILES.values():
                    _hpath.unlink(missing_ok=True)
                log.info("cache Cleared all AI caches")
                st.success("Cache cleared")
        with _cc2:
            if st.button("Cancel", use_container_width=True, key="cancel_clear_cache"):
                st.session_state._confirm_clear_cache = False
                st.rerun()
    elif st.button("Clear AI cache", help="Clear cached Claude/Gemini/OpenAI responses and history"):
        st.session_state._confirm_clear_cache = True
        st.rerun()


# --- Tabs ---
tab_analyze, tab_realtime, tab_history, tab_audit, tab_spend, tab_applog = st.tabs(
    ["Analyze", "Realtime Console", "History", "Audit Report", "Cloud Spend", "Application Log"]
)

with tab_analyze:
    uploaded_files = st.file_uploader(
        "Upload WebSphere log file(s)",
        type=["log", "gz"],
        accept_multiple_files=True,
        help="SystemOut.log, SystemErr.log, or .gz compressed logs",
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        top_n = st.number_input("Top-N items", min_value=1, max_value=50, value=10,
                                help="Number of top exceptions, message codes, and signal tags shown in the summary.")
    with col2:
        samples_n = st.number_input("Sample events", min_value=1, max_value=20, value=5,
                                    help="Number of representative sample events shown per error category.")
    with col3:
        hist_minutes = st.number_input("Histogram bucket (min)", min_value=1, max_value=60, value=1,
                                       help="Time resolution for the timeline histogram.")

    if uploaded_files and st.button("Analyze", type="primary"):
        total_size = sum(f.size for f in uploaded_files)
        _over_limit = total_size > MAX_UPLOAD_MB * 1024 * 1024
        if _over_limit:
            st.error(f"Total upload size ({total_size / 1024 / 1024:.1f} MB) exceeds the {MAX_UPLOAD_MB} MB limit. Please upload smaller files.")
        elif total_size > 50 * 1024 * 1024:
            st.warning("Large files detected (>50MB). Parsing may take a while.")
        if _over_limit:
            st.stop()
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        all_events = []

        for uploaded in uploaded_files:
            upload_name = f"{ts}_{uploaded.name}"
            upload_path = UPLOADS_DIR / upload_name
            upload_path.write_bytes(uploaded.getvalue())
            log.info("upload File uploaded: %s (%d bytes)", uploaded.name, len(uploaded.getvalue()))

            with st.spinner(f"Parsing {uploaded.name}..."):
                try:
                    events = parse_file(upload_path)
                    all_events.extend(events)
                    log.info("analysis Parsed %d events from %s", len(events), uploaded.name)
                except Exception as ex:
                    log.error("analysis Failed to parse %s: %s", uploaded.name, ex)
                    st.error(f"Failed to parse {uploaded.name}: {ex}")

        if not all_events:
            st.error("No log events found. Possible causes: files may be empty, contain no recognizable timestamps, or use an unsupported format.")
        else:
            pa = precompute_analysis(all_events, top_n=top_n, samples_n=samples_n, hist_minutes=hist_minutes)
            s = pa["summary"]
            error_count = sum(1 for e in all_events if e.get("level") in ("ERROR", "SEVERE", "FATAL"))
            file_summary = pa["file_summary"]
            causes = pa["causes"]
            hist = pa["hist"]
            splunk = pa["splunk"]
            hung = pa["hung"]
            samples = pa["samples"]
            report_md = render_markdown_report(all_events, _analysis=pa)
            report_json = render_json_report(all_events, _analysis=pa)
            report_pdf = render_pdf_report(all_events, _analysis=pa)
            report_csv = render_csv_report(all_events)
            report_xml = render_xml_report(all_events)
            report_name = f"report_{ts}.md"
            (REPORTS_DIR / report_name).write_text(report_md, encoding="utf-8")

            log.info("analysis Analysis complete: %d events, %d errors, %d causes, %d hung threads",
                     len(all_events), error_count, len(causes), len(hung))
            if s["codes"]:
                log.info("analysis Top codes: %s", ", ".join(f"{c}({n})" for c, n in s["codes"][:5]))
            if s["exceptions"]:
                log.info("analysis Top exceptions: %s", ", ".join(f"{e}({n})" for e, n in s["exceptions"][:5]))
            log.info("analysis Report saved: %s", report_name)

            itl = incident_timeline(all_events)

            st.session_state.analysis = {
                "events": all_events,
                "summary": s,
                "error_count": error_count,
                "file_count": len(uploaded_files),
                "file_summary": file_summary,
                "causes": causes,
                "hist": hist,
                "splunk": splunk,
                "hung": hung,
                "samples": samples,
                "incident_timeline": itl,
                "total_events": len(all_events),
                "report_md": report_md,
                "report_json": report_json,
                "report_pdf": report_pdf,
                "report_csv": report_csv,
                "report_xml": report_xml,
                "report_name": report_name,
                "top_n": top_n,
                "samples_n": samples_n,
                "hist_minutes": hist_minutes,
            }
            st.session_state.claude_answer = None
            st.session_state.claude_query_label = None
            st.session_state.claude_history = []
            st.session_state.selected_code = None
            st.session_state.selected_action = None
            _save_provider_history(HISTORY_FILE, [])

    a = st.session_state.analysis
    if a is not None:
        render_report_sections(a, log=log, lookup_cache=_lookup_cache, store_cache=_store_cache)
    elif not uploaded_files:
        st.info("Upload one or more WebSphere log files (.log or .gz) above, then click **Analyze** to generate a triage report.")

with tab_realtime:
    st.session_state.rt_enabled = True

    _scan_dirs = [
        _APP_DIR, UPLOADS_DIR, Path.cwd(), Path.home(),
        Path("/opt/IBM/WebSphere/AppServer/profiles"),
        Path("/var/log"),
    ]
    _found_logs: list[str] = []
    for _d in _scan_dirs:
        try:
            if _d.is_dir():
                for _f in sorted(_d.glob("*.log"))[:10]:
                    if _f.is_file() and str(_f) not in _found_logs:
                        _found_logs.append(str(_f))
        except (OSError, PermissionError):
            continue

    _col_path, _col_pick = st.columns(2)
    with _col_path:
        _rt_path = st.text_input(
            "Log file path",
            value=st.session_state.rt_file,
            placeholder="/var/log/websphere/SystemOut.log",
            key="rt_file_tab",
        )
        if _rt_path != st.session_state.rt_file:
            st.session_state.rt_file = _rt_path
    with _col_pick:
        if _found_logs:
            _pick = st.selectbox(
                "Or pick a detected log file",
                options=[""] + _found_logs,
                format_func=lambda x: "— select —" if x == "" else Path(x).name + f"  ({x})",
                key="rt_file_pick_tab",
            )
            if _pick and _pick != st.session_state.rt_file:
                st.session_state.rt_file = _pick
                st.rerun()

    _rt_live_view(log)

with tab_history:
    reports = get_report_history()
    if not reports:
        st.info("No reports yet. Upload and analyze a log file in the **Analyze** tab to generate your first report.")
    else:
        if st.session_state.get("_confirm_clear_history"):
            st.warning(f"Delete all {len(reports)} saved reports? This cannot be undone.")
            hc1, hc2 = st.columns(2)
            with hc1:
                if st.button("Yes, delete all", type="primary", use_container_width=True, key="confirm_clear_history"):
                    st.session_state._confirm_clear_history = False
                    log.info("history Cleared %d report(s)", len(reports))
                    for rpath in reports:
                        rpath.unlink(missing_ok=True)
                    st.rerun()
            with hc2:
                if st.button("Cancel", use_container_width=True, key="cancel_clear_history"):
                    st.session_state._confirm_clear_history = False
                    st.rerun()
        elif st.button("Clear history", type="secondary",
                      help="Delete all saved reports"):
            st.session_state._confirm_clear_history = True
            st.rerun()
        for rpath in reports:
            content = rpath.read_text(encoding="utf-8")
            col_name, col_dl = st.columns([4, 1])
            with col_name:
                with st.expander(rpath.name):
                    st.markdown(content)
            with col_dl:
                st.download_button(
                    label="Download",
                    data=content,
                    file_name=rpath.name,
                    mime="text/markdown",
                    key=f"dl_{rpath.name}",
                )

with tab_audit:
    _audit_html_path = _APP_DIR / "AUDIT_REPORT.html"

    col_model, col_run, col_dl = st.columns([2, 1, 1])
    with col_model:
        _audit_model = st.selectbox(
            "Model",
            list(_AUDIT_MODELS.keys()),
            key="audit_model",
            label_visibility="collapsed",
        )
    with col_run:
        _run_clicked = st.button("Run Audit", type="primary",
                                 help="Analyze the codebase and generate a fresh audit report")
    with col_dl:
        if _audit_html_path.is_file():
            _existing_html = _audit_html_path.read_text(encoding="utf-8")
            st.download_button(
                label="Download HTML",
                data=_existing_html,
                file_name="AUDIT_REPORT.html",
                mime="text/html",
                key="dl_audit_report",
            )

    if _run_clicked:
        _provider = _AUDIT_MODELS[_audit_model]["provider"]
        _model_id = _AUDIT_MODELS[_audit_model]["id"]
        log.info("audit Running audit report with %s (%s)...", _audit_model, _model_id)
        st.toast(f"Starting audit with {_audit_model}...", icon="⏳")
        with st.status(f"Running audit with {_model_id}...", expanded=True) as _audit_status:
            try:
                _fresh_html = _run_audit(_audit_model, log, status=_audit_status)
                _audit_status.update(label="Audit complete!", state="complete")
                log.info("audit Audit report complete (%s)", _model_id)
                st.toast("Audit report complete!", icon="✅")
                st.rerun()
            except Exception as ex:
                log.error("audit Audit failed: %s", ex)
                _audit_status.update(label="Audit failed", state="error")
                st.error(f"Audit failed: {ex}")

    _delta = getattr(st.session_state, "_audit_delta", None)
    if _delta:
        with st.expander("Changes since last audit", expanded=True):
            st.markdown(_delta)

    if _audit_html_path.is_file():
        _audit_html = _audit_html_path.read_text(encoding="utf-8")
        _audit_styled = _audit_html.replace("</head>", _AUDIT_LIGHT_CSS + "</head>")
        st.components.v1.html(_audit_styled, height=2000, scrolling=True)
    else:
        st.info("No audit report yet. Select a model above and click **Run Audit** to analyze the codebase.")

with tab_spend:
    render_spend_tab()

with tab_applog:
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
        st.info("No application log yet. The log will appear here as you use the app.")
