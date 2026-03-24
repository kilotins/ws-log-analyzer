"""Streamlit GUI for LogPilot."""
from __future__ import annotations

import logging
import logging.handlers
import os
import streamlit as st
from collections import deque
from datetime import datetime
from pathlib import Path

from logpilot import (
    parse_file, parse_file_cached, render_markdown_report, render_json_report,
    precompute_analysis, incident_timeline,
)
from logpilot.formats import list_formats

# --- Extracted modules ---
from app_ai import (
    PROVIDER_CONFIG, AI_MODELS, LOCAL_AI_PRESETS,
    init_provider_config,
)
from app_render import render_report_sections
from app_constants import CACHE_TTL_SECONDS, MAX_CACHE_ENTRIES as _MAX_CACHE_ENTRIES_DEFAULT, MAX_UPLOAD_MB
from app_realtime import _rt_live_view, _RT_BUFFER_SIZE
from app_audit import _AUDIT_MODELS, _AUDIT_LIGHT_CSS, _run_audit
from app_spend import render_spend_tab

# --- Paths and directories ---
_APP_DIR = Path(__file__).parent


def _get_version() -> str:
    """Build version string from pyproject.toml + git commit info.

    Returns e.g. '0.1.0+42.b00bc60' or '0.1.0' if git is unavailable.
    """
    # Base version from pyproject.toml
    base = "0.1.0"
    try:
        import tomllib
        base = tomllib.loads((_APP_DIR / "pyproject.toml").read_text())["project"]["version"]
    except Exception:
        pass
    # Git commit count + short hash
    try:
        import subprocess
        result = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            capture_output=True, text=True, cwd=str(_APP_DIR), timeout=5,
        )
        commit_count = result.stdout.strip() if result.returncode == 0 else None
        result2 = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=str(_APP_DIR), timeout=5,
        )
        short_hash = result2.stdout.strip() if result2.returncode == 0 else None
        if commit_count and short_hash:
            return f"{base}+{commit_count}.{short_hash}"
    except Exception:
        pass
    return base
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
LOCAL_HISTORY_FILE = CACHE_DIR / "local_history.json"


MAX_CACHE_ENTRIES = _MAX_CACHE_ENTRIES_DEFAULT
MAX_HISTORY_ENTRIES = 50


# --- JSON helpers (shared by multiple modules) ---
def _load_json_file(path: Path, default: object) -> object:
    """Load a JSON file, returning default on error."""
    if path.exists():
        try:
            import json
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            log.warning("_load_json_file: corrupt JSON in %s: %s", path.name, e)
        except OSError as e:
            log.warning("_load_json_file: could not read %s: %s", path.name, e)
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
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_name, str(path))
    except Exception:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        raise


_LOCAL_SETTINGS_FILE = CACHE_DIR / ".local_ai_settings.json"

def _load_local_ai_settings() -> dict:
    """Load saved local AI settings from disk."""
    data = _load_json_file(_LOCAL_SETTINGS_FILE, {})
    if not isinstance(data, dict):
        return {}
    # Reject corrupted values (e.g. MagicMock from test runs)
    for v in data.values():
        if not isinstance(v, str) or "MagicMock" in v:
            return {}
    return data

def _save_local_ai_settings(endpoint: str, model: str, api_key: str, preset: str) -> None:
    """Persist local AI settings to disk."""
    try:
        # Guard against mock objects from test environments
        vals = [endpoint, model, api_key, preset]
        if any("MagicMock" in repr(v) for v in vals):
            return
        data = {"endpoint": str(endpoint), "model": str(model),
                "api_key": str(api_key), "preset": str(preset)}
        _save_json_file(_LOCAL_SETTINGS_FILE, data)
        log.info("settings Local AI settings saved")
    except Exception:
        pass


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


class ProviderHistoryManager:
    """Centralises per-provider history file mapping, loading, and saving."""

    def __init__(self, cache_dir: Path, provider_files: dict[str, Path]) -> None:
        self._files: dict[str, Path] = dict(provider_files)

    # Public API ---------------------------------------------------------

    def load(self, provider: str) -> list[dict]:
        """Load and return history for *provider* from disk."""
        return _load_provider_history(self._files[provider])

    def save(self, provider: str, history: list[dict]) -> None:
        """Persist *history* for *provider* to disk."""
        _save_provider_history(self._files[provider], history)

    def clear_all(self) -> None:
        """Clear history files for every provider (write empty list)."""
        for provider in self._files:
            self.save(provider, [])

    # Expose the file mapping so callers can still inspect paths ----------

    @property
    def files(self) -> dict[str, Path]:
        return self._files


# Module-level manager instance
provider_history_manager = ProviderHistoryManager(
    CACHE_DIR,
    {
        "claude": HISTORY_FILE,
        "gemini": GEMINI_HISTORY_FILE,
        "openai": OPENAI_HISTORY_FILE,
        "local": LOCAL_HISTORY_FILE,
    },
)

# Backward-compat module-level dict — app_incident.py and tests use this directly
_PROVIDER_HISTORY_FILES = provider_history_manager.files

# Initialize the save_history callbacks in PROVIDER_CONFIG now that manager is ready
init_provider_config({
    provider: (lambda p: lambda hist: provider_history_manager.save(p, hist))(provider)
    for provider in _PROVIDER_HISTORY_FILES
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
    "local_answer": None,
    "local_query_label": None,
    "local_cache": {},
    "local_history": [],
    "local_ai_endpoint": "http://localhost:1234/v1",
    "local_ai_model": "",
    "local_ai_api_key": "not-needed",
    "_local_conn_status": "not_tested",  # not_tested | connected | failed | no_models
    "_local_conn_error": None,
    "_local_models": [],  # discovered model IDs
    "gemini_answer": None,
    "gemini_query_label": None,
    "gemini_cache": {},
    "gemini_history": [],
    "openai_answer": None,
    "openai_query_label": None,
    "openai_cache": {},
    "openai_history": [],
    "debug_payload": False,
    "_ai_probe_log": [],  # list of {ts, type, provider, model, request, response, error}
    "last_ai_call_ts": 0.0,
    "rt_enabled": False,
    "rt_running": False,
    "rt_paused": False,
    "rt_file": "",
    "rt_offset": 0,
    "rt_buffer": None,
    "_samples_show_all": False,
    "_samples_total": 0,
    "_context_event_idx": -1,
    "_audit_delta": None,
    "_local_prev_preset": None,
    "_local_saved_preset": None,
    "_local_settings_loaded": False,
    "local_ai_preset": "LM Studio",
    "_incident_description": "",
    "_incident_screenshot": None,
    "_incident_answer": None,
    "_incident_model": None,
    "_incident_provider": "claude",
    "_incident_model_id": "claude-sonnet-4-6",
    "_leadership_brief": None,
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
for _prov in _PROVIDER_HISTORY_FILES:
    _hkey = f"{_prov}_history"
    if not st.session_state[_hkey]:
        st.session_state[_hkey] = provider_history_manager.load(_prov)

# Load persisted local AI settings on fresh session
if not st.session_state._local_settings_loaded:
    _saved_local = _load_local_ai_settings()
    if _saved_local:
        st.session_state.local_ai_endpoint = _saved_local.get("endpoint", st.session_state.local_ai_endpoint)
        st.session_state.local_ai_model = _saved_local.get("model", "")
        st.session_state.local_ai_api_key = _saved_local.get("api_key", "not-needed")
        st.session_state._local_saved_preset = _saved_local.get("preset", "")
        st.session_state._local_prev_preset = _saved_local.get("preset", "")
    st.session_state._local_settings_loaded = True

# Load persisted theme on fresh session
_THEME_FILE = CACHE_DIR / ".theme.json"
if "_app_theme" not in st.session_state:
    _saved_theme = _load_json_file(_THEME_FILE, {})
    if isinstance(_saved_theme, dict) and _saved_theme.get("theme"):
        st.session_state._app_theme = _saved_theme["theme"]
        # Apply theme config immediately before UI renders
        try:
            import streamlit.config as _stcfg_init
            if _saved_theme["theme"] == "dark":
                _stcfg_init.set_option("theme.base", "dark")
                _stcfg_init.set_option("theme.backgroundColor", "#0d1117")
                _stcfg_init.set_option("theme.secondaryBackgroundColor", "#161b22")
                _stcfg_init.set_option("theme.textColor", "#e6edf3")
        except (ImportError, AttributeError):
            pass

# --- Streamlit UI ---
_FAVICON = str(_APP_DIR / "assets" / "favicon.svg")
st.set_page_config(page_title="LogPilot", page_icon=_FAVICON, layout="wide")

# --- Custom CSS (Item Consulting inspired) ---
st.markdown("""<style>
    /* Typography — clean system sans-serif like item.no */
    [data-testid="stAppViewContainer"] {
        font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        color: #0F172A;
    }
    h1, h2, h3 { font-weight: 700; letter-spacing: -0.02em; color: #0F172A; }

    /* Sidebar — light with subtle border */
    [data-testid="stSidebar"] { background-color: #F8FAFC; border-right: 1px solid #E2E8F0; }

    /* Metric cards — clean with Item-style subtle shadow */
    [data-testid="stMetric"] {
        background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px;
        padding: 12px 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    }
    [data-testid="stMetricValue"] { font-weight: 700; color: #0F172A; }
    [data-testid="stMetricLabel"] { font-size: 0.8rem; color: #64748B; text-transform: uppercase; letter-spacing: 0.04em; }

    /* Tabs — clean minimal */
    .stTabs [data-baseweb="tab-list"] { gap: 2px; border-bottom: 2px solid #E2E8F0; }
    .stTabs [data-baseweb="tab"] { font-weight: 500; font-size: 0.9rem; padding: 8px 16px; }

    /* Purple accent for links and active elements (Item brand) */
    a { color: #7C3AED; }
    a:hover { color: #6D28D9; }

    /* Expander headers */
    [data-testid="stExpander"] summary { font-weight: 600; }

    /* Code blocks — prevent overflow */
    [data-testid="stCode"] pre,
    [data-testid="stMarkdownContainer"] pre {
        overflow-x: auto;
        max-width: 100%;
    }

    /* Subtle dividers */
    hr { border: none; border-top: 1px solid #E2E8F0; margin: 1rem 0; }

    /* Sidebar footer — Item dark style */
    .sidebar-footer {
        margin-top: 2rem; padding: 12px 0; font-size: 0.75rem; color: #64748B;
        border-top: 1px solid #E2E8F0;
    }
    .sidebar-footer a { color: #7C3AED; text-decoration: none; font-weight: 500; }
    .sidebar-footer a:hover { text-decoration: underline; }

    /* LogPilot header — compact inline */
    .logpilot-header { display: flex; align-items: center; gap: 8px; margin-bottom: 0.25rem; }
    .logpilot-header svg { width: 28px; height: 28px; flex-shrink: 0; }
    .logpilot-header .title { font-size: 1.4rem; font-weight: 700; letter-spacing: -0.02em; }
    .logpilot-header .title span { color: #7C3AED; }
    .logpilot-header .subtitle { font-size: 0.7rem; letter-spacing: 0.05em; margin-top: -2px; }
</style>""", unsafe_allow_html=True)

# --- Compact header with inline logo ---
st.markdown('''<div class="logpilot-header">
    <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M6 16 L14 4 L18 4 L10 16 L18 28 L14 28 Z" fill="#7C3AED"/>
        <path d="M14 16 L22 4 L26 4 L18 16 L26 28 L22 28 Z" fill="#34D399"/>
    </svg>
    <div>
        <div class="title">Log<span>Pilot</span></div>
        <div class="subtitle">Log Intelligence Ai-Platform</div>
    </div>
</div>''', unsafe_allow_html=True)

# --- Sidebar: API key ---
_KEYRING_SERVICE = "logpilot"
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

    # --- Theme selector (top of sidebar) ---
    _theme_options = {"System default": "system", "Light": "light", "Dark": "dark"}
    _current_theme = st.session_state.get("_app_theme", "system")
    _theme_label = next((k for k, v in _theme_options.items() if v == _current_theme), "System default")
    _selected = st.selectbox("Theme", list(_theme_options.keys()),
                             index=list(_theme_options.keys()).index(_theme_label),
                             key="theme_select")
    if _theme_options[_selected] != _current_theme:
        st.session_state._app_theme = _theme_options[_selected]
        try:
            _save_json_file(_THEME_FILE, {"theme": _theme_options[_selected]})
        except Exception:
            pass
        import streamlit.config as _stcfg
        if _theme_options[_selected] == "dark":
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

    # Inject CSS to force dark sidebar when dark theme is active
    if _current_theme == "dark":
        st.markdown("""<style>
            /* Sidebar background */
            [data-testid="stSidebar"], [data-testid="stSidebar"] > div {
                background-color: #161b22 !important;
            }
            /* All sidebar text */
            [data-testid="stSidebar"] * {
                color: #c9d1d9 !important;
            }
            /* Headings */
            [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2,
            [data-testid="stSidebar"] h3, [data-testid="stSidebar"] header {
                color: #f0f6fc !important;
            }
            /* Links */
            [data-testid="stSidebar"] a { color: #a78bfa !important; }
            /* Expander borders */
            [data-testid="stSidebar"] details {
                border-color: #30363d !important;
            }
            /* Inputs & selects */
            [data-testid="stSidebar"] input, [data-testid="stSidebar"] select,
            [data-testid="stSidebar"] [data-baseweb="select"] {
                background-color: #0d1117 !important;
                color: #e6edf3 !important;
                border-color: #30363d !important;
            }
            /* Buttons */
            [data-testid="stSidebar"] button {
                background-color: #21262d !important;
                color: #c9d1d9 !important;
                border-color: #30363d !important;
            }
            /* Dividers */
            [data-testid="stSidebar"] hr {
                border-color: #30363d !important;
            }
            /* Toggle track */
            [data-testid="stSidebar"] [data-testid="stToggle"] span {
                color: #c9d1d9 !important;
            }

            /* === Main content dark mode fixes === */

            /* All main text */
            .stMainBlockContainer p, .stMainBlockContainer span,
            .stMainBlockContainer label, .stMainBlockContainer div {
                color: #c9d1d9 !important;
            }
            /* Headings */
            .stMainBlockContainer h1, .stMainBlockContainer h2,
            .stMainBlockContainer h3, .stMainBlockContainer h4 {
                color: #f0f6fc !important;
            }
            /* Expander summaries */
            .stMainBlockContainer details summary span {
                color: #e6edf3 !important;
            }
            /* Expander borders */
            .stMainBlockContainer details {
                border-color: #30363d !important;
            }
            /* Links */
            .stMainBlockContainer a { color: #a78bfa !important; }
            /* Metric cards */
            .stMainBlockContainer [data-testid="stMetric"],
            .stMainBlockContainer [data-testid="stMetricValue"],
            .stMainBlockContainer [data-testid="stMetricLabel"] {
                background-color: transparent !important;
            }
            .stMainBlockContainer [data-testid="stMetricValue"] {
                color: #e6edf3 !important;
            }
            .stMainBlockContainer [data-testid="stMetricLabel"] {
                color: #8b949e !important;
            }
            /* Tabs */
            .stMainBlockContainer [data-baseweb="tab"] {
                color: #8b949e !important;
            }
            .stMainBlockContainer [aria-selected="true"] {
                color: #a78bfa !important;
            }
            /* Info/success/warning boxes */
            .stMainBlockContainer .stAlert p {
                color: inherit !important;
            }
            /* Table text */
            .stMainBlockContainer table, .stMainBlockContainer th,
            .stMainBlockContainer td {
                color: #c9d1d9 !important;
            }
            /* Captions & small text */
            .stMainBlockContainer .stCaption, .stMainBlockContainer small {
                color: #8b949e !important;
            }
            /* Subheader */
            .stMainBlockContainer .stSubheader {
                color: #f0f6fc !important;
            }
        </style>""", unsafe_allow_html=True)

    st.markdown("---")

    # Count configured keys for the expander label
    _configured_keys = sum(1 for k in [
        st.session_state.api_key,
        st.session_state.gemini_api_key,
        st.session_state.openai_api_key,
    ] if k)
    _keys_label = f"Cloud API Keys ({_configured_keys}/3 configured)" if _configured_keys else "Cloud API Keys (none configured)"
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

    with st.expander("Local / Inhouse AI", expanded=False):
        from app_ai import discover_local_models

        # --- Preset + Endpoint ---
        _prev_preset = st.session_state.get("_local_prev_preset", "")
        _preset_names = list(LOCAL_AI_PRESETS.keys())
        _saved_preset = st.session_state.get("_local_saved_preset", "")
        _preset_index = _preset_names.index(_saved_preset) if _saved_preset in _preset_names else 0
        _preset = st.selectbox(
            "Preset",
            _preset_names,
            index=_preset_index,
            key="local_ai_preset",
            help="Select your local AI server type",
        )
        _preset_cfg = LOCAL_AI_PRESETS[_preset]

        # Only apply preset URL when user actively changes the preset
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
            _save_local_ai_settings(_local_endpoint, st.session_state.local_ai_model,
                                     st.session_state.local_ai_api_key, _preset)

        # --- Test Connection + Refresh ---
        _btn_col, _status_col = st.columns([1, 2])
        with _btn_col:
            _test_clicked = st.button("Test connection", key="local_test_conn",
                                      use_container_width=True)
        _endpoint = st.session_state.local_ai_endpoint
        _api_key = st.session_state.local_ai_api_key

        if _test_clicked and _endpoint:
            with st.spinner("Connecting..."):
                result = discover_local_models(_endpoint, _api_key)
            st.session_state._local_conn_status = result["status"]
            st.session_state._local_conn_error = result["error"]
            st.session_state._local_models = result["models"]
            if result["models"]:
                if not st.session_state.local_ai_model or st.session_state.local_ai_model not in result["models"]:
                    st.session_state.local_ai_model = result["models"][0]
                _save_local_ai_settings(_endpoint, st.session_state.local_ai_model,
                                         _api_key, _preset)
                st.rerun()

        with _status_col:
            _conn = st.session_state._local_conn_status
            if _conn == "connected":
                n = len(st.session_state._local_models)
                st.success(f"Connected — {n} model{'s' if n != 1 else ''} found")
            elif _conn == "failed":
                st.error(st.session_state._local_conn_error or "Connection failed")
            elif _conn == "no_models":
                st.warning(st.session_state._local_conn_error or "No models found")
            else:
                st.caption("Not tested")

        # --- Model selection ---
        _discovered = st.session_state._local_models
        if _discovered:
            _refresh_col, _model_col = st.columns([1, 3])
            with _refresh_col:
                if st.button("Refresh", key="local_refresh_models", use_container_width=True):
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
                    key="local_model_select",
                    label_visibility="collapsed",
                )
                if _selected_model != st.session_state.local_ai_model:
                    st.session_state.local_ai_model = _selected_model
                    _save_local_ai_settings(_endpoint, _selected_model,
                                             _api_key, _preset)
        else:
            _manual_model = st.text_input(
                "Model name",
                value=st.session_state.local_ai_model,
                placeholder="e.g. llama-3.1-8b, mistral-7b, qwen2.5",
                help="Model ID as shown in your local server",
                key="local_model_input",
            )
            if _manual_model != st.session_state.local_ai_model:
                st.session_state.local_ai_model = _manual_model
                _save_local_ai_settings(_endpoint, _manual_model,
                                         _api_key, _preset)

        # --- Advanced (API key) ---
        with st.expander("Advanced", expanded=False):
            _local_key = st.text_input(
                "API Key (optional)",
                value=st.session_state.local_ai_api_key,
                placeholder="not-needed",
                help="Most local servers don't require an API key",
                key="local_key_input",
            )
            if _local_key != st.session_state.local_ai_api_key:
                st.session_state.local_ai_api_key = _local_key
                _save_local_ai_settings(st.session_state.local_ai_endpoint,
                                         st.session_state.local_ai_model,
                                         _local_key, _preset)

    st.markdown("---")
    st.session_state.debug_payload = st.toggle(
        "Debug mode",
        value=st.session_state.debug_payload,
        help="Show Application Log and AI Probe tabs for debugging",
    )
    if st.session_state.get("_confirm_clear_cache"):
        st.warning("Clear all AI caches and history?")
        _cc1, _cc2 = st.columns(2)
        with _cc1:
            if st.button("Yes, clear", type="primary", use_container_width=True, key="confirm_clear_cache"):
                st.session_state._confirm_clear_cache = False
                from app_ai import clear_all_ai_history
                clear_all_ai_history()
                log.info("cache Cleared all AI caches and history")
                st.success("AI cache and history cleared")
        with _cc2:
            if st.button("Cancel", use_container_width=True, key="cancel_clear_cache"):
                st.session_state._confirm_clear_cache = False
                st.rerun()
    elif st.button("Clear AI cache & history", help="Clear all cached AI responses, answers, and conversation history"):
        st.session_state._confirm_clear_cache = True
        st.rerun()

    # --- Sidebar footer ---
    st.markdown(
        f'<div class="sidebar-footer">'
        f'v{_get_version()} &middot; <a href="https://item.no" target="_blank">Item Consulting</a>'
        f'</div>',
        unsafe_allow_html=True,
    )


# --- Tabs ---
_tab_names = ["Analyze", "Realtime Console", "Audit Report", "Cloud Spend"]
if st.session_state.debug_payload:
    _tab_names.append("Debug")
_tabs = st.tabs(_tab_names)
tab_analyze, tab_realtime, tab_audit, tab_spend = _tabs[:4]
tab_debug = _tabs[4] if len(_tabs) > 4 else None

with tab_analyze:
    uploaded_files = st.file_uploader(
        "Upload log file(s)",
        type=None,  # Accept any file — parser handles format detection
        accept_multiple_files=True,
        help="Application log files (.log or .gz compressed)",
    )

    # --- Folder scan (local path) ---
    with st.expander("Or scan a local folder", expanded=False):
        col_path, col_browse = st.columns([4, 1])
        with col_path:
            folder_path = st.text_input(
                "Folder path",
                value=st.session_state.get("folder_path", ""),
                placeholder="/var/log/myapp",
                help="Recursively scans for .log, .txt, .out, .gz files",
                label_visibility="collapsed",
            )
        with col_browse:
            if st.button("Browse…", use_container_width=True):
                _chosen = ""
                try:
                    # Try tkinter first (works when available)
                    import tkinter as _tk
                    from tkinter import filedialog as _fd
                    _root = _tk.Tk()
                    _root.withdraw()
                    _root.attributes("-topmost", True)
                    _chosen = _fd.askdirectory(title="Select log folder")
                    _root.destroy()
                except Exception:
                    # Fallback: macOS native folder picker via osascript
                    try:
                        import subprocess as _sp
                        _result = _sp.run(
                            ["osascript", "-e",
                             'POSIX path of (choose folder with prompt "Select log folder")'],
                            capture_output=True, text=True, timeout=60,
                        )
                        if _result.returncode == 0 and _result.stdout.strip():
                            _chosen = _result.stdout.strip().rstrip("/")
                    except Exception as _os_err:
                        st.warning(f"Folder picker not available: {_os_err}")
                if _chosen:
                    st.session_state["folder_path"] = _chosen
                    st.rerun()

        # Discover files if path is set
        _folder_files = []
        if folder_path and folder_path.strip():
            from logpilot.discovery import discover_log_files, _fmt_size
            _fp = Path(folder_path.strip()).expanduser()
            if _fp.is_dir():
                _disc = discover_log_files(_fp)
                if _disc.accepted:
                    st.success(f"Found **{len(_disc.accepted)} files** ({_fmt_size(_disc.total_size)})")
                    if _disc.truncated:
                        st.warning(f"⚠ {_disc.truncation_reason}")
                    with st.container(height=150):
                        for _df in _disc.accepted:
                            st.text(f"✓ {_df.relative_path}  ({_fmt_size(_df.size)})")
                    if _disc.rejected:
                        with st.expander(f"{len(_disc.rejected)} files skipped"):
                            for _rf in _disc.rejected[:20]:
                                st.text(f"✗ {_rf.relative_path} — {_rf.reason}")
                    _folder_files = _disc.accepted
                else:
                    st.warning("No supported log files found in this folder.")
                    if _disc.rejected:
                        with st.expander(f"{len(_disc.rejected)} files skipped"):
                            for _rf in _disc.rejected[:20]:
                                st.text(f"✗ {_rf.relative_path} — {_rf.reason}")
            elif folder_path.strip():
                st.error("Path is not a valid directory.")

    # Format plugins and parsing options
    _formats = list_formats()
    _format_names = ["Auto-detect"] + [f["name"] for f in _formats]
    _format_help = "Auto-detect analyzes the first 50 lines. Force a format if detection fails.\n\n" + \
                   "\n".join(f"**{f['name']}** — {f['description']}" for f in _formats)

    col_fmt, col_lines = st.columns(2)
    with col_fmt:
        _selected_format = st.selectbox(
            "Log format",
            _format_names,
            help=_format_help,
        )
    with col_lines:
        max_lines = st.number_input(
            "Max lines per file",
            min_value=1_000, max_value=5_000_000, value=500_000, step=100_000,
            help="Limit lines read per file. Lower = faster parsing, higher = more complete analysis.",
        )

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        top_n = st.number_input("Top-N items", min_value=1, max_value=50, value=10,
                                help="Number of top exceptions, message codes, and signal tags shown in the summary.")
    with col2:
        samples_n = st.number_input("Sample events", min_value=1, max_value=20, value=5,
                                    help="Number of representative sample events shown per error category.")
    with col3:
        hist_minutes = st.number_input("Histogram bucket (min)", min_value=1, max_value=60, value=1,
                                       help="Time resolution for the timeline histogram.")
    with col4:
        timeline_window = st.number_input("Timeline window (sec)", min_value=5, max_value=300, value=30,
                                          help="Seconds before/after the first error to include in the incident timeline.")

    sample_info_events = st.checkbox("Sample INFO events (large files)", value=False,
                                     help="Keep 1 in 10 INFO events to reduce memory. Recommended for access logs >100K lines.")

    _has_input = bool(uploaded_files) or bool(_folder_files)
    if _has_input and st.button("Analyze", type="primary"):
        # Size check for uploaded files
        if uploaded_files:
            total_size = sum(f.size for f in uploaded_files)
            _over_limit = total_size > MAX_UPLOAD_MB * 1024 * 1024
            if _over_limit:
                st.error(f"Total upload size ({total_size / 1024 / 1024:.1f} MB) exceeds the {MAX_UPLOAD_MB} MB limit. Please upload smaller files.")
                st.stop()
            elif total_size > 50 * 1024 * 1024:
                st.warning("Large files detected (>50MB). Parsing may take a while.")

        all_events = []

        # --- Parse uploaded files ---
        import hashlib as _hl
        _session_uploads: set[str] = set()
        _upload_count = len(uploaded_files) if uploaded_files else 0
        _total_files = _upload_count + len(_folder_files)
        _progress = st.progress(0, text=f"Parsing 0/{_total_files} files...")

        if uploaded_files:
            for uploaded in uploaded_files:
                safe_name = "".join(c for c in uploaded.name if c.isalnum() or c in "._-")[:100] or "upload.log"
                content = uploaded.getvalue()
                _hash = _hl.md5(content).hexdigest()[:10]
                upload_name = f"{_hash}_{safe_name}"
                upload_path = UPLOADS_DIR / upload_name
                if not upload_path.resolve().is_relative_to(UPLOADS_DIR.resolve()):
                    st.error(f"Invalid filename: {uploaded.name}")
                    continue
                _session_uploads.add(upload_path.name)
                if not upload_path.exists():
                    upload_path.write_bytes(content)
                    log.info("upload File saved: %s (%d bytes)", upload_name, len(content))
                else:
                    log.info("upload File reused (identical): %s", upload_name)

            # Remove old uploads not in this batch
            for old_file in UPLOADS_DIR.iterdir():
                if old_file.name not in _session_uploads and old_file.is_file():
                    old_file.unlink()
                    log.info("upload Cleaned old upload: %s", old_file.name)

            # Parse each uploaded file
            for _file_idx, uploaded in enumerate(uploaded_files):
                safe_name = "".join(c for c in uploaded.name if c.isalnum() or c in "._-")[:100] or "upload.log"
                _hash = _hl.md5(uploaded.getvalue()).hexdigest()[:10]
                upload_path = UPLOADS_DIR / f"{_hash}_{safe_name}"

                _progress.progress(_file_idx / _total_files,
                                   text=f"Parsing {uploaded.name} ({_file_idx + 1}/{_total_files})...")
                try:
                    _fmt_name = None if _selected_format == "Auto-detect" else _selected_format
                    events = parse_file_cached(upload_path, content_hash=_hash,
                                               cache_dir=UPLOADS_DIR / ".cache",
                                               max_lines=max_lines, format_name=_fmt_name,
                                               sample_info=10 if sample_info_events else 0)
                    _stem = uploaded.name.rsplit(".", 1)[0] if "." in uploaded.name else uploaded.name
                    for ev in events:
                        ev.system_label = _stem
                    all_events.extend(events)
                    log.info("analysis Parsed %d events from %s", len(events), uploaded.name)
                except Exception as ex:
                    log.error("analysis Failed to parse %s: %s", uploaded.name, ex)
                    st.error(f"Failed to parse {uploaded.name}: {ex}")

        # --- Parse folder files (read directly from disk) ---
        for _fi, _df in enumerate(_folder_files):
            _idx = _upload_count + _fi
            _progress.progress(_idx / _total_files,
                               text=f"Parsing {_df.relative_path} ({_idx + 1}/{_total_files})...")
            try:
                _fmt_name = None if _selected_format == "Auto-detect" else _selected_format
                events = parse_file(_df.path, max_lines=max_lines, format_name=_fmt_name)
                _stem = _df.path.stem if _df.path.suffix.lower() != ".gz" else Path(_df.path.stem).stem
                _label = f"{_df.group}/{_stem}" if _df.group else _stem
                for ev in events:
                    ev.system_label = _label
                all_events.extend(events)
                log.info("analysis Parsed %d events from %s", len(events), _df.relative_path)
            except Exception as ex:
                log.error("analysis Failed to parse %s: %s", _df.relative_path, ex)
                st.error(f"Failed to parse {_df.relative_path}: {ex}")

        _progress.progress(1.0, text=f"Parsed {_total_files} files ({len(all_events):,} events). Analyzing...")

        # Sort all events chronologically across files
        from logpilot.analysis import sort_events_chronologically
        sort_events_chronologically(all_events)

        if not all_events:
            st.error("No log events found. Possible causes: files may be empty, contain no recognizable timestamps, or use an unsupported format.")
        else:
            def _analysis_progress(text: str, frac: float) -> None:
                _progress.progress(frac, text=text)
            pa = precompute_analysis(all_events, top_n=top_n, samples_n=samples_n, hist_minutes=hist_minutes, progress_callback=_analysis_progress)
            s = pa["summary"]
            error_count = sum(1 for e in all_events if e.level in ("ERROR", "SEVERE", "FATAL"))
            file_summary = pa["file_summary"]
            causes = pa["causes"]
            hist = pa["hist"]
            hung = pa["hung"]
            samples = pa["samples"]
            report_md = render_markdown_report(all_events, _analysis=pa)
            report_json = render_json_report(all_events, _analysis=pa)

            log.info("analysis Analysis complete: %d events, %d errors, %d causes, %d hung threads",
                     len(all_events), error_count, len(causes), len(hung))
            if s["codes"]:
                log.info("analysis Top codes: %s", ", ".join(f"{c}({n})" for c, n in s["codes"][:5]))
            if s["exceptions"]:
                log.info("analysis Top exceptions: %s", ", ".join(f"{e}({n})" for e, n in s["exceptions"][:5]))
            log.info("analysis Analysis complete")

            itl = incident_timeline(all_events, window_seconds=timeline_window)

            st.session_state.analysis = {
                "events": all_events,
                "summary": s,
                "error_count": error_count,
                "file_count": _total_files,
                "file_summary": file_summary,
                "causes": causes,
                "hist": hist,
                "hung": hung,
                "samples": samples,
                "cascades": pa.get("cascades", []),
                "grouped": pa.get("grouped"),
                "failure_chain": pa.get("failure_chain", {}),
                "incident_timeline": itl,
                "total_events": len(all_events),
                "report_md": report_md,
                "report_json": report_json,
                "top_n": top_n,
                "samples_n": samples_n,
                "hist_minutes": hist_minutes,
            }
            st.session_state.claude_answer = None
            st.session_state.claude_query_label = None
            st.session_state.claude_history = []
            st.session_state.selected_code = None
            st.session_state.selected_action = None
            st.session_state._incident_answer = None
            st.session_state._leadership_brief = None
            provider_history_manager.save("claude", [])

    a = st.session_state.analysis
    if a is not None:
        # Re-compute analysis if display parameters changed
        _heavy_changed = (
            a.get("top_n") != top_n
            or a.get("hist_minutes") != hist_minutes
        )
        _samples_only = (not _heavy_changed and a.get("samples_n") != samples_n)
        if _samples_only and a.get("events"):
            # Only samples_n changed — cheap resample without full recomputation
            from logpilot.analysis import pick_samples
            _events = a["events"]
            a["samples"] = pick_samples(_events, samples_n)
            a["samples_n"] = samples_n
        elif _heavy_changed and a.get("events"):
            _events = a["events"]
            _pa = precompute_analysis(_events, top_n=top_n, samples_n=samples_n, hist_minutes=hist_minutes)
            _report_md = render_markdown_report(_events, _analysis=_pa)
            _report_json = render_json_report(_events, _analysis=_pa)
            a.update({
                "summary": _pa["summary"],
                "file_summary": _pa["file_summary"],
                "causes": _pa["causes"],
                "hist": _pa["hist"],
                "hung": _pa["hung"],
                "samples": _pa["samples"],
                "grouped": _pa.get("grouped"),
                "failure_chain": _pa.get("failure_chain", {}),
                "report_md": _report_md,
                "report_json": _report_json,
                "top_n": top_n,
                "samples_n": samples_n,
                "hist_minutes": hist_minutes,
            })
        render_report_sections(a, log=log, lookup_cache=_lookup_cache, store_cache=_store_cache)
    elif not uploaded_files:
        st.info("Upload one or more log files (.log or .gz) above, then click **Analyze** to generate a triage report.")

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
            placeholder="/var/log/app/application.log",
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

    if _audit_html_path.is_file():
        _audit_html = _audit_html_path.read_text(encoding="utf-8")
        # Inject theme override: force dark or light based on app setting
        _app_theme = st.session_state.get("_app_theme", "system")
        if _app_theme == "dark":
            _theme_css = '<style>html { --bg-primary:#0d1117; --bg-secondary:#010409; --bg-tertiary:#161b22; --bg-hover:#1c2128; --border:#21262d; --border-strong:#30363d; --text-primary:#e6edf3; --text-secondary:#c9d1d9; --text-muted:#8b949e; --text-heading:#f0f6fc; --accent:#a78bfa; --green:#6fdd8b; --green-bg:#1b4332; --yellow:#f0c74f; --yellow-bg:#3d2e00; --red:#f47067; --red-bg:#4a1e1e; --blue:#58a6ff; --blue-bg:#1a2332; --purple:#bc8cff; --purple-bg:#272145; } nav { display:none !important; } .layout { display:block !important; } main { max-width:800px !important; margin:0 !important; padding:20px !important; }</style>'
        else:
            _theme_css = _AUDIT_LIGHT_CSS
        _audit_styled = _audit_html.replace("</head>", _theme_css + "</head>")
        st.components.v1.html(_audit_styled, height=2000, scrolling=True)
    else:
        st.info("No audit report yet. Select a model above and click **Run Audit** to analyze the codebase.")

with tab_spend:
    render_spend_tab()

if tab_debug is not None:
    with tab_debug:
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
                st.info("No application log yet. The log will appear here as you use the app.")

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
                            st.button("Copy request", key=f"copy_req_{_entry['ts']}_{id(_entry)}",
                                      on_click=lambda r=_req: st.session_state.update({"_clipboard": r}))
                        if _resp:
                            st.markdown("**Response payload**")
                            st.code(_resp[:20000], language="markdown")
                            st.button("Copy response", key=f"copy_resp_{_entry['ts']}_{id(_entry)}",
                                      on_click=lambda r=_resp: st.session_state.update({"_clipboard": r}))
                        if _error:
                            st.markdown("**Error**")
                            st.code(_error, language="text")
            else:
                st.info("No AI calls recorded yet. Use Ask AI, Cross-System Triage, or Audit Report to see payloads here.")
