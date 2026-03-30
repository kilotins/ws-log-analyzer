"""Streamlit GUI for LogPilot."""
from __future__ import annotations

import sys

import io
import logging
import logging.handlers
import os
import tempfile
import streamlit as st
import zipfile
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
from logpilot.discovery import discover_log_files
from logpilot.license import require_license, validate_token, is_feature_licensed, allowed_providers, is_model_allowed

# --- Paths and directories ---
_APP_DIR = Path(__file__).parent


def _get_version() -> str:
    """Build version string from pyproject.toml + git commit info.

    Returns e.g. '0.1.0+42.b00bc60' or '0.1.0' if git is unavailable.
    """
    # Base version from __init__.py (single source of truth), fallback to pyproject.toml
    try:
        from logpilot import __version__
        base = __version__
    except ImportError:
        base = "unknown"
    except Exception:
        try:
            import tomllib
            base = tomllib.loads((_APP_DIR / "pyproject.toml").read_text())["project"]["version"]
        except Exception:
            base = "unknown"
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
_ARCHIVE_JUNK_NAMES = frozenset({
    ".ds_store",
    "thumbs.db",
    "desktop.ini",
    "__pycache__",
})


class _InMemoryUpload(io.BytesIO):
    """Minimal UploadedFile-like wrapper for extracted archive members."""

    def __init__(self, content: bytes, name: str):
        super().__init__(content)
        self.name = name
        self.size = len(content)


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
    # Reject corrupted values
    for v in data.values():
        if not isinstance(v, str):
            return {}
    return data

def _save_local_ai_settings(endpoint: str, model: str, api_key: str, preset: str) -> None:
    """Persist local AI settings to disk."""
    try:
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


def _cleanup_temp_dir(path: Path | str | None) -> None:
    """Best-effort recursive cleanup for temporary extraction directories."""
    if not path:
        return
    root = Path(path)
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        for filename in filenames:
            try:
                Path(dirpath, filename).unlink()
            except OSError:
                pass
        for dirname in dirnames:
            try:
                Path(dirpath, dirname).rmdir()
            except OSError:
                pass
    try:
        root.rmdir()
    except OSError:
        pass


def _is_zip_junk_member(member_name: str) -> bool:
    """Return True for archive members that should be ignored."""
    normalized = member_name.replace("\\", "/").strip("/")
    if not normalized:
        return True
    parts = [part.lower() for part in normalized.split("/") if part not in ("", ".")]
    if not parts:
        return True
    return any(part == "__macosx" or part in _ARCHIVE_JUNK_NAMES for part in parts)


def _safe_zip_member_path(root: Path, member_name: str) -> Path | None:
    """Resolve a zip member path under root, rejecting traversal attempts."""
    normalized = os.path.normpath(member_name.replace("\\", "/"))
    if normalized in ("", ".", ".."):
        return None
    if normalized.startswith("../") or normalized.startswith("/"):
        return None
    target = (root / normalized).resolve()
    if not target.is_relative_to(root.resolve()):
        return None
    return target


_ZIP_MAX_MEMBER_BYTES = 100 * 1024 * 1024   # 100 MB per member
_ZIP_MAX_TOTAL_BYTES  = 500 * 1024 * 1024   # 500 MB total uncompressed


def _extract_archive_upload(uploaded) -> tuple[list[_InMemoryUpload], list[str]]:
    """Extract one uploaded zip archive into in-memory uploads."""
    temp_dir = Path(tempfile.mkdtemp(prefix="logpilot_zip_"))
    extracted_files: list[_InMemoryUpload] = []
    preview_paths: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(uploaded.getvalue())) as archive:
            total_uncompressed = 0
            for member in archive.infolist():
                if member.is_dir():
                    continue
                if _is_zip_junk_member(member.filename):
                    continue
                # ZIP bomb check — member size
                if member.file_size > _ZIP_MAX_MEMBER_BYTES:
                    st.warning(
                        f"Skipped {member.filename}: member too large "
                        f"({member.file_size // (1024*1024)} MB > 100 MB limit)."
                    )
                    continue
                total_uncompressed += member.file_size
                if total_uncompressed > _ZIP_MAX_TOTAL_BYTES:
                    st.warning(
                        f"Stopped extracting {uploaded.name}: total uncompressed size "
                        f"exceeds 500 MB limit."
                    )
                    break
                target = _safe_zip_member_path(temp_dir, member.filename)
                if target is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as src:
                    target.write_bytes(src.read())

        discovered = discover_log_files(temp_dir)
        for discovered_file in discovered.accepted:
            content = discovered_file.path.read_bytes()
            extracted_files.append(_InMemoryUpload(content, discovered_file.relative_path))
            preview_paths.append(discovered_file.relative_path)
        return extracted_files, preview_paths
    finally:
        _cleanup_temp_dir(temp_dir)


def _expand_uploaded_archives(uploaded_files: list) -> tuple[list, list[tuple[str, list[str]]]]:
    """Replace uploaded zip archives with discovered log files."""
    expanded_files: list = []
    extracted_previews: list[tuple[str, list[str]]] = []

    for uploaded in uploaded_files:
        if not getattr(uploaded, "name", "").lower().endswith(".zip"):
            expanded_files.append(uploaded)
            continue
        try:
            extracted_files, preview_paths = _extract_archive_upload(uploaded)
        except zipfile.BadZipFile:
            st.warning(f"No files extracted from {uploaded.name}: invalid zip archive.")
            continue
        if extracted_files:
            expanded_files.extend(extracted_files)
            extracted_previews.append((uploaded.name, preview_paths))
            st.info(f"Extracted {len(extracted_files)} log files from {uploaded.name}")
        else:
            st.warning(f"No supported log files found in {uploaded.name}.")
    return expanded_files, extracted_previews


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
    "license_key": "",
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
    "_ai_exclude_patterns": "",
    "_incident_screenshot": None,
    "_incident_answer": None,
    "_incident_model": None,
    "_incident_provider": "claude",
    "_incident_model_id": "claude-sonnet-4-6",
    "_leadership_brief": None,
    # Jira / Confluence integration
    # Trace to Code
    "_code_repo_path": "",
    "_upload_session_id": "",
    "_code_matches": None,
    # Jira / Confluence integration
    "_jira_tickets": None,
    "_jira_cache_key": "",
    "_jira_url": "",
    "_jira_email": "",
    "_jira_token": "",
    "_jira_project": "",
    "_jira_issue_type": "Bug",
    "_jira_server_type": "cloud",
    "_confluence_space": "",
    "_confluence_parent": "",
    "_confluence_page_url": "",
    "_confluence_page_id": "",
}

_EXPECTED_STATE_KEYS = set(_STATE_DEFAULTS.keys())

for key, default in _STATE_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = default
if st.session_state.rt_buffer is None:
    st.session_state.rt_buffer = deque(maxlen=_RT_BUFFER_SIZE)
if not st.session_state._upload_session_id:
    import secrets as _secrets
    st.session_state._upload_session_id = _secrets.token_hex(8)

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

# Load persisted license key on fresh session
if not st.session_state.license_key:
    _LICENSE_FILE = CACHE_DIR / ".license_key"
    try:
        if _LICENSE_FILE.exists():
            st.session_state.license_key = _LICENSE_FILE.read_text().strip()
    except Exception:
        pass

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

    /* Settings section — compact separator */
    [data-testid="stSidebarNav"] > div:last-child {
        border-top: 1px solid #E2E8F0;
        padding-top: 0.5rem;
        margin-top: 0.5rem;
    }
</style>""", unsafe_allow_html=True)

# --- Dark mode CSS injection ---
_current_theme = st.session_state.get("_app_theme", "system")
if _current_theme == "dark":
    st.markdown("""<style>
        /* Sidebar background */
        [data-testid="stSidebar"], [data-testid="stSidebar"] > div {
            background-color: #161b22 !important;
        }
        [data-testid="stSidebar"] * { color: #c9d1d9 !important; }
        [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2,
        [data-testid="stSidebar"] h3, [data-testid="stSidebar"] header {
            color: #f0f6fc !important;
        }
        [data-testid="stSidebar"] a { color: #a78bfa !important; }
        [data-testid="stSidebar"] details { border-color: #30363d !important; }
        [data-testid="stSidebar"] input, [data-testid="stSidebar"] select,
        [data-testid="stSidebar"] [data-baseweb="select"] {
            background-color: #0d1117 !important; color: #e6edf3 !important;
            border-color: #30363d !important;
        }
        [data-testid="stSidebar"] button {
            background-color: #21262d !important; color: #c9d1d9 !important;
            border-color: #30363d !important;
        }
        [data-testid="stSidebar"] hr { border-color: #30363d !important; }

        /* Main content dark mode */
        .stMainBlockContainer p, .stMainBlockContainer span,
        .stMainBlockContainer label, .stMainBlockContainer div { color: #c9d1d9 !important; }
        .stMainBlockContainer h1, .stMainBlockContainer h2,
        .stMainBlockContainer h3, .stMainBlockContainer h4 { color: #f0f6fc !important; }
        .stMainBlockContainer details summary span { color: #e6edf3 !important; }
        .stMainBlockContainer details { border-color: #30363d !important; }
        .stMainBlockContainer a { color: #a78bfa !important; }
        .stMainBlockContainer [data-testid="stMetric"],
        .stMainBlockContainer [data-testid="stMetricValue"],
        .stMainBlockContainer [data-testid="stMetricLabel"] { background-color: transparent !important; }
        .stMainBlockContainer [data-testid="stMetricValue"] { color: #e6edf3 !important; }
        .stMainBlockContainer [data-testid="stMetricLabel"] { color: #8b949e !important; }
        .stMainBlockContainer [data-baseweb="tab"] { color: #8b949e !important; }
        .stMainBlockContainer [aria-selected="true"] { color: #a78bfa !important; }
        .stMainBlockContainer .stAlert p { color: inherit !important; }
        .stMainBlockContainer table, .stMainBlockContainer th,
        .stMainBlockContainer td { color: #c9d1d9 !important; }
        .stMainBlockContainer .stCaption, .stMainBlockContainer small { color: #8b949e !important; }
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
# Trial fallback: use baked-in API key from env var
if not st.session_state.api_key:
    st.session_state.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
# ---------------------------------------------------------------------------
# Register this module as 'app' so pages can `from app import ...`
# Streamlit runs this file via exec() — pages need the module in sys.modules
# ---------------------------------------------------------------------------
import types as _types
_app_module = _types.ModuleType("app")
_app_module.__file__ = __file__
_app_module.__dict__.update(
    {k: v for k, v in globals().items() if not k.startswith("_DEFERRED")}
)
sys.modules["app"] = _app_module

# ---------------------------------------------------------------------------
# Navigation (replaces old tab layout)
# ---------------------------------------------------------------------------
_analysis_pages = [
    st.Page("pages/home.py", title="Home", icon=":material/home:", default=True),
    st.Page("pages/overview.py", title="Overview", icon=":material/dashboard:"),
    st.Page("pages/causes.py", title="Causes & Fixes", icon=":material/search:"),
    st.Page("pages/ai_analysis.py", title="AI Analysis", icon=":material/smart_toy:"),
    st.Page("pages/timeline.py", title="Timeline", icon=":material/timeline:"),
    st.Page("pages/events.py", title="Events", icon=":material/list_alt:"),
    st.Page("pages/reports.py", title="Reports", icon=":material/description:"),
]

if st.session_state.get("_code_repo_path"):
    _analysis_pages.append(
        st.Page("pages/code.py", title="Trace to Code", icon=":material/code:")
    )

if st.session_state.get("debug_payload"):
    _analysis_pages.append(
        st.Page("pages/debug.py", title="Debug", icon=":material/bug_report:")
    )

_settings_page = st.Page("pages/settings.py", title="Settings", icon=":material/settings:")

_pages = {
    "Analysis": _analysis_pages,
    "Integrations": [
        st.Page("pages/jira.py", title="Jira & Confluence", icon=":material/confirmation_number:"),
    ],
    "Settings": [
        st.Page("pages/help.py", title="Help", icon=":material/help:"),
        _settings_page,
    ],
}

pg = st.navigation(_pages, expanded=False)

# --- Global severity/source filters in sidebar (below navigation) ---
with st.sidebar:
    # --- AI Model selector (global) ---
    from app_ai import AI_MODELS
    from logpilot.license import allowed_providers as _allowed_providers
    if require_license():
        _lic_providers = _allowed_providers(st.session_state.get("license_key", ""))
        _available_models = [
            name for name, cfg in AI_MODELS.items()
            if cfg["provider"] in _lic_providers
        ]
    else:
        _available_models = list(AI_MODELS.keys())
    if not _available_models:
        _available_models = [name for name, cfg in AI_MODELS.items() if cfg["provider"] == "local"]

    _prev_model = st.session_state.get("_selected_ai_model", "")
    _model_index = _available_models.index(_prev_model) if _prev_model in _available_models else 0
    st.selectbox(
        "AI Model",
        _available_models,
        index=_model_index,
        key="_selected_ai_model",
        help="Model used for AI analysis. Requires API key in Settings.",
    )

    # --- Severity / Source filters ---
    a = st.session_state.get("analysis")
    if a and a.get("events"):
        st.markdown("---")
        _filter_events = a["events"]
        _all_levels = sorted({e.level for e in _filter_events if e.level})
        _all_sources = sorted({e.system_label for e in _filter_events if e.system_label})

        if _all_levels:
            st.multiselect(
                "Severity", options=_all_levels, default=[], key="filter_levels",
                help="Filter all pages by severity level",
            )
        if len(_all_sources) > 1:
            st.multiselect(
                "Source", options=_all_sources, default=[], key="filter_sources",
                help="Filter all pages by log source",
            )

    # --- Theme toggle + footer (compact) ---
    _is_dark = st.session_state.get("_app_theme", "system") == "dark"
    _icon = ":material/light_mode:" if _is_dark else ":material/dark_mode:"
    if st.button(_icon, key="sidebar_theme_toggle", help="Toggle dark/light mode"):
        _new_theme = "light" if _is_dark else "dark"
        st.session_state._app_theme = _new_theme
        try:
            _save_json_file(_THEME_FILE, {"theme": _new_theme})
        except Exception:
            pass
        try:
            import streamlit.config as _stcfg
            if _new_theme == "dark":
                _stcfg.set_option("theme.base", "dark")
                _stcfg.set_option("theme.backgroundColor", "#0d1117")
                _stcfg.set_option("theme.secondaryBackgroundColor", "#161b22")
                _stcfg.set_option("theme.textColor", "#e6edf3")
            else:
                _stcfg.set_option("theme.base", "light")
                _stcfg.set_option("theme.backgroundColor", "#FFFFFF")
                _stcfg.set_option("theme.secondaryBackgroundColor", "#F8FAFC")
                _stcfg.set_option("theme.textColor", "#0F172A")
        except Exception:
            pass
        st.rerun()
    st.caption(
        f'v{_get_version()} · <a href="https://item.no" target="_blank">Item Consulting</a>',
        unsafe_allow_html=True,
    )

pg.run()
