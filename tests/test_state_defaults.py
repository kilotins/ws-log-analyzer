"""Smoke test: all runtime-written session_state keys must be declared in _STATE_DEFAULTS."""
import sys
import types
from unittest import mock


# ---------------------------------------------------------------------------
# Mock Streamlit before importing app so module-level startup code doesn't fail.
# ---------------------------------------------------------------------------
class _AttrDict(dict):
    """Dict that supports attribute access (like Streamlit session_state)."""
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)
    def __setattr__(self, key, value):
        self[key] = value
    def __delattr__(self, key):
        try:
            del self[key]
        except KeyError:
            raise AttributeError(key)
    def get(self, key, default=None):
        return self[key] if key in self else default


_session_state = _AttrDict()

_streamlit_mock = mock.MagicMock()
_streamlit_mock.session_state = _session_state
_streamlit_mock.fragment = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_streamlit_mock.cache_data = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_streamlit_mock.cache_resource = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_streamlit_mock.columns = lambda n=1, **kw: (
    [mock.MagicMock() for _ in range(n)] if isinstance(n, int)
    else [mock.MagicMock() for _ in n]
)
_streamlit_mock.tabs = lambda names: [mock.MagicMock() for _ in names]
_streamlit_mock.selectbox = lambda label, options, **kw: (list(options)[0] if options else "")
_streamlit_mock.button = lambda *a, **kw: False

sys.modules.setdefault("streamlit", _streamlit_mock)
sys.modules.setdefault("streamlit.components", mock.MagicMock())
sys.modules.setdefault("streamlit.components.v1", mock.MagicMock())


def test_state_defaults_contains_all_runtime_keys():
    """All keys actually written by app code at runtime must be declared in _STATE_DEFAULTS."""
    # Keys confirmed to be written by production code (see P0-3 audit):
    #   - pages/home.py, app_incident.py, app_ai.py, pages/code.py, app.py
    expected_keys = {
        "_incident_screenshots",     # pages/home.py:45  (plural)
        "noise_threshold_slider",    # app_incident.py:467
        "filter_levels",             # app.py:880
        "filter_sources",            # app.py:885
        "_selected_ai_model",        # app.py:866
        "incident_history",          # app_incident.py:587-593
        "folder_path",               # pages/home.py:108
        "_code_matches",             # pages/code.py:28, app_incident.py:715-718
        "_code_cache_key",           # pages/code.py:31, app_incident.py:719
        "_triage_answer",            # app_ai.py:1194, 1230
        "_triage_model",             # app_ai.py:1195, 1231
        "_pending_hist_delete",      # app_incident.py:848
        "_app_theme",                # app.py:571
        "triage_model",              # app_ai.py:1165 (widget key)
        "_ai_exclude_patterns",      # app_incident.py:413 (widget key)
        "last_ai_call_ts",           # app_ai.py:725, app_incident.py:544
    }

    from app import _STATE_DEFAULTS  # noqa: E402

    missing = expected_keys - set(_STATE_DEFAULTS.keys())
    assert not missing, (
        f"Keys written at runtime but missing from _STATE_DEFAULTS — "
        f"add them with sensible defaults: {sorted(missing)}"
    )


def test_state_defaults_no_singular_screenshot():
    """The obsolete singular _incident_screenshot key must NOT be in _STATE_DEFAULTS."""
    from app import _STATE_DEFAULTS  # noqa: E402

    assert "_incident_screenshot" not in _STATE_DEFAULTS, (
        "_incident_screenshot (singular) is never written by production code; "
        "remove it from _STATE_DEFAULTS to keep the schema clean."
    )
