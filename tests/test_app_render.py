"""Tests for pure/logic functions in app_render.py that don't require Streamlit widgets."""
from __future__ import annotations

import sys
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Stub Streamlit before importing app_render.
#
# IMPORTANT: We must register a mock before importing app_render so that
# `import streamlit as st` inside app_render binds to our mock. After that,
# even if other test modules replace sys.modules["streamlit"], app_render's
# `st` variable still holds a reference to THIS mock object — so we patch
# it directly via `app_render.st` in our autouse fixture.
# ---------------------------------------------------------------------------

class _AttrDict(dict):
    """Dict supporting attribute access — mirrors Streamlit session_state."""
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


# Build a dedicated session_state and mock for this test module.
# We register it only if nothing is already there; if another test module
# already registered one, we'll replace app_render.st in the autouse fixture.
_OWN_SESSION_STATE = _AttrDict()
_OWN_ST_MOCK = mock.MagicMock()
_OWN_ST_MOCK.session_state = _OWN_SESSION_STATE
_OWN_ST_MOCK.fragment = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_OWN_ST_MOCK.cache_data = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_OWN_ST_MOCK.cache_resource = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_OWN_ST_MOCK.columns = lambda n=1, **kw: (
    [mock.MagicMock() for _ in range(n)] if isinstance(n, int)
    else [mock.MagicMock() for _ in n]
)
_OWN_ST_MOCK.tabs = lambda names: [mock.MagicMock() for _ in names]
_OWN_ST_MOCK.selectbox = lambda label, options, **kw: (list(options)[0] if options else "")
_OWN_ST_MOCK.button = lambda *a, **kw: False
_OWN_ST_MOCK.multiselect = lambda label, options, default=None, **kw: default or []
_OWN_ST_MOCK.text_input = lambda label, value="", **kw: value
_OWN_ST_MOCK.checkbox = lambda label, value=False, **kw: value
_OWN_ST_MOCK.expander = mock.MagicMock(return_value=mock.MagicMock(
    __enter__=lambda s: s,
    __exit__=lambda s, *a: False,
))

if "streamlit" not in sys.modules:
    sys.modules["streamlit"] = _OWN_ST_MOCK
    sys.modules["streamlit.components"] = mock.MagicMock()
    sys.modules["streamlit.components.v1"] = mock.MagicMock()

# Import the module under test AFTER mock is registered.
import app_render  # noqa: E402
from app_render import _collect_ai_content, _apply_event_filters  # noqa: E402


# ---------------------------------------------------------------------------
# Autouse fixture
#
# We patch app_render.st with our own mock so that _collect_ai_content() and
# other functions read from _OWN_SESSION_STATE regardless of what other test
# modules do to sys.modules["streamlit"].
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _patch_st(monkeypatch):
    _OWN_SESSION_STATE.clear()
    monkeypatch.setattr(app_render, "st", _OWN_ST_MOCK)
    yield
    _OWN_SESSION_STATE.clear()


# Convenience shortcut used inside tests
_ss = _OWN_SESSION_STATE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(
    level="ERROR",
    code=None,
    exception=None,
    tags=None,
    system_label=None,
    ts=None,
    ts_utc=None,
    text="some log line",
):
    """Build a LogEvent for filter tests."""
    from logpilot.event import LogEvent
    return LogEvent(
        text=text,
        level=level,
        code=code,
        exception=exception,
        tags=tags or [],
        system_label=system_label or "server1",
        ts=ts or "10/12/15 21:22:04:257",
        ts_utc=ts_utc,
    )


# ===========================================================================
# _collect_ai_content
# ===========================================================================

class TestCollectAiContent:
    def test_returns_none_when_no_ai_content(self):
        result = _collect_ai_content()
        assert result is None

    def test_returns_incident_answer(self):
        _ss["_incident_answer"] = "Root cause is a DB connection pool exhaustion."
        _ss["_incident_model"] = "claude-sonnet-4-6"

        result = _collect_ai_content()

        assert result is not None
        assert result["incident"] == "Root cause is a DB connection pool exhaustion."
        assert result["incident_model"] == "claude-sonnet-4-6"

    def test_incident_model_defaults_to_ai_when_missing(self):
        _ss["_incident_answer"] = "Some triage answer"
        # intentionally omit _incident_model

        result = _collect_ai_content()

        assert result["incident_model"] == "AI"

    def test_returns_history_entries(self):
        _ss["claude_history"] = [
            {"query": "What caused this?", "answer": "OOM killer fired.", "timestamp": "12:00:00"},
        ]

        result = _collect_ai_content()

        assert result is not None
        assert "ask_ai" in result
        assert len(result["ask_ai"]) == 1
        entry = result["ask_ai"][0]
        assert entry["query"] == "What caused this?"
        assert entry["answer"] == "OOM killer fired."
        assert entry["provider"] == "Claude"

    def test_history_from_multiple_providers(self):
        _ss["claude_history"] = [{"query": "q1", "answer": "a1", "timestamp": "10:00"}]
        _ss["gemini_history"] = [{"query": "q2", "answer": "a2", "timestamp": "10:01"}]
        _ss["openai_history"] = [{"query": "q3", "answer": "a3", "timestamp": "10:02"}]
        _ss["local_history"] = [{"query": "q4", "answer": "a4", "timestamp": "10:03"}]

        result = _collect_ai_content()

        assert result is not None
        providers = {e["provider"] for e in result["ask_ai"]}
        assert providers == {"Claude", "Gemini", "OpenAI", "Local AI"}
        assert len(result["ask_ai"]) == 4

    def test_deduplicates_current_incident_answer_from_history(self):
        """History entry whose answer matches _incident_answer must be skipped."""
        shared_answer = "DB pool exhausted — increase maxPoolSize."
        _ss["_incident_answer"] = shared_answer
        _ss["claude_history"] = [
            {"query": "Why are connections failing?", "answer": shared_answer, "timestamp": "11:00"},
        ]

        result = _collect_ai_content()

        # The shared entry should not appear in ask_ai
        assert result.get("ask_ai") is None or result["ask_ai"] == []
        # But its query should be captured as incident_query
        assert result.get("incident_query") == "Why are connections failing?"

    def test_dedup_captures_query_only_once(self):
        """incident_query is set from the first matching history entry only."""
        shared_answer = "OOM"
        _ss["_incident_answer"] = shared_answer
        _ss["claude_history"] = [
            {"query": "first match", "answer": shared_answer, "timestamp": "10:00"},
            {"query": "second match", "answer": shared_answer, "timestamp": "10:01"},
        ]

        result = _collect_ai_content()

        # Only the first match sets incident_query
        assert result.get("incident_query") == "first match"

    def test_non_matching_history_entries_are_included(self):
        """History entries that don't match incident answer are included in ask_ai."""
        _ss["_incident_answer"] = "Answer A"
        _ss["claude_history"] = [
            {"query": "q1", "answer": "Answer A", "timestamp": "09:00"},  # deduped
            {"query": "q2", "answer": "Answer B", "timestamp": "09:01"},  # kept
        ]

        result = _collect_ai_content()

        assert result is not None
        assert len(result.get("ask_ai", [])) == 1
        assert result["ask_ai"][0]["query"] == "q2"

    def test_empty_history_lists_returns_none(self):
        _ss["claude_history"] = []
        _ss["gemini_history"] = []

        result = _collect_ai_content()

        assert result is None

    def test_history_entry_fields_are_mapped(self):
        """Provider label, timestamp, query and answer are correctly mapped."""
        _ss["openai_history"] = [
            {"query": "Explain ERROR", "answer": "It is an NPE", "timestamp": "15:30:00"},
        ]

        result = _collect_ai_content()
        entry = result["ask_ai"][0]

        assert entry["provider"] == "OpenAI"
        assert entry["timestamp"] == "15:30:00"
        assert entry["query"] == "Explain ERROR"
        assert entry["answer"] == "It is an NPE"

    def test_missing_history_fields_default_to_empty(self):
        """History entries with missing fields don't crash — they default to ''."""
        _ss["claude_history"] = [{}]  # completely empty entry

        result = _collect_ai_content()

        assert result is not None
        entry = result["ask_ai"][0]
        assert entry["query"] == ""
        assert entry["answer"] == ""
        assert entry["timestamp"] == ""


# ===========================================================================
# _apply_event_filters
# ===========================================================================

class TestApplyEventFilters:
    """Tests for _apply_event_filters — pure function, no Streamlit calls."""

    def _call(self, events, levels=None, code_prefix="", exception_types=None,
               time_range=None, sources=None):
        return _apply_event_filters(
            events,
            levels or [],
            code_prefix,
            exception_types or [],
            time_range,
            sources=sources,
        )

    # --- No filters ---

    def test_no_filters_returns_all_events(self):
        events = [_make_event("ERROR"), _make_event("INFO"), _make_event("WARNING")]
        result = self._call(events)
        assert len(result) == 3

    def test_does_not_modify_original_list(self):
        events = [_make_event("ERROR"), _make_event("INFO")]
        original_ids = [id(e) for e in events]
        self._call(events, levels=["ERROR"])
        assert [id(e) for e in events] == original_ids

    def test_empty_events_returns_empty(self):
        result = self._call([])
        assert result == []

    # --- Level filter ---

    def test_filter_by_single_level(self):
        events = [_make_event("ERROR"), _make_event("INFO"), _make_event("ERROR")]
        result = self._call(events, levels=["ERROR"])
        assert len(result) == 2
        assert all(e["level"] == "ERROR" for e in result)

    def test_filter_by_multiple_levels(self):
        events = [
            _make_event("ERROR"),
            _make_event("WARNING"),
            _make_event("INFO"),
            _make_event("DEBUG"),
        ]
        result = self._call(events, levels=["ERROR", "WARNING"])
        assert len(result) == 2
        assert {e["level"] for e in result} == {"ERROR", "WARNING"}

    def test_level_filter_treats_none_as_unknown(self):
        events = [
            _make_event(level=None),
            _make_event("ERROR"),
        ]
        result = self._call(events, levels=["UNKNOWN"])
        assert len(result) == 1
        assert result[0]["level"] is None

    def test_level_filter_no_match_returns_empty(self):
        events = [_make_event("INFO"), _make_event("DEBUG")]
        result = self._call(events, levels=["ERROR"])
        assert result == []

    def test_empty_levels_list_does_not_filter(self):
        events = [_make_event("ERROR"), _make_event("INFO")]
        result = self._call(events, levels=[])
        assert len(result) == 2

    # --- Code prefix filter ---

    def test_filter_by_code_prefix(self):
        events = [
            _make_event(code="SRVE0202E"),
            _make_event(code="CWWK0001I"),
            _make_event(code="SRVE0001W"),
            _make_event(code=None),
        ]
        result = self._call(events, code_prefix="SRVE")
        assert len(result) == 2
        assert all(e["code"].startswith("SRVE") for e in result)

    def test_code_prefix_is_case_insensitive(self):
        events = [
            _make_event(code="SRVE0202E"),
            _make_event(code="CWWK0001I"),
        ]
        result = self._call(events, code_prefix="srve")
        assert len(result) == 1
        assert result[0]["code"] == "SRVE0202E"

    def test_code_prefix_strips_whitespace(self):
        events = [_make_event(code="WSVR0001E"), _make_event(code="INFO001")]
        result = self._call(events, code_prefix="  WSVR  ")
        assert len(result) == 1

    def test_empty_code_prefix_does_not_filter(self):
        events = [_make_event(code="SRVE0202E"), _make_event(code=None)]
        result = self._call(events, code_prefix="")
        assert len(result) == 2

    def test_code_prefix_skips_events_without_code(self):
        events = [_make_event(code=None), _make_event(code="SRVE0001E")]
        result = self._call(events, code_prefix="SRVE")
        assert len(result) == 1

    # --- Exception type filter ---

    def test_filter_by_exception_type(self):
        events = [
            _make_event(exception="java.lang.NullPointerException"),
            _make_event(exception="java.io.IOException"),
            _make_event(exception=None),
        ]
        result = self._call(events, exception_types=["java.lang.NullPointerException"])
        assert len(result) == 1
        assert result[0]["exception"] == "java.lang.NullPointerException"

    def test_filter_by_multiple_exception_types(self):
        events = [
            _make_event(exception="java.lang.NullPointerException"),
            _make_event(exception="java.io.IOException"),
            _make_event(exception="java.lang.RuntimeException"),
        ]
        result = self._call(
            events,
            exception_types=["java.lang.NullPointerException", "java.io.IOException"],
        )
        assert len(result) == 2

    def test_exception_filter_excludes_none_exception(self):
        events = [_make_event(exception=None), _make_event(exception="NPE")]
        result = self._call(events, exception_types=["NPE"])
        assert len(result) == 1

    def test_empty_exception_list_does_not_filter(self):
        events = [_make_event(exception="NPE"), _make_event(exception=None)]
        result = self._call(events, exception_types=[])
        assert len(result) == 2

    # --- Source filter ---

    def test_filter_by_source(self):
        events = [
            _make_event(system_label="server1"),
            _make_event(system_label="server2"),
            _make_event(system_label="server1"),
        ]
        result = self._call(events, sources=["server1"])
        assert len(result) == 2
        assert all(e["system_label"] == "server1" for e in result)

    def test_filter_by_multiple_sources(self):
        events = [
            _make_event(system_label="appserver"),
            _make_event(system_label="dbserver"),
            _make_event(system_label="proxy"),
        ]
        result = self._call(events, sources=["appserver", "dbserver"])
        assert len(result) == 2

    def test_empty_sources_list_does_not_filter(self):
        events = [_make_event(system_label="s1"), _make_event(system_label="s2")]
        result = self._call(events, sources=[])
        assert len(result) == 2

    def test_sources_none_does_not_filter(self):
        events = [_make_event(system_label="s1"), _make_event(system_label="s2")]
        result = self._call(events, sources=None)
        assert len(result) == 2

    def test_source_missing_key_treated_as_unknown(self):
        """Events with system_label=None fall back to 'unknown'."""
        event_no_label = _make_event(system_label=None)
        # _make_event defaults system_label to "server1", override to None
        event_no_label.system_label = None
        result = self._call([event_no_label], sources=["unknown"])
        assert len(result) == 1

    # --- AND logic (combined filters) ---

    def test_level_and_exception_combined(self):
        events = [
            _make_event("ERROR", exception="NPE"),
            _make_event("ERROR", exception="IOE"),
            _make_event("WARNING", exception="NPE"),
        ]
        result = self._call(events, levels=["ERROR"], exception_types=["NPE"])
        assert len(result) == 1
        assert result[0]["exception"] == "NPE"
        assert result[0]["level"] == "ERROR"

    def test_level_and_code_prefix_combined(self):
        events = [
            _make_event("ERROR", code="SRVE0001E"),
            _make_event("ERROR", code="CWWK0001E"),
            _make_event("INFO", code="SRVE0002I"),
        ]
        result = self._call(events, levels=["ERROR"], code_prefix="SRVE")
        assert len(result) == 1
        assert result[0]["code"] == "SRVE0001E"

    def test_all_filters_combined_no_match(self):
        events = [_make_event("ERROR", code="SRVE", exception="NPE", system_label="s1")]
        # Add a source filter that excludes the event
        result = self._call(
            events,
            levels=["ERROR"],
            code_prefix="SRVE",
            exception_types=["NPE"],
            sources=["s2"],  # wrong source
        )
        assert result == []

    def test_all_filters_combined_match(self):
        events = [
            _make_event("ERROR", code="SRVE0001E", exception="NPE", system_label="s1"),
            _make_event("WARNING", code="SRVE0002W", exception="IOE", system_label="s1"),
        ]
        result = self._call(
            events,
            levels=["ERROR"],
            code_prefix="SRVE",
            exception_types=["NPE"],
            sources=["s1"],
        )
        assert len(result) == 1
        assert result[0]["level"] == "ERROR"

    # --- Time range filter ---

    def test_time_range_none_does_not_filter(self):
        events = [_make_event(ts="10/12/15 21:22:04:257")]
        result = self._call(events, time_range=None)
        assert len(result) == 1

    def test_time_range_single_none_values_does_not_filter(self):
        events = [_make_event(ts="10/12/15 21:22:04:257")]
        result = self._call(events, time_range=(None, None))
        assert len(result) == 1

    def test_events_without_ts_excluded_when_time_filter_active(self):
        from datetime import time as dt_time
        events = [
            _make_event(ts=None),
            _make_event(ts="10/12/15 21:22:04:257"),
        ]
        # Use a wide time range that would include 21:22 if parsed
        t_start = dt_time(0, 0)
        t_end = dt_time(23, 59, 59)
        result = self._call(events, time_range=(t_start, t_end))
        # ts=None events are excluded when time filtering is active
        assert all(e["ts"] is not None for e in result)
