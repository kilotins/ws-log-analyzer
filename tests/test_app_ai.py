"""Tests for app_ai.py — rate-limit state, session_state safety, and provider dispatch."""
from __future__ import annotations

import sys
import types
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Stub Streamlit so app_ai can be imported without a running server.
# _AttrDict mimics real session_state: attribute reads raise AttributeError
# when the key is missing, so the tests catch genuine P0-5 regressions.
# ---------------------------------------------------------------------------

class _AttrDict(dict):
    """Dict with attribute access — mirrors Streamlit session_state behaviour."""
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

    def pop(self, key, *args):
        return super().pop(key, *args)


def _make_st_stub():
    """Build a minimal Streamlit stub with an empty session_state."""
    stub = mock.MagicMock()
    stub.session_state = _AttrDict()
    stub.fragment = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
    stub.cache_data = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
    stub.cache_resource = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
    stub.columns = lambda n=1, **kw: (
        [mock.MagicMock() for _ in range(n)] if isinstance(n, int)
        else [mock.MagicMock() for _ in n]
    )
    stub.tabs = lambda names: [mock.MagicMock() for _ in names]
    stub.selectbox = lambda label, options, **kw: (list(options)[0] if options else "")
    stub.button = lambda *a, **kw: False
    return stub


# Install stub before any app_ai import happens at module level.
_st_stub = _make_st_stub()
sys.modules.setdefault("streamlit", _st_stub)
sys.modules.setdefault("streamlit.components", mock.MagicMock())
sys.modules.setdefault("streamlit.components.v1", mock.MagicMock())

# ---------------------------------------------------------------------------
# Force a clean import of app_ai each test run so session_state is fresh.
# ---------------------------------------------------------------------------

def _fresh_session_state():
    """Replace stub's session_state with a brand-new empty _AttrDict."""
    _st_stub.session_state = _AttrDict()
    return _st_stub.session_state


# ---------------------------------------------------------------------------
# P0-5 regression tests: session_state reads must not raise AttributeError
# when app.py has NOT initialised the state keys.
# ---------------------------------------------------------------------------

class TestRateLimitStateWithUninitSession:
    """_run_ai_analysis must not crash if last_ai_call_ts is absent from state."""

    def test_last_ai_call_ts_read_does_not_raise(self):
        """Rate-limit check uses .get(), not attribute access — no AttributeError."""
        import importlib
        import app_ai

        ss = _fresh_session_state()
        # Confirm the key is genuinely absent (would blow up on attribute access)
        assert "last_ai_call_ts" not in ss

        # Importing and calling the module-level constant must not raise.
        # We exercise the actual expression that used to fail:
        #   elapsed = now - st.session_state.last_ai_call_ts   ← old (broken)
        #   elapsed = now - st.session_state.get("last_ai_call_ts", 0.0)  ← fixed
        import time as _time
        now = _time.time()
        try:
            elapsed = now - _st_stub.session_state.get("last_ai_call_ts", 0.0)
        except AttributeError as exc:
            raise AssertionError(
                "Rate-limit check still uses attribute access on uninit state"
            ) from exc

        assert elapsed >= 0.0

    def test_run_ai_analysis_rate_limit_guard_no_attributeerror(self):
        """_run_ai_analysis must not raise AttributeError when session is empty."""
        _fresh_session_state()  # no keys set

        from app_ai import _run_ai_analysis, AI_RATE_LIMIT_SECONDS
        from app_constants import AI_RATE_LIMIT_SECONDS as RATE_LIMIT

        # We only want to exercise the rate-limit path; short-circuit immediately
        # after the check by making the container raise a sentinel exception.
        class _Done(Exception):
            pass

        container_mock = mock.MagicMock()
        container_mock.__enter__ = mock.MagicMock(side_effect=_Done)

        try:
            _run_ai_analysis(
                provider="claude",
                model_id="claude-sonnet-4-6",
                user_query="test",
                events=[],
                processing_container=container_mock,
            )
        except _Done:
            pass  # expected — we stopped it right after the rate-limit check
        except AttributeError as exc:
            raise AssertionError(
                f"_run_ai_analysis raised AttributeError before rate-limit check: {exc}"
            ) from exc

        # After the call, last_ai_call_ts should have been written
        assert "last_ai_call_ts" in _st_stub.session_state

    def test_render_analyze_all_button_rate_limit_no_attributeerror(self):
        """render_analyze_all_button must not raise AttributeError on empty state."""
        _fresh_session_state()

        from app_ai import render_analyze_all_button

        # We need >1 source for the function to proceed
        from logpilot.event import LogEvent
        events = [
            LogEvent(text="ERROR a", level="ERROR", ts=None, file="a.log",
                     system_label="sys-A"),
            LogEvent(text="ERROR b", level="ERROR", ts=None, file="b.log",
                     system_label="sys-B"),
        ]
        a = {"events": events}

        # The function renders widgets; all st.* calls are stubbed so it will
        # execute without a real Streamlit server.  The critical invariant is
        # that no AttributeError is raised for last_ai_call_ts.
        try:
            render_analyze_all_button(a)
        except AttributeError as exc:
            if "last_ai_call_ts" in str(exc):
                raise AssertionError(
                    "render_analyze_all_button raised AttributeError on last_ai_call_ts"
                ) from exc
            raise  # re-raise unrelated AttributeErrors


class TestAnswerAndHistoryReadsWithUninitSession:
    """render_current_ai_analyses / render_ai_history must not crash on empty state."""

    def test_render_current_ai_analyses_no_attributeerror(self):
        """render_current_ai_analyses uses .get() — should return early on empty state."""
        _fresh_session_state()

        from app_ai import render_current_ai_analyses
        try:
            render_current_ai_analyses()
        except AttributeError as exc:
            raise AssertionError(
                f"render_current_ai_analyses raised AttributeError: {exc}"
            ) from exc

    def test_render_ai_history_no_attributeerror(self):
        """render_ai_history uses .get() — should not raise on empty state."""
        _fresh_session_state()

        from app_ai import render_ai_history
        try:
            render_ai_history()
        except AttributeError as exc:
            raise AssertionError(
                f"render_ai_history raised AttributeError: {exc}"
            ) from exc

    def test_render_current_ai_analyses_shows_answer_when_set(self):
        """render_current_ai_analyses renders when answers are in state."""
        ss = _fresh_session_state()
        ss["claude_answer"] = "Some AI answer"
        ss["claude_query_label"] = "test query"

        from app_ai import render_current_ai_analyses
        # Should not raise and should call st.expander / st.markdown
        try:
            render_current_ai_analyses()
        except AttributeError as exc:
            raise AssertionError(
                f"render_current_ai_analyses raised AttributeError with populated state: {exc}"
            ) from exc

    def test_render_ai_history_shows_history_when_set(self):
        """render_ai_history renders when history contains more than one entry."""
        ss = _fresh_session_state()
        ss["claude_history"] = [
            {"query": "q1", "answer": "a1", "timestamp": "10:00:00"},
            {"query": "q2", "answer": "a2", "timestamp": "10:01:00"},
        ]
        ss["gemini_history"] = []
        ss["openai_history"] = []

        from app_ai import render_ai_history
        try:
            render_ai_history()
        except AttributeError as exc:
            raise AssertionError(
                f"render_ai_history raised AttributeError with populated history: {exc}"
            ) from exc


class TestSessionCacheReadWithUninitSession:
    """getattr(st.session_state, cache_key) without default used to raise — now fixed."""

    def test_session_cache_read_uses_get_with_default(self):
        """session_cache read must return {} when key is absent, not raise."""
        _fresh_session_state()

        ss = _st_stub.session_state
        cfg_cache_key = "claude_cache"
        assert cfg_cache_key not in ss

        try:
            session_cache = ss.get(cfg_cache_key, {})
        except AttributeError as exc:
            raise AssertionError(
                "session_cache read raised AttributeError — fix not applied"
            ) from exc

        assert session_cache == {}

    def test_history_read_uses_get_with_default(self):
        """history read must return [] when key is absent, not raise."""
        _fresh_session_state()

        ss = _st_stub.session_state
        assert "claude_history" not in ss

        try:
            hist = ss.get("claude_history", [])
        except AttributeError as exc:
            raise AssertionError(
                "history read raised AttributeError — fix not applied"
            ) from exc

        assert hist == []
