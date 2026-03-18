"""Tests for app_realtime.py — _highlight_line, _is_safe_rt_path, _rt_poll."""
from __future__ import annotations

import sys
import tempfile
import types
from pathlib import Path
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Stub streamlit before importing app_realtime so module-level decorators
# (@st.fragment) and any st.* references don't fail.
# ---------------------------------------------------------------------------
class _AttrDict(dict):
    """Dict with attribute access (mimics Streamlit session_state)."""
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


_session_state = _AttrDict()

_streamlit_mock = mock.MagicMock()
_streamlit_mock.session_state = _session_state
# @st.fragment(run_every=N) must be a no-op decorator
_streamlit_mock.fragment = lambda *a, **kw: (lambda fn: fn) if not a else (
    (lambda fn: fn) if callable(a[0]) else (lambda fn: fn)
)
_streamlit_mock.cache_data = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_streamlit_mock.cache_resource = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_streamlit_mock.button = lambda *a, **kw: False
_streamlit_mock.columns = lambda n=1, **kw: (
    [mock.MagicMock() for _ in range(n)] if isinstance(n, int)
    else [mock.MagicMock() for _ in n]
)

sys.modules["streamlit"] = _streamlit_mock
sys.modules["streamlit.components"] = mock.MagicMock()
sys.modules["streamlit.components.v1"] = mock.MagicMock()

# Ensure the project root is on sys.path so app_realtime and app_constants import
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import importlib
import app_realtime as _art_mod  # noqa: E402
importlib.reload(_art_mod)  # ensure it uses our streamlit mock
_art_mod.st = _streamlit_mock  # force session_state binding
from app_realtime import _highlight_line, _is_safe_rt_path, _rt_poll  # noqa: E402


# ===========================================================================
# _is_safe_rt_path
# ===========================================================================

class TestIsSafeRtPath:
    def test_valid_log_file(self, tmp_path):
        """A real .log file that exists is allowed."""
        f = tmp_path / "server.log"
        f.write_text("hello")
        assert _is_safe_rt_path(str(f)) is True

    def test_valid_gz_file(self, tmp_path):
        f = tmp_path / "server.log.gz"
        f.write_bytes(b"\x1f\x8b")  # gzip magic bytes
        assert _is_safe_rt_path(str(f)) is True

    def test_valid_txt_file(self, tmp_path):
        f = tmp_path / "output.txt"
        f.write_text("line")
        assert _is_safe_rt_path(str(f)) is True

    def test_empty_path_returns_false(self):
        assert _is_safe_rt_path("") is False

    def test_none_path_returns_false(self):
        assert _is_safe_rt_path(None) is False

    def test_relative_path_with_bad_extension(self, tmp_path, monkeypatch):
        """A relative path that resolves outside allowed extensions is rejected."""
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "script.sh"
        f.write_text("#!/bin/sh")
        assert _is_safe_rt_path("script.sh") is False

    def test_wrong_extension_rejected(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("key: value")
        assert _is_safe_rt_path(str(f)) is False

    def test_symlink_rejected(self, tmp_path):
        target = tmp_path / "real.log"
        target.write_text("data")
        link = tmp_path / "link.log"
        link.symlink_to(target)
        assert _is_safe_rt_path(str(link)) is False

    def test_blocked_etc_path(self):
        assert _is_safe_rt_path("/etc/shadow.log") is False

    def test_blocked_proc_path(self):
        assert _is_safe_rt_path("/proc/self/fd/1.log") is False

    def test_blocked_sys_path(self):
        assert _is_safe_rt_path("/sys/kernel/debug.log") is False

    def test_blocked_dev_path(self):
        assert _is_safe_rt_path("/dev/null.log") is False

    def test_non_existent_file_with_log_extension(self, tmp_path):
        """A non-existent path with .log extension passes the safety check
        (existence is checked separately at runtime, not in _is_safe_rt_path)."""
        p = tmp_path / "missing.log"
        # p does not exist — but _is_safe_rt_path only checks suffix + symlink + blocked prefix
        # resolve() on a non-existent path still returns an absolute path
        assert _is_safe_rt_path(str(p)) is True


# ===========================================================================
# _highlight_line
# ===========================================================================

class TestHighlightLine:
    def test_error_line_gets_colored_span(self):
        result = _highlight_line("2024-01-01 ERROR Something broke")
        assert '<span style="color:' in result
        assert "ERROR" in result
        assert "[E]" in result

    def test_warning_line_gets_colored_span(self):
        result = _highlight_line("2024-01-01 WARNING Disk space low")
        assert "WARNING" in result
        assert "[W]" in result
        assert '<span style="color:' in result

    def test_warn_alias_gets_w_prefix(self):
        result = _highlight_line("WARN this is a warning")
        assert "[W]" in result

    def test_info_line_gets_colored_span(self):
        result = _highlight_line("INFO Server started")
        assert "[I]" in result
        assert '<span style="color:' in result

    def test_fatal_line_gets_colored_span(self):
        result = _highlight_line("FATAL out of memory")
        assert "[F]" in result
        assert '<span style="color:' in result

    def test_severe_line_mapped_to_e_prefix(self):
        result = _highlight_line("SEVERE connection refused")
        assert "[E]" in result

    def test_debug_line_gets_colored_span(self):
        result = _highlight_line("DEBUG verbose output here")
        assert "[D]" in result

    def test_plain_line_no_span(self):
        """Lines with no log-level keyword pass through without a span."""
        result = _highlight_line("just some plain text")
        assert "<span" not in result

    def test_html_entities_are_escaped(self):
        """Characters like <, >, & must be HTML-escaped."""
        result = _highlight_line("plain <script>alert(1)</script> text")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_html_escaped_in_error_line(self):
        """Angle brackets inside an ERROR line are escaped, span is still present."""
        result = _highlight_line("ERROR <bad> input")
        assert "&lt;bad&gt;" in result
        assert "[E]" in result

    def test_multiple_levels_in_one_line(self):
        """Multiple keywords in one line — both get styled spans."""
        result = _highlight_line("INFO start then ERROR stop")
        assert "[I]" in result
        assert "[E]" in result

    def test_returns_string(self):
        assert isinstance(_highlight_line("ERROR test"), str)


# ===========================================================================
# _rt_poll (via session_state simulation)
# ===========================================================================

class TestRtPoll:
    """Test _rt_poll using a real temp file and a mock logger."""

    def _make_state(self, filepath, offset=0):
        """Populate session_state keys _rt_poll reads."""
        _session_state.rt_file = filepath
        _session_state.rt_offset = offset
        _session_state.rt_buffer = []

    def test_reads_new_lines_from_file(self, tmp_path):
        log_file = tmp_path / "app.log"
        log_file.write_text("line one\nline two\n")
        self._make_state(str(log_file), offset=0)
        logger = mock.MagicMock()
        _rt_poll(logger)
        assert "line one" in _session_state.rt_buffer
        assert "line two" in _session_state.rt_buffer

    def test_no_new_data_when_offset_equals_size(self, tmp_path):
        log_file = tmp_path / "app.log"
        content = "existing line\n"
        log_file.write_text(content)
        self._make_state(str(log_file), offset=len(content.encode()))
        logger = mock.MagicMock()
        _rt_poll(logger)
        assert _session_state.rt_buffer == []

    def test_offset_reset_on_truncation(self, tmp_path):
        log_file = tmp_path / "app.log"
        log_file.write_text("short\n")
        # Pretend we previously read 9999 bytes (file was bigger before rotation)
        self._make_state(str(log_file), offset=9999)
        logger = mock.MagicMock()
        _rt_poll(logger)
        # After reset, offset should be 0 and new content read
        assert "short" in _session_state.rt_buffer

    def test_skips_empty_path(self):
        self._make_state("", offset=0)
        logger = mock.MagicMock()
        _rt_poll(logger)
        assert _session_state.rt_buffer == []

    def test_skips_unsafe_path(self, tmp_path):
        # A .sh file is not an allowed extension
        bad_file = tmp_path / "run.sh"
        bad_file.write_text("#!/bin/sh\n")
        self._make_state(str(bad_file), offset=0)
        logger = mock.MagicMock()
        _rt_poll(logger)
        assert _session_state.rt_buffer == []

    def test_skips_missing_file(self, tmp_path):
        nonexistent = str(tmp_path / "missing.log")
        self._make_state(nonexistent, offset=0)
        logger = mock.MagicMock()
        _rt_poll(logger)
        assert _session_state.rt_buffer == []

    def test_blank_lines_ignored(self, tmp_path):
        log_file = tmp_path / "app.log"
        log_file.write_text("line one\n\n   \nline two\n")
        self._make_state(str(log_file), offset=0)
        logger = mock.MagicMock()
        _rt_poll(logger)
        assert "" not in _session_state.rt_buffer
        assert "   " not in _session_state.rt_buffer
        assert "line one" in _session_state.rt_buffer
