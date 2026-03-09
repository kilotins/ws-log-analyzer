"""Tests for helper functions in app.py that don't require a running Streamlit server."""
import json
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Mock Streamlit before importing app so module-level code doesn't fail.
# ---------------------------------------------------------------------------
class _AttrDict(dict):
    """Dict that also supports attribute access (like Streamlit session_state)."""
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

# Use MagicMock as the streamlit module so any st.* attribute resolves
_streamlit_mock = mock.MagicMock()
_streamlit_mock.session_state = _session_state
# Make fragment decorator a no-op that returns the function
_streamlit_mock.fragment = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
# Make cache_data/cache_resource decorators no-ops
_streamlit_mock.cache_data = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_streamlit_mock.cache_resource = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
# st.columns(n) must return n mock objects for tuple unpacking
_streamlit_mock.columns = lambda n=1, **kw: [mock.MagicMock() for _ in range(n)] if isinstance(n, int) else [mock.MagicMock() for _ in n]
# st.tabs must return list of mock context managers
_streamlit_mock.tabs = lambda names: [mock.MagicMock() for _ in names]
# st.selectbox must return a string (not MagicMock) to avoid dict key errors
_streamlit_mock.selectbox = lambda label, options, **kw: (list(options)[0] if options else "")
# st.button returns False by default (no click)
_streamlit_mock.button = lambda *a, **kw: False

sys.modules["streamlit"] = _streamlit_mock
sys.modules["streamlit.components"] = mock.MagicMock()
sys.modules["streamlit.components.v1"] = mock.MagicMock()

# Now import the helpers under test
from app import (                       # noqa: E402
    _load_json_file,
    _save_json_file,
    _looks_like_splunk,
    _split_combined_splunk,
    _extract_splunk_from_response,
    get_report_history,
    _highlight_line,
    _is_safe_rt_path,
    _load_keychain,
    _save_keychain,
    _load_provider_history,
    _save_provider_history,
    _PROVIDER_CONFIG,
    REPORTS_DIR,
)


# ── _load_json_file / _save_json_file ─────────────────────────────────────

class TestLoadJsonFile:
    def test_existing_valid_json(self, tmp_path):
        f = tmp_path / "data.json"
        f.write_text('{"a": 1}', encoding="utf-8")
        assert _load_json_file(f, {}) == {"a": 1}

    def test_missing_file_returns_default(self, tmp_path):
        f = tmp_path / "missing.json"
        assert _load_json_file(f, []) == []

    def test_corrupt_json_returns_default(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{not valid json", encoding="utf-8")
        assert _load_json_file(f, {"fallback": True}) == {"fallback": True}

    def test_empty_file_returns_default(self, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text("", encoding="utf-8")
        assert _load_json_file(f, 42) == 42


class TestSaveJsonFile:
    def test_write_and_read_back(self, tmp_path):
        f = tmp_path / "out.json"
        data = {"key": [1, 2, 3]}
        _save_json_file(f, data)
        assert json.loads(f.read_text(encoding="utf-8")) == data

    def test_unicode_roundtrip(self, tmp_path):
        f = tmp_path / "uni.json"
        data = {"emoji": "\u2603", "kanji": "\u6f22\u5b57"}
        _save_json_file(f, data)
        assert _load_json_file(f, {}) == data


# ── _looks_like_splunk ────────────────────────────────────────────────────

class TestLooksLikeSplunk:
    @pytest.mark.parametrize("code", [
        'index=was_logs sourcetype=websphere',
        'search index=main | timechart count by severity',
        '| stats count by host',
        'index=prod | table _time host message',
        'index=prod | where severity="ERROR"',
        '| eval duration=end-start',
    ])
    def test_recognises_splunk_queries(self, code):
        assert _looks_like_splunk(code) is True

    @pytest.mark.parametrize("code", [
        'System.out.println("hello");',
        'SELECT * FROM logs WHERE level = "ERROR"',
        'curl -X GET http://localhost:8080',
        '',
    ])
    def test_rejects_non_splunk(self, code):
        assert _looks_like_splunk(code) is False


# ── _split_combined_splunk ────────────────────────────────────────────────

class TestSplitCombinedSplunk:
    def test_single_query_no_separator(self):
        code = 'index=was_logs | stats count by host'
        result = _split_combined_splunk(code)
        assert len(result) == 1
        assert result[0]["query"] == code

    def test_multiple_queries_split(self):
        code = (
            "-- Error count by host\n"
            "index=was_logs severity=ERROR | stats count by host\n"
            "-- Timechart of errors\n"
            "index=was_logs severity=ERROR | timechart count"
        )
        result = _split_combined_splunk(code)
        assert len(result) == 2
        assert result[0]["description"] == "Error count by host"
        assert "stats count by host" in result[0]["query"]
        assert result[1]["description"] == "Timechart of errors"
        assert "timechart count" in result[1]["query"]

    def test_empty_string(self):
        result = _split_combined_splunk("")
        assert len(result) == 1
        assert result[0]["query"] == ""


# ── _extract_splunk_from_response ─────────────────────────────────────────

class TestExtractSplunkFromResponse:
    def test_extracts_fenced_splunk_query(self):
        text = (
            "Here is a useful Splunk query:\n"
            "```spl\n"
            "index=was_logs severity=ERROR | stats count by host\n"
            "```\n"
        )
        result = _extract_splunk_from_response(text)
        assert len(result) == 1
        assert "stats count by host" in result[0]["query"]

    def test_extracts_unlabelled_fence_with_splunk_content(self):
        text = (
            "Try this:\n"
            "```\n"
            "index=prod | table _time host message\n"
            "```\n"
        )
        result = _extract_splunk_from_response(text)
        assert len(result) == 1

    def test_ignores_non_splunk_code_blocks(self):
        text = (
            "Example Java code:\n"
            "```java\n"
            "System.out.println(\"hello\");\n"
            "```\n"
        )
        result = _extract_splunk_from_response(text)
        assert result == []

    def test_no_code_blocks(self):
        text = "No code blocks here, just plain text."
        result = _extract_splunk_from_response(text)
        assert result == []

    def test_uses_preceding_text_as_description(self):
        text = (
            "**Error rate query**\n"
            "```spl\n"
            "index=was_logs | stats count by severity\n"
            "```\n"
        )
        result = _extract_splunk_from_response(text)
        assert len(result) == 1
        assert "Error rate query" in result[0]["description"]


# ── get_report_history ────────────────────────────────────────────────────

class TestGetReportHistory:
    def test_returns_recent_reports(self, tmp_path, monkeypatch):
        # Point REPORTS_DIR to tmp_path
        import app as app_mod
        monkeypatch.setattr(app_mod, "REPORTS_DIR", tmp_path)

        # Create some dummy reports with distinct mtimes
        import time
        for i in range(5):
            p = tmp_path / f"report_{i:03d}.md"
            p.write_text(f"report {i}")
            # Ensure distinct mtimes
            import os
            os.utime(p, (1000 + i, 1000 + i))

        result = get_report_history(limit=3)
        assert len(result) == 3
        # Newest first (highest mtime)
        assert result[0].name == "report_004.md"

    def test_empty_directory(self, tmp_path, monkeypatch):
        import app as app_mod
        monkeypatch.setattr(app_mod, "REPORTS_DIR", tmp_path)
        assert get_report_history() == []

    def test_ignores_non_report_files(self, tmp_path, monkeypatch):
        import app as app_mod
        monkeypatch.setattr(app_mod, "REPORTS_DIR", tmp_path)
        (tmp_path / "notes.md").write_text("not a report")
        (tmp_path / "report_001.md").write_text("a report")
        result = get_report_history()
        assert len(result) == 1
        assert result[0].name == "report_001.md"


# ── _highlight_line ───────────────────────────────────────────────────────

class TestHighlightLine:
    def test_error_highlighted(self):
        result = _highlight_line("2024-01-01 ERROR something broke")
        assert 'color:#dc3545' in result
        assert "ERROR" in result

    def test_info_highlighted(self):
        result = _highlight_line("INFO server started")
        assert 'color:#0d6efd' in result

    def test_warn_highlighted(self):
        result = _highlight_line("WARN low memory")
        assert 'color:#ffc107' in result

    def test_no_level_unchanged(self):
        line = "just a plain line with no level"
        result = _highlight_line(line)
        # Should still be HTML-escaped but no color spans
        assert '<span' not in result
        assert line == result  # plain text passes through

    def test_html_entities_escaped(self):
        result = _highlight_line('<script>alert("ERROR")</script>')
        assert "<script>" not in result
        assert "&lt;script&gt;" in result
        # ERROR should still be highlighted
        assert 'color:#dc3545' in result


# ── _is_safe_rt_path ─────────────────────────────────────────────────────

class TestIsSafeRtPath:
    @pytest.mark.parametrize("path", [
        "/var/log/websphere/server.log",
        "/tmp/test.log",
        "/opt/IBM/output.gz",
        "/home/user/app.txt",
        "/home/user/server.out",
    ])
    def test_safe_paths(self, path):
        assert _is_safe_rt_path(path) is True

    @pytest.mark.parametrize("path", [
        "",
        None,
        "/etc/passwd",
        "/etc/shadow",
        "/private/etc/hosts",
        "/proc/1/cmdline",
        "/sys/class/net",
        "/dev/sda",
    ])
    def test_unsafe_paths(self, path):
        assert _is_safe_rt_path(path) is False

    def test_wrong_extension(self):
        assert _is_safe_rt_path("/tmp/data.csv") is False
        assert _is_safe_rt_path("/tmp/script.py") is False
        assert _is_safe_rt_path("/tmp/config.json") is False


# ── _load_keychain / _save_keychain ───────────────────────────────────────

class TestKeychainHelpers:
    def test_load_keychain_from_keyring(self):
        mock_keyring = mock.MagicMock()
        mock_keyring.get_password.return_value = "sk-secret-123"
        with mock.patch.dict(sys.modules, {"keyring": mock_keyring}):
            result = _load_keychain("test_user", "TEST_ENV_VAR")
        assert result == "sk-secret-123"
        mock_keyring.get_password.assert_called_once_with("ws-log-analyzer", "test_user")

    def test_load_keychain_falls_back_to_env(self, monkeypatch):
        # Simulate keyring not installed
        mock_keyring = mock.MagicMock()
        mock_keyring.get_password.side_effect = Exception("no keyring")
        monkeypatch.setenv("MY_API_KEY", "env-key-456")
        with mock.patch.dict(sys.modules, {"keyring": mock_keyring}):
            result = _load_keychain("test_user", "MY_API_KEY")
        assert result == "env-key-456"

    def test_load_keychain_returns_empty_when_nothing(self, monkeypatch):
        mock_keyring = mock.MagicMock()
        mock_keyring.get_password.return_value = None
        monkeypatch.delenv("NO_SUCH_VAR", raising=False)
        with mock.patch.dict(sys.modules, {"keyring": mock_keyring}):
            result = _load_keychain("test_user", "NO_SUCH_VAR")
        assert result == ""

    def test_save_keychain_stores_key(self):
        mock_keyring = mock.MagicMock()
        with mock.patch.dict(sys.modules, {"keyring": mock_keyring}):
            _save_keychain("test_user", "new-key-789", label="Test")
        mock_keyring.set_password.assert_called_once_with(
            "ws-log-analyzer", "test_user", "new-key-789"
        )

    def test_save_keychain_deletes_when_empty(self):
        mock_keyring = mock.MagicMock()
        with mock.patch.dict(sys.modules, {"keyring": mock_keyring}):
            _save_keychain("test_user", "", label="Test")
        mock_keyring.delete_password.assert_called_once_with(
            "ws-log-analyzer", "test_user"
        )

    def test_save_keychain_handles_exception(self):
        mock_keyring = mock.MagicMock()
        mock_keyring.set_password.side_effect = Exception("locked")
        with mock.patch.dict(sys.modules, {"keyring": mock_keyring}):
            # Should not raise
            _save_keychain("test_user", "key", label="Test")


# ── _load_provider_history / _save_provider_history ──────────────────────

class TestProviderHistory:
    def test_load_empty(self, tmp_path):
        f = tmp_path / "history.json"
        assert _load_provider_history(f) == []

    def test_save_and_load_roundtrip(self, tmp_path):
        f = tmp_path / "history.json"
        data = [{"query": "test", "answer": "ok", "timestamp": "12:00:00"}]
        _save_provider_history(f, data)
        assert _load_provider_history(f) == data

    def test_save_truncates_to_max(self, tmp_path):
        f = tmp_path / "history.json"
        import app as app_mod
        orig_max = app_mod.MAX_HISTORY_ENTRIES
        try:
            app_mod.MAX_HISTORY_ENTRIES = 3
            data = [{"query": f"q{i}", "answer": f"a{i}", "timestamp": "00:00"} for i in range(10)]
            _save_provider_history(f, data)
            loaded = _load_provider_history(f)
            assert len(loaded) == 3
            assert loaded[0]["query"] == "q7"  # kept last 3
        finally:
            app_mod.MAX_HISTORY_ENTRIES = orig_max

    def test_load_corrupt_returns_empty(self, tmp_path):
        f = tmp_path / "history.json"
        f.write_text("not json!", encoding="utf-8")
        assert _load_provider_history(f) == []

    def test_load_non_list_returns_empty(self, tmp_path):
        f = tmp_path / "history.json"
        f.write_text('{"key": "value"}', encoding="utf-8")
        assert _load_provider_history(f) == []


# ── _PROVIDER_CONFIG ─────────────────────────────────────────────────────

class TestProviderConfig:
    @pytest.mark.parametrize("provider", ["claude", "gemini", "openai"])
    def test_all_providers_have_required_keys(self, provider):
        cfg = _PROVIDER_CONFIG[provider]
        required = ["label", "cache_key", "answer_key", "query_label_key",
                     "history_key", "api_key_field", "save_history",
                     "extract_splunk", "api_key_error"]
        for key in required:
            assert key in cfg, f"Missing key '{key}' in {provider} config"

    def test_claude_extracts_splunk(self):
        assert _PROVIDER_CONFIG["claude"]["extract_splunk"] is True

    def test_gemini_does_not_extract_splunk(self):
        assert _PROVIDER_CONFIG["gemini"]["extract_splunk"] is False

    def test_openai_does_not_extract_splunk(self):
        assert _PROVIDER_CONFIG["openai"]["extract_splunk"] is False
