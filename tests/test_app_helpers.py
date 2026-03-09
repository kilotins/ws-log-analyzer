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
    _estimate_cost,
    _extract_signatures,
    _call_claude_api,
    _call_openai_api,
    _call_gemini_api,
    _collect_audit_sources,
    _PROVIDER_HISTORY_FILES,
    _AI_RATE_LIMIT_SECONDS,
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

    def test_out_extension_rejected(self):
        """'.out' extension was removed for security — should be rejected."""
        assert _is_safe_rt_path("/home/user/server.out") is False

    def test_symlink_rejected(self, tmp_path):
        """Symlinks should be rejected to prevent path traversal."""
        real_file = tmp_path / "real.log"
        real_file.write_text("log data", encoding="utf-8")
        link = tmp_path / "link.log"
        link.symlink_to(real_file)
        assert _is_safe_rt_path(str(link)) is False

    def test_symlink_to_sensitive_rejected(self, tmp_path):
        """Symlink pointing to sensitive path should be rejected."""
        link = tmp_path / "sneaky.log"
        link.symlink_to("/etc/passwd")
        assert _is_safe_rt_path(str(link)) is False


# ── API key prefix validation ────────────────────────────────────────────

class TestApiKeyPrefix:
    def test_claude_key_prefix(self):
        assert _PROVIDER_CONFIG["claude"]["api_key_prefix"] == "sk-ant-"

    def test_openai_key_prefix(self):
        assert _PROVIDER_CONFIG["openai"]["api_key_prefix"] == "sk-"

    def test_gemini_key_prefix(self):
        assert _PROVIDER_CONFIG["gemini"]["api_key_prefix"] == "AI"

    def test_all_providers_have_prefix(self):
        for provider, cfg in _PROVIDER_CONFIG.items():
            assert "api_key_prefix" in cfg, f"{provider} missing api_key_prefix"


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
        with mock.patch.dict(sys.modules, {"keyring": mock_keyring}), \
             mock.patch("app._load_json_file", return_value={}):
            result = _load_keychain("test_user", "MY_API_KEY")
        assert result == "env-key-456"

    def test_load_keychain_returns_empty_when_nothing(self, monkeypatch):
        mock_keyring = mock.MagicMock()
        mock_keyring.get_password.return_value = None
        monkeypatch.delenv("NO_SUCH_VAR", raising=False)
        with mock.patch.dict(sys.modules, {"keyring": mock_keyring}), \
             mock.patch("app._load_json_file", return_value={}):
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


# ── _estimate_cost ───────────────────────────────────────────────────────

class TestEstimateCost:
    def test_known_model(self):
        # gpt-4o: $2.50/1M input, $10.00/1M output
        cost = _estimate_cost("gpt-4o", 1000, 500)
        assert cost == pytest.approx(0.0025 + 0.005, abs=1e-6)

    def test_unknown_model_returns_zero(self):
        assert _estimate_cost("unknown-model", 1000, 500) == 0.0

    def test_zero_tokens(self):
        assert _estimate_cost("gpt-4o", 0, 0) == 0.0

    def test_large_input(self):
        # 1M tokens input on claude-sonnet-4-6: $3.00
        cost = _estimate_cost("claude-sonnet-4-6", 1_000_000, 0)
        assert cost == pytest.approx(3.00, abs=0.01)


# ── _extract_signatures ─────────────────────────────────────────────────

class TestExtractSignatures:
    def test_extracts_function_def(self):
        code = 'def hello(name):\n    """Say hello."""\n    print(name)\n'
        result = _extract_signatures(code)
        assert "def hello(name):" in result
        assert '"""Say hello."""' in result
        assert "print(name)" not in result

    def test_extracts_class_def(self):
        code = 'class Foo:\n    """A foo."""\n    x = 1\n'
        result = _extract_signatures(code)
        assert "class Foo:" in result
        assert '"""A foo."""' in result

    def test_extracts_imports(self):
        code = 'import os\nfrom pathlib import Path\nx = 1\n'
        result = _extract_signatures(code)
        assert "import os" in result
        assert "from pathlib import Path" in result

    def test_extracts_top_level_constants(self):
        code = 'MAX_SIZE = 100\n_INTERNAL = "abc"\n'
        result = _extract_signatures(code)
        assert "MAX_SIZE = 100" in result

    def test_empty_source(self):
        assert _extract_signatures("") == ""

    def test_multiline_docstring(self):
        code = 'def foo():\n    """Multi\n    line\n    doc."""\n    pass\n'
        result = _extract_signatures(code)
        assert "Multi" in result
        assert "doc." in result
        assert "pass" not in result


# ── API callers (mock-based) ────────────────────────────────────────────

class TestCallClaudeApi:
    def test_returns_text_and_usage(self):
        mock_anthropic = mock.MagicMock()
        mock_msg = mock.MagicMock()
        mock_msg.content = [mock.MagicMock(text="Hello from Claude")]
        mock_msg.usage = mock.MagicMock(input_tokens=100, output_tokens=50)
        mock_anthropic.Anthropic.return_value.messages.create.return_value = mock_msg
        with mock.patch.dict(sys.modules, {"anthropic": mock_anthropic}):
            answer, usage = _call_claude_api("key", "model", {"system": "s", "user": "u"})
        assert answer == "Hello from Claude"
        assert usage == {"input": 100, "output": 50}

    def test_empty_content_returns_none(self):
        mock_anthropic = mock.MagicMock()
        mock_msg = mock.MagicMock()
        mock_msg.content = []
        mock_anthropic.Anthropic.return_value.messages.create.return_value = mock_msg
        with mock.patch.dict(sys.modules, {"anthropic": mock_anthropic}):
            answer, usage = _call_claude_api("key", "model", {"system": "s", "user": "u"})
        assert answer is None


class TestCallOpenaiApi:
    def test_returns_text_and_usage(self):
        mock_openai = mock.MagicMock()
        mock_choice = mock.MagicMock()
        mock_choice.message.content = "Hello from GPT"
        mock_resp = mock.MagicMock()
        mock_resp.choices = [mock_choice]
        mock_resp.usage = mock.MagicMock(prompt_tokens=200, completion_tokens=80)
        mock_openai.OpenAI.return_value.chat.completions.create.return_value = mock_resp
        with mock.patch.dict(sys.modules, {"openai": mock_openai}):
            answer, usage = _call_openai_api("key", "model", {"system": "s", "user": "u"})
        assert answer == "Hello from GPT"
        assert usage == {"input": 200, "output": 80}

    def test_empty_answer_returns_none(self):
        mock_openai = mock.MagicMock()
        mock_choice = mock.MagicMock()
        mock_choice.message.content = ""
        mock_resp = mock.MagicMock()
        mock_resp.choices = [mock_choice]
        mock_resp.usage = None
        mock_openai.OpenAI.return_value.chat.completions.create.return_value = mock_resp
        with mock.patch.dict(sys.modules, {"openai": mock_openai}):
            answer, usage = _call_openai_api("key", "model", {"system": "s", "user": "u"})
        assert answer is None


class TestCallGeminiApi:
    def test_returns_answer_and_empty_usage(self):
        import app as app_mod
        with mock.patch.object(app_mod, "ask_gemini", return_value="Gemini says hi"):
            answer, usage = _call_gemini_api("key", "model", {"system": "s", "user": "u"})
        assert answer == "Gemini says hi"
        assert usage == {}

    def test_empty_returns_none(self):
        import app as app_mod
        with mock.patch.object(app_mod, "ask_gemini", return_value=""):
            answer, usage = _call_gemini_api("key", "model", {"system": "s", "user": "u"})
        assert answer is None


# ── _collect_audit_sources ─────────────────────────────────────────────

class TestCollectAuditSources:
    def test_returns_string(self):
        result = _collect_audit_sources()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_includes_main_files(self):
        result = _collect_audit_sources()
        assert "wslog.py" in result
        assert "app.py" in result

    def test_compact_mode_shorter(self):
        full = _collect_audit_sources(compact=False)
        compact = _collect_audit_sources(compact=True)
        assert len(compact) <= len(full)

    def test_includes_skill_content(self):
        result = _collect_audit_sources()
        # Should include skill directory content
        assert "skills" in result.lower() or "skill" in result.lower()


# ── _PROVIDER_HISTORY_FILES ───────────────────────────────────────────

class TestProviderHistoryFiles:
    def test_all_providers_have_files(self):
        for provider in ("claude", "gemini", "openai"):
            assert provider in _PROVIDER_HISTORY_FILES

    def test_files_are_paths(self):
        for path in _PROVIDER_HISTORY_FILES.values():
            assert hasattr(path, "suffix")  # Path-like object


# ── Rate limiting ─────────────────────────────────────────────────────

class TestRateLimit:
    def test_rate_limit_constant_exists(self):
        assert _AI_RATE_LIMIT_SECONDS > 0
        assert _AI_RATE_LIMIT_SECONDS <= 10  # Sanity check
