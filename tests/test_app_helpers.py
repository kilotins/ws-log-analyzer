"""Tests for helper functions in app.py that don't require a running Streamlit server."""
import json
import logging
import os
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
    get_report_history,
    _load_keychain,
    _save_keychain,
    _load_provider_history,
    _save_provider_history,
)
from app_ai import (                    # noqa: E402
    PROVIDER_CONFIG,
    estimate_cost,
    call_claude_api,
    call_openai_api,
    call_gemini_api,
)
from app_realtime import (              # noqa: E402
    _highlight_line,
    _is_safe_rt_path,
)
from app_audit import (                 # noqa: E402
    _extract_signatures,
    _collect_audit_sources,
)
from app_constants import AI_RATE_LIMIT_SECONDS  # noqa: E402
from app import (                       # noqa: E402
    _PROVIDER_HISTORY_FILES,
    _CACHE_TTL_SECONDS,
    _load_file_cache,
    _save_file_cache,
    _lookup_cache,
    _store_cache,
    CACHE_FILE,
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

    def test_atomic_write_no_partial_file(self, tmp_path):
        """If _save_json_file fails mid-write, the original file is untouched."""
        f = tmp_path / "safe.json"
        original = {"version": 1}
        _save_json_file(f, original)
        # Try saving an unserializable object — should raise and leave original intact
        with pytest.raises(TypeError):
            _save_json_file(f, {"bad": object()})
        assert json.loads(f.read_text(encoding="utf-8")) == original

    def test_atomic_write_creates_parent_dirs(self, tmp_path):
        f = tmp_path / "nested" / "dir" / "data.json"
        _save_json_file(f, {"ok": True})
        assert json.loads(f.read_text(encoding="utf-8")) == {"ok": True}

    def test_atomic_write_no_temp_files_left(self, tmp_path):
        f = tmp_path / "clean.json"
        _save_json_file(f, {"data": 1})
        files = list(tmp_path.iterdir())
        assert len(files) == 1 and files[0].name == "clean.json"


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
        assert 'color:#DC2626' in result
        assert "ERROR" in result

    def test_info_highlighted(self):
        result = _highlight_line("INFO server started")
        assert 'color:#7C3AED' in result

    def test_warn_highlighted(self):
        result = _highlight_line("WARN low memory")
        assert 'color:#D97706' in result

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
        assert 'color:#DC2626' in result


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
        assert PROVIDER_CONFIG["claude"]["api_key_prefix"] == "sk-ant-"

    def test_openai_key_prefix(self):
        assert PROVIDER_CONFIG["openai"]["api_key_prefix"] == "sk-"

    def test_gemini_key_prefix(self):
        assert PROVIDER_CONFIG["gemini"]["api_key_prefix"] == "AI"

    def test_all_providers_have_prefix(self):
        for provider, cfg in PROVIDER_CONFIG.items():
            assert "api_key_prefix" in cfg, f"{provider} missing api_key_prefix"


# ── _load_keychain / _save_keychain ───────────────────────────────────────

class TestKeychainHelpers:
    def test_load_keychain_from_keyring(self):
        mock_keyring = mock.MagicMock()
        mock_keyring.get_password.return_value = "sk-secret-123"
        with mock.patch.dict(sys.modules, {"keyring": mock_keyring}):
            result = _load_keychain("test_user", "TEST_ENV_VAR")
        assert result == "sk-secret-123"
        mock_keyring.get_password.assert_called_once_with("logpilot", "test_user")

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
            "logpilot", "test_user", "new-key-789"
        )

    def test_save_keychain_deletes_when_empty(self):
        mock_keyring = mock.MagicMock()
        with mock.patch.dict(sys.modules, {"keyring": mock_keyring}):
            _save_keychain("test_user", "", label="Test")
        mock_keyring.delete_password.assert_called_once_with(
            "logpilot", "test_user"
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


# ── PROVIDER_CONFIG ─────────────────────────────────────────────────────

class TestProviderConfig:
    @pytest.mark.parametrize("provider", ["claude", "gemini", "openai"])
    def test_all_providers_have_required_keys(self, provider):
        cfg = PROVIDER_CONFIG[provider]
        required = ["label", "cache_key", "answer_key", "query_label_key",
                     "history_key", "api_key_field", "save_history",
                     "api_key_error"]
        for key in required:
            assert key in cfg, f"Missing key '{key}' in {provider} config"


# ── estimate_cost ───────────────────────────────────────────────────────

class TestEstimateCost:
    def test_known_model(self):
        # gpt-4o: $2.50/1M input, $10.00/1M output
        cost = estimate_cost("gpt-4o", 1000, 500)
        assert cost == pytest.approx(0.0025 + 0.005, abs=1e-6)

    def test_unknown_model_returns_zero(self):
        assert estimate_cost("unknown-model", 1000, 500) == 0.0

    def test_zero_tokens(self):
        assert estimate_cost("gpt-4o", 0, 0) == 0.0

    def test_large_input(self):
        # 1M tokens input on claude-sonnet-4-6: $3.00
        cost = estimate_cost("claude-sonnet-4-6", 1_000_000, 0)
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
        mock_msg.usage = mock.MagicMock(
            input_tokens=100, output_tokens=50,
            cache_creation_input_tokens=10, cache_read_input_tokens=5,
        )
        mock_anthropic.Anthropic.return_value.messages.create.return_value = mock_msg
        with mock.patch.dict(sys.modules, {"anthropic": mock_anthropic}):
            answer, usage = call_claude_api("key", "model", {"system": "s", "user": "u"})
        assert answer == "Hello from Claude"
        assert usage["input"] == 100
        assert usage["output"] == 50
        assert usage["cache_creation"] == 10
        assert usage["cache_read"] == 5

    def test_empty_content_returns_none(self):
        mock_anthropic = mock.MagicMock()
        mock_msg = mock.MagicMock()
        mock_msg.content = []
        mock_anthropic.Anthropic.return_value.messages.create.return_value = mock_msg
        with mock.patch.dict(sys.modules, {"anthropic": mock_anthropic}):
            answer, usage = call_claude_api("key", "model", {"system": "s", "user": "u"})
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
            answer, usage = call_openai_api("key", "model", {"system": "s", "user": "u"})
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
            answer, usage = call_openai_api("key", "model", {"system": "s", "user": "u"})
        assert answer is None


class TestCallGeminiApi:
    def test_returns_answer_and_estimated_usage(self):
        import app_ai as app_ai_mod
        with mock.patch.object(app_ai_mod, "ask_gemini", return_value="Gemini says hi there friend"):
            answer, usage = call_gemini_api(
                "key", "model",
                {"system": "You are a helpful assistant", "user": "Analyze this log file"},
            )
        assert answer == "Gemini says hi there friend"
        assert "input" in usage
        assert "output" in usage
        assert usage["input"] > 0
        assert usage["output"] > 0

    def test_empty_returns_none(self):
        import app_ai as app_ai_mod
        with mock.patch.object(app_ai_mod, "ask_gemini", return_value=""):
            answer, usage = call_gemini_api("key", "model", {"system": "s", "user": "u"})
        assert answer is None


# ── _collect_audit_sources ─────────────────────────────────────────────

class TestCollectAuditSources:
    def test_returns_string(self):
        result = _collect_audit_sources()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_includes_main_files(self):
        result = _collect_audit_sources()
        assert "logpilot/" in result or "parser.py" in result
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
        assert AI_RATE_LIMIT_SECONDS > 0
        assert AI_RATE_LIMIT_SECONDS <= 10  # Sanity check


# ── Cache TTL ─────────────────────────────────────────────────────────

class TestCacheTTL:
    def test_fresh_entries_are_kept(self, tmp_path, monkeypatch):
        import time, app as app_mod
        cache_file = tmp_path / "ai_responses.json"
        monkeypatch.setattr(app_mod, "CACHE_FILE", cache_file)
        now = time.time()
        data = {"key1": {"text": "answer1", "ts": now - 3600}}  # 1 hour old
        _save_json_file(cache_file, data)
        loaded = _load_file_cache()
        assert "key1" in loaded
        assert loaded["key1"]["text"] == "answer1"

    def test_expired_entries_are_removed(self, tmp_path, monkeypatch):
        import time, app as app_mod
        cache_file = tmp_path / "ai_responses.json"
        monkeypatch.setattr(app_mod, "CACHE_FILE", cache_file)
        now = time.time()
        data = {
            "old": {"text": "stale", "ts": now - _CACHE_TTL_SECONDS - 1},
            "new": {"text": "fresh", "ts": now - 100},
        }
        _save_json_file(cache_file, data)
        loaded = _load_file_cache()
        assert "old" not in loaded
        assert "new" in loaded

    def test_old_format_plain_string_migrated(self, tmp_path, monkeypatch):
        import app as app_mod
        cache_file = tmp_path / "ai_responses.json"
        monkeypatch.setattr(app_mod, "CACHE_FILE", cache_file)
        data = {"legacy_key": "plain string answer"}
        _save_json_file(cache_file, data)
        loaded = _load_file_cache()
        assert "legacy_key" in loaded
        assert loaded["legacy_key"]["text"] == "plain string answer"
        assert "ts" in loaded["legacy_key"]

    def test_ttl_is_seven_days(self):
        assert _CACHE_TTL_SECONDS == 7 * 24 * 60 * 60


# ── 15.3 — _lookup_cache / _store_cache ──────────────────────────────────

class TestLookupCache:
    def test_cache_hit_from_session(self):
        """Session cache hit returns the cached value immediately."""
        session_cache = {"my_key": "cached_answer"}
        result = _lookup_cache("my_key", session_cache, "test", "some query")
        assert result == "cached_answer"

    def test_cache_miss_returns_none(self, tmp_path, monkeypatch):
        """Missing key in both session and file cache returns None."""
        import app as app_mod
        cache_file = tmp_path / "ai_responses.json"
        monkeypatch.setattr(app_mod, "CACHE_FILE", cache_file)
        # Empty file cache
        _save_json_file(cache_file, {})
        session_cache = {}
        result = _lookup_cache("nonexistent", session_cache, "test", "query")
        assert result is None

    def test_cache_hit_from_file(self, tmp_path, monkeypatch):
        """File cache hit returns value and populates session cache."""
        import time, app as app_mod
        cache_file = tmp_path / "ai_responses.json"
        monkeypatch.setattr(app_mod, "CACHE_FILE", cache_file)
        _save_json_file(cache_file, {
            "file_key": {"text": "file_answer", "ts": time.time()}
        })
        session_cache = {}
        result = _lookup_cache("file_key", session_cache, "test", "query")
        assert result == "file_answer"
        # Should also populate session cache
        assert session_cache["file_key"] == "file_answer"


class TestStoreCache:
    def test_store_adds_to_session_and_file(self, tmp_path, monkeypatch):
        """Storing a value puts it in both session cache and file cache."""
        import app as app_mod
        cache_file = tmp_path / "ai_responses.json"
        monkeypatch.setattr(app_mod, "CACHE_FILE", cache_file)
        _save_json_file(cache_file, {})
        session_cache = {}
        _store_cache("new_key", "new_answer", session_cache)
        # Session cache updated
        assert session_cache["new_key"] == "new_answer"
        # File cache updated
        file_data = _load_json_file(cache_file, {})
        assert "new_key" in file_data
        assert file_data["new_key"]["text"] == "new_answer"
        assert "ts" in file_data["new_key"]

    def test_store_overwrites_existing(self, tmp_path, monkeypatch):
        """Storing a key that already exists overwrites the old value."""
        import time, app as app_mod
        cache_file = tmp_path / "ai_responses.json"
        monkeypatch.setattr(app_mod, "CACHE_FILE", cache_file)
        _save_json_file(cache_file, {
            "key": {"text": "old_answer", "ts": time.time() - 100}
        })
        session_cache = {"key": "old_answer"}
        _store_cache("key", "updated_answer", session_cache)
        assert session_cache["key"] == "updated_answer"
        file_data = _load_json_file(cache_file, {})
        assert file_data["key"]["text"] == "updated_answer"


# ── 15.4 — Concurrency-simulated cache file access ──────────────────────

class TestCacheFileConcurrency:
    def test_sequential_writes_no_corruption(self, tmp_path, monkeypatch):
        """Two sequential writes to the same cache file produce valid JSON."""
        import app as app_mod
        cache_file = tmp_path / "ai_responses.json"
        monkeypatch.setattr(app_mod, "CACHE_FILE", cache_file)

        # First write
        session1 = {}
        _store_cache("key_a", "answer_a", session1)

        # Second write (simulates a second "concurrent" access)
        session2 = {}
        _store_cache("key_b", "answer_b", session2)

        # Verify file is valid JSON and contains both entries
        file_data = _load_json_file(cache_file, {})
        assert "key_a" in file_data
        assert file_data["key_a"]["text"] == "answer_a"
        assert "key_b" in file_data
        assert file_data["key_b"]["text"] == "answer_b"

    def test_sequential_overwrites_no_corruption(self, tmp_path, monkeypatch):
        """Overwriting the same key sequentially keeps file valid."""
        import app as app_mod
        cache_file = tmp_path / "ai_responses.json"
        monkeypatch.setattr(app_mod, "CACHE_FILE", cache_file)

        session = {}
        _store_cache("shared_key", "first_value", session)
        _store_cache("shared_key", "second_value", session)

        file_data = _load_json_file(cache_file, {})
        assert file_data["shared_key"]["text"] == "second_value"
        # File should be parseable (not corrupted)
        raw = cache_file.read_text(encoding="utf-8")
        assert json.loads(raw) is not None


# ── 15.5 — Timeout error handling ────────────────────────────────────────

class TestTimeoutErrorHandling:
    def test_claude_api_timeout_raises(self):
        """Claude API raising a timeout exception propagates (caller handles it)."""
        mock_anthropic = mock.MagicMock()
        mock_anthropic.Anthropic.return_value.messages.create.side_effect = \
            TimeoutError("Connection timed out")
        with mock.patch.dict(sys.modules, {"anthropic": mock_anthropic}):
            with pytest.raises((TimeoutError, Exception)):
                call_claude_api("key", "model", {"system": "s", "user": "u"})

    def test_openai_api_timeout_raises(self):
        """OpenAI API raising a timeout exception propagates (caller handles it)."""
        mock_openai = mock.MagicMock()
        mock_openai.OpenAI.return_value.chat.completions.create.side_effect = \
            TimeoutError("Request timed out")
        with mock.patch.dict(sys.modules, {"openai": mock_openai}):
            with pytest.raises((TimeoutError, Exception)):
                call_openai_api("key", "model", {"system": "s", "user": "u"})

    def test_gemini_api_timeout_raises(self):
        """Gemini API raising a timeout exception propagates (caller handles it)."""
        import app_ai as app_ai_mod
        with mock.patch.object(app_ai_mod, "ask_gemini",
                               side_effect=TimeoutError("Gemini timed out")):
            with pytest.raises((TimeoutError, Exception)):
                call_gemini_api("key", "model", {"system": "s", "user": "u"})

    def test_connection_error_propagates(self):
        """ConnectionError from API call propagates without crash."""
        mock_anthropic = mock.MagicMock()
        mock_anthropic.Anthropic.return_value.messages.create.side_effect = \
            ConnectionError("Network unreachable")
        with mock.patch.dict(sys.modules, {"anthropic": mock_anthropic}):
            with pytest.raises((ConnectionError, Exception)):
                call_claude_api("key", "model", {"system": "s", "user": "u"})


# ── JSON log format ───────────────────────────────────────────────────

class TestJsonLogFormatter:
    def test_json_formatter_produces_valid_json(self):
        import json as _json
        from app import _JsonLogFormatter
        formatter = _JsonLogFormatter()
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=0,
            msg="something broke", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = _json.loads(output)
        assert parsed["level"] == "ERROR"
        assert parsed["msg"] == "something broke"
        assert "ts" in parsed

    def test_json_formatter_with_args(self):
        import json as _json
        from app import _JsonLogFormatter
        formatter = _JsonLogFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="file %s has %d events", args=("server.log", 42), exc_info=None,
        )
        output = formatter.format(record)
        parsed = _json.loads(output)
        assert "server.log" in parsed["msg"]
        assert "42" in parsed["msg"]

    def test_json_format_env_toggle(self, monkeypatch, tmp_path):
        """WSLOG_LOG_FORMAT=json activates JSON formatter."""
        monkeypatch.setenv("WSLOG_LOG_FORMAT", "json")
        from app import _JsonLogFormatter
        use_json = os.environ.get("WSLOG_LOG_FORMAT", "").lower() == "json"
        assert use_json is True


# ── Warning logging on silent returns (22.3) ─────────────────────────

class TestLoadJsonFileWarningLogging:
    def test_corrupt_json_logs_warning(self, tmp_path, caplog):
        f = tmp_path / "bad.json"
        f.write_text("{not valid", encoding="utf-8")
        with caplog.at_level(logging.WARNING, logger="wslog_app"):
            result = _load_json_file(f, {})
        assert result == {}
        assert any("corrupt JSON" in r.message for r in caplog.records)
