"""Unit tests for pure helper functions in app_incident.py.

Streamlit is stubbed before importing so no server is needed.
"""
from __future__ import annotations

import base64
import json
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Stub Streamlit before importing app_incident (module-level st.* calls).
# ---------------------------------------------------------------------------
class _AttrDict(dict):
    """Dict that supports attribute access — mirrors Streamlit session_state."""
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

_st_mock = mock.MagicMock()
_st_mock.session_state = _session_state
_st_mock.fragment = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_st_mock.cache_data = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_st_mock.cache_resource = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_st_mock.columns = lambda n=1, **kw: (
    [mock.MagicMock() for _ in range(n)]
    if isinstance(n, int)
    else [mock.MagicMock() for _ in n]
)
_st_mock.tabs = lambda names: [mock.MagicMock() for _ in names]
_st_mock.selectbox = lambda label, options, **kw: (list(options)[0] if options else "")
_st_mock.button = lambda *a, **kw: False
_st_mock.slider = lambda *a, **kw: 0.5
_st_mock.text_area = lambda *a, **kw: ""
_st_mock.file_uploader = lambda *a, **kw: None
_st_mock.checkbox = lambda *a, **kw: False

sys.modules["streamlit"] = _st_mock
sys.modules["streamlit.components"] = mock.MagicMock()
sys.modules["streamlit.components.v1"] = mock.MagicMock()


@pytest.fixture(autouse=True)
def _clear_session_state():
    """Wipe shared session state before and after every test to prevent pollution."""
    _session_state.clear()
    yield
    _session_state.clear()


# Now import the functions under test
from app_incident import (  # noqa: E402
    _build_multimodal_messages,
    _delete_history_entry,
    _extract_missing_logs,
    _extract_usage,
    _save_to_history,
    _HIST_DISK_FILES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_image_bytes() -> bytes:
    """Return a small valid PNG-like bytes payload."""
    return b"\x89PNG fake image data for tests"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


# ---------------------------------------------------------------------------
# _build_multimodal_messages
# ---------------------------------------------------------------------------

class TestBuildMultimodalMessages:
    """Tests for _build_multimodal_messages across all providers."""

    # ── text-only (no image) ────────────────────────────────────────────

    def test_text_only_returns_simple_dict(self):
        result = _build_multimodal_messages("sys", "user text", None, None, "claude")
        assert result == {"system": "sys", "user": "user text"}

    def test_text_only_all_providers_same_shape(self):
        for provider in ("claude", "gemini", "openai", "local", "unknown"):
            result = _build_multimodal_messages("sys", "hello", None, None, provider)
            assert "system" in result
            assert result["user"] == "hello"
            assert "messages" not in result

    # ── Claude with image ───────────────────────────────────────────────

    def test_claude_with_image_has_messages_key(self):
        img = _make_image_bytes()
        result = _build_multimodal_messages("sys", "describe this", img, "image/png", "claude")
        assert "messages" in result
        assert "system" in result

    def test_claude_image_content_blocks(self):
        img = _make_image_bytes()
        result = _build_multimodal_messages("sys", "describe", img, "image/png", "claude")
        msg = result["messages"][0]
        assert msg["role"] == "user"
        content = msg["content"]
        types_ = [c["type"] for c in content]
        assert "image" in types_
        assert "text" in types_

    def test_claude_image_block_correct_fields(self):
        img = _make_image_bytes()
        result = _build_multimodal_messages("sys", "q", img, "image/jpeg", "claude")
        image_block = next(c for c in result["messages"][0]["content"] if c["type"] == "image")
        assert image_block["source"]["type"] == "base64"
        assert image_block["source"]["media_type"] == "image/jpeg"
        assert image_block["source"]["data"] == _b64(img)

    def test_claude_text_block_correct(self):
        img = _make_image_bytes()
        result = _build_multimodal_messages("sys", "my question", img, "image/png", "claude")
        text_block = next(c for c in result["messages"][0]["content"] if c["type"] == "text")
        assert text_block["text"] == "my question"

    # ── OpenAI with image ───────────────────────────────────────────────

    def test_openai_with_image_has_messages_key(self):
        img = _make_image_bytes()
        result = _build_multimodal_messages("sys", "analyze", img, "image/png", "openai")
        assert "messages" in result

    def test_openai_image_url_format(self):
        img = _make_image_bytes()
        mime = "image/png"
        result = _build_multimodal_messages("sys", "q", img, mime, "openai")
        content = result["messages"][0]["content"]
        img_block = next(c for c in content if c["type"] == "image_url")
        expected_url = f"data:{mime};base64,{_b64(img)}"
        assert img_block["image_url"]["url"] == expected_url

    def test_local_provider_uses_openai_format(self):
        """'local' provider should produce the same format as 'openai'."""
        img = _make_image_bytes()
        openai_result = _build_multimodal_messages("sys", "q", img, "image/png", "openai")
        local_result = _build_multimodal_messages("sys", "q", img, "image/png", "local")
        assert openai_result["messages"][0]["content"] == local_result["messages"][0]["content"]

    # ── Gemini with image ───────────────────────────────────────────────

    def test_gemini_with_image_has_messages_key(self):
        img = _make_image_bytes()
        result = _build_multimodal_messages("sys", "q", img, "image/png", "gemini")
        assert "messages" in result

    def test_gemini_uses_parts_format(self):
        img = _make_image_bytes()
        mime = "image/webp"
        result = _build_multimodal_messages("sys", "q", img, mime, "gemini")
        msg = result["messages"][0]
        assert "parts" in msg
        parts = msg["parts"]
        inline = next((p for p in parts if "inline_data" in p), None)
        assert inline is not None
        assert inline["inline_data"]["mime_type"] == mime
        assert inline["inline_data"]["data"] == _b64(img)

    def test_gemini_parts_include_text(self):
        img = _make_image_bytes()
        result = _build_multimodal_messages("sys", "gemini question", img, "image/png", "gemini")
        parts = result["messages"][0]["parts"]
        text_part = next((p for p in parts if "text" in p), None)
        assert text_part is not None
        assert text_part["text"] == "gemini question"

    # ── Unknown provider fallback ────────────────────────────────────────

    def test_unknown_provider_with_image_falls_back_to_text_only(self):
        img = _make_image_bytes()
        result = _build_multimodal_messages("sys", "q", img, "image/png", "unknown_provider")
        # Should fall back to text-only dict
        assert "user" in result
        assert "messages" not in result

    # ── System prompt preserved ──────────────────────────────────────────

    def test_system_prompt_preserved_in_all_providers(self):
        img = _make_image_bytes()
        sys_prompt = "You are a log analysis expert."
        for provider in ("claude", "openai", "gemini", "local"):
            result = _build_multimodal_messages(sys_prompt, "q", img, "image/png", provider)
            assert result["system"] == sys_prompt, f"system prompt lost for {provider}"


# ---------------------------------------------------------------------------
# _extract_missing_logs
# ---------------------------------------------------------------------------

class TestExtractMissingLogs:
    def test_no_missing_logs_section(self):
        answer = "This is the main analysis.\n\nSome details here."
        main, missing = _extract_missing_logs(answer)
        assert main == answer
        assert missing == ""

    def test_h2_missing_logs_extracted(self):
        answer = "Main analysis text.\n\n## Missing Logs\nYou need access.log and error.log."
        main, missing = _extract_missing_logs(answer)
        assert "Main analysis text" in main
        assert "access.log" in missing
        assert "## Missing Logs" not in main

    def test_h3_missing_logs_extracted(self):
        answer = "Analysis.\n\n### Missing Logs\nNeed GC logs."
        main, missing = _extract_missing_logs(answer)
        assert "Need GC logs" in missing

    def test_bold_missing_logs_extracted(self):
        answer = "Analysis result.\n\n**Missing Logs**: thread dumps, heap dumps."
        main, missing = _extract_missing_logs(answer)
        assert "thread dumps" in missing
        assert "Analysis result" in main

    def test_numbered_heading_extracted(self):
        answer = "Summary.\n\n## 9. **Missing Logs**\nNeed application logs."
        main, missing = _extract_missing_logs(answer)
        assert "Need application logs" in missing

    def test_case_insensitive(self):
        answer = "Main.\n\n## MISSING LOGS\nSome logs."
        main, missing = _extract_missing_logs(answer)
        assert "Some logs" in missing

    def test_empty_input(self):
        main, missing = _extract_missing_logs("")
        assert main == ""
        assert missing == ""

    def test_main_part_does_not_include_section_header(self):
        answer = "Intro.\n\n## Missing Logs\nDetails."
        main, missing = _extract_missing_logs(answer)
        assert "Missing Logs" not in main


# ---------------------------------------------------------------------------
# _extract_usage
# ---------------------------------------------------------------------------

class TestExtractUsage:
    def test_none_returns_empty(self):
        assert _extract_usage(None, "claude") == {}

    def test_claude_usage_obj(self):
        usage_obj = mock.MagicMock()
        usage_obj.input_tokens = 100
        usage_obj.output_tokens = 50
        usage_obj.cache_creation_input_tokens = 10
        usage_obj.cache_read_input_tokens = 5
        result = _extract_usage(usage_obj, "claude")
        assert result["input"] == 100
        assert result["output"] == 50
        assert result["cache_creation"] == 10
        assert result["cache_read"] == 5

    def test_claude_usage_missing_attr_defaults_to_zero(self):
        usage_obj = mock.MagicMock(spec=[])  # No attributes
        result = _extract_usage(usage_obj, "claude")
        assert result["input"] == 0
        assert result["output"] == 0

    def test_non_claude_dict_returned_as_is(self):
        usage_dict = {"input": 200, "output": 80}
        result = _extract_usage(usage_dict, "openai")
        assert result == usage_dict

    def test_non_claude_non_dict_returns_empty(self):
        result = _extract_usage("some string", "gemini")
        assert result == {}


# ---------------------------------------------------------------------------
# _HIST_DISK_FILES
# ---------------------------------------------------------------------------

class TestHistDiskFiles:
    def test_all_four_providers_present(self):
        for provider in ("claude", "gemini", "openai", "local"):
            assert provider in _HIST_DISK_FILES, f"Missing provider: {provider}"

    def test_values_are_json_filenames(self):
        for provider, filename in _HIST_DISK_FILES.items():
            assert filename.endswith(".json"), f"{provider} → {filename!r} not .json"

    def test_filenames_are_strings(self):
        for provider, filename in _HIST_DISK_FILES.items():
            assert isinstance(filename, str), f"{provider} filename is not a str"

    def test_filenames_are_unique(self):
        filenames = list(_HIST_DISK_FILES.values())
        assert len(filenames) == len(set(filenames)), "Duplicate filenames in _HIST_DISK_FILES"

    def test_expected_filenames(self):
        assert _HIST_DISK_FILES["claude"] == "claude_history.json"
        assert _HIST_DISK_FILES["gemini"] == "gemini_history.json"
        assert _HIST_DISK_FILES["openai"] == "openai_history.json"
        assert _HIST_DISK_FILES["local"] == "local_history.json"


# ---------------------------------------------------------------------------
# _delete_history_entry
# ---------------------------------------------------------------------------

class TestDeleteHistoryEntry:
    def setup_method(self):
        """Reset session state before each test."""
        _session_state.clear()

    def test_removes_entry_at_index(self):
        history = [
            {"query": "q1", "answer": "a1"},
            {"query": "q2", "answer": "a2"},
            {"query": "q3", "answer": "a3"},
        ]
        _session_state["test_hist"] = history.copy()
        _delete_history_entry("test_hist", "claude", 1)
        remaining = _session_state["test_hist"]
        assert len(remaining) == 2
        assert remaining[0]["query"] == "q1"
        assert remaining[1]["query"] == "q3"

    def test_removes_first_entry(self):
        _session_state["test_hist"] = [{"q": "a"}, {"q": "b"}]
        _delete_history_entry("test_hist", "claude", 0)
        assert len(_session_state["test_hist"]) == 1
        assert _session_state["test_hist"][0]["q"] == "b"

    def test_removes_last_entry(self):
        _session_state["test_hist"] = [{"q": "a"}, {"q": "b"}]
        _delete_history_entry("test_hist", "claude", 1)
        assert len(_session_state["test_hist"]) == 1
        assert _session_state["test_hist"][0]["q"] == "a"

    def test_out_of_range_index_does_nothing(self):
        _session_state["test_hist"] = [{"q": "a"}]
        _delete_history_entry("test_hist", "claude", 99)
        assert len(_session_state["test_hist"]) == 1

    def test_negative_index_does_nothing(self):
        _session_state["test_hist"] = [{"q": "a"}]
        _delete_history_entry("test_hist", "claude", -1)
        # -1 < 0 → guarded by `0 <= idx < len(history)`
        assert len(_session_state["test_hist"]) == 1

    def test_empty_history_does_not_raise(self):
        _session_state["test_hist"] = []
        _delete_history_entry("test_hist", "claude", 0)
        assert _session_state["test_hist"] == []

    def test_missing_hist_key_does_not_raise(self):
        # Key not in session_state — defaults to []
        _delete_history_entry("nonexistent_hist", "claude", 0)

    def test_writes_to_disk_when_cache_dir_exists(self):
        """When the cache dir exists the updated history is written to disk.

        Code path in _delete_history_entry:
            _cache_dir = Path(__file__).parent / "cache"   # parent / "cache" = mock_cache_dir
            _hf = _cache_dir / filename                    # mock_cache_dir / filename = mock_hf
        """
        with mock.patch("app_incident.Path") as MockPath:
            mock_hf = mock.MagicMock()
            mock_hf.name = "claude_history.json"
            mock_hf.parent.exists.return_value = True

            # _cache_dir = Path(__file__).parent / "cache"
            # MockPath(__file__).parent = mock_module_parent
            # mock_module_parent / "cache" = mock_cache_dir
            # mock_cache_dir / "claude_history.json" = mock_hf
            mock_cache_dir = mock.MagicMock()
            mock_cache_dir.__truediv__ = mock.MagicMock(return_value=mock_hf)

            mock_module_parent = mock.MagicMock()
            mock_module_parent.__truediv__ = mock.MagicMock(return_value=mock_cache_dir)

            mock_pi = mock.MagicMock()
            mock_pi.parent = mock_module_parent
            MockPath.return_value = mock_pi

            _session_state["claude_history"] = [
                {"query": "q1", "answer": "a1"}, {"query": "q2", "answer": "a2"}
            ]
            _delete_history_entry("claude_history", "claude", 0)

            mock_hf.write_text.assert_called_once()
            written_arg = mock_hf.write_text.call_args[0][0]
            written = json.loads(written_arg)
            assert len(written) == 1
            assert written[0]["query"] == "q2"

    def _make_path_mock(self, mock_hf):
        """Build the two-level truediv chain that _delete_history_entry traverses.

        Code path:
            _cache_dir = Path(__file__).parent / "cache"   # parent / "cache" = mock_cache_dir
            _hf        = _cache_dir / filename             # mock_cache_dir / filename = mock_hf
        """
        mock_cache_dir = mock.MagicMock()
        mock_cache_dir.__truediv__ = mock.MagicMock(return_value=mock_hf)
        mock_module_parent = mock.MagicMock()
        mock_module_parent.__truediv__ = mock.MagicMock(return_value=mock_cache_dir)
        mock_pi = mock.MagicMock()
        mock_pi.parent = mock_module_parent
        return mock_pi

    def test_no_disk_write_when_cache_dir_missing(self):
        """When the cache dir does not exist, no write is attempted."""
        with mock.patch("app_incident.Path") as MockPath:
            mock_hf = mock.MagicMock()
            mock_hf.name = "claude_history.json"
            mock_hf.parent.exists.return_value = False
            MockPath.return_value = self._make_path_mock(mock_hf)

            _session_state["claude_history"] = [{"query": "q", "answer": "a"}]
            _delete_history_entry("claude_history", "claude", 0)

            mock_hf.write_text.assert_not_called()

    def test_unknown_provider_uses_empty_filename_no_write(self):
        """Unknown provider → _HIST_DISK_FILES.get() returns '' → no write."""
        with mock.patch("app_incident.Path") as MockPath:
            mock_hf = mock.MagicMock()
            mock_hf.name = ""  # empty string — guarded by `if _hf.name`
            MockPath.return_value = self._make_path_mock(mock_hf)

            _session_state["test_hist"] = [{"query": "q", "answer": "a"}]
            _delete_history_entry("test_hist", "unknown_provider", 0)

            mock_hf.write_text.assert_not_called()

    def test_oserror_on_disk_write_does_not_raise(self):
        """OSError during write is swallowed — the in-memory state is still updated."""
        with mock.patch("app_incident.Path") as MockPath:
            mock_hf = mock.MagicMock()
            mock_hf.name = "claude_history.json"
            mock_hf.parent.exists.return_value = True
            mock_hf.write_text.side_effect = OSError("disk full")
            MockPath.return_value = self._make_path_mock(mock_hf)

            _session_state["claude_history"] = [{"query": "q", "answer": "a"}]
            # Must not raise
            _delete_history_entry("claude_history", "claude", 0)
            assert _session_state["claude_history"] == []


# ---------------------------------------------------------------------------
# _save_to_history
# ---------------------------------------------------------------------------

class TestSaveToHistory:
    def setup_method(self):
        _session_state.clear()

    def _make_provider_config(self, history_key: str, save_fn=None) -> dict:
        return {
            "history_key": history_key,
            "save_history": save_fn,
        }

    def test_appends_entry_to_empty_history(self):
        from app_ai import PROVIDER_CONFIG
        hist_key = PROVIDER_CONFIG["claude"]["history_key"]
        _session_state[hist_key] = []
        _save_to_history("What is OOM?", "OOM = Out of Memory", "claude", "Claude Sonnet")
        history = _session_state[hist_key]
        assert len(history) == 1
        entry = history[0]
        assert entry["query"] == "What is OOM?"
        assert entry["answer"] == "OOM = Out of Memory"
        assert entry["provider"] == "Claude Sonnet"
        assert "timestamp" in entry

    def test_timestamp_format_is_hhmmss(self):
        from app_ai import PROVIDER_CONFIG
        hist_key = PROVIDER_CONFIG["claude"]["history_key"]
        _session_state[hist_key] = []
        _save_to_history("q", "a", "claude", "Claude")
        ts = _session_state[hist_key][0]["timestamp"]
        # Should be HH:MM:SS
        parts = ts.split(":")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_duplicate_query_answer_not_added_twice(self):
        from app_ai import PROVIDER_CONFIG
        hist_key = PROVIDER_CONFIG["claude"]["history_key"]
        existing = [{"query": "q", "answer": "a", "provider": "Claude", "timestamp": "10:00:00"}]
        _session_state[hist_key] = existing.copy()
        _save_to_history("q", "a", "claude", "Claude")
        assert len(_session_state[hist_key]) == 1

    def test_different_answer_is_added(self):
        from app_ai import PROVIDER_CONFIG
        hist_key = PROVIDER_CONFIG["claude"]["history_key"]
        _session_state[hist_key] = [
            {"query": "q", "answer": "a1", "provider": "Claude", "timestamp": "10:00:00"}
        ]
        _save_to_history("q", "a2", "claude", "Claude")
        assert len(_session_state[hist_key]) == 2

    def test_save_history_callback_called(self):
        """If PROVIDER_CONFIG has a save_history fn, it should be called."""
        from app_ai import PROVIDER_CONFIG
        import app_ai as app_ai_mod
        save_fn = mock.MagicMock()
        original_save = PROVIDER_CONFIG["claude"]["save_history"]
        try:
            PROVIDER_CONFIG["claude"]["save_history"] = save_fn
            hist_key = PROVIDER_CONFIG["claude"]["history_key"]
            _session_state[hist_key] = []
            _save_to_history("q", "a", "claude", "Claude")
            save_fn.assert_called_once()
        finally:
            PROVIDER_CONFIG["claude"]["save_history"] = original_save

    def test_gemini_provider_uses_gemini_history_key(self):
        from app_ai import PROVIDER_CONFIG
        hist_key = PROVIDER_CONFIG["gemini"]["history_key"]
        _session_state[hist_key] = []
        _save_to_history("How does GC work?", "GC explanation", "gemini", "Gemini Pro")
        assert len(_session_state[hist_key]) == 1
        assert _session_state[hist_key][0]["query"] == "How does GC work?"

    def test_openai_provider_uses_openai_history_key(self):
        from app_ai import PROVIDER_CONFIG
        hist_key = PROVIDER_CONFIG["openai"]["history_key"]
        _session_state[hist_key] = []
        _save_to_history("Explain 502", "Bad gateway error", "openai", "GPT-4o")
        assert len(_session_state[hist_key]) == 1

    def test_unknown_provider_falls_back_to_claude_config(self):
        """Unknown provider falls back to PROVIDER_CONFIG['claude']."""
        from app_ai import PROVIDER_CONFIG
        hist_key = PROVIDER_CONFIG["claude"]["history_key"]
        _session_state[hist_key] = []
        _save_to_history("q", "a", "completely_unknown", "Some Model")
        # Should not raise and should write to the claude fallback key
        assert len(_session_state[hist_key]) == 1
