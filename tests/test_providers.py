"""Tests for logpilot/providers.py — pure provider functions, no Streamlit needed."""
from __future__ import annotations

import sys
import importlib
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_prompt(system: str = "You are a helpful assistant.", user: str = "Hello") -> dict:
    return {"system": system, "user": user}


# ---------------------------------------------------------------------------
# ProviderResult dataclass
# ---------------------------------------------------------------------------

class TestProviderResult:
    def test_defaults(self):
        from logpilot.providers import ProviderResult
        r = ProviderResult()
        assert r.answer == ""
        assert r.input_tokens == 0
        assert r.output_tokens == 0
        assert r.error is None

    def test_from_error(self):
        from logpilot.providers import ProviderResult
        r = ProviderResult.from_error("API key invalid")
        assert r.answer == ""
        assert r.error == "API key invalid"

    def test_from_usage(self):
        from logpilot.providers import ProviderResult
        usage = {"input": 10, "output": 20, "cache_creation": 5, "cache_read": 3}
        r = ProviderResult.from_usage("Hello!", usage)
        assert r.answer == "Hello!"
        assert r.input_tokens == 10
        assert r.output_tokens == 20
        assert r.cache_creation_tokens == 5
        assert r.cache_read_tokens == 3
        assert r.error is None

    def test_from_usage_missing_keys(self):
        from logpilot.providers import ProviderResult
        r = ProviderResult.from_usage("Hi", {})
        assert r.input_tokens == 0
        assert r.output_tokens == 0


# ---------------------------------------------------------------------------
# _should_retry
# ---------------------------------------------------------------------------

class TestShouldRetry:
    def test_connection_error_retried(self):
        from logpilot.providers import _should_retry
        assert _should_retry(ConnectionError("timeout"))

    def test_timeout_error_retried(self):
        from logpilot.providers import _should_retry
        assert _should_retry(TimeoutError())

    def test_401_not_retried(self):
        from logpilot.providers import _should_retry
        exc = Exception("Unauthorized")
        exc.status_code = 401
        assert not _should_retry(exc)

    def test_403_not_retried(self):
        from logpilot.providers import _should_retry
        exc = Exception("Forbidden")
        exc.status_code = 403
        assert not _should_retry(exc)

    def test_429_retried(self):
        from logpilot.providers import _should_retry
        exc = Exception("Rate limited")
        exc.status_code = 429
        assert _should_retry(exc)

    def test_500_retried(self):
        from logpilot.providers import _should_retry
        exc = Exception("Internal Server Error")
        exc.status_code = 500
        assert _should_retry(exc)

    def test_unknown_exception_not_retried(self):
        from logpilot.providers import _should_retry
        assert not _should_retry(ValueError("some value error"))


# ---------------------------------------------------------------------------
# Dispatch — call_provider_pure
# ---------------------------------------------------------------------------

class TestCallProviderPureDispatch:
    """Verify dispatch routes correctly without hitting real APIs."""

    def test_dispatches_to_claude(self):
        from logpilot.providers import call_provider_pure
        with mock.patch("logpilot.providers.call_claude_pure") as mock_fn:
            mock_fn.return_value = mock.MagicMock(answer="ok", error=None)
            call_provider_pure("claude", "key", "claude-sonnet-4-6", _make_prompt())
            mock_fn.assert_called_once()
            args = mock_fn.call_args
            assert args[0][0] == "key"  # api_key
            assert args[0][1] == "claude-sonnet-4-6"  # model

    def test_dispatches_to_gemini(self):
        from logpilot.providers import call_provider_pure
        with mock.patch("logpilot.providers.call_gemini_pure") as mock_fn:
            mock_fn.return_value = mock.MagicMock(answer="ok", error=None)
            call_provider_pure("gemini", "key", "gemini-2.5-flash", _make_prompt())
            mock_fn.assert_called_once()

    def test_dispatches_to_openai(self):
        from logpilot.providers import call_provider_pure
        with mock.patch("logpilot.providers.call_openai_pure") as mock_fn:
            mock_fn.return_value = mock.MagicMock(answer="ok", error=None)
            call_provider_pure("openai", "key", "gpt-4o", _make_prompt())
            mock_fn.assert_called_once()

    def test_dispatches_to_local(self):
        from logpilot.providers import call_provider_pure
        with mock.patch("logpilot.providers.call_local_pure") as mock_fn:
            mock_fn.return_value = mock.MagicMock(answer="ok", error=None)
            call_provider_pure("local", "not-needed", "", _make_prompt(),
                               endpoint="http://localhost:1234/v1")
            mock_fn.assert_called_once()

    def test_unknown_provider_returns_error(self):
        from logpilot.providers import call_provider_pure
        result = call_provider_pure("unknown_provider", "", "", _make_prompt())
        assert result.error is not None
        assert "Unknown provider" in result.error

    def test_empty_api_key_returns_error_result_not_raise(self):
        """With empty key, should return error result (auth fail) — not crash."""
        from logpilot.providers import call_provider_pure, ProviderResult
        # Mock _call_claude_impl to simulate auth failure
        with mock.patch("logpilot.providers._call_claude_impl",
                        side_effect=Exception("401 Unauthorized")):
            result = call_provider_pure("claude", "", "claude-sonnet-4-6", _make_prompt())
        assert isinstance(result, ProviderResult)
        assert result.answer == "" or result.error is not None


# ---------------------------------------------------------------------------
# call_claude_pure — unit tests with mocked SDK
# ---------------------------------------------------------------------------

class TestCallClaudePure:
    def test_returns_answer_on_success(self):
        from logpilot.providers import call_claude_pure

        mock_msg = mock.MagicMock()
        mock_msg.content = [mock.MagicMock(text="Claude says hello")]
        mock_msg.usage = mock.MagicMock(
            input_tokens=10, output_tokens=5,
            cache_creation_input_tokens=0, cache_read_input_tokens=0,
        )

        mock_client = mock.MagicMock()
        mock_client.messages.create.return_value = mock_msg

        with mock.patch("logpilot.providers._call_claude_impl") as mock_impl:
            mock_impl.return_value = ("Claude says hello", {"input": 10, "output": 5})
            result = call_claude_pure("sk-ant-fake", "claude-sonnet-4-6", _make_prompt())

        assert result.answer == "Claude says hello"
        assert result.error is None
        assert result.input_tokens == 10
        assert result.output_tokens == 5

    def test_returns_error_result_on_exception(self):
        from logpilot.providers import call_claude_pure

        with mock.patch("logpilot.providers._call_claude_impl",
                        side_effect=Exception("Connection refused")):
            result = call_claude_pure("sk-ant-fake", "claude-sonnet-4-6", _make_prompt())

        assert result.answer == ""
        assert result.error is not None
        assert "Connection refused" in result.error

    def test_missing_anthropic_package_returns_error(self):
        from logpilot.providers import call_claude_pure

        with mock.patch("logpilot.providers._call_claude_impl",
                        side_effect=ImportError("anthropic not installed")):
            result = call_claude_pure("", "claude-sonnet-4-6", _make_prompt())

        assert result.error is not None


# ---------------------------------------------------------------------------
# call_local_pure — endpoint/model resolution
# ---------------------------------------------------------------------------

class TestCallLocalPure:
    def test_falls_back_to_env_endpoint(self, monkeypatch):
        from logpilot.providers import call_local_pure

        monkeypatch.setenv("LOGPILOT_AI_ENDPOINT", "http://myserver:8080/v1")
        monkeypatch.setenv("LOGPILOT_AI_MODEL", "llama3")

        with mock.patch("logpilot.providers.call_openai_pure") as mock_fn:
            mock_fn.return_value = mock.MagicMock(answer="ok", error=None,
                                                   input_tokens=0, output_tokens=0)
            call_local_pure(endpoint="", model="", prompt=_make_prompt())
            _, kwargs = mock_fn.call_args
            assert kwargs.get("base_url") == "http://myserver:8080/v1" or \
                   mock_fn.call_args[0][3] == "http://myserver:8080/v1"  # positional fallback

    def test_invalid_api_key_returns_error(self):
        from logpilot.providers import call_local_pure

        result = call_local_pure(
            endpoint="http://localhost:1234/v1",
            model="model",
            prompt=_make_prompt(),
            api_key="invalid\xff\xfe",  # non-ASCII
        )
        assert result.error is not None
        assert "non-ASCII" in result.error or "invalid" in result.error.lower()


# ---------------------------------------------------------------------------
# No Streamlit import at module level
# ---------------------------------------------------------------------------

class TestNoStreamlitAtTopLevel:
    def test_providers_importable_without_streamlit(self):
        """logpilot.providers must not import streamlit at module level."""
        # Strip streamlit from sys.modules and reimport providers
        filtered = {k: v for k, v in sys.modules.items() if "streamlit" not in k}
        with mock.patch.dict(sys.modules, filtered, clear=True):
            # Also ensure streamlit itself raises ImportError if accessed
            sys.modules["streamlit"] = None  # type: ignore
            try:
                import logpilot.providers as providers_mod
                importlib.reload(providers_mod)
                assert hasattr(providers_mod, "call_provider_pure")
            except ImportError as exc:
                if "streamlit" in str(exc).lower():
                    pytest.fail(
                        f"logpilot.providers imports streamlit at top level: {exc}"
                    )
            finally:
                # Restore
                if "streamlit" in sys.modules and sys.modules["streamlit"] is None:
                    del sys.modules["streamlit"]
