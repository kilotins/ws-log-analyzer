"""Tests for local/inhouse AI support (M38)."""
from __future__ import annotations

import sys
import os
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from logpilot.event import LogEvent


class TestLocalAIProviderConfig:
    """Test that local AI provider is properly configured."""

    def test_provider_config_has_local(self):
        from app_ai import PROVIDER_CONFIG
        assert "local" in PROVIDER_CONFIG
        cfg = PROVIDER_CONFIG["local"]
        assert cfg["label"] == "Local AI"
        assert cfg["api_key_prefix"] == ""  # No prefix validation

    def test_ai_models_has_local(self):
        from app_ai import AI_MODELS
        local_models = {k: v for k, v in AI_MODELS.items() if v["provider"] == "local"}
        assert len(local_models) >= 1
        for name, info in local_models.items():
            assert info["provider"] == "local"

    def test_local_ai_presets(self):
        from app_ai import LOCAL_AI_PRESETS
        assert "LM Studio" in LOCAL_AI_PRESETS
        assert "Ollama" in LOCAL_AI_PRESETS
        assert "vLLM" in LOCAL_AI_PRESETS
        assert "Custom" in LOCAL_AI_PRESETS

        assert LOCAL_AI_PRESETS["LM Studio"]["base_url"] == "http://localhost:1234/v1"
        assert LOCAL_AI_PRESETS["Ollama"]["base_url"] == "http://localhost:11434/v1"
        assert LOCAL_AI_PRESETS["vLLM"]["base_url"] == "http://localhost:8000/v1"

    def test_api_callers_has_local(self):
        from app_ai import _API_CALLERS
        assert "local" in _API_CALLERS


class TestCallLocalAPI:
    """Test call_local_api function."""

    def test_call_local_api_connection_refused(self):
        """Verify graceful error when local server is not running."""
        from app_ai import call_local_api
        prompt = {"system": "You are helpful.", "user": "Hello"}

        with pytest.raises(Exception):
            # Should raise connection error, not crash
            call_local_api(
                api_key="not-needed",
                model_id="test-model",
                prompt=prompt,
                base_url="http://localhost:19999/v1",  # Unlikely to be running
                timeout=2.0,
            )

    def test_call_local_api_uses_base_url(self):
        """Verify that base_url is passed to OpenAI client."""
        mock_openai = mock.MagicMock()
        mock_client = mock.MagicMock()
        mock_openai.OpenAI.return_value = mock_client

        # Mock the response
        mock_response = mock.MagicMock()
        mock_response.choices = [mock.MagicMock()]
        mock_response.choices[0].message.content = "Test response"
        mock_response.usage = mock.MagicMock()
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 5
        mock_client.chat.completions.create.return_value = mock_response

        with mock.patch.dict(sys.modules, {"openai": mock_openai}):
            from app_ai import call_local_api
            answer, usage = call_local_api(
                api_key="test-key",
                model_id="llama-3.1-8b",
                prompt={"system": "You are helpful.", "user": "Hello"},
                base_url="http://localhost:1234/v1",
            )

        assert answer == "Test response"
        mock_openai.OpenAI.assert_called_once_with(
            api_key="test-key",
            base_url="http://localhost:1234/v1",
            timeout=120.0,
        )

    def test_call_local_api_no_key_needed(self):
        """Verify that empty api_key defaults to 'not-needed'."""
        mock_openai = mock.MagicMock()
        mock_client = mock.MagicMock()
        mock_openai.OpenAI.return_value = mock_client

        mock_response = mock.MagicMock()
        mock_response.choices = [mock.MagicMock()]
        mock_response.choices[0].message.content = "OK"
        mock_response.usage = None
        mock_client.chat.completions.create.return_value = mock_response

        with mock.patch.dict(sys.modules, {"openai": mock_openai}):
            from app_ai import call_local_api
            answer, usage = call_local_api(
                api_key="",
                model_id="test",
                prompt={"system": "sys", "user": "usr"},
                base_url="http://localhost:1234/v1",
            )

        assert answer == "OK"
        # Verify "not-needed" was used as api_key
        mock_openai.OpenAI.assert_called_once_with(
            api_key="not-needed",
            base_url="http://localhost:1234/v1",
            timeout=120.0,
        )


class TestLocalAIBuildContext:
    """Test that build_ai_request_context handles local provider."""

    def test_local_cache_key_prefix(self):
        from app_ai import build_ai_request_context
        events = [LogEvent(text="ERROR foo", level="ERROR", code=None,
                           exception=None, tags=[], ts=None, file="test.log")]
        _, cache_key, _ = build_ai_request_context("test query", events, provider="local")
        assert cache_key.startswith("local:")


class TestCLILocalAI:
    """Test CLI --ai-endpoint and --ai-model flags."""

    def test_cli_has_ai_endpoint_flag(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "logpilot", "--help"],
            capture_output=True, text=True,
            cwd=str(os.path.dirname(os.path.dirname(__file__)))
        )
        assert "--ai-endpoint" in result.stdout
        assert "--ai-model" in result.stdout

    def test_env_vars_documented(self):
        """Verify LOGPILOT_AI_ENDPOINT and LOGPILOT_AI_MODEL are referenced in code."""
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "logpilot", "--help"],
            capture_output=True, text=True,
            cwd=str(os.path.dirname(os.path.dirname(__file__)))
        )
        assert "LOGPILOT_AI_ENDPOINT" in result.stdout


class TestCloudProvidersUnaffected:
    """Verify that existing cloud providers are not affected by local AI changes."""

    def test_claude_config_unchanged(self):
        from app_ai import PROVIDER_CONFIG
        cfg = PROVIDER_CONFIG["claude"]
        assert cfg["label"] == "Claude"
        assert cfg["api_key_prefix"] == "sk-ant-"

    def test_gemini_config_unchanged(self):
        from app_ai import PROVIDER_CONFIG
        cfg = PROVIDER_CONFIG["gemini"]
        assert cfg["label"] == "Gemini"
        assert cfg["api_key_prefix"] == "AI"

    def test_openai_config_unchanged(self):
        from app_ai import PROVIDER_CONFIG
        cfg = PROVIDER_CONFIG["openai"]
        assert cfg["label"] == "GPT"
        assert cfg["api_key_prefix"] == "sk-"

    def test_cloud_models_still_present(self):
        from app_ai import _ALL_AI_MODELS
        assert "Claude Sonnet 4.6" in _ALL_AI_MODELS
        assert "Gemini 2.5 Flash" in _ALL_AI_MODELS
        assert "GPT-4o" in _ALL_AI_MODELS

    def test_token_costs_unchanged(self):
        from app_constants import TOKEN_COSTS
        assert "claude-sonnet-4-6" in TOKEN_COSTS
        assert "gpt-4o" in TOKEN_COSTS
