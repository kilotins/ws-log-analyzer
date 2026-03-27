"""AI provider orchestration module for the Streamlit GUI."""
from __future__ import annotations

import logging
import threading
import time
import streamlit as st
from datetime import datetime

# Lock for Gemini SDK global state (genai.configure sets API key globally)
_gemini_lock = threading.Lock()

from logpilot import (
    match_user_query, build_claude_prompt, claude_cache_key, triage_cache_key,
    ask_gemini,
    estimate_tokens, TOKEN_LIMITS,
)
from logpilot.ai import _FORMAT_PLACEHOLDER, sanitize_error as _sanitize_error_impl
from app_constants import AI_RATE_LIMIT_SECONDS, AI_MAX_RETRIES, TOKEN_COSTS, CACHE_TOKEN_COSTS
from logpilot.license import is_feature_licensed, allowed_providers, is_model_allowed

_LICENSE_MSG = ("AI analysis requires a valid license key. "
               "Enter one in the sidebar or contact eric@item.no.")


def _check_ai_license(provider: str = "", model: str = "") -> str | None:
    """Return error message if cloud AI is not licensed, else None."""
    token = st.session_state.get("license_key", "")
    if not is_feature_licensed(token):
        return _LICENSE_MSG
    if provider and provider != "local":
        providers = allowed_providers(token)
        if provider not in providers:
            return f"Provider '{provider}' requires a Pro license. Contact eric@item.no to upgrade."
    if model and not is_model_allowed(token, model):
        return f"Model '{model}' requires a Pro license. Contact eric@item.no to upgrade."
    return None

_log = logging.getLogger(__name__)

# HTTP status codes that should NOT be retried (auth/client errors)
_NO_RETRY_STATUS = frozenset({400, 401, 403, 404})

# Transient HTTP status codes that warrant a retry
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


def _sanitize_error(msg: str) -> str:
    """Remove API keys and tokens from error messages before displaying to users."""
    return _sanitize_error_impl(msg)


def _should_retry(exc: Exception) -> bool:
    """Return True if *exc* represents a transient error worth retrying."""
    import socket
    # Connection-level errors
    if isinstance(exc, (TimeoutError, ConnectionError, OSError, socket.timeout)):
        return True
    # urllib timeout/connection errors
    try:
        import urllib.error
        if isinstance(exc, urllib.error.URLError):
            return True
    except ImportError:
        pass
    # Check for HTTP status codes embedded in the exception
    status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
    if status is None:
        # Anthropic SDK wraps status in .response
        resp = getattr(exc, "response", None)
        if resp is not None:
            status = getattr(resp, "status_code", None)
    if status in _NO_RETRY_STATUS:
        return False
    if status in _RETRY_STATUS:
        return True
    # Anthropic/OpenAI SDK exception class names
    cls_name = type(exc).__name__
    if any(k in cls_name for k in ("Timeout", "Connection", "RateLimit", "APIStatusError", "ServiceUnavailable")):
        # Still skip 401/403 even by name
        if status in _NO_RETRY_STATUS:
            return False
        return True
    return False


def _with_retries(func, *args, max_retries: int = AI_MAX_RETRIES, **kwargs):
    """Call *func* with exponential backoff on transient errors.

    Retries up to *max_retries* times (default from AI_MAX_RETRIES).
    Backoff delays: 1s, 2s, 4s, ...
    Auth errors (401/403) and client errors (400) are re-raised immediately.
    """
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            if not _should_retry(exc):
                raise
            last_exc = exc
            if attempt < max_retries:
                delay = 2 ** (attempt - 1)  # 1s, 2s, 4s
                _log.warning(
                    "AI API transient error (attempt %d/%d), retrying in %ds: %s",
                    attempt, max_retries, delay, exc,
                )
                time.sleep(delay)
            else:
                _log.error(
                    "AI API call failed after %d attempts: %s", max_retries, exc
                )
    raise last_exc


def _log_probe(call_type: str, provider: str, model: str, request: str, response: str, error: str | None = None):
    """Record an AI call in the probe log (visible in Debug > Probe tab)."""
    try:
        if not st.session_state.get("debug_payload"):
            return
        entry = {
            "ts": datetime.now().strftime("%H:%M:%S"),
            "type": call_type,
            "provider": provider,
            "model": model,
            "request": request,
            "response": response,
            "error": error,
        }
        if "_ai_probe_log" not in st.session_state:
            st.session_state._ai_probe_log = []
        st.session_state._ai_probe_log.append(entry)
    except Exception:
        pass  # Never break the app for probe logging


# --- Provider configuration for the common AI orchestrator ---
PROVIDER_CONFIG = {
    "claude": {
        "label": "Claude",
        "cache_key": "claude_cache",
        "answer_key": "claude_answer",
        "query_label_key": "claude_query_label",
        "history_key": "claude_history",
        "api_key_field": "api_key",
        "save_history": None,  # Set by init_provider_config()
        "api_key_error": "Enter your Anthropic API key in the sidebar.",
        "api_key_prefix": "sk-ant-",
    },
    "gemini": {
        "label": "Gemini",
        "cache_key": "gemini_cache",
        "answer_key": "gemini_answer",
        "query_label_key": "gemini_query_label",
        "history_key": "gemini_history",
        "api_key_field": "gemini_api_key",
        "save_history": None,  # Set by init_provider_config()
        "api_key_error": "Enter your Gemini API key in the sidebar or set GEMINI_API_KEY env var.",
        "api_key_prefix": "AI",
    },
    "openai": {
        "label": "GPT",
        "cache_key": "openai_cache",
        "answer_key": "openai_answer",
        "query_label_key": "openai_query_label",
        "history_key": "openai_history",
        "api_key_field": "openai_api_key",
        "save_history": None,  # Set by init_provider_config()
        "api_key_error": "Enter your OpenAI API key in the sidebar or set OPENAI_API_KEY env var.",
        "api_key_prefix": "sk-",
    },
    "local": {
        "label": "Local AI",
        "cache_key": "local_cache",
        "answer_key": "local_answer",
        "query_label_key": "local_query_label",
        "history_key": "local_history",
        "api_key_field": "local_api_key",
        "save_history": None,  # Set by init_provider_config()
        "api_key_error": "",
        "api_key_prefix": "",  # No prefix validation for local
    },
}


def init_provider_config(save_history_funcs: dict):
    """Initialize save_history callbacks. Called from app.py after history files are set up.

    Args:
        save_history_funcs: dict mapping provider name -> save function
    """
    for provider, func in save_history_funcs.items():
        PROVIDER_CONFIG[provider]["save_history"] = func


_ALL_AI_MODELS = {
    "Claude Sonnet 4.6": {"provider": "claude", "model_id": "claude-sonnet-4-6"},
    "Claude Haiku 4.5": {"provider": "claude", "model_id": "claude-haiku-4-5-20251001"},
    "Gemini 2.5 Flash": {"provider": "gemini", "model_id": "gemini-2.5-flash"},
    "Gemini 2.5 Pro": {"provider": "gemini", "model_id": "gemini-2.5-pro"},
    "GPT-4o": {"provider": "openai", "model_id": "gpt-4o"},
    "GPT-4o mini": {"provider": "openai", "model_id": "gpt-4o-mini"},
    "Local AI (custom)": {"provider": "local", "model_id": ""},
}

# Check which cloud provider packages are actually installed
_AVAILABLE_PROVIDERS = {"local"}  # local always available (uses urllib)
try:
    import anthropic  # noqa: F401
    _AVAILABLE_PROVIDERS.add("claude")
except ImportError:
    pass
try:
    import google.generativeai  # noqa: F401
    _AVAILABLE_PROVIDERS.add("gemini")
except ImportError:
    pass
try:
    import openai  # noqa: F401
    _AVAILABLE_PROVIDERS.add("openai")
except ImportError:
    pass

AI_MODELS = {
    name: cfg for name, cfg in _ALL_AI_MODELS.items()
    if cfg["provider"] in _AVAILABLE_PROVIDERS
}

# Presets for local/inhouse AI servers
LOCAL_AI_PRESETS = {
    "LM Studio": {"base_url": "http://localhost:1234/v1", "api_key": "lm-studio"},
    "Ollama": {"base_url": "http://localhost:11434/v1", "api_key": "ollama"},
    "vLLM": {"base_url": "http://localhost:8000/v1", "api_key": "vllm"},
    "Custom": {"base_url": "", "api_key": ""},
}


def discover_local_models(endpoint: str, api_key: str = "not-needed", timeout: float = 5.0) -> dict:
    """Probe a local OpenAI-compatible endpoint for available models.

    Returns {"status": "connected"|"failed"|"no_models", "models": [...], "error": str|None}.
    """
    import urllib.request
    import urllib.error

    url = endpoint.rstrip("/")
    if not url.endswith("/models"):
        url += "/models"

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {api_key}")
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            import json as _json
            data = _json.loads(resp.read().decode("utf-8"))
            models = []
            if isinstance(data, dict) and "data" in data:
                for m in data["data"]:
                    mid = m.get("id") or m.get("name", "")
                    if mid:
                        models.append(mid)
            elif isinstance(data, list):
                for m in data:
                    mid = m.get("id") or m.get("name", "") if isinstance(m, dict) else str(m)
                    if mid:
                        models.append(mid)
            if models:
                return {"status": "connected", "models": sorted(models), "error": None}
            return {"status": "no_models", "models": [], "error": "Endpoint responded but returned no models."}
    except urllib.error.URLError as ex:
        return {"status": "failed", "models": [], "error": f"Cannot reach endpoint: {ex.reason}"}
    except (ValueError, OSError) as ex:
        return {"status": "failed", "models": [], "error": f"Invalid endpoint: {ex}"}
    except Exception as ex:
        return {"status": "failed", "models": [], "error": str(ex)}


def estimate_cost(model_id: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate cost in USD given model and token counts."""
    costs = TOKEN_COSTS.get(model_id, (0, 0))
    return (input_tokens * costs[0] + output_tokens * costs[1]) / 1_000_000


def _call_claude_api_impl(api_key: str, model_id: str, prompt: dict, stream_placeholder=None,
                          timeout: float = 120.0, max_tokens: int = 2048,
                          images: list[dict] | None = None) -> tuple[str, dict]:
    """Internal implementation — use call_claude_api (which adds retry logic)."""
    try:
        from anthropic import Anthropic
    except ImportError:
        raise ImportError("The `anthropic` package is not installed. Install with: `pip install anthropic`")
    client = Anthropic(api_key=api_key, timeout=timeout)

    # Build user message content — multimodal when images are provided
    if images:
        user_content: list[dict] = []
        for img in images:
            user_content.append({
                "type": "image",
                "source": {"type": "base64", "media_type": img["media_type"], "data": img["data"]},
            })
        user_content.append({"type": "text", "text": prompt.get("user", "")})
    else:
        user_content = prompt.get("user", "")

    # Support pre-built messages list (multimodal path from _build_multimodal_messages)
    if "messages" in prompt:
        messages = prompt["messages"]
    else:
        messages = [{"role": "user", "content": user_content}]

    if stream_placeholder:
        chunks = []
        with client.messages.stream(
            model=model_id, max_tokens=max_tokens,
            system=[{"type": "text", "text": prompt["system"], "cache_control": {"type": "ephemeral"}}],
            messages=messages,
        ) as stream:
            for text in stream.text_stream:
                chunks.append(text)
                stream_placeholder.markdown("".join(chunks) + "\n\n*Streaming...*")
            final = stream.get_final_message()
        answer = "".join(chunks)
        usage = _extract_claude_usage(final.usage if final else None)
        return (answer or None, usage)

    message = client.messages.create(
        model=model_id, max_tokens=max_tokens,
        system=[{"type": "text", "text": prompt["system"], "cache_control": {"type": "ephemeral"}}],
        messages=messages,
    )
    if not message.content:
        return (None, {})
    usage = _extract_claude_usage(message.usage)
    return (message.content[0].text, usage)


def call_claude_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None,
                    timeout: float = 120.0, max_tokens: int = 2048,
                    images: list[dict] | None = None) -> tuple[str, dict]:
    """Make the actual Claude API call with retry logic on transient errors.

    Retries up to AI_MAX_RETRIES times with exponential backoff (1s, 2s, 4s).
    Auth errors (401/403) and bad-request errors (400) are raised immediately.

    Args:
        images: Optional list of image dicts with keys ``media_type`` (e.g. ``"image/png"``)
                and ``data`` (base64-encoded string). When provided, the user message is
                sent as a multimodal content block (image + text) instead of plain text.

    Returns (answer, usage_dict).
    """
    _lic_err = _check_ai_license(provider="claude", model=model_id)
    if _lic_err:
        return (_lic_err, {})
    return _with_retries(
        _call_claude_api_impl, api_key, model_id, prompt,
        stream_placeholder=stream_placeholder, timeout=timeout,
        max_tokens=max_tokens, images=images,
    )


def _extract_claude_usage(usage) -> dict:
    """Extract token usage from Claude API response, including cache tokens."""
    if not usage:
        return {}
    return {
        "input": getattr(usage, "input_tokens", 0) or 0,
        "output": getattr(usage, "output_tokens", 0) or 0,
        "cache_creation": getattr(usage, "cache_creation_input_tokens", 0) or 0,
        "cache_read": getattr(usage, "cache_read_input_tokens", 0) or 0,
    }


def _call_gemini_api_impl(api_key: str, model_id: str, prompt: dict, stream_placeholder=None,
                          timeout: float = 120.0, max_tokens: int = 2048,
                          images: list[dict] | None = None) -> tuple[str, dict]:
    """Internal implementation — use call_gemini_api (which adds retry logic)."""
    import os
    key = api_key or os.environ.get("GEMINI_API_KEY", "")

    if images:
        # Multimodal path — use native Gemini SDK with inline_data
        if not key:
            raise ValueError("GEMINI_API_KEY is not set.")
        try:
            import google.generativeai as genai
            import base64 as _base64
        except ImportError:
            raise ImportError(
                "The `google-generativeai` package is not installed. "
                "Install with: pip install google-generativeai"
            )
        with _gemini_lock:
            genai.configure(api_key=key)
            gen_model = genai.GenerativeModel(model_id, system_instruction=prompt["system"])
            content_parts: list = []
            for img in images:
                content_parts.append({
                    "inline_data": {
                        "mime_type": img["media_type"],
                        "data": _base64.b64decode(img["data"]),
                    }
                })
            content_parts.append(prompt.get("user", ""))
            response = gen_model.generate_content(content_parts, request_options={"timeout": timeout})
        answer = response.text if response else None
    elif "messages" in prompt:
        # Pre-built multimodal messages dict (from _build_multimodal_messages)
        if not key:
            raise ValueError("GEMINI_API_KEY is not set.")
        try:
            import google.generativeai as genai
            import base64 as _base64
        except ImportError:
            raise ImportError(
                "The `google-generativeai` package is not installed. "
                "Install with: pip install google-generativeai"
            )
        with _gemini_lock:
            genai.configure(api_key=key)
            gen_model = genai.GenerativeModel(model_id, system_instruction=prompt["system"])
            msg = prompt["messages"][0]
            parts = msg.get("parts", [])
            content_parts = []
            for p in parts:
                if "inline_data" in p:
                    content_parts.append({
                        "inline_data": {
                            "mime_type": p["inline_data"]["mime_type"],
                            "data": _base64.b64decode(p["inline_data"]["data"]),
                        }
                    })
                elif "text" in p:
                    content_parts.append(p["text"])
            response = gen_model.generate_content(
                content_parts or prompt.get("user", ""),
                request_options={"timeout": timeout},
            )
        answer = response.text if response else None
    else:
        # Text-only path — use the logpilot wrapper
        answer = ask_gemini(prompt["user"], api_key=api_key, system=prompt["system"], model=model_id, timeout=timeout)

    # Gemini SDK doesn't return token usage, so estimate from prompt/response text
    usage = {}
    if answer:
        input_text = (prompt.get("system") or "") + (prompt.get("user") or "")
        usage = {
            "input": estimate_tokens(input_text),
            "output": estimate_tokens(answer),
        }
    return (answer or None, usage)


def call_gemini_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None,
                    timeout: float = 120.0, max_tokens: int = 2048,
                    images: list[dict] | None = None) -> tuple[str, dict]:
    """Make the actual Gemini API call with retry logic on transient errors.

    Retries up to AI_MAX_RETRIES times with exponential backoff (1s, 2s, 4s).
    Auth errors (401/403) and bad-request errors (400) are raised immediately.

    Args:
        images: Optional list of image dicts with keys ``media_type`` and ``data``
                (base64-encoded string). When provided, the call uses the native
                Gemini SDK directly to send inline image data instead of plain text.

    Returns (answer, usage_dict). Streaming not supported.
    """
    _lic_err = _check_ai_license(provider="gemini", model=model_id)
    if _lic_err:
        return (_lic_err, {})
    return _with_retries(
        _call_gemini_api_impl, api_key, model_id, prompt,
        stream_placeholder=stream_placeholder, timeout=timeout,
        max_tokens=max_tokens, images=images,
    )


def _call_openai_api_impl(api_key: str, model_id: str, prompt: dict, stream_placeholder=None,
                          timeout: float = 120.0, max_tokens: int = 2048,
                          images: list[dict] | None = None,
                          base_url: str | None = None) -> tuple[str, dict]:
    """Internal implementation — use call_openai_api (which adds retry logic)."""
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("The `openai` package is not installed. Install with: `pip install openai`")

    client_kwargs: dict = {"api_key": api_key or "not-needed", "timeout": timeout}
    if base_url:
        client_kwargs["base_url"] = base_url
    client = OpenAI(**client_kwargs)

    # Build messages list — multimodal when images or pre-built messages are present
    if "messages" in prompt:
        # Pre-built multimodal messages dict (from _build_multimodal_messages)
        messages_list = [{"role": "system", "content": prompt["system"]}]
        messages_list.extend(prompt["messages"])
    elif images:
        user_content: list[dict] = []
        for img in images:
            user_content.append({
                "type": "image_url",
                "image_url": {"url": f"data:{img['media_type']};base64,{img['data']}"},
            })
        user_content.append({"type": "text", "text": prompt.get("user", "")})
        messages_list = [
            {"role": "system", "content": prompt["system"]},
            {"role": "user", "content": user_content},
        ]
    else:
        messages_list = [
            {"role": "system", "content": prompt["system"]},
            {"role": "user", "content": prompt.get("user", "")},
        ]

    if stream_placeholder:
        chunks = []
        response = client.chat.completions.create(
            model=model_id, max_completion_tokens=max_tokens, stream=True,
            stream_options={"include_usage": True},
            messages=messages_list,
        )
        usage = {}
        for chunk in response:
            if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                chunks.append(chunk.choices[0].delta.content)
                stream_placeholder.markdown("".join(chunks) + "\n\n*Streaming...*")
            if chunk.usage:
                usage = {"input": chunk.usage.prompt_tokens, "output": chunk.usage.completion_tokens}
        answer = "".join(chunks)
        return (answer or None, usage)

    response = client.chat.completions.create(
        model=model_id, max_completion_tokens=max_tokens,
        messages=messages_list,
    )
    answer = response.choices[0].message.content
    usage = {}
    if response.usage:
        usage = {"input": response.usage.prompt_tokens, "output": response.usage.completion_tokens}
    return (answer or None, usage)


def call_openai_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None,
                    timeout: float = 120.0, max_tokens: int = 2048,
                    images: list[dict] | None = None,
                    base_url: str | None = None) -> tuple[str, dict]:
    """Make the actual OpenAI API call with retry logic on transient errors.

    Retries up to AI_MAX_RETRIES times with exponential backoff (1s, 2s, 4s).
    Auth errors (401/403) and bad-request errors (400) are raised immediately.

    Args:
        images: Optional list of image dicts with keys ``media_type`` and ``data``
                (base64-encoded string). When provided, the user message is sent as
                a multimodal content block (image_url + text) instead of plain text.
        base_url: Optional base URL for OpenAI-compatible local servers.

    Returns (answer, usage_dict).
    """
    _lic_err = _check_ai_license(provider="openai", model=model_id)
    if _lic_err:
        return (_lic_err, {})
    return _with_retries(
        _call_openai_api_impl, api_key, model_id, prompt,
        stream_placeholder=stream_placeholder, timeout=timeout,
        max_tokens=max_tokens, images=images, base_url=base_url,
    )


def _call_local_api_impl(api_key: str, model_id: str, prompt: dict, stream_placeholder=None,
                         timeout: float = 120.0, max_tokens: int = 2048,
                         base_url: str | None = None,
                         images: list[dict] | None = None) -> tuple[str, dict]:
    """Internal implementation — use call_local_api (which adds retry logic)."""
    # Delegate to the OpenAI impl directly (not the retry wrapper) to avoid double retry
    if not base_url:
        # Read from session state or env
        try:
            import streamlit as _st
            base_url = getattr(_st.session_state, "local_ai_endpoint", "") or ""
        except Exception:
            pass
        if not base_url:
            import os
            base_url = os.environ.get("LOGPILOT_AI_ENDPOINT", "http://localhost:1234/v1")

    if not model_id:
        try:
            import streamlit as _st
            model_id = getattr(_st.session_state, "local_ai_model", "") or ""
        except Exception:
            pass
        if not model_id:
            import os
            model_id = os.environ.get("LOGPILOT_AI_MODEL", "default")

    return _call_openai_api_impl(
        api_key=api_key or "not-needed",
        model_id=model_id,
        prompt=prompt,
        stream_placeholder=stream_placeholder,
        timeout=timeout,
        max_tokens=max_tokens,
        images=images,
        base_url=base_url,
    )


def call_local_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None,
                   timeout: float = 120.0, max_tokens: int = 2048,
                   base_url: str | None = None,
                   images: list[dict] | None = None) -> tuple[str, dict]:
    """Call a local/inhouse OpenAI-compatible API with retry logic on transient errors.

    Retries up to AI_MAX_RETRIES times with exponential backoff (1s, 2s, 4s).
    Auth errors (401/403) and bad-request errors (400) are raised immediately.

    Uses the OpenAI SDK with a custom base_url. The api_key can be any
    non-empty string for servers that don't require authentication.

    Args:
        images: Optional list of image dicts with keys ``media_type`` and ``data``
                (base64-encoded string). When provided, the user message is sent as
                a multimodal content block (image_url + text).
    """
    return _with_retries(
        _call_local_api_impl, api_key, model_id, prompt,
        stream_placeholder=stream_placeholder, timeout=timeout,
        max_tokens=max_tokens, base_url=base_url, images=images,
    )


_API_CALLERS = {
    "claude": call_claude_api,
    "gemini": call_gemini_api,
    "openai": call_openai_api,
    "local": call_local_api,
}



def detect_dominant_format(events: list[dict]) -> str:
    """Detect the most common log format from parsed events."""
    if not events:
        return ""
    from collections import Counter
    formats = Counter(e.format for e in events if e.format)
    if not formats:
        return ""
    return formats.most_common(1)[0][0]


def build_ai_request_context(user_query: str, events: list[dict], provider: str = "claude", log=None) -> dict:
    """Compute match, cache key, and prompt for an AI analysis request."""
    match = match_user_query(user_query, events)
    cache_key = claude_cache_key(user_query, match)
    if provider == "gemini":
        cache_key = "gemini:" + cache_key
    elif provider == "openai":
        cache_key = "openai:" + cache_key
    elif provider == "local":
        cache_key = "local:" + cache_key
    detected_format = detect_dominant_format(events)
    prompt = build_claude_prompt(user_query, match, detected_format=detected_format)
    skills = prompt.get("skills", [])
    if skills and log:
        log.info("skills %s selected skills: %s (format: %s)", provider, ", ".join(skills), detected_format or "unknown")
    return match, cache_key, prompt



def _run_ai_analysis(provider: str, model_id: str, user_query: str, events: list[dict],
                     processing_container, log=None, lookup_cache=None, store_cache=None) -> None:
    """Common AI analysis orchestrator. Handles caching, history, and error display."""
    import time as _time
    now = _time.time()
    elapsed = now - st.session_state.last_ai_call_ts
    if elapsed < AI_RATE_LIMIT_SECONDS:
        st.warning(f"Rate limit: wait {AI_RATE_LIMIT_SECONDS - elapsed:.0f}s before next AI call.")
        return
    st.session_state.last_ai_call_ts = now

    cfg = PROVIDER_CONFIG[provider]
    label = cfg["label"]

    if log:
        log.info("%s Ask %s request: %s", provider, label, user_query[:100])
    with processing_container:
        status = st.status(f"Analyzing with {label}...", expanded=True)

    match, cache_key, prompt = build_ai_request_context(user_query, events, provider, log=log)
    session_cache = getattr(st.session_state, cfg["cache_key"])

    cached = None
    if lookup_cache and provider != "local":
        cached = lookup_cache(cache_key, session_cache, label, user_query)

    def _record_answer(answer):
        setattr(st.session_state, cfg["answer_key"], answer)
        setattr(st.session_state, cfg["query_label_key"], user_query)
        entry = {
            "query": user_query,
            "answer": answer,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }
        hist = getattr(st.session_state, cfg["history_key"])
        if not any(h["query"] == user_query and h["answer"] == answer for h in hist):
            hist.append(entry)
            cfg["save_history"](hist)

    if cached:
        _record_answer(cached)
        status.update(label=f"{label} analysis complete (cached)", state="complete")
        return

    if match["matched"]:
        status.write(f"Found {len(match['matching_events'])} matching event(s) "
                     f"(match type: {match['match_type']})")
    else:
        status.write(f"No exact match -- sending general question to {label}.")

    api_key = getattr(st.session_state, cfg["api_key_field"], "")
    if provider == "local":
        # Local providers don't require an API key — use a placeholder
        if not api_key:
            api_key = getattr(st.session_state, "local_ai_api_key", "") or "not-needed"
    elif not api_key:
        status.update(label=f"No {label} API key set", state="error")
        st.error(cfg["api_key_error"])
        return
    expected_prefix = cfg.get("api_key_prefix", "")
    if expected_prefix and not api_key.startswith(expected_prefix):
        status.update(label=f"Invalid {label} API key format", state="error")
        st.error(f"{label} API key should start with `{expected_prefix}`. Check your key in the sidebar.")
        return

    # Pre-flight token estimation — warn if prompt is near context limit
    prompt_text = prompt.get("system", "") + prompt.get("user", "")
    est_tokens = estimate_tokens(prompt_text)
    token_limit = TOKEN_LIMITS.get(provider, TOKEN_LIMITS["claude"])
    if est_tokens > int(token_limit * 0.8):
        pct = est_tokens / token_limit * 100
        st.warning(
            f"Estimated prompt size (~{est_tokens:,} tokens) is {pct:.0f}% of "
            f"{label}'s {token_limit:,}-token context limit. "
            f"Consider shortening your query or reducing log input."
        )

    _req_text = f"[SYSTEM]\n{prompt['system']}\n\n[USER]\n{prompt['user']}"

    if log:
        log.info("cache Cache miss -- calling %s API for: %s", label, user_query[:60])
    status.write(f"Calling {label} API ({model_id})...")
    stream_placeholder = st.empty()  # for streaming text display
    try:
        caller = _API_CALLERS[provider]
        answer, usage = caller(api_key, model_id, prompt, stream_placeholder=stream_placeholder)
        if not answer:
            if log:
                log.warning("%s %s returned empty response for: %s", provider, label, user_query[:60])
            status.update(label=f"Empty response from {label}", state="error")
            _log_probe("Ask AI", provider, model_id, _req_text, "", error="Empty response")
            return
        if log:
            log.info("%s %s response received (%d chars) for: %s",
                     provider, label, len(answer), user_query[:60])
        _log_probe("Ask AI", provider, model_id, _req_text, answer)
        stream_placeholder.empty()  # clear streaming display
        _record_answer(answer)
        if store_cache and provider != "local":
            store_cache(cache_key, answer, session_cache)
        # Display token usage and cost
        cost_info = ""
        if usage:
            inp = usage.get("input", 0)
            out = usage.get("output", 0)
            cache_c = usage.get("cache_creation", 0)
            cache_r = usage.get("cache_read", 0)
            cost = estimate_cost(model_id, inp, out)
            cost_info = f" -- {inp:,}+{out:,} tokens (~${cost:.4f})"
            cache_badge = ""
            if cache_c or cache_r:
                cost_info += f" [cache W:{cache_c:,} R:{cache_r:,}]"
                cache_badge = " (cached)" if cache_r > cache_c else ""
            if log:
                log.info("%s tokens: %d in / %d out, cache: %d write / %d read, est cost: $%.4f",
                         label, inp, out, cache_c, cache_r, cost)
            from app_spend import record_spend
            record_spend(provider, model_id, inp, out, source="chat",
                         cache_creation=cache_c, cache_read=cache_r)
            st.caption(f"{label}{cache_badge}: {inp:,} in + {out:,} out tokens — estimated cost **${cost:.4f}**")
        status.update(label=f"{label} analysis complete{cost_info}", state="complete")
    except ImportError as ex:
        status.update(label="Missing package", state="error")
        st.error(str(ex))
        _log_probe("Ask AI", provider, model_id, _req_text, "", error=str(ex))
    except Exception as ex:
        if log:
            log.error("%s %s API error: %s", provider, label, _sanitize_error(str(ex)))
        _log_probe("Ask AI", provider, model_id, _req_text, "", error=str(ex))
        status.update(label=f"{label} API error: {ex}", state="error")


def run_claude_analysis(user_query, events, processing_container, model_id="claude-sonnet-4-6",
                        log=None, lookup_cache=None, store_cache=None):
    """Run Claude API analysis with caching."""
    _run_ai_analysis("claude", model_id, user_query, events, processing_container,
                     log=log, lookup_cache=lookup_cache, store_cache=store_cache)


def run_gemini_analysis(user_query, events, processing_container, model_id="gemini-2.5-flash",
                        log=None, lookup_cache=None, store_cache=None):
    """Run Gemini API analysis with caching."""
    _run_ai_analysis("gemini", model_id, user_query, events, processing_container,
                     log=log, lookup_cache=lookup_cache, store_cache=store_cache)


def run_openai_analysis(user_query, events, processing_container, model_id="gpt-4o",
                        log=None, lookup_cache=None, store_cache=None):
    """Run OpenAI API analysis with caching."""
    _run_ai_analysis("openai", model_id, user_query, events, processing_container,
                     log=log, lookup_cache=lookup_cache, store_cache=store_cache)


def run_local_analysis(user_query, events, processing_container, model_id="",
                       log=None, lookup_cache=None, store_cache=None):
    """Run local/inhouse AI analysis via OpenAI-compatible API."""
    _run_ai_analysis("local", model_id, user_query, events, processing_container,
                     log=log, lookup_cache=lookup_cache, store_cache=store_cache)


# --- AI response rendering ---

def _render_claude_response(text):
    """Render AI response as markdown with proper code block handling.

    Renders the entire response as a single st.markdown() call for reliability,
    with separate st.code() calls only for fenced code blocks.
    This avoids Streamlit element limits that can cause truncated rendering.
    """
    lines = text.split("\n")
    in_block = False
    fence_len = 0
    block_lang = ""
    block_lines: list[str] = []
    sections: list[tuple[str, str | None]] = []  # (content, lang_or_None)
    prose_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            tick_count = sum(1 for ch in stripped if ch == "`")
            remaining = stripped[tick_count:].strip()
            # Recount properly (only leading backticks)
            tick_count = 0
            for ch in stripped:
                if ch == "`":
                    tick_count += 1
                else:
                    break

            if not in_block:
                # Flush prose
                prose = "\n".join(prose_lines).strip()
                if prose:
                    sections.append((prose, None))
                prose_lines = []
                in_block = True
                fence_len = tick_count
                block_lang = stripped[tick_count:].strip().lower()
                block_lines = []
            elif tick_count >= fence_len:
                in_block = False
                code = "\n".join(block_lines).strip()
                if code:
                    sections.append((code, block_lang or "text"))
                block_lines = []
                block_lang = ""
                fence_len = 0
            else:
                block_lines.append(line)
        elif in_block:
            block_lines.append(line)
        else:
            prose_lines.append(line)

    # Flush remaining
    if in_block and block_lines:
        code = "\n".join(block_lines).strip()
        if code:
            sections.append((code, block_lang or "text"))
    prose = "\n".join(prose_lines).strip()
    if prose:
        sections.append((prose, None))

    # Render: prose as single markdown, code as st.code
    for content, lang in sections:
        if lang is None:
            st.markdown(content)
        else:
            st.code(content, language=lang)


def render_current_ai_analyses():
    """Render expanders for current Claude, Gemini, GPT, and Local AI results."""
    _has_claude = bool(st.session_state.claude_answer)
    _has_gemini = bool(st.session_state.gemini_answer)
    _has_openai = bool(st.session_state.openai_answer)
    _has_local = bool(st.session_state.get("local_answer"))
    if not _has_claude and not _has_gemini and not _has_openai and not _has_local:
        return

    _count = sum([_has_claude, _has_gemini, _has_openai, _has_local])
    _expand_last = _count == 1

    st.markdown("---")
    st.subheader("Current AI analyses")

    if _has_claude:
        label = st.session_state.claude_query_label or "query"
        with st.expander(f"Claude analysis \u2014 {label}", expanded=_expand_last and _has_claude):
            _render_claude_response(st.session_state.claude_answer)

    if _has_gemini:
        label = st.session_state.gemini_query_label or "query"
        with st.expander(f"Gemini analysis \u2014 {label}", expanded=_expand_last and _has_gemini):
            st.markdown(st.session_state.gemini_answer)

    if _has_openai:
        label = st.session_state.openai_query_label or "query"
        with st.expander(f"GPT analysis \u2014 {label}", expanded=_expand_last and _has_openai):
            st.markdown(st.session_state.openai_answer)

    if _has_local:
        label = st.session_state.get("local_query_label") or "query"
        with st.expander(f"Local AI analysis \u2014 {label}", expanded=_expand_last and _has_local):
            st.markdown(st.session_state.local_answer)


def render_ai_history():
    """Render previous query history for Claude, Gemini, and GPT."""
    claude_history = st.session_state.claude_history
    if len(claude_history) > 1:
        st.markdown("---")
        st.subheader("Previous Claude queries")
        for _, entry in enumerate(reversed(claude_history[:-1])):
            hist_label = f"Claude \u2014 {entry['query']} ({entry['timestamp']})"
            with st.expander(hist_label):
                _render_claude_response(entry["answer"])

    gemini_history = st.session_state.gemini_history
    if len(gemini_history) > 1:
        st.markdown("---")
        st.subheader("Previous Gemini queries")
        for _, entry in enumerate(reversed(gemini_history[:-1])):
            hist_label = f"Gemini \u2014 {entry['query']} ({entry['timestamp']})"
            with st.expander(hist_label):
                st.markdown(entry["answer"])

    openai_history = st.session_state.openai_history
    if len(openai_history) > 1:
        st.markdown("---")
        st.subheader("Previous GPT queries")
        for _, entry in enumerate(reversed(openai_history[:-1])):
            hist_label = f"GPT \u2014 {entry['query']} ({entry['timestamp']})"
            with st.expander(hist_label):
                st.markdown(entry["answer"])

    local_history = st.session_state.get("local_history", [])
    if len(local_history) > 1:
        st.markdown("---")
        st.subheader("Previous Local AI queries")
        for _, entry in enumerate(reversed(local_history[:-1])):
            hist_label = f"Local AI \u2014 {entry['query']} ({entry['timestamp']})"
            with st.expander(hist_label):
                st.markdown(entry["answer"])


def clear_all_ai_history():
    """Clear all AI history, current answers, and incident from session and disk."""
    # Clear session state
    for key in ("claude_answer", "gemini_answer", "openai_answer", "local_answer",
                "claude_query_label", "gemini_query_label", "openai_query_label", "local_query_label",
                "_incident_answer", "_incident_model"):
        if key in st.session_state:
            st.session_state[key] = None
    for key in ("claude_history", "gemini_history", "openai_history", "local_history"):
        if key in st.session_state:
            st.session_state[key] = []
    for key in ("claude_cache", "gemini_cache", "openai_cache", "local_cache"):
        if key in st.session_state:
            st.session_state[key] = {}

    # Clear disk files
    from pathlib import Path
    cache_dir = Path(__file__).parent / "cache"
    for fname in ("ai_responses.json", "claude_history.json", "gemini_history.json",
                  "openai_history.json", "local_history.json"):
        p = cache_dir / fname
        if p.exists():
            try:
                p.write_text("{}" if fname == "ai_responses.json" else "[]", encoding="utf-8")
            except OSError:
                pass


def render_ai_responses():
    """Render current AI analyses and history outside expanders for proper scrolling."""
    render_current_ai_analyses()
    render_ai_history()

    # Clear button — only show if there's any AI content
    has_any = any([
        st.session_state.get("claude_answer"),
        st.session_state.get("gemini_answer"),
        st.session_state.get("openai_answer"),
        st.session_state.get("local_answer"),
        st.session_state.get("_triage_answer"),
        st.session_state.get("_incident_answer"),
        len(st.session_state.get("claude_history", [])) > 0,
        len(st.session_state.get("gemini_history", [])) > 0,
        len(st.session_state.get("openai_history", [])) > 0,
        len(st.session_state.get("local_history", [])) > 0,
    ])
    if has_any:
        st.markdown("---")
        if st.button("Clear all AI history", key="clear_ai_history_btn"):
            clear_all_ai_history()
            st.rerun()


def render_ask_claude(events, log=None, lookup_cache=None, store_cache=None):
    """Render AI analysis input, API calls, and response history."""
    detected_format = detect_dominant_format(events)
    placeholder = _FORMAT_PLACEHOLDER.get(detected_format,
        "e.g. error code, exception name, or troubleshooting question")
    st.caption("Paste an error code, exception, or message from the summary above — or type a question.")
    user_query = st.text_input(
        "Ask AI",
        placeholder=placeholder,
        key="claude_query_input",
        label_visibility="collapsed",
    )

    col_model, col_btn = st.columns([2, 1])
    with col_model:
        selected_model = st.selectbox(
            "AI Model",
            list(AI_MODELS.keys()),
            key="ai_analysis_model",
            label_visibility="collapsed",
        )
    with col_btn:
        analyze_clicked = st.button(
            "Analyze",
            type="primary",
            disabled=not user_query,
            key="ai_analyze_btn",
        )

    _model_info = AI_MODELS.get(selected_model, {})

    processing_container = st.container()

    if user_query and analyze_clicked:
        provider = _model_info.get("provider", "claude")
        model_id = _model_info.get("model_id", "")
        if provider == "claude":
            run_claude_analysis(user_query, events, processing_container, model_id=model_id,
                               log=log, lookup_cache=lookup_cache, store_cache=store_cache)
        elif provider == "gemini":
            run_gemini_analysis(user_query, events, processing_container, model_id=model_id,
                               log=log, lookup_cache=lookup_cache, store_cache=store_cache)
        elif provider == "local":
            run_local_analysis(user_query, events, processing_container, model_id=model_id,
                              log=log, lookup_cache=lookup_cache, store_cache=store_cache)
        else:
            run_openai_analysis(user_query, events, processing_container, model_id=model_id,
                               log=log, lookup_cache=lookup_cache, store_cache=store_cache)

    pending = st.session_state.pop("_ask_claude_pending", False)
    gemini_pending = st.session_state.pop("_ask_gemini_pending", False)
    openai_pending = st.session_state.pop("_ask_openai_pending", False)
    if user_query and pending:
        run_claude_analysis(user_query, events, processing_container,
                           log=log, lookup_cache=lookup_cache, store_cache=store_cache)
    if user_query and gemini_pending:
        run_gemini_analysis(user_query, events, processing_container,
                           log=log, lookup_cache=lookup_cache, store_cache=store_cache)
    if user_query and openai_pending:
        run_openai_analysis(user_query, events, processing_container,
                           log=log, lookup_cache=lookup_cache, store_cache=store_cache)

    # AI responses are rendered by render_ai_responses() outside the expander
    # to avoid scrolling issues with long content inside expanders.


def render_analyze_all_button(a: dict, log=None, lookup_cache=None, store_cache=None):
    """Render the 'Analyze all logs' cross-system triage button."""
    from logpilot.ai import build_cross_system_prompt, estimate_tokens

    events = a.get("events", [])
    sources = set(e.system_label or "" for e in events)
    if len(sources) < 2:
        return  # Only for multi-source

    st.subheader("AI Cross-System Triage")
    st.caption(f"Analyze all {len(events)} events from {len(sources)} sources in one AI call.")

    # Model selection
    _model_col, _btn_col = st.columns([1, 1])
    with _model_col:
        _triage_model = st.selectbox(
            "Model",
            list(AI_MODELS.keys()),
            key="triage_model",
            label_visibility="collapsed",
        )

    with _btn_col:
        _triage_clicked = st.button("Analyze All Logs", type="primary", key="triage_btn",
                                    use_container_width=True)

    # Show cached result if available
    _triage_answer = st.session_state.get("_triage_answer")

    if _triage_clicked:
        import time as _time
        now = _time.time()
        elapsed = now - st.session_state.last_ai_call_ts
        if elapsed < AI_RATE_LIMIT_SECONDS:
            st.warning(f"Rate limit: wait {AI_RATE_LIMIT_SECONDS - elapsed:.0f}s before next AI call.")
            return
        st.session_state.last_ai_call_ts = now

        model_info = AI_MODELS[_triage_model]
        provider = model_info["provider"]
        model_id = model_info["model_id"]

        # Cache lookup
        _cache_key = triage_cache_key(events, model_id)
        _session_cache = getattr(st.session_state, PROVIDER_CONFIG.get(provider, PROVIDER_CONFIG["claude"])["cache_key"], {})
        cached = lookup_cache(_cache_key, _session_cache, f"triage/{provider}", "cross-system triage") if lookup_cache and provider != "local" else None
        if cached:
            st.session_state._triage_answer = cached
            st.session_state._triage_model = _triage_model
            _triage_answer = cached
            st.info("Cross-system triage loaded from cache.")
        else:
            # Check API key
            key_map = {"claude": "api_key", "gemini": "gemini_api_key", "openai": "openai_api_key",
                       "local": "local_ai_api_key"}
            api_key = getattr(st.session_state, key_map.get(provider, "api_key"), "")

            if not api_key and provider != "local":
                st.error(f"No {provider} API key configured. Set it in the sidebar.")
                return
            if provider == "local" and not api_key:
                api_key = "not-needed"

            prompt = build_cross_system_prompt(events)
            _triage_req = f"[SYSTEM]\n{prompt['system']}\n\n[USER]\n{prompt['user']}"
            est_tokens = estimate_tokens(prompt["system"] + prompt["user"])

            with st.status(f"Running cross-system triage with {_triage_model}...", expanded=True) as status:
                st.write(f"Estimated prompt: ~{est_tokens:,} tokens")

                try:
                    if provider == "claude":
                        answer, usage = call_claude_api(api_key, model_id, prompt)
                    elif provider == "gemini":
                        answer, usage = call_gemini_api(api_key, model_id, prompt)
                    elif provider == "openai":
                        answer, usage = call_openai_api(api_key, model_id, prompt)
                    elif provider == "local":
                        answer, usage = call_local_api(api_key, model_id, prompt)
                    else:
                        st.error(f"Unsupported provider: {provider}")
                        return

                    st.session_state._triage_answer = answer
                    st.session_state._triage_model = _triage_model
                    _triage_answer = answer
                    _log_probe("Triage", provider, model_id, _triage_req, answer or "")

                    # Store in cache (skip local — model changes frequently)
                    if store_cache and answer and provider != "local":
                        store_cache(_cache_key, answer, _session_cache)

                    # Track spend
                    if usage:
                        inp = usage.get("input", 0)
                        out = usage.get("output", 0)
                        cache_c = usage.get("cache_creation", 0)
                        cache_r = usage.get("cache_read", 0)
                        cost = estimate_cost(model_id, inp, out)
                        from app_spend import record_spend
                        record_spend(provider, model_id, inp, out, source="triage",
                                     cache_creation=cache_c, cache_read=cache_r)
                        st.caption(f"Triage: {inp:,} in + {out:,} out tokens — estimated cost **${cost:.4f}**")

                    status.update(label="Triage complete!", state="complete")

                    if log:
                        log.info("triage Cross-system triage complete (%s)", model_id)
                except Exception as ex:
                    _log_probe("Triage", provider, model_id, _triage_req, "", error=str(ex))
                    status.update(label="Triage failed", state="error")
                    st.error(f"AI call failed: {_sanitize_error(str(ex))}")
                    if log:
                        log.error("triage Cross-system triage failed: %s", _sanitize_error(str(ex)))
                    return

    if _triage_answer:
        _model_label = st.session_state.get("_triage_model", "AI")
        st.markdown(f"**Cross-System Triage** ({_model_label}):")
        st.markdown(_triage_answer)


def call_ai_provider(provider: str, model_id: str, prompt: dict,
                     max_tokens: int = 4096) -> tuple[str | None, dict]:
    """Dispatch an AI call to the correct provider. Returns (text, usage)."""
    if provider != "local" and provider not in _AVAILABLE_PROVIDERS:
        _pkg = {"claude": "anthropic", "gemini": "google-generativeai", "openai": "openai"}.get(provider, provider)
        raise ImportError(f"Provider '{provider}' requires `pip install {_pkg}`")
    if provider == "claude":
        return call_claude_api(
            st.session_state.get("api_key", ""), model_id, prompt, max_tokens=max_tokens)
    elif provider == "gemini":
        return call_gemini_api(
            st.session_state.get("gemini_api_key", ""), model_id, prompt, max_tokens=max_tokens)
    elif provider == "openai":
        return call_openai_api(
            st.session_state.get("openai_api_key", "") or "not-needed",
            model_id, prompt, max_tokens=max_tokens)
    elif provider == "local":
        _local_url = getattr(st.session_state, "local_ai_endpoint", "") or None
        return call_local_api(
            "not-needed", model_id, prompt, max_tokens=max_tokens, base_url=_local_url)
    return (None, {})
