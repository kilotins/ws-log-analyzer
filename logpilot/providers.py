"""Pure provider call functions. Streamlit-free, callable from any context.

In 2.0 these will move to core/ai/providers/{claude,gemini,openai,local}.py
with one file per provider. For 1.x → 1.5.3, we keep them as siblings here
to minimize churn.

All functions accept explicit parameters — no st.session_state, no global
side effects. Retry logic, rate limiting, probe logging, and UI feedback
stay in app_ai.py (the Streamlit orchestration layer).
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field

_log = logging.getLogger(__name__)

# HTTP status codes that should NOT be retried (auth/client errors)
_NO_RETRY_STATUS = frozenset({400, 401, 403, 404})

# Transient HTTP status codes that warrant a retry
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


@dataclass
class ProviderResult:
    """Result from a pure provider call."""
    answer: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0
    cost_usd: float = 0.0
    error: str | None = None

    @classmethod
    def from_error(cls, error: str) -> "ProviderResult":
        """Convenience constructor for error results."""
        return cls(answer="", error=error)

    @classmethod
    def from_usage(cls, answer: str, usage: dict) -> "ProviderResult":
        """Construct from a (answer, usage_dict) pair as returned by app_ai impl functions."""
        return cls(
            answer=answer or "",
            input_tokens=usage.get("input", 0),
            output_tokens=usage.get("output", 0),
            cache_creation_tokens=usage.get("cache_creation", 0),
            cache_read_tokens=usage.get("cache_read", 0),
        )


def _should_retry(exc: Exception) -> bool:
    """Return True if *exc* represents a transient error worth retrying."""
    import socket
    if isinstance(exc, (TimeoutError, ConnectionError, OSError, socket.timeout)):
        return True
    try:
        import urllib.error
        if isinstance(exc, urllib.error.URLError):
            return True
    except ImportError:
        pass
    status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
    if status is None:
        resp = getattr(exc, "response", None)
        if resp is not None:
            status = getattr(resp, "status_code", None)
    if status in _NO_RETRY_STATUS:
        return False
    if status in _RETRY_STATUS:
        return True
    cls_name = type(exc).__name__
    if any(k in cls_name for k in ("Timeout", "Connection", "RateLimit", "APIStatusError", "ServiceUnavailable")):
        if status in _NO_RETRY_STATUS:
            return False
        return True
    return False


def _with_retries(func, *args, max_retries: int = 3, **kwargs):
    """Call *func* with exponential backoff on transient errors.

    Retries up to *max_retries* times. Backoff delays: 1s, 2s, 4s, ...
    Auth errors (401/403) and client errors (400/404) are re-raised immediately.
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
                delay = 2 ** (attempt - 1)
                _log.warning(
                    "AI API transient error (attempt %d/%d), retrying in %ds: %s",
                    attempt, max_retries, delay, exc,
                )
                time.sleep(delay)
            else:
                _log.error("AI API call failed after %d attempts: %s", max_retries, exc)
    raise last_exc


# ---------------------------------------------------------------------------
# Claude
# ---------------------------------------------------------------------------

def _extract_claude_usage(usage) -> dict:
    """Extract token usage from a Claude API response object."""
    if not usage:
        return {}
    return {
        "input": getattr(usage, "input_tokens", 0) or 0,
        "output": getattr(usage, "output_tokens", 0) or 0,
        "cache_creation": getattr(usage, "cache_creation_input_tokens", 0) or 0,
        "cache_read": getattr(usage, "cache_read_input_tokens", 0) or 0,
    }


def _call_claude_impl(
    api_key: str,
    model: str,
    prompt: dict,
    stream_placeholder=None,
    timeout: float = 120.0,
    max_tokens: int = 2048,
    images: list[dict] | None = None,
) -> tuple[str | None, dict]:
    """Raw Claude API call — no retry, no Streamlit."""
    try:
        from anthropic import Anthropic
    except ImportError:
        raise ImportError(
            "The `anthropic` package is not installed. "
            "Install with: `pip install anthropic`"
        )
    client = Anthropic(api_key=api_key, timeout=timeout)

    if images:
        user_content: list[dict] = []
        for img in images:
            user_content.append({
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": img["media_type"],
                    "data": img["data"],
                },
            })
        user_content.append({"type": "text", "text": prompt.get("user", "")})
    else:
        user_content = prompt.get("user", "")

    if "messages" in prompt:
        messages = prompt["messages"]
    else:
        messages = [{"role": "user", "content": user_content}]

    if stream_placeholder:
        chunks = []
        with client.messages.stream(
            model=model,
            max_tokens=max_tokens,
            system=[{
                "type": "text",
                "text": prompt["system"],
                "cache_control": {"type": "ephemeral"},
            }],
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
        model=model,
        max_tokens=max_tokens,
        system=[{
            "type": "text",
            "text": prompt["system"],
            "cache_control": {"type": "ephemeral"},
        }],
        messages=messages,
    )
    if not message.content:
        return (None, {})
    usage = _extract_claude_usage(message.usage)
    return (message.content[0].text, usage)


def call_claude_pure(
    api_key: str,
    model: str,
    prompt: dict,
    stream_placeholder=None,
    timeout: float = 120.0,
    max_tokens: int = 2048,
    images: list[dict] | None = None,
    max_retries: int = 3,
) -> ProviderResult:
    """Pure Claude API call with retry. No Streamlit, no rate-limit state.

    Args:
        api_key: Anthropic API key (sk-ant-...).
        model: Model ID (e.g. "claude-sonnet-4-6").
        prompt: Dict with "system" and "user" keys (and optionally "messages").
        stream_placeholder: Optional Streamlit placeholder for streaming display.
        timeout: HTTP timeout in seconds.
        max_tokens: Maximum output tokens.
        images: Optional list of {"media_type": ..., "data": <base64>} dicts.
        max_retries: Retry count on transient errors.

    Returns:
        ProviderResult with answer/tokens or error string.
    """
    try:
        answer, usage = _with_retries(
            _call_claude_impl,
            api_key, model, prompt,
            stream_placeholder=stream_placeholder,
            timeout=timeout,
            max_tokens=max_tokens,
            images=images,
            max_retries=max_retries,
        )
        return ProviderResult.from_usage(answer or "", usage)
    except Exception as exc:
        return ProviderResult.from_error(str(exc))


# ---------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------

def _call_gemini_impl(
    api_key: str,
    model: str,
    prompt: dict,
    stream_placeholder=None,
    timeout: float = 120.0,
    max_tokens: int = 2048,
    images: list[dict] | None = None,
) -> tuple[str | None, dict]:
    """Raw Gemini API call — no retry, no Streamlit."""
    from logpilot.ai import ask_gemini, estimate_tokens

    key = api_key or os.environ.get("GEMINI_API_KEY", "")

    if images or "messages" in prompt:
        if not key:
            raise ValueError("GEMINI_API_KEY is not set.")
        try:
            from google import genai
            from google.genai import types as genai_types
            import base64 as _base64
        except ImportError:
            raise ImportError(
                "The `google-genai` package is not installed. "
                "Install with: pip install google-genai"
            )
        client = genai.Client(api_key=key)
        content_parts: list = []
        if images:
            for img in images:
                content_parts.append(genai_types.Part(
                    inline_data=genai_types.Blob(
                        mime_type=img["media_type"],
                        data=_base64.b64decode(img["data"]),
                    )
                ))
            content_parts.append(prompt.get("user", ""))
        else:
            msg = prompt["messages"][0]
            for p in msg.get("parts", []):
                if "inline_data" in p:
                    content_parts.append(genai_types.Part(
                        inline_data=genai_types.Blob(
                            mime_type=p["inline_data"]["mime_type"],
                            data=_base64.b64decode(p["inline_data"]["data"]),
                        )
                    ))
                elif "text" in p:
                    content_parts.append(p["text"])
        config = genai_types.GenerateContentConfig(
            system_instruction=prompt.get("system"),
            http_options=genai_types.HttpOptions(timeout=int(timeout * 1000)),
        )
        response = client.models.generate_content(
            model=model,
            contents=content_parts or prompt.get("user", ""),
            config=config,
        )
        answer = response.text if response else None
    else:
        answer = ask_gemini(
            prompt["user"],
            api_key=api_key,
            system=prompt["system"],
            model=model,
            timeout=timeout,
        )

    usage = {}
    if answer:
        input_text = (prompt.get("system") or "") + (prompt.get("user") or "")
        usage = {
            "input": estimate_tokens(input_text),
            "output": estimate_tokens(answer),
        }
    return (answer or None, usage)


def call_gemini_pure(
    api_key: str,
    model: str,
    prompt: dict,
    stream_placeholder=None,
    timeout: float = 120.0,
    max_tokens: int = 2048,
    images: list[dict] | None = None,
    max_retries: int = 3,
) -> ProviderResult:
    """Pure Gemini API call with retry. No Streamlit, no rate-limit state.

    Args:
        api_key: Google Gemini API key (or "" to fall back to GEMINI_API_KEY env var).
        model: Model ID (e.g. "gemini-2.5-flash").
        prompt: Dict with "system" and "user" keys (and optionally "messages").
        stream_placeholder: Ignored — Gemini streaming not implemented.
        timeout: HTTP timeout in seconds.
        max_tokens: Maximum output tokens (advisory; Gemini uses its own limit).
        images: Optional list of {"media_type": ..., "data": <base64>} dicts.
        max_retries: Retry count on transient errors.

    Returns:
        ProviderResult with answer/tokens or error string.
    """
    try:
        answer, usage = _with_retries(
            _call_gemini_impl,
            api_key, model, prompt,
            stream_placeholder=stream_placeholder,
            timeout=timeout,
            max_tokens=max_tokens,
            images=images,
            max_retries=max_retries,
        )
        return ProviderResult.from_usage(answer or "", usage)
    except Exception as exc:
        return ProviderResult.from_error(str(exc))


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------

def _call_openai_impl(
    api_key: str,
    model: str,
    prompt: dict,
    stream_placeholder=None,
    timeout: float = 120.0,
    max_tokens: int = 2048,
    images: list[dict] | None = None,
    base_url: str | None = None,
) -> tuple[str | None, dict]:
    """Raw OpenAI API call — no retry, no Streamlit."""
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError(
            "The `openai` package is not installed. "
            "Install with: `pip install openai`"
        )

    client_kwargs: dict = {"api_key": api_key or "not-needed", "timeout": timeout}
    if base_url:
        client_kwargs["base_url"] = base_url
    client = OpenAI(**client_kwargs)

    if "messages" in prompt:
        messages_list = [{"role": "system", "content": prompt["system"]}]
        messages_list.extend(prompt["messages"])
    elif images:
        user_content_parts: list[dict] = []
        for img in images:
            user_content_parts.append({
                "type": "image_url",
                "image_url": {"url": f"data:{img['media_type']};base64,{img['data']}"},
            })
        user_content_parts.append({"type": "text", "text": prompt.get("user", "")})
        messages_list = [
            {"role": "system", "content": prompt["system"]},
            {"role": "user", "content": user_content_parts},
        ]
    else:
        messages_list = [
            {"role": "system", "content": prompt["system"]},
            {"role": "user", "content": prompt.get("user", "")},
        ]

    if stream_placeholder:
        chunks = []
        response = client.chat.completions.create(
            model=model,
            max_completion_tokens=max_tokens,
            stream=True,
            stream_options={"include_usage": True},
            messages=messages_list,
        )
        usage = {}
        for chunk in response:
            if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                chunks.append(chunk.choices[0].delta.content)
                stream_placeholder.markdown("".join(chunks) + "\n\n*Streaming...*")
            if chunk.usage:
                usage = {
                    "input": chunk.usage.prompt_tokens,
                    "output": chunk.usage.completion_tokens,
                }
        answer = "".join(chunks)
        return (answer or None, usage)

    response = client.chat.completions.create(
        model=model,
        max_completion_tokens=max_tokens,
        messages=messages_list,
    )
    answer = response.choices[0].message.content
    usage = {}
    if response.usage:
        usage = {
            "input": response.usage.prompt_tokens,
            "output": response.usage.completion_tokens,
        }
    return (answer or None, usage)


def call_openai_pure(
    api_key: str,
    model: str,
    prompt: dict,
    stream_placeholder=None,
    timeout: float = 120.0,
    max_tokens: int = 2048,
    images: list[dict] | None = None,
    base_url: str | None = None,
    max_retries: int = 3,
) -> ProviderResult:
    """Pure OpenAI API call with retry. No Streamlit, no rate-limit state.

    Args:
        api_key: OpenAI API key (sk-...).
        model: Model ID (e.g. "gpt-4o").
        prompt: Dict with "system" and "user" keys (and optionally "messages").
        stream_placeholder: Optional Streamlit placeholder for streaming display.
        timeout: HTTP timeout in seconds.
        max_tokens: Maximum output tokens.
        images: Optional list of {"media_type": ..., "data": <base64>} dicts.
        base_url: Optional base URL for OpenAI-compatible servers.
        max_retries: Retry count on transient errors.

    Returns:
        ProviderResult with answer/tokens or error string.
    """
    try:
        answer, usage = _with_retries(
            _call_openai_impl,
            api_key, model, prompt,
            stream_placeholder=stream_placeholder,
            timeout=timeout,
            max_tokens=max_tokens,
            images=images,
            base_url=base_url,
            max_retries=max_retries,
        )
        return ProviderResult.from_usage(answer or "", usage)
    except Exception as exc:
        return ProviderResult.from_error(str(exc))


# ---------------------------------------------------------------------------
# Local AI (OpenAI-compatible)
# ---------------------------------------------------------------------------

def call_local_pure(
    endpoint: str,
    model: str,
    prompt: dict,
    api_key: str = "not-needed",
    stream_placeholder=None,
    timeout: float = 120.0,
    max_tokens: int = 2048,
    images: list[dict] | None = None,
    max_retries: int = 3,
) -> ProviderResult:
    """Pure local/inhouse OpenAI-compatible API call with retry.

    Uses the OpenAI SDK with a custom base_url. Caller is responsible for
    resolving endpoint and model from environment or config — no st.session_state.

    Args:
        endpoint: Base URL of the local server (e.g. "http://localhost:1234/v1").
        model: Model ID. Pass "" or "default" if the server has only one model.
        prompt: Dict with "system" and "user" keys.
        api_key: API key; defaults to "not-needed" for servers without auth.
        stream_placeholder: Optional Streamlit placeholder for streaming display.
        timeout: HTTP timeout in seconds.
        max_tokens: Maximum output tokens.
        images: Optional multimodal image list.
        max_retries: Retry count on transient errors.

    Returns:
        ProviderResult with answer/tokens or error string.
    """
    resolved_endpoint = endpoint or os.environ.get("LOGPILOT_AI_ENDPOINT", "http://localhost:1234/v1")
    resolved_model = model or os.environ.get("LOGPILOT_AI_MODEL", "default")

    # Sanitize API key
    if api_key and api_key != "not-needed":
        api_key = api_key.strip()
        try:
            api_key.encode("ascii")
        except UnicodeEncodeError:
            return ProviderResult.from_error(
                "API key contains invalid characters (non-ASCII). "
                "Re-copy the key from your server settings."
            )

    return call_openai_pure(
        api_key=api_key or "not-needed",
        model=resolved_model,
        prompt=prompt,
        stream_placeholder=stream_placeholder,
        timeout=timeout,
        max_tokens=max_tokens,
        images=images,
        base_url=resolved_endpoint,
        max_retries=max_retries,
    )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def call_provider_pure(
    provider: str,
    api_key: str,
    model: str,
    prompt: dict,
    **kwargs,
) -> ProviderResult:
    """Dispatch to the correct pure provider function.

    Pure version of app_ai.call_ai_provider — no Streamlit, no session state.

    Args:
        provider: One of "claude", "gemini", "openai", "local".
        api_key: API key or endpoint URL (for local, pass as api_key or use
                 the ``endpoint`` kwarg).
        model: Model identifier string.
        prompt: Dict with "system" and "user" keys.
        **kwargs: Forwarded to the specific provider function
                  (timeout, max_tokens, images, base_url, max_retries, etc.).

    Returns:
        ProviderResult with answer/tokens or error string.
    """
    if provider == "claude":
        return call_claude_pure(api_key, model, prompt, **kwargs)
    elif provider == "gemini":
        return call_gemini_pure(api_key, model, prompt, **kwargs)
    elif provider == "openai":
        return call_openai_pure(api_key, model, prompt, **kwargs)
    elif provider == "local":
        # For local, api_key may be the auth token; endpoint should be in kwargs
        endpoint = kwargs.pop("endpoint", kwargs.pop("base_url", api_key))
        # If endpoint looks like an API key (no http), use it as api_key
        if endpoint and not endpoint.startswith("http"):
            endpoint = os.environ.get("LOGPILOT_AI_ENDPOINT", "http://localhost:1234/v1")
        return call_local_pure(endpoint=endpoint, model=model, prompt=prompt,
                               api_key=api_key, **kwargs)
    else:
        return ProviderResult.from_error(f"Unknown provider: {provider}")
