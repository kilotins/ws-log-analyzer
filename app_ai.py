"""AI provider orchestration module for the Streamlit GUI."""
from __future__ import annotations

import streamlit as st
from datetime import datetime

from logpilot import (
    match_user_query, build_claude_prompt, claude_cache_key, triage_cache_key,
    ask_gemini,
    estimate_tokens, TOKEN_LIMITS,
    _FORMAT_PLACEHOLDER,
)
from app_constants import AI_RATE_LIMIT_SECONDS


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


# Approximate cost per 1M tokens (input, output) in USD
TOKEN_COSTS = {
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5-20251001": (0.80, 4.00),
    "claude-opus-4-6": (15.00, 75.00),
    "gemini-2.5-flash": (0.15, 0.60),
    "gemini-2.5-pro": (1.25, 10.00),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "o3": (10.00, 40.00),
    "o4-mini": (1.10, 4.40),
}

# Cache token pricing per 1M tokens (cache_write, cache_read) in USD
# cache_write = cost to create cached content, cache_read = cost to read from cache
CACHE_TOKEN_COSTS = {
    "claude-sonnet-4-6": (3.75, 0.30),
    "claude-haiku-4-5-20251001": (1.00, 0.08),
    "claude-opus-4-6": (18.75, 1.50),
}


AI_MODELS = {
    "Claude Sonnet 4.6": {"provider": "claude", "model_id": "claude-sonnet-4-6"},
    "Claude Haiku 4.5": {"provider": "claude", "model_id": "claude-haiku-4-5-20251001"},
    "Gemini 2.5 Flash": {"provider": "gemini", "model_id": "gemini-2.5-flash"},
    "Gemini 2.5 Pro": {"provider": "gemini", "model_id": "gemini-2.5-pro"},
    "GPT-4o": {"provider": "openai", "model_id": "gpt-4o"},
    "GPT-4o mini": {"provider": "openai", "model_id": "gpt-4o-mini"},
    "Local AI (custom)": {"provider": "local", "model_id": ""},
}

# Presets for local/inhouse AI servers
LOCAL_AI_PRESETS = {
    "LM Studio": {"base_url": "http://localhost:1234/v1", "api_key": "lm-studio"},
    "Ollama": {"base_url": "http://localhost:11434/v1", "api_key": "ollama"},
    "vLLM": {"base_url": "http://localhost:8000/v1", "api_key": "vllm"},
    "Custom": {"base_url": "", "api_key": ""},
}


def estimate_cost(model_id: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate cost in USD given model and token counts."""
    costs = TOKEN_COSTS.get(model_id, (0, 0))
    return (input_tokens * costs[0] + output_tokens * costs[1]) / 1_000_000


def call_claude_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None,
                    timeout: float = 120.0, max_tokens: int = 2048) -> tuple[str, dict]:
    """Make the actual Claude API call with optional streaming. Returns (answer, usage_dict)."""
    try:
        from anthropic import Anthropic
    except ImportError:
        raise ImportError("The `anthropic` package is not installed. Install with: `pip install anthropic`")
    client = Anthropic(api_key=api_key, timeout=timeout)

    if stream_placeholder:
        chunks = []
        with client.messages.stream(
            model=model_id, max_tokens=max_tokens,
            system=prompt["system"],
            messages=[{"role": "user", "content": prompt["user"]}],
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
        system=prompt["system"],
        messages=[{"role": "user", "content": prompt["user"]}],
    )
    if not message.content:
        return (None, {})
    usage = _extract_claude_usage(message.usage)
    return (message.content[0].text, usage)


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


def call_gemini_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None,
                    timeout: float = 120.0, max_tokens: int = 2048) -> tuple[str, dict]:
    """Make the actual Gemini API call. Returns (answer, usage_dict). Streaming not supported."""
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


def call_openai_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None,
                    timeout: float = 120.0, max_tokens: int = 2048) -> tuple[str, dict]:
    """Make the actual OpenAI API call with optional streaming. Returns (answer, usage_dict)."""
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("The `openai` package is not installed. Install with: `pip install openai`")
    client = OpenAI(api_key=api_key, timeout=timeout)

    if stream_placeholder:
        chunks = []
        response = client.chat.completions.create(
            model=model_id, max_completion_tokens=max_tokens, stream=True,
            stream_options={"include_usage": True},
            messages=[
                {"role": "system", "content": prompt["system"]},
                {"role": "user", "content": prompt["user"]},
            ],
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
        messages=[
            {"role": "system", "content": prompt["system"]},
            {"role": "user", "content": prompt["user"]},
        ],
    )
    answer = response.choices[0].message.content
    usage = {}
    if response.usage:
        usage = {"input": response.usage.prompt_tokens, "output": response.usage.completion_tokens}
    return (answer or None, usage)


def call_local_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None,
                    timeout: float = 120.0, max_tokens: int = 2048,
                    base_url: str | None = None) -> tuple[str, dict]:
    """Call a local/inhouse OpenAI-compatible API (LM Studio, Ollama, vLLM, etc.).

    Uses the OpenAI SDK with a custom base_url. The api_key can be any
    non-empty string for servers that don't require authentication.
    """
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("The `openai` package is not installed. Install with: `pip install openai`")

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

    # Local servers often don't need a real API key
    client = OpenAI(api_key=api_key or "not-needed", base_url=base_url, timeout=timeout)

    if stream_placeholder:
        chunks = []
        response = client.chat.completions.create(
            model=model_id, max_completion_tokens=max_tokens, stream=True,
            messages=[
                {"role": "system", "content": prompt["system"]},
                {"role": "user", "content": prompt["user"]},
            ],
        )
        usage = {}
        for chunk in response:
            if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                chunks.append(chunk.choices[0].delta.content)
                stream_placeholder.markdown("".join(chunks) + "\n\n*Streaming...*")
            if hasattr(chunk, "usage") and chunk.usage:
                usage = {"input": chunk.usage.prompt_tokens, "output": chunk.usage.completion_tokens}
        answer = "".join(chunks)
        return (answer or None, usage)

    response = client.chat.completions.create(
        model=model_id, max_completion_tokens=max_tokens,
        messages=[
            {"role": "system", "content": prompt["system"]},
            {"role": "user", "content": prompt["user"]},
        ],
    )
    answer = response.choices[0].message.content
    usage = {}
    if response.usage:
        usage = {"input": response.usage.prompt_tokens, "output": response.usage.completion_tokens}
    return (answer or None, usage)


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
    formats = Counter(e.get("format", "") for e in events if e.get("format"))
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
    if lookup_cache:
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

    if st.session_state.debug_payload:
        with st.expander(f"{label} request payload", expanded=False):
            import json as _json
            st.code(f"[SYSTEM]\n{prompt['system']}\n\n[USER]\n{prompt['user']}", language="text")

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
            return
        if log:
            log.info("%s %s response received (%d chars) for: %s",
                     provider, label, len(answer), user_query[:60])
        if st.session_state.debug_payload:
            with st.expander(f"{label} response payload", expanded=False):
                st.code(answer, language="markdown")
        stream_placeholder.empty()  # clear streaming display
        _record_answer(answer)
        if store_cache:
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
    except Exception as ex:
        if log:
            log.error("%s %s API error: %s", provider, label, ex)
        if st.session_state.debug_payload:
            with st.expander(f"{label} error details", expanded=True):
                st.code(str(ex), language="text")
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
    """Render AI response with prose and fenced code blocks.

    Uses a line-by-line state-machine parser that handles nested fences correctly.
    """
    lines = text.split("\n")
    in_block = False
    fence_len = 0
    block_lang = ""
    block_lines = []
    prose_lines = []

    def _flush_prose():
        content = "\n".join(prose_lines).strip()
        if content:
            st.markdown(content)
        prose_lines.clear()

    def _flush_code(lang, code_text):
        code_text = code_text.strip()
        if not code_text:
            return
        st.code(code_text, language=lang or None)

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            tick_count = 0
            for ch in stripped:
                if ch == "`":
                    tick_count += 1
                else:
                    break

            if not in_block:
                _flush_prose()
                in_block = True
                fence_len = tick_count
                block_lang = stripped[tick_count:].strip().lower()
                block_lines = []
            elif tick_count >= fence_len:
                in_block = False
                _flush_code(block_lang, "\n".join(block_lines))
                block_lines = []
                block_lang = ""
                fence_len = 0
            else:
                block_lines.append(line)
        elif in_block:
            block_lines.append(line)
        else:
            prose_lines.append(line)

    # Flush remaining prose or unclosed code block
    if in_block and block_lines:
        _flush_code(block_lang, "\n".join(block_lines))
    _flush_prose()


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


def render_ai_responses():
    """Render current AI analyses and history outside expanders for proper scrolling."""
    render_current_ai_analyses()
    render_ai_history()


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
    sources = set(e.get("system_label", "") for e in events)
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
        cached = lookup_cache(_cache_key, _session_cache, f"triage/{provider}", "cross-system triage") if lookup_cache else None
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

                    # Store in cache
                    if store_cache and answer:
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
                    status.update(label="Triage failed", state="error")
                    st.error(f"AI call failed: {ex}")
                    if log:
                        log.error("triage Cross-system triage failed: %s", ex)
                    return

    if _triage_answer:
        _model_label = st.session_state.get("_triage_model", "AI")
        st.markdown(f"**Cross-System Triage** ({_model_label}):")
        st.markdown(_triage_answer)
