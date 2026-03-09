"""AI provider orchestration module for the Streamlit GUI."""
from __future__ import annotations

import re as _re
import streamlit as st
from datetime import datetime
from pathlib import Path

from wslog import (
    match_user_query, build_claude_prompt, claude_cache_key,
    SWEDISH_CHEF_STYLE, ask_gemini,
    estimate_tokens, TOKEN_LIMITS,
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
        "extract_splunk": True,
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
        "extract_splunk": False,
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
        "extract_splunk": False,
        "api_key_error": "Enter your OpenAI API key in the sidebar or set OPENAI_API_KEY env var.",
        "api_key_prefix": "sk-",
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
    "gemini-2.5-flash-preview-05-20": (0.15, 0.60),
    "gemini-2.5-pro-preview-06-05": (1.25, 10.00),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "o3": (10.00, 40.00),
    "o4-mini": (1.10, 4.40),
}


AI_MODELS = {
    "Claude Sonnet 4.6": {"provider": "claude", "model_id": "claude-sonnet-4-6"},
    "Claude Haiku 4.5": {"provider": "claude", "model_id": "claude-haiku-4-5-20251001"},
    "Gemini 2.5 Flash": {"provider": "gemini", "model_id": "gemini-2.5-flash"},
    "Gemini 2.5 Pro": {"provider": "gemini", "model_id": "gemini-2.5-pro-preview-06-05"},
    "GPT-4o": {"provider": "openai", "model_id": "gpt-4o"},
    "GPT-4o mini": {"provider": "openai", "model_id": "gpt-4o-mini"},
    "Swedish Chef": {"provider": "openai_chef", "model_id": "gpt-4o-mini"},
}


def estimate_cost(model_id: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate cost in USD given model and token counts."""
    costs = TOKEN_COSTS.get(model_id, (0, 0))
    return (input_tokens * costs[0] + output_tokens * costs[1]) / 1_000_000


def call_claude_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None) -> tuple[str, dict]:
    """Make the actual Claude API call with optional streaming. Returns (answer, usage_dict)."""
    try:
        from anthropic import Anthropic
    except ImportError:
        raise ImportError("The `anthropic` package is not installed. Install with: `pip install anthropic`")
    client = Anthropic(api_key=api_key, timeout=120.0)

    if stream_placeholder:
        chunks = []
        with client.messages.stream(
            model=model_id, max_tokens=2048,
            system=prompt["system"],
            messages=[{"role": "user", "content": prompt["user"]}],
        ) as stream:
            for text in stream.text_stream:
                chunks.append(text)
                stream_placeholder.markdown("".join(chunks) + "...")
            final = stream.get_final_message()
        answer = "".join(chunks)
        usage = {"input": final.usage.input_tokens, "output": final.usage.output_tokens} if final and final.usage else {}
        return (answer or None, usage)

    message = client.messages.create(
        model=model_id, max_tokens=2048,
        system=prompt["system"],
        messages=[{"role": "user", "content": prompt["user"]}],
    )
    if not message.content:
        return (None, {})
    usage = {"input": message.usage.input_tokens, "output": message.usage.output_tokens} if message.usage else {}
    return (message.content[0].text, usage)


def call_gemini_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None) -> tuple[str, dict]:
    """Make the actual Gemini API call. Returns (answer, usage_dict). Streaming not supported."""
    answer = ask_gemini(prompt["user"], api_key=api_key, system=prompt["system"], model=model_id)
    # Gemini SDK doesn't return token usage, so estimate from prompt/response text
    usage = {}
    if answer:
        input_text = (prompt.get("system") or "") + (prompt.get("user") or "")
        usage = {
            "input": estimate_tokens(input_text),
            "output": estimate_tokens(answer),
        }
    return (answer or None, usage)


def call_openai_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None) -> tuple[str, dict]:
    """Make the actual OpenAI API call with optional streaming. Returns (answer, usage_dict)."""
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("The `openai` package is not installed. Install with: `pip install openai`")
    client = OpenAI(api_key=api_key, timeout=120.0)

    if stream_placeholder:
        chunks = []
        response = client.chat.completions.create(
            model=model_id, max_completion_tokens=2048, stream=True,
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
                stream_placeholder.markdown("".join(chunks) + "...")
            if chunk.usage:
                usage = {"input": chunk.usage.prompt_tokens, "output": chunk.usage.completion_tokens}
        answer = "".join(chunks)
        return (answer or None, usage)

    response = client.chat.completions.create(
        model=model_id, max_completion_tokens=2048,
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
}



def build_ai_request_context(user_query: str, events: list[dict], provider: str = "claude", log=None) -> dict:
    """Compute match, cache key, and prompt for an AI analysis request."""
    match = match_user_query(user_query, events)
    cache_key = claude_cache_key(user_query, match)
    if st.session_state.swedish_chef:
        cache_key += ":swedish_chef"
    if provider == "gemini":
        cache_key = "gemini:" + cache_key
    elif provider == "openai":
        cache_key = "openai:" + cache_key
    style = SWEDISH_CHEF_STYLE if st.session_state.swedish_chef else None
    prompt = build_claude_prompt(user_query, match, style=style)
    skills = prompt.get("skills", [])
    if skills and log:
        log.info("skills %s selected skills: %s", provider, ", ".join(skills))
    return match, cache_key, prompt


def extract_splunk_from_response(text):
    """Extract Splunk queries from a Claude response.

    Uses a line-by-line state-machine parser that handles nested fences
    and inline backticks correctly.

    Returns list of {description, query} dicts.
    """
    from app_render import _looks_like_splunk, _split_combined_splunk

    results = []
    lines = text.split("\n")
    in_block = False
    fence_len = 0  # backtick length of the opening fence
    block_lang = ""
    block_lines = []
    preceding_text = []  # non-code lines before the current block

    for line in lines:
        stripped = line.strip()
        # Check if this line is a fence (3+ backticks at start)
        if stripped.startswith("```"):
            tick_count = 0
            for ch in stripped:
                if ch == "`":
                    tick_count += 1
                else:
                    break

            if not in_block:
                # Opening fence
                in_block = True
                fence_len = tick_count
                block_lang = stripped[tick_count:].strip().lower()
                block_lines = []
            elif tick_count >= fence_len:
                # Closing fence (must be at least as long as opening)
                in_block = False
                code = "\n".join(block_lines).strip()
                if block_lang in ("spl", "splunk", "") and code and _looks_like_splunk(code):
                    split = _split_combined_splunk(code)
                    if len(split) > 1:
                        results.extend(split)
                    else:
                        # Use preceding text as description
                        desc = ""
                        for prev_line in reversed(preceding_text):
                            candidate = prev_line.strip().strip("*").strip("#").strip()
                            if candidate:
                                desc = candidate
                                break
                        results.append({"description": desc or "Splunk query", "query": code})
                block_lines = []
                block_lang = ""
                fence_len = 0
                preceding_text = []
            else:
                # Nested fence (shorter than opening) — treat as content
                block_lines.append(line)
        elif in_block:
            block_lines.append(line)
        else:
            preceding_text.append(line)

    # If a code block was never closed, still check its content
    if in_block and block_lines:
        code = "\n".join(block_lines).strip()
        if block_lang in ("spl", "splunk", "") and code and _looks_like_splunk(code):
            split = _split_combined_splunk(code)
            if len(split) > 1:
                results.extend(split)
            else:
                desc = ""
                for prev_line in reversed(preceding_text):
                    candidate = prev_line.strip().strip("*").strip("#").strip()
                    if candidate:
                        desc = candidate
                        break
                results.append({"description": desc or "Splunk query", "query": code})

    return results


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
        if cfg["extract_splunk"]:
            entry["splunk_queries"] = extract_splunk_from_response(answer)
        hist = getattr(st.session_state, cfg["history_key"])
        if not any(h["query"] == user_query and h["answer"] == answer for h in hist):
            hist.append(entry)
            cfg["save_history"](hist)

    if cached:
        _record_answer(cached)
        status.update(label=f"Using cached {label} response", state="complete")
        return

    if match["matched"]:
        status.write(f"Found {len(match['matching_events'])} matching event(s) "
                     f"(match type: {match['match_type']})")
    else:
        status.write(f"No exact match -- sending general question to {label}.")

    api_key = getattr(st.session_state, cfg["api_key_field"], "")
    if not api_key:
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
    status.write(f"Calling {label} API...")
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
            cost = estimate_cost(model_id, inp, out)
            cost_info = f" -- {inp:,}+{out:,} tokens (~${cost:.4f})"
            if log:
                log.info("%s tokens: %d in / %d out, est cost: $%.4f", label, inp, out, cost)
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


# --- Chef sound/image helpers ---
_APP_DIR = Path(__file__).parent
_CHEF_SOUNDS_DIR = _APP_DIR / "assets" / "chef"
_CHEF_IMAGE = _APP_DIR / "assets" / "chef" / "The_Swedish_Chef.jpg"


def _get_all_chef_sounds_b64():
    """Return all Chef sound clips as a list of base64 data URIs."""
    import base64
    if not _CHEF_SOUNDS_DIR.is_dir():
        return []
    clips = sorted(_CHEF_SOUNDS_DIR.glob("*.mp3"))
    results = []
    for clip in clips:
        data = clip.read_bytes()
        b64 = base64.b64encode(data).decode()
        results.append(f"data:audio/mpeg;base64,{b64}")
    return results


def _get_chef_image_b64():
    """Return the Chef image as a base64 data URI, or None."""
    import base64
    if not _CHEF_IMAGE.is_file():
        return None
    data = _CHEF_IMAGE.read_bytes()
    ext = _CHEF_IMAGE.suffix.lower().lstrip(".")
    mime = {"jpg": "jpeg", "jpeg": "jpeg", "png": "png", "gif": "gif", "webp": "webp"}.get(ext, "jpeg")
    b64 = base64.b64encode(data).decode()
    return f"data:image/{mime};base64,{b64}"


def _render_chef_sound_button():
    """Render a clickable Swedish Chef image that plays a random sound clip."""
    chef_img = _get_chef_image_b64()
    chef_sounds = _get_all_chef_sounds_b64()
    if not chef_img or not chef_sounds:
        return

    import json as _json
    sounds_js = _json.dumps(chef_sounds)

    import streamlit.components.v1 as components
    components.html(f"""
    <div style="display:inline-block">
      <button id="chef-btn" onclick="playChef()" title="Bork bork bork!"
        style="background:none;border:2px solid #555;border-radius:12px;
               padding:6px;cursor:pointer;transition:all 0.3s;
               display:flex;align-items:center;gap:8px">
        <img id="chef-img" src="{chef_img}"
             style="width:60px;height:60px;border-radius:8px;object-fit:cover;
                    transition:transform 0.3s"
             onmouseover="this.style.transform='scale(1.1) rotate(-5deg)'"
             onmouseout="if(!playing)this.style.transform='scale(1)'" />
        <span style="font-size:13px;color:inherit;text-align:left;line-height:1.3"
              id="chef-label">Let zee Chef<br>explain zee problem!</span>
      </button>
    </div>
    <script>
      const chefSounds = {sounds_js};
      let playing = false;
      let currentAudio = null;
      let lastIdx = -1;
      function playChef() {{
        if (playing && currentAudio) {{
          currentAudio.pause();
          currentAudio = null;
          playing = false;
          document.getElementById('chef-img').style.transform = 'scale(1)';
          document.getElementById('chef-label').innerHTML = 'Let zee Chef<br>explain zee problem!';
          document.getElementById('chef-btn').style.borderColor = '#555';
          return;
        }}
        let idx = Math.floor(Math.random() * chefSounds.length);
        if (chefSounds.length > 1 && idx === lastIdx) {{
          idx = (idx + 1) % chefSounds.length;
        }}
        lastIdx = idx;
        const audio = new Audio(chefSounds[idx]);
        audio.volume = 0.7;
        currentAudio = audio;
        playing = true;
        document.getElementById('chef-img').style.transform = 'scale(1.1) rotate(-5deg)';
        document.getElementById('chef-label').innerHTML = 'Bork bork bork!<br><small>Click to stop</small>';
        document.getElementById('chef-btn').style.borderColor = '#dc3545';
        audio.onended = () => {{
          playing = false;
          currentAudio = null;
          document.getElementById('chef-img').style.transform = 'scale(1)';
          document.getElementById('chef-label').innerHTML = 'Let zee Chef<br>explain zee problem!';
          document.getElementById('chef-btn').style.borderColor = '#555';
        }};
        audio.play();
      }}
    </script>
    """, height=85)


# --- AI response rendering ---

def _render_claude_response(text):
    """Render Claude response with separate copyable blocks for each Splunk query.

    Uses a line-by-line state-machine parser that handles nested fences correctly.
    """
    from app_render import _looks_like_splunk, _split_combined_splunk

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
        if lang in ("spl", "splunk", "") and _looks_like_splunk(code_text):
            queries = _split_combined_splunk(code_text)
            if len(queries) > 1:
                for sq in queries:
                    st.markdown(f"**{sq['description']}**")
                    st.code(sq["query"], language="spl")
            else:
                st.code(code_text, language="spl")
        else:
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
    """Render expanders for current Claude, Gemini, and GPT results."""
    _has_claude = bool(st.session_state.claude_answer)
    _has_gemini = bool(st.session_state.gemini_answer)
    _has_openai = bool(st.session_state.openai_answer)
    if not _has_claude and not _has_gemini and not _has_openai:
        return

    _count = sum([_has_claude, _has_gemini, _has_openai])
    _expand_claude = _has_claude and _count == 1
    _expand_gemini = _has_gemini and _count == 1
    _expand_openai = _has_openai and _count == 1
    if _count > 1:
        _expand_claude = False
        _expand_gemini = False
        _expand_openai = _has_openai

    st.markdown("---")
    st.subheader("Current AI analyses")

    if _has_claude:
        label = st.session_state.claude_query_label or "query"
        expander_title = f"\U0001f373 Zee Chef's analysis \u2014 {label}" if st.session_state.swedish_chef else f"Claude analysis \u2014 {label}"
        with st.expander(expander_title, expanded=_expand_claude):
            if st.session_state.swedish_chef:
                _render_chef_sound_button()
            _render_claude_response(st.session_state.claude_answer)

    if _has_gemini:
        label = st.session_state.gemini_query_label or "query"
        with st.expander(f"Gemini analysis \u2014 {label}", expanded=_expand_gemini):
            st.markdown(st.session_state.gemini_answer)

    if _has_openai:
        label = st.session_state.openai_query_label or "query"
        _chef_openai = st.session_state.swedish_chef
        expander_title = f"\U0001f373 Zee Chef's analysis \u2014 {label}" if _chef_openai else f"GPT analysis \u2014 {label}"
        with st.expander(expander_title, expanded=_expand_openai):
            if _chef_openai:
                _render_chef_sound_button()
            st.markdown(st.session_state.openai_answer)


def render_ai_history():
    """Render previous query history for Claude, Gemini, and GPT."""
    claude_history = st.session_state.claude_history
    if len(claude_history) > 1:
        st.markdown("---")
        if st.session_state.swedish_chef:
            st.subheader("Previoos queries from zee Chef")
        else:
            st.subheader("Previous Claude queries")
        for _, entry in enumerate(reversed(claude_history[:-1])):
            hist_label = f"Claude \u2014 {entry['query']} ({entry['timestamp']})"
            with st.expander(hist_label):
                if st.session_state.swedish_chef:
                    _render_chef_sound_button()
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
        _chef_hist = st.session_state.swedish_chef
        st.markdown("---")
        st.subheader("\U0001f373 Previ\u00f6oos Chef queries" if _chef_hist else "Previous GPT queries")
        for _, entry in enumerate(reversed(openai_history[:-1])):
            if _chef_hist:
                hist_label = f"\U0001f373 Zee Chef \u2014 {entry['query']} ({entry['timestamp']})"
            else:
                hist_label = f"GPT \u2014 {entry['query']} ({entry['timestamp']})"
            with st.expander(hist_label):
                if _chef_hist:
                    _render_chef_sound_button()
                st.markdown(entry["answer"])


def render_ai_responses():
    """Render current AI analyses and history outside expanders for proper scrolling."""
    render_current_ai_analyses()
    render_ai_history()


def render_ask_claude(events, log=None, lookup_cache=None, store_cache=None):
    """Render AI analysis input, API calls, and response history."""
    user_query = st.text_input(
        "Ask an AI assistant about an error code, exception, or troubleshooting question",
        placeholder="e.g. CWPKI0022E, SSLHandshakeException, why are threads hanging?",
        key="claude_query_input",
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
    _is_chef = _model_info.get("provider") == "openai_chef"
    st.session_state.swedish_chef = _is_chef

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
