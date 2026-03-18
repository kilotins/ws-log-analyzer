"""Unified AI analysis — symptom-driven debugging, error code lookup, and general questions.

Merges the former Ask AI and Incident Assistant into a single interface with:
- Query matching (codes, exceptions, tags → raw log excerpts)
- Domain skills (.md files) in the system prompt
- Full analysis context (summary, heuristics, timeline, cascades)
- Optional multimodal screenshot analysis
- Per-query history with clear button
"""
from __future__ import annotations

import base64
import hashlib
import time

import streamlit as st
from datetime import datetime

from logpilot import (
    build_incident_system_prompt, build_incident_user_prompt,
    incident_cache_key, estimate_tokens, TOKEN_LIMITS,
    match_user_query, select_skills, load_skill_content,
    triage_cache_key, per_source_summary,
)
from logpilot.ai import _FORMAT_PLACEHOLDER
from logpilot.analysis import ERROR_LEVELS
from app_ai import (
    AI_MODELS, PROVIDER_CONFIG, _API_CALLERS,
    _log_probe, detect_dominant_format, estimate_cost,
    _render_claude_response, clear_all_ai_history,
)
from app_constants import AI_RATE_LIMIT_SECONDS, MAX_SCREENSHOT_MB


_SUPPORTED_IMAGE_TYPES = ["png", "jpg", "jpeg", "gif", "webp"]


def _build_multimodal_messages(
    system_prompt: str,
    user_text: str,
    image_bytes: bytes | None,
    mime_type: str | None,
    provider: str,
) -> dict:
    """Build provider-specific message structures for multimodal calls.

    Returns a dict with 'system' and 'messages' (or 'user' for text-only fallback).
    """
    if not image_bytes:
        # Text-only — use standard prompt dict
        return {"system": system_prompt, "user": user_text}

    b64 = base64.b64encode(image_bytes).decode("utf-8")

    if provider == "claude":
        # Claude: content blocks with image + text
        return {
            "system": system_prompt,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": mime_type, "data": b64}},
                    {"type": "text", "text": user_text},
                ],
            }],
        }
    elif provider == "openai" or provider == "local":
        # OpenAI / local: image_url content type
        return {
            "system": system_prompt,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "image_url", "image_url": {"url": f"data:{mime_type};base64,{b64}"}},
                    {"type": "text", "text": user_text},
                ],
            }],
        }
    elif provider == "gemini":
        # Gemini: inline_data parts
        return {
            "system": system_prompt,
            "messages": [{
                "role": "user",
                "parts": [
                    {"inline_data": {"mime_type": mime_type, "data": b64}},
                    {"text": user_text},
                ],
            }],
        }
    # Fallback: text-only
    return {"system": system_prompt, "user": user_text}


def _call_multimodal_claude(api_key: str, model_id: str, msg_dict: dict,
                            stream_placeholder=None, max_tokens: int = 4096) -> tuple[str | None, dict]:
    """Call Claude API with multimodal content blocks."""
    try:
        from anthropic import Anthropic
    except ImportError:
        raise ImportError("The `anthropic` package is not installed. Install with: `pip install anthropic`")

    client = Anthropic(api_key=api_key, timeout=120.0)
    messages = msg_dict.get("messages", [{"role": "user", "content": msg_dict.get("user", "")}])

    if stream_placeholder:
        chunks: list[str] = []
        with client.messages.stream(
            model=model_id, max_tokens=max_tokens,
            system=[{"type": "text", "text": msg_dict["system"], "cache_control": {"type": "ephemeral"}}],
            messages=messages,
        ) as stream:
            for text in stream.text_stream:
                chunks.append(text)
                stream_placeholder.markdown("".join(chunks) + "\n\n*Streaming...*")
            final = stream.get_final_message()
        answer = "".join(chunks)
        usage = _extract_usage(final.usage if final else None, "claude")
        return (answer or None, usage)

    message = client.messages.create(
        model=model_id, max_tokens=max_tokens,
        system=[{"type": "text", "text": msg_dict["system"], "cache_control": {"type": "ephemeral"}}],
        messages=messages,
    )
    if not message.content:
        return (None, {})
    usage = _extract_usage(message.usage, "claude")
    return (message.content[0].text, usage)


def _call_multimodal_openai(api_key: str, model_id: str, msg_dict: dict,
                            stream_placeholder=None, max_tokens: int = 4096,
                            base_url: str | None = None) -> tuple[str | None, dict]:
    """Call OpenAI (or local) API with multimodal content blocks."""
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("The `openai` package is not installed. Install with: `pip install openai`")

    kwargs = {"api_key": api_key or "not-needed", "timeout": 120.0}
    if base_url:
        kwargs["base_url"] = base_url
    client = OpenAI(**kwargs)

    messages_list = [{"role": "system", "content": msg_dict["system"]}]
    if "messages" in msg_dict:
        messages_list.extend(msg_dict["messages"])
    else:
        messages_list.append({"role": "user", "content": msg_dict.get("user", "")})

    if stream_placeholder:
        chunks: list[str] = []
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


def _call_multimodal_gemini(api_key: str, model_id: str, msg_dict: dict,
                            stream_placeholder=None, max_tokens: int = 4096) -> tuple[str | None, dict]:
    """Call Gemini API with multimodal content (inline_data)."""
    import os
    key = api_key or os.environ.get("GEMINI_API_KEY", "")
    if not key:
        raise ValueError("GEMINI_API_KEY is not set.")
    try:
        import google.generativeai as genai
    except ImportError:
        raise ImportError("The `google-generativeai` package is not installed. Install with: pip install google-generativeai")

    genai.configure(api_key=key)
    gen_model = genai.GenerativeModel(model_id, system_instruction=msg_dict["system"])

    # Build content parts
    if "messages" in msg_dict and msg_dict["messages"]:
        msg = msg_dict["messages"][0]
        parts = msg.get("parts", [])
        if parts:
            # Convert inline_data to genai format
            content_parts = []
            for p in parts:
                if "inline_data" in p:
                    content_parts.append({
                        "inline_data": {
                            "mime_type": p["inline_data"]["mime_type"],
                            "data": base64.b64decode(p["inline_data"]["data"]),
                        }
                    })
                elif "text" in p:
                    content_parts.append(p["text"])
            response = gen_model.generate_content(content_parts, request_options={"timeout": 120})
        else:
            response = gen_model.generate_content(msg_dict.get("user", ""), request_options={"timeout": 120})
    else:
        response = gen_model.generate_content(msg_dict.get("user", ""), request_options={"timeout": 120})

    answer = response.text if response else None
    usage = {}
    if answer:
        input_text = msg_dict.get("system", "") + msg_dict.get("user", "")
        usage = {"input": estimate_tokens(input_text), "output": estimate_tokens(answer)}
    return (answer, usage)


def _extract_usage(usage_obj, provider: str) -> dict:
    """Extract token usage dict from provider-specific usage object."""
    if not usage_obj:
        return {}
    if provider == "claude":
        return {
            "input": getattr(usage_obj, "input_tokens", 0) or 0,
            "output": getattr(usage_obj, "output_tokens", 0) or 0,
            "cache_creation": getattr(usage_obj, "cache_creation_input_tokens", 0) or 0,
            "cache_read": getattr(usage_obj, "cache_read_input_tokens", 0) or 0,
        }
    return usage_obj if isinstance(usage_obj, dict) else {}


def _save_to_history(query: str, answer: str, provider: str, model_label: str):
    """Save an AI response to the per-provider history."""
    cfg = PROVIDER_CONFIG.get(provider, PROVIDER_CONFIG["claude"])
    entry = {
        "query": query,
        "answer": answer,
        "provider": model_label,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }
    hist = getattr(st.session_state, cfg["history_key"], [])
    if not any(h["query"] == query and h["answer"] == answer for h in hist):
        hist.append(entry)
        if cfg["save_history"]:
            cfg["save_history"](hist)


def _run_ai_call(provider, model_id, selected_model, msg_dict, image_bytes,
                 description, cache_key, session_cache, log, store_cache):
    """Execute the AI API call, handle streaming, caching, and spend tracking.

    Returns the answer text or None on failure.
    """
    system_prompt = msg_dict.get("system", "")
    user_text = msg_dict.get("user", "")
    _req_text = f"[SYSTEM]\n{system_prompt[:300]}...\n\n[USER]\n{user_text[:500]}..."
    prompt_text = system_prompt + user_text
    est_tokens_val = estimate_tokens(prompt_text)
    token_limit = TOKEN_LIMITS.get(provider, TOKEN_LIMITS["claude"])
    call_label = "Ask AI"

    with st.status(f"Analyzing with {selected_model}...", expanded=True) as status:
        st.write(f"Estimated prompt: ~{est_tokens_val:,} tokens")
        if image_bytes:
            st.write(f"Screenshot: {len(image_bytes) / 1024:.0f} KB")
        if est_tokens_val > int(token_limit * 0.8):
            st.warning(f"Prompt is ~{est_tokens_val / token_limit * 100:.0f}% of context limit.")

        try:
            stream_placeholder = st.empty()
            if provider == "claude":
                answer, usage = _call_multimodal_claude(
                    st.session_state.get("api_key", ""), model_id, msg_dict,
                    stream_placeholder=stream_placeholder)
            elif provider == "gemini":
                answer, usage = _call_multimodal_gemini(
                    st.session_state.get("gemini_api_key", ""), model_id, msg_dict)
            elif provider in ("openai", "local"):
                base_url = None
                api_key_field = "openai_api_key" if provider == "openai" else "local_ai_api_key"
                api_key = st.session_state.get(api_key_field, "") or "not-needed"
                if provider == "local":
                    base_url = getattr(st.session_state, "local_ai_endpoint", "") or None
                    model_id = getattr(st.session_state, "local_ai_model", "") or model_id
                answer, usage = _call_multimodal_openai(
                    api_key, model_id, msg_dict, stream_placeholder=stream_placeholder,
                    base_url=base_url)
            else:
                st.error(f"Unsupported provider: {provider}")
                return None

            if not answer:
                status.update(label="Empty response from AI", state="error")
                _log_probe(call_label, provider, model_id, _req_text, "", error="Empty response")
                return None

            stream_placeholder.empty()
            _log_probe(call_label, provider, model_id, _req_text, answer)

            # Cache (skip if screenshot or local)
            if store_cache and provider != "local" and image_bytes is None:
                store_cache(cache_key, answer, session_cache)

            # Track spend
            if usage:
                inp = usage.get("input", 0)
                out = usage.get("output", 0)
                cost = estimate_cost(model_id, inp, out)
                try:
                    from app_spend import record_spend
                    record_spend(provider, model_id, inp, out, source="ask_ai",
                                 cache_creation=usage.get("cache_creation", 0),
                                 cache_read=usage.get("cache_read", 0))
                except Exception:
                    pass
                st.caption(f"{inp:,} in + {out:,} out tokens — est. **${cost:.4f}**")

            status.update(label="Analysis complete!", state="complete")
            if log:
                log.info("ai Analysis complete (%s)", model_id)
            return answer

        except Exception as ex:
            _log_probe(call_label, provider, model_id, _req_text, "", error=str(ex))
            status.update(label="Analysis failed", state="error")
            st.error(f"AI call failed: {ex}")
            if log:
                log.error("ai Analysis failed: %s", ex)
            return None


def _check_api_key(provider):
    """Validate and return API key for provider. Returns key or None on error."""
    key_map = {"claude": "api_key", "gemini": "gemini_api_key", "openai": "openai_api_key",
               "local": "local_ai_api_key"}
    api_key = getattr(st.session_state, key_map.get(provider, "api_key"), "")
    if not api_key and provider != "local":
        st.error(f"No {provider} API key configured. Set it in the sidebar.")
        return None
    return api_key or "not-needed"


def render_incident_assistant(events, analysis, log=None, lookup_cache=None, store_cache=None):
    """Render the Incident AI Assistant — unified AI analysis for all use cases."""
    summary = analysis.get("summary", {})
    causes = analysis.get("causes", [])
    itl = analysis.get("incident_timeline")
    cascades = analysis.get("cascades", [])

    detected_format = detect_dominant_format(events)
    placeholder = _FORMAT_PLACEHOLDER.get(detected_format,
        "e.g. CWWKZ0001E, NullPointerException, 502 errors since 14:30, why are threads hanging?")

    # Detect multi-source
    sources = set(e.get("system_label", "") for e in events)
    is_multi_source = len(sources) >= 2

    # --- "Analyze All Logs" button (multi-source only) ---
    triage_clicked = False
    if is_multi_source:
        st.caption(f"Multi-source: {len(sources)} systems detected — analyze all logs in one AI call.")
        triage_clicked = st.button(
            f"Analyze All Logs ({len(events)} events, {len(sources)} sources)",
            type="primary", key="triage_all_btn", use_container_width=True)

    # --- Symptom / question input ---
    description = st.text_area(
        "Describe a symptom, paste an error code, or ask a question",
        placeholder=placeholder,
        height=100,
        key="incident_description_input",
    )

    screenshot_file = st.file_uploader(
        "Upload screenshot (optional)",
        type=_SUPPORTED_IMAGE_TYPES,
        key="incident_screenshot_upload",
    )

    # Validate screenshot size
    image_bytes = None
    mime_type = None
    if screenshot_file is not None:
        image_bytes = screenshot_file.getvalue()
        size_mb = len(image_bytes) / (1024 * 1024)
        if size_mb > MAX_SCREENSHOT_MB:
            st.warning(f"Screenshot is {size_mb:.1f} MB — max {MAX_SCREENSHOT_MB} MB. It will be ignored.")
            image_bytes = None
        else:
            ext = screenshot_file.name.rsplit(".", 1)[-1].lower()
            mime_map = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                        "gif": "image/gif", "webp": "image/webp"}
            mime_type = mime_map.get(ext, "image/png")
            st.image(image_bytes, caption="Uploaded screenshot", width=400)

    # Model selector + analyze button
    model_col, btn_col = st.columns([1, 1])
    with model_col:
        selected_model = st.selectbox(
            "AI Model",
            list(AI_MODELS.keys()),
            key="incident_model_select",
            label_visibility="collapsed",
        )
    with btn_col:
        analyze_clicked = st.button("Analyze", type="primary", key="incident_analyze_btn",
                                    use_container_width=True)

    # Previous AI answer for conversation context
    previous_answer = st.session_state.get("_incident_answer")
    cached_answer = previous_answer

    # --- Handle button clicks ---
    clicked = triage_clicked or (analyze_clicked and description.strip())

    if analyze_clicked and not description.strip() and not triage_clicked:
        st.warning("Enter an error code, question, or symptom description.")

    if clicked:
        # Rate limiting
        now = time.time()
        elapsed = now - st.session_state.get("last_ai_call_ts", 0)
        if elapsed < AI_RATE_LIMIT_SECONDS:
            st.warning(f"Rate limit: wait {AI_RATE_LIMIT_SECONDS - elapsed:.0f}s before next AI call.")
        else:
            st.session_state.last_ai_call_ts = now
            model_info = AI_MODELS[selected_model]
            provider = model_info["provider"]
            model_id = model_info["model_id"]

            api_key = _check_api_key(provider)
            if api_key is None:
                pass  # Error already shown
            else:
                answer = _run_analysis(
                    events=events, description=description if not triage_clicked else "",
                    summary=summary, causes=causes, itl=itl, cascades=cascades,
                    detected_format=detected_format, is_multi_source=is_multi_source,
                    is_triage=triage_clicked,
                    image_bytes=image_bytes, mime_type=mime_type,
                    provider=provider, model_id=model_id, selected_model=selected_model,
                    previous_answer=previous_answer if not triage_clicked else None,
                    log=log, lookup_cache=lookup_cache, store_cache=store_cache,
                )
                if answer:
                    st.session_state._incident_answer = answer
                    st.session_state._incident_model = selected_model
                    cached_answer = answer

    # --- Render current result ---
    if cached_answer:
        model_label = st.session_state.get("_incident_model", "AI")
        st.markdown(f"**AI Analysis** ({model_label}):")
        _render_claude_response(cached_answer)

    # --- Render history ---
    _render_ai_history()

    # --- Clear button ---
    has_any = any([
        cached_answer,
        len(st.session_state.get("claude_history", [])) > 0,
        len(st.session_state.get("gemini_history", [])) > 0,
        len(st.session_state.get("openai_history", [])) > 0,
        len(st.session_state.get("local_history", [])) > 0,
    ])
    if has_any:
        if st.button("Clear all AI history", key="clear_ai_history_btn"):
            clear_all_ai_history()
            st.rerun()


def _run_analysis(events, description, summary, causes, itl, cascades,
                  detected_format, is_multi_source, is_triage,
                  image_bytes, mime_type, provider, model_id, selected_model,
                  previous_answer, log, lookup_cache, store_cache):
    """Build prompt, check cache, call AI, save to history. Returns answer or None."""

    # --- Build per-source data (for multi-source) ---
    sources_data = None
    source_errors = None
    source_formats = None
    if is_multi_source:
        sources_data = per_source_summary(events)
        source_formats = list(set(s.get("format", "") for s in sources_data if s.get("format")))
        source_errors = {}
        for s in sources_data:
            errs = [e for e in events
                    if e.get("system_label") == s["label"]
                    and e.get("level") in ERROR_LEVELS][:3]
            if errs:
                source_errors[f"{s['label']} ({s.get('format', '?')})"] = errs

    # --- Query matching (skip for triage mode) ---
    match = None
    if not is_triage and description:
        match = match_user_query(description, events)

    # --- Domain skills ---
    skill_files = select_skills(
        match or {"matched": False, "codes": [], "exceptions": [], "tags": []},
        description or "",
        detected_format=detected_format,
    )
    skill_content = load_skill_content(skill_files)
    if skill_files and log:
        log.info("ai skills: %s (format: %s)", ", ".join(skill_files), detected_format or "?")

    # --- System prompt ---
    system_prompt = build_incident_system_prompt(
        detected_format,
        skill_content=skill_content,
        is_multi_source=is_multi_source,
        source_formats=source_formats,
    )

    # --- Error events ---
    error_events = [e for e in events if e.get("level") in ERROR_LEVELS][:5]

    # --- User prompt ---
    query_label = description or "Cross-system analysis of all uploaded logs"
    user_text = build_incident_user_prompt(
        description=query_label,
        summary=summary,
        causes=causes,
        itl=itl,
        error_events=error_events,
        cascades=cascades,
        has_screenshot=image_bytes is not None,
        match_result=match,
        per_source=sources_data,
        per_source_errors=source_errors,
        previous_answer=previous_answer,
    )

    # --- Cache ---
    if is_triage:
        cache_key = "triage:" + triage_cache_key(events, model_id)
    else:
        cache_key = f"incident:{provider}:" + incident_cache_key(description, summary, model_id)

    cfg = PROVIDER_CONFIG.get(provider, PROVIDER_CONFIG["claude"])
    session_cache = getattr(st.session_state, cfg["cache_key"], {})

    cached = None
    if lookup_cache and provider != "local" and image_bytes is None:
        cached = lookup_cache(cache_key, session_cache, f"ai/{provider}", query_label[:60])

    if cached:
        _save_to_history(query_label, cached, provider, selected_model)
        st.info("AI analysis loaded from cache.")
        return cached

    # --- Build message and call AI ---
    msg_dict = _build_multimodal_messages(system_prompt, user_text, image_bytes, mime_type, provider)

    answer = _run_ai_call(
        provider, model_id, selected_model, msg_dict, image_bytes,
        query_label, cache_key, session_cache, log, store_cache,
    )
    if answer:
        _save_to_history(query_label, answer, provider, selected_model)
    return answer


def _render_ai_history():
    """Render previous AI query history from all providers."""
    for provider_key, hist_key, label in [
        ("claude", "claude_history", "Claude"),
        ("gemini", "gemini_history", "Gemini"),
        ("openai", "openai_history", "GPT"),
        ("local", "local_history", "Local AI"),
    ]:
        history = st.session_state.get(hist_key, [])
        # Skip the latest entry if it matches the current answer (already shown above)
        current = st.session_state.get("_incident_answer")
        display_hist = [h for h in history if h.get("answer") != current]
        if not display_hist:
            continue
        st.markdown("---")
        for entry in reversed(display_hist):
            query_preview = entry.get("query", "")[:80]
            provider_label = entry.get("provider", label)
            ts = entry.get("timestamp", "")
            with st.expander(f"{provider_label} — {query_preview} ({ts})"):
                _render_claude_response(entry["answer"])
