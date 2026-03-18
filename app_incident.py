"""Incident Assistant — symptom-driven debugging with optional screenshot analysis."""
from __future__ import annotations

import base64
import hashlib
import time

import streamlit as st
from datetime import datetime

from logpilot import (
    build_incident_system_prompt, build_incident_user_prompt,
    incident_cache_key, estimate_tokens, TOKEN_LIMITS,
)
from app_ai import (
    AI_MODELS, PROVIDER_CONFIG, _API_CALLERS,
    _log_probe, detect_dominant_format, estimate_cost,
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


def render_incident_assistant(events, analysis, log=None, lookup_cache=None, store_cache=None):
    """Render the Incident Assistant UI section."""
    summary = analysis.get("summary", {})
    causes = analysis.get("causes", [])
    itl = analysis.get("incident_timeline")
    cascades = analysis.get("cascades", [])

    # --- UI ---
    description = st.text_area(
        "Describe the symptom you're seeing",
        placeholder="e.g. Users report 502 errors on checkout page since 14:30, response times doubled",
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

    # Model selector
    model_col, btn_col = st.columns([1, 1])
    with model_col:
        selected_model = st.selectbox(
            "AI Model",
            list(AI_MODELS.keys()),
            key="incident_model_select",
            label_visibility="collapsed",
        )
    with btn_col:
        diagnose_clicked = st.button("Diagnose", type="primary", key="incident_diagnose_btn",
                                     use_container_width=True)

    # Show cached result
    cached_answer = st.session_state.get("_incident_answer")

    if diagnose_clicked:
        if not description.strip():
            st.warning("Please describe the symptom you're seeing.")
            return

        # Rate limiting
        now = time.time()
        elapsed = now - st.session_state.get("last_ai_call_ts", 0)
        if elapsed < AI_RATE_LIMIT_SECONDS:
            st.warning(f"Rate limit: wait {AI_RATE_LIMIT_SECONDS - elapsed:.0f}s before next AI call.")
            return
        st.session_state.last_ai_call_ts = now

        model_info = AI_MODELS[selected_model]
        provider = model_info["provider"]
        model_id = model_info["model_id"]
        detected_format = detect_dominant_format(events)

        # Build prompt
        system_prompt = build_incident_system_prompt(detected_format)

        # Collect error events for context
        error_levels = {"ERROR", "SEVERE", "FATAL"}
        error_events = [e for e in events if e.get("level") in error_levels][:5]

        user_text = build_incident_user_prompt(
            description=description,
            summary=summary,
            causes=causes,
            itl=itl,
            error_events=error_events,
            cascades=cascades,
            has_screenshot=image_bytes is not None,
        )

        # Check cache
        cache_key = f"incident:{provider}:" + incident_cache_key(description, summary, model_id)
        cfg = PROVIDER_CONFIG.get(provider, PROVIDER_CONFIG["claude"])
        session_cache = getattr(st.session_state, cfg["cache_key"], {})

        cached = None
        if lookup_cache and provider != "local" and image_bytes is None:
            cached = lookup_cache(cache_key, session_cache, f"incident/{provider}", description[:60])

        if cached:
            st.session_state._incident_answer = cached
            st.session_state._incident_model = selected_model
            cached_answer = cached
            st.info("Incident diagnosis loaded from cache.")
        else:
            # Build multimodal messages
            msg_dict = _build_multimodal_messages(system_prompt, user_text, image_bytes, mime_type, provider)

            # Get API key
            key_map = {"claude": "api_key", "gemini": "gemini_api_key", "openai": "openai_api_key",
                       "local": "local_ai_api_key"}
            api_key = getattr(st.session_state, key_map.get(provider, "api_key"), "")
            if not api_key and provider != "local":
                st.error(f"No {provider} API key configured. Set it in the sidebar.")
                return
            if provider == "local" and not api_key:
                api_key = "not-needed"

            # Token estimation
            prompt_text = system_prompt + user_text
            est_tokens_val = estimate_tokens(prompt_text)
            token_limit = TOKEN_LIMITS.get(provider, TOKEN_LIMITS["claude"])
            _req_text = f"[SYSTEM]\n{system_prompt}\n\n[USER]\n{user_text[:500]}..."

            with st.status(f"Diagnosing with {selected_model}...", expanded=True) as status:
                st.write(f"Estimated prompt: ~{est_tokens_val:,} tokens")
                if image_bytes:
                    st.write(f"Screenshot: {len(image_bytes) / 1024:.0f} KB")

                if est_tokens_val > int(token_limit * 0.8):
                    st.warning(f"Prompt is ~{est_tokens_val / token_limit * 100:.0f}% of context limit.")

                try:
                    stream_placeholder = st.empty()

                    if provider == "claude":
                        answer, usage = _call_multimodal_claude(
                            api_key, model_id, msg_dict, stream_placeholder=stream_placeholder)
                    elif provider == "gemini":
                        answer, usage = _call_multimodal_gemini(
                            api_key, model_id, msg_dict)
                    elif provider in ("openai", "local"):
                        base_url = None
                        if provider == "local":
                            base_url = getattr(st.session_state, "local_ai_endpoint", "") or None
                            model_id = getattr(st.session_state, "local_ai_model", "") or model_id
                        answer, usage = _call_multimodal_openai(
                            api_key, model_id, msg_dict, stream_placeholder=stream_placeholder,
                            base_url=base_url)
                    else:
                        st.error(f"Unsupported provider: {provider}")
                        return

                    if not answer:
                        status.update(label="Empty response from AI", state="error")
                        _log_probe("Incident", provider, model_id, _req_text, "", error="Empty response")
                        return

                    stream_placeholder.empty()
                    st.session_state._incident_answer = answer
                    st.session_state._incident_model = selected_model
                    cached_answer = answer
                    _log_probe("Incident", provider, model_id, _req_text, answer)

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
                            record_spend(provider, model_id, inp, out, source="incident",
                                         cache_creation=usage.get("cache_creation", 0),
                                         cache_read=usage.get("cache_read", 0))
                        except Exception:
                            pass
                        st.caption(f"Incident: {inp:,} in + {out:,} out tokens — est. **${cost:.4f}**")

                    status.update(label="Diagnosis complete!", state="complete")
                    if log:
                        log.info("incident Diagnosis complete (%s)", model_id)

                except Exception as ex:
                    _log_probe("Incident", provider, model_id, _req_text, "", error=str(ex))
                    status.update(label="Diagnosis failed", state="error")
                    st.error(f"AI call failed: {ex}")
                    if log:
                        log.error("incident Diagnosis failed: %s", ex)
                    return

    # Render result
    if cached_answer:
        model_label = st.session_state.get("_incident_model", "AI")
        st.markdown(f"**Incident Diagnosis** ({model_label}):")
        st.markdown(cached_answer)
