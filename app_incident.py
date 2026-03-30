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
import json
import time
from pathlib import Path

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
    call_claude_api, call_gemini_api, call_openai_api, call_local_api,
)
from app_constants import AI_RATE_LIMIT_SECONDS, MAX_SCREENSHOT_MB
from logpilot.license import require_license, allowed_providers, is_model_allowed


_SUPPORTED_IMAGE_TYPES = ["png", "jpg", "jpeg", "gif", "webp"]

import re

def _extract_exclude_hints(description: str) -> list[str]:
    """Extract exclude keywords from symptom text.

    Only matches explicit exclusion phrases followed by identifiers:
    - "ignore X", "skip X", "exclude X", "disregard X"
    - "don't focus on X", "do not focus on X"
    - "not related to X", "not about X"
    - "anything related to X"

    X must look like an identifier: domain name, code, hyphenated term, or CamelCase.
    Plain English phrases like "do not appear to be encrypted" are NOT matched.
    """
    if not description:
        return []
    # Match explicit exclusion verbs followed by identifiers
    patterns = [
        # "ignore/skip/exclude/disregard [anything related to] <identifier>"
        r"(?:ignore|skip|exclude|disregard)\s+(?:anything\s+)?(?:related\s+to\s+|about\s+|regarding\s+)?([a-zA-Z0-9][\w.*-]*(?:\.[a-zA-Z0-9][\w-]*)+)",
        r"(?:ignore|skip|exclude|disregard)\s+(?:anything\s+)?(?:related\s+to\s+|about\s+|regarding\s+)?([a-zA-Z][\w-]*(?:-[\w]+)+)",
        r"(?:ignore|skip|exclude|disregard)\s+(?:anything\s+)?(?:related\s+to\s+|about\s+|regarding\s+)?([A-Z][a-z]+(?:[A-Z][a-z]+)+)",
        # "don't/do not focus on [anything related to] <identifier>"
        r"(?:do\s*n[o']?t|don't)\s+focus\s+on\s+(?:anything\s+)?(?:related\s+to\s+)?([a-zA-Z0-9][\w.*-]*(?:\.[a-zA-Z0-9][\w-]*)+)",
        r"(?:do\s*n[o']?t|don't)\s+focus\s+on\s+(?:anything\s+)?(?:related\s+to\s+)?([a-zA-Z][\w-]*(?:-[\w]+)+)",
        r"(?:do\s*n[o']?t|don't)\s+focus\s+on\s+(?:anything\s+)?(?:related\s+to\s+)?([A-Z][a-z]+(?:[A-Z][a-z]+)+)",
        # "not related to <identifier>"
        r"not\s+related\s+to\s+([a-zA-Z0-9][\w.*-]*(?:\.[a-zA-Z0-9][\w-]*)+)",
        r"not\s+related\s+to\s+([a-zA-Z][\w-]*(?:-[\w]+)+)",
        # Fallback: "ignore/skip <single-word>" but only if word has 4+ chars and isn't common English
        r"(?:ignore|skip|exclude|disregard)\s+([a-zA-Z]\w{3,})",
    ]
    _common_english = {
        "anything", "everything", "something", "nothing", "errors", "error",
        "issues", "issue", "problems", "problem", "warnings", "messages",
        "events", "logs", "that", "this", "those", "these", "them", "they",
        "focus", "likely", "probably", "possibly", "also", "just", "only",
        "encrypted", "properly", "appear", "related", "about",
    }
    hints = []
    for pat in patterns:
        for m in re.finditer(pat, description, re.IGNORECASE):
            word = m.group(1).strip().rstrip(".")
            if word.lower() not in _common_english:
                hints.append(word.lower())
    return list(set(hints))


def _strip_exclude_sentences(description: str) -> str:
    """Remove sentences containing exclude directives from symptom text.

    Strips sentences like 'Do not focus on anything related to no.fiskeridir.'
    so the AI only sees the actual symptom description.
    """
    if not description:
        return description
    # Split on sentence boundaries (. or — followed by space/newline)
    sentences = re.split(r'(?<=[.!?])\s+|(?<=—)\s+', description)
    _exclude_verbs = re.compile(
        r'\b(?:do\s*n[o\']?t|don\'t)\s+focus\s+on\b'
        r'|\b(?:ignore|skip|exclude|disregard)\s+(?:anything\s+)?(?:related\s+to\s+)?'
        r'|\bnot\s+related\s+to\b',
        re.IGNORECASE,
    )
    kept = [s for s in sentences if not _exclude_verbs.search(s)]
    return " ".join(kept).strip()


def _apply_exclude_filter(events, causes, exclude_patterns):
    """Filter events and heuristic causes by exclude patterns. Returns (filtered_events, filtered_causes)."""
    if not exclude_patterns:
        return events, causes

    def _matches(text):
        text_lower = text.lower() if text else ""
        return any(pat in text_lower for pat in exclude_patterns)

    filtered_events = [
        e for e in events
        if not _matches(e.text) and not _matches(getattr(e, "exception", "") or "")
    ]
    filtered_causes = [
        c for c in causes
        if not _matches(c.get("label", "")) and not _matches(c.get("description", ""))
           and not _matches(str(c.get("sample_events", [])))
    ]
    return filtered_events, filtered_causes


def _build_multimodal_messages(
    system_prompt: str,
    user_text: str,
    image_bytes: bytes | None,
    mime_type: str | None,
    provider: str,
    *,
    images: list[tuple[bytes, str]] | None = None,
) -> dict:
    """Build provider-specific message structures for multimodal calls.

    Supports single image (image_bytes/mime_type) or multiple images (images list).
    Returns a dict with 'system' and 'messages' (or 'user' for text-only fallback).
    """
    # Build image list from either single or multi input
    img_list: list[tuple[bytes, str]] = []
    if images:
        img_list = images
    elif image_bytes and mime_type:
        img_list = [(image_bytes, mime_type)]

    if not img_list:
        return {"system": system_prompt, "user": user_text}

    if provider == "claude":
        content = []
        for img_data, img_mime in img_list:
            b64 = base64.b64encode(img_data).decode("utf-8")
            content.append({"type": "image", "source": {"type": "base64", "media_type": img_mime, "data": b64}})
        content.append({"type": "text", "text": user_text})
        return {
            "system": system_prompt,
            "messages": [{"role": "user", "content": content}],
        }
    elif provider == "openai" or provider == "local":
        content = []
        for img_data, img_mime in img_list:
            b64 = base64.b64encode(img_data).decode("utf-8")
            content.append({"type": "image_url", "image_url": {"url": f"data:{img_mime};base64,{b64}"}})
        content.append({"type": "text", "text": user_text})
        return {
            "system": system_prompt,
            "messages": [{"role": "user", "content": content}],
        }
    elif provider == "gemini":
        parts = []
        for img_data, img_mime in img_list:
            b64 = base64.b64encode(img_data).decode("utf-8")
            parts.append({"inline_data": {"mime_type": img_mime, "data": b64}})
        parts.append({"text": user_text})
        return {
            "system": system_prompt,
            "messages": [{"role": "user", "parts": parts}],
        }
    return {"system": system_prompt, "user": user_text}


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


def _extract_missing_logs(answer: str) -> tuple[str, str]:
    """Extract the 'Missing Logs' section from an AI response.

    Returns (main_answer, missing_logs_text). If no section found,
    missing_logs_text is empty.
    """
    import re
    # Match ## Missing Logs, **Missing Logs**, or numbered heading like "9. **Missing Logs**"
    pattern = r'(?:^#{1,3}\s*(?:\d+\.\s*)?(?:\*\*)?Missing Logs(?:\*\*)?.*$)'
    match = re.search(pattern, answer, re.MULTILINE | re.IGNORECASE)
    if not match:
        # Try simpler pattern: **Missing Logs**:
        pattern2 = r'(?:^\*\*Missing Logs\*\*\s*[:—-]?\s*)'
        match = re.search(pattern2, answer, re.MULTILINE | re.IGNORECASE)
    if match:
        split_pos = match.start()
        main = answer[:split_pos].rstrip()
        missing = answer[match.end():].strip()
        return main, missing
    return answer, ""


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
    _req_text = f"[SYSTEM]\n{system_prompt[:800]}...\n\n[USER]\n{user_text[:2000]}..."
    prompt_text = system_prompt + user_text
    est_tokens_val = estimate_tokens(prompt_text)
    token_limit = TOKEN_LIMITS.get(provider, TOKEN_LIMITS["claude"])
    call_label = "Ask AI"

    # Pre-estimate cost (assume ~2K output tokens)
    est_output = 2000
    est_cost = estimate_cost(model_id, est_tokens_val, est_output)

    with st.status(f"Analyzing with {selected_model}...", expanded=True) as status:
        cost_str = f" — est. ~${est_cost:.4f}" if est_cost > 0 else " — free (local)"
        st.write(f"Estimated prompt: ~{est_tokens_val:,} tokens{cost_str}")
        if image_bytes:
            st.write(f"Screenshot: {len(image_bytes) / 1024:.0f} KB")
        if est_tokens_val > int(token_limit * 0.8):
            st.warning(f"Prompt is ~{est_tokens_val / token_limit * 100:.0f}% of context limit.")

        try:
            # Check package availability before calling
            from app_ai import _AVAILABLE_PROVIDERS
            if provider not in ("local",) and provider not in _AVAILABLE_PROVIDERS:
                _pkg = {"claude": "anthropic", "gemini": "google-generativeai", "openai": "openai"}.get(provider, provider)
                st.error(f"Provider '{provider}' not available. Install with: `pip install {_pkg}`")
                return None

            stream_placeholder = st.empty()
            if provider == "claude":
                answer, usage = call_claude_api(
                    st.session_state.get("api_key", ""), model_id, msg_dict,
                    stream_placeholder=stream_placeholder, max_tokens=8192)
            elif provider == "gemini":
                answer, usage = call_gemini_api(
                    st.session_state.get("gemini_api_key", ""), model_id, msg_dict,
                    max_tokens=8192)
            elif provider == "openai":
                answer, usage = call_openai_api(
                    st.session_state.get("openai_api_key", "") or "not-needed",
                    model_id, msg_dict, stream_placeholder=stream_placeholder,
                    max_tokens=8192)
            elif provider == "local":
                _local_key = st.session_state.get("local_ai_api_key", "") or "not-needed"
                _local_url = getattr(st.session_state, "local_ai_endpoint", "") or None
                _local_model = getattr(st.session_state, "local_ai_model", "") or model_id
                answer, usage = call_local_api(
                    _local_key, _local_model, msg_dict, stream_placeholder=stream_placeholder,
                    max_tokens=4096, base_url=_local_url)
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
            from app_ai import _sanitize_error
            st.error(f"AI call failed: {_sanitize_error(str(ex))}")
            if log:
                log.error("ai Analysis failed: %s", ex)
            return None


def _check_api_key(provider):
    """Validate and return API key for provider. Returns key or None on error."""
    key_map = {"claude": "api_key", "gemini": "gemini_api_key", "openai": "openai_api_key",
               "local": "local_ai_api_key"}
    api_key = getattr(st.session_state, key_map.get(provider, "api_key"), "")
    # Trial license: use baked-in API key from env var
    if not api_key and provider == "claude":
        import os
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key and provider != "local":
        st.error(f"No {provider} API key configured. Set it in the sidebar.")
        return None
    return api_key or "not-needed"


def _enrich_causes_with_groups(causes: list, events: list | None = None) -> list:
    """Add incident group ranking (cascade_order, is_primary) to causes for AI prompt context."""
    if not causes:
        return causes
    from logpilot.heuristics import group_into_incidents
    result = group_into_incidents(causes, events=events)
    groups = result.get("groups", [])
    # Build lookup: cause_id → group ranking info
    cause_rank = {}
    for g in groups:
        for t in g.get("triggers", []):
            cause_rank[t["id"]] = {"cascade_order": g.get("cascade_order", ""), "is_primary": g.get("is_primary", False)}
        for e in g.get("effects", []):
            cause_rank[e["id"]] = {"cascade_order": g.get("cascade_order", ""), "is_primary": False}
    # Annotate causes (non-destructive copy)
    enriched = []
    for c in causes:
        ec = dict(c)
        rank_info = cause_rank.get(c["id"], {})
        ec["cascade_order"] = rank_info.get("cascade_order", "")
        ec["is_primary"] = rank_info.get("is_primary", False)
        enriched.append(ec)
    return enriched


def render_incident_assistant(events, analysis, log=None, lookup_cache=None, store_cache=None):
    """Render the Incident AI Assistant — unified AI analysis for all use cases."""
    summary = analysis.get("summary", {})
    causes = _enrich_causes_with_groups(analysis.get("causes", []), events=events)
    itl = analysis.get("incident_timeline")
    cascades = analysis.get("cascades", [])

    detected_format = detect_dominant_format(events)

    # Detect multi-source
    sources = set(e.system_label or "" for e in events)
    is_multi_source = len(sources) >= 2

    # --- AI model check ---
    selected_model = st.session_state.get("_selected_ai_model", "")

    if not selected_model or selected_model not in AI_MODELS:
        st.warning("Select an AI model in the **sidebar** first.")
        return

    # --- Symptoms / incident description ---
    st.text_area(
        "Describe symptoms (optional)",
        placeholder="e.g. Users get 502 errors since 14:00, restart did not help...",
        help="Give AI context about what you're investigating.",
        key="_incident_description",
    )
    description = st.session_state.get("_incident_description", "")

    # --- Exclude patterns (explicit + auto-extracted from symptoms) ---
    st.text_input(
        "Exclude from AI (comma-separated)",
        placeholder="e.g. fiskeridir, legacy-module, WARN0042",
        help="Events and heuristics matching these keywords are filtered out before AI analysis.",
        key="_ai_exclude_patterns",
    )
    _explicit_excludes = [
        p.strip().lower() for p in
        st.session_state.get("_ai_exclude_patterns", "").split(",")
        if p.strip()
    ]
    _auto_excludes = _extract_exclude_hints(description)
    exclude_patterns = list(set(_explicit_excludes + _auto_excludes))
    if exclude_patterns:
        st.caption(f"Excluding: {', '.join(exclude_patterns)}")
    if log:
        log.info("ai exclude debug: explicit=%s auto=%s combined=%s desc_len=%d",
                 _explicit_excludes, _auto_excludes, exclude_patterns, len(description))

    # Show what we're working with
    _model_info_label = f"**Model:** {selected_model}"
    _desc_label = f" · **Symptoms:** {description[:60]}..." if description and len(description) > 60 else (f" · **Symptoms:** {description}" if description else "")
    st.caption(_model_info_label + _desc_label)

    # --- Collect screenshots from Home page ---
    images: list[tuple[bytes, str]] = []
    image_bytes = None
    mime_type = None
    mime_map = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                "gif": "image/gif", "webp": "image/webp"}
    for sf in st.session_state.get("_incident_screenshots", []):
        data = sf.getvalue()
        size_mb = len(data) / (1024 * 1024)
        if size_mb > MAX_SCREENSHOT_MB:
            st.warning(f"Screenshot '{sf.name}' skipped ({size_mb:.1f} MB > {MAX_SCREENSHOT_MB} MB limit)")
            continue
        ext = sf.name.rsplit(".", 1)[-1].lower()
        mt = mime_map.get(ext, "image/png")
        images.append((data, mt))
        if image_bytes is None:
            image_bytes = data
            mime_type = mt
    if images:
        st.caption(f"{len(images)} screenshot(s) from Home will be included in AI context.")

    # --- Single analyze button ---
    if is_multi_source:
        st.caption(f"Multi-source: {len(sources)} systems detected — {len(events)} events, {len(sources)} sources.")

    analyze_clicked = st.button("Start AI Analysis", type="primary", key="incident_analyze_btn",
                                use_container_width=True)
    triage_clicked = analyze_clicked and is_multi_source

    # --- Noise filter controls ---
    from logpilot.analysis import compute_noise_scores, filter_noise
    noise_threshold = st.slider(
        "Noise filter",
        min_value=0.0, max_value=1.0, value=0.5, step=0.1,
        key="noise_threshold_slider",
        help="Filter repetitive/low-value events before AI analysis. Higher = more aggressive filtering.",
    )
    # Compute noise scores for preview
    _noise_scores = compute_noise_scores(events)
    if _noise_scores and noise_threshold > 0:
        _noisy_keys = [k for k, score in _noise_scores.items() if score >= noise_threshold]
        _filtered_preview = filter_noise(events, threshold=noise_threshold, noise_scores=_noise_scores)
        _n_filtered = len(events) - len(_filtered_preview)
        if _n_filtered > 0:
            st.caption(f"Filtering {_n_filtered} noisy events ({len(_noisy_keys)} patterns)")
        show_noise_details = st.checkbox("Show noise details", key="show_noise_details")
        if show_noise_details:
            _detail_rows = []
            for key, score in sorted(_noise_scores.items(), key=lambda x: -x[1]):
                if score > 0:
                    _label = key[4:50] + "..." if key.startswith("sig:") and len(key) > 54 else key[4:] if key.startswith("sig:") else key
                    _detail_rows.append({"Pattern": _label, "Score": f"{score:.2f}",
                                        "Status": "Filtered" if score >= noise_threshold else "Kept"})
            if _detail_rows:
                import pandas as _pd
                st.dataframe(_pd.DataFrame(_detail_rows[:20]), use_container_width=True, hide_index=True)
    elif noise_threshold > 0 and not _noise_scores:
        st.caption("No repetitive patterns found to filter.")

    # Cost preview — build a realistic estimate of prompt size
    _model_info = AI_MODELS.get(selected_model, {})
    _est_events_for_cost = (
        filter_noise(events, threshold=noise_threshold, noise_scores=_noise_scores)
        if _noise_scores and noise_threshold > 0 else events
    )
    _est_parts = [
        str(summary),                                    # log summary
        str(causes[:10]),                                # heuristic findings
        str(cascades[:5]),                               # cascades
        description or "Cross-system analysis",          # user description
    ]
    # Estimate incident timeline
    if itl:
        _est_parts.append(str(itl.get("trigger_event", {})))
        _est_parts.append(str(itl.get("window_events", [])[:8]))
    # Per-source summaries for multi-source
    if is_multi_source:
        from logpilot import per_source_summary as _pss
        _est_parts.append(str(_pss(_est_events_for_cost)))
    # Previous answer context
    _prev = st.session_state.get("_incident_answer")
    if _prev:
        _est_parts.append(_prev[:8000])
    _est_input = estimate_tokens("".join(_est_parts)) + 3000  # system prompt + skills overhead
    _est_output = 2000
    _est_cost = estimate_cost(_model_info.get("model_id", ""), _est_input, _est_output)
    if _est_cost > 0:
        st.caption(f"Est. ~{_est_input:,} input tokens · ~${_est_cost:.4f} with {selected_model}")
    else:
        st.caption(f"Est. ~{_est_input:,} input tokens · free (local model)")

    # Previous AI answer for conversation context (filter out excluded patterns)
    previous_answer = st.session_state.get("_incident_answer")
    if previous_answer and exclude_patterns:
        # Remove previous analysis if it contains excluded terms — forces fresh analysis
        _prev_lower = previous_answer.lower()
        if any(pat in _prev_lower for pat in exclude_patterns):
            previous_answer = None
            st.caption("Previous analysis cleared (contained excluded terms)")
    cached_answer = previous_answer

    # --- Handle button clicks ---
    clicked = triage_clicked or analyze_clicked

    if clicked:
        # Rate limiting
        now = time.time()
        elapsed = now - st.session_state.get("last_ai_call_ts", 0)
        if elapsed < AI_RATE_LIMIT_SECONDS:
            st.warning(f"Rate limit: wait {AI_RATE_LIMIT_SECONDS - elapsed:.0f}s before next AI call.")
        else:
            st.session_state.last_ai_call_ts = now
            if not selected_model or selected_model not in AI_MODELS:
                st.error("No AI model available. Check your license key.")
                return
            model_info = AI_MODELS[selected_model]
            provider = model_info["provider"]
            model_id = model_info["model_id"]

            api_key = _check_api_key(provider)
            if api_key is None:
                pass  # Error already shown
            else:
                answer = _run_analysis(
                    events=events, description=description,
                    summary=summary, causes=causes, itl=itl, cascades=cascades,
                    exclude_patterns=exclude_patterns,
                    detected_format=detected_format, is_multi_source=is_multi_source,
                    is_triage=triage_clicked,
                    image_bytes=image_bytes, mime_type=mime_type,
                    provider=provider, model_id=model_id, selected_model=selected_model,
                    previous_answer=previous_answer,
                    log=log, lookup_cache=lookup_cache, store_cache=store_cache,
                    images=images,
                )
                if answer:
                    st.session_state._incident_answer = answer
                    st.session_state._incident_model = selected_model
                    st.session_state._incident_provider = provider
                    st.session_state._incident_model_id = model_id
                    cached_answer = answer

                    # Debug log: AI response details
                    if log:
                        _has_ml = "Missing Logs" in answer
                        _last_50 = answer[-50:].replace("\n", "\\n")
                        log.info("ai_response provider=%s model=%s chars=%d has_missing_logs=%s ends_with='%s'",
                                 provider, model_id, len(answer), _has_ml, _last_50)

                    # Save incident fingerprint to session history
                    from logpilot.heuristics import incident_fingerprint, match_similar_incidents
                    if causes:
                        fp = incident_fingerprint(causes)
                        cause_ids = [c.get("id", c.get("title", "")) for c in causes]
                        history = st.session_state.get("incident_history", [])
                        history.append({
                            "fingerprint": fp,
                            "ids": cause_ids,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        })
                        st.session_state.incident_history = history

    # --- Render current result ---
    if cached_answer:
        # Check for similar past incidents
        if causes:
            from logpilot.heuristics import incident_fingerprint, match_similar_incidents
            history = st.session_state.get("incident_history", [])
            if len(history) >= 2:  # Need at least 2 entries (including current)
                # Exclude the latest entry (which is the current analysis)
                past_history = history[:-1]
                similar = match_similar_incidents(causes, past_history)
                if similar:
                    best = similar[0]
                    pct = int(best["similarity"] * 100)
                    st.info(f"Similar to analysis from {best['timestamp']} ({pct}% match)", icon="🔍")

        model_label = st.session_state.get("_incident_model", "AI")
        # Extract "Missing Logs" section and render it prominently
        main_answer, missing_logs = _extract_missing_logs(cached_answer)
        _answer_len = len(cached_answer)
        _has_missing = "Missing Logs" in cached_answer
        st.markdown(f"**AI Analysis** ({model_label}) — {_answer_len:,} chars{' · includes Missing Logs' if _has_missing else ' · no Missing Logs section'}:")
        _render_claude_response(main_answer)
        if missing_logs and "none" not in missing_logs.lower()[:50]:
            st.info(f"**Missing Logs — upload these for a more complete diagnosis:**\n\n{missing_logs}", icon="📋")
        elif not _has_missing:
            st.caption("AI response did not include a Missing Logs section — the response may have been truncated by the model's token limit.")

    # AI history removed — only the current analysis is shown above.
    # Old responses are cached in session state for conversation context but not displayed.

    # Clear button moved to sidebar (Settings)


def _run_analysis(events, description, summary, causes, itl, cascades,
                  detected_format, is_multi_source, is_triage,
                  image_bytes, mime_type, provider, model_id, selected_model,
                  previous_answer, log, lookup_cache, store_cache,
                  images=None, exclude_patterns=None):
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
                    if e.system_label == s["label"]
                    and e.level in ERROR_LEVELS][:3]
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
        source_formats=source_formats,
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

    # --- Noise filtering ---
    noise_threshold = st.session_state.get("noise_threshold_slider", 0.5)
    if noise_threshold > 0:
        from logpilot.analysis import compute_noise_scores, filter_noise
        _noise_scores = compute_noise_scores(events)
        events_for_ai = filter_noise(events, threshold=noise_threshold, noise_scores=_noise_scores)
    else:
        events_for_ai = events

    # --- Exclude filter (keyword-based) ---
    if exclude_patterns:
        events_for_ai, causes = _apply_exclude_filter(events_for_ai, causes, exclude_patterns)
        if log:
            log.info("ai exclude: %d patterns, %d events after filter",
                     len(exclude_patterns), len(events_for_ai))

    # --- Error events ---
    error_events = [e for e in events_for_ai if e.level in ERROR_LEVELS][:5]

    # Use filtered events for AI prompt if noise or exclude filter is active
    if len(events_for_ai) < len(events):
        from logpilot.analysis import summarize as _summarize_fn
        ai_summary = _summarize_fn(events_for_ai, 10)
    else:
        ai_summary = summary

    # --- What Changed? ---
    from logpilot.analysis import compare_periods
    what_changed = compare_periods(events_for_ai)

    # --- Trace to Code (if repo linked) ---
    code_matches_for_ai = None
    _repo_path = st.session_state.get("_code_repo_path", "")
    if _repo_path and _repo_path.strip():
        # Compute if not already cached
        _code_cache_key = f"_code_{len(events_for_ai)}_{_repo_path}"
        if st.session_state.get("_code_cache_key") != _code_cache_key:
            from logpilot.trace_to_code import extract_code_locations
            from logpilot.code_search import search_codebase
            _locations = extract_code_locations(events_for_ai)
            if _locations:
                st.session_state["_code_matches"] = search_codebase(
                    _repo_path, _locations, max_results=30)
            else:
                st.session_state["_code_matches"] = []
            st.session_state["_code_cache_key"] = _code_cache_key
        _cached_matches = st.session_state.get("_code_matches")
        if _cached_matches:
            code_matches_for_ai = [m.to_dict() for m in _cached_matches[:5]]

    # --- User prompt ---
    # Strip exclude sentences from description before sending to AI
    prompt_description = _strip_exclude_sentences(description) if exclude_patterns else description
    user_text = build_incident_user_prompt(
        description=prompt_description,
        summary=ai_summary,
        causes=causes,
        itl=itl,
        error_events=error_events,
        cascades=cascades,
        has_screenshot=image_bytes is not None,
        match_result=match,
        per_source=sources_data,
        per_source_errors=source_errors,
        previous_answer=previous_answer,
        what_changed=what_changed,
        code_matches=code_matches_for_ai,
    )

    # --- Cache ---
    history_label = description or "Log analysis"
    if is_triage:
        cache_key = "triage:" + triage_cache_key(events, model_id)
    else:
        cache_key = f"incident:{provider}:" + incident_cache_key(description, summary, model_id)

    cfg = PROVIDER_CONFIG.get(provider, PROVIDER_CONFIG["claude"])
    session_cache = getattr(st.session_state, cfg["cache_key"], {})

    cached = None
    if lookup_cache and provider != "local" and image_bytes is None:
        cached = lookup_cache(cache_key, session_cache, f"ai/{provider}", history_label[:60])

    if cached:
        _save_to_history(history_label, cached, provider, selected_model)
        st.info("AI analysis loaded from cache.")
        return cached

    # --- Build message and call AI ---
    msg_dict = _build_multimodal_messages(system_prompt, user_text, image_bytes, mime_type, provider, images=images if images and len(images) > 1 else None)

    answer = _run_ai_call(
        provider, model_id, selected_model, msg_dict, image_bytes,
        history_label, cache_key, session_cache, log, store_cache,
    )
    if answer:
        _save_to_history(history_label, answer, provider, selected_model)
    return answer


_HIST_DISK_FILES = {
    "claude": "claude_history.json",
    "gemini": "gemini_history.json",
    "openai": "openai_history.json",
    "local": "local_history.json",
}


def _delete_history_entry(hist_key: str, provider_key: str, idx: int) -> None:
    """Remove a single AI history entry from session state and disk."""
    history = st.session_state.get(hist_key, [])
    if 0 <= idx < len(history):
        history.pop(idx)
        st.session_state[hist_key] = history
        _cache_dir = Path(__file__).parent / "cache"
        _hf = _cache_dir / _HIST_DISK_FILES.get(provider_key, "")
        if _hf.name and _hf.parent.exists():
            try:
                # Atomic write (tempfile + rename) to prevent corruption
                import tempfile, os
                _tmp_name = None
                with tempfile.NamedTemporaryFile(
                    mode="w", dir=_hf.parent, suffix=".tmp",
                    delete=False, encoding="utf-8",
                ) as tmp:
                    _tmp_name = tmp.name
                    json.dump(history, tmp, ensure_ascii=False)
                    tmp.flush()
                    os.fsync(tmp.fileno())
                if _tmp_name:
                    os.replace(_tmp_name, str(_hf))
            except OSError:
                if _tmp_name:
                    try:
                        os.unlink(_tmp_name)
                    except OSError:
                        pass


def process_pending_delete():
    """Process any pending AI history deletion. Call early in the render cycle."""
    _pending = st.session_state.pop("_pending_hist_delete", None)
    if _pending:
        _delete_history_entry(_pending["hist_key"], _pending["provider_key"], _pending["idx"])


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
        display_hist = [(i, h) for i, h in enumerate(history) if h.get("answer") != current]
        if not display_hist:
            continue
        st.markdown("---")
        for orig_idx, entry in reversed(display_hist):
            query_preview = entry.get("query", "")[:80]
            provider_label = entry.get("provider", label)
            ts = entry.get("timestamp", "")
            # Delete button OUTSIDE expander to avoid Streamlit key issues
            col_exp, col_del = st.columns([12, 1])
            with col_exp:
                with st.expander(f"{provider_label} — {query_preview} ({ts})"):
                    _render_claude_response(entry["answer"])
            with col_del:
                if st.button("🗑️", key=f"del_{hist_key}_{orig_idx}",
                             help="Remove this response"):
                    st.session_state["_pending_hist_delete"] = {
                        "hist_key": hist_key,
                        "provider_key": provider_key,
                        "idx": orig_idx,
                    }
                    st.rerun()
