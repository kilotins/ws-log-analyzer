"""Streamlit GUI for the WebSphere Log Analyzer."""
from __future__ import annotations

import html
import logging
import logging.handlers
import os
import re as _re
import streamlit as st
from collections import deque
from datetime import datetime
from pathlib import Path

from wslog import (
    parse_file, summarize, render_markdown_report, render_json_report,
    render_pdf_report, render_csv_report, render_xml_report, per_file_summary, time_histogram,
    render_histogram, pick_samples, likely_causes, suggested_splunk_queries,
    hung_thread_drilldown, precompute_analysis,
    match_user_query, build_claude_prompt, claude_cache_key,
    incident_timeline, SWEDISH_CHEF_STYLE, ask_gemini,
)

_APP_DIR = Path(__file__).parent
UPLOADS_DIR = _APP_DIR / "uploads"
REPORTS_DIR = _APP_DIR / "reports"
CACHE_DIR = _APP_DIR / "cache"
LOGS_DIR = _APP_DIR / "logs"
UPLOADS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
CACHE_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

LOG_FILE = LOGS_DIR / "app.log"

def _setup_logging():
    """Configure application logging with rotating file handler."""
    logger = logging.getLogger("wslog_app")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-5s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(handler)
    return logger

log = _setup_logging()
log.info("startup Application started")

CACHE_FILE = CACHE_DIR / "ai_responses.json"
# Migrate old cache file name
_old_cache = CACHE_DIR / "claude_responses.json"
if _old_cache.exists() and not (CACHE_DIR / "ai_responses.json").exists():
    _old_cache.rename(CACHE_FILE)
HISTORY_FILE = CACHE_DIR / "claude_history.json"
GEMINI_HISTORY_FILE = CACHE_DIR / "gemini_history.json"


MAX_CACHE_ENTRIES = 100
MAX_HISTORY_ENTRIES = 50


def _load_json_file(path: Path, default: object) -> object:
    """Load a JSON file, returning default on error."""
    if path.exists():
        try:
            import json
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return default


def _save_json_file(path: Path, data: object) -> None:
    """Save data as JSON."""
    import json
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_file_cache():
    return _load_json_file(CACHE_FILE, {})


def _save_file_cache(cache):
    # Evict oldest entries if over limit
    if len(cache) > MAX_CACHE_ENTRIES:
        keys = list(cache.keys())
        for k in keys[:len(keys) - MAX_CACHE_ENTRIES]:
            del cache[k]
    _save_json_file(CACHE_FILE, cache)


OPENAI_HISTORY_FILE = CACHE_DIR / "openai_history.json"


def _load_provider_history(path: Path) -> list[dict]:
    """Load provider history from a JSON file."""
    data = _load_json_file(path, [])
    return data if isinstance(data, list) else []


def _save_provider_history(path: Path, history: list[dict]) -> None:
    """Save provider history, keeping only the most recent entries."""
    _save_json_file(path, history[-MAX_HISTORY_ENTRIES:])


# Provider history file paths — keyed by provider name
_PROVIDER_HISTORY_FILES = {
    "claude": HISTORY_FILE,
    "gemini": GEMINI_HISTORY_FILE,
    "openai": OPENAI_HISTORY_FILE,
}


# --- Session state defaults ---
_STATE_DEFAULTS = {
    "analysis": None,           # dict with all analysis results
    "claude_answer": None,      # last Claude response
    "claude_query_label": None, # query that produced the Claude answer
    "claude_cache": {},         # cache key -> response text
    "claude_history": [],       # list of {query, answer, splunk_queries, timestamp}
    "selected_code": None,      # code selected via any action button
    "selected_action": None,    # "copy" | "claude" | "splunk"
    "api_key": "",              # Anthropic API key (entered via sidebar)
    "gemini_api_key": "",        # Google Gemini API key
    "openai_api_key": "",        # OpenAI API key
    "gemini_answer": None,       # last Gemini response
    "gemini_query_label": None,  # query that produced the Gemini answer
    "gemini_cache": {},          # cache key -> response text
    "gemini_history": [],        # list of {query, answer, timestamp}
    "openai_answer": None,       # last OpenAI response
    "openai_query_label": None,  # query that produced the OpenAI answer
    "openai_cache": {},          # cache key -> response text
    "openai_history": [],        # list of {query, answer, timestamp}
    "debug_payload": False,     # Show AI API request/response payloads
    "last_ai_call_ts": 0.0,     # Timestamp of last AI API call (rate limiting)
    "swedish_chef": False,      # Swedish Chef response style
    "rt_enabled": False,        # Realtime log monitoring toggle
    "rt_running": False,        # Monitoring is actively polling
    "rt_paused": False,         # Monitoring is paused (keep offset)
    "rt_file": "",              # Path to monitored file
    "rt_offset": 0,             # Current file read offset (bytes)
    "rt_buffer": None,          # deque of recent lines (set in init)
}
_RT_BUFFER_SIZE = 300

for key, default in _STATE_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = default
if st.session_state.rt_buffer is None:
    st.session_state.rt_buffer = deque(maxlen=_RT_BUFFER_SIZE)

# Load persisted history on fresh session
for _prov, _hpath in _PROVIDER_HISTORY_FILES.items():
    _hkey = f"{_prov}_history" if _prov != "claude" else "claude_history"
    if not st.session_state[_hkey]:
        st.session_state[_hkey] = _load_provider_history(_hpath)


def get_report_history(limit=20):
    """Return list of (path, mtime) for recent reports, newest first."""
    reports = sorted(REPORTS_DIR.glob("report_*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    return reports[:limit]


# --- Section renderers ---

def _on_copy_code(code):
    """Copy an error code into the AI query input field."""
    st.session_state.claude_query_input = code


def render_code_row(code, count):
    """Render a message code row with count and a copy-to-query button."""
    cols = st.columns([3, 1])
    with cols[0]:
        st.text(f"  {count:>4}  {code}")
    with cols[1]:
        st.button("Ask AI",
                  key=f"ask_{code}",
                  on_click=_on_copy_code, args=(code,),
                  help=f"Copy {code} to the AI query field below")


def render_summary(s, error_count, file_count, file_summary):
    """Render metrics, top exceptions, codes, levels, and per-file breakdown."""
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Events", s["total_events"])
    m2.metric("Errors", error_count)
    m3.metric("Files", file_count)
    level_counts = dict(s["levels"])
    m4.metric("Warnings", level_counts.get("WARNING", 0))

    if len(file_summary) > 1:
        st.subheader("Per-File Breakdown")
        for fname, total, errors in file_summary:
            err_note = f" ({errors} errors)" if errors else ""
            st.text(f"  {Path(fname).name}: {total} events{err_note}")

    exc_col, code_col = st.columns(2)
    with exc_col:
        st.subheader("Top Exceptions")
        if s["exceptions"]:
            for name, count in s["exceptions"]:
                st.text(f"  {count:>4}  {name}")
        else:
            st.caption("None detected")
    with code_col:
        st.subheader("Top Message Codes")
        if s["codes"]:
            for code, count in s["codes"]:
                render_code_row(code, count)
        else:
            st.caption("None detected")

    if s["tags"]:
        st.subheader("Signal Tags")
        for tag, count in s["tags"]:
            st.text(f"  {count:>4}  {tag}")


def _looks_like_splunk(code):
    """Heuristic: does this code block look like a Splunk query?"""
    lower = code.lower()
    return any(kw in lower for kw in ("index=", "sourcetype=", "| timechart", "| stats",
                                       "| table", "| where", "| eval"))


def _split_combined_splunk(code):
    """Split a code block containing multiple -- separated Splunk queries.

    Returns list of {description, query} dicts. If no -- separators found,
    returns a single entry.
    """
    # Split on lines starting with "-- "
    chunks = _re.split(r'^-- +', code, flags=_re.MULTILINE)
    if len(chunks) <= 1:
        return [{"description": "Splunk query", "query": code.strip()}]

    results = []
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        lines = chunk.split("\n", 1)
        desc = lines[0].strip()
        query = lines[1].strip() if len(lines) > 1 else ""
        if query and _looks_like_splunk(query):
            results.append({"description": desc, "query": query})
    return results


def _extract_splunk_from_response(text):
    """Extract Splunk queries from a Claude response.

    Returns list of {description, query} dicts.
    """
    results = []
    parts = _re.split(r'(```[^\n]*\n.*?\n```)', text, flags=_re.DOTALL)
    for i, part in enumerate(parts):
        code_match = _re.match(r'```(\w*)\n(.*?)\n```$', part, flags=_re.DOTALL)
        if not code_match:
            continue
        lang = code_match.group(1).lower()
        code = code_match.group(2).strip()
        if lang in ("spl", "splunk", "") and _looks_like_splunk(code):
            # Split combined queries (-- separated) into individual entries
            split = _split_combined_splunk(code)
            if len(split) > 1:
                results.extend(split)
            else:
                # Single query — use preceding text as description
                desc = ""
                if i > 0:
                    prev = parts[i - 1].strip()
                    for line in reversed(prev.splitlines()):
                        line = line.strip().strip("*").strip("#").strip()
                        if line:
                            desc = line
                            break
                results.append({"description": desc or "Splunk query", "query": code})
    return results


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
    """Render a clickable Swedish Chef image that plays a random sound clip.

    All clips are embedded as a JS array so randomization happens
    client-side on each click — not at render time.
    """
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
        // Pick a random clip, avoid repeating the same one twice in a row
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


def _render_claude_response(text):
    """Render Claude response with separate copyable blocks for each Splunk query."""
    parts = _re.split(r'(```[^\n]*\n.*?\n```)', text, flags=_re.DOTALL)
    for part in parts:
        code_match = _re.match(r'```(\w*)\n(.*?)\n```$', part, flags=_re.DOTALL)
        if code_match:
            lang = code_match.group(1).lower()
            code = code_match.group(2).strip()
            if lang in ("spl", "splunk", "") and _looks_like_splunk(code):
                # Split combined queries (-- separated) into individual cards
                queries = _split_combined_splunk(code)
                if len(queries) > 1:
                    for sq in queries:
                        st.markdown(f"**{sq['description']}**")
                        st.code(sq["query"], language="spl")
                else:
                    st.code(code, language="spl")
            else:
                st.code(code, language=lang or None)
        else:
            stripped = part.strip()
            if stripped:
                st.markdown(stripped)


def render_likely_causes(causes):
    """Render likely causes section."""
    if causes:
        for c in causes:
            st.markdown(f"**{c['title']}** ({c['count']} event{'s' if c['count'] != 1 else ''})")
            st.markdown(f"*Likely cause:* {c['cause']}")
            for fix in c["fixes"]:
                st.markdown(f"- {fix}")
    else:
        st.caption("No known issue patterns detected.")


def _on_ask_claude_click():
    """Callback: mark that the user clicked Analyze with Claude."""
    st.session_state._ask_claude_pending = True


def _on_ask_gemini_click():
    """Callback: mark that the user clicked Ask Gemini."""
    st.session_state._ask_gemini_pending = True


def _on_ask_openai_click():
    """Callback: mark that the user clicked Ask GPT."""
    st.session_state._ask_openai_pending = True


def build_ai_request_context(user_query: str, events: list[dict], provider: str = "claude") -> dict:
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
    if skills:
        log.info("skills %s selected skills: %s", provider, ", ".join(skills))
    return match, cache_key, prompt


def _lookup_cache(cache_key, session_cache, provider_label, user_query):
    """Check session cache then file cache. Returns cached value or None."""
    log.info("cache %s looking up key: %s", provider_label, cache_key[:80])
    cached = session_cache.get(cache_key)
    if cached:
        log.info("cache %s session cache HIT for: %s", provider_label, user_query[:60])
        return cached
    file_cache = _load_file_cache()
    cached = file_cache.get(cache_key)
    if cached:
        log.info("cache %s file cache HIT for: %s", provider_label, user_query[:60])
        session_cache[cache_key] = cached
        return cached
    log.info("cache %s MISS for: %s", provider_label, user_query[:60])
    return None


def _store_cache(cache_key, answer, session_cache):
    """Store answer in both session and file cache."""
    session_cache[cache_key] = answer
    file_cache = _load_file_cache()
    file_cache[cache_key] = answer
    _save_file_cache(file_cache)


# --- Provider configuration for the common AI orchestrator ---
_PROVIDER_CONFIG = {
    "claude": {
        "label": "Claude",
        "cache_key": "claude_cache",
        "answer_key": "claude_answer",
        "query_label_key": "claude_query_label",
        "history_key": "claude_history",
        "api_key_field": "api_key",
        "save_history": lambda hist: _save_provider_history(HISTORY_FILE, hist),
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
        "save_history": lambda hist: _save_provider_history(GEMINI_HISTORY_FILE, hist),
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
        "save_history": lambda hist: _save_provider_history(OPENAI_HISTORY_FILE, hist),
        "extract_splunk": False,
        "api_key_error": "Enter your OpenAI API key in the sidebar or set OPENAI_API_KEY env var.",
        "api_key_prefix": "sk-",
    },
}


# Approximate cost per 1M tokens (input, output) in USD
_TOKEN_COSTS = {
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


def _estimate_cost(model_id: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate cost in USD given model and token counts."""
    costs = _TOKEN_COSTS.get(model_id, (0, 0))
    return (input_tokens * costs[0] + output_tokens * costs[1]) / 1_000_000


def _call_claude_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None) -> tuple[str, dict]:
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


def _call_gemini_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None) -> tuple[str, dict]:
    """Make the actual Gemini API call. Returns (answer, usage_dict). Streaming not supported."""
    answer = ask_gemini(prompt["user"], api_key=api_key, system=prompt["system"], model=model_id)
    return (answer or None, {})


def _call_openai_api(api_key: str, model_id: str, prompt: dict, stream_placeholder=None) -> tuple[str, dict]:
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
    "claude": _call_claude_api,
    "gemini": _call_gemini_api,
    "openai": _call_openai_api,
}


_AI_RATE_LIMIT_SECONDS = 2.0  # Minimum seconds between AI API calls


def _run_ai_analysis(provider: str, model_id: str, user_query: str, events: list[dict], processing_container) -> None:
    """Common AI analysis orchestrator. Handles caching, history, and error display."""
    import time as _time
    now = _time.time()
    elapsed = now - st.session_state.last_ai_call_ts
    if elapsed < _AI_RATE_LIMIT_SECONDS:
        st.warning(f"Rate limit: wait {_AI_RATE_LIMIT_SECONDS - elapsed:.0f}s before next AI call.")
        return
    st.session_state.last_ai_call_ts = now

    cfg = _PROVIDER_CONFIG[provider]
    label = cfg["label"]

    log.info("%s Ask %s request: %s", provider, label, user_query[:100])
    with processing_container:
        status = st.status(f"Analyzing with {label}...", expanded=True)

    match, cache_key, prompt = build_ai_request_context(user_query, events, provider)
    session_cache = getattr(st.session_state, cfg["cache_key"])

    cached = _lookup_cache(cache_key, session_cache, label, user_query)

    def _record_answer(answer):
        setattr(st.session_state, cfg["answer_key"], answer)
        setattr(st.session_state, cfg["query_label_key"], user_query)
        entry = {
            "query": user_query,
            "answer": answer,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }
        if cfg["extract_splunk"]:
            entry["splunk_queries"] = _extract_splunk_from_response(answer)
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
        status.write(f"No exact match — sending general question to {label}.")

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

    if st.session_state.debug_payload:
        with st.expander(f"{label} request payload", expanded=False):
            import json as _json
            st.code(f"[SYSTEM]\n{prompt['system']}\n\n[USER]\n{prompt['user']}", language="text")

    log.info("cache Cache miss — calling %s API for: %s", label, user_query[:60])
    status.write(f"Calling {label} API...")
    stream_placeholder = st.empty()  # for streaming text display
    try:
        caller = _API_CALLERS[provider]
        answer, usage = caller(api_key, model_id, prompt, stream_placeholder=stream_placeholder)
        if not answer:
            log.warning("%s %s returned empty response for: %s", provider, label, user_query[:60])
            status.update(label=f"Empty response from {label}", state="error")
            return
        log.info("%s %s response received (%d chars) for: %s",
                 provider, label, len(answer), user_query[:60])
        if st.session_state.debug_payload:
            with st.expander(f"{label} response payload", expanded=False):
                st.code(answer, language="markdown")
        stream_placeholder.empty()  # clear streaming display
        _record_answer(answer)
        _store_cache(cache_key, answer, session_cache)
        # Display token usage and cost
        cost_info = ""
        if usage:
            inp = usage.get("input", 0)
            out = usage.get("output", 0)
            cost = _estimate_cost(model_id, inp, out)
            cost_info = f" — {inp:,}+{out:,} tokens (~${cost:.4f})"
            log.info("%s tokens: %d in / %d out, est cost: $%.4f", label, inp, out, cost)
        status.update(label=f"{label} analysis complete{cost_info}", state="complete")
    except ImportError as ex:
        status.update(label="Missing package", state="error")
        st.error(str(ex))
    except Exception as ex:
        log.error("%s %s API error: %s", provider, label, ex)
        if st.session_state.debug_payload:
            with st.expander(f"{label} error details", expanded=True):
                st.code(str(ex), language="text")
        status.update(label=f"{label} API error: {ex}", state="error")


def run_claude_analysis(user_query, events, processing_container, model_id="claude-sonnet-4-6"):
    """Run Claude API analysis with caching."""
    _run_ai_analysis("claude", model_id, user_query, events, processing_container)


def run_gemini_analysis(user_query, events, processing_container, model_id="gemini-2.5-flash"):
    """Run Gemini API analysis with caching."""
    _run_ai_analysis("gemini", model_id, user_query, events, processing_container)


def run_openai_analysis(user_query, events, processing_container, model_id="gpt-4o"):
    """Run OpenAI API analysis with caching."""
    _run_ai_analysis("openai", model_id, user_query, events, processing_container)


def render_current_ai_analyses():
    """Render expanders for current Claude, Gemini, and GPT results."""
    _has_claude = bool(st.session_state.claude_answer)
    _has_gemini = bool(st.session_state.gemini_answer)
    _has_openai = bool(st.session_state.openai_answer)
    if not _has_claude and not _has_gemini and not _has_openai:
        return

    # Expand the most recently added one
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
        expander_title = f"🍳 Zee Chef's analysis — {label}" if st.session_state.swedish_chef else f"Claude analysis — {label}"
        with st.expander(expander_title, expanded=_expand_claude):
            if st.session_state.swedish_chef:
                _render_chef_sound_button()
            _render_claude_response(st.session_state.claude_answer)

    if _has_gemini:
        label = st.session_state.gemini_query_label or "query"
        with st.expander(f"Gemini analysis — {label}", expanded=_expand_gemini):
            st.markdown(st.session_state.gemini_answer)

    if _has_openai:
        label = st.session_state.openai_query_label or "query"
        _chef_openai = st.session_state.swedish_chef
        expander_title = f"🍳 Zee Chef's analysis — {label}" if _chef_openai else f"GPT analysis — {label}"
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
        for h_idx, entry in enumerate(reversed(claude_history[:-1])):
            hist_label = f"Claude — {entry['query']} ({entry['timestamp']})"
            with st.expander(hist_label):
                if st.session_state.swedish_chef:
                    _render_chef_sound_button()
                _render_claude_response(entry["answer"])

    gemini_history = st.session_state.gemini_history
    if len(gemini_history) > 1:
        st.markdown("---")
        st.subheader("Previous Gemini queries")
        for g_idx, entry in enumerate(reversed(gemini_history[:-1])):
            hist_label = f"Gemini — {entry['query']} ({entry['timestamp']})"
            with st.expander(hist_label):
                st.markdown(entry["answer"])

    openai_history = st.session_state.openai_history
    if len(openai_history) > 1:
        _chef_hist = st.session_state.swedish_chef
        st.markdown("---")
        st.subheader("🍳 Previöoos Chef queries" if _chef_hist else "Previous GPT queries")
        for o_idx, entry in enumerate(reversed(openai_history[:-1])):
            if _chef_hist:
                hist_label = f"🍳 Zee Chef — {entry['query']} ({entry['timestamp']})"
            else:
                hist_label = f"GPT — {entry['query']} ({entry['timestamp']})"
            with st.expander(hist_label):
                if _chef_hist:
                    _render_chef_sound_button()
                st.markdown(entry["answer"])


def render_ask_claude(events):
    """Render AI analysis input, API calls, and response history."""
    _AI_MODELS = {
        "Claude Sonnet 4.6": {"provider": "claude", "model_id": "claude-sonnet-4-6"},
        "Claude Haiku 4.5": {"provider": "claude", "model_id": "claude-haiku-4-5-20251001"},
        "Gemini 2.5 Flash": {"provider": "gemini", "model_id": "gemini-2.5-flash"},
        "Gemini 2.5 Pro": {"provider": "gemini", "model_id": "gemini-2.5-pro-preview-06-05"},
        "GPT-4o": {"provider": "openai", "model_id": "gpt-4o"},
        "GPT-4o mini": {"provider": "openai", "model_id": "gpt-4o-mini"},
        "Swedish Chef": {"provider": "openai_chef", "model_id": "gpt-4o-mini"},
    }

    user_query = st.text_input(
        "Ask an AI assistant about an error code, exception, or troubleshooting question",
        placeholder="e.g. CWPKI0022E, SSLHandshakeException, why are threads hanging?",
        key="claude_query_input",
    )

    col_model, col_btn = st.columns([2, 1])
    with col_model:
        selected_model = st.selectbox(
            "AI Model",
            list(_AI_MODELS.keys()),
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

    # Swedish Chef mode is driven by the model dropdown selection
    _model_info = _AI_MODELS.get(selected_model, {})
    _is_chef = _model_info.get("provider") == "openai_chef"
    st.session_state.swedish_chef = _is_chef

    processing_container = st.container()

    if user_query and analyze_clicked:
        provider = _model_info.get("provider", "claude")
        model_id = _model_info.get("model_id", "")
        if provider == "claude":
            run_claude_analysis(user_query, events, processing_container, model_id=model_id)
        elif provider == "gemini":
            run_gemini_analysis(user_query, events, processing_container, model_id=model_id)
        else:
            # Both "openai" and "openai_chef" route to OpenAI
            run_openai_analysis(user_query, events, processing_container, model_id=model_id)

    # Also handle pending actions from Ask AI button clicks on code rows
    pending = st.session_state.pop("_ask_claude_pending", False)
    gemini_pending = st.session_state.pop("_ask_gemini_pending", False)
    openai_pending = st.session_state.pop("_ask_openai_pending", False)
    if user_query and pending:
        run_claude_analysis(user_query, events, processing_container)
    if user_query and gemini_pending:
        run_gemini_analysis(user_query, events, processing_container)
    if user_query and openai_pending:
        run_openai_analysis(user_query, events, processing_container)

    render_current_ai_analyses()
    render_ai_history()


def _render_splunk_query(sq, idx):
    """Render a single Splunk query as a numbered card."""
    st.markdown(f"**{idx}. {sq['description']}**")
    st.code(sq["query"], language="spl")


def render_splunk_section(splunk):
    """Render baseline Splunk searches + Claude-enhanced searches from history."""
    # --- Baseline searches ---
    st.subheader("Baseline searches")
    if splunk:
        for idx, sq in enumerate(splunk, 1):
            _render_splunk_query(sq, idx)
    else:
        st.caption("No baseline Splunk queries generated.")

    # --- Claude-enhanced searches ---
    history = st.session_state.claude_history
    entries_with_splunk = [e for e in history if e.get("splunk_queries")]
    if entries_with_splunk:
        st.markdown("---")
        st.subheader("Claude-enhanced searches")
        for h_idx, entry in enumerate(entries_with_splunk):
            st.markdown(f"***{entry['query']}** ({entry['timestamp']})*")
            for q_idx, sq in enumerate(entry["splunk_queries"], 1):
                _render_splunk_query(sq, q_idx)
    else:
        st.markdown("---")
        st.caption("Run an AI analysis to get context-aware Splunk searches.")


def render_hung_threads(hung):
    """Render hung thread drilldown."""
    if not hung:
        st.caption("No hung threads detected.")
        return
    for t in hung:
        st.markdown(f"**{t['thread_name']}** ({t['count']} occurrence{'s' if t['count'] != 1 else ''})")
        ts_parts = []
        if t["first_ts"]:
            ts_parts.append(f"First: {t['first_ts']}")
        if t["last_ts"] and t["last_ts"] != t["first_ts"]:
            ts_parts.append(f"Last: {t['last_ts']}")
        if t["hex_ids"]:
            ts_parts.append(f"Thread IDs: {', '.join('0x' + h for h in t['hex_ids'])}")
        if ts_parts:
            st.text("  " + " | ".join(ts_parts))
        if t["stack_sample"]:
            st.code("\n".join(t["stack_sample"]), language="java")
        st.code(t["splunk_query"], language="spl")


def render_timeline(hist):
    """Render timeline histogram."""
    if hist:
        lines = render_histogram(hist)
        st.code("\n".join(lines))
    else:
        st.caption("No timestamped events.")


def render_incident_timeline(itl):
    """Render an incident timeline using Plotly."""
    if not itl:
        st.caption("No error events with timestamps found.")
        return

    import plotly.graph_objects as go

    trigger = itl["trigger_event"]
    trigger_dt = itl["trigger_dt"]
    window_events = itl["window_events"]

    # Build data for the chart
    times = []
    labels = []
    colors = []
    sizes = []
    hovers = []

    level_colors = {
        "FATAL": "#dc3545",
        "ERROR": "#dc3545",
        "SEVERE": "#dc3545",
        "WARNING": "#ffc107",
        "WARN": "#ffc107",
        "INFO": "#0d6efd",
        "AUDIT": "#6c757d",
        "DEBUG": "#adb5bd",
    }

    for w in window_events:
        e = w["event"]
        dt = w["dt"]
        level = e.get("level") or "UNKNOWN"
        is_trigger = (e is trigger)

        times.append(dt)
        code_label = e.get("code") or ""
        exc_label = (e.get("exception") or "").rsplit(".", 1)[-1] if e.get("exception") else ""
        label = f"{level} {code_label} {exc_label}".strip()
        labels.append(label)
        colors.append(level_colors.get(level, "#6c757d"))
        sizes.append(16 if is_trigger else 9)

        offset = w["offset_seconds"]
        sign = "+" if offset >= 0 else ""
        hover = (
            f"<b>{level}</b> {sign}{offset:.1f}s<br>"
            f"Time: {dt.strftime('%H:%M:%S.%f')[:-3]}<br>"
        )
        if code_label:
            hover += f"Code: {code_label}<br>"
        if exc_label:
            hover += f"Exception: {exc_label}<br>"
        if e.get("thread_id"):
            hover += f"Thread: 0x{e['thread_id']}<br>"
        text_preview = (e.get("text") or "")[:120].replace("<", "&lt;")
        if text_preview:
            hover += f"<br>{text_preview}..."
        hovers.append(hover)

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=times,
        y=labels,
        mode="markers",
        marker=dict(color=colors, size=sizes, line=dict(width=1, color="white")),
        hovertext=hovers,
        hoverinfo="text",
    ))

    # Mark the trigger event with a vertical line
    fig.add_shape(
        type="line",
        x0=trigger_dt, x1=trigger_dt,
        y0=0, y1=1,
        yref="paper",
        line=dict(dash="dash", color="#dc3545", width=1),
    )
    fig.add_annotation(
        x=trigger_dt, y=1, yref="paper",
        text="First error", showarrow=False,
        font=dict(color="#dc3545", size=11),
        yshift=10,
    )

    fig.update_layout(
        title="",
        xaxis_title="Time",
        yaxis_title=None,
        height=max(250, len(set(labels)) * 35 + 100),
        margin=dict(l=10, r=10, t=30, b=40),
        showlegend=False,
        xaxis=dict(type="date"),
        yaxis=dict(autorange="reversed"),
    )

    trigger_code = trigger.get("code") or ""
    trigger_exc = (trigger.get("exception") or "").rsplit(".", 1)[-1]
    trigger_label = f"{trigger.get('level')} {trigger_code} {trigger_exc}".strip()
    st.caption(
        f"Showing {len(window_events)} events within "
        f"±{itl['window_seconds']}s of first error: "
        f"**{trigger_label}** at {trigger_dt.strftime('%H:%M:%S.%f')[:-3]}"
    )
    st.plotly_chart(fig, use_container_width=True)


def render_samples(samples):
    """Render sample events."""
    if not samples:
        st.caption("No events to display.")
        return
    for idx, e in enumerate(samples, start=1):
        header = f"{idx}. {e['level'] or 'UNKNOWN'}"
        if e["code"]:
            header += f" {e['code']}"
        if e["exception"]:
            header += f" -- {e['exception']}"
        if e["ts"]:
            header += f" ({e['ts']})"
        st.markdown(f"**{header}**")
        parts = []
        if e["tags"]:
            parts.append(f"Tags: {', '.join(e['tags'])}")
        if e["thread_id"]:
            parts.append(f"Thread: 0x{e['thread_id']}")
        if e["root_cause"] and e["root_cause"] != e["exception"]:
            parts.append(f"Root cause: {e['root_cause']}")
        if parts:
            st.text("  " + " | ".join(parts))
        st.code(e["text"][:4000], language="text")


def render_report_sections(a):
    """Render all report sections from persisted analysis dict."""
    st.success(f"Parsed {a['total_events']} events from {a['file_count']} file(s). "
               f"Report saved as `{a['report_name']}`.")

    dl1, dl2, dl3, dl4, dl5 = st.columns(5)
    with dl1:
        st.download_button(
            label="Download Markdown",
            data=a["report_md"],
            file_name=a["report_name"],
            mime="text/markdown",
        )
    with dl2:
        st.download_button(
            label="Download JSON",
            data=a["report_json"],
            file_name=a["report_name"].replace(".md", ".json"),
            mime="application/json",
        )
    with dl3:
        st.download_button(
            label="Download PDF",
            data=a["report_pdf"],
            file_name=a["report_name"].replace(".md", ".pdf"),
            mime="application/pdf",
        )
    with dl4:
        if a.get("report_csv"):
            st.download_button(
                label="Download CSV",
                data=a["report_csv"],
                file_name=a["report_name"].replace(".md", ".csv"),
                mime="text/csv",
            )
    with dl5:
        if a.get("report_xml"):
            st.download_button(
                label="Download XML",
                data=a["report_xml"],
                file_name=a["report_name"].replace(".md", ".xml"),
                mime="application/xml",
            )

    st.markdown("---")

    with st.expander("Summary", expanded=True):
        render_summary(a["summary"], a["error_count"], a["file_count"], a["file_summary"])

    if a["causes"]:
        with st.expander(f"Likely Causes & Fixes ({len(a['causes'])} detected)"):
            render_likely_causes(a["causes"])

    with st.expander("Ask AI for help", expanded=True):
        render_ask_claude(a["events"])

    claude_splunk_count = sum(len(e.get("splunk_queries", []))
                               for e in st.session_state.claude_history)
    splunk_label = f"Suggested Splunk Searches ({len(a['splunk'])} baseline"
    if claude_splunk_count:
        splunk_label += f" + {claude_splunk_count} Claude"
    splunk_label += ")"
    with st.expander(splunk_label):
        render_splunk_section(a["splunk"])

    with st.expander(f"Hung Thread Analysis ({len(a['hung'])} threads)"):
        render_hung_threads(a["hung"])

    with st.expander("Timeline"):
        render_timeline(a["hist"])

    itl = a.get("incident_timeline")
    itl_label = "Incident Timeline"
    if itl:
        n = len(itl["window_events"])
        itl_label += f" ({n} events around first error)"
    with st.expander(itl_label):
        render_incident_timeline(itl)

    with st.expander(f"Event Samples ({len(a['samples'])} shown)"):
        render_samples(a["samples"])


# --- Streamlit UI ---

st.set_page_config(page_title="WS Log Analyzer", page_icon="📋", layout="wide")
st.title("WebSphere Log Analyzer")

# --- Sidebar: API key ---
_KEYRING_SERVICE = "ws-log-analyzer"
_KEYRING_USERNAME = "anthropic_api_key"
_KEYRING_GEMINI_USERNAME = "gemini_api_key"
_KEYRING_OPENAI_USERNAME = "openai_api_key"


_KEYS_FILE = CACHE_DIR / ".api_keys.json"


def _load_keychain(username: str, env_var: str) -> str:
    """Load an API key from keyring → local file → env var → empty string."""
    # 1. Try system keyring (macOS Keychain, etc.)
    try:
        import keyring
        stored = keyring.get_password(_KEYRING_SERVICE, username)
        if stored:
            return stored
    except Exception:
        pass
    # 2. Try local encrypted file
    try:
        keys = _load_json_file(_KEYS_FILE, {})
        if isinstance(keys, dict) and keys.get(username):
            return keys[username]
    except Exception:
        pass
    # 3. Fall back to environment variable
    return os.environ.get(env_var, "")


def _save_keychain(username: str, key: str, label: str = "API") -> None:
    """Store or remove an API key in keyring + local file."""
    # Save to system keyring
    try:
        import keyring
        if key:
            keyring.set_password(_KEYRING_SERVICE, username, key)
            log.info("settings %s key saved to system keychain", label)
        else:
            keyring.delete_password(_KEYRING_SERVICE, username)
            log.info("settings %s key removed from system keychain", label)
    except Exception as ex:
        log.warning("settings Could not save %s key to keychain: %s", label, ex)
    # Also save to local file as fallback
    try:
        keys = _load_json_file(_KEYS_FILE, {})
        if not isinstance(keys, dict):
            keys = {}
        if key:
            keys[username] = key
        else:
            keys.pop(username, None)
        _save_json_file(_KEYS_FILE, keys)
        # Restrict file permissions (owner-only)
        _KEYS_FILE.chmod(0o600)
        log.info("settings %s key saved to local file", label)
    except Exception as ex:
        log.warning("settings Could not save %s key to local file: %s", label, ex)


def _load_saved_api_key():
    return _load_keychain(_KEYRING_USERNAME, "ANTHROPIC_API_KEY")


def _save_api_key(key):
    _save_keychain(_KEYRING_USERNAME, key, "Claude")


def _load_saved_gemini_key():
    return _load_keychain(_KEYRING_GEMINI_USERNAME, "GEMINI_API_KEY")


def _save_gemini_key(key):
    _save_keychain(_KEYRING_GEMINI_USERNAME, key, "Gemini")


def _load_saved_openai_key():
    return _load_keychain(_KEYRING_OPENAI_USERNAME, "OPENAI_API_KEY")


def _save_openai_key(key):
    _save_keychain(_KEYRING_OPENAI_USERNAME, key, "OpenAI")


# Initialize from saved key on first load
if not st.session_state.api_key:
    st.session_state.api_key = _load_saved_api_key()

with st.sidebar:
    st.header("Settings")
    api_key = st.text_input(
        "Anthropic API Key",
        value=st.session_state.api_key,
        type="password",
        placeholder="sk-ant-...",
        help="Required for Ask Claude. Get a key at console.anthropic.com/settings/keys",
    )
    if api_key != st.session_state.api_key:
        _save_api_key(api_key)
    st.session_state.api_key = api_key
    if api_key:
        st.success("API key set")
    else:
        st.caption("Enter your key to enable Ask Claude")

    if not st.session_state.gemini_api_key:
        st.session_state.gemini_api_key = _load_saved_gemini_key()
    gemini_key = st.text_input(
        "Gemini API Key",
        value=st.session_state.gemini_api_key,
        type="password",
        placeholder="AIza...",
        help="Required for Ask Gemini. Get a key at aistudio.google.com/apikey",
    )
    if gemini_key != st.session_state.gemini_api_key:
        _save_gemini_key(gemini_key)
    st.session_state.gemini_api_key = gemini_key
    if gemini_key:
        st.success("Gemini API key set")
    else:
        st.caption("Enter your key or set GEMINI_API_KEY env var")

    if not st.session_state.openai_api_key:
        st.session_state.openai_api_key = _load_saved_openai_key()
    openai_key = st.text_input(
        "OpenAI API Key",
        value=st.session_state.openai_api_key,
        type="password",
        placeholder="sk-...",
        help="Required for OpenAI models. Get a key at platform.openai.com/api-keys",
    )
    if openai_key != st.session_state.openai_api_key:
        _save_openai_key(openai_key)
    st.session_state.openai_api_key = openai_key
    if openai_key:
        st.success("OpenAI API key set")
    else:
        st.caption("Enter your key or set OPENAI_API_KEY env var")

    st.markdown("---")
    st.session_state.debug_payload = st.toggle(
        "Enable AI debug payloads",
        value=st.session_state.debug_payload,
        help="Show request/response payloads for Claude and Gemini API calls",
    )
    if st.button("Clear AI cache", help="Clear cached Claude/Gemini/OpenAI responses and history"):
        st.session_state.claude_cache = {}
        st.session_state.claude_answer = None
        st.session_state.claude_query_label = None
        st.session_state.claude_history = []
        st.session_state.gemini_cache = {}
        st.session_state.gemini_answer = None
        st.session_state.gemini_query_label = None
        st.session_state.gemini_history = []
        st.session_state.openai_cache = {}
        st.session_state.openai_answer = None
        st.session_state.openai_query_label = None
        st.session_state.openai_history = []
        if CACHE_FILE.exists():
            CACHE_FILE.unlink()
        for _hpath in _PROVIDER_HISTORY_FILES.values():
            _save_provider_history(_hpath, [])
        log.info("cache Cleared all AI caches")
        st.success("Cache cleared")



# --- Realtime log monitoring ---

_LEVEL_COLORS = {
    "FATAL": "#dc3545", "ERROR": "#dc3545", "SEVERE": "#dc3545",
    "WARNING": "#ffc107", "WARN": "#ffc107",
    "INFO": "#0d6efd", "DEBUG": "#adb5bd",
}
_LEVEL_HIGHLIGHT_RE = _re.compile(
    r'\b(FATAL|ERROR|SEVERE|WARNING|WARN|INFO|DEBUG)\b'
)


def _highlight_line(line):
    """Return a line with HTML color spans for log levels."""
    def _color_match(m):
        lvl = m.group(1)
        color = _LEVEL_COLORS.get(lvl, "inherit")
        return f'<span style="color:{color};font-weight:bold">{lvl}</span>'
    return _LEVEL_HIGHLIGHT_RE.sub(_color_match, html.escape(line, quote=True))


def _is_safe_rt_path(filepath: str | None) -> bool:
    """Check if a realtime monitor path is safe (only .log/.gz/.txt files)."""
    if not filepath:
        return False
    p = Path(filepath)
    # Reject symlinks before resolving to prevent traversal
    if p.is_symlink():
        return False
    p = p.resolve()
    # Only allow log-like file extensions
    if p.suffix.lower() not in (".log", ".gz", ".txt"):
        return False
    # Block obvious sensitive paths
    _blocked = {"/etc", "/private/etc", "/var/run", "/proc", "/sys", "/dev"}
    for blocked in _blocked:
        if str(p).startswith(blocked + "/") or str(p) == blocked:
            return False
    return True


def _rt_poll():
    """Read new lines from the monitored file and append to buffer."""
    filepath = st.session_state.rt_file
    if not filepath or not _is_safe_rt_path(filepath):
        return
    p = Path(filepath)
    try:
        if not p.exists() or not p.is_file():
            return
        size = p.stat().st_size
        offset = st.session_state.rt_offset
        # File was truncated/rotated — reset
        if size < offset:
            st.session_state.rt_offset = 0
            offset = 0
        if size == offset:
            return  # no new data
        with p.open("r", errors="ignore") as f:
            f.seek(offset)
            new_data = f.read(64 * 1024)  # read up to 64KB at a time
            st.session_state.rt_offset = f.tell()
        for line in new_data.splitlines():
            if line.strip():
                st.session_state.rt_buffer.append(line)
    except (OSError, PermissionError) as ex:
        st.session_state.rt_buffer.append(f"[monitoring error: {ex}]")
        log.warning("realtime File read error: %s", ex)



@st.fragment(run_every=2)
def _rt_live_view():
    """Fragment that renders controls, polls, and shows the live log buffer."""
    ss = st.session_state
    filepath = ss.rt_file

    # Status
    if not filepath:
        st.info("Enter a log file path or select a detected file above to start monitoring.")
        return

    # Controls — read state fresh each render
    running = ss.rt_running
    paused = ss.rt_paused
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        if st.button("Start", disabled=running and not paused, key="rt_start"):
            ss.rt_running = True
            ss.rt_paused = False
            p = Path(filepath)
            if p.exists():
                ss.rt_offset = p.stat().st_size
            log.info("realtime Started monitoring %s", filepath)
    with c2:
        if st.button("Pause", disabled=not running or paused, key="rt_pause"):
            ss.rt_paused = True
            log.info("realtime Paused monitoring")
    with c3:
        if st.button("Resume", disabled=not paused, key="rt_resume"):
            ss.rt_paused = False
            log.info("realtime Resumed monitoring")
    with c4:
        if st.button("Stop", disabled=not running, key="rt_stop"):
            ss.rt_running = False
            ss.rt_paused = False
            log.info("realtime Stopped monitoring")
    with c5:
        if st.button("Clear", key="rt_clear"):
            ss.rt_buffer.clear()

    # Re-read state after button clicks
    running = ss.rt_running
    paused = ss.rt_paused

    # Status message
    if not running:
        st.caption("Monitoring stopped. Press **Start** to begin.")
    elif paused:
        st.warning("Monitoring paused")
    else:
        _rt_poll()
        p = Path(filepath)
        if p.exists():
            st.success(f"Monitoring **{p.name}** — {len(ss.rt_buffer)} lines in buffer")
        else:
            st.error(f"File not found: {filepath}")

    # Render buffer
    buf = ss.rt_buffer
    if buf:
        highlighted = "<br>".join(_highlight_line(line) for line in buf)
        st.markdown(
            f'<div style="font-family:monospace;font-size:12px;'
            f'background:#0e1117;color:#fafafa;padding:12px;'
            f'border-radius:4px;max-height:500px;overflow-y:auto;'
            f'white-space:pre-wrap;line-height:1.5">'
            f'{highlighted}</div>',
            unsafe_allow_html=True,
        )
    elif running:
        st.caption("Waiting for new log lines...")


tab_analyze, tab_realtime, tab_history, tab_audit, tab_applog = st.tabs(
    ["Analyze", "Realtime Console", "History", "Audit Report", "Application Log"]
)

with tab_analyze:
    uploaded_files = st.file_uploader(
        "Upload WebSphere log file(s)",
        type=["log", "gz"],
        accept_multiple_files=True,
        help="SystemOut.log, SystemErr.log, or .gz compressed logs",
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        top_n = st.number_input("Top-N items", min_value=1, max_value=50, value=10,
                                help="Number of top exceptions, message codes, and signal tags shown in the summary.")
    with col2:
        samples_n = st.number_input("Sample events", min_value=1, max_value=20, value=5,
                                    help="Number of representative sample events shown per error category.")
    with col3:
        hist_minutes = st.number_input("Histogram bucket (min)", min_value=1, max_value=60, value=1,
                                       help="Time resolution for the timeline histogram. Lower values give more detail, higher values give a broader overview.")

    # --- Run analysis (only on button click) ---
    if uploaded_files and st.button("Analyze", type="primary"):
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        all_events = []

        for uploaded in uploaded_files:
            upload_name = f"{ts}_{uploaded.name}"
            upload_path = UPLOADS_DIR / upload_name
            upload_path.write_bytes(uploaded.getvalue())
            log.info("upload File uploaded: %s (%d bytes)", uploaded.name, len(uploaded.getvalue()))

            with st.spinner(f"Parsing {uploaded.name}..."):
                try:
                    events = parse_file(upload_path)
                    all_events.extend(events)
                    log.info("analysis Parsed %d events from %s", len(events), uploaded.name)
                except Exception as ex:
                    log.error("analysis Failed to parse %s: %s", uploaded.name, ex)
                    st.error(f"Failed to parse {uploaded.name}: {ex}")

        if not all_events:
            st.error("No events parsed. Are the files empty or in an unsupported format?")
        else:
            pa = precompute_analysis(all_events, top_n=top_n, samples_n=samples_n, hist_minutes=hist_minutes)
            s = pa["summary"]
            error_count = sum(1 for e in all_events if e.get("level") in ("ERROR", "SEVERE", "FATAL"))
            file_summary = pa["file_summary"]
            causes = pa["causes"]
            hist = pa["hist"]
            splunk = pa["splunk"]
            hung = pa["hung"]
            samples = pa["samples"]
            report_md = render_markdown_report(all_events, _analysis=pa)
            report_json = render_json_report(all_events, _analysis=pa)
            report_pdf = render_pdf_report(all_events, _analysis=pa)
            report_csv = render_csv_report(all_events)
            report_xml = render_xml_report(all_events)
            report_name = f"report_{ts}.md"
            (REPORTS_DIR / report_name).write_text(report_md, encoding="utf-8")

            log.info("analysis Analysis complete: %d events, %d errors, %d causes, %d hung threads",
                     len(all_events), error_count, len(causes), len(hung))
            if s["codes"]:
                log.info("analysis Top codes: %s", ", ".join(f"{c}({n})" for c, n in s["codes"][:5]))
            if s["exceptions"]:
                log.info("analysis Top exceptions: %s", ", ".join(f"{e}({n})" for e, n in s["exceptions"][:5]))
            log.info("analysis Report saved: %s", report_name)

            # Persist everything in session state
            itl = incident_timeline(all_events)

            st.session_state.analysis = {
                "events": all_events,
                "summary": s,
                "error_count": error_count,
                "file_count": len(uploaded_files),
                "file_summary": file_summary,
                "causes": causes,
                "hist": hist,
                "splunk": splunk,
                "hung": hung,
                "samples": samples,
                "incident_timeline": itl,
                "total_events": len(all_events),
                "report_md": report_md,
                "report_json": report_json,
                "report_pdf": report_pdf,
                "report_csv": report_csv,
                "report_xml": report_xml,
                "report_name": report_name,
            }
            # Clear previous actions on new analysis (keep file cache for repeat queries)
            st.session_state.claude_answer = None
            st.session_state.claude_query_label = None
            st.session_state.claude_history = []
            st.session_state.selected_code = None
            st.session_state.selected_action = None
            _save_provider_history(HISTORY_FILE, [])

    # --- Render results from session state (survives reruns) ---
    a = st.session_state.analysis
    if a is not None:
        render_report_sections(a)
    elif not uploaded_files:
        st.info("Upload one or more log files to get started.")

with tab_realtime:
    st.session_state.rt_enabled = True  # always enabled when on this tab

    # --- File selection ---
    _scan_dirs = [
        _APP_DIR, UPLOADS_DIR, Path.cwd(), Path.home(),
        Path("/opt/IBM/WebSphere/AppServer/profiles"),
        Path("/var/log"),
    ]
    _found_logs: list[str] = []
    for _d in _scan_dirs:
        try:
            if _d.is_dir():
                for _f in sorted(_d.glob("*.log"))[:10]:
                    if _f.is_file() and str(_f) not in _found_logs:
                        _found_logs.append(str(_f))
        except (OSError, PermissionError):
            continue

    _col_path, _col_pick = st.columns(2)
    with _col_path:
        _rt_path = st.text_input(
            "Log file path",
            value=st.session_state.rt_file,
            placeholder="/var/log/websphere/SystemOut.log",
            key="rt_file_tab",
        )
        if _rt_path != st.session_state.rt_file:
            st.session_state.rt_file = _rt_path
    with _col_pick:
        if _found_logs:
            _pick = st.selectbox(
                "Or pick a detected log file",
                options=[""] + _found_logs,
                format_func=lambda x: "— select —" if x == "" else Path(x).name + f"  ({x})",
                key="rt_file_pick_tab",
            )
            if _pick and _pick != st.session_state.rt_file:
                st.session_state.rt_file = _pick
                st.rerun()

    _rt_live_view()

with tab_history:
    reports = get_report_history()
    if not reports:
        st.info("No reports yet. Upload a log file in the Analyze tab to get started.")
    else:
        if st.button("Clear history", type="secondary",
                      help="Delete all saved reports"):
            log.info("history Cleared %d report(s)", len(reports))
            for rpath in reports:
                rpath.unlink(missing_ok=True)
            st.rerun()
        for rpath in reports:
            content = rpath.read_text(encoding="utf-8")
            col_name, col_dl = st.columns([4, 1])
            with col_name:
                with st.expander(rpath.name):
                    st.markdown(content)
            with col_dl:
                st.download_button(
                    label="Download",
                    data=content,
                    file_name=rpath.name,
                    mime="text/markdown",
                    key=f"dl_{rpath.name}",
                )

_AUDIT_LIGHT_CSS = """
<style>
:root {
  --bg-primary: #ffffff !important;
  --bg-secondary: #f6f8fa !important;
  --bg-tertiary: #f0f2f5 !important;
  --bg-hover: #e8eaed !important;
  --border: #d0d7de !important;
  --border-strong: #bbc0c7 !important;
  --text-primary: #1f2328 !important;
  --text-secondary: #2d333b !important;
  --text-muted: #656d76 !important;
  --text-heading: #1f2328 !important;
  --accent: #0969da !important;
  --green: #1a7f37 !important;
  --green-bg: #dafbe1 !important;
  --yellow: #9a6700 !important;
  --yellow-bg: #fff8c5 !important;
  --red: #cf222e !important;
  --red-bg: #ffebe9 !important;
  --blue: #0969da !important;
  --blue-bg: #ddf4ff !important;
  --purple: #8250df !important;
  --purple-bg: #fbefff !important;
}
body { background: #ffffff !important; color: #2d333b !important; }
nav { display: none !important; }
.layout { display: block !important; }
main { max-width: 800px !important; margin: 0 !important; padding: 20px !important; }
</style>
"""

_AUDIT_FILES_FULL = ["wslog.py", "app.py", "tests/test_wslog.py", "CLAUDE.md", "ARCHITECTURE.md"]
_AUDIT_FILES_COMPACT = ["wslog.py", "app.py", "CLAUDE.md"]  # For models with low TPM limits
_AUDIT_SKILL_DIRS = ["skills", ".claude/skills"]

_AUDIT_MODELS = {
    "Claude Sonnet 4.6 (~$0.20)": {"provider": "claude", "id": "claude-sonnet-4-6", "max_tokens": 8192, "compact": True},
    "Claude Opus 4.6 (~$1.00)": {"provider": "claude", "id": "claude-opus-4-6", "max_tokens": 8192},
    "Claude Haiku 4.5 (~$0.05)": {"provider": "claude", "id": "claude-haiku-4-5-20251001", "max_tokens": 8192, "compact": True},
    "Gemini 2.5 Pro (~$0.15)": {"provider": "gemini", "id": "gemini-2.5-pro-preview-06-05", "max_tokens": 8192},
    "Gemini 2.5 Flash (~$0.03)": {"provider": "gemini", "id": "gemini-2.5-flash-preview-05-20", "max_tokens": 8192},
    "GPT-4o (~$0.15)": {"provider": "openai", "id": "gpt-4o", "max_tokens": 8192, "compact": True},
    "GPT-4o mini (~$0.02)": {"provider": "openai", "id": "gpt-4o-mini", "max_tokens": 8192, "compact": True},
    "o3 (~$0.60)": {"provider": "openai", "id": "o3", "max_tokens": 8192, "compact": True},
    "o4-mini (~$0.07)": {"provider": "openai", "id": "o4-mini", "max_tokens": 8192, "compact": True},
}

_AUDIT_SYSTEM_PROMPT = """\
You are a senior software engineer performing a technical audit of a Python project.
Produce a structured Markdown report with these sections:
1. Executive Summary (strengths, key findings)
2. Repository Overview (file counts, line counts)
3. Documentation Audit (accuracy, completeness)
4. Skills System Analysis (coverage, gaps)
5. Code Review Findings (bugs, style, security)
6. AI Integration Review (prompt safety, caching)
7. Test Coverage Analysis (coverage, gaps)
8. Refactoring Opportunities
9. Feature Opportunities
10. Prioritized Improvement Plan

For each section, assign a grade: A, A-, B+, B, B-, C+, C, or lower.
Include an overall grade at the top. Use this format for grades:
**Grade: X/10** (or letter grade)

Mark fixed issues with ~~strikethrough~~ ✅ Fixed.
Be specific — reference file names, line numbers, and function names.
Start the report with: # Technical Audit Report — WS Log Analyzer
"""


_COMPACT_MAX_LINES = 250  # Max lines per file in compact mode


def _extract_signatures(content: str) -> str:
    """Extract function/class signatures and docstrings from Python source for compact audit."""
    lines = content.splitlines()
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        # Keep imports, constants, class/function defs
        if (stripped.startswith(("import ", "from ", "class ", "def "))
                or (stripped and not stripped.startswith("#") and "=" in stripped.split("#")[0]
                    and not stripped.startswith(" ") and not stripped.startswith("\t"))):
            result.append(line)
            # If it's a def/class, grab the docstring
            if stripped.startswith(("def ", "class ")):
                # Multi-line signature (only if current line doesn't end with ':')
                if not line.rstrip().endswith(":"):
                    i += 1
                    while i < len(lines) and not lines[i].rstrip().endswith(":"):
                        result.append(lines[i])
                        i += 1
                    if i < len(lines):
                        result.append(lines[i])
                i += 1
                # Docstring
                if i < len(lines) and '"""' in lines[i]:
                    result.append(lines[i])
                    if lines[i].count('"""') < 2:  # multi-line docstring
                        i += 1
                        while i < len(lines) and '"""' not in lines[i]:
                            result.append(lines[i])
                            i += 1
                        if i < len(lines):
                            result.append(lines[i])
                    i += 1
                    continue
        i += 1
    return "\n".join(result)


def _collect_audit_sources(compact=False):
    """Collect source files for auditing. Compact mode sends signatures + docstrings."""
    file_list = _AUDIT_FILES_COMPACT if compact else _AUDIT_FILES_FULL
    file_contents = []
    for rel in file_list:
        path = _APP_DIR / rel
        if path.is_file():
            content = path.read_text(encoding="utf-8", errors="replace")
            all_lines = content.splitlines()
            total = len(all_lines)
            if compact and total > _COMPACT_MAX_LINES and rel.endswith(".py"):
                sig_content = _extract_signatures(content)
                sig_lines = len(sig_content.splitlines())
                file_contents.append(
                    f"--- {rel} ({total} lines, showing {sig_lines} signature lines) ---\n{sig_content}"
                )
            elif compact and total > _COMPACT_MAX_LINES:
                content = "\n".join(all_lines[:_COMPACT_MAX_LINES])
                file_contents.append(f"--- {rel} ({total} lines, showing first {_COMPACT_MAX_LINES}) ---\n{content}")
            else:
                file_contents.append(f"--- {rel} ({total} lines) ---\n{content}")

    # In compact mode, only include skill filenames (not full content)
    if compact:
        skill_names = []
        for skill_dir in _AUDIT_SKILL_DIRS:
            sdir = _APP_DIR / skill_dir
            if sdir.is_dir():
                for sf in sorted(sdir.glob("*.md")) + sorted(sdir.glob("*.yaml")):
                    skill_names.append(str(sf.relative_to(_APP_DIR)))
        if skill_names:
            file_contents.append(f"--- Skills files (names only) ---\n" + "\n".join(skill_names))
    else:
        for skill_dir in _AUDIT_SKILL_DIRS:
            sdir = _APP_DIR / skill_dir
            if sdir.is_dir():
                for sf in sorted(sdir.glob("*.md")) + sorted(sdir.glob("*.yaml")):
                    content = sf.read_text(encoding="utf-8", errors="replace")
                    rel_path = sf.relative_to(_APP_DIR)
                    file_contents.append(f"--- {rel_path} ({len(content.splitlines())} lines) ---\n{content}")

    return "Perform a full technical audit of the following codebase.\n\n" + "\n\n".join(file_contents)


def _run_audit_claude(api_key, model_id, max_tokens, compact=False):
    """Run audit via Claude API."""
    from anthropic import Anthropic
    client = Anthropic(api_key=api_key, timeout=300.0)
    message = client.messages.create(
        model=model_id,
        max_tokens=max_tokens,
        system=_AUDIT_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": _collect_audit_sources(compact=compact)}],
    )
    return message.content[0].text


def _run_audit_gemini(api_key, model_id, compact=False):
    """Run audit via Gemini API."""
    return ask_gemini(
        _collect_audit_sources(compact=compact),
        api_key=api_key,
        system=_AUDIT_SYSTEM_PROMPT,
        model=model_id,
    )


def _run_audit_openai(api_key, model_id, max_tokens, compact=False):
    """Run audit via OpenAI API."""
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("The openai package is not installed. Install with: pip install openai")
    client = OpenAI(api_key=api_key, timeout=300.0)
    response = client.chat.completions.create(
        model=model_id,
        max_completion_tokens=max_tokens,
        messages=[
            {"role": "system", "content": _AUDIT_SYSTEM_PROMPT},
            {"role": "user", "content": _collect_audit_sources(compact=compact)},
        ],
    )
    return response.choices[0].message.content


def _run_audit(model_label):
    """Run a full audit and regenerate the HTML report."""
    from report_renderer import render_html

    model_info = _AUDIT_MODELS[model_label]
    provider = model_info["provider"]
    compact = model_info.get("compact", False)

    if provider == "claude":
        if not st.session_state.api_key:
            raise ValueError("Enter your Anthropic API key in the sidebar first.")
        audit_md = _run_audit_claude(
            st.session_state.api_key, model_info["id"], model_info["max_tokens"], compact=compact
        )
    elif provider == "gemini":
        gemini_key = st.session_state.gemini_api_key
        if not gemini_key:
            raise ValueError("Enter your Gemini API key in the sidebar first.")
        audit_md = _run_audit_gemini(gemini_key, model_info["id"], compact=compact)
    else:
        openai_key = st.session_state.openai_api_key
        if not openai_key:
            raise ValueError("Enter your OpenAI API key in the sidebar first.")
        audit_md = _run_audit_openai(
            openai_key, model_info["id"], model_info["max_tokens"], compact=compact
        )

    if not audit_md:
        raise ValueError("Model returned an empty response.")

    # Save markdown
    md_path = _APP_DIR / "AUDIT_REPORT.md"
    md_path.write_text(audit_md, encoding="utf-8")

    # Version the report and generate delta if previous exists
    _delta_md = None
    try:
        reports_dir = _APP_DIR / "reports"
        reports_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        versioned = reports_dir / f"AUDIT_{timestamp}.md"
        versioned.write_text(audit_md, encoding="utf-8")
        log.info("audit Versioned report: %s", versioned.name)

        # Find previous versioned report
        import re as _re_mod
        pattern = _re_mod.compile(r'^AUDIT_\d{4}-\d{2}-\d{2}_\d{4}\.md$')
        all_reports = sorted(p for p in reports_dir.iterdir() if pattern.match(p.name))
        previous = None
        for r in all_reports:
            if r != versioned:
                previous = r
        if previous:
            sys.path.insert(0, str(_APP_DIR / "scripts"))
            from compare_audits import compare_audits, render_delta
            results = compare_audits(previous, versioned)
            _delta_md = render_delta(results, previous.name, versioned.name)
            delta_path = reports_dir / f"DELTA_AUDIT_{timestamp}.md"
            delta_path.write_text(_delta_md, encoding="utf-8")
            log.info("audit Delta report: %s", delta_path.name)
    except Exception as ex:
        log.warning("audit Could not generate delta: %s", ex)

    # Convert to HTML
    audit_html = render_html(audit_md, title="Technical Audit Report — WS Log Analyzer")
    html_path = _APP_DIR / "AUDIT_REPORT.html"
    html_path.write_text(audit_html, encoding="utf-8")

    log.info("audit Audit report generated with %s: %s", model_label, html_path)
    # Store delta for display
    if _delta_md:
        st.session_state._audit_delta = _delta_md
    return audit_html


with tab_audit:
    _audit_html_path = _APP_DIR / "AUDIT_REPORT.html"

    col_model, col_run, col_dl = st.columns([2, 1, 1])
    with col_model:
        _audit_model = st.selectbox(
            "Model",
            list(_AUDIT_MODELS.keys()),
            key="audit_model",
            label_visibility="collapsed",
        )
    with col_run:
        _run_clicked = st.button("Run Audit", type="primary",
                                 help="Analyze the codebase and generate a fresh audit report")
    with col_dl:
        if _audit_html_path.is_file():
            _existing_html = _audit_html_path.read_text(encoding="utf-8")
            st.download_button(
                label="Download HTML",
                data=_existing_html,
                file_name="AUDIT_REPORT.html",
                mime="text/html",
                key="dl_audit_report",
            )

    if _run_clicked:
        _provider = _AUDIT_MODELS[_audit_model]["provider"]
        _model_id = _AUDIT_MODELS[_audit_model]["id"]
        with st.status(f"Running audit with {_model_id}...", expanded=True) as _audit_status:
            _audit_status.write("Reading source files...")
            try:
                _audit_status.write(f"Sending to {_provider.title()} for analysis (this may take a minute)...")
                _fresh_html = _run_audit(_audit_model)
                _audit_status.update(label="Audit complete!", state="complete")
                st.rerun()
            except Exception as ex:
                log.error("audit Audit failed: %s", ex)
                _audit_status.update(label="Audit failed", state="error")
                st.error(f"Audit failed: {ex}")

    # Show delta comparison if available
    _delta = getattr(st.session_state, "_audit_delta", None)
    if _delta:
        with st.expander("Changes since last audit", expanded=True):
            st.markdown(_delta)

    if _audit_html_path.is_file():
        _audit_html = _audit_html_path.read_text(encoding="utf-8")
        _audit_styled = _audit_html.replace("</head>", _AUDIT_LIGHT_CSS + "</head>")
        st.components.v1.html(_audit_styled, height=2000, scrolling=True)
    else:
        st.info("No audit report yet. Click **Run Audit** to generate one.")

with tab_applog:
    _log_level_filter = st.selectbox(
        "Filter by level",
        ["ALL", "INFO", "WARNING", "ERROR"],
        key="log_level_filter",
    )
    if LOG_FILE.exists():
        _raw_lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        if _log_level_filter != "ALL":
            _raw_lines = [l for l in _raw_lines if f" {_log_level_filter:<5s}" in l
                          or f" {_log_level_filter} " in l]
        _display_lines = _raw_lines[-100:]
        if _display_lines:
            st.code("\n".join(_display_lines), language="log")
        else:
            st.caption("No matching log entries.")
    else:
        st.caption("No application log yet.")
