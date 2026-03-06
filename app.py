"""Streamlit GUI for the WebSphere Log Analyzer."""
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
    render_pdf_report, per_file_summary, time_histogram, render_histogram,
    pick_samples, likely_causes, suggested_splunk_queries, hung_thread_drilldown,
    match_user_query, build_claude_prompt, claude_cache_key,
    incident_timeline,
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

CACHE_FILE = CACHE_DIR / "claude_responses.json"
HISTORY_FILE = CACHE_DIR / "claude_history.json"


MAX_CACHE_ENTRIES = 100
MAX_HISTORY_ENTRIES = 50


def _load_json_file(path, default):
    """Load a JSON file, returning default on error."""
    if path.exists():
        try:
            import json
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return default


def _save_json_file(path, data):
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


def _load_history():
    data = _load_json_file(HISTORY_FILE, [])
    return data if isinstance(data, list) else []


def _save_history(history):
    # Keep only the most recent entries
    _save_json_file(HISTORY_FILE, history[-MAX_HISTORY_ENTRIES:])

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
    "debug_payload": False,     # Show Claude API request/response payloads
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
if not st.session_state.claude_history:
    st.session_state.claude_history = _load_history()


def get_report_history(limit=20):
    """Return list of (path, mtime) for recent reports, newest first."""
    reports = sorted(REPORTS_DIR.glob("report_*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    return reports[:limit]


# --- Section renderers ---

def _on_code_action(code, action):
    """Callback for code row buttons. Populates the Ask Claude input field."""
    st.session_state.claude_query_input = code
    st.session_state.selected_code = code
    st.session_state.selected_action = action
    if action == "claude":
        st.session_state._ask_claude_pending = True


def render_code_row(code, count):
    """Render a message code row with count and action buttons."""
    cols = st.columns([3, 1])
    with cols[0]:
        st.text(f"  {count:>4}  {code}")
    with cols[1]:
        st.button("Ask Claude", key=f"ask_{code}",
                  on_click=_on_code_action, args=(code, "claude"),
                  help=f"Ask Claude about {code}")


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
            for name, count in s["exceptions"][:5]:
                st.text(f"  {count:>4}  {name}")
        else:
            st.caption("None detected")
    with code_col:
        st.subheader("Top Message Codes")
        if s["codes"]:
            for code, count in s["codes"][:5]:
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


def render_ask_claude(events):
    """Render Ask Claude input, API call, and response history."""
    user_query = st.text_input(
        "Ask Claude about an error code, exception, or troubleshooting question",
        placeholder="e.g. CWPKI0022E, SSLHandshakeException, why are threads hanging?",
        key="claude_query_input",
    )

    st.button("Analyze with Claude", type="primary",
              on_click=_on_ask_claude_click,
              disabled=not user_query)

    # Check if the button was clicked (set by on_click callback on previous rerun)
    pending = st.session_state.pop("_ask_claude_pending", False)

    if user_query and pending:
        log.info("claude Ask Claude request: %s", user_query[:100])
        status = st.status("Analyzing with Claude...", expanded=True)
        match = match_user_query(user_query, events)
        cache_key = claude_cache_key(user_query, match)

        # Check session cache, then file cache
        cached = st.session_state.claude_cache.get(cache_key)
        if cached:
            log.info("cache Session cache hit for query: %s", user_query[:60])
        if not cached:
            file_cache = _load_file_cache()
            cached = file_cache.get(cache_key)
            if cached:
                log.info("cache File cache hit for query: %s", user_query[:60])

        def _record_answer(answer, from_cache=False):
            """Store answer in state and append to history."""
            st.session_state.claude_answer = answer
            st.session_state.claude_query_label = user_query
            splunk_queries = _extract_splunk_from_response(answer)
            entry = {
                "query": user_query,
                "answer": answer,
                "splunk_queries": splunk_queries,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }
            hist = st.session_state.claude_history
            if not any(h["query"] == user_query and h["answer"] == answer for h in hist):
                hist.append(entry)
                _save_history(hist)

        if cached:
            _record_answer(cached, from_cache=True)
            status.update(label="Using cached Claude response", state="complete")
        else:
            if match["matched"]:
                status.write(f"Found {len(match['matching_events'])} matching event(s) "
                             f"(match type: {match['match_type']})")
            else:
                status.write("No exact match — sending general question to Claude.")

            if not st.session_state.api_key:
                status.update(label="No API key set", state="error")
                st.error("Enter your Anthropic API key in the sidebar.")
                return

            try:
                from anthropic import Anthropic
            except ImportError:
                status.update(label="Missing package", state="error")
                st.error("The `anthropic` package is not installed. "
                         "Install with: `pip install anthropic`")
                return

            log.info("cache Cache miss — calling Claude API for: %s", user_query[:60])
            prompt = build_claude_prompt(user_query, match)
            request_payload = {
                "model": "claude-sonnet-4-6",
                "max_tokens": 2048,
                "system": prompt["system"],
                "messages": [{"role": "user", "content": prompt["user"]}],
            }
            if st.session_state.debug_payload:
                with st.expander("Request payload", expanded=False):
                    import json as _json
                    st.code(_json.dumps(request_payload, indent=2), language="json")

            status.write("Calling Claude API...")
            try:
                client = Anthropic(api_key=st.session_state.api_key)
                message = client.messages.create(**request_payload)
                if not message.content:
                    log.warning("claude Claude returned empty response for: %s", user_query[:60])
                    status.update(label="Empty response from Claude", state="error")
                    return
                answer = message.content[0].text
                log.info("claude Claude response received (%d chars) for: %s",
                         len(answer), user_query[:60])
                if st.session_state.debug_payload:
                    with st.expander("Response payload", expanded=False):
                        st.code(answer, language="markdown")
                _record_answer(answer)
                st.session_state.claude_cache[cache_key] = answer
                file_cache = _load_file_cache()
                file_cache[cache_key] = answer
                _save_file_cache(file_cache)
                status.update(label="Claude analysis complete", state="complete")
            except Exception as ex:
                log.error("claude Claude API error: %s", ex)
                if st.session_state.debug_payload:
                    with st.expander("Error details", expanded=True):
                        st.code(str(ex), language="text")
                status.update(label=f"Claude API error: {ex}", state="error")
                return

    # Show persisted Claude answer
    if st.session_state.claude_answer:
        label = st.session_state.claude_query_label or "query"
        st.markdown("---")
        st.subheader(f"Claude analysis for {label}")
        _render_claude_response(st.session_state.claude_answer)

    # Show previous Claude queries (if more than just the current one)
    history = st.session_state.claude_history
    if len(history) > 1:
        st.markdown("---")
        st.subheader("Previous Claude queries")
        for h_idx, entry in enumerate(reversed(history[:-1])):
            with st.expander(f"{entry['query']} ({entry['timestamp']})"):
                _render_claude_response(entry["answer"])


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
        st.caption("Run Ask Claude to get context-aware Splunk searches.")


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
        title=None,
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

    dl1, dl2, dl3 = st.columns(3)
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

    st.markdown("---")

    with st.expander("Summary", expanded=True):
        render_summary(a["summary"], a["error_count"], a["file_count"], a["file_summary"])

    if a["causes"]:
        with st.expander(f"Likely Causes & Fixes ({len(a['causes'])} detected)"):
            render_likely_causes(a["causes"])

    with st.expander("Ask Claude", expanded=True):
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


def _load_saved_api_key():
    """Load API key from macOS Keychain, env var, or empty string."""
    try:
        import keyring
        stored = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
        if stored:
            return stored
    except Exception:
        pass
    return os.environ.get("ANTHROPIC_API_KEY", "")


def _save_api_key(key):
    """Store API key in macOS Keychain."""
    try:
        import keyring
        if key:
            keyring.set_password(_KEYRING_SERVICE, _KEYRING_USERNAME, key)
            log.info("settings API key saved to system keychain")
        else:
            keyring.delete_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
            log.info("settings API key removed from system keychain")
    except Exception as ex:
        log.warning("settings Could not save API key to keychain: %s", ex)


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

    st.markdown("---")
    st.session_state.debug_payload = st.toggle(
        "Enable Ask Claude payload",
        value=st.session_state.debug_payload,
        help="Show request/response payloads for Claude API calls",
    )
    if st.button("Clear Claude cache", help="Clear cached Claude responses and history"):
        st.session_state.claude_cache = {}
        st.session_state.claude_answer = None
        st.session_state.claude_query_label = None
        st.session_state.claude_history = []
        if CACHE_FILE.exists():
            CACHE_FILE.unlink()
        _save_history([])
        log.info("cache Cleared all Claude caches")
        st.success("Cache cleared")

    st.markdown("---")
    st.subheader("Realtime monitoring")
    st.session_state.rt_enabled = st.toggle(
        "Enable realtime log monitoring",
        value=st.session_state.rt_enabled,
        help="Monitor a local log file in real time (tail -f style)",
    )
    if st.session_state.rt_enabled:
        rt_file = st.text_input(
            "Log file path",
            value=st.session_state.rt_file,
            placeholder="/var/log/websphere/SystemOut.log",
        )
        st.session_state.rt_file = rt_file

        # Quick pick: scan for .log files in common locations
        scan_dirs = [
            _APP_DIR,
            UPLOADS_DIR,
            Path.cwd(),
            Path.home(),
            Path("/opt/IBM/WebSphere/AppServer/profiles"),
            Path("/var/log"),
        ]
        found_logs = []
        for d in scan_dirs:
            try:
                if d.is_dir():
                    for f in sorted(d.glob("*.log"))[:10]:
                        if f.is_file() and str(f) not in found_logs:
                            found_logs.append(str(f))
            except (OSError, PermissionError):
                continue
        if found_logs:
            pick = st.selectbox(
                "Or pick a detected log file",
                options=[""] + found_logs,
                format_func=lambda x: "— select —" if x == "" else Path(x).name + f"  ({x})",
                key="rt_file_pick",
            )
            if pick and pick != st.session_state.rt_file:
                st.session_state.rt_file = pick
                st.rerun()
        else:
            st.caption("No .log files found in common locations.")


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
    return _LEVEL_HIGHLIGHT_RE.sub(_color_match, line.replace("<", "&lt;").replace(">", "&gt;"))


def _rt_poll():
    """Read new lines from the monitored file and append to buffer."""
    filepath = st.session_state.rt_file
    if not filepath:
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
    """Fragment that polls and renders the live log stream."""
    ss = st.session_state
    if not ss.rt_enabled:
        return

    filepath = ss.rt_file
    running = ss.rt_running
    paused = ss.rt_paused

    # Status indicator
    if not filepath:
        st.info("Enter a log file path in the sidebar to start monitoring.")
        return
    if not running:
        st.caption("Monitoring stopped.")
    elif paused:
        st.warning("Monitoring paused")
    else:
        # Active polling
        _rt_poll()
        p = Path(filepath)
        if p.exists():
            st.success(f"Monitoring **{p.name}** — {len(ss.rt_buffer)} lines in buffer")
        else:
            st.error(f"File not found: {filepath}")

    # Control buttons
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        if st.button("Start", disabled=running and not paused, key="rt_start"):
            ss.rt_running = True
            ss.rt_paused = False
            # Seek to end of file on fresh start
            p = Path(filepath)
            if p.exists():
                ss.rt_offset = p.stat().st_size
            log.info("realtime Started monitoring %s", filepath)
            st.rerun()
    with c2:
        if st.button("Pause", disabled=not running or paused, key="rt_pause"):
            ss.rt_paused = True
            log.info("realtime Paused monitoring")
            st.rerun()
    with c3:
        if st.button("Resume", disabled=not paused, key="rt_resume"):
            ss.rt_paused = False
            log.info("realtime Resumed monitoring")
            st.rerun()
    with c4:
        if st.button("Stop", disabled=not running, key="rt_stop"):
            ss.rt_running = False
            ss.rt_paused = False
            log.info("realtime Stopped monitoring")
            st.rerun()
    with c5:
        if st.button("Clear", key="rt_clear"):
            ss.rt_buffer.clear()
            st.rerun()

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
    else:
        st.caption("Buffer empty. New lines will appear here when the file is written to.")


# --- Realtime section (above tabs, always visible when enabled) ---
if st.session_state.rt_enabled:
    with st.expander("Realtime Log Monitor", expanded=st.session_state.rt_running):
        _rt_live_view()

tab_analyze, tab_history = st.tabs(["Analyze", "History"])

with tab_analyze:
    uploaded_files = st.file_uploader(
        "Upload WebSphere log file(s)",
        type=["log", "gz"],
        accept_multiple_files=True,
        help="SystemOut.log, SystemErr.log, or .gz compressed logs",
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        top_n = st.number_input("Top-N items", min_value=1, max_value=50, value=10)
    with col2:
        samples_n = st.number_input("Sample events", min_value=1, max_value=20, value=5)
    with col3:
        hist_minutes = st.number_input("Histogram bucket (min)", min_value=1, max_value=60, value=1)

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
            s = summarize(all_events, top_n)
            error_count = sum(1 for e in all_events if e.get("level") in ("ERROR", "SEVERE", "FATAL"))
            file_summary = per_file_summary(all_events)
            causes = likely_causes(all_events)
            hist = time_histogram(all_events, bucket_minutes=hist_minutes)
            splunk = suggested_splunk_queries(s, causes, hist)
            hung = hung_thread_drilldown(all_events)
            samples = pick_samples(all_events, samples_n)
            report_md = render_markdown_report(all_events, top_n=top_n, samples_n=samples_n, hist_minutes=hist_minutes)
            report_json = render_json_report(all_events, top_n=top_n, samples_n=samples_n, hist_minutes=hist_minutes)
            report_pdf = render_pdf_report(all_events, top_n=top_n, samples_n=samples_n, hist_minutes=hist_minutes)
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
                "report_name": report_name,
            }
            # Clear previous actions on new analysis
            st.session_state.claude_answer = None
            st.session_state.claude_query_label = None
            st.session_state.claude_cache = {}
            st.session_state.claude_history = []
            st.session_state.selected_code = None
            st.session_state.selected_action = None
            # Sync to disk
            if CACHE_FILE.exists():
                CACHE_FILE.unlink()
            _save_history([])

    # --- Render results from session state (survives reruns) ---
    a = st.session_state.analysis
    if a is not None:
        render_report_sections(a)
    elif not uploaded_files:
        st.info("Upload one or more log files to get started.")

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

# --- Application Log ---
st.markdown("---")
with st.expander("Application Log"):
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
