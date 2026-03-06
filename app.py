"""Streamlit GUI for the WebSphere Log Analyzer."""
import os
import re as _re
import streamlit as st
from datetime import datetime
from pathlib import Path

from wslog import (
    parse_file, summarize, render_markdown_report, render_json_report,
    render_pdf_report, per_file_summary, time_histogram, render_histogram,
    pick_samples, likely_causes, suggested_splunk_queries, hung_thread_drilldown,
    match_user_query, build_claude_prompt, claude_cache_key,
)

_APP_DIR = Path(__file__).parent
UPLOADS_DIR = _APP_DIR / "uploads"
REPORTS_DIR = _APP_DIR / "reports"
CACHE_DIR = _APP_DIR / "cache"
UPLOADS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
CACHE_DIR.mkdir(exist_ok=True)

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
}
for key, default in _STATE_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = default

# Load persisted history on fresh session
if not st.session_state.claude_history:
    st.session_state.claude_history = _load_history()


def get_report_history(limit=20):
    """Return list of (path, mtime) for recent reports, newest first."""
    reports = sorted(REPORTS_DIR.glob("report_*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    return reports[:limit]


# --- Section renderers ---

def _on_code_action(code, action):
    """Callback for code row buttons. Sets state without triggering extra reruns."""
    st.session_state.selected_code = code
    st.session_state.selected_action = action


def render_code_row(code, count):
    """Render a message code row with count and action buttons."""
    cols = st.columns([3, 1, 1])
    with cols[0]:
        st.text(f"  {count:>4}  {code}")
    with cols[1]:
        st.button("Copy", key=f"copy_{code}",
                  on_click=_on_code_action, args=(code, "copy"),
                  help=f"Copy {code}")
    with cols[2]:
        st.button("Ask Claude", key=f"ask_{code}",
                  on_click=_on_code_action, args=(code, "claude"),
                  help=f"Ask Claude about {code}")


def render_code_action_panel():
    """Render the result of the last code button action, below the summary."""
    code = st.session_state.selected_code
    action = st.session_state.selected_action
    if not code or not action:
        return

    if action == "copy":
        st.info(f"Code **{code}** ready to copy:")
        st.code(code, language=None)
    elif action == "claude":
        st.info(f"Code **{code}** loaded — open Likely Causes & Fixes to ask Claude.")


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

    # Show action result below the summary
    render_code_action_panel()


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


def render_likely_causes(causes, events):
    """Render likely causes, Ask Claude input, and Claude answer."""
    if causes:
        for c in causes:
            st.markdown(f"**{c['title']}** ({c['count']} event{'s' if c['count'] != 1 else ''})")
            st.markdown(f"*Likely cause:* {c['cause']}")
            for fix in c["fixes"]:
                st.markdown(f"- {fix}")
    else:
        st.caption("No known issue patterns detected.")

    # --- Ask Claude subsection ---
    st.markdown("---")

    # Pre-fill from code button action (consume once)
    default_query = ""
    if st.session_state.selected_action == "claude" and st.session_state.selected_code:
        default_query = st.session_state.selected_code
        st.session_state.selected_action = None

    user_query = st.text_input(
        "Ask Claude about an error code, exception, or troubleshooting question",
        value=default_query,
        placeholder="e.g. CWPKI0022E, SSLHandshakeException, why are threads hanging?",
    )

    if user_query and st.button("Analyze with Claude", type="secondary"):
        match = match_user_query(user_query, events)
        cache_key = claude_cache_key(user_query, match)

        # Check session cache, then file cache
        cached = st.session_state.claude_cache.get(cache_key)
        if not cached:
            file_cache = _load_file_cache()
            cached = file_cache.get(cache_key)

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
            # Avoid duplicate entries for same query
            hist = st.session_state.claude_history
            if not any(h["query"] == user_query and h["answer"] == answer for h in hist):
                hist.append(entry)
                _save_history(hist)

        if cached:
            _record_answer(cached, from_cache=True)
            st.success("Using cached Claude response")
        else:
            if match["matched"]:
                st.info(f"Found {len(match['matching_events'])} matching event(s) "
                        f"(match type: {match['match_type']})")
            else:
                st.warning("No exact match in current log — sending general question to Claude.")

            if not st.session_state.api_key:
                st.error("No API key set. Enter your Anthropic API key in the sidebar.")
                return

            try:
                from anthropic import Anthropic
            except ImportError:
                st.error("The `anthropic` package is not installed. "
                         "Install with: `pip install anthropic`")
                return

            prompt = build_claude_prompt(user_query, match)
            with st.spinner("Asking Claude..."):
                try:
                    client = Anthropic(api_key=st.session_state.api_key)
                    message = client.messages.create(
                        model="claude-sonnet-4-6",
                        max_tokens=2048,
                        system=prompt["system"],
                        messages=[{"role": "user", "content": prompt["user"]}],
                    )
                    if not message.content:
                        st.warning("Claude returned an empty response.")
                        return
                    answer = message.content[0].text
                    _record_answer(answer)
                    # Store in caches
                    st.session_state.claude_cache[cache_key] = answer
                    file_cache = _load_file_cache()
                    file_cache[cache_key] = answer
                    _save_file_cache(file_cache)
                except Exception as ex:
                    st.error(f"Claude API error: {ex}")
                    st.caption("Tip: ensure ANTHROPIC_API_KEY is set in your environment.")
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
        # Show all except the last (which is the current answer shown above)
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

    with st.expander(f"Likely Causes & Fixes ({len(a['causes'])} detected)"):
        render_likely_causes(a["causes"], a["events"])

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

    with st.expander(f"Event Samples ({len(a['samples'])} shown)"):
        render_samples(a["samples"])


# --- Streamlit UI ---

st.set_page_config(page_title="WS Log Analyzer", page_icon="📋", layout="wide")
st.title("WebSphere Log Analyzer")

# --- Sidebar: API key ---
with st.sidebar:
    st.header("Settings")
    env_key = os.environ.get("ANTHROPIC_API_KEY", "")
    api_key = st.text_input(
        "Anthropic API Key",
        value=st.session_state.api_key or env_key,
        type="password",
        placeholder="sk-ant-...",
        help="Required for Ask Claude. Get a key at console.anthropic.com/settings/keys",
    )
    st.session_state.api_key = api_key
    if api_key:
        st.success("API key set")
    else:
        st.caption("Enter your key to enable Ask Claude")

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

            with st.spinner(f"Parsing {uploaded.name}..."):
                try:
                    events = parse_file(upload_path)
                    all_events.extend(events)
                except Exception as ex:
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

            # Persist everything in session state
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
