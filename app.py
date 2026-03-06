"""Streamlit GUI for the WebSphere Log Analyzer."""
import streamlit as st
from datetime import datetime
from pathlib import Path

from wslog import (
    parse_file, summarize, render_markdown_report, render_json_report,
    per_file_summary, time_histogram, render_histogram, pick_samples,
    likely_causes, suggested_splunk_queries, hung_thread_drilldown,
    match_user_query, build_claude_prompt, _SPLUNK_PREFIX,
)

UPLOADS_DIR = Path("uploads")
REPORTS_DIR = Path("reports")
UPLOADS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# --- Session state defaults ---
_STATE_DEFAULTS = {
    "analysis": None,           # dict with all analysis results
    "claude_answer": None,      # last Claude response
    "selected_code": None,      # code selected via any action button
    "selected_action": None,    # "copy" | "claude" | "splunk"
}
for key, default in _STATE_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = default


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
    cols = st.columns([3, 1, 1, 1])
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
    with cols[3]:
        st.button("Splunk", key=f"splunk_{code}",
                  on_click=_on_code_action, args=(code, "splunk"),
                  help=f"Splunk search for {code}")


def render_code_action_panel():
    """Render the result of the last code button action, below the summary."""
    code = st.session_state.selected_code
    action = st.session_state.selected_action
    if not code or not action:
        return

    if action == "copy":
        st.info(f"Code **{code}** ready to copy:")
        st.code(code, language=None)
    elif action == "splunk":
        query = f'{_SPLUNK_PREFIX} "{code}"'
        st.info(f"Splunk search for **{code}**:")
        st.code(query, language="spl")
    elif action == "claude":
        st.info(f"Code **{code}** loaded into Ask Claude below.")


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


def render_likely_causes(causes):
    """Render likely causes and fixes section."""
    if not causes:
        st.caption("No known issue patterns detected.")
        return
    for c in causes:
        st.markdown(f"**{c['title']}** ({c['count']} event{'s' if c['count'] != 1 else ''})")
        st.markdown(f"*Likely cause:* {c['cause']}")
        for fix in c["fixes"]:
            st.markdown(f"- {fix}")


def render_splunk_section(splunk):
    """Render suggested Splunk searches."""
    if not splunk:
        st.caption("No Splunk queries generated.")
        return
    for sq in splunk:
        st.markdown(f"**{sq['description']}**")
        st.code(sq["query"], language="spl")


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

    dl1, dl2 = st.columns(2)
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

    st.markdown("---")

    with st.expander("Summary", expanded=True):
        render_summary(a["summary"], a["error_count"], a["file_count"], a["file_summary"])

    with st.expander(f"Likely Causes & Fixes ({len(a['causes'])} detected)"):
        render_likely_causes(a["causes"])

    with st.expander(f"Suggested Splunk Searches ({len(a['splunk'])} queries)"):
        render_splunk_section(a["splunk"])

    with st.expander(f"Hung Thread Analysis ({len(a['hung'])} threads)"):
        render_hung_threads(a["hung"])

    with st.expander("Timeline"):
        render_timeline(a["hist"])

    with st.expander(f"Event Samples ({len(a['samples'])} shown)"):
        render_samples(a["samples"])


def render_ask_claude(events):
    """Render the Ask Claude section. Uses events from session state."""
    st.markdown("---")
    st.subheader("Ask Claude")

    # Pre-fill from code button action (consumed once via default_value)
    default_query = ""
    if st.session_state.selected_action == "claude" and st.session_state.selected_code:
        default_query = st.session_state.selected_code

    user_query = st.text_input(
        "Enter an error code, exception name, or troubleshooting question",
        value=default_query,
        placeholder="e.g. CWPKI0022E, SSLHandshakeException, why are threads hanging?",
    )

    if user_query and st.button("Analyze with Claude", type="secondary"):
        match = match_user_query(user_query, events)
        prompt = build_claude_prompt(user_query, match)

        if match["matched"]:
            st.info(f"Found {len(match['matching_events'])} matching event(s) "
                    f"(match type: {match['match_type']})")
        else:
            st.warning("No exact match in current log — sending general question to Claude.")

        try:
            from anthropic import Anthropic
        except ImportError:
            st.error("The `anthropic` package is not installed. "
                     "Install with: `pip install anthropic`")
            return

        with st.spinner("Asking Claude..."):
            try:
                client = Anthropic()
                message = client.messages.create(
                    model="claude-sonnet-4-6",
                    max_tokens=2048,
                    messages=[{"role": "user", "content": prompt}],
                )
                st.session_state.claude_answer = message.content[0].text
            except Exception as ex:
                st.error(f"Claude API error: {ex}")
                st.caption("Tip: ensure ANTHROPIC_API_KEY is set in your environment.")
                return

    # Show persisted Claude answer across reruns
    if st.session_state.claude_answer:
        with st.expander("Claude's Analysis", expanded=True):
            st.markdown(st.session_state.claude_answer)


# --- Streamlit UI ---

st.set_page_config(page_title="WS Log Analyzer", page_icon="📋", layout="wide")
st.title("WebSphere Log Analyzer")

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
                "report_name": report_name,
            }
            # Clear previous actions on new analysis
            st.session_state.claude_answer = None
            st.session_state.selected_code = None
            st.session_state.selected_action = None

    # --- Render results from session state (survives reruns) ---
    a = st.session_state.analysis
    if a is not None:
        render_report_sections(a)
        render_ask_claude(a["events"])
    elif not uploaded_files:
        st.info("Upload one or more log files to get started.")

with tab_history:
    reports = get_report_history()
    if not reports:
        st.info("No reports yet. Upload a log file in the Analyze tab to get started.")
    else:
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
