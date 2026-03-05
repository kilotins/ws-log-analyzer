"""Streamlit GUI for the WebSphere Log Analyzer."""
import streamlit as st
from datetime import datetime
from pathlib import Path

from wslog import parse_file, summarize, pick_samples, time_histogram, render_histogram, per_file_summary

UPLOADS_DIR = Path("uploads")
REPORTS_DIR = Path("reports")
UPLOADS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)


def generate_report(events, top_n=10, samples_n=5, hist_minutes=1):
    """Generate a markdown report string from parsed events (mirrors CLI logic)."""
    s = summarize(events, top_n)
    samples = pick_samples(events, samples_n)
    hist = time_histogram(events, bucket_minutes=hist_minutes)
    file_summary = per_file_summary(events)

    md = []
    md.append("# WebSphere/Java Log Triage Report")
    md.append("")
    md.append(f"- Files: {len(file_summary)}")
    md.append(f"- Parsed events: {s['total_events']}")
    md.append("")

    if len(file_summary) > 1:
        md.append("## Per-File Breakdown")
        for fname, total, errors in file_summary:
            err_note = f" ({errors} errors)" if errors else ""
            md.append(f"- `{fname}`: {total} events{err_note}")
        md.append("")

    md.append("## Top Levels")
    md += [f"- **{k}**: {v}" for k, v in s["levels"]]
    md.append("")
    md.append("## Top WebSphere/Liberty Codes")
    md += [f"- `{k}`: {v}" for k, v in s["codes"]] or ["- _(none detected)_"]
    md.append("")
    md.append("## Top Exceptions/Errors")
    md += [f"- `{k}`: {v}" for k, v in s["exceptions"]] or ["- _(none detected)_"]
    md.append("")
    md.append("## Signal Tags")
    md += [f"- **{k}**: {v}" for k, v in s["tags"]] or ["- _(none detected)_"]
    md.append("")
    md.append("## Timeline (events per minute)")
    md.append("")
    md.append("```")
    md += render_histogram(hist)
    md.append("```")
    md.append("")
    md.append("## Sample Events (sanitized)")
    md.append("")
    for idx, e in enumerate(samples, start=1):
        header = f"### {idx}. {e['level'] or 'UNKNOWN'}"
        if e["code"]:
            header += f" `{e['code']}`"
        if e["exception"]:
            header += f" -- {e['exception']}"
        if e["ts"]:
            header += f" ({e['ts']})"
        md.append(header)
        parts = []
        if e["tags"]:
            parts.append(f"Tags: {', '.join(e['tags'])}")
        if e["thread_id"]:
            parts.append(f"Thread: 0x{e['thread_id']}")
        if e["root_cause"] and e["root_cause"] != e["exception"]:
            parts.append(f"Root cause: `{e['root_cause']}`")
        if parts:
            md.append(f"- {' | '.join(parts)}")
        md.append("")
        md.append("```")
        md.append(e["text"][:4000])
        if len(e["text"]) > 4000:
            md.append("\n...[TRUNCATED]...")
        md.append("```")
        md.append("")

    return "\n".join(md)


def get_report_history(limit=20):
    """Return list of (path, mtime) for recent reports, newest first."""
    reports = sorted(REPORTS_DIR.glob("report_*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    return reports[:limit]


# --- Streamlit UI ---

st.set_page_config(page_title="WS Log Analyzer", page_icon="📋", layout="wide")
st.title("WebSphere Log Analyzer")

tab_analyze, tab_history = st.tabs(["Analyze", "History"])

with tab_analyze:
    uploaded = st.file_uploader(
        "Upload a WebSphere log file",
        type=["log", "gz"],
        help="SystemOut.log, SystemErr.log, or .gz compressed logs",
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        top_n = st.number_input("Top-N items", min_value=1, max_value=50, value=10)
    with col2:
        samples_n = st.number_input("Sample events", min_value=1, max_value=20, value=5)
    with col3:
        hist_minutes = st.number_input("Histogram bucket (min)", min_value=1, max_value=60, value=1)

    if uploaded is not None:
        if st.button("Analyze", type="primary"):
            ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

            # Save uploaded file
            upload_name = f"{ts}_{uploaded.name}"
            upload_path = UPLOADS_DIR / upload_name
            upload_path.write_bytes(uploaded.getvalue())

            # Parse
            with st.spinner("Parsing log file..."):
                events = parse_file(upload_path, max_lines=None)

            if not events:
                st.error("No events parsed. Is the file empty or in an unsupported format?")
            else:
                report = generate_report(events, top_n=top_n, samples_n=samples_n, hist_minutes=hist_minutes)

                # Save report
                report_name = f"report_{ts}.md"
                report_path = REPORTS_DIR / report_name
                report_path.write_text(report, encoding="utf-8")

                st.success(f"Parsed {len(events)} events. Report saved as `{report_name}`.")

                st.download_button(
                    label="Download Report",
                    data=report,
                    file_name=report_name,
                    mime="text/markdown",
                )

                st.markdown("---")
                st.markdown(report)

with tab_history:
    reports = get_report_history()
    if not reports:
        st.info("No reports yet. Upload a log file in the Analyze tab to get started.")
    else:
        for rpath in reports:
            col_name, col_dl = st.columns([4, 1])
            with col_name:
                with st.expander(rpath.name):
                    st.markdown(rpath.read_text(encoding="utf-8"))
            with col_dl:
                st.download_button(
                    label="Download",
                    data=rpath.read_text(encoding="utf-8"),
                    file_name=rpath.name,
                    mime="text/markdown",
                    key=f"dl_{rpath.name}",
                )
