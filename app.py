"""Streamlit GUI for the WebSphere Log Analyzer."""
import streamlit as st
from datetime import datetime
from pathlib import Path

from wslog import parse_file, summarize, render_markdown_report, render_json_report

UPLOADS_DIR = Path("uploads")
REPORTS_DIR = Path("reports")
UPLOADS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)


def get_report_history(limit=20):
    """Return list of (path, mtime) for recent reports, newest first."""
    reports = sorted(REPORTS_DIR.glob("report_*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    return reports[:limit]


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

    if uploaded_files:
        if st.button("Analyze", type="primary"):
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
                # Quick metrics
                s = summarize(all_events, top_n)
                error_count = sum(1 for e in all_events if e.get("level") in ("ERROR", "SEVERE", "FATAL"))

                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Total Events", s["total_events"])
                m2.metric("Errors", error_count)
                m3.metric("Files", len(uploaded_files))
                level_counts = dict(s["levels"])
                m4.metric("Warnings", level_counts.get("WARNING", 0))

                # Top exceptions & codes tables side by side
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
                            st.text(f"  {count:>4}  {code}")
                    else:
                        st.caption("None detected")

                report = render_markdown_report(all_events, top_n=top_n, samples_n=samples_n, hist_minutes=hist_minutes)

                # Save report
                report_name = f"report_{ts}.md"
                report_path = REPORTS_DIR / report_name
                report_path.write_text(report, encoding="utf-8")

                json_report = render_json_report(all_events, top_n=top_n, samples_n=samples_n, hist_minutes=hist_minutes)

                st.success(f"Parsed {len(all_events)} events from {len(uploaded_files)} file(s). Report saved as `{report_name}`.")

                dl1, dl2 = st.columns(2)
                with dl1:
                    st.download_button(
                        label="Download Markdown",
                        data=report,
                        file_name=report_name,
                        mime="text/markdown",
                    )
                with dl2:
                    st.download_button(
                        label="Download JSON",
                        data=json_report,
                        file_name=report_name.replace(".md", ".json"),
                        mime="application/json",
                    )

                st.markdown("---")
                st.markdown(report)

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
