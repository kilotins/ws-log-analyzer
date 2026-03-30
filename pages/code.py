"""LogPilot — Trace to Code: match stacktraces to source code."""
import streamlit as st

a = st.session_state.get("analysis")
if a is None:
    st.info("Upload and analyze log files on the **Home** page first.")
    st.stop()

repo_path = st.session_state.get("_code_repo_path", "")
if not repo_path or not repo_path.strip():
    st.info("Link a source code directory in **Settings** to enable Trace to Code.")
    st.stop()

st.title("Trace to Code")

events = a.get("events", [])

# --- Extract and search ---
from logpilot.trace_to_code import extract_code_locations
from logpilot.code_search import search_codebase

cache_key = f"_code_{len(events)}_{repo_path}"
if st.session_state.get("_code_cache_key") != cache_key:
    with st.spinner("Scanning codebase..."):
        locations = extract_code_locations(events)
        if locations:
            matches = search_codebase(repo_path, locations, max_results=30)
            st.session_state["_code_matches"] = matches
        else:
            st.session_state["_code_matches"] = []
        st.session_state["_code_cache_key"] = cache_key

matches = st.session_state.get("_code_matches", [])

if not matches:
    st.warning("No stacktrace locations found in log events, or no matching files in the linked repository.")
    st.stop()

# --- Summary metrics ---
by_file: dict[str, list] = {}
for m in matches:
    by_file.setdefault(m.rel_path, []).append(m)

languages = set()
for m in matches:
    if m.location.language:
        languages.add(m.location.language)

col1, col2, col3 = st.columns(3)
col1.metric("Matches", len(matches))
col2.metric("Files", len(by_file))
col3.metric("Languages", ", ".join(sorted(languages)) if languages else "unknown")

st.caption(f"Linked repo: `{repo_path}`")

# --- Confidence legend ---
st.markdown(
    "**Confidence:** "
    ":green_circle: exact (file + line) · "
    ":yellow_circle: file (file match, line approximate) · "
    ":white_circle: grep (text search match)"
)

st.divider()

# --- Code matches grouped by file ---
conf_badge = {"exact": ":green_circle:", "file": ":yellow_circle:", "grep": ":white_circle:"}

for rel_path, file_matches in by_file.items():
    lang = file_matches[0].location.language or "text"
    with st.expander(f"{rel_path} ({len(file_matches)} match{'es' if len(file_matches) != 1 else ''})", expanded=True):
        for m in file_matches:
            badge = conf_badge.get(m.confidence, ":white_circle:")
            method_str = f" — `{m.location.method}()`" if m.location.method else ""
            st.markdown(f"{badge} **Line {m.line_num}**{method_str}")
            st.code("\n".join(m.snippet), language=lang)

            # Show which stacktrace line matched
            source_hint = m.location.source_line or m.location.file_hint
            st.caption(f"Matched from stacktrace: `{source_hint}` [{m.confidence}]")
