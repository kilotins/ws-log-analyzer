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

# --- Parse AI code fix suggestions (if available) ---
import re as _re

def _parse_ai_code_fixes(ai_answer: str) -> dict[str, str]:
    """Extract per-file code fix suggestions from AI analysis.

    Looks for the '## Code Fix Suggestions' section and splits by file references.
    Returns {filename_fragment: suggestion_text}.
    """
    if not ai_answer:
        return {}

    # Extract Code Fix Suggestions section
    pattern = r'##\s*Code Fix Suggestions\s*\n(.*?)(?=\n##\s|\Z)'
    m = _re.search(pattern, ai_answer, _re.DOTALL)
    if not m:
        return {}

    section = m.group(1).strip()
    if not section or "skip this section" in section.lower() or "no source code" in section.lower():
        return {}

    # Try to split by file references (e.g., "**PdfExporter.java**" or "`BouncyCastleBeanImpl.java`")
    file_pattern = r'(?:\*\*|`)([\w/]+\.(?:java|py|js|ts|kt|go|rs|rb|cs))(?:\*\*|`)'
    file_refs = list(_re.finditer(file_pattern, section))

    if not file_refs:
        # No file references found — return as general suggestion
        return {"_general": section}

    fixes: dict[str, str] = {}
    for i, fm in enumerate(file_refs):
        filename = fm.group(1)
        start = fm.start()
        end = file_refs[i + 1].start() if i + 1 < len(file_refs) else len(section)
        fixes[filename] = section[start:end].strip()

    return fixes


_ai_answer = st.session_state.get("_incident_answer", "")
_ai_fixes = _parse_ai_code_fixes(_ai_answer)
_has_ai_fixes = bool(_ai_fixes)

if _has_ai_fixes:
    st.success("AI code fix suggestions available — shown below each matching file.")
elif _ai_answer:
    st.caption("AI analysis completed but no code fix suggestions were generated.")
else:
    st.info("Run **AI Analysis** to get code fix suggestions for matched files.")

# --- Code matches grouped by file ---
conf_badge = {"exact": ":green_circle:", "file": ":yellow_circle:", "grep": ":white_circle:"}

for rel_path, file_matches in by_file.items():
    lang = file_matches[0].location.language or "text"
    # Check if AI has suggestions for this file
    _file_fix = None
    if _has_ai_fixes:
        filename = rel_path.rsplit("/", 1)[-1]  # e.g. "BouncyCastleBeanImpl.java"
        for fix_key, fix_text in _ai_fixes.items():
            if fix_key == "_general" or filename in fix_key or fix_key in rel_path:
                _file_fix = fix_text
                break

    _label = rel_path
    if _file_fix:
        _label += " — AI fix available"

    with st.expander(f"{_label} ({len(file_matches)} match{'es' if len(file_matches) != 1 else ''})", expanded=True):
        for m in file_matches:
            badge = conf_badge.get(m.confidence, ":white_circle:")
            method_str = f" — `{m.location.method}()`" if m.location.method else ""
            st.markdown(f"{badge} **Line {m.line_num}**{method_str}")
            st.code("\n".join(m.snippet), language=lang)

            # Show which stacktrace line matched
            source_hint = m.location.source_line or m.location.file_hint
            st.caption(f"Matched from stacktrace: `{source_hint}` [{m.confidence}]")

        # Show AI fix suggestion for this file
        if _file_fix:
            st.markdown("---")
            st.markdown("**AI Fix Suggestion**")
            st.markdown(_file_fix)

# Show general AI suggestions (not tied to a specific file)
if _ai_fixes.get("_general"):
    st.divider()
    st.markdown("### AI Code Fix Suggestions")
    st.markdown(_ai_fixes["_general"])
