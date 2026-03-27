"""LogPilot — Home page: upload, configure, and analyze."""
from __future__ import annotations

import hashlib as _hl
from pathlib import Path

import streamlit as st

from app import (
    _expand_uploaded_archives, UPLOADS_DIR, MAX_UPLOAD_MB, log,
    _lookup_cache, _store_cache, provider_history_manager,
)
from logpilot import (
    parse_file, parse_file_cached, precompute_analysis, incident_timeline,
    render_markdown_report, render_json_report,
)
from logpilot.formats import list_formats
from logpilot.discovery import discover_log_files
from logpilot.analysis import sort_events_chronologically

st.title("Analyze Logs")

# --- Upload log files ---
uploaded_files = st.file_uploader(
    "Upload log file(s)",
    type=None,
    accept_multiple_files=True,
    help="Application log files (.log, .gz, .zip). Zip archives are automatically extracted.",
)
uploaded_files = list(uploaded_files) if uploaded_files else []
uploaded_files, _archive_previews = _expand_uploaded_archives(uploaded_files)
for _archive_name, _preview_paths in _archive_previews:
    with st.expander(f"Extracted files from {_archive_name}", expanded=False):
        for _preview_path in _preview_paths:
            st.text(_preview_path)

# --- Upload screenshots ---
_screenshots = st.file_uploader(
    "Upload screenshots (optional, for AI context)",
    type=["png", "jpg", "jpeg", "gif", "webp"],
    accept_multiple_files=True,
    help="Attach screenshots to give AI more context (e.g. error dialog, dashboard).",
    key="_screenshot_uploader",
)
st.session_state._incident_screenshots = list(_screenshots) if _screenshots else []

# --- Show uploaded files list ---
if uploaded_files:
    with st.expander(f"{len(uploaded_files)} file(s) ready", expanded=False):
        for f in uploaded_files:
            size_kb = getattr(f, "size", 0) / 1024
            if size_kb >= 1024:
                size_str = f"{size_kb / 1024:.1f} MB"
            else:
                size_str = f"{size_kb:.1f} KB"
            st.text(f"{f.name}  ({size_str})")
elif not uploaded_files and st.session_state.get("analysis"):
    # Show previously uploaded files from disk when file_uploader resets after navigation
    _existing = sorted(UPLOADS_DIR.iterdir()) if UPLOADS_DIR.exists() else []
    _existing = [f for f in _existing if f.is_file() and not f.name.startswith(".")]
    if _existing:
        with st.expander(f"{len(_existing)} file(s) loaded (from previous upload)", expanded=False):
            for f in _existing:
                size_kb = f.stat().st_size / 1024
                # Strip hash prefix (e.g. "abc1234567_server.log" → "server.log")
                _display_name = f.name.split("_", 1)[1] if "_" in f.name else f.name
                if size_kb >= 1024:
                    size_str = f"{size_kb / 1024:.1f} MB"
                else:
                    size_str = f"{size_kb:.1f} KB"
                st.text(f"{_display_name}  ({size_str})")

# --- Folder scan ---
with st.expander("Or scan a local folder", expanded=False):
    col_path, col_browse = st.columns([4, 1])
    with col_path:
        folder_path = st.text_input(
            "Folder path",
            value=st.session_state.get("folder_path", ""),
            placeholder="/var/log/myapp",
            help="Recursively scans for .log, .txt, .out, .gz files",
            label_visibility="collapsed",
        )
    with col_browse:
        if st.button("Browse...", use_container_width=True):
            _chosen = ""
            try:
                import tkinter as _tk
                from tkinter import filedialog as _fd
                _root = _tk.Tk()
                _root.withdraw()
                _root.attributes("-topmost", True)
                _chosen = _fd.askdirectory(title="Select log folder")
                _root.destroy()
            except Exception:
                try:
                    import subprocess as _sp
                    _result = _sp.run(
                        ["osascript", "-e",
                         'POSIX path of (choose folder with prompt "Select log folder")'],
                        capture_output=True, text=True, timeout=60,
                    )
                    if _result.returncode == 0 and _result.stdout.strip():
                        _chosen = _result.stdout.strip().rstrip("/")
                except Exception as _os_err:
                    st.warning(f"Folder picker not available: {_os_err}")
            if _chosen:
                st.session_state["folder_path"] = _chosen
                st.rerun()

    _folder_files = []
    if folder_path and folder_path.strip():
        from logpilot.discovery import _fmt_size
        _fp = Path(folder_path.strip()).expanduser()
        if _fp.is_dir():
            _disc = discover_log_files(_fp)
            if _disc.accepted:
                st.success(f"Found **{len(_disc.accepted)} files** ({_fmt_size(_disc.total_size)})")
                if _disc.truncated:
                    st.warning(f"\u26a0 {_disc.truncation_reason}")
                with st.container(height=150):
                    for _df in _disc.accepted:
                        st.text(f"\u2713 {_df.relative_path}  ({_fmt_size(_df.size)})")
                if _disc.rejected:
                    with st.expander(f"{len(_disc.rejected)} files skipped"):
                        for _rf in _disc.rejected[:20]:
                            st.text(f"\u2717 {_rf.relative_path} \u2014 {_rf.reason}")
                _folder_files = _disc.accepted
            else:
                st.warning("No supported log files found in this folder.")
                if _disc.rejected:
                    with st.expander(f"{len(_disc.rejected)} files skipped"):
                        for _rf in _disc.rejected[:20]:
                            st.text(f"\u2717 {_rf.relative_path} \u2014 {_rf.reason}")
        elif folder_path.strip():
            st.error("Path is not a valid directory.")

# --- Log format + max lines ---
_formats = list_formats()
_format_names = ["Auto-detect"] + [f["name"] for f in _formats]
_format_help = (
    "Auto-detect analyzes the first 50 lines. Force a format if detection fails.\n\n"
    + "\n".join(f"**{f['name']}** \u2014 {f['description']}" for f in _formats)
)

col_fmt, col_lines = st.columns(2)
with col_fmt:
    _selected_format = st.selectbox(
        "Log format",
        _format_names,
        help=_format_help,
    )
with col_lines:
    max_lines = st.number_input(
        "Max lines per file",
        min_value=1_000, max_value=5_000_000, value=500_000, step=100_000,
        help="Limit lines read per file. Lower = faster parsing, higher = more complete analysis.",
    )

# --- Sample INFO events ---
sample_info_events = st.checkbox(
    "Sample INFO events (large files)",
    value=False,
    help="Keep 1 in 10 INFO events to reduce memory. Recommended for access logs >100K lines.",
)

# --- Symptoms / incident description ---
_symptoms = st.text_area(
    "Describe symptoms (optional)",
    value=st.session_state.get("_incident_description", ""),
    placeholder="e.g. Users get 502 errors since 14:00, restart did not help...",
    help="Give AI context about what you're investigating.",
    key="_symptoms_input",
)
st.session_state._incident_description = _symptoms


# --- Analyze button ---
_has_input = bool(uploaded_files) or bool(_folder_files)
if _has_input and st.button("Analyze", type="primary", use_container_width=False):
    if uploaded_files:
        total_size = sum(getattr(f, "size", 0) for f in uploaded_files)
        _over_limit = total_size > MAX_UPLOAD_MB * 1024 * 1024
        if _over_limit:
            st.error(
                f"Total upload size ({total_size / 1024 / 1024:.1f} MB) exceeds the "
                f"{MAX_UPLOAD_MB} MB limit. Please upload smaller files."
            )
            st.stop()
        elif total_size > 50 * 1024 * 1024:
            st.warning("Large files detected (>50MB). Parsing may take a while.")

    all_events = []
    _session_uploads: set[str] = set()
    _upload_count = len(uploaded_files) if uploaded_files else 0
    _total_files = _upload_count + len(_folder_files)
    _progress = st.progress(0, text=f"Parsing 0/{_total_files} files...")

    # --- Save uploaded files to disk ---
    if uploaded_files:
        for uploaded in uploaded_files:
            safe_name = (
                "".join(c for c in uploaded.name if c.isalnum() or c in "._-")[:100]
                or "upload.log"
            )
            content = uploaded.getvalue()
            _hash = _hl.md5(content).hexdigest()[:10]
            upload_name = f"{_hash}_{safe_name}"
            upload_path = UPLOADS_DIR / upload_name
            if not upload_path.resolve().is_relative_to(UPLOADS_DIR.resolve()):
                st.error(f"Invalid filename: {uploaded.name}")
                continue
            _session_uploads.add(upload_path.name)
            if not upload_path.exists():
                upload_path.write_bytes(content)
                log.info("upload File saved: %s (%d bytes)", upload_name, len(content))
            else:
                log.info("upload File reused (identical): %s", upload_name)

        # Remove old uploads not in this batch
        for old_file in UPLOADS_DIR.iterdir():
            if old_file.name not in _session_uploads and old_file.is_file():
                old_file.unlink()
                log.info("upload Cleaned old upload: %s", old_file.name)

        # Parse each uploaded file
        for _file_idx, uploaded in enumerate(uploaded_files):
            safe_name = (
                "".join(c for c in uploaded.name if c.isalnum() or c in "._-")[:100]
                or "upload.log"
            )
            _hash = _hl.md5(uploaded.getvalue()).hexdigest()[:10]
            upload_path = UPLOADS_DIR / f"{_hash}_{safe_name}"

            _progress.progress(
                _file_idx / _total_files,
                text=f"Parsing {uploaded.name} ({_file_idx + 1}/{_total_files})...",
            )
            try:
                _fmt_name = None if _selected_format == "Auto-detect" else _selected_format
                events = parse_file_cached(
                    upload_path,
                    content_hash=_hash,
                    cache_dir=UPLOADS_DIR / ".cache",
                    max_lines=max_lines,
                    format_name=_fmt_name,
                    sample_info=10 if sample_info_events else 0,
                )
                _stem = (
                    uploaded.name.rsplit(".", 1)[0]
                    if "." in uploaded.name
                    else uploaded.name
                )
                for ev in events:
                    ev.system_label = _stem
                all_events.extend(events)
                log.info("analysis Parsed %d events from %s", len(events), uploaded.name)
            except Exception as ex:
                log.error("analysis Failed to parse %s: %s", uploaded.name, ex)
                st.error(f"Failed to parse {uploaded.name}: {ex}")

    # --- Parse folder files ---
    for _fi, _df in enumerate(_folder_files):
        _idx = _upload_count + _fi
        _progress.progress(
            _idx / _total_files,
            text=f"Parsing {_df.relative_path} ({_idx + 1}/{_total_files})...",
        )
        try:
            _fmt_name = None if _selected_format == "Auto-detect" else _selected_format
            events = parse_file(_df.path, max_lines=max_lines, format_name=_fmt_name)
            _stem = (
                _df.path.stem
                if _df.path.suffix.lower() != ".gz"
                else Path(_df.path.stem).stem
            )
            _label = f"{_df.group}/{_stem}" if _df.group else _stem
            for ev in events:
                ev.system_label = _label
            all_events.extend(events)
            log.info("analysis Parsed %d events from %s", len(events), _df.relative_path)
        except Exception as ex:
            log.error("analysis Failed to parse %s: %s", _df.relative_path, ex)
            st.error(f"Failed to parse {_df.relative_path}: {ex}")

    _progress.progress(
        1.0,
        text=f"Parsed {_total_files} files ({len(all_events):,} events). Analyzing...",
    )

    sort_events_chronologically(all_events)

    if not all_events:
        st.error(
            "No log events found. Possible causes: files may be empty, contain no "
            "recognizable timestamps, or use an unsupported format."
        )
    else:
        def _analysis_progress(text: str, frac: float) -> None:
            _progress.progress(frac, text=text)

        pa = precompute_analysis(
            all_events,
            top_n=10,
            samples_n=5,
            hist_minutes=1,
            progress_callback=_analysis_progress,
        )
        s = pa["summary"]
        error_count = sum(1 for e in all_events if e.level in ("ERROR", "SEVERE", "FATAL"))
        file_summary = pa["file_summary"]
        causes = pa["causes"]
        hist = pa["hist"]
        hung = pa["hung"]
        samples = pa["samples"]
        report_md = render_markdown_report(all_events, _analysis=pa)
        report_json = render_json_report(all_events, _analysis=pa)

        log.info(
            "analysis Analysis complete: %d events, %d errors, %d causes, %d hung threads",
            len(all_events), error_count, len(causes), len(hung),
        )
        if s["codes"]:
            log.info("analysis Top codes: %s", ", ".join(f"{c}({n})" for c, n in s["codes"][:5]))
        if s["exceptions"]:
            log.info(
                "analysis Top exceptions: %s",
                ", ".join(f"{e}({n})" for e, n in s["exceptions"][:5]),
            )

        itl = incident_timeline(all_events, window_seconds=30)

        st.session_state.analysis = {
            "events": all_events,
            "summary": s,
            "error_count": error_count,
            "file_count": _total_files,
            "file_summary": file_summary,
            "causes": causes,
            "hist": hist,
            "hung": hung,
            "samples": samples,
            "cascades": pa.get("cascades", []),
            "grouped": pa.get("grouped"),
            "failure_chain": pa.get("failure_chain", {}),
            "incident_timeline": itl,
            "total_events": len(all_events),
            "report_md": report_md,
            "report_json": report_json,
            "top_n": 10,
            "samples_n": 5,
            "hist_minutes": 1,
        }
        st.session_state.claude_answer = None
        st.session_state.claude_query_label = None
        st.session_state.claude_history = []
        st.session_state.selected_code = None
        st.session_state.selected_action = None
        st.session_state._incident_answer = None
        st.session_state._leadership_brief = None
        provider_history_manager.save("claude", [])

        st.success(
            f"Analysis complete: {len(all_events):,} events, {error_count:,} errors. "
            "Go to **Overview** to see results."
        )

elif not _has_input:
    st.info("Upload log files or select a folder to get started.")
