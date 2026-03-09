"""Realtime log monitoring module for the Streamlit GUI."""
from __future__ import annotations

import html
import re as _re
import streamlit as st
from pathlib import Path

from app_constants import LEVEL_COLORS, RT_BUFFER_SIZE


_LEVEL_COLORS = LEVEL_COLORS
_LEVEL_HIGHLIGHT_RE = _re.compile(
    r'\b(FATAL|ERROR|SEVERE|WARNING|WARN|INFO|DEBUG)\b'
)

_RT_BUFFER_SIZE = RT_BUFFER_SIZE


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


def _rt_poll(log):
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
        # File was truncated/rotated -- reset
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
def _rt_live_view(log):
    """Fragment that renders controls, polls, and shows the live log buffer."""
    ss = st.session_state
    filepath = ss.rt_file

    # Status
    if not filepath:
        st.info("Enter a log file path or select a detected file above to start monitoring.")
        return

    # Controls -- read state fresh each render
    running = ss.rt_running
    paused = ss.rt_paused
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        if st.button("Start", disabled=running and not paused, key="rt_start"):
            if not _is_safe_rt_path(filepath):
                st.error(f"Invalid or unsafe path: {filepath}. Only .log, .gz, and .txt files are allowed.")
            elif not Path(filepath).exists():
                st.error(f"File not found: {filepath}")
            else:
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
        _rt_poll(log)
        p = Path(filepath)
        if p.exists():
            st.success(f"Monitoring **{p.name}** -- {len(ss.rt_buffer)} lines in buffer")
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
