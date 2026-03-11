"""Log format plugin registry with auto-detection.

Usage:
    from logpilot.formats import detect_format, get_format, list_formats

    fmt = detect_format(path)       # auto-detect from file content
    fmt = get_format("was")         # explicit format by name
    formats = list_formats()        # all registered formats
"""
from __future__ import annotations

from pathlib import Path
from typing import IO

from .base import LogFormat
from .crio import CRIOFormat
from .json_log import JSONFormat
from .log4j import Log4jFormat
from .nginx import NginxFormat
from .was import WASFormat

# --- Registry ---
# New formats are registered here. Order doesn't matter — detect() scores decide.
_FORMATS: list[LogFormat] = [
    WASFormat(),
    JSONFormat(),
    NginxFormat(),
    Log4jFormat(),
    CRIOFormat(),
]

_FORMAT_MAP: dict[str, LogFormat] = {f.name: f for f in _FORMATS}

# Default fallback when no format scores above threshold
_DEFAULT_FORMAT_NAME = "was"

_DETECT_LINES = 50
_DETECT_THRESHOLD = 0.05


def register_format(fmt: LogFormat) -> None:
    """Register a new log format plugin at runtime."""
    _FORMATS.append(fmt)
    _FORMAT_MAP[fmt.name] = fmt


def get_format(name: str) -> LogFormat:
    """Get a format by name. Raises KeyError if not found."""
    return _FORMAT_MAP[name]


def list_formats() -> list[dict[str, str]]:
    """Return list of {name, description} for all registered formats."""
    return [{"name": f.name, "description": f.description} for f in _FORMATS]


def detect_format(path_or_lines: Path | list[str] | IO[str]) -> LogFormat:
    """Auto-detect log format from file content.

    Reads the first 50 non-empty lines (if given a Path or file object),
    scores each registered format, and returns the best match.
    Falls back to default format if no format scores above threshold.
    """
    lines: list[str]

    if isinstance(path_or_lines, list):
        lines = path_or_lines[:_DETECT_LINES]
    elif isinstance(path_or_lines, Path):
        lines = _read_head_lines(path_or_lines)
    else:
        # File-like object
        lines = []
        for raw_line in path_or_lines:
            stripped = raw_line.rstrip("\n")
            if stripped:
                lines.append(stripped)
            if len(lines) >= _DETECT_LINES:
                break
        # Try to seek back so the file can be re-read for parsing
        try:
            path_or_lines.seek(0)
        except (OSError, AttributeError):
            pass

    if not lines:
        return _FORMAT_MAP[_DEFAULT_FORMAT_NAME]

    best_fmt = _FORMAT_MAP[_DEFAULT_FORMAT_NAME]
    best_score = 0.0

    for fmt in _FORMATS:
        score = fmt.detect(lines)
        if score > best_score:
            best_score = score
            best_fmt = fmt

    if best_score < _DETECT_THRESHOLD:
        return _FORMAT_MAP[_DEFAULT_FORMAT_NAME]

    return best_fmt


def _read_head_lines(path: Path) -> list[str]:
    """Read up to _DETECT_LINES non-empty lines from a file."""
    from ..parser import open_text

    lines: list[str] = []
    try:
        with open_text(path) as f:
            for raw_line in f:
                stripped = raw_line.rstrip("\n")
                if stripped:
                    lines.append(stripped)
                if len(lines) >= _DETECT_LINES:
                    break
    except OSError:
        pass
    return lines
