"""Recursive log file discovery and filtering.

Traverses a directory tree, finds log files by extension and content
sniffing, applies size/count limits, and groups files by path structure.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

_log = logging.getLogger(__name__)

# ── Defaults ────────────────────────────────────────────────────────

INCLUDE_EXTENSIONS: frozenset[str] = frozenset({
    ".log", ".txt", ".out", ".gz", ".json", ".ndjson",
})

# Filename patterns that indicate log files regardless of extension
# (e.g. "accesslog.2026.03.11", "server.log.1", "messages.20260319")
_LOG_NAME_RE = re.compile(
    r'(access[-_.]?log|error[-_.]?log|server[-_.]?log|system[-_.]?out|'
    r'catalina\.out|messages|syslog|SystemOut|SystemErr)',
    re.IGNORECASE,
)

EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".git", ".svn", ".hg", "__pycache__", "node_modules",
    ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
})

DEFAULT_MAX_FILES = 100
DEFAULT_MAX_TOTAL_SIZE = 500 * 1024 * 1024  # 500 MB
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024   # 100 MB


# ── Data classes ────────────────────────────────────────────────────


@dataclass
class DiscoveredFile:
    """A file found during directory traversal."""

    path: Path
    relative_path: str
    size: int
    group: str


@dataclass
class RejectedFile:
    """A file that was found but excluded."""

    path: Path
    relative_path: str
    reason: str


@dataclass
class DiscoveryResult:
    """Result of a directory scan."""

    accepted: list[DiscoveredFile] = field(default_factory=list)
    rejected: list[RejectedFile] = field(default_factory=list)
    total_size: int = 0
    truncated: bool = False
    truncation_reason: str = ""


# ── Core functions ──────────────────────────────────────────────────


def _is_binary(path: Path, probe_size: int = 512) -> bool:
    """Check if a file is likely binary by looking for null bytes."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(probe_size)
        return b"\x00" in chunk
    except (OSError, PermissionError):
        return True


def _is_hidden(path: Path) -> bool:
    """Check if any component of the path starts with a dot."""
    return any(part.startswith(".") for part in path.parts)


def guess_group(relative_path: str) -> str:
    """Extract a service/group name from a relative path.

    Examples:
        "api/server.log"          → "api"
        "logs/worker/out.log"     → "worker"
        "server.log"              → ""  (root level)
        "a/b/c/deep.log"          → "a/b/c"
    """
    p = Path(relative_path)
    if p.parent == Path("."):
        return ""
    return str(p.parent)


def discover_log_files(
    root: Path,
    *,
    include_extensions: frozenset[str] = INCLUDE_EXTENSIONS,
    exclude_dirs: frozenset[str] = EXCLUDE_DIRS,
    include_hidden: bool = False,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> DiscoveryResult:
    """Recursively discover log files in a directory.

    Args:
        root: Directory to scan.
        include_extensions: File extensions to include (with dot).
        exclude_dirs: Directory names to skip entirely.
        include_hidden: Whether to include hidden files/dirs.
        max_files: Maximum number of files to accept.
        max_total_size: Maximum total size in bytes.
        max_file_size: Maximum size per file in bytes.

    Returns:
        DiscoveryResult with accepted/rejected files and metadata.
    """
    root = root.resolve()
    result = DiscoveryResult()

    if not root.is_dir():
        _log.warning("discover_log_files: %s is not a directory", root)
        return result

    candidates: list[tuple[Path, str, int]] = []

    for dirpath, dirnames, filenames in os.walk(root):
        dp = Path(dirpath)

        # Prune excluded directories in-place
        dirnames[:] = [
            d for d in dirnames
            if d not in exclude_dirs and (include_hidden or not d.startswith("."))
        ]

        for fname in sorted(filenames):
            fpath = dp / fname
            rel = str(fpath.relative_to(root))

            # Skip hidden files
            if not include_hidden and fname.startswith("."):
                continue

            # Check extension — with name-based fallback for rotated logs
            suffix = fpath.suffix.lower()
            # For .gz, check the double extension (e.g. .log.gz)
            if suffix == ".gz":
                stem_suffix = Path(fpath.stem).suffix.lower()
                if stem_suffix and stem_suffix not in include_extensions:
                    result.rejected.append(RejectedFile(fpath, rel, "extension not in include list"))
                    continue
            elif suffix not in include_extensions:
                # Fallback: check if filename contains log-like patterns
                # (e.g. "accesslog.2026.03.11", "server.log.1", "messages.20260319")
                if not _LOG_NAME_RE.search(fname):
                    result.rejected.append(RejectedFile(fpath, rel, "extension not in include list"))
                    continue

            # Get file size
            try:
                size = fpath.stat().st_size
            except (OSError, PermissionError) as exc:
                result.rejected.append(RejectedFile(fpath, rel, f"cannot stat: {exc}"))
                continue

            # Skip empty files
            if size == 0:
                result.rejected.append(RejectedFile(fpath, rel, "empty file"))
                continue

            # Per-file size limit
            if size > max_file_size:
                result.rejected.append(RejectedFile(fpath, rel, f"exceeds max file size ({size:,} bytes)"))
                continue

            # Binary check (skip for .gz files)
            if suffix != ".gz" and _is_binary(fpath):
                result.rejected.append(RejectedFile(fpath, rel, "binary file"))
                continue

            candidates.append((fpath, rel, size))

    # Sort by relative path for deterministic order
    candidates.sort(key=lambda x: x[1])

    # Apply limits
    running_size = 0
    for fpath, rel, size in candidates:
        if len(result.accepted) >= max_files:
            result.truncated = True
            result.truncation_reason = f"max files limit ({max_files}) reached"
            result.rejected.append(RejectedFile(fpath, rel, "max files limit reached"))
            continue

        if running_size + size > max_total_size:
            result.truncated = True
            result.truncation_reason = f"max total size ({max_total_size:,} bytes) reached"
            result.rejected.append(RejectedFile(fpath, rel, "max total size limit reached"))
            continue

        group = guess_group(rel)
        result.accepted.append(DiscoveredFile(
            path=fpath,
            relative_path=rel,
            size=size,
            group=group,
        ))
        running_size += size

    result.total_size = running_size
    _log.info("discover_log_files: %s → %d accepted, %d rejected, %s total",
              root, len(result.accepted), len(result.rejected), _fmt_size(result.total_size))
    return result


def _fmt_size(nbytes: int) -> str:
    """Format bytes as human-readable string."""
    if nbytes < 1024:
        return f"{nbytes} B"
    if nbytes < 1024 * 1024:
        return f"{nbytes / 1024:.1f} KB"
    if nbytes < 1024 * 1024 * 1024:
        return f"{nbytes / (1024 * 1024):.1f} MB"
    return f"{nbytes / (1024 * 1024 * 1024):.1f} GB"
