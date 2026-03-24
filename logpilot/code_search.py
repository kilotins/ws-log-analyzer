"""Search a local codebase for code matching extracted stacktrace locations.

Strictly READ-ONLY — never writes to files. Uses stdlib only (pathlib, re).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .trace_to_code import CodeLocation

# Directories to skip during search
_SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "build", "dist", "target", ".tox", ".mypy_cache", ".pytest_cache",
    "env", ".eggs", ".gradle", ".mvn", ".idea", ".vscode",
})

# Max file size to read (skip generated/binary files)
_MAX_FILE_SIZE = 1_048_576  # 1 MB

# Max files to scan before stopping
_MAX_FILES_SCANNED = 10_000

# File extensions by language
_LANG_EXTENSIONS = {
    "java": {".java", ".kt", ".scala", ".groovy"},
    "python": {".py"},
}


@dataclass
class CodeMatch:
    """A matched code location in the user's codebase."""
    abs_path: str           # Absolute path to the matched file
    rel_path: str           # Relative to repo root
    line_num: int           # 1-based line number of the key match
    snippet: list[str]      # Context lines (numbered)
    location: CodeLocation  # The CodeLocation that triggered this match
    confidence: str         # "exact" (file+line), "file" (file only), "grep" (content match)

    def to_dict(self) -> dict[str, Any]:
        return {
            "abs_path": self.abs_path,
            "rel_path": self.rel_path,
            "line_num": self.line_num,
            "snippet": "\n".join(self.snippet),
            "confidence": self.confidence,
            "language": self.location.language,
            "method": self.location.method,
            "file_hint": self.location.file_hint,
        }


def _iter_files(repo_path: Path, extensions: set[str] | None = None) -> list[Path]:
    """Iterate source files in a repo, respecting skip dirs and limits."""
    files: list[Path] = []
    count = 0

    def _walk(directory: Path) -> None:
        nonlocal count
        if count >= _MAX_FILES_SCANNED:
            return
        try:
            entries = sorted(directory.iterdir())
        except PermissionError:
            return
        for entry in entries:
            if count >= _MAX_FILES_SCANNED:
                return
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS:
                    _walk(entry)
            elif entry.is_file():
                if extensions and entry.suffix not in extensions:
                    continue
                try:
                    if entry.stat().st_size > _MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                files.append(entry)
                count += 1

    _walk(repo_path)
    return files


def _read_snippet(path: Path, line_num: int, context: int = 5) -> list[str]:
    """Read a snippet of code around a specific line number.

    Returns numbered lines: ["  42 |   def foo():", "  43 |       bar()", ...]
    """
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeDecodeError):
        return []

    start = max(0, line_num - 1 - context)
    end = min(len(lines), line_num + context)
    snippet: list[str] = []
    for i in range(start, end):
        marker = ">" if i == line_num - 1 else " "
        snippet.append(f"{marker}{i + 1:5d} | {lines[i]}")
    return snippet


def search_codebase(
    repo_path: str | Path,
    locations: list[CodeLocation],
    context_lines: int = 5,
    max_results: int = 50,
) -> list[CodeMatch]:
    """Search a local codebase for code matching extracted locations.

    Returns matches ordered by confidence (exact > file > grep), limited to max_results.
    Strictly READ-ONLY — only opens files for reading.
    """
    repo = Path(repo_path)
    if not repo.is_dir():
        return []

    matches: list[CodeMatch] = []
    seen_paths: set[tuple[str, int]] = set()  # (rel_path, line) dedup

    # Build file index grouped by language
    all_extensions = set()
    for loc in locations:
        all_extensions.update(_LANG_EXTENSIONS.get(loc.language, set()))
    indexed_files = _iter_files(repo, extensions=all_extensions if all_extensions else None)

    # Build filename → paths lookup
    name_to_paths: dict[str, list[Path]] = {}
    for f in indexed_files:
        name_to_paths.setdefault(f.name, []).append(f)

    for loc in locations:
        if len(matches) >= max_results:
            break

        # Strategy 1: Exact file name match
        candidates = name_to_paths.get(loc.file_hint, [])
        if candidates:
            for cand in candidates:
                rel = str(cand.relative_to(repo))
                if loc.line and (rel, loc.line) not in seen_paths:
                    snippet = _read_snippet(cand, loc.line, context_lines)
                    if snippet:
                        matches.append(CodeMatch(
                            abs_path=str(cand),
                            rel_path=rel,
                            line_num=loc.line,
                            snippet=snippet,
                            location=loc,
                            confidence="exact",
                        ))
                        seen_paths.add((rel, loc.line))
                        break
                elif not loc.line and (rel, 1) not in seen_paths:
                    # File match without line number — show top of file
                    snippet = _read_snippet(cand, 1, context_lines)
                    if snippet:
                        matches.append(CodeMatch(
                            abs_path=str(cand),
                            rel_path=rel,
                            line_num=1,
                            snippet=snippet,
                            location=loc,
                            confidence="file",
                        ))
                        seen_paths.add((rel, 1))
                        break
            continue  # Found file match, skip grep

        # Strategy 2: Grep fallback — search for method/class name in matching files
        search_terms = loc.search_terms()
        if not search_terms:
            continue

        lang_exts = _LANG_EXTENSIONS.get(loc.language, set())
        for f in indexed_files:
            if len(matches) >= max_results:
                break
            if lang_exts and f.suffix not in lang_exts:
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for term in search_terms:
                if term in content:
                    # Find the line number
                    for i, line in enumerate(content.splitlines(), 1):
                        if term in line:
                            rel = str(f.relative_to(repo))
                            if (rel, i) not in seen_paths:
                                snippet = _read_snippet(f, i, context_lines)
                                if snippet:
                                    matches.append(CodeMatch(
                                        abs_path=str(f),
                                        rel_path=rel,
                                        line_num=i,
                                        snippet=snippet,
                                        location=loc,
                                        confidence="grep",
                                    ))
                                    seen_paths.add((rel, i))
                                    break  # One match per file per term
                    break  # First matching term is enough

    # Sort: exact first, then file, then grep
    priority = {"exact": 0, "file": 1, "grep": 2}
    matches.sort(key=lambda m: priority.get(m.confidence, 3))
    return matches[:max_results]
