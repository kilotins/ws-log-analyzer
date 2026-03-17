"""Audit tab module for the Streamlit GUI."""
from __future__ import annotations

import ast
import sys
import textwrap
import streamlit as st
from datetime import datetime
from pathlib import Path

from logpilot import ask_gemini, estimate_tokens
from app_spend import record_spend


def _get_app_dir():
    """Return the application directory (same as app.py's _APP_DIR)."""
    return Path(__file__).parent


_AUDIT_FILES_FULL = [
    "logpilot/parser.py", "logpilot/analysis.py", "logpilot/reports.py", "logpilot/ai.py", "logpilot/cli.py",
    "app.py", "tests/test_wslog.py", "CLAUDE.md", "ARCHITECTURE.md",
]
_AUDIT_FILES_COMPACT = ["logpilot/parser.py", "logpilot/analysis.py", "logpilot/ai.py", "app.py", "CLAUDE.md"]
_AUDIT_SKILL_DIRS = ["skills", ".claude/skills"]

_AUDIT_MODELS = {
    "Local AI (free — uses active model)": {"provider": "local", "id": "", "max_tokens": 8192, "compact": True},
    "Claude — Sonnet 4.6 (~$0.20)": {"provider": "claude", "id": "claude-sonnet-4-6", "max_tokens": 8192, "compact": True},
    "Claude — Opus 4.6 (~$1.00)": {"provider": "claude", "id": "claude-opus-4-6", "max_tokens": 8192},
    "Claude — Haiku 4.5 (~$0.05)": {"provider": "claude", "id": "claude-haiku-4-5-20251001", "max_tokens": 8192, "compact": True},
    "Gemini — 2.5 Pro (~$0.15)": {"provider": "gemini", "id": "gemini-2.5-pro", "max_tokens": 8192},
    "Gemini — 2.5 Flash (~$0.03)": {"provider": "gemini", "id": "gemini-2.5-flash", "max_tokens": 8192},
    "OpenAI — GPT-4o (~$0.15)": {"provider": "openai", "id": "gpt-4o", "max_tokens": 8192, "compact": True},
    "OpenAI — GPT-4o mini (~$0.02)": {"provider": "openai", "id": "gpt-4o-mini", "max_tokens": 8192, "compact": True},
    "OpenAI — o3 (~$0.60)": {"provider": "openai", "id": "o3", "max_tokens": 8192, "compact": True},
    "OpenAI — o4-mini (~$0.07)": {"provider": "openai", "id": "o4-mini", "max_tokens": 8192, "compact": True},
}

_AUDIT_SYSTEM_PROMPT = """\
You are a senior software engineer performing a technical audit of a Python project.
Produce a structured Markdown report with these sections:
1. Executive Summary (strengths, key findings)
2. Repository Overview (file counts, line counts)
3. Documentation Audit (accuracy, completeness)
4. Skills System Analysis (coverage, gaps)
5. Code Review Findings (bugs, style, security)
6. AI Integration Review (prompt safety, caching)
7. Test Coverage Analysis (coverage, gaps)
8. Refactoring Opportunities
9. Feature Opportunities
10. Prioritized Improvement Plan

For each section, assign a grade: A, A-, B+, B, B-, C+, C, or lower.
Include an overall grade at the top. Use this format for grades:
**Grade: X/10** (or letter grade)

Mark fixed issues with ~~strikethrough~~ ✅ Fixed.
Be specific — reference file names, line numbers, and function names.
Start the report with: # Technical Audit Report — LogPilot
"""


_COMPACT_MAX_LINES = 250  # Max lines per file in compact mode


def _extract_signatures_regex(content: str) -> str:
    """Regex fallback: extract function/class signatures and docstrings from Python source."""
    lines = content.splitlines()
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        if (stripped.startswith(("import ", "from ", "class ", "def "))
                or (stripped and not stripped.startswith("#") and "=" in stripped.split("#")[0]
                    and not stripped.startswith(" ") and not stripped.startswith("\t"))):
            result.append(line)
            if stripped.startswith(("def ", "class ")):
                if not line.rstrip().endswith(":"):
                    i += 1
                    while i < len(lines) and not lines[i].rstrip().endswith(":"):
                        result.append(lines[i])
                        i += 1
                    if i < len(lines):
                        result.append(lines[i])
                i += 1
                if i < len(lines) and '"""' in lines[i]:
                    result.append(lines[i])
                    if lines[i].count('"""') < 2:
                        i += 1
                        while i < len(lines) and '"""' not in lines[i]:
                            result.append(lines[i])
                            i += 1
                        if i < len(lines):
                            result.append(lines[i])
                    i += 1
                    continue
        i += 1
    return "\n".join(result)


def _extract_signatures(content: str) -> str:
    """Extract function/class signatures and docstrings from Python source using AST.

    Falls back to regex-based extraction if ast.parse() fails (e.g. non-Python or partial files).
    """
    source_lines = content.splitlines()

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return _extract_signatures_regex(content)

    result = []

    def _get_source_line(lineno: int) -> str:
        """Return 0-indexed source line."""
        return source_lines[lineno - 1] if 1 <= lineno <= len(source_lines) else ""

    def _get_docstring_lines(node) -> list[str]:
        """Extract docstring lines from a function/class node."""
        ds = ast.get_docstring(node)
        if not ds:
            return []
        # Find the actual docstring node to get its source lines
        first_stmt = node.body[0]
        lines_out = []
        for ln in range(first_stmt.lineno, first_stmt.end_lineno + 1):
            lines_out.append(_get_source_line(ln))
        return lines_out

    def _get_decorator_lines(node) -> list[str]:
        """Extract decorator lines from a function/class node."""
        lines_out = []
        for dec in node.decorator_list:
            for ln in range(dec.lineno, dec.end_lineno + 1):
                lines_out.append(_get_source_line(ln))
        return lines_out

    def _get_signature_lines(node) -> list[str]:
        """Extract the def/class signature line(s) up to the colon."""
        lines_out = []
        # The signature spans from node.lineno to the line containing the colon
        # For functions/classes the body starts after the signature
        body_start = node.body[0].lineno if node.body else node.end_lineno
        for ln in range(node.lineno, body_start):
            line = _get_source_line(ln)
            lines_out.append(line)
            if line.rstrip().endswith(":"):
                break
        if not lines_out:
            lines_out.append(_get_source_line(node.lineno))
        return lines_out

    def _process_class(cls_node, indent=0):
        """Process a class definition: signature, docstring, and method signatures."""
        result.extend(_get_decorator_lines(cls_node))
        result.extend(_get_signature_lines(cls_node))
        result.extend(_get_docstring_lines(cls_node))
        # Process methods inside the class
        for item in cls_node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result.extend(_get_decorator_lines(item))
                result.extend(_get_signature_lines(item))
                result.extend(_get_docstring_lines(item))
            elif isinstance(item, ast.ClassDef):
                _process_class(item, indent + 1)

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            # Emit import lines as-is from source
            for ln in range(node.lineno, node.end_lineno + 1):
                result.append(_get_source_line(ln))
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            # Module-level constant/assignment — first line only
            result.append(_get_source_line(node.lineno))
        elif isinstance(node, ast.ClassDef):
            _process_class(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result.extend(_get_decorator_lines(node))
            result.extend(_get_signature_lines(node))
            result.extend(_get_docstring_lines(node))

    # Respect compact limit
    output = "\n".join(result)
    out_lines = output.splitlines()
    if len(out_lines) > _COMPACT_MAX_LINES:
        out_lines = out_lines[:_COMPACT_MAX_LINES]
        output = "\n".join(out_lines)
    return output


def _collect_audit_sources(compact=False):
    """Collect source files for auditing. Compact mode sends signatures + docstrings."""
    app_dir = _get_app_dir()
    file_list = _AUDIT_FILES_COMPACT if compact else _AUDIT_FILES_FULL
    file_contents = []
    for rel in file_list:
        path = app_dir / rel
        if path.is_file():
            content = path.read_text(encoding="utf-8", errors="replace")
            all_lines = content.splitlines()
            total = len(all_lines)
            if compact and total > _COMPACT_MAX_LINES and rel.endswith(".py"):
                sig_content = _extract_signatures(content)
                sig_lines = len(sig_content.splitlines())
                file_contents.append(
                    f"--- {rel} ({total} lines, showing {sig_lines} signature lines) ---\n{sig_content}"
                )
            elif compact and total > _COMPACT_MAX_LINES:
                content = "\n".join(all_lines[:_COMPACT_MAX_LINES])
                file_contents.append(f"--- {rel} ({total} lines, showing first {_COMPACT_MAX_LINES}) ---\n{content}")
            else:
                file_contents.append(f"--- {rel} ({total} lines) ---\n{content}")

    # In compact mode, only include skill filenames (not full content)
    if compact:
        skill_names = []
        for skill_dir in _AUDIT_SKILL_DIRS:
            sdir = app_dir / skill_dir
            if sdir.is_dir():
                for sf in sorted(sdir.glob("*.md")) + sorted(sdir.glob("*.yaml")):
                    skill_names.append(str(sf.relative_to(app_dir)))
        if skill_names:
            file_contents.append(f"--- Skills files (names only) ---\n" + "\n".join(skill_names))
    else:
        for skill_dir in _AUDIT_SKILL_DIRS:
            sdir = app_dir / skill_dir
            if sdir.is_dir():
                for sf in sorted(sdir.glob("*.md")) + sorted(sdir.glob("*.yaml")):
                    content = sf.read_text(encoding="utf-8", errors="replace")
                    rel_path = sf.relative_to(app_dir)
                    file_contents.append(f"--- {rel_path} ({len(content.splitlines())} lines) ---\n{content}")

    return "Perform a full technical audit of the following codebase.\n\n" + "\n\n".join(file_contents)


_AUDIT_TIMEOUT = 300.0


def _run_audit_claude(api_key, model_id, max_tokens, compact=False):
    """Run audit via Claude API. Returns (text, usage_dict)."""
    from app_ai import call_claude_api
    prompt = {"system": _AUDIT_SYSTEM_PROMPT, "user": _collect_audit_sources(compact=compact)}
    return call_claude_api(api_key, model_id, prompt, timeout=_AUDIT_TIMEOUT, max_tokens=max_tokens)


def _run_audit_gemini(api_key, model_id, compact=False):
    """Run audit via Gemini API. Returns (text, usage_dict)."""
    from app_ai import call_gemini_api
    prompt = {"system": _AUDIT_SYSTEM_PROMPT, "user": _collect_audit_sources(compact=compact)}
    return call_gemini_api(api_key, model_id, prompt, timeout=_AUDIT_TIMEOUT)


def _run_audit_openai(api_key, model_id, max_tokens, compact=False):
    """Run audit via OpenAI API. Returns (text, usage_dict)."""
    from app_ai import call_openai_api
    prompt = {"system": _AUDIT_SYSTEM_PROMPT, "user": _collect_audit_sources(compact=compact)}
    return call_openai_api(api_key, model_id, prompt, timeout=_AUDIT_TIMEOUT, max_tokens=max_tokens)


def _run_audit_local(model_id, max_tokens, compact=False):
    """Run audit via local OpenAI-compatible API. Returns (text, usage_dict)."""
    from app_ai import call_local_api
    api_key = getattr(st.session_state, "local_ai_api_key", "") or "not-needed"
    base_url = getattr(st.session_state, "local_ai_endpoint", "") or None
    if not model_id:
        model_id = getattr(st.session_state, "local_ai_model", "") or "default"
    prompt = {"system": _AUDIT_SYSTEM_PROMPT, "user": _collect_audit_sources(compact=compact)}
    return call_local_api(api_key, model_id, prompt, timeout=_AUDIT_TIMEOUT,
                          max_tokens=max_tokens, base_url=base_url)


def _run_audit(model_label, log, status=None):
    """Run a full audit and regenerate the HTML report."""
    from report_renderer import render_html
    from app_ai import _log_probe

    def _status_write(msg):
        if status:
            status.write(msg)

    app_dir = _get_app_dir()
    model_info = _AUDIT_MODELS[model_label]
    provider = model_info["provider"]
    compact = model_info.get("compact", False)

    _status_write("Collecting source files...")
    _audit_req = _collect_audit_sources(compact=compact)
    _audit_req_text = f"[SYSTEM]\n{_AUDIT_SYSTEM_PROMPT}\n\n[USER]\n{_audit_req}"

    if provider == "local":
        local_model = model_info["id"] or getattr(st.session_state, "local_ai_model", "") or "default"
        endpoint = getattr(st.session_state, "local_ai_endpoint", "")
        if not endpoint:
            raise ValueError("Configure a Local AI endpoint in the sidebar first.")
        _status_write(f"Sending to Local AI ({local_model})... this may take a few minutes.")
        audit_md, usage = _run_audit_local(local_model, model_info["max_tokens"], compact=compact)
    elif provider == "claude":
        if not st.session_state.api_key:
            raise ValueError("Enter your Anthropic API key in the sidebar. Open **API Keys** to configure.")
        _status_write(f"Sending to Claude ({model_info['id']})... this may take 1-2 minutes.")
        audit_md, usage = _run_audit_claude(
            st.session_state.api_key, model_info["id"], model_info["max_tokens"], compact=compact
        )
    elif provider == "gemini":
        gemini_key = st.session_state.gemini_api_key
        if not gemini_key:
            raise ValueError("Enter your Gemini API key in the sidebar. Open **API Keys** to configure.")
        _status_write(f"Sending to Gemini ({model_info['id']})... this may take 1-2 minutes.")
        audit_md, usage = _run_audit_gemini(gemini_key, model_info["id"], compact=compact)
    else:
        openai_key = st.session_state.openai_api_key
        if not openai_key:
            raise ValueError("Enter your OpenAI API key in the sidebar. Open **API Keys** to configure.")
        _status_write(f"Sending to OpenAI ({model_info['id']})... this may take 1-2 minutes.")
        audit_md, usage = _run_audit_openai(
            openai_key, model_info["id"], model_info["max_tokens"], compact=compact
        )

    _audit_model_id = model_info["id"] or getattr(st.session_state, "local_ai_model", "local")
    _log_probe("Audit", provider, _audit_model_id, _audit_req_text, audit_md or "")

    _status_write("Tracking spend...")
    # Track spend (including cache tokens for Claude)
    spend_model = model_info["id"] or getattr(st.session_state, "local_ai_model", "local") or "local"
    record_spend(provider, spend_model, usage.get("input", 0), usage.get("output", 0),
                 source="audit", cache_creation=usage.get("cache_creation", 0),
                 cache_read=usage.get("cache_read", 0))

    if not audit_md:
        raise ValueError("Model returned an empty response.")

    _status_write("Generating report...")
    # Save markdown
    md_path = app_dir / "AUDIT_REPORT.md"
    md_path.write_text(audit_md, encoding="utf-8")

    # Version the report and generate delta if previous exists
    _delta_md = None
    try:
        reports_dir = app_dir / "reports"
        reports_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        versioned = reports_dir / f"AUDIT_{timestamp}.md"
        versioned.write_text(audit_md, encoding="utf-8")
        log.info("audit Versioned report: %s", versioned.name)

        # Find previous versioned report
        import re as _re_mod
        pattern = _re_mod.compile(r'^AUDIT_\d{4}-\d{2}-\d{2}_\d{4}\.md$')
        all_reports = sorted(p for p in reports_dir.iterdir() if pattern.match(p.name))
        previous = None
        for r in all_reports:
            if r != versioned:
                previous = r
        if previous:
            sys.path.insert(0, str(app_dir / "scripts"))
            from compare_audits import compare_audits, render_delta
            results = compare_audits(previous, versioned)
            _delta_md = render_delta(results, previous.name, versioned.name)
            delta_path = reports_dir / f"DELTA_AUDIT_{timestamp}.md"
            delta_path.write_text(_delta_md, encoding="utf-8")
            log.info("audit Delta report: %s", delta_path.name)
    except Exception as ex:
        log.warning("audit Could not generate delta: %s", ex)

    # Convert to HTML
    audit_html = render_html(audit_md, title="Technical Audit Report -- LogPilot")
    html_path = app_dir / "AUDIT_REPORT.html"
    html_path.write_text(audit_html, encoding="utf-8")

    log.info("audit Audit report generated with %s: %s", model_label, html_path)
    # Store delta for display
    if _delta_md:
        st.session_state._audit_delta = _delta_md
    return audit_html


_AUDIT_LIGHT_CSS = """
<style>
:root {
  --bg-primary: #ffffff !important;
  --bg-secondary: #f6f8fa !important;
  --bg-tertiary: #f0f2f5 !important;
  --bg-hover: #e8eaed !important;
  --border: #d0d7de !important;
  --border-strong: #bbc0c7 !important;
  --text-primary: #1f2328 !important;
  --text-secondary: #2d333b !important;
  --text-muted: #656d76 !important;
  --text-heading: #1f2328 !important;
  --accent: #0969da !important;
  --green: #1a7f37 !important;
  --green-bg: #dafbe1 !important;
  --yellow: #9a6700 !important;
  --yellow-bg: #fff8c5 !important;
  --red: #cf222e !important;
  --red-bg: #ffebe9 !important;
  --blue: #0969da !important;
  --blue-bg: #ddf4ff !important;
  --purple: #8250df !important;
  --purple-bg: #fbefff !important;
}
body { background: #ffffff !important; color: #2d333b !important; }
nav { display: none !important; }
.layout { display: block !important; }
main { max-width: 800px !important; margin: 0 !important; padding: 20px !important; }
</style>
"""
