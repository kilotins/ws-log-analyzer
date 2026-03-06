#!/usr/bin/env python3
"""Convert Markdown audit reports to self-contained HTML with collapsible sections.

Usage:
    python report_renderer.py AUDIT_REPORT.md --open
    python report_renderer.py AUDIT_REPORT.md -o reports/AUDIT_REPORT.html
"""

import argparse
import re
import sys
import webbrowser
from html import escape
from pathlib import Path

# ---------------------------------------------------------------------------
# Markdown → HTML converter  (no external deps — handles audit report patterns)
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"^```(\w*)\s*$")
_TABLE_SEP_RE = re.compile(r"^\|[-| :]+\|$")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+)$")
_HR_RE = re.compile(r"^-{3,}\s*$")
_UL_RE = re.compile(r"^(\s*)[-*]\s+(.+)$")
_OL_RE = re.compile(r"^(\s*)\d+[.)]\s+(.+)$")
_TABLE_ROW_RE = re.compile(r"^\|(.+)\|$")


def _inline(text: str) -> str:
    """Convert inline markdown to HTML."""
    text = escape(text)
    text = re.sub(r"\*\*\*(.+?)\*\*\*", r"<strong><em>\1</em></strong>", text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    text = re.sub(r"`([^`]+)`", r'<code class="inline">\1</code>', text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    return text


def _highlight_code(code: str, lang: str) -> str:
    """Basic syntax highlighting via CSS classes."""
    code = escape(code)
    if lang in ("python", "py"):
        kw = (r"\b(def|class|import|from|if|elif|else|for|while|return|with|as|"
              r"try|except|raise|not|and|or|in|is|None|True|False|self|yield|"
              r"lambda|pass|break|continue|async|await)\b")
        code = re.sub(kw, r'<span class="kw">\1</span>', code)
        code = re.sub(r"(#[^\n]*)", r'<span class="cm">\1</span>', code)
        code = re.sub(r'(&quot;[^&]*?&quot;|&#x27;[^&]*?&#x27;)',
                       r'<span class="st">\1</span>', code)
    elif lang in ("spl", "splunk"):
        code = re.sub(
            r"\b(index|sourcetype|stats|timechart|table|where|eval|head|"
            r"sort|count|by|span|earliest|latest|predict|transaction|rex|"
            r"search|fields|rename|dedup|top|rare)\b",
            r'<span class="kw">\1</span>', code)
        code = re.sub(r"(\|)", r'<span class="op">\1</span>', code)
    elif lang in ("bash", "sh", "shell"):
        code = re.sub(r"(#[^\n]*)", r'<span class="cm">\1</span>', code)
        code = re.sub(
            r"\b(pip|python3?|pytest|streamlit|git|cd|ls|kill|lsof|export|"
            r"echo|rm|mkdir|cat|grep|find|curl|wget)\b",
            r'<span class="kw">\1</span>', code)
    elif lang in ("xml", "html"):
        code = re.sub(r"(&lt;/?[a-zA-Z_][^&]*?&gt;)",
                       r'<span class="kw">\1</span>', code)
    elif lang == "json":
        code = re.sub(r'(&quot;[^&]*?&quot;)\s*:',
                       r'<span class="kw">\1</span>:', code)
        code = re.sub(r':\s*(&quot;[^&]*?&quot;)',
                       r': <span class="st">\1</span>', code)
    return code


def md_to_html(md: str) -> str:
    """Convert markdown text to HTML body content."""
    lines = md.split("\n")
    out: list[str] = []
    i = 0
    in_table = False

    def _flush_table():
        nonlocal in_table
        if in_table:
            out.append("</tbody></table></div>")
            in_table = False

    while i < len(lines):
        line = lines[i]

        # --- Fenced code block ---
        fence = _FENCE_RE.match(line)
        if fence:
            _flush_table()
            lang = fence.group(1) or ""
            code_lines: list[str] = []
            i += 1
            while i < len(lines) and not _FENCE_RE.match(lines[i]):
                code_lines.append(lines[i])
                i += 1
            code = "\n".join(code_lines)
            highlighted = _highlight_code(code, lang)
            lang_attr = f' data-lang="{escape(lang)}"' if lang else ""
            out.append(
                f'<pre class="code-block"{lang_attr}><code>{highlighted}</code></pre>'
            )
            i += 1
            continue

        # --- Heading ---
        hm = _HEADING_RE.match(line)
        if hm:
            _flush_table()
            level = len(hm.group(1))
            raw_text = hm.group(2)
            html_text = _inline(raw_text)
            slug = re.sub(r"[^a-z0-9]+", "-", raw_text.lower()).strip("-")
            out.append(f'<h{level} id="{slug}">{html_text}</h{level}>')
            i += 1
            continue

        # --- Horizontal rule ---
        if _HR_RE.match(line):
            _flush_table()
            out.append("<hr>")
            i += 1
            continue

        # --- Table ---
        tr = _TABLE_ROW_RE.match(line)
        if tr:
            if not in_table:
                if i + 1 < len(lines) and _TABLE_SEP_RE.match(lines[i + 1]):
                    cells = [c.strip() for c in tr.group(1).split("|")]
                    hdr = "".join(f"<th>{_inline(c)}</th>" for c in cells)
                    out.append(
                        f'<div class="table-wrap"><table>'
                        f'<thead><tr>{hdr}</tr></thead><tbody>'
                    )
                    in_table = True
                    i += 2
                    continue
                else:
                    out.append('<div class="table-wrap"><table><tbody>')
                    in_table = True
            if in_table:
                if _TABLE_SEP_RE.match(line):
                    i += 1
                    continue
                cells = [c.strip() for c in tr.group(1).split("|")]
                row = "".join(f"<td>{_inline(c)}</td>" for c in cells)
                out.append(f"<tr>{row}</tr>")
                i += 1
                continue

        if in_table and not _TABLE_ROW_RE.match(line):
            _flush_table()

        # --- Unordered list ---
        if _UL_RE.match(line):
            items: list[str] = []
            while i < len(lines):
                m = _UL_RE.match(lines[i])
                if m:
                    items.append(f"<li>{_inline(m.group(2))}</li>")
                    i += 1
                elif lines[i].startswith("  ") and items:
                    items[-1] = items[-1].replace(
                        "</li>", f" {_inline(lines[i].strip())}</li>"
                    )
                    i += 1
                else:
                    break
            out.append(f'<ul>{"".join(items)}</ul>')
            continue

        # --- Ordered list ---
        if _OL_RE.match(line):
            items = []
            while i < len(lines):
                m = _OL_RE.match(lines[i])
                if m:
                    items.append(f"<li>{_inline(m.group(2))}</li>")
                    i += 1
                else:
                    break
            out.append(f'<ol>{"".join(items)}</ol>')
            continue

        # --- Blank line ---
        if not line.strip():
            _flush_table()
            i += 1
            continue

        # --- Paragraph (absorb consecutive non-special lines) ---
        para: list[str] = []
        while (i < len(lines) and lines[i].strip()
               and not _HEADING_RE.match(lines[i])
               and not _FENCE_RE.match(lines[i])
               and not _HR_RE.match(lines[i])
               and not _UL_RE.match(lines[i])
               and not _OL_RE.match(lines[i])
               and not _TABLE_ROW_RE.match(lines[i])):
            para.append(lines[i])
            i += 1
        if para:
            out.append(f"<p>{_inline(' '.join(para))}</p>")

    _flush_table()
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Severity extraction — parse grades from the report itself
# ---------------------------------------------------------------------------

_GRADE_COLORS = {
    "A+": "good", "A": "good", "A-": "good",
    "B+": "warn", "B": "warn", "B-": "warn",
    "C+": "bad", "C": "bad", "C-": "bad",
    "D": "bad", "F": "bad",
}

# Patterns to extract grades from various report formats:
# 1) Table rows: "| Architecture | **A-** | ..."  or "| Architecture | A- | ..."
# 2) Inline: "Architecture: A-"  or "Architecture — A-"
# 3) "Grade: A-"
_GRADE_PATTERNS = [
    # Table: | Area | Grade | ... (with optional ** bold markers)
    re.compile(
        r"\|\s*\*{0,2}(Architecture|Security|AI Integration|Tests?(?:\s*&\s*Reliability)?|"
        r"Skills?\s*System|Reliability|Prompt\s*Safety|Caching)\*{0,2}\s*\|"
        r"[^|]*?\*{0,2}([ABCDF][+-]?)\*{0,2}\s*\|",
        re.IGNORECASE,
    ),
    # Inline: "Area ... A-" within same line
    re.compile(
        r"\b(Architecture|Security|AI Integration|Tests?|Skills?\s*System|Reliability)"
        r"\b[^|\n]{0,30}?\b([ABCDF][+-]?)\b",
        re.IGNORECASE,
    ),
    # "Grade: A-"
    re.compile(r"Grade:\s*\*{0,2}([ABCDF][+-]?)\*{0,2}", re.IGNORECASE),
]


def _extract_grades(md: str) -> list[tuple[str, str, str]]:
    """Extract (label, grade, css_class) tuples from the markdown."""
    seen: set[str] = set()
    results: list[tuple[str, str, str]] = []

    for pattern in _GRADE_PATTERNS:
        for m in pattern.finditer(md):
            if pattern.groups == 1:
                # "Grade: X" pattern — use surrounding context as label
                label = "Overall"
                grade = m.group(1).upper()
            else:
                label = m.group(1).strip().title()
                grade = m.group(2).upper()
            key = label.lower().replace("  ", " ")
            if key not in seen and grade in _GRADE_COLORS:
                seen.add(key)
                css = _GRADE_COLORS[grade]
                results.append((label, grade, css))
    return results


# ---------------------------------------------------------------------------
# Section wrapping — collapsible <details> with anchor IDs
# ---------------------------------------------------------------------------

_SECTION_BADGES: dict[str, tuple[str, str]] = {
    "executive summary": ("summary", ""),
    "repository overview": ("info", ""),
    "system architecture": ("good", ""),
    "security": ("warn", ""),
    "ai integration": ("good", ""),
    "test": ("good", ""),
    "skills system": ("good", ""),
    "documentation": ("info", ""),
    "code review": ("warn", ""),
    "refactoring": ("info", ""),
    "feature opportunit": ("info", ""),
    "prioritized improvement": ("info", ""),
}


def _badge_for_section(title: str) -> str:
    lower = title.lower()
    for key, (cls, _grade) in _SECTION_BADGES.items():
        if key in lower:
            return cls
    return "info"


def _wrap_sections(html_body: str) -> tuple[str, list[tuple[str, str, str]]]:
    """Wrap H2 sections in collapsible <details> elements.

    Returns (wrapped_html, nav_items) where nav_items is a list of
    (section_id, slug, plain_title) tuples for the sidebar.
    """
    parts = re.split(r'(<h2\s[^>]*>.*?</h2>)', html_body)
    result: list[str] = []
    nav_items: list[tuple[str, str, str]] = []
    section_open = False
    section_id = 0

    for part in parts:
        h2 = re.match(r'<h2\s+id="([^"]*)">(.*?)</h2>', part)
        if h2:
            if section_open:
                result.append("</div></details>")
            section_id += 1
            slug = h2.group(1)
            title_html = h2.group(2)
            plain = re.sub(r"<[^>]+>", "", title_html)
            badge_cls = _badge_for_section(plain)

            sid = f"sect-{slug}"
            open_attr = " open" if section_id <= 1 else ""
            result.append(
                f'<details class="section" id="{sid}"{open_attr}>'
                f'<summary>'
                f'<span class="section-title">{title_html}</span>'
                f'<span class="badge badge-{badge_cls} section-badge">'
                f'{section_id}/{len([p for p in parts if re.match(r"<h2", p)])}'
                f'</span>'
                f'</summary>'
                f'<div class="section-body">'
            )
            nav_items.append((sid, slug, plain))
            section_open = True
        else:
            result.append(part)

    if section_open:
        result.append("</div></details>")

    return "".join(result), nav_items


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

_CSS = """\
*, *::before, *::after { box-sizing: border-box; }

:root {
  --bg-primary: #0d1117;
  --bg-secondary: #010409;
  --bg-tertiary: #161b22;
  --bg-hover: #1c2128;
  --border: #21262d;
  --border-strong: #30363d;
  --text-primary: #e6edf3;
  --text-secondary: #c9d1d9;
  --text-muted: #8b949e;
  --text-heading: #f0f6fc;
  --accent: #58a6ff;
  --green: #6fdd8b;
  --green-bg: #1b4332;
  --yellow: #f0c74f;
  --yellow-bg: #3d2e00;
  --red: #f47067;
  --red-bg: #4a1e1e;
  --blue: #58a6ff;
  --blue-bg: #1a2332;
  --purple: #bc8cff;
  --purple-bg: #272145;
}

body {
  margin: 0; padding: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
               'Helvetica Neue', Arial, sans-serif;
  background: var(--bg-primary); color: var(--text-secondary);
  line-height: 1.7; font-size: 15px;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* --- Layout --- */
.layout { display: flex; min-height: 100vh; }

nav {
  position: sticky; top: 0; height: 100vh; overflow-y: auto;
  width: 260px; min-width: 260px;
  background: var(--bg-secondary); border-right: 1px solid var(--border);
  padding: 20px 14px; font-size: 13px;
  display: flex; flex-direction: column;
}
nav .nav-title {
  font-weight: 700; font-size: 15px; color: var(--text-heading);
  margin-bottom: 6px;
}
nav .nav-subtitle {
  font-size: 11px; color: var(--text-muted);
  margin-bottom: 14px; padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
}
nav .nav-links { flex: 1; }
nav a.nav-link {
  display: flex; align-items: center; gap: 8px;
  padding: 7px 10px; border-radius: 6px;
  color: var(--text-muted); transition: all 0.15s;
  margin-bottom: 1px; line-height: 1.35;
  font-size: 12.5px;
}
nav a.nav-link:hover { background: var(--bg-tertiary); color: var(--text-secondary); text-decoration: none; }
nav a.nav-link.active { background: var(--bg-tertiary); color: var(--text-primary); font-weight: 500; }
nav a.nav-link .num {
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 20px; height: 20px; border-radius: 4px;
  background: var(--bg-tertiary); color: var(--text-muted);
  font-size: 11px; font-weight: 600;
}
nav .nav-controls {
  margin-top: 12px; padding-top: 12px;
  border-top: 1px solid var(--border);
  display: flex; gap: 6px;
}
nav .nav-controls button {
  flex: 1; padding: 7px; background: var(--bg-tertiary);
  color: var(--text-muted); border: 1px solid var(--border-strong);
  border-radius: 6px; cursor: pointer; font-size: 11px;
  transition: all 0.15s;
}
nav .nav-controls button:hover { background: var(--border-strong); color: var(--text-secondary); }

/* --- Search --- */
.search-box {
  margin-bottom: 12px;
}
.search-box input {
  width: 100%; padding: 7px 10px; font-size: 12px;
  background: var(--bg-primary); color: var(--text-secondary);
  border: 1px solid var(--border-strong); border-radius: 6px;
  outline: none; transition: border-color 0.15s;
}
.search-box input:focus { border-color: var(--accent); }
.search-box input::placeholder { color: var(--text-muted); }
.search-count { font-size: 11px; color: var(--text-muted); margin-top: 4px; display: none; }

main {
  flex: 1; max-width: 980px; padding: 36px 48px 80px;
}

/* --- Typography --- */
h1 { color: var(--text-heading); font-size: 26px; margin: 0 0 4px; }
h2 { color: var(--text-heading); font-size: 21px; margin: 28px 0 10px; }
h3 { color: var(--text-primary); font-size: 17px; margin: 22px 0 8px; }
h4 { color: var(--text-secondary); font-size: 15px; font-weight: 600; margin: 18px 0 6px; }
p  { margin: 8px 0; }
hr { border: none; border-top: 1px solid var(--border); margin: 24px 0; }
strong { color: var(--text-primary); }

/* --- Header area --- */
.report-header { margin-bottom: 28px; border-bottom: 1px solid var(--border); padding-bottom: 20px; }
.report-meta { color: var(--text-muted); font-size: 13px; margin: 6px 0 16px; }
.report-meta span { margin-right: 16px; }

/* --- Severity grid --- */
.severity-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 8px; margin-top: 12px;
}
.sev-card {
  background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px;
  padding: 10px 14px; display: flex; justify-content: space-between; align-items: center;
}
.sev-card .sev-label { color: var(--text-muted); font-size: 12px; }
.sev-card .sev-grade { font-weight: 700; font-size: 15px; }
.sev-card .sev-grade.good { color: var(--green); }
.sev-card .sev-grade.warn { color: var(--yellow); }
.sev-card .sev-grade.bad  { color: var(--red); }
.sev-card .sev-grade.info { color: var(--blue); }

/* --- Collapsible sections --- */
details.section {
  margin: 10px 0; border: 1px solid var(--border); border-radius: 8px;
  background: var(--bg-primary); transition: background 0.15s;
}
details.section[open] { background: var(--bg-secondary); }
details.section > summary {
  padding: 14px 18px; cursor: pointer;
  font-weight: 600; color: var(--text-heading); list-style: none;
  border-radius: 8px; transition: background 0.15s;
  display: flex; align-items: center; gap: 10px;
  user-select: none;
}
details.section > summary::-webkit-details-marker { display: none; }
details.section > summary::before {
  content: '\\25B6'; font-size: 10px; color: var(--text-muted);
  transition: transform 0.2s ease; display: inline-block; min-width: 14px;
}
details.section[open] > summary::before { transform: rotate(90deg); }
details.section > summary:hover { background: var(--bg-tertiary); }
.section-title { flex: 1; font-size: 17px; }
.section-badge { margin-left: auto; font-size: 11px; }
.section-body { padding: 4px 18px 18px; }

/* --- Badges --- */
.badge {
  display: inline-block; padding: 2px 10px; border-radius: 12px;
  font-size: 11px; font-weight: 600; letter-spacing: 0.3px;
}
.badge-good    { background: var(--green-bg);  color: var(--green); }
.badge-warn    { background: var(--yellow-bg); color: var(--yellow); }
.badge-bad     { background: var(--red-bg);    color: var(--red); }
.badge-info    { background: var(--blue-bg);   color: var(--blue); }
.badge-summary { background: var(--purple-bg); color: var(--purple); }

/* --- Tables --- */
.table-wrap { overflow-x: auto; margin: 12px 0; border-radius: 8px; border: 1px solid var(--border); }
table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
thead th {
  background: var(--bg-tertiary); color: var(--text-primary); text-align: left;
  padding: 10px 14px; font-weight: 600; white-space: nowrap;
  border-bottom: 2px solid var(--border-strong);
}
tbody td { padding: 8px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
tbody tr:hover { background: var(--bg-tertiary); }

/* --- Code blocks --- */
pre.code-block {
  background: var(--bg-tertiary); border: 1px solid var(--border);
  border-radius: 8px; padding: 16px; overflow-x: auto; margin: 12px 0;
  font-size: 13px; line-height: 1.55; position: relative;
}
pre.code-block code {
  font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', 'Cascadia Code', Consolas, monospace;
}
pre.code-block[data-lang]::before {
  content: attr(data-lang); position: absolute; top: 8px; right: 12px;
  font-size: 10px; color: var(--text-muted); font-family: sans-serif;
  text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.7;
}
code.inline {
  background: var(--bg-hover); padding: 2px 7px; border-radius: 4px;
  font-size: 0.88em; color: var(--text-primary);
  font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
}
.kw { color: #ff7b72; } .st { color: #a5d6ff; }
.cm { color: #8b949e; font-style: italic; } .op { color: #79c0ff; }

/* --- Lists --- */
ul, ol { padding-left: 22px; margin: 8px 0; }
li { margin: 3px 0; }

/* --- Back to top --- */
.back-to-top {
  position: fixed; bottom: 24px; right: 24px;
  width: 40px; height: 40px; border-radius: 50%;
  background: var(--bg-tertiary); border: 1px solid var(--border-strong);
  color: var(--text-muted); cursor: pointer; font-size: 18px;
  display: none; align-items: center; justify-content: center;
  transition: all 0.2s; z-index: 100;
}
.back-to-top:hover { background: var(--border-strong); color: var(--text-primary); }
.back-to-top.visible { display: flex; }

/* --- Search highlights --- */
mark.search-hit { background: var(--yellow-bg); color: var(--yellow); padding: 1px 2px; border-radius: 2px; }

/* --- Responsive --- */
@media (max-width: 900px) {
  nav { display: none; }
  main { padding: 20px 16px; }
}
@media print {
  nav, .back-to-top { display: none !important; }
  details.section { border: none; break-inside: avoid; }
  details.section > summary::before { content: ''; }
  details.section .section-body { display: block !important; }
}
"""

_JS = """\
// --- Expand / Collapse ---
function expandAll() {
  document.querySelectorAll('details.section').forEach(d => d.open = true);
}
function collapseAll() {
  document.querySelectorAll('details.section').forEach(d => d.open = false);
}

// --- Smooth scroll nav ---
document.querySelectorAll('nav a.nav-link').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    const id = a.getAttribute('href').slice(1);
    const target = document.getElementById(id);
    if (target) {
      if (target.tagName === 'DETAILS') target.open = true;
      // Scroll to the summary inside the details
      const summary = target.querySelector('summary') || target;
      summary.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// --- Active nav tracking ---
const sections = document.querySelectorAll('details.section');
const navLinks = document.querySelectorAll('nav a.nav-link');
const observerOpts = { threshold: 0, rootMargin: '-80px 0px -70% 0px' };
const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const id = entry.target.id;
      navLinks.forEach(a => {
        a.classList.toggle('active', a.getAttribute('href') === '#' + id);
      });
    }
  });
}, observerOpts);
sections.forEach(s => observer.observe(s));

// --- Back to top ---
const btt = document.querySelector('.back-to-top');
window.addEventListener('scroll', () => {
  btt.classList.toggle('visible', window.scrollY > 400);
});
btt.addEventListener('click', () => {
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

// --- In-page search ---
const searchInput = document.getElementById('report-search');
const searchCount = document.querySelector('.search-count');
let searchTimeout = null;

function clearHighlights() {
  document.querySelectorAll('mark.search-hit').forEach(m => {
    const parent = m.parentNode;
    parent.replaceChild(document.createTextNode(m.textContent), m);
    parent.normalize();
  });
  searchCount.style.display = 'none';
}

function highlightText(query) {
  clearHighlights();
  if (!query || query.length < 2) return;
  const re = new RegExp('(' + query.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&') + ')', 'gi');
  let count = 0;
  const walker = document.createTreeWalker(
    document.querySelector('main'), NodeFilter.SHOW_TEXT, null
  );
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  nodes.forEach(node => {
    if (node.parentElement.closest('pre, code, script, style, summary')) return;
    if (!re.test(node.textContent)) return;
    const frag = document.createDocumentFragment();
    let last = 0;
    node.textContent.replace(re, (match, _, offset) => {
      frag.appendChild(document.createTextNode(node.textContent.slice(last, offset)));
      const mark = document.createElement('mark');
      mark.className = 'search-hit';
      mark.textContent = match;
      frag.appendChild(mark);
      last = offset + match.length;
      count++;
    });
    frag.appendChild(document.createTextNode(node.textContent.slice(last)));
    node.parentNode.replaceChild(frag, node);
  });
  if (count > 0) {
    searchCount.textContent = count + ' match' + (count === 1 ? '' : 'es');
    searchCount.style.display = 'block';
    // Open section containing first hit and scroll to it
    const first = document.querySelector('mark.search-hit');
    if (first) {
      const details = first.closest('details.section');
      if (details) details.open = true;
      first.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }
}

searchInput.addEventListener('input', () => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => highlightText(searchInput.value.trim()), 250);
});
"""


def render_html(md_text: str, title: str = "Audit Report") -> str:
    """Convert markdown text to a complete self-contained HTML page."""
    from datetime import datetime

    body_html = md_to_html(md_text)
    wrapped, nav_items = _wrap_sections(body_html)
    grades = _extract_grades(md_text)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Build nav links
    nav_links = []
    for i, (sid, _slug, plain) in enumerate(nav_items, 1):
        short = plain[:34] + "..." if len(plain) > 37 else plain
        nav_links.append(
            f'<a class="nav-link" href="#{sid}" title="{escape(plain)}">'
            f'<span class="num">{i}</span> {escape(short)}</a>'
        )

    # Build severity cards
    sev_cards = []
    for label, grade, css in grades:
        sev_cards.append(
            f'<div class="sev-card">'
            f'<span class="sev-label">{escape(label)}</span>'
            f'<span class="sev-grade {css}">{escape(grade)}</span>'
            f'</div>'
        )

    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{escape(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="layout">
<nav>
  <div class="nav-title">Audit Report</div>
  <div class="nav-subtitle">WS Log Analyzer &middot; {timestamp}</div>
  <div class="search-box">
    <input type="text" id="report-search" placeholder="Search report..." autocomplete="off">
    <div class="search-count"></div>
  </div>
  <div class="nav-links">
    {"".join(nav_links)}
  </div>
  <div class="nav-controls">
    <button onclick="expandAll()">Expand all</button>
    <button onclick="collapseAll()">Collapse all</button>
  </div>
</nav>
<main>
  <div class="report-header">
    <h1>{escape(title)}</h1>
    <div class="report-meta">
      <span>Generated: {timestamp}</span>
      <span>{len(nav_items)} sections</span>
    </div>
    {f'<div class="severity-grid">{"".join(sev_cards)}</div>' if sev_cards else ''}
  </div>
  {wrapped}
</main>
</div>
<button class="back-to-top" title="Back to top">&#8593;</button>
<script>{_JS}</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Convert Markdown audit report to interactive HTML.",
    )
    ap.add_argument(
        "input", nargs="?", default="AUDIT_REPORT.md",
        help="Input Markdown file (default: AUDIT_REPORT.md)",
    )
    ap.add_argument(
        "-o", "--output", default=None,
        help="Output HTML file (default: same name with .html extension)",
    )
    ap.add_argument(
        "--open", action="store_true",
        help="Open the HTML report in default browser after generation",
    )
    ap.add_argument(
        "--title", default=None,
        help="Report title (default: extracted from first H1)",
    )
    args = ap.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        alt = Path("reports") / input_path.name
        if alt.exists():
            input_path = alt
        else:
            print(f"Error: {input_path} not found", file=sys.stderr)
            sys.exit(1)

    md_text = input_path.read_text(encoding="utf-8")

    title = args.title
    if not title:
        m = re.search(r"^#\s+(.+)$", md_text, re.MULTILINE)
        title = m.group(1).strip(" \t\u2014-") if m else "Audit Report"

    html = render_html(md_text, title=title)

    output_path = Path(args.output) if args.output else input_path.with_suffix(".html")
    output_path.write_text(html, encoding="utf-8")
    print(f"Wrote: {output_path} ({len(html):,} bytes)")

    if args.open:
        url = output_path.resolve().as_uri()
        print(f"Opening: {url}")
        webbrowser.open(url)


if __name__ == "__main__":
    main()
