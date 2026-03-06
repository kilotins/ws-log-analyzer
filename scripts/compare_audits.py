#!/usr/bin/env python3
"""Compare two audit reports and generate a delta report.

Parses structured markdown audit reports, extracts findings from key sections,
and produces a delta highlighting fixes, new issues, and remaining items.

Usage:
    python scripts/compare_audits.py reports/AUDIT_old.md reports/AUDIT_new.md
    python scripts/compare_audits.py reports/AUDIT_old.md reports/AUDIT_new.md -o reports/DELTA.md
"""

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Section parsing
# ---------------------------------------------------------------------------

# Sections we care about for comparison
TARGET_SECTIONS = [
    "Executive Summary",
    "Code Review Findings",
    "AI Integration Review",
    "Test Coverage Analysis",
    "Prioritized Improvement Plan",
]


def _extract_sections(text):
    """Split markdown into {section_title: section_body} by H2 headings."""
    sections = {}
    current = None
    lines = []
    for line in text.splitlines():
        m = re.match(r'^##\s+\d*\.?\s*(.*)', line)
        if m:
            if current:
                sections[current] = "\n".join(lines)
            current = m.group(1).strip()
            lines = []
        else:
            lines.append(line)
    if current:
        sections[current] = "\n".join(lines)
    return sections


def _match_section(title, targets):
    """Fuzzy-match a section title against target names."""
    title_lower = title.lower()
    for t in targets:
        if t.lower() in title_lower or title_lower in t.lower():
            return t
    return None


# ---------------------------------------------------------------------------
# Finding extraction
# ---------------------------------------------------------------------------

# Patterns for extractable findings
_FINDING_ID_RE = re.compile(
    r'####\s+([A-Z]\d+):\s*(.*)', re.IGNORECASE
)
_TABLE_ROW_RE = re.compile(
    r'^\|\s*(\d+)\s*\|\s*(.*?)\s*\|', re.MULTILINE
)
_BULLET_RE = re.compile(
    r'^[-*]\s+(.*)', re.MULTILINE
)
_STRIKETHROUGH_RE = re.compile(r'~~(.*?)~~')
_CHECKMARK_RE = re.compile(r'[✅✔]')


def _is_fixed(text):
    """Check if a finding line is marked as fixed/done."""
    return bool(_CHECKMARK_RE.search(text) or _STRIKETHROUGH_RE.search(text)
                or "Done" in text or "Fixed" in text)


def _normalize(text):
    """Normalize finding text for comparison."""
    text = _STRIKETHROUGH_RE.sub(r'\1', text)
    text = _CHECKMARK_RE.sub('', text)
    text = re.sub(r'\s+', ' ', text).strip()
    text = re.sub(r'[|`*_~]', '', text)
    # Remove effort/file columns from table rows
    text = re.sub(r'\s*\d+\s*min\b', '', text)
    text = re.sub(r'\s*\d+\s*hr\b', '', text)
    text = re.sub(r'\b(app|wslog|tests/)[\w./:-]*', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text.lower()


def _extract_findings(section_body, section_name):
    """Extract a list of findings from a section body.

    Returns list of dicts: {id, text, raw, fixed}
    """
    findings = []
    seen_normalized = set()

    # 1) Named findings (#### B1: ..., #### I1: ...)
    for m in _FINDING_ID_RE.finditer(section_body):
        fid = m.group(1).upper()
        raw = m.group(2).strip()
        findings.append({
            "id": fid,
            "text": raw,
            "raw": m.group(0),
            "fixed": _is_fixed(raw),
        })
        seen_normalized.add(_normalize(raw))

    # 2) Numbered table rows (| 1 | Fix HTML escaping ... |)
    for m in _TABLE_ROW_RE.finditer(section_body):
        num = m.group(1)
        raw = m.group(2).strip()
        # Skip header rows
        if raw.startswith("---") or raw.lower().startswith("item") or raw.startswith("#"):
            continue
        norm = _normalize(raw)
        if norm and norm not in seen_normalized:
            findings.append({
                "id": f"#{num}",
                "text": raw,
                "raw": m.group(0),
                "fixed": _is_fixed(raw),
            })
            seen_normalized.add(norm)

    # 3) Key findings bullets (Executive Summary — only "requiring attention" section)
    if "summary" in section_name.lower():
        # Only extract bullets from the "findings requiring attention" block
        attention_match = re.search(
            r'(?:findings requiring attention|key findings).*?:(.*?)(?=\n\n|\n\*\*|\Z)',
            section_body, re.DOTALL | re.IGNORECASE
        )
        attention_block = attention_match.group(1) if attention_match else ""
        for m in _BULLET_RE.finditer(attention_block):
            raw = m.group(1).strip()
            norm = _normalize(raw)
            if norm and norm not in seen_normalized and len(raw) > 10:
                findings.append({
                    "id": None,
                    "text": raw,
                    "raw": m.group(0),
                    "fixed": _is_fixed(raw),
                })
                seen_normalized.add(norm)

    # 4) Coverage gap table rows (| `parse_ts_datetime()` | High | ...)
    if "coverage" in section_name.lower() or "test" in section_name.lower():
        for m in re.finditer(r'^\|\s*`?([^|]+?)`?\s*\|\s*(\w+)\s*\|', section_body, re.MULTILINE):
            raw = m.group(1).strip()
            norm = _normalize(raw)
            if norm and norm not in seen_normalized and not raw.startswith("---") and raw.lower() != "missing test":
                findings.append({
                    "id": None,
                    "text": raw,
                    "raw": m.group(0),
                    "fixed": _is_fixed(raw),
                })
                seen_normalized.add(norm)

    return findings


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def compare_findings(old_findings, new_findings):
    """Compare two lists of findings, return categorized results.

    Returns dict with keys: fixed, remaining, new, regressed
    """
    old_by_norm = {}
    for f in old_findings:
        key = _normalize(f["text"])
        if key:
            old_by_norm[key] = f

    new_by_norm = {}
    for f in new_findings:
        key = _normalize(f["text"])
        if key:
            new_by_norm[key] = f

    fixed = []
    remaining = []
    new_items = []

    # Check what happened to old findings
    for key, old_f in old_by_norm.items():
        if key in new_by_norm:
            new_f = new_by_norm[key]
            if new_f["fixed"] and not old_f["fixed"]:
                fixed.append(new_f)
            elif new_f["fixed"]:
                fixed.append(new_f)
            else:
                remaining.append(new_f)
        else:
            # Gone from new report — assume fixed/removed
            fixed.append({**old_f, "fixed": True})

    # Check for new findings
    for key, new_f in new_by_norm.items():
        if key not in old_by_norm and not new_f["fixed"]:
            new_items.append(new_f)

    return {
        "fixed": fixed,
        "remaining": remaining,
        "new": new_items,
    }


def _build_fixed_index(text):
    """Scan the full report for items marked as fixed/done.

    Returns a tuple: (set of normalized texts, set of finding IDs like "B1", "I3")
    """
    fixed_texts = set()
    fixed_ids = set()
    for line in text.splitlines():
        if _is_fixed(line):
            fixed_texts.add(_normalize(line))
            # Extract finding IDs from the line (e.g., B1, I3, #7)
            for fid in re.findall(r'\b([A-Z]\d+)\b', line):
                fixed_ids.add(fid)
            for num in re.findall(r'#(\d+)', line):
                fixed_ids.add(f"#{num}")
    return fixed_texts, fixed_ids


def compare_audits(old_path, new_path):
    """Compare two audit markdown files.

    Returns dict: {section_name: {fixed, remaining, new}}
    """
    old_text = Path(old_path).read_text(encoding="utf-8")
    new_text = Path(new_path).read_text(encoding="utf-8")

    old_sections = _extract_sections(old_text)
    new_sections = _extract_sections(new_text)

    # Build a global index of what's marked fixed in the new report
    # so Code Review findings (B1, I1...) can be cross-referenced
    # with Improvement Plan status markers
    new_fixed_texts, new_fixed_ids = _build_fixed_index(new_text)

    results = {}
    for target in TARGET_SECTIONS:
        old_key = None
        new_key = None
        for k in old_sections:
            if _match_section(k, [target]):
                old_key = k
                break
        for k in new_sections:
            if _match_section(k, [target]):
                new_key = k
                break

        old_findings = _extract_findings(old_sections.get(old_key, ""), target) if old_key else []
        new_findings = _extract_findings(new_sections.get(new_key, ""), target) if new_key else []

        # Cross-reference: if a finding's ID or key words overlap with a globally
        # fixed item, mark it as fixed even if this section doesn't have strikethrough
        for f in new_findings:
            if not f["fixed"]:
                # Check by finding ID first (B1, I3, #7, etc.)
                if f.get("id") and f["id"] in new_fixed_ids:
                    f["fixed"] = True
                    continue

                norm = _normalize(f["text"])
                if not norm:
                    continue
                stop = {"the", "a", "an", "in", "to", "for", "of", "is", "not", "and", "or", "with"}
                norm_words = set(norm.split()) - stop
                for fixed_norm in new_fixed_texts:
                    if not fixed_norm:
                        continue
                    # Substring match
                    if norm in fixed_norm or fixed_norm in norm:
                        f["fixed"] = True
                        break
                    # Keyword overlap: if 60%+ of significant words match
                    fixed_words = set(fixed_norm.split()) - stop
                    if norm_words and fixed_words:
                        overlap = norm_words & fixed_words
                        smaller = min(len(norm_words), len(fixed_words))
                        if smaller > 0 and len(overlap) >= 2 and len(overlap) / smaller >= 0.4:
                            f["fixed"] = True
                            break

        if old_findings or new_findings:
            results[target] = compare_findings(old_findings, new_findings)

    return results


# ---------------------------------------------------------------------------
# Delta report rendering
# ---------------------------------------------------------------------------

def _finding_label(f):
    """Format a finding for the delta report."""
    prefix = f"**{f['id']}** " if f.get("id") else ""
    # Clean up strikethrough and checkmarks for display
    text = _STRIKETHROUGH_RE.sub(r'\1', f["text"])
    text = _CHECKMARK_RE.sub('', text).strip()
    text = re.sub(r'\s+', ' ', text)
    return f"{prefix}{text}"


def render_delta(results, old_name, new_name):
    """Render a delta report as markdown."""
    lines = [
        "# Audit Delta Report",
        "",
        f"**Previous:** {old_name}",
        f"**Current:** {new_name}",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "---",
        "",
    ]

    # Aggregate across sections
    all_fixed = []
    all_remaining = []
    all_new = []

    for section, data in results.items():
        for f in data["fixed"]:
            all_fixed.append((section, f))
        for f in data["remaining"]:
            all_remaining.append((section, f))
        for f in data["new"]:
            all_new.append((section, f))

    # Summary counts
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Category | Count |")
    lines.append(f"|----------|-------|")
    lines.append(f"| Issues fixed | {len(all_fixed)} |")
    lines.append(f"| Remaining issues | {len(all_remaining)} |")
    lines.append(f"| New findings | {len(all_new)} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Fixed
    lines.append("## Improvements (Fixed)")
    lines.append("")
    if all_fixed:
        for section, f in all_fixed:
            lines.append(f"- [x] {_finding_label(f)}")
    else:
        lines.append("No issues were fixed since the previous audit.")
    lines.append("")

    # Remaining
    lines.append("## Remaining Issues")
    lines.append("")
    if all_remaining:
        current_section = None
        for section, f in all_remaining:
            if section != current_section:
                lines.append(f"### {section}")
                lines.append("")
                current_section = section
            lines.append(f"- [ ] {_finding_label(f)}")
        lines.append("")
    else:
        lines.append("All previously identified issues have been addressed.")
        lines.append("")

    # New
    lines.append("## New Findings")
    lines.append("")
    if all_new:
        current_section = None
        for section, f in all_new:
            if section != current_section:
                lines.append(f"### {section}")
                lines.append("")
                current_section = section
            lines.append(f"- {_finding_label(f)}")
        lines.append("")
    else:
        lines.append("No new issues were introduced.")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*Generated by compare_audits.py*")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Compare two audit reports and generate a delta report."
    )
    ap.add_argument("old", help="Path to previous audit report")
    ap.add_argument("new", help="Path to current audit report")
    ap.add_argument("-o", "--output", help="Write delta report to file (default: stdout)")
    args = ap.parse_args()

    old_path = Path(args.old)
    new_path = Path(args.new)

    if not old_path.exists():
        print(f"Error: {old_path} not found", file=sys.stderr)
        sys.exit(1)
    if not new_path.exists():
        print(f"Error: {new_path} not found", file=sys.stderr)
        sys.exit(1)

    results = compare_audits(old_path, new_path)
    delta = render_delta(results, old_path.name, new_path.name)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(delta, encoding="utf-8")
        print(f"Wrote delta report: {out}")
    else:
        print(delta)


if __name__ == "__main__":
    main()
