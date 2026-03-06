#!/usr/bin/env python3
"""Run the audit workflow: version report, compare with previous, generate delta.

Usage:
    python scripts/run_audit.py                    # Use AUDIT_REPORT.md
    python scripts/run_audit.py path/to/audit.md   # Use specific file
    python scripts/run_audit.py --list              # List all versioned reports

Workflow:
    1. Read the current audit report (AUDIT_REPORT.md by default)
    2. Save a versioned copy to reports/AUDIT_YYYY-MM-DD_HHMM.md
    3. Find the previous versioned report (if any)
    4. Compare current vs previous and generate reports/DELTA_AUDIT_YYYY-MM-DD_HHMM.md
"""

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

# Resolve paths relative to the project root (parent of scripts/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
DEFAULT_AUDIT = PROJECT_ROOT / "AUDIT_REPORT.md"

# Import compare_audits from the same directory
sys.path.insert(0, str(Path(__file__).resolve().parent))
from compare_audits import compare_audits, render_delta


def _find_versioned_reports():
    """Find all versioned audit reports sorted by name (oldest first)."""
    if not REPORTS_DIR.exists():
        return []
    pattern = re.compile(r'^AUDIT_\d{4}-\d{2}-\d{2}_\d{4}\.md$')
    reports = sorted(
        p for p in REPORTS_DIR.iterdir()
        if pattern.match(p.name)
    )
    return reports


def _list_reports():
    """Print all versioned reports and deltas."""
    reports = _find_versioned_reports()
    deltas = sorted(REPORTS_DIR.glob("DELTA_AUDIT_*.md")) if REPORTS_DIR.exists() else []

    if not reports and not deltas:
        print("No versioned reports found in reports/")
        return

    print("Versioned audit reports:")
    print()
    for r in reports:
        size = r.stat().st_size
        print(f"  {r.name}  ({size:,} bytes)")

    if deltas:
        print()
        print("Delta reports:")
        print()
        for d in deltas:
            size = d.stat().st_size
            print(f"  {d.name}  ({size:,} bytes)")


def run(audit_path):
    """Execute the full audit workflow."""
    audit_path = Path(audit_path)
    if not audit_path.exists():
        print(f"Error: {audit_path} not found", file=sys.stderr)
        print("Generate an audit report first (AUDIT_REPORT.md).", file=sys.stderr)
        sys.exit(1)

    # 1. Create reports dir
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # 2. Save versioned copy
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    versioned_name = f"AUDIT_{timestamp}.md"
    versioned_path = REPORTS_DIR / versioned_name

    if versioned_path.exists():
        print(f"Warning: {versioned_path} already exists, skipping copy.", file=sys.stderr)
    else:
        content = audit_path.read_text(encoding="utf-8")
        versioned_path.write_text(content, encoding="utf-8")
        print(f"Saved: {versioned_path.relative_to(PROJECT_ROOT)}")

    # 3. Find previous report
    all_reports = _find_versioned_reports()
    previous = None
    for r in all_reports:
        if r != versioned_path:
            previous = r  # Keep updating — we want the latest one before current

    if not previous:
        print("No previous audit report found. Delta comparison skipped.")
        print()
        print("Run another audit later and re-run this script to see changes.")
        return versioned_path, None

    # 4. Compare and generate delta
    print(f"Comparing: {previous.name} -> {versioned_name}")
    results = compare_audits(previous, versioned_path)
    delta = render_delta(results, previous.name, versioned_name)

    delta_name = f"DELTA_AUDIT_{timestamp}.md"
    delta_path = REPORTS_DIR / delta_name
    delta_path.write_text(delta, encoding="utf-8")
    print(f"Wrote delta: {delta_path.relative_to(PROJECT_ROOT)}")

    # 5. Print summary
    fixed = sum(len(d["fixed"]) for d in results.values())
    remaining = sum(len(d["remaining"]) for d in results.values())
    new = sum(len(d["new"]) for d in results.values())

    print()
    print(f"  Fixed:     {fixed}")
    print(f"  Remaining: {remaining}")
    print(f"  New:       {new}")

    return versioned_path, delta_path


def main():
    ap = argparse.ArgumentParser(
        description="Version an audit report and compare with previous."
    )
    ap.add_argument(
        "audit", nargs="?", default=str(DEFAULT_AUDIT),
        help=f"Path to current audit report (default: {DEFAULT_AUDIT.name})"
    )
    ap.add_argument(
        "--list", action="store_true",
        help="List all versioned reports and exit"
    )
    args = ap.parse_args()

    if args.list:
        _list_reports()
        return

    run(args.audit)


if __name__ == "__main__":
    main()
