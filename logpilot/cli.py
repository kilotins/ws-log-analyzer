"""CLI entry point for logpilot."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .parser import parse_file
from .analysis import summarize
from .reports import render_json_report, render_markdown_report
from .ai import build_claude_prompt, _sanitize_prompt_input


def main() -> None:
    """CLI entry point: parse log files, generate triage report."""
    ap = argparse.ArgumentParser(description="LogPilot — WebSphere/Java log analyzer (quick triage).")
    ap.add_argument("paths", nargs="+", help="Log files (supports .gz). Globs allowed by shell.")
    ap.add_argument("--max-lines", type=int, default=None, help="Limit lines per file (speed/safety).")
    ap.add_argument("--top", type=int, default=10, help="Top-N items in summary.")
    ap.add_argument("--samples", type=int, default=5, help="How many sample events to print.")
    ap.add_argument("--hist-minutes", type=int, default=1, help="Histogram bucket size in minutes.")
    ap.add_argument("--out", default="report.md", help="Write markdown report to this file.")
    ap.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format.")
    ap.add_argument("--claude", action="store_true", help="Also ask Claude for root-cause suggestions (sanitized).")
    ap.add_argument("--model", default="claude-sonnet-4-6", help="Claude model to use with --claude.")
    ap.add_argument("-q", "--quiet", action="store_true", help="Suppress progress messages.")
    ap.add_argument("--log-format", choices=["text", "json"], default="text", help="Log output format.")
    args = ap.parse_args()

    if args.log_format == "json":
        os.environ["WSLOG_LOG_FORMAT"] = "json"

    all_events: list[dict] = []
    for p in args.paths:
        path = Path(p).expanduser()
        if not path.exists():
            print(f"Skip (not found): {path}", file=sys.stderr)
            continue
        file_events = parse_file(path, args.max_lines)
        if not args.quiet:
            print(f"  {path.name}: {len(file_events)} events", file=sys.stderr)
        all_events.extend(file_events)

    if not all_events:
        print("No events parsed. Are the files empty or binary/scanned?", file=sys.stderr)
        sys.exit(2)

    if not args.quiet and len(args.paths) > 1:
        print(f"  Combined: {len(all_events)} events from {len(args.paths)} files", file=sys.stderr)

    out_path = Path(args.out)
    if args.format == "json" and args.out == "report.md":
        out_path = out_path.with_suffix(".json")

    if args.format == "json":
        report = render_json_report(all_events, top_n=args.top, samples_n=args.samples, hist_minutes=args.hist_minutes)
    else:
        report = render_markdown_report(all_events, top_n=args.top, samples_n=args.samples, hist_minutes=args.hist_minutes)

    out_path.write_text(report, encoding="utf-8")
    if not args.quiet:
        print(f"Wrote report: {out_path}")

    if args.claude:
        try:
            from anthropic import Anthropic
        except ImportError:
            print("anthropic package not installed. Install with: pip install anthropic", file=sys.stderr)
            sys.exit(1)

        summary = summarize(all_events, args.top)
        cli_match = {
            "matched": True,
            "codes": [c for c, _ in summary["codes"]],
            "exceptions": [e for e, _ in summary["exceptions"]],
            "tags": [t for t, _ in summary["tags"]],
            "matching_events": [],
        }

        cli_query = "Analyze this triage report and provide root-cause analysis."
        prompt = build_claude_prompt(cli_query, cli_match)

        safe_report = _sanitize_prompt_input(report)[:12000]
        cli_instruction = (
            "Based on the triage report below, give:\n"
            "1) likely root causes (ranked),\n"
            "2) next debugging steps (specific),\n"
            "3) quick mitigations,\n"
            "4) what extra info you would ask for.\n\n"
            "If data seems truncated, note assumptions."
        )
        user_content = f"<user_query>{cli_instruction}</user_query>\n\n<report>\n{safe_report}\n</report>"

        try:
            client = Anthropic(timeout=30.0)
            message = client.messages.create(
                model=args.model,
                max_tokens=4096,
                system=prompt["system"],  # type: ignore[arg-type]
                messages=[{"role": "user", "content": user_content}],
            )
            analysis = message.content[0].text  # type: ignore[union-attr]
            analysis_path = out_path.parent / "claude-analysis.md"
            analysis_path.write_text(analysis, encoding="utf-8")
            if not args.quiet:
                if prompt.get("skills"):
                    print(f"[skills] Selected: {', '.join(prompt['skills'])}", file=sys.stderr)
                print(f"Wrote claude-analysis.md: {analysis_path}")
        except (ImportError, OSError, ValueError, RuntimeError) as ex:
            print(f"Claude API call failed: {ex}", file=sys.stderr)
            print("Tip: ensure ANTHROPIC_API_KEY is set.", file=sys.stderr)
