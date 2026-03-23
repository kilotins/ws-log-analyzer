"""CLI entry point for logpilot."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .event import LogEvent, ERROR_LEVELS
from .parser import parse_file
from .analysis import summarize
from .reports import render_json_report, render_markdown_report, render_html_report
from .ai import build_claude_prompt, _sanitize_prompt_input


def main() -> None:
    """CLI entry point: parse log files, generate triage report."""
    ap = argparse.ArgumentParser(description="LogPilot — Log analyzer (quick triage).")
    ap.add_argument("paths", nargs="*", help="Log files (supports .gz). Globs allowed by shell.")
    ap.add_argument("-d", "--directory", default=None, help="Recursively scan directory for log files.")
    ap.add_argument("--max-lines", type=int, default=None, help="Limit lines per file (speed/safety).")
    ap.add_argument("--top", type=int, default=10, help="Top-N items in summary.")
    ap.add_argument("--samples", type=int, default=5, help="How many sample events to print.")
    ap.add_argument("--hist-minutes", type=int, default=1, help="Histogram bucket size in minutes.")
    ap.add_argument("--out", default=None, help="Output file path (default: report.md/json/html based on format).")
    ap.add_argument("--format", choices=["markdown", "json", "html"], default="markdown", help="Output format.")
    ap.add_argument("--claude", action="store_true", help="Also ask Claude for root-cause suggestions (sanitized).")
    ap.add_argument("--model", default="claude-sonnet-4-6", help="Claude model to use with --claude.")
    ap.add_argument("-q", "--quiet", action="store_true", help="Suppress progress messages.")
    ap.add_argument("--log-format", choices=["text", "json"], default="text", help="Log output format.")
    ap.add_argument("--log-type", default=None, help="Force log type (e.g. was, json, nginx, log4j). Auto-detects if omitted.")
    ap.add_argument("--list-formats", action="store_true", help="List available log format plugins and exit.")
    ap.add_argument("--ai-endpoint", default=None, help="Local AI endpoint URL (e.g. http://localhost:1234/v1). Also: LOGPILOT_AI_ENDPOINT env var.")
    ap.add_argument("--ai-model", default=None, help="Local AI model name. Also: LOGPILOT_AI_MODEL env var.")
    ap.add_argument("--exit-code", action="store_true", help="Exit with code 1 if errors exceed threshold")
    ap.add_argument("--error-threshold", type=int, default=0, help="Number of errors that triggers non-zero exit (used with --exit-code)")
    args = ap.parse_args()

    if args.log_format == "json":
        os.environ["WSLOG_LOG_FORMAT"] = "json"

    if args.list_formats:
        from .formats import list_formats
        print("Available log format plugins:")
        for f in list_formats():
            print(f"  {f['name']:12s}  {f['description']}")
        return

    # Collect file paths from both positional args and --directory
    file_paths: list[Path] = []
    for p in args.paths:
        file_paths.append(Path(p).expanduser())

    if args.directory:
        from .discovery import discover_log_files
        dir_path = Path(args.directory).expanduser()
        if not dir_path.is_dir():
            ap.error(f"--directory: {dir_path} is not a directory")
        result = discover_log_files(dir_path)
        if not args.quiet:
            print(f"  Scanned {dir_path}: {len(result.accepted)} files ({len(result.rejected)} skipped)", file=sys.stderr)
            if result.truncated:
                print(f"  Warning: {result.truncation_reason}", file=sys.stderr)
        for df in result.accepted:
            file_paths.append(df.path)

    if not file_paths:
        ap.error("no input: provide file paths or --directory")

    all_events: list[LogEvent] = []
    for path in file_paths:
        if not path.exists():
            print(f"Skip (not found): {path}", file=sys.stderr)
            continue
        file_events = parse_file(path, args.max_lines, format_name=args.log_type)
        # Set system_label from filename stem
        stem = path.stem if path.suffix.lower() != ".gz" else Path(path.stem).stem
        for ev in file_events:
            ev.system_label = stem
        if not args.quiet:
            print(f"  {path.name}: {len(file_events)} events", file=sys.stderr)
        all_events.extend(file_events)

    if not all_events:
        print("No events parsed. Are the files empty or binary/scanned?", file=sys.stderr)
        sys.exit(2)

    if not args.quiet and len(file_paths) > 1:
        print(f"  Combined: {len(all_events)} events from {len(file_paths)} files", file=sys.stderr)

    _format_ext = {"markdown": ".md", "json": ".json", "html": ".html"}
    if args.out:
        out_path = Path(args.out)
    else:
        out_path = Path("report" + _format_ext[args.format])

    from .analysis import precompute_analysis
    _analysis = precompute_analysis(all_events, top_n=args.top, samples_n=args.samples, hist_minutes=args.hist_minutes)

    if args.format == "json":
        report = render_json_report(all_events, _analysis=_analysis)
    elif args.format == "html":
        report = render_html_report(all_events, _analysis=_analysis)
    else:
        report = render_markdown_report(all_events, _analysis=_analysis)

    out_path.write_text(report, encoding="utf-8")
    if not args.quiet:
        print(f"Wrote report: {out_path}")

    # Exit-code check — must run before AI to ensure reliable exit code
    if args.exit_code:
        error_count = sum(1 for e in all_events if e.level in ERROR_LEVELS)
        if error_count > args.error_threshold:
            sys.exit(1)

    # AI analysis — build shared prompt
    _use_ai = args.claude or args.ai_endpoint or args.ai_model
    if _use_ai:
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
        full_prompt = {"system": prompt["system"], "user": user_content}

        if args.ai_endpoint or args.ai_model:
            # Local AI via OpenAI-compatible endpoint
            endpoint = args.ai_endpoint or os.environ.get("LOGPILOT_AI_ENDPOINT", "http://localhost:1234/v1")
            model_name = args.ai_model or os.environ.get("LOGPILOT_AI_MODEL", "default")

            try:
                from openai import OpenAI
            except ImportError:
                print("openai package not installed. Install with: pip install openai", file=sys.stderr)
                sys.exit(1)

            try:
                client = OpenAI(api_key="not-needed", base_url=endpoint, timeout=120.0)
                response = client.chat.completions.create(
                    model=model_name,
                    max_completion_tokens=4096,
                    messages=[
                        {"role": "system", "content": full_prompt["system"]},
                        {"role": "user", "content": full_prompt["user"]},
                    ],
                )
                analysis = response.choices[0].message.content
                analysis_path = out_path.parent / "ai-analysis.md"
                analysis_path.write_text(analysis, encoding="utf-8")
                if not args.quiet:
                    print(f"Wrote ai-analysis.md ({model_name} via {endpoint}): {analysis_path}")
            except (ImportError, OSError, ValueError, RuntimeError) as ex:
                print(f"Local AI call failed: {ex}", file=sys.stderr)
                print(f"Tip: ensure {endpoint} is running.", file=sys.stderr)
            except Exception as ex:
                print(f"Local AI call failed: {type(ex).__name__}: {ex}", file=sys.stderr)

        elif args.claude:
            try:
                from anthropic import Anthropic
            except ImportError:
                print("anthropic package not installed. Install with: pip install anthropic", file=sys.stderr)
                sys.exit(1)

            try:
                client = Anthropic(timeout=30.0)
                message = client.messages.create(
                    model=args.model,
                    max_tokens=4096,
                    system=[{"type": "text", "text": full_prompt["system"], "cache_control": {"type": "ephemeral"}}],  # type: ignore[arg-type]
                    messages=[{"role": "user", "content": full_prompt["user"]}],
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
            except Exception as ex:
                print(f"Claude API call failed: {type(ex).__name__}: {ex}", file=sys.stderr)
