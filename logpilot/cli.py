"""CLI entry point for logpilot."""
from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from pathlib import Path

from .event import LogEvent, ERROR_LEVELS
from .parser import parse_file
from .reports import render_json_report, render_markdown_report, render_html_report, render_executive_summary, render_executive_summary_html
from .ai import (
    build_incident_system_prompt, build_incident_user_prompt,
    select_skills, load_skill_content, _sanitize_prompt_input,
)


def _detect_formats(events: list[LogEvent]) -> tuple[str, list[str], bool]:
    """Detect dominant format and list of all formats from events.

    Returns (dominant_format, source_formats, is_multi_source).
    """
    formats = Counter(e.format for e in events if e.format)
    if not formats:
        return "", [], False
    source_formats = [f for f, _ in formats.most_common()]
    dominant = source_formats[0]
    is_multi = len(source_formats) > 1
    return dominant, source_formats, is_multi


def _build_cli_ai_prompt(events: list[LogEvent], analysis: dict) -> dict[str, str]:
    """Build the incident AI prompt for CLI — same quality as Streamlit.

    Returns {"system": ..., "user": ...}.
    """
    summary = analysis["summary"]
    causes = analysis.get("causes", [])
    cascades = analysis.get("cascades", [])

    # Detect format for specialist prompt
    dominant, source_formats, is_multi = _detect_formats(events)
    cli_match = {
        "matched": True,
        "codes": [c for c, _ in summary["codes"]],
        "exceptions": [e for e, _ in summary["exceptions"]],
        "tags": [t for t, _ in summary["tags"]],
        "matching_events": [],
    }
    skills = select_skills(cli_match, detected_format=dominant, source_formats=source_formats)
    skill_content = load_skill_content(skills)

    system_prompt = build_incident_system_prompt(
        detected_format=dominant,
        skill_content=skill_content,
        is_multi_source=is_multi,
        source_formats=source_formats,
    )

    description = "Analyze these logs and provide root-cause analysis with specific remediation steps."
    user_prompt = build_incident_user_prompt(
        description=description,
        summary=summary,
        causes=causes,
        itl=analysis.get("incident_timeline"),
        error_events=[e for e in events if e.level in ERROR_LEVELS][:50],
        cascades=cascades,
    )

    return {"system": system_prompt, "user": user_prompt}


def _resolve_ai_provider(args) -> tuple[str, str, str]:
    """Resolve provider, model, and endpoint from CLI args.

    Returns (provider, model, endpoint).
    """
    if args.ai:
        provider = args.ai
    elif args.claude:
        provider = "claude"
    elif args.ai_endpoint or args.ai_model:
        provider = "local"
    else:
        return ("", "", "")

    if provider == "claude":
        model = args.model or "claude-sonnet-4-6"
        return (provider, model, "")
    elif provider == "gemini":
        model = args.model or "gemini-2.0-flash"
        return (provider, model, "")
    elif provider == "openai":
        model = args.model or "gpt-4o-mini"
        return (provider, model, "")
    else:  # local
        endpoint = args.ai_endpoint or os.environ.get("LOGPILOT_AI_ENDPOINT", "http://localhost:1234/v1")
        model = args.ai_model or args.model or os.environ.get("LOGPILOT_AI_MODEL", "default")
        return ("local", model, endpoint)


def _call_ai(provider: str, model: str, endpoint: str, prompt: dict,
             quiet: bool = False) -> str | None:
    """Call the specified AI provider and return the response text.

    Prints streaming output to stderr. Returns None on failure.
    """
    if provider == "claude":
        try:
            from anthropic import Anthropic
        except ImportError:
            print("anthropic package not installed. Install with: pip install anthropic", file=sys.stderr)
            sys.exit(1)
        try:
            client = Anthropic(timeout=120.0)
            if not quiet:
                print(f"[AI] Calling {model}...", file=sys.stderr)
            # Stream response
            text_parts: list[str] = []
            with client.messages.stream(
                model=model,
                max_tokens=8192,
                system=[{"type": "text", "text": prompt["system"], "cache_control": {"type": "ephemeral"}}],
                messages=[{"role": "user", "content": prompt["user"]}],
            ) as stream:
                for text in stream.text_stream:
                    text_parts.append(text)
                    if not quiet:
                        print(text, end="", file=sys.stderr, flush=True)
            if not quiet:
                print("", file=sys.stderr)  # newline after stream
            return "".join(text_parts)
        except (ImportError, OSError, ValueError, RuntimeError) as ex:
            print(f"Claude API call failed: {ex}", file=sys.stderr)
            print("Tip: ensure ANTHROPIC_API_KEY is set.", file=sys.stderr)
        except Exception as ex:
            print(f"Claude API call failed: {type(ex).__name__}: {ex}", file=sys.stderr)
        return None

    elif provider == "gemini":
        try:
            import google.generativeai as genai
        except ImportError:
            print("google-generativeai not installed. Install with: pip install google-generativeai", file=sys.stderr)
            sys.exit(1)
        try:
            api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY", "")
            if not api_key:
                print("Set GEMINI_API_KEY or GOOGLE_API_KEY environment variable.", file=sys.stderr)
                sys.exit(1)
            genai.configure(api_key=api_key)
            gen_model = genai.GenerativeModel(model, system_instruction=prompt["system"])
            if not quiet:
                print(f"[AI] Calling {model}...", file=sys.stderr)
            response = gen_model.generate_content(prompt["user"])
            text = response.text
            if not quiet:
                print(text, file=sys.stderr)
            return text
        except Exception as ex:
            print(f"Gemini API call failed: {type(ex).__name__}: {ex}", file=sys.stderr)
        return None

    elif provider == "openai":
        try:
            from openai import OpenAI
        except ImportError:
            print("openai package not installed. Install with: pip install openai", file=sys.stderr)
            sys.exit(1)
        try:
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if not api_key:
                print("Set OPENAI_API_KEY environment variable.", file=sys.stderr)
                sys.exit(1)
            client = OpenAI(api_key=api_key, timeout=120.0)
            if not quiet:
                print(f"[AI] Calling {model}...", file=sys.stderr)
            text_parts = []
            stream = client.chat.completions.create(
                model=model,
                max_completion_tokens=8192,
                stream=True,
                messages=[
                    {"role": "system", "content": prompt["system"]},
                    {"role": "user", "content": prompt["user"]},
                ],
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content if chunk.choices[0].delta.content else ""
                text_parts.append(delta)
                if not quiet:
                    print(delta, end="", file=sys.stderr, flush=True)
            if not quiet:
                print("", file=sys.stderr)
            return "".join(text_parts)
        except Exception as ex:
            print(f"OpenAI API call failed: {type(ex).__name__}: {ex}", file=sys.stderr)
        return None

    else:  # local
        try:
            from openai import OpenAI
        except ImportError:
            print("openai package not installed. Install with: pip install openai", file=sys.stderr)
            sys.exit(1)
        try:
            client = OpenAI(api_key="not-needed", base_url=endpoint, timeout=120.0)
            if not quiet:
                print(f"[AI] Calling {model} via {endpoint}...", file=sys.stderr)
            text_parts = []
            stream = client.chat.completions.create(
                model=model,
                max_completion_tokens=4096,
                stream=True,
                messages=[
                    {"role": "system", "content": prompt["system"]},
                    {"role": "user", "content": prompt["user"]},
                ],
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content if chunk.choices[0].delta.content else ""
                text_parts.append(delta)
                if not quiet:
                    print(delta, end="", file=sys.stderr, flush=True)
            if not quiet:
                print("", file=sys.stderr)
            return "".join(text_parts)
        except (ImportError, OSError, ValueError, RuntimeError) as ex:
            print(f"Local AI call failed: {ex}", file=sys.stderr)
            print(f"Tip: ensure {endpoint} is running.", file=sys.stderr)
        except Exception as ex:
            print(f"Local AI call failed: {type(ex).__name__}: {ex}", file=sys.stderr)
        return None


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
    ap.add_argument("--format", choices=["markdown", "json", "html", "summary", "summary-html"], default="markdown",
                     help="Output format. 'summary' and 'summary-html' generate a 1-page executive summary.")
    ap.add_argument("--ai", choices=["claude", "gemini", "openai", "local"], default=None,
                     help="Run AI analysis with specified provider. Result is included in the report.")
    ap.add_argument("--claude", action="store_true", help="Shortcut for --ai claude (backwards compat).")
    ap.add_argument("--model", default=None, help="AI model to use (default depends on provider).")
    ap.add_argument("-q", "--quiet", action="store_true", help="Suppress progress messages.")
    ap.add_argument("--log-format", choices=["text", "json"], default="text", help="Log output format.")
    ap.add_argument("--log-type", default=None, help="Force log type (e.g. was, json, nginx, log4j). Auto-detects if omitted.")
    ap.add_argument("--list-formats", action="store_true", help="List available log format plugins and exit.")
    ap.add_argument("--ai-endpoint", default=None, help="Local AI endpoint URL (e.g. http://localhost:1234/v1). Also: LOGPILOT_AI_ENDPOINT env var.")
    ap.add_argument("--ai-model", default=None, help="Local AI model name. Also: LOGPILOT_AI_MODEL env var.")
    ap.add_argument("--redaction-level", choices=["none", "secrets", "standard", "strict"], default="secrets",
                     help="PII redaction level: none, secrets (default), standard (+PII), strict (+IPs/usernames)")
    ap.add_argument("--exit-code", action="store_true", help="Exit with code 1 if errors exceed threshold")
    ap.add_argument("--error-threshold", type=int, default=0, help="Number of errors that triggers non-zero exit (used with --exit-code)")
    args = ap.parse_args()

    if args.log_format == "json":
        os.environ["WSLOG_LOG_FORMAT"] = "json"

    if args.redaction_level != "secrets":
        os.environ["LOGPILOT_REDACTION_LEVEL"] = args.redaction_level

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

    _format_ext = {"markdown": ".md", "json": ".json", "html": ".html", "summary": ".md", "summary-html": ".html"}
    if args.out:
        out_path = Path(args.out)
    else:
        out_path = Path("report" + _format_ext[args.format])

    from .analysis import precompute_analysis
    _analysis = precompute_analysis(all_events, top_n=args.top, samples_n=args.samples, hist_minutes=args.hist_minutes)

    # Exit-code check — must run before AI to ensure reliable exit code
    if args.exit_code:
        error_count = sum(1 for e in all_events if e.level in ERROR_LEVELS)
        if error_count > args.error_threshold:
            sys.exit(1)

    # AI analysis
    provider, model, endpoint = _resolve_ai_provider(args)
    ai_content: dict | None = None

    if provider:
        prompt = _build_cli_ai_prompt(all_events, _analysis)
        dominant, source_formats, _ = _detect_formats(all_events)
        _summary = _analysis["summary"]
        _cli_match = {
            "codes": [c for c, _ in _summary["codes"]],
            "exceptions": [e for e, _ in _summary["exceptions"]],
            "tags": [t for t, _ in _summary["tags"]],
        }
        skills = select_skills(_cli_match, detected_format=dominant, source_formats=source_formats)
        if skills and not args.quiet:
            print(f"[skills] Selected: {', '.join(skills)}", file=sys.stderr)

        ai_text = _call_ai(provider, model, endpoint, prompt, quiet=args.quiet)
        if ai_text:
            ai_content = {
                "incident": ai_text,
                "incident_query": "CLI root-cause analysis",
                "incident_model": f"{provider}/{model}",
            }
            if not args.quiet:
                print(f"[AI] Analysis complete ({provider}/{model})", file=sys.stderr)

    # Generate report (with AI content inline if available)
    from .reports import ReportConfig
    _cfg = ReportConfig(
        events=all_events,
        top_n=args.top,
        samples_n=args.samples,
        hist_minutes=args.hist_minutes,
        analysis=_analysis,
        ai_content=ai_content,
    )

    if args.format == "json":
        report = render_json_report(_cfg)
    elif args.format == "html":
        report = render_html_report(_cfg)
    elif args.format == "summary":
        report = render_executive_summary(all_events, _analysis=_analysis)
    elif args.format == "summary-html":
        report = render_executive_summary_html(all_events, _analysis=_analysis)
    else:
        report = render_markdown_report(_cfg)

    if isinstance(report, bytes):
        out_path.write_bytes(report)
    else:
        out_path.write_text(report, encoding="utf-8")
    if not args.quiet:
        print(f"Wrote report: {out_path}")
