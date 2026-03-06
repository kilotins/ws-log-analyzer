# Claude Code Project Context: WS Log Analyzer

WebSphere/Java log analyzer that parses log files, extracts events with metadata (severity, exceptions, WAS codes, signal tags), and generates triage reports. Built as a single-file Python CLI with an optional Streamlit GUI.

## What This Tool Does

1. **Parses** WebSphere and Java log files (plain text or `.gz`) into structured events
2. **Classifies** events by severity, WAS message codes, exceptions, root causes, and signal tags (OOM, HungThreads, DB/Pool, SSL, HTTP)
3. **Generates** triage reports in Markdown or JSON with timeline histograms and prioritized samples
4. **Redacts** secrets (bearer tokens, passwords, API keys) before output
5. **Optional AI analysis** via Claude API for root-cause suggestions

## Technology Stack

- **Language**: Python 3.9+ (stdlib only for core — zero required deps)
- **CLI**: argparse
- **GUI**: Streamlit (optional)
- **AI**: Anthropic SDK + Google Gemini SDK (optional)
- **Tests**: pytest

## Project Structure

See [ARCHITECTURE.md](ARCHITECTURE.md) for full project structure, data flow, and function tables.
See [README.md](README.md) for installation, CLI options, and usage.

## Skills

| Category | Skill |
|----------|-------|
| **Domain** | `.claude/skills/ws-log-parsing.yaml` — event boundaries, signal tags, extending the analyzer |
| **UI** | `.claude/skills/streamlit-patterns.md` — session state, callbacks, widget gotchas, file structure |
| **AI** | `.claude/skills/claude-integration.md` — prompt structure, security, caching, API key storage |
| **Testing** | `.claude/skills/testing.md` — pytest, Playwright e2e, Streamlit DOM gotchas |
| **WAS Codes** | `skills/message-codes.md` — WAS message code prefixes and high-impact codes |
| **Stacktraces** | `skills/stacktrace-analysis.md` — Java stacktrace reading, common exceptions |
| **Threads** | `skills/thread-correlation.md` — Thread naming, hung thread patterns |
| **Splunk** | `skills/splunk-query.md` — Ready-made Splunk queries for WAS |
| **Startup** | `skills/websphere-startup.md` — Startup sequence, failure patterns |
| **Servlets** | `skills/servlet-errors.md` — SRVE codes, servlet lifecycle |
| **Liberty** | `skills/liberty-analysis.md` — Liberty-specific patterns, MicroProfile |
| **Deploy** | `skills/deployment-analysis.md` — Deploy lifecycle, rollback indicators |
| **Security** | `skills/security-analysis.md` — Auth failures, SSL, brute force detection |
| **Noise** | `skills/log-noise-filter.md` — Safe-to-ignore patterns, noise heuristics |

## Critical Gotchas

- **Single-file core**: All parsing/analysis logic is in `wslog.py` — `app.py` only imports from it
- **No required deps**: Core runs on stdlib only. `anthropic`, `google-generativeai`, `streamlit`, `pytest` are optional
- **Event boundary heuristic**: New events start at timestamps, but stacktraces and `Caused by:` lines are kept with their parent event
- **Secret redaction**: Runs on all event text before output — never expose raw log content
- **WAS severity precedence**: Single-letter WAS codes (I/A/W/E/O/F/R/D) take priority over keyword-level matching
