# Claude Code Project Context: LogPilot

LogPilot is a multi-format log analyzer with 8 format plugins (WAS, JSON, nginx, Log4j, Python, syslog, Enonic XP, Kubernetes/CRI-O). Parses log files, extracts events with metadata (severity, exceptions, codes, signal tags), and generates triage reports. Built as a Python CLI with an optional Streamlit GUI.

## What This Tool Does

1. **Parses** log files (plain text or `.gz`) with auto-detected format plugins into structured events
2. **Classifies** events by severity, message codes, exceptions, root causes, and signal tags (OOM, HungThreads, DB/Pool, SSL, HTTP)
3. **Generates** triage reports in Markdown, JSON, CSV, XML, and PDF with timeline histograms and prioritized samples
4. **Redacts** secrets (bearer tokens, passwords, API keys) before output
5. **Optional AI analysis** via Claude, Gemini, or OpenAI for root-cause suggestions

## Technology Stack

- **Language**: Python 3.9+ (stdlib only for core — zero required deps)
- **CLI**: argparse
- **GUI**: Streamlit (optional)
- **AI**: Anthropic SDK + Google Gemini SDK + OpenAI SDK (optional)
- **Tests**: pytest + Playwright (e2e)

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
| **GC** | `skills/gc-performance.md` — GC tuning, OOM patterns, heap analysis |
| **JMS** | `skills/jms-messaging.md` — JMS messaging, queue issues, connection factories |
| **JSON Logs** | `skills/json-structured-logs.md` — Bunyan, Pino, structlog, zap, Docker/K8s, CloudWatch |
| **nginx** | `skills/nginx-analysis.md` — Access/error logs, HTTP statuskoder, upstream-problem |
| **Log4j** | `skills/log4j-analysis.md` — Log4j/Logback, Spring Boot, HikariCP, Kafka |
| **Python** | `skills/python-logging-analysis.md` — Django, Flask, FastAPI, tracebacks, Celery |
| **syslog** | `skills/syslog-analysis.md` — RFC 3164/5424, journald, OOM killer, systemd |
| **Enonic XP** | `skills/enonic-xp-analysis.md` — server.log, Jetty request log, cluster health, repo/blob errors |
| **OpenShift/K8s** | `skills/openshift-k8s-analysis.md` — CRI-O logs, pod lifecycle, operators, routes, audit |
| **Docker** | `.claude/skills/docker-deployment.md` — Dockerfile, compose, volumes, security |
| **Log Formats** | `.claude/skills/log-format-plugins.md` — LogFormat protocol, auto-detect, skapa nya format-plugins |
| **Packaging** | `.claude/skills/python-packaging.md` — pyproject.toml, building, PyPI, entry points |
| **Rebranding** | `.claude/skills/rebranding-guide.md` — Checklista för att byta projektnamn |

## Critical Gotchas

- **Modular core**: All parsing/analysis logic is in the `logpilot/` package (parser, analysis, reports, ai, cli, formats/) — `app*.py` only imports from it
- **No required deps**: Core runs on stdlib only. `anthropic`, `google-generativeai`, `openai`, `streamlit`, `pytest` are optional
- **Event boundary heuristic**: New events start at timestamps, but stacktraces and `Caused by:` lines are kept with their parent event
- **Secret redaction**: Runs on all event text before output — never expose raw log content
- **WAS severity precedence**: Single-letter WAS codes (I/A/W/E/O/F/R/D) take priority over keyword-level matching
