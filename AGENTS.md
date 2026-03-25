# LogPilot — Shared Agent Instructions

This file is read by all AI coding agents (Claude Code, Codex, Gemini CLI).
For agent-specific config see: CLAUDE.md, GEMINI.md.

## Project

LogPilot is a multi-format log analyzer (Python 3.9+, stdlib-only core). Parses logs, detects incidents with 68 heuristics, generates triage reports, and provides AI-powered root cause analysis.

- **Core package:** `logpilot/` — parser, analysis, heuristics, event, formats/, reports/, ai, cli
- **GUI:** `app.py` + `app_*.py` (Streamlit) — will be replaced by React + FastAPI in 2.0
- **Tests:** `tests/` — 1842+ unit tests (pytest), Playwright e2e
- **Skills:** `skills/` — domain knowledge YAML/MD used in AI prompts
- **Distribution:** Docker Hub (`kilotin/logpilot`), TestPyPI (`logpilot`)

## Rules

1. **Core is Streamlit-free.** `logpilot/` has zero Streamlit imports. Keep it that way.
2. **No required deps.** Core runs on stdlib only. AI SDKs, Streamlit, fpdf2 are optional.
3. **Secret redaction.** All event text is redacted before output. Use `sanitize_error()` from `logpilot.ai` for error messages.
4. **Preserve behavior.** Don't change logic unless clearly buggy. All existing tests must pass.
5. **No architecture changes.** This is a V1 codebase being maintained until 2.0 platform launches.

## Key Files

| File | Purpose |
|------|---------|
| `logpilot/parser.py` | Event parsing, redaction, format auto-detection |
| `logpilot/analysis.py` | Summarize, timeline, cascades, incident grouping |
| `logpilot/heuristics.py` | 68 heuristics, 19 correlations, 7 incident groups |
| `logpilot/ai.py` | AI prompts, token estimation, `sanitize_error()` |
| `logpilot/formats/` | 14 format plugins (WAS, JSON, nginx, Log4j, etc.) |
| `logpilot/reports/` | 7 renderers (markdown, html, json, pdf, etc.) |
| `app.py` | Streamlit GUI entry point |
| `app_ai.py` | AI provider orchestration (Streamlit-coupled) |
| `app_incident.py` | Incident AI assistant with multimodal support |
| `report_renderer.py` | Markdown to branded HTML converter |

## Tools

- **Render MD as HTML:** `python3 report_renderer.py <file>.md --open`
- **Run tests:** `python3 -m pytest tests/ --ignore=tests/test_app_e2e.py -q`
- **Build Docker:** `docker build -t kilotin/logpilot:latest .`
- **Build PyPI:** `pipx run build . && pipx run twine upload --repository testpypi dist/*`

## Reviews

Save code reviews or audit reports as `.md` files in the project root. Use `report_renderer.py` to convert to branded HTML.
