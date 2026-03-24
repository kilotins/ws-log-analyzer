# Contributing to LogPilot

## Development Setup

```bash
# Clone and create virtual environment
git clone https://github.com/kilotins/ws-log-analyzer.git
cd ws-log-analyzer
python3 -m venv .venv
source .venv/bin/activate

# Install with all optional dependencies
pip install -e ".[test,gui,pdf,claude,gemini,openai]"
```

## Running Tests

```bash
# All unit tests (1629+ tests, ~25 seconds)
pytest tests/ --ignore=tests/test_app_e2e.py --ignore=tests/test_e2e_full.py --ignore=tests/test_scenario_e2e.py -v

# Fast: stop on first failure
pytest tests/ --ignore=tests/test_app_e2e.py --ignore=tests/test_e2e_full.py --ignore=tests/test_scenario_e2e.py -x -q

# Single test file
pytest tests/test_parsing.py -v

# E2E tests (requires running Streamlit server + Playwright)
pip install -e ".[e2e]"
playwright install chromium
pytest tests/test_app_e2e.py -v
```

## Project Structure

```
logpilot/                  # Core engine package (stdlib only, zero required deps)
├── event.py               # LogEvent dataclass
├── parser.py              # Parsing, redaction, format auto-detection
├── analysis.py            # Summarize, timeline, cross-system cascades
├── heuristics.py          # 68 heuristics, 19 correlations, 7 incident groups
├── discovery.py           # Recursive folder scan, rotated log support
├── trace_to_code.py       # Stack trace → source code location mapping
├── code_search.py         # Source code search for trace correlation
├── jira_tickets.py        # Jira ticket generation from incidents
├── ai.py                  # AI prompt building, skill selection, caching
├── cli.py                 # CLI entry point
├── reports/               # Report renderers (7 modules)
│   ├── markdown.py        # Markdown report
│   ├── html.py            # HTML report
│   ├── json_report.py     # JSON report
│   ├── pdf.py             # PDF report
│   ├── brief_pdf.py       # Executive brief PDF
│   ├── executive_summary.py  # Executive summary extraction
│   └── config.py          # Report configuration
└── formats/               # 11 format plugins (WAS, JSON, nginx, Log4j, Python, syslog, Enonic, CRI-O, DataPower, Tomcat, PostgreSQL)

app.py                     # Streamlit GUI entry point
app_ai.py                  # AI provider orchestration (Claude, Gemini, OpenAI, local)
app_incident.py            # Unified Incident AI Assistant
app_render.py              # Report rendering UI with incident grouping
app_audit.py               # AI-driven code quality audit
app_jira.py                # Jira integration UI
app_spend.py               # Cost tracking & analytics
app_realtime.py            # Live log monitoring
app_constants.py           # Shared constants (LEVEL_COLORS, etc.)
report_renderer.py         # Markdown → HTML conversion

skills/                    # Domain knowledge files (20+ files)
.claude/skills/            # Claude Code skills (12+ files)
tests/                     # 1629+ tests across 44+ test files + 25 Playwright e2e tests
scripts/                   # Audit automation (run_audit.py, compare_audits.py)
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed data flow and module documentation.

## Key Conventions

- **LogEvent dataclass** — all events are `LogEvent` instances (not raw dicts). Use attribute access (`event.level`) in new code
- **No required deps** — core `logpilot/` package runs on stdlib only. AI SDKs, Streamlit, etc. are optional
- **Format plugins** — each implements `detect()`, `extract_ts()`, `extract_level()`, `is_continuation()`, `classify_event()`, `bucket_tags()`
- **Private symbols** — import from submodules (`from logpilot.heuristics import _HEURISTICS`), never from `logpilot` package root
- **Type hints** — all public functions have annotations with `from __future__ import annotations`
- **Lint** — `ruff check .`

## Code Style

- Python 3.9+ compatible
- Type hints on all public functions
- Docstrings on public functions
- f-strings (no `%`-formatting except in lazy `logging` calls)
- Module-level loggers: `logging.getLogger(__name__)`

## PR Checklist

- [ ] All existing tests pass (`pytest tests/ --ignore=tests/test_app_e2e.py`)
- [ ] New tests added for new functionality
- [ ] No secrets or API keys in committed code
- [ ] Type hints on new public functions
- [ ] LogEvent used (not raw dicts) for event data
