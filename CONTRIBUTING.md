# Contributing to WS Log Analyzer

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
# Unit tests (fast, no external deps)
pytest tests/test_wslog.py tests/test_app_helpers.py -v

# E2E tests (requires Playwright)
pip install -e ".[e2e]"
playwright install chromium
pytest tests/test_app_e2e.py -v
```

## Project Structure

- `wslog.py` — Core parsing/analysis engine (zero required deps)
- `app.py` — Streamlit GUI entry point
- `app_ai.py` — AI provider orchestration (Claude, Gemini, OpenAI)
- `app_render.py` — Report rendering UI
- `app_audit.py` — Audit report generation
- `app_realtime.py` — Live log monitoring
- `app_spend.py` — Cloud spend tracking
- `report_renderer.py` — Markdown to HTML conversion
- `skills/` — Domain knowledge files (12 files)
- `.claude/skills/` — Claude Code specific skills (4 files)
- `tests/` — Test suite (463 tests)

## Code Style

- Python 3.9+ compatible
- Type hints on all public functions
- Docstrings on public functions
- No required external dependencies for core (`wslog.py`)
- Lint with `ruff check .`

## PR Checklist

- [ ] All existing tests pass (`pytest tests/test_wslog.py tests/test_app_helpers.py`)
- [ ] New tests added for new functionality
- [ ] No secrets or API keys in committed code
- [ ] Type hints on new public functions
