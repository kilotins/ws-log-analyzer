Run the project test suite. Use the testing skill at `.claude/skills/testing.md` for context.

## Steps

1. Run unit tests: `python3 -m pytest tests/test_wslog.py -v --tb=short`
2. Report results: total, passed, failed, errors
3. If any tests fail, analyze the failures and suggest fixes
4. Do NOT run E2E tests (Playwright) unless explicitly asked — they require a running Streamlit server

## Options

- If the user says "all" or "e2e", also run: `python3 -m pytest tests/test_app_e2e.py -v --tb=short`
- If the user says "fast", run: `python3 -m pytest tests/test_wslog.py -x -q` (stop on first failure, quiet)
