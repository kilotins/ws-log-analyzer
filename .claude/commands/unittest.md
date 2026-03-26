Run all unit tests from the project test suite.

Refer to `.claude/skills/testing.md` for test patterns and conventions.

## Steps

1. Run: `python3 -m pytest tests/test_wslog.py -v --tb=short`
2. Report: total, passed, failed, errors
3. If any tests fail, read the failing test and the relevant source code, then explain the root cause and fix it

## Options

- If the user says "fast": run `python3 -m pytest tests/test_wslog.py -x -q` (stop on first failure)
- If the user says "fix": automatically fix any failing tests
