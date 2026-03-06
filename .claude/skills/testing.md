# Testing Patterns

## Test Stack

- **Unit tests**: `pytest` — `tests/test_wslog.py`
- **E2E tests**: `playwright` — `tests/test_app_e2e.py`
- **Fixtures**: `tests/fixtures/sample.log` (git add -f, since *.log is gitignored)

## Unit Tests (test_wslog.py)

- Use string constants (SAMPLE_LOG, STACKTRACE_LOG, etc.) as inline fixtures
- Use `tmp_path` pytest fixture for file-based tests
- Test regexes directly for pattern matching
- Use `parse_file()` for integration tests
- Every new signal tag needs a `test_bucket_tags_*` test
- Every new function in `wslog.py` needs tests

Current count: 152 tests.

## E2E Tests (test_app_e2e.py)

Uses `pytest-playwright` with a `streamlit_server` fixture that auto-starts/stops
the Streamlit app on port 8501.

### Streamlit-Specific DOM Gotchas

- **Strict mode**: Streamlit often renders duplicate elements. Use `.first` on locators.
- **Exact matching**: Use `exact=True` or `get_by_role(name=..., exact=True)` to avoid
  matching substrings (e.g., "Analyze" vs "Analyze with Claude").
- **Collapsed expanders**: Content exists in DOM but isn't visible. Use
  `scroll_into_view_if_needed()` or check DOM presence instead of visibility.
- **Async reruns**: After clicking buttons, add `page.wait_for_timeout(1000-3000)`
  for Streamlit to complete its rerun cycle.
- **File upload**: Use `page.locator('input[type="file"]').set_input_files(path)`.

### Port Conflicts

Streamlit instances on port 8501 can linger. Kill before tests:
```bash
lsof -ti:8501 | xargs kill -9
```

## Running Tests

```bash
# Unit tests
python3 -m pytest tests/test_wslog.py -v

# E2E tests (starts its own Streamlit server)
python3 -m pytest tests/test_app_e2e.py -v

# All tests
python3 -m pytest -v
```
