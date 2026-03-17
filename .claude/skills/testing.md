# Testing Patterns

## Test Stack

- **Unit tests**: `pytest` — multiple files under `tests/`
- **E2E tests**: `playwright` — `tests/test_app_e2e.py`
- **Fixtures**: `tests/fixtures/sample.log` (git add -f, since *.log is gitignored)

Current count: **1004+ tests**.

## Test File Overview

| File                      | Covers                                                        |
|---------------------------|---------------------------------------------------------------|
| `test_parsing.py`         | `parse_file()`, event boundaries, redaction, gzip fallback   |
| `test_reports.py`         | All report renderers (Markdown, JSON, HTML, PDF) + AI content |
| `test_ai_prompt.py`       | Format-aware AI prompt construction, `_sanitize_prompt_input` |
| `test_app_helpers.py`     | Streamlit helper functions, session state utilities           |
| `test_local_ai.py`        | Local AI provider calls, token estimation                     |
| `test_audit_gaps.py`      | Burst detection, correlation rules, cascade detection         |
| `test_heuristics.py`      | Analysis heuristics, severity scoring                         |
| `test_integration.py`     | End-to-end pipeline: parse → analyze → report                 |
| `test_performance.py`     | Parse throughput, memory usage on large files                 |
| `test_wslog.py`           | Legacy WAS-specific unit tests (kept for regression coverage) |
| `test_formats.py`         | Format auto-detection, plugin registry, ambiguity cases       |
| `test_format_enonic.py`   | Enonic XP format plugin                                       |
| `test_format_json.py`     | JSON structured log format plugin                             |
| `test_format_k8s.py`      | CRI-O / Kubernetes format plugin                              |
| `test_format_log4j.py`    | Log4j / Logback / Spring Boot format plugin                   |
| `test_format_nginx.py`    | nginx access and error log format plugin                      |
| `test_format_python.py`   | Python logging format plugin                                  |
| `test_format_syslog.py`   | syslog (RFC 3164/5424, journald) format plugin                |

## Unit Test Conventions

- Use string constants (`SAMPLE_LOG`, `STACKTRACE_LOG`, etc.) as inline fixtures — no real log files
- Use `tmp_path` pytest fixture for file-based tests
- Test regexes directly for pattern matching
- Use `parse_file()` for integration-style tests
- Every new signal tag needs a `test_bucket_tags_*` test
- Every new function in the `logpilot/` package needs tests

### Per-Format Test Convention

Each format plugin has a dedicated test file `tests/test_format_<name>.py`. It must cover:

1. `detect()` — scores high on matching lines, low on non-matching lines
2. `extract_ts()` — extracts timestamp correctly
3. `extract_level()` — maps format-specific levels to normalized levels
4. `is_continuation()` — stacktrace/multiline lines return True
5. `classify_event()` — required keys present in output dict
6. `bucket_tags()` — each signal tag is detectable

## Notable Test Patterns

### Burst Detection (test_audit_gaps.py)
```python
def test_burst_detection_groups_closely_spaced_events():
    # Feed events with ts_utc within a short window, assert burst flagged
```

### Correlation Rule Tests (test_audit_gaps.py)
```python
def test_correlation_links_oom_and_gc_events():
    # Events with OOM tag and GC tag close in time should be correlated
```

### Cascade Detection (test_audit_gaps.py)
```python
def test_cascade_detection_finds_error_chain():
    # Sequence of related errors produces a CascadeGroup
```

### Gzip Fallback (test_parsing.py)
```python
def test_parse_file_reads_gz_compressed_log(tmp_path):
    # Write a .gz file, assert parse_file() produces same events as plain text
```

### Adversarial Redaction (test_parsing.py)
```python
def test_redact_does_not_strip_non_secret_urls():
    ...
def test_redact_removes_bearer_token():
    ...
def test_redact_handles_empty_string():
    ...
```

### Prompt Injection Guard (test_ai_prompt.py)
```python
def test_sanitize_prompt_input_strips_injection_attempts():
    # Input containing "Ignore previous instructions" is sanitized
```

### time_histogram Edge Cases (test_reports.py)
```python
def test_time_histogram_empty_events():
    ...
def test_time_histogram_all_same_timestamp():
    ...
def test_time_histogram_missing_ts():
    ...
```

### Format Auto-Detection Ambiguity (test_formats.py)
```python
def test_detect_prefers_crio_over_json_for_kubernetes_fields():
    # Lines with kubernetes.pod_name should score higher for CRI-O than JSON
```

### Cross-System Timeline / Trace ID (future, test_integration.py)
```python
# When cross-system analysis is added:
def test_sort_events_chronologically_merges_two_sources():
    ...
def test_trace_id_correlation_links_nginx_and_app_events():
    ...
```

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
# All unit tests
python3 -m pytest tests/ --ignore=tests/test_app_e2e.py -v

# Specific test file
python3 -m pytest tests/test_parsing.py -v
python3 -m pytest tests/test_format_nginx.py -v

# All format plugin tests
python3 -m pytest tests/test_format_*.py -v

# Audit / burst / correlation tests
python3 -m pytest tests/test_audit_gaps.py -v

# E2E tests (starts its own Streamlit server)
python3 -m pytest tests/test_app_e2e.py -v

# Full suite
python3 -m pytest -v
```
