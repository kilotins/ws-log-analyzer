# WS Log Analyzer — Public API Reference

All public functions live in `wslog.py`. The module has zero required dependencies (Python 3.9+ stdlib only).

```python
from wslog import parse_file, precompute_analysis, render_markdown_report
```

---

## Parsing

### `parse_file(path, max_lines=None)`

Parse a log file and return a list of event dicts.

```python
from pathlib import Path
from wslog import parse_file

events = parse_file(Path("server.log"))
# Each event: {"ts": "10/12/15 21:22:04:257", "level": "ERROR", "code": "CWPKI0022E",
#              "exception": "CertPathBuilderException", "root_cause": "...",
#              "tags": ["SSL"], "text": "...", "file": "server.log", "thread_id": "00000150"}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | `Path` | required | Log file path (`.log`, `.txt`, or `.gz`) |
| `max_lines` | `int \| None` | `None` | Stop after N lines (useful for previews) |

**Returns:** `list[dict[str, object]]` — list of event dicts.

### `parse_file_iter(path, max_lines=None)`

Generator version of `parse_file()`. Yields event dicts one at a time without holding all events in memory.

```python
from wslog import parse_file_iter

for event in parse_file_iter(Path("large_server.log")):
    if event["level"] == "ERROR":
        print(event["code"], event["text"][:80])
```

Same parameters and event format as `parse_file()`.

---

## Classification

### `classify_event(text)`

Classify a block of log text and return metadata.

```python
from wslog import classify_event

meta = classify_event("[10/12/15 21:22:13:837 CEST] 00000150 WSX509TrustMa E   CWPKI0022E: SSL HANDSHAKE FAILURE")
# {"level": "ERROR", "code": "CWPKI0022E", "exception": None,
#  "root_cause": None, "tags": ["SSL"]}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `text` | `str` | Raw log event text block |

**Returns:** `dict` with keys `level`, `code`, `exception`, `root_cause`, `tags`.

### `redact(s)`

Remove secrets (bearer tokens, API keys, passwords, AWS keys) from text.

```python
from wslog import redact

safe = redact("Authorization: Bearer eyJhbGciOi...")
# "Authorization: Bearer ***REDACTED***"
```

---

## Analysis

### `precompute_analysis(events, top_n=10, samples_n=5, hist_minutes=1)`

Run all analysis passes once and return a dict of results.

```python
from wslog import parse_file, precompute_analysis

events = parse_file(Path("server.log"))
pa = precompute_analysis(events, top_n=5)
print(pa["summary"])       # {"total": 150, "errors": 23, "warnings": 45, ...}
print(pa["causes"])        # [("SSL HANDSHAKE FAILURE", 12), ...]
print(pa["hist"])          # [("21:22", 5), ("21:23", 8), ...]
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `events` | `list[dict]` | required | Parsed events from `parse_file()` |
| `top_n` | `int` | `10` | Number of top codes/exceptions to include |
| `samples_n` | `int` | `5` | Number of sample events per category |
| `hist_minutes` | `int` | `1` | Histogram time bucket size in minutes |

**Returns:** `dict` with keys: `summary`, `file_summary`, `causes`, `hist`, `splunk`, `hung`, `samples`, `top_n`, `samples_n`, `hist_minutes`.

### `summarize(events, top_n)`

Compute summary statistics: total events, counts by level, top codes, top exceptions, top tags.

```python
from wslog import parse_file, summarize

events = parse_file(Path("server.log"))
s = summarize(events, top_n=5)
print(s["total"], s["errors"])
print(s["codes"])  # [("CWPKI0022E", 12), ("TCPC0001I", 8), ...]
```

### `incident_timeline(events, window_seconds=30)`

Build a timeline around the first error event within a +/- time window.

```python
from wslog import parse_file, incident_timeline

events = parse_file(Path("server.log"))
timeline = incident_timeline(events, window_seconds=60)
if timeline:
    print(f"Trigger: {timeline['trigger_event']['code']}")
    for we in timeline["window_events"]:
        print(f"  {we['offset_seconds']:+.1f}s  {we['event']['level']}")
```

**Returns:** `dict` with `trigger_event`, `trigger_dt`, `window_events`, `window_seconds` — or `None` if no error events found.

### `estimate_tokens(text, provider="claude")`

Rough token estimate using provider-specific character ratios (Claude ~3.5, GPT/Gemini ~4.0 chars/token).

```python
from wslog import estimate_tokens

tokens = estimate_tokens("Hello world", provider="claude")  # ~3
tokens = estimate_tokens("Hello world", provider="openai")  # ~2
```

---

## Report Rendering

All renderers accept the same event list from `parse_file()`. Pass a pre-computed `_analysis` dict to avoid redundant computation.

### `render_markdown_report(events, top_n=10, samples_n=5, hist_minutes=1, _analysis=None)`

Generate a Markdown triage report.

```python
from wslog import parse_file, precompute_analysis, render_markdown_report

events = parse_file(Path("server.log"))
pa = precompute_analysis(events)
md = render_markdown_report(events, _analysis=pa)
Path("report.md").write_text(md)
```

**Returns:** `str` — Markdown text.

### `render_json_report(events, top_n=10, samples_n=5, hist_minutes=1, _analysis=None)`

Generate a JSON triage report.

**Returns:** `str` — JSON string.

### `render_pdf_report(events, top_n=10, samples_n=5, hist_minutes=1, _analysis=None)`

Generate a PDF triage report. Requires `fpdf2` (`pip install fpdf2`).

**Returns:** `bytes` — PDF file content.

### `render_csv_report(events, max_text=500)`

Export events as CSV.

**Returns:** `str` — CSV text with columns: `timestamp`, `level`, `code`, `exception`, `tags`, `text`.

### `render_xml_report(events, max_text=500)`

Export events as XML.

**Returns:** `str` — XML document string.

---

## Event Dict Schema

Every event dict returned by `parse_file()` has these keys:

| Key | Type | Description |
|-----|------|-------------|
| `ts` | `str \| None` | Timestamp string as found in the log |
| `level` | `str` | Severity: `ERROR`, `WARNING`, `INFO`, `DEBUG`, etc. |
| `code` | `str \| None` | WAS message code (e.g., `CWPKI0022E`) |
| `exception` | `str \| None` | Java exception class name |
| `root_cause` | `str \| None` | Innermost `Caused by:` exception |
| `tags` | `list[str]` | Signal tags: `OOM`, `HungThread`, `DB/Pool`, `SSL`, `HTTP` |
| `text` | `str` | Full event text (redacted, max 4000 chars) |
| `file` | `str` | Source filename |
| `thread_id` | `str \| None` | WebSphere thread ID |
