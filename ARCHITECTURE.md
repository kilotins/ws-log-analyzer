# Architecture Overview

```
ws-log-analyzer/
├── wslog.py              # Core engine + CLI (single-file, zero required deps)
├── app.py                # Streamlit web GUI
├── tests/
│   └── test_wslog.py     # 54 pytest tests
├── pyproject.toml         # Package config with optional deps
├── README.md
└── .gitignore
```

## `wslog.py` — Core Engine + CLI (~470 lines)

The entire analysis pipeline lives in one file with no required dependencies (stdlib only). It breaks down into three layers:

**Regex Layer** — Compiled patterns at module level for timestamp extraction (WAS classic + ISO), WAS single-letter severity codes, thread IDs, message codes (`[A-Z]{4,5}\d{4}[A-Z]`), Java exceptions, stacktrace lines, and signal detection (OOM, hung threads, DB pool, SSL, HTTP errors). Also handles secret redaction (bearer tokens, passwords, API keys).

**Parsing Layer** — `parse_file()` reads log files (plain text or `.gz`) line by line, splitting on timestamp boundaries with stacktrace awareness. A `flush()` closure accumulates lines into events, skipping preamble (lines before the first timestamp). Each event is classified by `classify_event()` which extracts level, thread ID, WAS code, exception, root cause (deepest `Caused by:` chain entry), and signal tags.

**Reporting Layer** — Three functions consume parsed events:
- `summarize()` — Counter-based aggregation of levels, codes, exceptions, tags
- `render_markdown_report()` — Full markdown triage report with histogram, samples
- `render_json_report()` — Structured JSON equivalent

Supporting functions: `time_histogram()` (date-aware bucketing), `render_histogram()` (ASCII bar chart), `pick_samples()` (deduplicated, priority-scored event selection), `per_file_summary()`.

**CLI** — `main()` wires argparse to the pipeline. Supports multi-file input, markdown/JSON output, `--quiet`, `--max-lines`, and optional `--claude` integration (lazy-imports `anthropic`, sends sanitized report for AI root-cause analysis).

## `app.py` — Streamlit GUI (~130 lines)

Thin UI layer that imports from `wslog.py`. Two tabs:
- **Analyze** — Multi-file upload, configurable settings (top-N, samples, histogram bucket), metric cards (events/errors/warnings/files), top exceptions & codes panels, markdown+JSON download buttons, inline report display
- **History** — Lists timestamped reports from `reports/` directory with expand/download

Files are persisted as `{timestamp}_{name}` in `uploads/`, reports as `report_{timestamp}.md` in `reports/`.

## Data Flow

```
Log file(s)  →  parse_file()  →  List[event dicts]  →  summarize() / render_*_report()
                                                     →  pick_samples()
                                                     →  time_histogram()
```

Each event dict contains: `level`, `thread_id`, `code`, `exception`, `root_cause`, `tags`, `ts`, `file`, `text`.

## Dependencies

- **Core**: Python 3.9+ stdlib only (re, gzip, json, collections, argparse)
- **Optional**: `anthropic` (AI analysis), `streamlit` (GUI), `pytest` (tests)
