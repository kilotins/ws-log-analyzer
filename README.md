# WebSphere Log Analyzer

CLI tool and Streamlit web GUI that analyzes WebSphere / Java logs and generates triage reports with actionable insights.

## Features

- **Log parsing** — WebSphere classic and ISO timestamp formats, `.log` and `.gz` files, multi-file support
- **Event classification** — severity levels, WAS message codes, Java exceptions with root cause extraction
- **Signal tagging** — OOM/GC, HungThreads, DB/Pool, SSL/TLS, HTTP errors
- **Likely Causes & Fixes** — heuristic pattern matching with suggested remediation steps
- **Suggested Splunk Searches** — auto-generated queries based on detected issues
- **Hung Thread Drilldown** — per-thread analysis with stack samples and timeline
- **Timeline histogram** — configurable bucket size, error overlay
- **Secret redaction** — bearer tokens, passwords, API keys, JWTs, connection strings
- **Reports** — Markdown, JSON, and PDF output
- **AI analysis** — optional Claude and Gemini integration for root-cause suggestions (CLI and GUI)
- **Prompt injection protection** — system/user prompt separation, XML delimiters, input sanitization

## CLI Usage

```bash
# Basic analysis
./wslog.py SystemOut.log

# Multi-file with options
./wslog.py SystemOut.log SystemErr.log --top 20 --samples 10 --hist-minutes 5

# JSON output
./wslog.py SystemOut.log --format json

# AI root-cause analysis
./wslog.py SystemOut.log --claude
./wslog.py SystemOut.log --claude --model claude-sonnet-4-6
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--top` | 10 | Top-N items in summary |
| `--samples` | 5 | Number of sample events |
| `--hist-minutes` | 1 | Histogram bucket size in minutes |
| `--format` | markdown | Output format (markdown / json) |
| `--out` | report.md | Output file path |
| `--max-lines` | unlimited | Limit lines per file |
| `--claude` | off | Enable AI root-cause analysis |
| `--model` | claude-sonnet-4-6 | Claude model to use |
| `-q` | off | Suppress progress messages |

## GUI Usage

Install dependencies:

```bash
pip install -e ".[gui]"
```

Run the Streamlit app:

```bash
streamlit run app.py
```

Open http://localhost:8501.

### GUI Features

- **Analyze tab** — upload `.log` / `.gz` files, configure settings, click Analyze
- **Collapsible sections** — Summary, Likely Causes & Fixes, Splunk Searches, Hung Threads, Timeline, Event Samples
- **Incident timeline** — groups errors into time-windowed incidents for faster triage
- **Ask Claude** — enter an error code or question, get AI-powered analysis with Splunk suggestions
- **Ask Gemini** — Google Gemini AI analysis alongside Claude
- **Dual AI caching** — repeated queries return instantly for both providers (session + file-based cache)
- **Realtime log monitoring** — tail a log file and see new events as they arrive
- **Swedish Chef mode** — novelty mode with sound clips and Muppet-style translated responses
- **API keys in sidebar** — Anthropic and Gemini keys (or `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` env vars)
- **Download reports** — Markdown, JSON, and PDF
- **History tab** — browse and download previous reports, clear history

## Installation

```bash
# Core only (no dependencies)
pip install -e .

# With GUI
pip install -e ".[gui]"

# With Claude AI analysis
pip install -e ".[claude]"

# With Gemini AI analysis
pip install -e ".[gemini]"

# With tests
pip install -e ".[test]"

# Everything
pip install -e ".[gui,claude,gemini,test]"
```

## Tests

```bash
pytest
```

177+ tests covering parsing, classification, redaction, heuristics, Splunk queries, hung thread analysis, caching, prompt injection protection, Gemini integration, skill auto-selection, and report generation.

## Gemini Setup

1. Install the dependency:

```bash
pip install -e ".[gemini]"
```

2. Set your API key:

```bash
export GEMINI_API_KEY="your_api_key_here"
```

Or enter the key directly in the Streamlit sidebar under "Gemini API Key".

3. In the GUI, click **Ask Gemini** next to the existing **Analyze with Claude** button to get Gemini's analysis of the same query.
