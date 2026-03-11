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
- **Reports** — Markdown, JSON, CSV, XML, and PDF output
- **AI analysis** — optional Claude, Gemini, and OpenAI integration for root-cause suggestions (CLI and GUI)
- **Persistent API keys** — keyring with file-based fallback, keys survive app restarts
- **API rate limiting** — configurable cooldown between AI calls to prevent budget exhaustion
- **Prompt injection protection** — system/user prompt separation, XML delimiters, input sanitization
- **Security hardening** — symlink rejection, path traversal prevention, API key format validation

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
- **Ask AI for help** — enter an error code or question, select Claude/Gemini/OpenAI from the model dropdown, get AI-powered analysis with Splunk suggestions
- **AI caching** — repeated queries return instantly for all providers (session + file-based cache)
- **Realtime log monitoring** — tail a log file and see new events as they arrive
- **Swedish Chef mode** — novelty mode with sound clips and Muppet-style translated responses
- **API keys in sidebar** — Anthropic, Gemini, and OpenAI keys (or `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` / `OPENAI_API_KEY` env vars). Keys persist via keyring + file fallback
- **Download reports** — Markdown, JSON, CSV, XML, and PDF
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

# With OpenAI analysis
pip install -e ".[openai]"

# With tests
pip install -e ".[test]"

# With e2e tests (Playwright)
pip install -e ".[e2e]"

# Everything
pip install -e ".[gui,claude,gemini,openai,test,e2e]"
```

## Tests

```bash
pytest
```

463 tests covering parsing, classification, redaction, heuristics, Splunk queries, hung thread analysis, caching, prompt injection protection, Gemini integration, OpenAI integration, skill auto-selection, report generation (Markdown/JSON/CSV/XML/PDF), app helpers, keychain management, symlink rejection, API key validation, rate limiting, and 31 Playwright end-to-end tests. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## AI Provider Setup

All AI providers are optional. Install the one(s) you want:

### Claude (Anthropic)

```bash
pip install -e ".[claude]"
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Gemini (Google)

```bash
pip install -e ".[gemini]"
export GEMINI_API_KEY="AI..."
```

### OpenAI

```bash
pip install -e ".[openai]"
export OPENAI_API_KEY="sk-..."
```

API keys can also be entered in the Streamlit sidebar. Keys are persisted via system keyring with a local file fallback (`cache/.api_keys.json`), so you only need to enter them once.

In the GUI, select your preferred model from the **AI Model** dropdown, then click **Ask AI for help**.
