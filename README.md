# LogPilot

CLI tool and Streamlit web GUI that analyzes WebSphere / Java logs and generates triage reports with actionable insights.

## Features

- **Log parsing** — 8 format plugins: WebSphere/Liberty, JSON (Bunyan/Pino/structlog/zap), nginx, Log4j/Logback, Python (Django/Flask/FastAPI), syslog/journald, Enonic XP, Kubernetes/CRI-O. Supports `.log` and `.gz` files, multi-file, auto-detection
- **Event classification** — severity levels, WAS message codes, Java exceptions with root cause extraction
- **Signal tagging** — OOM/GC, HungThreads, DB/Pool, SSL/TLS, HTTP errors
- **Likely Causes & Fixes** — heuristic pattern matching with suggested remediation steps
- **Suggested Splunk Searches** — auto-generated queries based on detected issues
- **Hung Thread Drilldown** — per-thread analysis with stack samples and timeline
- **Timeline histogram** — configurable bucket size, error overlay
- **Secret redaction** — bearer tokens, passwords, API keys, JWTs, connection strings
- **Incident grouping** — 7 incident chain patterns (OOM cascade, auth failure, timeout cascade, deploy, network, database, thread starvation)
- **Cross-system analysis** — timezone normalization, trace ID correlation, Plotly timeline, 6 cascade detection patterns
- **Reports** — Markdown, JSON, HTML, and PDF output
- **AI analysis** — optional Claude, Gemini, and OpenAI integration for root-cause suggestions (CLI and GUI)
- **Persistent API keys** — keyring with file-based fallback, keys survive app restarts
- **API rate limiting** — configurable cooldown between AI calls to prevent budget exhaustion
- **Prompt injection protection** — system/user prompt separation, XML delimiters, input sanitization
- **Security hardening** — symlink rejection, path traversal prevention, API key format validation

## CLI Usage

```bash
# Basic analysis
python -m logpilot SystemOut.log

# Multi-file with options
python -m logpilot SystemOut.log SystemErr.log --top 20 --samples 10 --hist-minutes 5

# JSON output
python -m logpilot SystemOut.log --format json

# AI root-cause analysis
python -m logpilot SystemOut.log --claude
python -m logpilot SystemOut.log --claude --model claude-sonnet-4-6
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
| `--log-type` | auto | Force log type (was, json, nginx, log4j, python, syslog, enonic, crio) |
| `--list-formats` | off | List available log format plugins and exit |
| `--claude` | off | Enable AI root-cause analysis |
| `--model` | claude-sonnet-4-6 | Claude model to use |
| `--ai-endpoint` | — | Local AI endpoint URL (e.g. http://localhost:1234/v1) |
| `--ai-model` | — | Local AI model name |
| `--log-format` | text | Log output format (text / json) |
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
- **API keys in sidebar** — Anthropic, Gemini, and OpenAI keys (or `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` / `OPENAI_API_KEY` env vars). Keys persist via keyring + file fallback
- **Cross-system timeline** — Plotly stacked charts per source with cascade detection (when 2+ files uploaded)
- **Analyze All Logs** — AI-powered cross-system triage with all providers
- **Download reports** — Markdown, JSON, HTML, and PDF
- **History tab** — browse and download previous reports, clear history

## Installation

```bash
# Core only (no dependencies)
pip install -e .

# With GUI (includes charts)
pip install -e ".[gui]"

# With GUI + PDF export
pip install -e ".[gui,pdf]"

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

1217 tests across 27 test files covering parsing, classification, redaction, heuristics, correlations, incident grouping, all 8 format plugins, Splunk queries, hung thread analysis, caching, prompt injection protection, AI integration (Claude/Gemini/OpenAI/local), skill auto-selection, report generation (Markdown/JSON/HTML/PDF), CLI, audit, spend tracking, app helpers, keychain management, symlink rejection, API key validation, rate limiting, and Playwright end-to-end tests. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

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
