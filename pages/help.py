"""LogPilot — Help: in-app user guide."""
import streamlit as st

st.title("Help")
st.caption("LogPilot user guide — all features, workflows, and tips in one place.")

# ---------------------------------------------------------------------------
# Quick Start
# ---------------------------------------------------------------------------
with st.expander("Quick Start", expanded=True):
    st.markdown("""
### Get up and running in 3 steps

1. **Upload log files** on the **Home** page — drag and drop `.log`, `.gz`, or `.zip` files,
   or point LogPilot at a folder for recursive scanning.
2. **Click Analyze** — LogPilot auto-detects the format and parses all events.
3. **Explore results** — use the sidebar pages (Overview, Causes & Fixes, AI Analysis, etc.)
   to investigate findings.
""")
    col1, col2 = st.columns(2)
    with col1:
        st.info("**14 log formats** are auto-detected with no configuration required.")
    with col2:
        st.info("**Heuristics run offline** — Causes & Fixes works without any AI or API key.")

# ---------------------------------------------------------------------------
# Pages Guide
# ---------------------------------------------------------------------------
with st.expander("Pages Guide", expanded=False):
    st.markdown("""
| Page | What it does |
|------|-------------|
| **Home** | Upload log files, configure analysis options, run the analyzer |
| **Overview** | Dashboard — severity breakdown, top codes, exceptions, signal tags |
| **Causes & Fixes** | 68 automated heuristic findings with fix suggestions — works fully offline |
| **AI Analysis** | Symptom-driven AI diagnosis across all log sources |
| **Timeline** | Visual event histogram per day — spot bursts and quiet periods |
| **Events** | Browse and filter every parsed event with full message text |
| **Reports** | Export to PDF, HTML, or Leadership Brief (PDF/HTML) |
| **Trace to Code** | Match stacktraces to your source code — appears when a repo is linked |
| **Jira & Confluence** | Generate Jira tickets and publish analysis to Confluence |
| **Settings** | API keys, license, local AI endpoint, source code path, theme |
""")
    st.info("The **sidebar** shows global severity and source filters that apply across all pages.")

# ---------------------------------------------------------------------------
# AI Analysis Guide
# ---------------------------------------------------------------------------
with st.expander("AI Analysis Guide", expanded=False):
    st.markdown("### How AI Analysis works")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
**Symptoms field**
Describe what you are investigating in plain language.
- "Application crashes every night at 02:00"
- "Users see 502 errors after deploy"
- "Database connections exhausted"

The AI uses your description to focus on relevant events.

**Exclude filter**
Comma-separated keywords to strip out before analysis.
- Removes noisy patterns (e.g. health-check pings, expected retries)
- Auto-extracted from symptoms: phrases like *"ignore X"* or *"don't focus on X"* are
  parsed into the filter automatically.

**Noise filter (slider)**
Removes repetitive low-value events before the AI sees them.
Higher values = more aggressive deduplication.
""")
    with col2:
        st.markdown("""
**Model selection**
Pick a provider and model in the sidebar:
- **Claude** (Anthropic) — best for complex multi-system analysis
- **Gemini** (Google) — fast, cost-effective for large log sets
- **OpenAI** — GPT-4o and friends
- **Local** — Ollama, LM Studio, any OpenAI-compatible endpoint

**Multi-source analysis**
When logs from multiple systems are loaded, LogPilot automatically
correlates events across sources and prompts the AI accordingly.

**Leadership Brief**
One-click rewrite of the technical analysis into a non-technical
executive summary — export as PDF or HTML.

**Screenshots**
Attach browser screenshots, dashboards, or error pages.
The AI uses them as additional context (multimodal input).
""")

    st.markdown("---")
    st.markdown("""
**Conversation context** — run analysis multiple times to refine findings.
The AI builds on previous answers so you can drill down without repeating context.
""")
    st.warning("Screenshots may contain PII. Review before uploading to cloud AI providers.")

# ---------------------------------------------------------------------------
# Supported Log Formats
# ---------------------------------------------------------------------------
with st.expander("Supported Log Formats", expanded=False):
    st.markdown("""
All 14 formats are auto-detected. You can also specify a format explicitly with `--format`
on the CLI or via the Settings page.

| Format | Description | Auto-detect |
|--------|-------------|:-----------:|
| `was` | IBM WebSphere Application Server & Liberty | Yes |
| `nginx` | nginx access logs and error logs | Yes |
| `log4j` | Log4j / Logback, Spring Boot, HikariCP, Kafka | Yes |
| `json` | Bunyan, Pino, structlog, zap, CloudWatch | Yes |
| `python` | Django, Flask, FastAPI, Celery, tracebacks | Yes |
| `syslog` | RFC 3164 / RFC 5424, journald, OOM killer | Yes |
| `enonic` | Enonic XP server.log and Jetty request log | Yes |
| `crio` | Kubernetes CRI-O container logs | Yes |
| `docker_json` | Docker JSON log driver | Yes |
| `datapower` | IBM DataPower gateway | Yes |
| `tomcat` | Apache Tomcat Catalina JUL format | Yes |
| `postgresql` | PostgreSQL server logs with DETAIL/HINT | Yes |
| `docker_compose` | Docker Compose multi-service logs | Yes |
| `generic` | Fallback parser for unknown formats | Yes |
""")
    st.info("Compressed files (`.gz`) and zip archives are supported for all formats.")

# ---------------------------------------------------------------------------
# Heuristics & Signal Tags
# ---------------------------------------------------------------------------
with st.expander("Heuristics & Signal Tags", expanded=False):
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
### Automated Heuristics
LogPilot ships **68 heuristic patterns** that run on every analysis — no AI or internet
connection required.

**What heuristics detect:**
- Out-of-memory (OOM) events and heap exhaustion
- SSL/TLS handshake failures and certificate errors
- Database connection pool exhaustion
- HTTP 4xx/5xx error spikes
- Hung and stuck threads
- Deployment and startup failures
- Authentication and security events
- Garbage collection pressure
""")
    with col2:
        st.markdown("""
### Signal Tags
Each event is tagged when it matches a known high-signal pattern:

| Tag | Meaning |
|-----|---------|
| `OOM` | Out-of-memory event |
| `HungThread` | Thread stuck or blocked |
| `DB/Pool` | Database / connection pool issue |
| `SSL` | SSL/TLS error |
| `HTTP` | HTTP error (4xx/5xx) |
| `Deploy` | Deployment lifecycle event |
| `Auth` | Authentication failure |
| `GC` | Garbage collection warning |

### Incident Groups
Related events are clustered into **incident groups** with:
- Root cause / downstream / concurrent labels
- Confidence scoring (0–100 %)
- Failure chain visualization
""")

# ---------------------------------------------------------------------------
# Reports & Export
# ---------------------------------------------------------------------------
with st.expander("Reports & Export", expanded=False):
    st.markdown("""
### Export formats

| Format | Best for |
|--------|---------|
| **PDF** | Branded technical report — numbered sections, stacktraces, AI findings |
| **HTML** | Interactive report — sidebar nav, dark/light mode, collapsible sections |
| **Leadership Brief (PDF)** | Non-technical summary for executives and stakeholders |
| **Leadership Brief (HTML)** | Quick share via email or chat |

All reports include:
- Severity breakdown and top event codes
- Heuristic findings with fix suggestions
- Timeline histogram
- Prioritized event samples
- AI analysis section (if AI was run)

### Secret redaction
All event text is automatically redacted before export.
Bearer tokens, passwords, and API keys are replaced with `[REDACTED]`.
""")

# ---------------------------------------------------------------------------
# Settings & Configuration
# ---------------------------------------------------------------------------
with st.expander("Settings & Configuration", expanded=False):
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
**License**
Required for cloud AI features (Claude, Gemini, OpenAI).
Contact eric@item.no to get a license key.

**API Keys**
- Anthropic — for Claude models
- Google — for Gemini models
- OpenAI — for GPT models

Keys are stored locally in the LogPilot cache directory and never sent anywhere
except the respective AI provider.
""")
    with col2:
        st.markdown("""
**Local AI**
Connect to a local model server using any OpenAI-compatible endpoint:
- Ollama (`http://localhost:11434`)
- LM Studio (`http://localhost:1234`)
- Any custom endpoint

**Trace to Code**
Provide a path to your source code directory. LogPilot will match
stacktrace frames to actual source files. See the dedicated section below.

**Theme**
Dark/Light mode toggle is in the sidebar.
""")

# ---------------------------------------------------------------------------
# Trace to Code
# ---------------------------------------------------------------------------
with st.expander("Trace to Code", expanded=False):
    st.markdown("""
Match stacktraces from your logs to actual source code in your repository.

### How it works
1. **Link a repo** in Settings → Source Code Path (e.g. `/app/source/my-project`)
2. **Trace to Code page** appears in the nav — shows matched files with code snippets
3. **AI Analysis** automatically includes matched code in the AI prompt
4. **AI suggests fixes** — specific code changes shown per file on the Trace to Code page

### Supported stacktrace formats
| Language | Format | Example |
|----------|--------|---------|
| **Java** | Standard `at` frames | `at com.myapp.OrderDAO.save(OrderDAO.java:67)` |
| **Nashorn/Enonic XP** | Script frames | `(no.seeds.ukom:/site/layouts/article.js:97)` |
| **Python** | `File` traceback | `File "/app/tasks.py", line 45, in process` |
| **Node.js** | V8 `at` frames | `at requestHandler (/app/server.js:42:5)` |

### Confidence levels
- **Exact** (green) — file + line number match
- **File** (yellow) — file match, line approximate
- **Grep** (grey) — text search match (method name found in file)

### Framework filtering
LogPilot automatically filters out framework/library code and prioritizes
your application code. Supported frameworks: Spring, Hibernate, Enonic XP,
Django, Flask, FastAPI, Express, and 30+ more.

### Docker usage
Mount your source code as a read-only volume:
```yaml
volumes:
  - /path/to/your/code:/app/source:ro
```
Then set the path in Settings to `/app/source/your-project`.
""")

# ---------------------------------------------------------------------------
# Tips & Tricks
# ---------------------------------------------------------------------------
with st.expander("Tips & Tricks", expanded=False):
    st.markdown("""
### Performance
- For directories with many files, use **folder scan** instead of individual uploads
  to avoid browser upload overhead.
- Enable **"Sample INFO events"** when analyzing files with 100 000+ lines —
  it keeps all WARN/ERROR events but samples INFO to reduce noise.
- The parse result is **cached** — re-running analysis on the same files is instant.

### AI Analysis
- Add an **Exclude filter** before running AI to remove known noise
  (e.g. `health-check, OPTIONS /ping, ELB-HealthChecker`).
- Start with a broad symptom description, then narrow down with follow-up analyses.
- Use **Leadership Brief** after the technical analysis — it automatically rewrites
  the findings in non-technical language.

### Exports
- **HTML reports** are fully self-contained — share them as a single file.
- Run `logpilot --help` for CLI export options (also supports Markdown and JSON).

### Sidebar filters
Global **severity** and **source** filters in the sidebar apply to Overview, Events,
Timeline, and Reports simultaneously — use them to focus on a single system or severity.
""")
    st.info("Pressing **Analyze** again on the Home page clears the cache and re-parses all files.")

# ---------------------------------------------------------------------------
# About
# ---------------------------------------------------------------------------
with st.expander("About LogPilot", expanded=False):
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
**LogPilot** is a multi-format log analyzer built by [Item Consulting](https://item.no).

Supports 14 log formats, 68 heuristics, AI-assisted root cause analysis,
and exports to PDF and HTML.
""")
    with col2:
        st.markdown("""
| | |
|-|-|
| **Docker Hub** | `kilotin/logpilot:latest` |
| **PyPI** | `pip install logpilot[gui]` |
| **CLI** | `logpilot --help` |
| **Contact** | eric@item.no |
""")
    st.info("LogPilot core runs on Python stdlib only — zero required dependencies for CLI use.")
