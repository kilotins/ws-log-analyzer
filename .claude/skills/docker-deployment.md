# Docker Deployment for LogPilot

## Architecture

The app runs as a Streamlit container exposing port 8501.
All dependencies are installed via `pyproject.toml` optional extras.

## Project Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Multi-stage build for the Streamlit app |
| `.dockerignore` | Excludes .venv, .git, caches, tests |
| `docker-compose.yml` | Optional: orchestration with env vars and volumes |

## Dockerfile Pattern

Based on [Streamlit Docker docs](https://docs.streamlit.io/deploy/tutorials/docker).

```dockerfile
FROM python:3.9-slim

WORKDIR /app

# System deps (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (cache-friendly layer)
COPY pyproject.toml .
RUN pip install --no-cache-dir ".[gui,claude,gemini,openai,pdf]"

# Copy application code
COPY logpilot/ logpilot/
COPY app.py app_ai.py app_render.py app_audit.py app_spend.py app_realtime.py app_constants.py ./
COPY skills/ skills/
COPY heuristics.yaml ./
COPY assets/ assets/

# Non-root user for security
RUN useradd --create-home appuser
USER appuser

EXPOSE 8501

HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "app.py", \
    "--server.port=8501", \
    "--server.address=0.0.0.0", \
    "--server.headless=true", \
    "--browser.gatherUsageStats=false"]
```

### Key Design Decisions

1. **`python:3.9-slim`** — Matches `requires-python = ">=3.9"`, slim keeps image small (~200MB vs ~900MB full)
2. **Layer ordering** — `pyproject.toml` copied first so deps are cached until dependencies change
3. **Non-root user** — Security best practice; Streamlit does not need root
4. **`--server.headless=true`** — Suppresses "open browser" prompt in container
5. **`--no-cache-dir`** — Smaller image, no pip cache in container
6. **Healthcheck** — Uses Streamlit's built-in `/_stcore/health` endpoint

## .dockerignore Pattern

```
.venv/
.git/
.github/
.claude/
__pycache__/
*.pyc
*.pyo
.mypy_cache/
.pytest_cache/
.ruff_cache/
tests/
docs/
scripts/
uploads/
reports/
cache/
logs/
*.egg-info/
*.bak
.DS_Store
.env
AUDIT_REPORT.*
PROJECT_OVERVIEW.*
```

## Environment Variables

API keys should **never** be baked into the image. Pass them at runtime:

```bash
# Single keys
docker run -p 8501:8501 \
    -e ANTHROPIC_API_KEY=sk-ant-... \
    -e GOOGLE_API_KEY=... \
    -e OPENAI_API_KEY=sk-... \
    logpilot-app

# Or use an env file
docker run -p 8501:8501 --env-file .env logpilot-app
```

The app also supports entering API keys in the sidebar UI (stored in session state, not persisted to disk in the container).

## Volumes

Mount volumes for persistent data across container restarts:

```bash
docker run -p 8501:8501 \
    -v logpilot-uploads:/app/uploads \
    -v logpilot-reports:/app/reports \
    -v logpilot-cache:/app/cache \
    logpilot-app
```

| Volume | Purpose |
|--------|---------|
| `/app/uploads` | Uploaded log files |
| `/app/reports` | Generated triage reports |
| `/app/cache` | AI response cache (JSON files) |

## docker-compose.yml Pattern

```yaml
services:
  logpilot:
    build: .
    ports:
      - "8501:8501"
    env_file:
      - .env
    volumes:
      - uploads:/app/uploads
      - reports:/app/reports
      - cache:/app/cache
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8501/_stcore/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  uploads:
  reports:
  cache:
```

## Build & Run Commands

```bash
# Build
docker build -t logpilot-app .

# Run (basic)
docker run -p 8501:8501 logpilot-app

# Run (production, with env and volumes)
docker run -d --name logpilot \
    -p 8501:8501 \
    --env-file .env \
    -v logpilot-uploads:/app/uploads \
    -v logpilot-reports:/app/reports \
    --restart unless-stopped \
    logpilot-app

# Compose
docker compose up -d
```

## Streamlit Config in Container

If you need custom Streamlit config, create `.streamlit/config.toml`:

```toml
[server]
maxUploadSize = 200
enableXsrfProtection = true
enableCORS = false

[browser]
gatherUsageStats = false
```

Then add to Dockerfile: `COPY .streamlit/ .streamlit/`

## Gotchas

- **keyring** does not work in containers (no desktop keyring daemon). API keys must come from env vars or sidebar input
- **Realtime monitoring** (`app_realtime.py`) needs the log file mounted into the container: `-v /var/log/was:/logs:ro`
- **fpdf2** (PDF reports) works out of the box — no system fonts needed for latin-1
- **File uploads** are written to `/app/uploads/` — use a volume or they disappear on restart
- **Container size**: ~500MB with all optional deps. Drop `openai`/`gemini` extras to save ~100MB
- **Port mapping**: For external access, map to 80: `-p 80:8501`

## Security Checklist

- [ ] Non-root user in Dockerfile
- [ ] No API keys in image (use env vars or secrets)
- [ ] `.env` in `.dockerignore` and `.gitignore`
- [ ] `enableXsrfProtection = true` in Streamlit config
- [ ] Read-only mounts where possible (`:ro`)
- [ ] Pin base image version for reproducibility (`python:3.9.21-slim`)
