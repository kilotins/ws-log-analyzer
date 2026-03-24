FROM python:3.12-slim

WORKDIR /app

# System deps (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (cache-friendly — only reruns when pyproject.toml changes)
# Copy minimal package structure so pip can resolve ".[extras]"
COPY pyproject.toml .
RUN mkdir -p logpilot && touch logpilot/__init__.py
RUN pip install --no-cache-dir ".[gui,claude,gemini,openai,pdf]"

# Copy all application code (overwrites the stub __init__.py)
COPY logpilot/ logpilot/
COPY app.py app_ai.py app_render.py app_incident.py app_audit.py \
     app_spend.py app_realtime.py app_jira.py app_constants.py \
     report_renderer.py ./
COPY skills/ skills/
COPY assets/ assets/
COPY .streamlit/ .streamlit/

# Runtime directories
RUN mkdir -p uploads reports cache

# Non-root user for security
RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "app.py", \
    "--server.port=8501", \
    "--server.address=0.0.0.0", \
    "--server.headless=true", \
    "--browser.gatherUsageStats=false"]
