"""Shared constants for the Streamlit GUI modules."""

# Level-to-color mapping used by incident timeline and realtime monitor
LEVEL_COLORS = {
    "FATAL": "#dc3545",
    "ERROR": "#dc3545",
    "SEVERE": "#dc3545",
    "WARNING": "#D97706",
    "WARN": "#D97706",
    "INFO": "#0d6efd",
    "AUDIT": "#0891B2",
    "DEBUG": "#adb5bd",
}

# Realtime monitor buffer size (max lines kept in memory)
RT_BUFFER_SIZE = 300

# AI response cache TTL (7 days)
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60

# Maximum number of cached AI responses stored on disk
MAX_CACHE_ENTRIES = 100

# Minimum seconds between AI API calls (rate limiting)
AI_RATE_LIMIT_SECONDS = 2.0

# Maximum characters of event text shown in reports
MAX_EVENT_TEXT = 4000

# Hard upload size limit (MB) — files exceeding this are rejected
MAX_UPLOAD_MB = 200
