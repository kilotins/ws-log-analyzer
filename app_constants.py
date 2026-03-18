"""Shared constants for the Streamlit GUI modules."""

# Level-to-color mapping used by incident timeline, realtime monitor, and chart renderers
LEVEL_COLORS = {
    "FATAL": "#DC2626",
    "SEVERE": "#DC2626",
    "ERROR": "#EF4444",
    "WARNING": "#F59E0B",
    "WARN": "#F59E0B",
    "INFO": "#7C3AED",
    "AUDIT": "#0891B2",
    "DEBUG": "#94A3B8",
    "UNKNOWN": "#6B7280",
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

# Maximum screenshot size for incident assistant (MB)
MAX_SCREENSHOT_MB = 10
