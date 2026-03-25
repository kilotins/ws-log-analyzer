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

# Maximum number of retry attempts for transient AI API errors (timeout, 429, 500-503)
AI_MAX_RETRIES = 3

# Approximate cost per 1M tokens (input, output) in USD
TOKEN_COSTS = {
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5-20251001": (0.80, 4.00),
    "claude-opus-4-6": (15.00, 75.00),
    "gemini-2.5-flash": (0.15, 0.60),
    "gemini-2.5-pro": (1.25, 10.00),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "o3": (10.00, 40.00),
    "o4-mini": (1.10, 4.40),
}

# Cache token pricing per 1M tokens (cache_write, cache_read) in USD
# cache_write = cost to create cached content, cache_read = cost to read from cache
CACHE_TOKEN_COSTS = {
    "claude-sonnet-4-6": (3.75, 0.30),
    "claude-haiku-4-5-20251001": (1.00, 0.08),
    "claude-opus-4-6": (18.75, 1.50),
}
