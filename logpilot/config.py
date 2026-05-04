"""Centralized application paths and config.

In 2.0 (FastAPI), all paths come from env-vars. In 1.x (Streamlit),
defaults are derived from app.py location for backward compat.
"""
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AppConfig:
    """Application paths. All overridable via env-vars."""
    base_dir: Path
    uploads_dir: Path
    reports_dir: Path
    cache_dir: Path
    logs_dir: Path
    api_keys_file: Path
    license_key_file: Path
    theme_file: Path
    local_ai_settings_file: Path
    keyring_file: Path

    @classmethod
    def from_env(cls, default_base: Path | None = None) -> "AppConfig":
        """Build config from environment variables, falling back to default_base."""
        base = Path(
            os.environ.get(
                "LOGPILOT_BASE_DIR",
                str(default_base or Path.home() / ".logpilot"),
            )
        )

        return cls(
            base_dir=base,
            uploads_dir=Path(os.environ.get("LOGPILOT_UPLOADS_DIR", str(base / "uploads"))),
            reports_dir=Path(os.environ.get("LOGPILOT_REPORTS_DIR", str(base / "reports"))),
            cache_dir=Path(os.environ.get("LOGPILOT_CACHE_DIR", str(base / "cache"))),
            logs_dir=Path(os.environ.get("LOGPILOT_LOGS_DIR", str(base / "logs"))),
            api_keys_file=Path(os.environ.get("LOGPILOT_API_KEYS_FILE", str(base / ".api_keys.json"))),
            license_key_file=Path(os.environ.get("LOGPILOT_LICENSE_KEY_FILE", str(base / ".license_key"))),
            theme_file=Path(os.environ.get("LOGPILOT_THEME_FILE", str(base / ".theme.json"))),
            local_ai_settings_file=Path(
                os.environ.get("LOGPILOT_LOCAL_AI_SETTINGS", str(base / ".local_ai_settings.json"))
            ),
            keyring_file=Path(os.environ.get("LOGPILOT_KEYRING_FILE", str(base / ".keyring.json"))),
        )

    def ensure_dirs(self) -> None:
        """Create all directories that should exist."""
        for d in [self.uploads_dir, self.reports_dir, self.cache_dir, self.logs_dir, self.base_dir]:
            d.mkdir(parents=True, exist_ok=True)


# Module-level singleton for app.py compat.
# default_base = repo root (parent of the logpilot/ package directory).
_default_app_dir = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = AppConfig.from_env(default_base=_default_app_dir)
