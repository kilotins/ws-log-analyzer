"""LogEvent dataclass — structured representation of a parsed log event."""
from __future__ import annotations

from dataclasses import dataclass, field, fields, asdict
from typing import Any


@dataclass
class LogEvent:
    """A single parsed log event with structured metadata.

    Supports dict-protocol access (``event["level"]``, ``event.get("level")``)
    for backwards compatibility with code that used raw dicts.
    """

    text: str = ""
    ts: str | None = None
    level: str | None = None
    thread_id: str | None = None
    code: str | None = None
    exception: str | None = None
    root_cause: str | None = None
    tags: list[str] = field(default_factory=list)
    file: str = ""
    line_num: int = 0

    # Fields added later in the pipeline
    format: str | None = None
    tz_hint: str | None = None
    trace_ids: list[str] = field(default_factory=list)
    system_label: str | None = None
    ts_utc: str | None = None
    source: str | None = None

    # --- Dict-protocol compatibility ---

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, key, value)

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def keys(self):
        return [f.name for f in fields(self)]

    def values(self):
        return [getattr(self, f.name) for f in fields(self)]

    def items(self):
        return [(f.name, getattr(self, f.name)) for f in fields(self)]

    def to_dict(self) -> dict[str, Any]:
        """Convert to a plain dict (e.g. for JSON serialization)."""
        return asdict(self)
