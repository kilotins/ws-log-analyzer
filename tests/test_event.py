"""Tests for LogEvent dataclass and dict-protocol compatibility."""
import json
from dataclasses import asdict

import pytest
from logpilot.event import LogEvent


class TestLogEventCreation:
    """Test LogEvent construction and defaults."""

    def test_default_fields(self):
        e = LogEvent()
        assert e.text == ""
        assert e.ts is None
        assert e.level is None
        assert e.tags == []
        assert e.file == ""
        assert e.line_num == 0
        assert e.trace_ids == []

    def test_keyword_construction(self):
        e = LogEvent(text="error msg", level="ERROR", code="CWWKZ0002E")
        assert e.text == "error msg"
        assert e.level == "ERROR"
        assert e.code == "CWWKZ0002E"

    def test_tags_are_independent(self):
        """Each LogEvent should have its own tags list."""
        e1 = LogEvent()
        e2 = LogEvent()
        e1.tags.append("OOM/GC")
        assert e2.tags == []


class TestDictProtocol:
    """Test backwards-compatible dict access."""

    def test_getitem(self):
        e = LogEvent(level="ERROR")
        assert e["level"] == "ERROR"

    def test_getitem_missing_raises_keyerror(self):
        e = LogEvent()
        with pytest.raises(KeyError):
            _ = e["nonexistent_field"]

    def test_setitem(self):
        e = LogEvent()
        e["level"] = "WARNING"
        assert e.level == "WARNING"

    def test_contains(self):
        e = LogEvent()
        assert "level" in e
        assert "nonexistent" not in e

    def test_get_existing(self):
        e = LogEvent(level="INFO")
        assert e.get("level") == "INFO"

    def test_get_default(self):
        e = LogEvent()
        assert e.get("nonexistent", "fallback") == "fallback"

    def test_get_none_field(self):
        e = LogEvent()
        assert e.get("level") is None

    def test_keys(self):
        e = LogEvent()
        keys = e.keys()
        assert "text" in keys
        assert "level" in keys
        assert "ts_utc" in keys

    def test_values(self):
        e = LogEvent(level="ERROR")
        values = e.values()
        assert "ERROR" in values

    def test_items(self):
        e = LogEvent(level="ERROR", code="CWWKZ0002E")
        items = dict(e.items())
        assert items["level"] == "ERROR"
        assert items["code"] == "CWWKZ0002E"

    def test_keys_issubset(self):
        """keys() should work with set operations (used in tests)."""
        e = LogEvent(level="ERROR")
        required = {"level", "text", "tags"}
        assert required.issubset(set(e.keys()))


class TestSerialization:
    """Test JSON serialization via asdict/to_dict."""

    def test_to_dict(self):
        e = LogEvent(text="hello", level="ERROR", tags=["OOM/GC"])
        d = e.to_dict()
        assert isinstance(d, dict)
        assert d["text"] == "hello"
        assert d["level"] == "ERROR"
        assert d["tags"] == ["OOM/GC"]

    def test_asdict(self):
        e = LogEvent(text="test")
        d = asdict(e)
        assert d["text"] == "test"

    def test_json_serializable(self):
        e = LogEvent(text="log line", level="INFO", tags=["HTTP"])
        j = json.dumps(e.to_dict())
        assert "log line" in j


class TestPipelineFields:
    """Test fields added later in the pipeline."""

    def test_ts_utc_setitem(self):
        e = LogEvent()
        e["ts_utc"] = "2025-03-05T12:34:56+00:00"
        assert e.ts_utc == "2025-03-05T12:34:56+00:00"

    def test_system_label_setitem(self):
        e = LogEvent()
        e["system_label"] = "frontend"
        assert e.system_label == "frontend"

    def test_format_field(self):
        e = LogEvent(format="was")
        assert e["format"] == "was"

    def test_trace_ids(self):
        e = LogEvent(trace_ids=["abc-123", "def-456"])
        assert len(e.trace_ids) == 2
