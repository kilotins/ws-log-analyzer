"""Shared test fixtures for ws-log-analyzer tests."""
import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')")


def make_event(text, level="ERROR", code=None, exception=None, root_cause=None, tags=None):
    """Build a minimal event dict for tests."""
    return {
        "level": level, "code": code, "exception": exception,
        "root_cause": root_cause, "tags": tags or [],
        "ts": "10/12/15 21:22:04:257",
        "file": "test.log", "text": text, "thread_id": "00000001",
    }


def empty_match(**overrides):
    """Build a minimal match result dict for skill/prompt tests."""
    base = {"matched": False, "match_type": None, "matching_events": [],
            "codes": [], "exceptions": [], "tags": []}
    base.update(overrides)
    return base
