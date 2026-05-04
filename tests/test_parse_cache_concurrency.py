"""Concurrency tests for parse-cache eviction (2.0-6 fix)."""
import os
import threading
import time
from pathlib import Path

import pytest


def _make_cache_files(tmp_path: Path, count: int) -> None:
    """Create *count* fake cache files with staggered mtimes."""
    for i in range(count):
        f = tmp_path / f"parsed_test{i:04d}.json.gz"
        f.write_text(f"data{i}")
        # Stagger mtimes so eviction order is deterministic
        os.utime(f, (time.time() - i, time.time() - i))


def test_evict_under_concurrency(tmp_path):
    """Multiple concurrent evictions must not crash or leave more files than max."""
    from logpilot.parser import _evict_parse_cache

    _make_cache_files(tmp_path, 60)

    errors: list[Exception] = []

    def worker():
        try:
            _evict_parse_cache(tmp_path, max_files=10)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors, f"Eviction crashed under concurrency: {errors}"

    remaining = list(tmp_path.glob("parsed_*.json.gz"))
    # Allow some slack: lock-skipped workers may leave slightly more than max,
    # but the combined result must be well below the original 60.
    assert len(remaining) <= 15, (
        f"Too many cache files remain after concurrent eviction: {len(remaining)}"
    )


def test_evict_no_files(tmp_path):
    """Eviction on an empty (or below-threshold) directory is a no-op."""
    from logpilot.parser import _evict_parse_cache

    _make_cache_files(tmp_path, 5)
    _evict_parse_cache(tmp_path, max_files=10)

    remaining = list(tmp_path.glob("parsed_*.json.gz"))
    assert len(remaining) == 5


def test_evict_exactly_at_limit(tmp_path):
    """Exactly max_files entries — nothing should be removed."""
    from logpilot.parser import _evict_parse_cache

    _make_cache_files(tmp_path, 50)
    _evict_parse_cache(tmp_path, max_files=50)

    remaining = list(tmp_path.glob("parsed_*.json.gz"))
    assert len(remaining) == 50


def test_evict_stale_lock_is_cleared(tmp_path):
    """A stale lock (>30 s) should be removed and eviction should proceed."""
    from logpilot.parser import _evict_parse_cache

    _make_cache_files(tmp_path, 60)

    # Plant a stale lock directory
    lock_dir = tmp_path / ".eviction.lock"
    lock_dir.mkdir()
    stale_time = time.time() - 60  # 60 s old
    os.utime(lock_dir, (stale_time, stale_time))

    _evict_parse_cache(tmp_path, max_files=10)

    remaining = list(tmp_path.glob("parsed_*.json.gz"))
    assert len(remaining) <= 10
    assert not lock_dir.exists(), "Stale lock directory should have been cleaned up"
