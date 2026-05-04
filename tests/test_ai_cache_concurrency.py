"""Concurrency tests for the AI response file cache in app.py."""
import json
import threading
import time
from pathlib import Path

import pytest


@pytest.fixture()
def cache_file(tmp_path):
    """Return a temporary cache file path with an empty JSON object."""
    f = tmp_path / "ai_responses.json"
    f.write_text("{}")
    return f


def test_concurrent_writes_dont_clobber(cache_file, monkeypatch):
    """Multiple threads writing to the ai_response cache shouldn't lose each other's entries."""
    import app
    monkeypatch.setattr(app, "CACHE_FILE", cache_file)

    now = time.time()
    errors: list = []

    def worker(i):
        try:
            app._save_file_cache(f"key{i}", {"text": f"value{i}", "ts": now})
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert not errors, f"Worker errors: {errors}"

    result = json.loads(cache_file.read_text())
    assert len(result) == 20, (
        f"Expected 20 entries, got {len(result)}: {sorted(result.keys())}"
    )


def test_load_file_cache_filters_expired(cache_file, monkeypatch):
    """_load_file_cache should discard entries beyond the TTL."""
    import time
    import app

    monkeypatch.setattr(app, "CACHE_FILE", cache_file)
    monkeypatch.setattr(app, "_CACHE_TTL_SECONDS", 60)

    old_ts = time.time() - 120  # 2 minutes ago — expired
    fresh_ts = time.time() - 10  # 10 seconds ago — still valid

    cache_file.write_text(json.dumps({
        "old_key": {"text": "old_value", "ts": old_ts},
        "fresh_key": {"text": "fresh_value", "ts": fresh_ts},
    }))

    result = app._load_file_cache()
    assert "fresh_key" in result
    assert "old_key" not in result


def test_save_file_cache_evicts_lru(cache_file, monkeypatch):
    """_save_file_cache should evict oldest entries when MAX_CACHE_ENTRIES is exceeded."""
    import time
    import app

    monkeypatch.setattr(app, "CACHE_FILE", cache_file)
    monkeypatch.setattr(app, "MAX_CACHE_ENTRIES", 5)

    # Pre-populate with 5 entries
    now = time.time()
    initial = {f"key{i}": {"text": f"val{i}", "ts": now + i} for i in range(5)}
    cache_file.write_text(json.dumps(initial))

    # Adding one more should evict the oldest (key0 has smallest ts)
    app._save_file_cache("key5", {"text": "val5", "ts": now + 5})

    result = json.loads(cache_file.read_text())
    assert len(result) == 5, f"Expected 5 entries after eviction, got {len(result)}"
    assert "key0" not in result, "Oldest entry should have been evicted"
    assert "key5" in result


def test_file_lock_context_manager(tmp_path):
    """_file_lock should create and release a .lock file without error."""
    import app

    target = tmp_path / "test.json"
    target.write_text("{}")

    with app._file_lock(target):
        lock_file = Path(str(target) + ".lock")
        if app._HAS_FCNTL:
            assert lock_file.exists(), ".lock file should exist while lock is held"

    # After context exits the lock is released (file may still exist — that's fine)
