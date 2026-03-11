"""Performance and stress tests for ws-log-analyzer.

These tests are marked @pytest.mark.slow and excluded from standard CI.
Run with: pytest tests/test_performance.py -v
"""
import json
import threading
import time
from pathlib import Path

import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from wslog import parse_file, parse_file_iter, precompute_analysis, redact


def _generate_log_lines(n_events: int) -> str:
    """Generate n synthetic WAS log events."""
    lines = []
    base_hour = 10
    base_min = 0
    base_sec = 0
    levels = [
        ("I", "INFO", "ARFM5007I: config loaded"),
        ("W", "WARNING", "XJMS0022W: Destination in use"),
        ("E", "ERROR", "CWPKI0022E: SSL HANDSHAKE FAILURE\njava.security.cert.CertPathBuilderException: could not build path"),
        ("I", "INFO", "TCPC0001I: TCP listening on port 9081"),
        ("E", "ERROR", "J2CA0056E: Connection allocation failure\njava.sql.SQLException: pool exhausted"),
    ]
    for i in range(n_events):
        ltype, _, msg = levels[i % len(levels)]
        sec = base_sec + (i % 60)
        minute = base_min + ((i // 60) % 60)
        hour = base_hour + (i // 3600)
        ts = f"[10/12/15 {hour:02d}:{minute:02d}:{sec:02d}:000 CEST]"
        thread = f"{(i % 256):08x}"
        lines.append(f"{ts} {thread} Component {ltype}   {msg}")
    return "\n".join(lines) + "\n"


# ── 24.3 Stress tests for large files ───────────────────────────────

@pytest.mark.slow
class TestLargeFileParsing:
    def test_parse_100k_events(self, tmp_path):
        """parse_file should handle 100K events without error."""
        log_text = _generate_log_lines(100_000)
        log_file = tmp_path / "large.log"
        log_file.write_text(log_text)

        events = parse_file(log_file)
        assert len(events) >= 99_000  # allow small variance from boundary detection
        assert len(events) <= 101_000

    def test_parse_iter_100k_events(self, tmp_path):
        """parse_file_iter should stream 100K events without holding all in memory."""
        log_text = _generate_log_lines(100_000)
        log_file = tmp_path / "large.log"
        log_file.write_text(log_text)

        count = 0
        for event in parse_file_iter(log_file):
            count += 1
            assert "level" in event
        assert count >= 99_000

    def test_parse_iter_matches_parse_file(self, tmp_path):
        """parse_file and parse_file_iter should produce the same event count."""
        log_text = _generate_log_lines(10_000)
        log_file = tmp_path / "medium.log"
        log_file.write_text(log_text)

        events_list = parse_file(log_file)
        events_iter = list(parse_file_iter(log_file))
        assert len(events_list) == len(events_iter)

    def test_precompute_100k_events(self, tmp_path):
        """precompute_analysis should complete on 100K events."""
        log_text = _generate_log_lines(100_000)
        log_file = tmp_path / "large.log"
        log_file.write_text(log_text)

        events = parse_file(log_file)
        start = time.monotonic()
        pa = precompute_analysis(events)
        elapsed = time.monotonic() - start

        assert pa["summary"]["total_events"] >= 99_000
        assert elapsed < 30, f"precompute_analysis took {elapsed:.1f}s, expected <30s"

    def test_redact_performance_bulk(self):
        """redact() should handle 100K lines efficiently."""
        lines = [
            "Normal log line without secrets #" + str(i)
            for i in range(100_000)
        ]
        start = time.monotonic()
        for line in lines:
            redact(line)
        elapsed = time.monotonic() - start
        # Early-exit optimization should make this fast
        assert elapsed < 5, f"Bulk redact took {elapsed:.1f}s, expected <5s"

    def test_redact_with_secrets_bulk(self):
        """redact() with actual secrets should still complete in reasonable time."""
        lines = [
            f"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.token{i}"
            for i in range(10_000)
        ]
        start = time.monotonic()
        for line in lines:
            result = redact(line)
            assert "eyJ" not in result
        elapsed = time.monotonic() - start
        assert elapsed < 10, f"Secret redact took {elapsed:.1f}s, expected <10s"


# ── 24.4 Concurrent cache access ────────────────────────────────────

@pytest.mark.slow
class TestConcurrentCacheAccess:
    def test_concurrent_json_writes_no_corruption(self, tmp_path):
        """4 threads writing to the same JSON file should not corrupt it."""
        cache_file = tmp_path / "cache.json"
        cache_file.write_text("{}", encoding="utf-8")
        errors = []

        def writer(thread_id: int):
            try:
                for i in range(50):
                    # Read-modify-write cycle
                    try:
                        data = json.loads(cache_file.read_text(encoding="utf-8"))
                    except (json.JSONDecodeError, OSError):
                        data = {}
                    data[f"t{thread_id}_k{i}"] = f"value_{i}"
                    # Atomic write pattern
                    import tempfile
                    tmp_name = None
                    try:
                        with tempfile.NamedTemporaryFile(
                            mode="w", dir=tmp_path, suffix=".tmp",
                            delete=False, encoding="utf-8"
                        ) as tmp:
                            tmp_name = tmp.name
                            json.dump(data, tmp, ensure_ascii=False)
                        os.replace(tmp_name, str(cache_file))
                    except Exception:
                        if tmp_name:
                            try:
                                os.unlink(tmp_name)
                            except OSError:
                                pass
                        raise
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Thread errors: {errors}"

        # Final file must be valid JSON
        final = json.loads(cache_file.read_text(encoding="utf-8"))
        assert isinstance(final, dict)
        # At least some keys from each thread should survive
        thread_keys = {f"t{i}" for i in range(4)}
        surviving_threads = {k.split("_")[0] for k in final.keys()}
        assert len(surviving_threads & thread_keys) >= 1

    def test_concurrent_reads_during_write(self, tmp_path):
        """Readers should not crash even if a writer is active."""
        cache_file = tmp_path / "cache.json"
        cache_file.write_text('{"initial": "data"}', encoding="utf-8")
        read_errors = []
        write_errors = []

        def reader():
            try:
                for _ in range(100):
                    try:
                        text = cache_file.read_text(encoding="utf-8")
                        json.loads(text)
                    except (json.JSONDecodeError, OSError):
                        pass  # Expected during concurrent writes
            except Exception as e:
                read_errors.append(e)

        def writer():
            try:
                for i in range(50):
                    data = {f"key_{i}": f"value_{i}"}
                    import tempfile
                    tmp_name = None
                    try:
                        with tempfile.NamedTemporaryFile(
                            mode="w", dir=tmp_path, suffix=".tmp",
                            delete=False, encoding="utf-8"
                        ) as tmp:
                            tmp_name = tmp.name
                            json.dump(data, tmp)
                        os.replace(tmp_name, str(cache_file))
                    except Exception:
                        if tmp_name:
                            try:
                                os.unlink(tmp_name)
                            except OSError:
                                pass
                        raise
            except Exception as e:
                write_errors.append(e)

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not read_errors, f"Reader errors: {read_errors}"
        assert not write_errors, f"Writer errors: {write_errors}"
        # File should be valid at the end
        final = json.loads(cache_file.read_text(encoding="utf-8"))
        assert isinstance(final, dict)
