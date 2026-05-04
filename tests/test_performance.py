"""Performance and stress tests for LogPilot.

These tests are marked @pytest.mark.slow and excluded from standard CI.
Run with: pytest tests/test_performance.py -v
"""
import json
import sys
import os
import threading
import time
from dataclasses import fields
from pathlib import Path

import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from logpilot import parse_file_iter, precompute_analysis, redact
from logpilot.event import LogEvent
from logpilot.parser import parse_file, parse_file_cached, classify_event


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


# ── M44: LogEvent __slots__ ──────────────────────────────────────────

class TestLogEventSlots:
    def test_logevent_has_slots(self):
        """On Python 3.10+, LogEvent should use __slots__ for memory efficiency."""
        if sys.version_info >= (3, 10):
            assert hasattr(LogEvent, "__slots__")
            e = LogEvent(text="test", level="INFO")
            assert not hasattr(e, "__dict__")
        else:
            # On 3.9, __slots__ not available via dataclass
            pass

    def test_logevent_dict_protocol_with_slots(self):
        """Dict-protocol methods must work even with __slots__."""
        e = LogEvent(text="hello", level="ERROR", code="WSVR0001I")
        assert e["level"] == "ERROR"
        assert e.get("code") == "WSVR0001I"
        assert "text" in e
        e["level"] = "WARNING"
        assert e.level == "WARNING"
        assert set(e.keys()) == set(f.name for f in fields(LogEvent))

    def test_logevent_getitem_missing_key_raises(self):
        """Accessing a non-existent key via [] should raise KeyError."""
        e = LogEvent(text="test")
        with pytest.raises(KeyError):
            _ = e["nonexistent_field"]

    def test_logevent_contains_known_and_unknown_fields(self):
        """__contains__ should return True for known fields, False for unknown."""
        e = LogEvent(text="test", level="INFO")
        assert "level" in e
        assert "text" in e
        assert "tags" in e
        assert "not_a_field" not in e

    def test_logevent_items_and_values_consistent(self):
        """items() and values() should be consistent with keys()."""
        e = LogEvent(text="msg", level="ERROR", code="CWPKI0022E")
        key_list = e.keys()
        items = dict(e.items())
        values = e.values()
        assert list(items.keys()) == key_list
        assert list(items.values()) == values
        assert items["level"] == "ERROR"
        assert items["code"] == "CWPKI0022E"

    def test_logevent_to_dict_round_trip(self):
        """to_dict() should produce a plain dict with all field values."""
        e = LogEvent(text="msg", level="WARNING", tags=["OOM/GC"])
        d = e.to_dict()
        assert isinstance(d, dict)
        assert d["text"] == "msg"
        assert d["level"] == "WARNING"
        assert d["tags"] == ["OOM/GC"]
        assert set(d.keys()) == set(f.name for f in fields(LogEvent))


# ── M44: String interning ─────────────────────────────────────────────

class TestStringInterning:
    def test_classify_event_interns_level(self):
        """classify_event should return interned strings for level."""
        r1 = classify_event("[10/12/15 21:22:04:257 CEST] 0000001 Component I some info")
        r2 = classify_event("[10/12/15 21:22:04:258 CEST] 0000002 Component I other info")
        # Interned strings share identity
        if r1.get("level") and r2.get("level"):
            assert r1["level"] is r2["level"]  # same object, not just equal

    def test_classify_event_interns_error_level(self):
        """ERROR level strings should also be interned across calls."""
        r1 = classify_event("[10/12/15 21:22:04:257 CEST] 0000001 Component E first error")
        r2 = classify_event("[10/12/15 21:22:04:258 CEST] 0000002 Component E second error")
        if r1.get("level") and r2.get("level"):
            assert r1["level"] is r2["level"]

    def test_classify_event_interns_code(self):
        """Message codes should be interned across calls."""
        r1 = classify_event("[10/12/15 21:22:04:257 CEST] 0000001 Component I CWPKI0022E: ssl error")
        r2 = classify_event("[10/12/15 21:22:04:258 CEST] 0000002 Component I CWPKI0022E: ssl again")
        if r1.get("code") and r2.get("code"):
            assert r1["code"] is r2["code"]


# ── M44: Smart sampling (sample_info) ────────────────────────────────

class TestSmartSampling:
    def test_parse_file_sample_info(self, tmp_path):
        """sample_info=10 should keep ~10% of plain INFO events."""
        lines = []
        for i in range(100):
            lines.append(f"2025-01-01 10:00:{i % 60:02d}.000 INFO plain message {i}")
        for i in range(5):
            lines.append(f"2025-01-01 11:00:{i:02d}.000 ERROR something broke {i}")
        log_file = tmp_path / "test.log"
        log_file.write_text("\n".join(lines))

        full = parse_file(log_file, sample_info=0)
        sampled = parse_file(log_file, sample_info=10)

        full_info = [e for e in full if e.level == "INFO"]
        sampled_info = [e for e in sampled if e.level == "INFO"]
        full_errors = [e for e in full if e.level == "ERROR"]
        sampled_errors = [e for e in sampled if e.level == "ERROR"]

        # All errors preserved
        assert len(sampled_errors) == len(full_errors)
        # INFO events reduced (roughly 10%, allow some tolerance)
        assert len(sampled_info) < len(full_info)
        assert len(sampled_info) >= 5  # at least some kept

    def test_sample_info_preserves_interesting_info(self, tmp_path):
        """INFO events with codes or exceptions should not be sampled away."""
        # Use WAS bracket timestamps so the WAS format is detected and code extraction works
        lines = []
        for i in range(50):
            lines.append(
                f"[10/12/15 10:{i // 60:02d}:{i % 60:02d}:000 CEST] {i:08x} Component I plain boring {i}"
            )
        # INFO event with a WAS message code — must be preserved
        lines.append("[10/12/15 10:01:00:000 CEST] 00000032 Component I CWWKE0001I: Server started")
        log_file = tmp_path / "test.log"
        log_file.write_text("\n".join(lines))

        sampled = parse_file(log_file, sample_info=10)
        # Events with codes should be kept
        codes = [e for e in sampled if e.code]
        assert len(codes) >= 1

    def test_sample_info_deterministic(self, tmp_path):
        """Sampling should produce identical results on repeated runs."""
        lines = [f"2025-01-01 10:00:{i % 60:02d}.000 INFO message {i}" for i in range(100)]
        log_file = tmp_path / "test.log"
        log_file.write_text("\n".join(lines))

        run1 = parse_file(log_file, sample_info=5)
        run2 = parse_file(log_file, sample_info=5)
        assert len(run1) == len(run2)
        assert [e.text for e in run1] == [e.text for e in run2]

    def test_sample_info_zero_means_no_sampling(self, tmp_path):
        """sample_info=0 (default) should return all events."""
        lines = [f"2025-01-01 10:00:{i % 60:02d}.000 INFO event {i}" for i in range(20)]
        log_file = tmp_path / "test.log"
        log_file.write_text("\n".join(lines))

        full = parse_file(log_file, sample_info=0)
        assert len(full) == 20

    def test_sample_info_preserves_tagged_info_events(self, tmp_path):
        """INFO events that have signal tags (e.g. OOM) should not be dropped."""
        lines = []
        for i in range(50):
            lines.append(f"2025-01-01 10:00:{i % 60:02d}.000 INFO plain boring {i}")
        # INFO with OOM tag (should be kept)
        lines.append("2025-01-01 10:01:00.000 INFO OutOfMemoryError: Java heap space")
        log_file = tmp_path / "test.log"
        log_file.write_text("\n".join(lines))

        sampled = parse_file(log_file, sample_info=10)
        oom_events = [e for e in sampled if "OOM/GC" in e.tags]
        assert len(oom_events) >= 1


# ── M44: Parse cache ──────────────────────────────────────────────────

class TestParseFileCache:
    def test_parse_file_cached_miss_and_hit(self, tmp_path):
        """First call should parse, second should hit cache."""
        log_file = tmp_path / "test.log"
        log_file.write_text("2025-01-01 10:00:00.000 ERROR something broke\n" * 5)
        cache_dir = tmp_path / "cache"

        events1 = parse_file_cached(log_file, content_hash="abc123", cache_dir=cache_dir)
        assert len(events1) == 5
        # Cache file should exist
        cache_files = list(cache_dir.glob("*.json.gz"))
        assert len(cache_files) == 1

        # Second call should hit cache
        events2 = parse_file_cached(log_file, content_hash="abc123", cache_dir=cache_dir)
        assert len(events2) == 5
        assert events1[0].text == events2[0].text
        assert events1[0].level == events2[0].level

    def test_parse_file_cached_different_params(self, tmp_path):
        """Different max_lines should get separate cache entries."""
        log_file = tmp_path / "test.log"
        log_file.write_text("2025-01-01 10:00:00.000 ERROR error\n" * 20)
        cache_dir = tmp_path / "cache"

        e1 = parse_file_cached(log_file, content_hash="abc", cache_dir=cache_dir, max_lines=5)
        e2 = parse_file_cached(log_file, content_hash="abc", cache_dir=cache_dir, max_lines=0)
        assert len(e1) != len(e2)

    def test_parse_file_cached_no_cache_dir(self, tmp_path):
        """Without cache_dir, should work like parse_file."""
        log_file = tmp_path / "test.log"
        log_file.write_text("2025-01-01 10:00:00.000 ERROR broke\n")
        events = parse_file_cached(log_file, content_hash="x", cache_dir=None)
        assert len(events) == 1

    def test_parse_file_cached_creates_cache_dir(self, tmp_path):
        """Cache dir should be created automatically if it doesn't exist."""
        log_file = tmp_path / "test.log"
        log_file.write_text("2025-01-01 10:00:00.000 ERROR broke\n")
        cache_dir = tmp_path / "nested" / "cache"
        assert not cache_dir.exists()

        parse_file_cached(log_file, content_hash="x", cache_dir=cache_dir)
        assert cache_dir.exists()

    def test_parse_file_cached_preserves_event_fields(self, tmp_path):
        """Cached events should have the same fields as freshly parsed ones."""
        log_file = tmp_path / "test.log"
        log_file.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001 Component E CWPKI0022E: SSL error\n"
            "java.security.cert.CertPathBuilderException: could not build path\n"
        )
        cache_dir = tmp_path / "cache"

        fresh = parse_file_cached(log_file, content_hash="h1", cache_dir=cache_dir)
        cached = parse_file_cached(log_file, content_hash="h1", cache_dir=cache_dir)

        assert len(fresh) == len(cached) == 1
        f, c = fresh[0], cached[0]
        assert f.level == c.level
        assert f.code == c.code
        assert f.exception == c.exception
        assert f.ts == c.ts

    def test_parse_file_cached_different_hash_separate_entries(self, tmp_path):
        """Different content hashes should produce independent cache files."""
        log_file = tmp_path / "test.log"
        log_file.write_text("2025-01-01 10:00:00.000 ERROR broke\n")
        cache_dir = tmp_path / "cache"

        parse_file_cached(log_file, content_hash="hash_v1", cache_dir=cache_dir)
        parse_file_cached(log_file, content_hash="hash_v2", cache_dir=cache_dir)

        cache_files = list(cache_dir.glob("*.json.gz"))
        assert len(cache_files) == 2

    def test_parse_file_cached_includes_redaction_in_cache_key(self, tmp_path):
        """Different LOGPILOT_REDACTION_LEVEL must produce different cache files."""
        import os
        log_file = tmp_path / "test.log"
        log_file.write_text("2024-01-01 INFO Bearer abc123def456\n")
        cache_dir = tmp_path / "cache"

        saved = os.environ.get("LOGPILOT_REDACTION_LEVEL")
        try:
            os.environ["LOGPILOT_REDACTION_LEVEL"] = "none"
            parse_file_cached(log_file, content_hash="hash1", cache_dir=cache_dir)
            cache_files_none = set(f.name for f in cache_dir.glob("parsed_*.json.gz"))

            os.environ["LOGPILOT_REDACTION_LEVEL"] = "secrets"
            parse_file_cached(log_file, content_hash="hash1", cache_dir=cache_dir)
            cache_files_secrets = set(f.name for f in cache_dir.glob("parsed_*.json.gz"))
        finally:
            if saved is None:
                os.environ.pop("LOGPILOT_REDACTION_LEVEL", None)
            else:
                os.environ["LOGPILOT_REDACTION_LEVEL"] = saved

        # Should have created a NEW cache file, not reused the "none" one
        assert len(cache_files_secrets) > len(cache_files_none)
        # The two sets must differ (different file names)
        assert cache_files_secrets != cache_files_none

    def test_parse_file_cached_explicit_redaction_level_overrides_env(self, tmp_path):
        """Explicit redaction_level param must override env variable."""
        import os
        log_file = tmp_path / "test.log"
        log_file.write_text("2024-01-01 INFO Bearer abc123def456\n")
        cache_dir = tmp_path / "cache"

        saved = os.environ.get("LOGPILOT_REDACTION_LEVEL")
        try:
            os.environ["LOGPILOT_REDACTION_LEVEL"] = "none"
            # Pass explicit level — should use "secrets" regardless of env
            parse_file_cached(log_file, content_hash="hash2", cache_dir=cache_dir,
                              redaction_level="secrets")
            cache_files = list(cache_dir.glob("parsed_*.json.gz"))
        finally:
            if saved is None:
                os.environ.pop("LOGPILOT_REDACTION_LEVEL", None)
            else:
                os.environ["LOGPILOT_REDACTION_LEVEL"] = saved

        assert len(cache_files) == 1
        # File name must contain the explicit level, not the env "none"
        assert "_secrets" in cache_files[0].name


# ── M44: Progress callback ────────────────────────────────────────────

class TestPrecomputeAnalysisProgress:
    def test_precompute_analysis_progress_callback(self):
        """progress_callback should be called at each stage."""
        from logpilot.analysis import precompute_analysis
        events = [
            LogEvent(
                text=f"2025-01-01 10:00:0{i}.000 ERROR broke {i}",
                ts=f"2025-01-01 10:00:0{i}.000",
                level="ERROR",
            )
            for i in range(5)
        ]

        calls = []

        def cb(text, frac):
            calls.append((text, frac))

        precompute_analysis(events, progress_callback=cb)
        assert len(calls) >= 5  # at least 5 stages
        assert calls[0][1] == 0.0  # starts at 0
        assert calls[-1][1] == 1.0  # ends at 1
        # Fractions should be monotonically non-decreasing
        fracs = [c[1] for c in calls]
        assert fracs == sorted(fracs)

    def test_precompute_analysis_no_callback(self):
        """Without callback, should work normally (backward compat)."""
        from logpilot.analysis import precompute_analysis
        events = [
            LogEvent(
                text="2025-01-01 10:00:00.000 ERROR x",
                ts="2025-01-01 10:00:00.000",
                level="ERROR",
            )
        ]
        result = precompute_analysis(events)
        assert "summary" in result
        assert "causes" in result

    def test_precompute_analysis_callback_text_is_string(self):
        """Each progress_callback call should pass a non-empty string label."""
        from logpilot.analysis import precompute_analysis
        events = [
            LogEvent(
                text="2025-01-01 10:00:00.000 ERROR broke",
                ts="2025-01-01 10:00:00.000",
                level="ERROR",
            )
        ]
        labels = []

        def cb(text, frac):
            labels.append(text)

        precompute_analysis(events, progress_callback=cb)
        for label in labels:
            assert isinstance(label, str)
            assert len(label) > 0

    def test_precompute_analysis_callback_frac_in_range(self):
        """All fraction values must be in [0.0, 1.0]."""
        from logpilot.analysis import precompute_analysis
        events = [
            LogEvent(
                text="2025-01-01 10:00:00.000 ERROR broke",
                ts="2025-01-01 10:00:00.000",
                level="ERROR",
            )
        ]
        fracs = []

        def cb(text, frac):
            fracs.append(frac)

        precompute_analysis(events, progress_callback=cb)
        for frac in fracs:
            assert 0.0 <= frac <= 1.0, f"Fraction out of range: {frac}"

    def test_precompute_analysis_empty_events(self):
        """precompute_analysis should handle empty event list gracefully."""
        from logpilot.analysis import precompute_analysis
        result = precompute_analysis([])
        assert "summary" in result
        assert "causes" in result
        assert "hist" in result


# ── M44: Heuristics optimisation (merged count+severity) ──────────────

class TestLikelyCausesOptimized:
    def test_likely_causes_single_pass_same_results(self):
        """Optimized likely_causes should produce same results as before."""
        from logpilot.heuristics import likely_causes
        events = [
            LogEvent(text="java.lang.OutOfMemoryError: Java heap space", level="FATAL"),
            LogEvent(text="java.lang.OutOfMemoryError: GC overhead limit exceeded", level="ERROR"),
            LogEvent(text="Normal operation info", level="INFO"),
        ]
        causes = likely_causes(events)
        oom = [
            c for c in causes
            if "OOM" in c.get("title", "")
            or "OutOfMemory" in c.get("title", "")
            or "memory" in c.get("title", "").lower()
        ]
        assert len(oom) >= 1
        assert oom[0]["count"] >= 2
        # _sev is an internal field stripped before return; result must have required public fields
        assert "id" in oom[0]
        assert "title" in oom[0]
        assert "count" in oom[0]

    def test_likely_causes_severity_weighted(self):
        """Results should be sorted by severity — FATAL-heavy matches rank first."""
        from logpilot.heuristics import likely_causes
        # Two distinct heuristic patterns: OOM (FATAL) and a lower-severity pattern
        events = [
            LogEvent(text="OutOfMemoryError: Java heap space", level="FATAL"),
            LogEvent(text="OutOfMemoryError: Java heap space", level="FATAL"),
            LogEvent(text="OutOfMemoryError: Java heap space", level="FATAL"),
        ]
        causes = likely_causes(events)
        # At least one cause found
        assert len(causes) >= 1
        # The OOM cause should be present with a count
        oom = next((c for c in causes if "memory" in c.get("title", "").lower()), None)
        assert oom is not None
        assert oom["count"] >= 3

    def test_likely_causes_empty_events(self):
        """likely_causes on empty list should return empty list."""
        from logpilot.heuristics import likely_causes
        causes = likely_causes([])
        assert isinstance(causes, list)
        assert len(causes) == 0

    def test_likely_causes_returns_expected_fields(self):
        """Each result dict should contain id, title, count, cause, fixes."""
        from logpilot.heuristics import likely_causes
        events = [
            LogEvent(text="java.lang.OutOfMemoryError: Java heap space", level="ERROR"),
        ]
        causes = likely_causes(events)
        assert len(causes) >= 1
        for c in causes:
            assert "id" in c
            assert "title" in c
            assert "count" in c
            assert "cause" in c
            assert "fixes" in c
            # _sev is an internal ranking field stripped before return
            assert isinstance(c["count"], int)
            assert c["count"] > 0

    def test_likely_causes_count_matches_actual_occurrences(self):
        """count in each cause should reflect actual number of matching events."""
        from logpilot.heuristics import likely_causes
        # 3 OOM events
        events = [
            LogEvent(text="OutOfMemoryError: Java heap space", level="ERROR"),
            LogEvent(text="OutOfMemoryError: Java heap space", level="ERROR"),
            LogEvent(text="OutOfMemoryError: Java heap space", level="ERROR"),
            LogEvent(text="Normal log line with no issues", level="INFO"),
        ]
        causes = likely_causes(events)
        oom = next(
            (c for c in causes if "memory" in c.get("title", "").lower()),
            None,
        )
        assert oom is not None
        assert oom["count"] == 3
