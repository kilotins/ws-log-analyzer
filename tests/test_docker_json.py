"""Tests for Docker JSON log driver format plugin."""
from __future__ import annotations

from pathlib import Path

import pytest

from logpilot.formats.docker_json import DockerJSONFormat, _parse_docker_json
from logpilot.parser import parse_file
from logpilot.formats import detect_format

FIXTURE = Path(__file__).parent / "fixtures" / "docker-json-sample.log"
FMT = DockerJSONFormat()


class TestDetection:
    def test_detect_docker_json(self):
        lines = FIXTURE.read_text().splitlines()[:20]
        score = FMT.detect(lines)
        assert score > 0.5

    def test_not_detect_plain_json(self):
        lines = ['{"level":"info","message":"test","timestamp":"2026-03-23T10:00:00Z"}']
        assert FMT.detect(lines) == 0.0

    def test_not_detect_nginx(self):
        lines = ['10.0.0.1 - - [23/Mar/2026:10:00:00 +0100] "GET / HTTP/1.1" 200 612']
        assert FMT.detect(lines) == 0.0

    def test_auto_detect_fixture(self):
        fmt = detect_format(FIXTURE)
        assert fmt.name == "docker_json"

    def test_detect_empty(self):
        assert FMT.detect([]) == 0.0


class TestTimestamp:
    def test_extract_ts(self):
        line = '{"log":"test\\n","stream":"stdout","time":"2026-03-23T10:30:00.000000001Z"}'
        assert FMT.extract_ts(line) == "2026-03-23T10:30:00.000000001Z"

    def test_extract_ts_none_for_non_json(self):
        assert FMT.extract_ts("  at com.example.Foo.bar()") is None


class TestLevel:
    def test_level_from_log_message(self):
        line = '{"log":"2026-03-23 10:30:00 ERROR Something failed\\n","stream":"stderr","time":"2026-03-23T10:30:00Z"}'
        assert FMT.extract_level(line) == "ERROR"

    def test_level_info_from_message(self):
        line = '{"log":"2026-03-23 10:30:00 INFO Starting\\n","stream":"stdout","time":"2026-03-23T10:30:00Z"}'
        assert FMT.extract_level(line) == "INFO"

    def test_level_from_stderr_fallback(self):
        line = '{"log":"some message without level keyword\\n","stream":"stderr","time":"2026-03-23T10:30:00Z"}'
        assert FMT.extract_level(line) == "WARNING"

    def test_level_from_stdout_fallback(self):
        line = '{"log":"some message\\n","stream":"stdout","time":"2026-03-23T10:30:00Z"}'
        assert FMT.extract_level(line) == "INFO"

    def test_level_fatal(self):
        line = '{"log":"FATAL OutOfMemoryError\\n","stream":"stderr","time":"2026-03-23T10:30:00Z"}'
        assert FMT.extract_level(line) == "FATAL"


class TestContinuation:
    def test_new_json_event_not_continuation(self):
        line = '{"log":"2026-03-23 10:30:00 ERROR fail\\n","stream":"stderr","time":"2026-03-23T10:30:00Z"}'
        assert FMT.is_continuation(line) is False

    def test_stacktrace_in_json_is_continuation(self):
        line = '{"log":"\\tat com.example.Foo.bar(Foo.java:42)\\n","stream":"stderr","time":"2026-03-23T10:30:00Z"}'
        assert FMT.is_continuation(line) is True

    def test_caused_by_in_json_is_continuation(self):
        line = '{"log":"Caused by: java.io.IOException: fail\\n","stream":"stderr","time":"2026-03-23T10:30:00Z"}'
        assert FMT.is_continuation(line) is True

    def test_empty_not_continuation(self):
        assert FMT.is_continuation("") is False


class TestClassify:
    def test_classify_error(self):
        text = '{"log":"2026-03-23 10:35:00 ERROR Connection pool exhausted\\n","stream":"stderr","time":"2026-03-23T10:35:00Z"}'
        result = FMT.classify_event(text)
        assert result["level"] == "ERROR"
        assert "DB/Pool" in result["tags"]

    def test_classify_with_stacktrace(self):
        text = (
            '{"log":"2026-03-23 10:35:00 ERROR Pool exhausted\\n","stream":"stderr","time":"2026-03-23T10:35:00Z"}\n'
            '{"log":"  java.sql.SQLTransientConnectionException: timeout\\n","stream":"stderr","time":"2026-03-23T10:35:00Z"}\n'
            '{"log":"Caused by: java.util.NoSuchElementException: Timeout\\n","stream":"stderr","time":"2026-03-23T10:35:00Z"}'
        )
        result = FMT.classify_event(text)
        assert result["exception"] == "java.sql.SQLTransientConnectionException"
        assert result["root_cause"] == "java.util.NoSuchElementException"

    def test_classify_oom(self):
        text = '{"log":"FATAL java.lang.OutOfMemoryError: Java heap space\\n","stream":"stderr","time":"2026-03-23T10:35:05Z"}'
        result = FMT.classify_event(text)
        assert "OOM/GC" in result["tags"]

    def test_classify_network(self):
        text = '{"log":"ERROR ECONNREFUSED: connection refused to 10.0.3.5\\n","stream":"stderr","time":"2026-03-23T10:35:01Z"}'
        result = FMT.classify_event(text)
        assert "Network" in result["tags"]

    def test_classify_ssl(self):
        text = '{"log":"ERROR SSLHandshakeException: PKIX path building failed\\n","stream":"stderr","time":"2026-03-23T10:35:03Z"}'
        result = FMT.classify_event(text)
        assert "SSL/TLS" in result["tags"]


class TestSignalTags:
    def test_no_tags(self):
        tags = FMT.bucket_tags("INFO Starting application")
        assert len(tags) == 0

    def test_oom_tag(self):
        tags = FMT.bucket_tags("OutOfMemoryError: Java heap space")
        assert "OOM/GC" in tags

    def test_network_tag(self):
        tags = FMT.bucket_tags("ECONNREFUSED connection refused")
        assert "Network" in tags


class TestParsing:
    def test_parse_fixture(self):
        events = parse_file(FIXTURE)
        assert len(events) > 0

    def test_event_count(self):
        events = parse_file(FIXTURE)
        assert len(events) >= 10

    def test_error_events(self):
        events = parse_file(FIXTURE)
        errors = [e for e in events if e.level in ("ERROR", "FATAL")]
        assert len(errors) >= 4

    def test_multiline_stacktrace(self):
        events = parse_file(FIXTURE)
        pool_events = [e for e in events if "pool" in (e.text or "").lower() and "exhaust" in (e.text or "").lower()]
        assert len(pool_events) >= 1
        evt = pool_events[0]
        assert "Caused by" in evt.text

    def test_signal_tags_present(self):
        events = parse_file(FIXTURE)
        all_tags = set()
        for e in events:
            all_tags.update(e.tags or [])
        assert "OOM/GC" in all_tags
        assert "DB/Pool" in all_tags
        assert "Network" in all_tags
