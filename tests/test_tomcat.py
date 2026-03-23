"""Tests for Apache Tomcat / Catalina format plugin."""
from __future__ import annotations

from pathlib import Path

import pytest

from logpilot.formats.tomcat import TomcatFormat, TOMCAT_RE
from logpilot.parser import parse_file
from logpilot.formats import detect_format

FIXTURE = Path(__file__).parent / "fixtures" / "tomcat-sample.log"
FMT = TomcatFormat()


class TestDetection:
    def test_detect_tomcat_log(self):
        lines = FIXTURE.read_text().splitlines()[:50]
        score = FMT.detect(lines)
        assert score > 0.5

    def test_bonus_for_catalina_logger(self):
        lines = [
            "22-Mar-2026 08:30:00.000 INFO [main] org.apache.catalina.startup.Catalina.start Server startup",
            "22-Mar-2026 08:30:01.000 INFO [main] com.example.MyApp.init Starting",
        ]
        score = FMT.detect(lines)
        # First line gets 3+1=4 (catalina bonus), second gets 3
        assert score > 0.5

    def test_not_detect_log4j(self):
        lines = [
            "2026-03-22 08:30:00.000 INFO  [main] com.example.App - Starting",
            "2026-03-22 08:30:01.000 ERROR [main] com.example.App - Failed",
        ]
        assert FMT.detect(lines) == 0.0

    def test_not_detect_nginx(self):
        lines = ['10.0.0.1 - - [22/Mar/2026:08:30:00 +0100] "GET / HTTP/1.1" 200 612']
        assert FMT.detect(lines) == 0.0

    def test_auto_detect_fixture(self):
        fmt = detect_format(FIXTURE)
        assert fmt.name == "tomcat"

    def test_detect_empty(self):
        assert FMT.detect([]) == 0.0


class TestTimestamp:
    def test_extract_ts(self):
        line = "22-Mar-2026 08:30:00.000 INFO [main] org.apache.catalina.startup.Catalina.start Startup"
        assert FMT.extract_ts(line) == "22-Mar-2026 08:30:00.000"

    def test_extract_ts_single_digit_day(self):
        line = "1-Jan-2026 09:00:00.000 INFO [main] org.example.App.init Starting"
        assert FMT.extract_ts(line) == "1-Jan-2026 09:00:00.000"

    def test_extract_ts_none_for_continuation(self):
        assert FMT.extract_ts("  at com.example.Foo.bar(Foo.java:42)") is None


class TestLevel:
    @pytest.mark.parametrize("level_str,expected", [
        ("SEVERE", "ERROR"),
        ("WARNING", "WARNING"),
        ("INFO", "INFO"),
        ("CONFIG", "INFO"),
        ("FINE", "DEBUG"),
        ("FINER", "DEBUG"),
        ("FINEST", "DEBUG"),
    ])
    def test_level_mapping(self, level_str, expected):
        line = f"22-Mar-2026 08:30:00.000 {level_str} [main] org.example.App.test Message"
        assert FMT.extract_level(line) == expected

    def test_level_none_for_continuation(self):
        assert FMT.extract_level("  at com.example.Foo.bar(Foo.java:42)") is None


class TestContinuation:
    def test_new_event_not_continuation(self):
        line = "22-Mar-2026 08:30:00.000 INFO [main] org.example.App.init Starting"
        assert FMT.is_continuation(line) is False

    def test_stacktrace_is_continuation(self):
        assert FMT.is_continuation("\tat com.example.Foo.bar(Foo.java:42)") is True

    def test_caused_by_is_continuation(self):
        assert FMT.is_continuation("Caused by: java.io.IOException: Connection refused") is True

    def test_indented_text_is_continuation(self):
        assert FMT.is_continuation("  Pool exhausted: timeout waiting") is True

    def test_empty_not_continuation(self):
        assert FMT.is_continuation("") is False


class TestClassify:
    def test_classify_severe(self):
        text = "22-Mar-2026 08:35:01.000 SEVERE [http-nio-8080-exec-5] org.apache.catalina.connector.CoyoteAdapter.service Exception"
        result = FMT.classify_event(text)
        assert result["level"] == "ERROR"
        assert result["thread_id"] == "http-nio-8080-exec-5"

    def test_classify_with_stacktrace(self):
        text = (
            "22-Mar-2026 08:35:02.000 SEVERE [exec-6] org.apache.tomcat.jdbc.pool.ConnectionPool.getConnection Pool exhausted\n"
            "  java.sql.SQLException: Cannot get a connection\n"
            "\tat org.apache.tomcat.jdbc.pool.ConnectionPool.borrowConnection(ConnectionPool.java:672)\n"
            "Caused by: java.util.NoSuchElementException: Timeout waiting for idle object\n"
            "\tat org.apache.tomcat.dbcp.pool2.impl.GenericObjectPool.borrowObject(GenericObjectPool.java:449)"
        )
        result = FMT.classify_event(text)
        assert result["exception"] == "java.sql.SQLException"
        assert result["root_cause"] == "java.util.NoSuchElementException"
        assert "DB/Pool" in result["tags"]

    def test_classify_oom(self):
        text = "22-Mar-2026 08:35:01.000 SEVERE [exec-5] CoyoteAdapter.service Exception\n  java.lang.OutOfMemoryError: Java heap space"
        result = FMT.classify_event(text)
        assert "OOM/GC" in result["tags"]

    def test_classify_ssl(self):
        text = "22-Mar-2026 08:35:05.000 SEVERE [exec-8] StandardWrapperValve.invoke Servlet threw exception\n  javax.net.ssl.SSLHandshakeException: PKIX path building failed"
        result = FMT.classify_event(text)
        assert "SSL/TLS" in result["tags"]

    def test_classify_stuck_thread(self):
        text = "22-Mar-2026 08:35:00.000 WARNING [exec-5] org.apache.catalina.valves.StuckThreadDetectionValve.notifyStuckThreadDetected Thread stuck"
        result = FMT.classify_event(text)
        assert "Valve" in result["tags"]

    def test_classify_deploy(self):
        text = "22-Mar-2026 08:30:02.000 INFO [main] org.apache.catalina.startup.HostConfig.deployWAR Deploying web application"
        result = FMT.classify_event(text)
        assert "Deploy" in result["tags"]

    def test_classify_session(self):
        text = "22-Mar-2026 08:35:10.000 WARNING [exec-3] StandardManager.unload Exception while saving Session\n  java.io.NotSerializableException: com.example.ShoppingCart"
        result = FMT.classify_event(text)
        assert "Session" in result["tags"]


class TestSignalTags:
    def test_db_pool_tag(self):
        tags = FMT.bucket_tags("connection pool exhausted, getConnection timeout")
        assert "DB/Pool" in tags

    def test_ssl_tag(self):
        tags = FMT.bucket_tags("SSLHandshakeException: PKIX path building failed")
        assert "SSL/TLS" in tags

    def test_deploy_tag(self):
        tags = FMT.bucket_tags("Deploying web application archive")
        assert "Deploy" in tags

    def test_no_tags(self):
        tags = FMT.bucket_tags("GET /api/users/123 completed (12ms)")
        assert len(tags) == 0


class TestParsing:
    def test_parse_fixture(self):
        events = parse_file(FIXTURE)
        assert len(events) > 0

    def test_event_count(self):
        events = parse_file(FIXTURE)
        assert len(events) >= 15

    def test_error_events(self):
        events = parse_file(FIXTURE)
        errors = [e for e in events if e.level == "ERROR"]
        assert len(errors) >= 4

    def test_multiline_stacktrace(self):
        events = parse_file(FIXTURE)
        pool_events = [e for e in events if "Pool exhausted" in (e.text or "")]
        assert len(pool_events) >= 1
        evt = pool_events[0]
        assert "Caused by" in evt.text
        assert evt.exception == "java.sql.SQLException"
        assert evt.root_cause == "java.util.NoSuchElementException"

    def test_signal_tags_present(self):
        events = parse_file(FIXTURE)
        all_tags = set()
        for e in events:
            all_tags.update(e.tags or [])
        assert "OOM/GC" in all_tags
        assert "DB/Pool" in all_tags
        assert "SSL/TLS" in all_tags
        assert "Deploy" in all_tags

    def test_warning_events(self):
        events = parse_file(FIXTURE)
        warns = [e for e in events if e.level == "WARNING"]
        assert len(warns) >= 3

    def test_thread_ids_extracted(self):
        events = parse_file(FIXTURE)
        threads = {e.thread_id for e in events if e.thread_id}
        assert "main" in threads
        assert any("http-nio" in t for t in threads)
