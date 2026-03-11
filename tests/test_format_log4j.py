"""Tests for the Log4j / Logback log format plugin."""
import pytest

from logpilot.formats.log4j import Log4jFormat


@pytest.fixture
def fmt():
    return Log4jFormat()


# ── Detection ──────────────────────────────────────────────────────────

class TestDetect:
    def test_log4j2_standard_scores_high(self, fmt):
        lines = [
            "2025-03-11 10:15:33,123 ERROR [main] com.example.App - Connection failed",
            "2025-03-11 10:15:34,456 INFO  [main] com.example.App - Retrying...",
            "2025-03-11 10:15:35,789 WARN  [pool-1] com.example.Pool - Slow query",
        ]
        assert fmt.detect(lines) > 0.5

    def test_logback_default_scores_high(self, fmt):
        lines = [
            "2025-03-11 10:15:33.123 INFO  [main] c.e.app.MyService - Starting",
            "2025-03-11 10:15:34.456 ERROR [worker-1] c.e.app.Handler - Failed",
        ]
        assert fmt.detect(lines) > 0.5

    def test_spring_boot_scores_high(self, fmt):
        lines = [
            "2025-03-11 10:15:33.123  INFO 12345 --- [main] c.e.app.MyApplication : Starting",
            "2025-03-11 10:15:34.456  ERROR 12345 --- [nio-8080-exec-1] c.e.controller.UserCtrl : Failed",
            "2025-03-11 10:15:35.789  WARN  12345 --- [scheduling-1] c.e.service.DataSync : Timeout",
        ]
        score = fmt.detect(lines)
        assert score > 0.7

    def test_logback_time_only_scores_high(self, fmt):
        lines = [
            "10:15:33.123 INFO  c.e.xp.core.Service - Starting export",
            "10:15:34.456 WARN  c.e.xp.core.Service - Slow operation",
            "10:15:35.789 ERROR c.e.xp.core.Service - Export failed",
        ]
        assert fmt.detect(lines) > 0.5

    def test_was_format_scores_low(self, fmt):
        lines = [
            "[3/5/25 12:00:00:000 UTC] 0000001a Component I SRVE0242I: Starting",
            "[3/5/25 12:00:01:000 UTC] 0000001a Component E CWWKE0701E: Error",
        ]
        assert fmt.detect(lines) < 0.2

    def test_json_format_scores_low(self, fmt):
        lines = [
            '{"timestamp":"2025-03-05T12:00:00Z","level":"info","msg":"started"}',
            '{"timestamp":"2025-03-05T12:00:01Z","level":"error","msg":"failed"}',
        ]
        assert fmt.detect(lines) < 0.2

    def test_empty_scores_zero(self, fmt):
        assert fmt.detect([]) == 0.0


# ── Timestamp Extraction ──────────────────────────────────────────────

class TestExtractTs:
    def test_iso_with_comma_millis(self, fmt):
        line = "2025-03-11 10:15:33,123 ERROR [main] com.example.App - Failed"
        assert fmt.extract_ts(line) == "2025-03-11 10:15:33,123"

    def test_iso_with_dot_millis(self, fmt):
        line = "2025-03-11 10:15:33.123 INFO [main] c.e.app.Service - OK"
        assert fmt.extract_ts(line) == "2025-03-11 10:15:33.123"

    def test_iso_with_t_separator(self, fmt):
        line = "2025-03-11T10:15:33.123 ERROR [main] com.example.App - Error"
        assert fmt.extract_ts(line) == "2025-03-11T10:15:33.123"

    def test_time_only(self, fmt):
        line = "10:15:33.123 INFO  c.e.xp.core.Service - Starting"
        assert fmt.extract_ts(line) == "10:15:33.123"

    def test_no_timestamp(self, fmt):
        line = "\tat com.example.App.run(App.java:42)"
        assert fmt.extract_ts(line) is None

    def test_spring_boot_timestamp(self, fmt):
        line = "2025-03-11 10:15:33.123  INFO 12345 --- [main] c.e.App : Starting"
        assert fmt.extract_ts(line) == "2025-03-11 10:15:33.123"


# ── Level Extraction ──────────────────────────────────────────────────

class TestExtractLevel:
    @pytest.mark.parametrize("level", ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"])
    def test_all_standard_levels(self, fmt, level):
        line = f"2025-03-11 10:15:33.123 {level} [main] com.example.App - message"
        assert fmt.extract_level(line) == level

    def test_no_level(self, fmt):
        line = "\tat com.example.App.run(App.java:42)"
        assert fmt.extract_level(line) is None

    def test_spring_boot_level(self, fmt):
        line = "2025-03-11 10:15:33.123  ERROR 12345 --- [main] c.e.App : Failed"
        assert fmt.extract_level(line) == "ERROR"

    def test_logback_short_level(self, fmt):
        line = "10:15:33.123 WARN  c.e.xp.core.Service - Slow"
        assert fmt.extract_level(line) == "WARN"


# ── Continuation Detection ────────────────────────────────────────────

class TestIsContinuation:
    def test_stacktrace_line(self, fmt):
        assert fmt.is_continuation("\tat com.example.App.run(App.java:42)")

    def test_caused_by(self, fmt):
        assert fmt.is_continuation("Caused by: java.sql.SQLException: Connection refused")

    def test_plain_continuation(self, fmt):
        # No timestamp = continuation
        assert fmt.is_continuation("    some continued message text")

    def test_new_event_not_continuation(self, fmt):
        assert not fmt.is_continuation(
            "2025-03-11 10:15:33.123 ERROR [main] com.example.App - New event"
        )

    def test_spring_boot_new_event(self, fmt):
        assert not fmt.is_continuation(
            "2025-03-11 10:15:33.123  INFO 12345 --- [main] c.e.App : New"
        )

    def test_logback_short_new_event(self, fmt):
        assert not fmt.is_continuation(
            "10:15:33.123 INFO  c.e.xp.core.Service - New event"
        )


# ── Event Classification ──────────────────────────────────────────────

class TestClassifyEvent:
    def test_basic_log4j_event(self, fmt):
        text = "2025-03-11 10:15:33,123 ERROR [main] com.example.App - Connection failed"
        result = fmt.classify_event(text)
        assert result["level"] == "ERROR"
        assert result["thread_id"] == "main"
        assert result["code"] is None
        assert result["logger"] == "com.example.App"

    def test_spring_boot_event(self, fmt):
        text = "2025-03-11 10:15:33.123  ERROR 12345 --- [nio-8080-exec-1] c.e.controller.UserCtrl : Failed to fetch user"
        result = fmt.classify_event(text)
        assert result["level"] == "ERROR"
        assert result["thread_id"] == "nio-8080-exec-1"

    def test_event_with_exception(self, fmt):
        text = (
            "2025-03-11 10:15:33.123 ERROR [main] com.example.App - Failed\n"
            "java.lang.NullPointerException: value is null\n"
            "\tat com.example.App.process(App.java:42)\n"
            "\tat com.example.App.main(App.java:10)"
        )
        result = fmt.classify_event(text)
        assert result["level"] == "ERROR"
        assert result["exception"] == "java.lang.NullPointerException"
        assert result["root_cause"] is None  # No Caused by

    def test_event_with_caused_by(self, fmt):
        text = (
            "2025-03-11 10:15:33.123 ERROR [main] com.example.App - DB error\n"
            "org.springframework.jdbc.CannotCreateTransactionException: Could not open connection\n"
            "\tat org.springframework.jdbc.Transaction.begin(Transaction.java:50)\n"
            "Caused by: java.sql.SQLException: Connection refused\n"
            "\tat com.mysql.jdbc.Driver.connect(Driver.java:100)\n"
            "Caused by: java.net.ConnectException: Connection refused\n"
            "\tat java.net.Socket.connect(Socket.java:200)"
        )
        result = fmt.classify_event(text)
        assert result["exception"] == "org.springframework.jdbc.CannotCreateTransactionException"
        assert result["root_cause"] == "java.net.ConnectException"

    def test_event_no_logger(self, fmt):
        text = "2025-03-11 10:15:33.123 INFO [main] - Simple message"
        result = fmt.classify_event(text)
        assert result["level"] == "INFO"
        assert "logger" not in result or result.get("logger") is None


# ── Bucket Tags ───────────────────────────────────────────────────────

class TestBucketTags:
    def test_oom_tag(self, fmt):
        text = "java.lang.OutOfMemoryError: Java heap space"
        assert "OOM/GC" in fmt.bucket_tags(text)

    def test_gc_overhead_tag(self, fmt):
        text = "java.lang.OutOfMemoryError: GC overhead limit exceeded"
        assert "OOM/GC" in fmt.bucket_tags(text)

    def test_ssl_tag(self, fmt):
        text = "javax.net.ssl.SSLHandshakeException: PKIX path building failed"
        tags = fmt.bucket_tags(text)
        assert "SSL/TLS" in tags

    def test_db_pool_hikari(self, fmt):
        text = "HikariPool-1 - Connection is not available, request timed out after 30000ms."
        tags = fmt.bucket_tags(text)
        assert "DB/Pool" in tags

    def test_db_pool_datasource(self, fmt):
        text = "Failed to configure DataSource: 'url' attribute is not specified"
        tags = fmt.bucket_tags(text)
        assert "DB/Pool" in tags

    def test_spring_bean_creation(self, fmt):
        text = "org.springframework.beans.factory.BeanCreationException: Error creating bean"
        tags = fmt.bucket_tags(text)
        assert "Spring" in tags

    def test_spring_app_failed(self, fmt):
        text = "APPLICATION FAILED TO START"
        tags = fmt.bucket_tags(text)
        assert "Spring" in tags

    def test_spring_circular_dependency(self, fmt):
        text = "CircularDependency detected between beans"
        tags = fmt.bucket_tags(text)
        assert "Spring" in tags

    def test_kafka_tag(self, fmt):
        text = "CommitFailedException: Commit cannot be completed since the group has already rebalanced"
        tags = fmt.bucket_tags(text)
        assert "Kafka" in tags

    def test_no_tags(self, fmt):
        text = "2025-03-11 10:15:33.123 INFO [main] com.example.App - Started successfully"
        tags = fmt.bucket_tags(text)
        assert len(tags) == 0

    def test_multiple_tags(self, fmt):
        text = (
            "HikariPool-1 - Connection is not available\n"
            "java.lang.OutOfMemoryError: Java heap space"
        )
        tags = fmt.bucket_tags(text)
        assert "DB/Pool" in tags
        assert "OOM/GC" in tags


# ── Integration: Registry ─────────────────────────────────────────────

class TestRegistry:
    def test_log4j_in_registry(self):
        from logpilot.formats import list_formats, get_format
        names = [f["name"] for f in list_formats()]
        assert "log4j" in names
        fmt = get_format("log4j")
        assert fmt.name == "log4j"

    def test_detect_spring_boot_log(self):
        from logpilot.formats import detect_format
        lines = [
            "2025-03-11 10:15:33.123  INFO 12345 --- [main] c.e.app.MyApplication : Starting",
            "2025-03-11 10:15:34.456  INFO 12345 --- [main] c.e.app.MyApplication : Started in 4.5s",
            "2025-03-11 10:15:35.789  ERROR 12345 --- [nio-8080-exec-1] c.e.ctrl.Api : Request failed",
        ]
        fmt = detect_format(lines)
        assert fmt.name == "log4j"

    def test_detect_log4j2_log(self):
        from logpilot.formats import detect_format
        lines = [
            "2025-03-11 10:15:33,123 ERROR [main] com.example.App - Connection failed",
            "2025-03-11 10:15:34,456 INFO  [main] com.example.App - Retrying",
            "2025-03-11 10:15:35,789 WARN  [pool-1] com.example.Pool - Timeout",
        ]
        fmt = detect_format(lines)
        assert fmt.name == "log4j"
