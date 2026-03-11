"""Tests for the JSON structured log format plugin."""
import json
import pytest

from logpilot.formats.json_log import JSONFormat


@pytest.fixture
def fmt():
    return JSONFormat()


# ── Detection ──────────────────────────────────────────────────────────

class TestDetect:
    def test_all_json_lines_score_high(self, fmt):
        lines = [
            '{"timestamp":"2025-03-05T12:00:00Z","level":"info","msg":"started"}',
            '{"timestamp":"2025-03-05T12:00:01Z","level":"error","msg":"failed"}',
            '{"timestamp":"2025-03-05T12:00:02Z","level":"warn","msg":"slow query"}',
        ]
        assert fmt.detect(lines) > 0.5

    def test_plain_text_scores_low(self, fmt):
        lines = [
            "[3/5/25 12:00:00:000 UTC] 0000001 Component I some message",
            "[3/5/25 12:00:01:000 UTC] 0000002 Component E error",
        ]
        assert fmt.detect(lines) < 0.1

    def test_empty_scores_zero(self, fmt):
        assert fmt.detect([]) == 0.0

    def test_mixed_content_moderate_score(self, fmt):
        lines = [
            '{"timestamp":"2025-03-05T12:00:00Z","level":"info","msg":"ok"}',
            "this is plain text",
            '{"timestamp":"2025-03-05T12:00:02Z","level":"error","msg":"fail"}',
            "more plain text",
        ]
        score = fmt.detect(lines)
        assert 0.1 < score < 0.9

    def test_json_without_log_fields_moderate(self, fmt):
        lines = [
            '{"foo": "bar"}',
            '{"baz": 42}',
        ]
        score = fmt.detect(lines)
        # Valid JSON but no log-like fields → lower score
        assert score <= 0.5

    def test_docker_json_detected(self, fmt):
        lines = [
            '{"log":"2025-03-05 INFO starting\\n","stream":"stdout","time":"2025-03-05T12:00:00.123Z"}',
            '{"log":"2025-03-05 ERROR failed\\n","stream":"stderr","time":"2025-03-05T12:00:01.456Z"}',
        ]
        assert fmt.detect(lines) > 0.5


# ── Timestamp Extraction ───────────────────────────────────────────────

class TestExtractTs:
    @pytest.mark.parametrize("field", ["timestamp", "time", "ts", "@timestamp", "datetime", "date", "t"])
    def test_various_ts_fields(self, fmt, field):
        line = json.dumps({field: "2025-03-05T12:00:00Z", "msg": "hello"})
        assert fmt.extract_ts(line) == "2025-03-05T12:00:00Z"

    def test_numeric_timestamp(self, fmt):
        line = json.dumps({"ts": 1709640000.123, "msg": "hello"})
        assert fmt.extract_ts(line) == "1709640000.123"

    def test_no_ts_field(self, fmt):
        line = json.dumps({"msg": "hello"})
        assert fmt.extract_ts(line) is None

    def test_non_json_returns_none(self, fmt):
        assert fmt.extract_ts("plain text line") is None

    def test_broken_json_returns_none(self, fmt):
        assert fmt.extract_ts('{"broken json') is None

    def test_docker_wrapper_ts(self, fmt):
        line = json.dumps({"log": "hello\n", "stream": "stdout", "time": "2025-03-05T12:00:00Z"})
        assert fmt.extract_ts(line) == "2025-03-05T12:00:00Z"


# ── Level Extraction ──────────────────────────────────────────────────

class TestExtractLevel:
    @pytest.mark.parametrize("level_str,expected", [
        ("info", "INFO"), ("INFO", "INFO"),
        ("error", "ERROR"), ("ERROR", "ERROR"),
        ("warn", "WARN"), ("warning", "WARN"), ("WARNING", "WARN"),
        ("debug", "DEBUG"), ("DEBUG", "DEBUG"),
        ("fatal", "FATAL"), ("FATAL", "FATAL"),
        ("trace", "TRACE"), ("TRACE", "TRACE"),
        ("critical", "CRITICAL"),
    ])
    def test_string_levels(self, fmt, level_str, expected):
        line = json.dumps({"level": level_str, "msg": "test"})
        assert fmt.extract_level(line) == expected

    @pytest.mark.parametrize("num,expected", [
        (10, "TRACE"), (20, "DEBUG"), (30, "INFO"),
        (40, "WARN"), (50, "ERROR"), (60, "FATAL"),
    ])
    def test_bunyan_numeric_levels(self, fmt, num, expected):
        line = json.dumps({"level": num, "msg": "test"})
        assert fmt.extract_level(line) == expected

    def test_syslog_priority(self, fmt):
        line = json.dumps({"priority": 3, "msg": "test"})
        assert fmt.extract_level(line) == "ERROR"

    @pytest.mark.parametrize("field", ["level", "severity", "lvl", "loglevel", "log_level"])
    def test_various_level_fields(self, fmt, field):
        line = json.dumps({field: "error", "msg": "test"})
        assert fmt.extract_level(line) == "ERROR"

    def test_non_json_fallback(self, fmt):
        assert fmt.extract_level("2025-03-05 ERROR something failed") == "ERROR"

    def test_no_level_returns_none(self, fmt):
        line = json.dumps({"msg": "no level here"})
        assert fmt.extract_level(line) is None


# ── Continuation ───────────────────────────────────────────────────────

class TestIsContinuation:
    def test_json_line_not_continuation(self, fmt):
        line = json.dumps({"level": "error", "msg": "test"})
        assert fmt.is_continuation(line) is False

    def test_stack_line_is_continuation(self, fmt):
        assert fmt.is_continuation("    at com.example.Foo.bar(Foo.java:42)") is True

    def test_caused_by_is_continuation(self, fmt):
        assert fmt.is_continuation("Caused by: java.io.IOException: failed") is True

    def test_plain_text_not_continuation(self, fmt):
        assert fmt.is_continuation("some random text") is False


# ── Classification ─────────────────────────────────────────────────────

class TestClassifyEvent:
    def test_basic_json_event(self, fmt):
        line = json.dumps({
            "timestamp": "2025-03-05T12:00:00Z",
            "level": "error",
            "msg": "Connection refused",
            "thread": "main",
        })
        result = fmt.classify_event(line)
        assert result["level"] == "ERROR"
        assert result["thread_id"] == "main"

    def test_exception_in_error_field(self, fmt):
        line = json.dumps({
            "level": "error",
            "msg": "request failed",
            "error": "java.lang.NullPointerException: value is null",
        })
        result = fmt.classify_event(line)
        assert result["exception"] == "java.lang.NullPointerException"

    def test_stacktrace_field(self, fmt):
        line = json.dumps({
            "level": "error",
            "msg": "unhandled",
            "stacktrace": "java.lang.RuntimeException: boom\n\tat com.example.Foo.bar(Foo.java:42)",
        })
        result = fmt.classify_event(line)
        assert result["exception"] == "java.lang.RuntimeException"

    def test_root_cause_extraction(self, fmt):
        stack = (
            "java.lang.RuntimeException: outer\n"
            "\tat com.example.A.m(A.java:1)\n"
            "Caused by: java.sql.SQLException: connection lost\n"
            "\tat com.example.B.n(B.java:2)"
        )
        line = json.dumps({"level": "error", "msg": "failed", "stack_trace": stack})
        result = fmt.classify_event(line)
        assert result["root_cause"] == "java.sql.SQLException"

    def test_exception_in_message(self, fmt):
        line = json.dumps({
            "level": "error",
            "message": "Caught java.io.FileNotFoundException: /tmp/missing.txt",
        })
        result = fmt.classify_event(line)
        assert result["exception"] == "java.io.FileNotFoundException"

    def test_oom_tag(self, fmt):
        line = json.dumps({"level": "fatal", "msg": "java.lang.OutOfMemoryError: Java heap space"})
        result = fmt.classify_event(line)
        assert "OOM/GC" in result["tags"]

    def test_ssl_tag(self, fmt):
        line = json.dumps({"level": "error", "msg": "SSLHandshakeException: handshake_failure"})
        result = fmt.classify_event(line)
        assert "SSL/TLS" in result["tags"]

    def test_connection_tag(self, fmt):
        line = json.dumps({"level": "error", "msg": "connection pool exhausted"})
        result = fmt.classify_event(line)
        assert "DB/Pool" in result["tags"]

    def test_http_error_tag(self, fmt):
        line = json.dumps({"level": "error", "msg": "request returned 503"})
        result = fmt.classify_event(line)
        assert "HTTP" in result["tags"]

    def test_no_tags(self, fmt):
        line = json.dumps({"level": "info", "msg": "startup complete"})
        result = fmt.classify_event(line)
        assert result["tags"] == []

    def test_non_json_fallback(self, fmt):
        result = fmt.classify_event("2025-03-05 ERROR java.lang.RuntimeException: boom")
        assert result["level"] == "ERROR"
        assert result["exception"] == "java.lang.RuntimeException"

    def test_thread_name_field(self, fmt):
        line = json.dumps({"level": "info", "msg": "ok", "threadName": "http-nio-8080-exec-1"})
        result = fmt.classify_event(line)
        assert result["thread_id"] == "http-nio-8080-exec-1"

    def test_returns_all_required_keys(self, fmt):
        line = json.dumps({"level": "info", "msg": "test"})
        result = fmt.classify_event(line)
        for key in ("level", "thread_id", "code", "exception", "root_cause", "tags"):
            assert key in result


# ── Docker/K8s JSON Wrapper ────────────────────────────────────────────

class TestDockerK8s:
    def test_docker_plain_text_log(self, fmt):
        line = json.dumps({
            "log": "2025-03-05 ERROR something failed\n",
            "stream": "stderr",
            "time": "2025-03-05T12:00:00.123Z",
        })
        result = fmt.classify_event(line)
        assert result["level"] == "ERROR"

    def test_docker_json_inner(self, fmt):
        inner = json.dumps({"level": "error", "msg": "inner failure"})
        line = json.dumps({
            "log": inner + "\n",
            "stream": "stderr",
            "time": "2025-03-05T12:00:00.123Z",
        })
        result = fmt.classify_event(line)
        assert result["level"] == "ERROR"

    def test_docker_ts_extraction(self, fmt):
        line = json.dumps({
            "log": "starting app\n",
            "stream": "stdout",
            "time": "2025-03-05T12:00:00.123Z",
        })
        assert fmt.extract_ts(line) == "2025-03-05T12:00:00.123Z"

    def test_k8s_metadata(self, fmt):
        line = json.dumps({
            "log": "ERROR connection refused\n",
            "stream": "stderr",
            "time": "2025-03-05T12:00:00Z",
            "kubernetes": {
                "namespace_name": "production",
                "pod_name": "api-server-abc123",
            },
        })
        ts = fmt.extract_ts(line)
        assert ts == "2025-03-05T12:00:00Z"
        result = fmt.classify_event(line)
        assert result["level"] == "ERROR"


# ── Broken/Edge Cases ─────────────────────────────────────────────────

class TestEdgeCases:
    def test_broken_json_no_crash(self, fmt):
        assert fmt.extract_ts('{"broken": json') is None
        assert fmt.extract_level('{"broken": json') is None
        assert fmt.is_continuation('{"broken": json') is False
        result = fmt.classify_event('{"broken": json')
        assert result["level"] is None

    def test_empty_json_object(self, fmt):
        line = "{}"
        assert fmt.extract_ts(line) is None
        assert fmt.extract_level(line) is None
        result = fmt.classify_event(line)
        assert result["level"] is None

    def test_json_array_not_treated_as_log(self, fmt):
        assert fmt.extract_ts("[1, 2, 3]") is None
        assert fmt.detect(["[1, 2, 3]", "[4, 5, 6]"]) == 0.0

    def test_nested_error_dict(self, fmt):
        line = json.dumps({
            "level": "error",
            "msg": "request failed",
            "err": {"message": "java.net.ConnectException: refused", "code": 500},
        })
        result = fmt.classify_event(line)
        assert result["exception"] == "java.net.ConnectException"


# ── Multiple Library Formats ──────────────────────────────────────────

class TestLibraryFormats:
    def test_structlog(self, fmt):
        line = json.dumps({
            "timestamp": "2025-03-05T12:00:00Z",
            "level": "info",
            "event": "request handled",  # structlog uses 'event' but we look at 'msg'/'message'
            "msg": "request handled",
        })
        result = fmt.classify_event(line)
        assert result["level"] == "INFO"

    def test_bunyan(self, fmt):
        line = json.dumps({
            "v": 0, "level": 50, "name": "myapp",
            "hostname": "server1", "pid": 1234,
            "time": "2025-03-05T12:00:00Z",
            "msg": "database connection failed",
        })
        result = fmt.classify_event(line)
        assert result["level"] == "ERROR"
        assert fmt.extract_ts(line) == "2025-03-05T12:00:00Z"

    def test_zap(self, fmt):
        line = json.dumps({
            "level": "error", "ts": 1709640000.123,
            "caller": "handler/main.go:42",
            "msg": "SSLHandshakeException during TLS negotiation",
            "stacktrace": "main.handler\n\tmain.go:42",
        })
        result = fmt.classify_event(line)
        assert result["level"] == "ERROR"
        assert "SSL/TLS" in result["tags"]

    def test_winston(self, fmt):
        line = json.dumps({
            "level": "error",
            "message": "Unhandled java.lang.NullPointerException",
            "timestamp": "2025-03-05T12:00:00.000Z",
            "service": "api",
        })
        result = fmt.classify_event(line)
        assert result["level"] == "ERROR"
        assert result["exception"] == "java.lang.NullPointerException"

    def test_gelf(self, fmt):
        """GELF (Graylog) uses short_message."""
        line = json.dumps({
            "version": "1.1",
            "short_message": "Connection timed out",
            "timestamp": 1709640000,
            "level": 3,  # syslog: error
        })
        result = fmt.classify_event(line)
        assert result["level"] == "ERROR"


# ── Registry Integration ──────────────────────────────────────────────

class TestRegistry:
    def test_json_format_in_registry(self):
        from logpilot.formats import list_formats, get_format
        names = [f["name"] for f in list_formats()]
        assert "json" in names
        fmt = get_format("json")
        assert fmt.name == "json"

    def test_auto_detect_json(self):
        from logpilot.formats import detect_format
        lines = [
            '{"timestamp":"2025-03-05T12:00:00Z","level":"info","msg":"started"}',
            '{"timestamp":"2025-03-05T12:00:01Z","level":"error","msg":"failed"}',
            '{"timestamp":"2025-03-05T12:00:02Z","level":"warn","msg":"slow"}',
        ]
        fmt = detect_format(lines)
        assert fmt.name == "json"
