"""Tests for the Python logging format plugin."""
import pytest

from logpilot.formats.python_log import PythonFormat


@pytest.fixture
def fmt():
    return PythonFormat()


# ── Detection ──────────────────────────────────────────────────────────

class TestDetect:
    def test_stdlib_scores_high(self, fmt):
        lines = [
            "2025-03-11 10:15:33,123 - myapp.views - ERROR - Something went wrong",
            "2025-03-11 10:15:34,456 - myapp.views - INFO - Request processed",
            "2025-03-11 10:15:35,789 - myapp.models - WARNING - Slow query detected",
        ]
        assert fmt.detect(lines) > 0.5

    def test_django_dev_server_scores_high(self, fmt):
        lines = [
            '[11/Mar/2025 10:15:33] "GET /admin/ HTTP/1.1" 200 5432',
            '[11/Mar/2025 10:15:34] "POST /api/users/ HTTP/1.1" 201 123',
            '[11/Mar/2025 10:15:35] "GET /static/style.css HTTP/1.1" 304 0',
        ]
        assert fmt.detect(lines) > 0.5

    def test_flask_uvicorn_access_scores_high(self, fmt):
        lines = [
            'INFO:     127.0.0.1:54321 - "GET / HTTP/1.1" 200',
            'INFO:     127.0.0.1:54322 - "POST /api HTTP/1.1" 201',
            'WARNING:  127.0.0.1:54323 - "GET /missing HTTP/1.1" 404',
        ]
        assert fmt.detect(lines) > 0.5

    def test_uvicorn_general_scores_moderate(self, fmt):
        lines = [
            "INFO:     Started server process [1234]",
            "INFO:     Waiting for application startup.",
            "INFO:     Application startup complete.",
            "INFO:     Uvicorn running on http://0.0.0.0:8000",
        ]
        assert fmt.detect(lines) > 0.3

    def test_gunicorn_scores_high(self, fmt):
        lines = [
            "[2025-03-11 10:15:33 +0000] [1234] [INFO] Starting gunicorn 21.2.0",
            "[2025-03-11 10:15:33 +0000] [1234] [INFO] Listening at: http://0.0.0.0:8000",
            "[2025-03-11 10:15:33 +0000] [1235] [INFO] Booting worker with pid: 1235",
        ]
        assert fmt.detect(lines) > 0.5

    def test_python_traceback_contributes(self, fmt):
        lines = [
            "Traceback (most recent call last):",
            '  File "/app/views.py", line 42, in get',
            "    return obj.name",
            "AttributeError: 'NoneType' object has no attribute 'name'",
        ]
        assert fmt.detect(lines) > 0.2

    def test_log4j_scores_low(self, fmt):
        lines = [
            "2025-03-11 10:15:33,123 ERROR [main] com.example.App - Connection failed",
            "2025-03-11 10:15:34,456 INFO  [main] com.example.App - Retrying...",
        ]
        # stdlib regex requires " - name - LEVEL - " pattern, not "[thread] class -"
        assert fmt.detect(lines) < 0.5

    def test_was_format_scores_low(self, fmt):
        lines = [
            "[3/5/25 12:00:00:000 UTC] 0000001a Component I SRVE0242I: Starting",
            "[3/5/25 12:00:01:000 UTC] 0000001a Component E CWWKE0701E: Error",
        ]
        assert fmt.detect(lines) < 0.3

    def test_empty_scores_zero(self, fmt):
        assert fmt.detect([]) == 0.0

    def test_json_format_scores_low(self, fmt):
        lines = [
            '{"timestamp":"2025-03-05T12:00:00Z","level":"info","msg":"started"}',
            '{"timestamp":"2025-03-05T12:00:01Z","level":"error","msg":"failed"}',
        ]
        assert fmt.detect(lines) < 0.2

    def test_mixed_stdlib_and_traceback(self, fmt):
        lines = [
            "2025-03-11 10:15:33,123 - myapp - ERROR - Unhandled exception",
            "Traceback (most recent call last):",
            '  File "/app/main.py", line 10, in main',
            "    process()",
            "RuntimeError: something broke",
        ]
        assert fmt.detect(lines) > 0.4


# ── Timestamp Extraction ──────────────────────────────────────────────

class TestExtractTs:
    def test_stdlib_timestamp(self, fmt):
        line = "2025-03-11 10:15:33,123 - myapp - ERROR - Failed"
        assert fmt.extract_ts(line) == "2025-03-11 10:15:33,123"

    def test_stdlib_dot_millis(self, fmt):
        line = "2025-03-11 10:15:33.456 - myapp - INFO - OK"
        assert fmt.extract_ts(line) == "2025-03-11 10:15:33.456"

    def test_django_timestamp(self, fmt):
        line = '[11/Mar/2025 10:15:33] "GET /admin/ HTTP/1.1" 200 5432'
        assert fmt.extract_ts(line) == "11/Mar/2025 10:15:33"

    def test_gunicorn_timestamp(self, fmt):
        line = "[2025-03-11 10:15:33 +0000] [1234] [INFO] Starting"
        assert fmt.extract_ts(line) == "2025-03-11 10:15:33"

    def test_no_timestamp_traceback(self, fmt):
        line = "Traceback (most recent call last):"
        assert fmt.extract_ts(line) is None

    def test_no_timestamp_file_line(self, fmt):
        line = '  File "/app/views.py", line 42, in get'
        assert fmt.extract_ts(line) is None

    def test_no_timestamp_exception(self, fmt):
        line = "ValueError: invalid literal"
        assert fmt.extract_ts(line) is None

    def test_uvicorn_no_timestamp(self, fmt):
        line = 'INFO:     127.0.0.1:54321 - "GET / HTTP/1.1" 200'
        # uvicorn access logs typically have no timestamp
        assert fmt.extract_ts(line) is None


# ── Level Extraction ──────────────────────────────────────────────────

class TestExtractLevel:
    def test_stdlib_error(self, fmt):
        line = "2025-03-11 10:15:33,123 - myapp - ERROR - Failed"
        assert fmt.extract_level(line) == "ERROR"

    def test_stdlib_warning(self, fmt):
        line = "2025-03-11 10:15:33,123 - myapp - WARNING - Slow"
        assert fmt.extract_level(line) == "WARNING"

    def test_stdlib_critical(self, fmt):
        line = "2025-03-11 10:15:33,123 - myapp - CRITICAL - Fatal error"
        assert fmt.extract_level(line) == "CRITICAL"

    def test_stdlib_info(self, fmt):
        line = "2025-03-11 10:15:33,123 - myapp - INFO - Started"
        assert fmt.extract_level(line) == "INFO"

    def test_stdlib_debug(self, fmt):
        line = "2025-03-11 10:15:33,123 - myapp - DEBUG - Query SQL"
        assert fmt.extract_level(line) == "DEBUG"

    def test_gunicorn_info(self, fmt):
        line = "[2025-03-11 10:15:33 +0000] [1234] [INFO] Starting"
        assert fmt.extract_level(line) == "INFO"

    def test_gunicorn_error(self, fmt):
        line = "[2025-03-11 10:15:33 +0000] [1234] [ERROR] Worker failed"
        assert fmt.extract_level(line) == "ERROR"

    def test_uvicorn_access_200(self, fmt):
        line = 'INFO:     127.0.0.1:54321 - "GET / HTTP/1.1" 200'
        assert fmt.extract_level(line) == "INFO"

    def test_uvicorn_access_404(self, fmt):
        line = 'WARNING:  127.0.0.1:54323 - "GET /missing HTTP/1.1" 404'
        assert fmt.extract_level(line) == "WARNING"

    def test_uvicorn_access_500(self, fmt):
        line = 'ERROR:    127.0.0.1:54324 - "POST /api HTTP/1.1" 500'
        assert fmt.extract_level(line) == "ERROR"

    def test_django_200_is_info(self, fmt):
        line = '[11/Mar/2025 10:15:33] "GET /admin/ HTTP/1.1" 200 5432'
        assert fmt.extract_level(line) == "INFO"

    def test_django_404_is_warning(self, fmt):
        line = '[11/Mar/2025 10:15:33] "GET /missing HTTP/1.1" 404 0'
        assert fmt.extract_level(line) == "WARNING"

    def test_django_500_is_error(self, fmt):
        line = '[11/Mar/2025 10:15:33] "GET /crash HTTP/1.1" 500 0'
        assert fmt.extract_level(line) == "ERROR"

    def test_uvicorn_general(self, fmt):
        line = "INFO:     Application startup complete."
        assert fmt.extract_level(line) == "INFO"

    def test_no_level_stacktrace(self, fmt):
        line = '  File "/app/views.py", line 42, in get'
        assert fmt.extract_level(line) is None


# ── Continuation Detection ────────────────────────────────────────────

class TestIsContinuation:
    def test_traceback_header(self, fmt):
        assert fmt.is_continuation("Traceback (most recent call last):")

    def test_file_line(self, fmt):
        assert fmt.is_continuation('  File "/app/views.py", line 42, in get')

    def test_indented_code(self, fmt):
        assert fmt.is_continuation("    return obj.name")

    def test_caret_line(self, fmt):
        assert fmt.is_continuation("    ^^^^")

    def test_exception_chaining(self, fmt):
        assert fmt.is_continuation(
            "During handling of the above exception, another exception occurred:"
        )

    def test_direct_cause_chaining(self, fmt):
        assert fmt.is_continuation(
            "The above exception was the direct cause of the following exception:"
        )

    def test_exception_line(self, fmt):
        assert fmt.is_continuation("ValueError: invalid literal for int()")

    def test_java_caused_by(self, fmt):
        assert fmt.is_continuation("Caused by: java.sql.SQLException: Connection refused")

    def test_java_stack_line(self, fmt):
        assert fmt.is_continuation("\tat com.example.App.run(App.java:42)")

    def test_stdlib_new_event_not_continuation(self, fmt):
        assert not fmt.is_continuation(
            "2025-03-11 10:15:33,123 - myapp - ERROR - New event"
        )

    def test_django_new_event_not_continuation(self, fmt):
        assert not fmt.is_continuation(
            '[11/Mar/2025 10:15:33] "GET /admin/ HTTP/1.1" 200 5432'
        )

    def test_gunicorn_new_event_not_continuation(self, fmt):
        assert not fmt.is_continuation(
            "[2025-03-11 10:15:33 +0000] [1234] [INFO] Starting"
        )

    def test_uvicorn_new_event_not_continuation(self, fmt):
        assert not fmt.is_continuation(
            "INFO:     Application startup complete."
        )

    def test_blank_indented_line(self, fmt):
        assert fmt.is_continuation("    ")

    def test_tab_indented(self, fmt):
        assert fmt.is_continuation("\tsome continued text")


# ── Event Classification ──────────────────────────────────────────────

class TestClassifyEvent:
    def test_stdlib_error_event(self, fmt):
        text = "2025-03-11 10:15:33,123 - myapp.views - ERROR - Request failed"
        result = fmt.classify_event(text)
        assert result["level"] == "ERROR"
        assert result["code"] is None
        assert result["thread_id"] is None

    def test_stdlib_warning_event(self, fmt):
        text = "2025-03-11 10:15:33,123 - myapp - WARNING - Deprecated call"
        result = fmt.classify_event(text)
        assert result["level"] == "WARNING"

    def test_event_with_python_traceback(self, fmt):
        text = (
            "2025-03-11 10:15:33,123 - myapp - ERROR - Unhandled exception\n"
            "Traceback (most recent call last):\n"
            '  File "/app/views.py", line 42, in get\n'
            "    return obj.name\n"
            "AttributeError: 'NoneType' object has no attribute 'name'"
        )
        result = fmt.classify_event(text)
        assert result["level"] == "ERROR"
        assert result["exception"] == "AttributeError"

    def test_event_with_chained_exceptions(self, fmt):
        text = (
            "2025-03-11 10:15:33,123 - myapp - ERROR - DB failure\n"
            "Traceback (most recent call last):\n"
            '  File "/app/db.py", line 10, in connect\n'
            "    conn = psycopg2.connect(dsn)\n"
            "psycopg2.OperationalError: connection refused\n"
            "\n"
            "During handling of the above exception, another exception occurred:\n"
            "\n"
            "Traceback (most recent call last):\n"
            '  File "/app/views.py", line 20, in get\n'
            "    data = fetch_data()\n"
            "RuntimeError: database unavailable"
        )
        result = fmt.classify_event(text)
        assert result["exception"] == "psycopg2.OperationalError"
        assert result["root_cause"] == "RuntimeError"

    def test_django_access_event(self, fmt):
        text = '[11/Mar/2025 10:15:33] "GET /crash HTTP/1.1" 500 0'
        result = fmt.classify_event(text)
        assert result["level"] == "ERROR"
        assert "HTTP" in result["tags"]

    def test_gunicorn_event(self, fmt):
        text = "[2025-03-11 10:15:33 +0000] [1234] [ERROR] Worker timeout"
        result = fmt.classify_event(text)
        assert result["level"] == "ERROR"

    def test_classify_returns_sorted_tags(self, fmt):
        text = (
            "2025-03-11 10:15:33,123 - myapp - ERROR - Import and DB failure\n"
            "ImportError: No module named 'psycopg2'\n"
            "django.db.utils.OperationalError: connection refused"
        )
        result = fmt.classify_event(text)
        tags = result["tags"]
        assert tags == sorted(tags)

    def test_classify_info_no_exception(self, fmt):
        text = "2025-03-11 10:15:33,123 - myapp - INFO - Server started"
        result = fmt.classify_event(text)
        assert result["level"] == "INFO"
        assert result["exception"] is None
        assert result["root_cause"] is None


# ── Bucket Tags ───────────────────────────────────────────────────────

class TestBucketTags:
    def test_import_error(self, fmt):
        text = "ImportError: No module named 'flask'"
        assert "Import" in fmt.bucket_tags(text)

    def test_module_not_found_error(self, fmt):
        text = "ModuleNotFoundError: No module named 'django'"
        assert "Import" in fmt.bucket_tags(text)

    def test_database_error(self, fmt):
        text = "django.db.utils.DatabaseError: relation does not exist"
        assert "DB" in fmt.bucket_tags(text)

    def test_operational_error(self, fmt):
        text = "psycopg2.OperationalError: could not connect to server"
        assert "DB" in fmt.bucket_tags(text)

    def test_integrity_error(self, fmt):
        text = "django.db.utils.IntegrityError: duplicate key value"
        assert "DB" in fmt.bucket_tags(text)

    def test_sqlalchemy_error(self, fmt):
        text = "sqlalchemy.exc.OperationalError: connection refused"
        assert "DB" in fmt.bucket_tags(text)

    def test_template_syntax_error(self, fmt):
        text = "django.template.exceptions.TemplateSyntaxError: Invalid block tag"
        assert "Template" in fmt.bucket_tags(text)

    def test_template_does_not_exist(self, fmt):
        text = "django.template.exceptions.TemplateDoesNotExist: index.html"
        assert "Template" in fmt.bucket_tags(text)

    def test_jinja2_error(self, fmt):
        text = "jinja2.exceptions.UndefinedError: 'foo' is undefined"
        assert "Template" in fmt.bucket_tags(text)

    def test_csrf_tag(self, fmt):
        text = "Forbidden (CSRF cookie not set.): /api/submit"
        assert "Auth" in fmt.bucket_tags(text)

    def test_permission_denied(self, fmt):
        text = "django.core.exceptions.PermissionDenied: You do not have permission"
        assert "Auth" in fmt.bucket_tags(text)

    def test_authentication_failed(self, fmt):
        text = "rest_framework.exceptions.AuthenticationFailed: Invalid token"
        assert "Auth" in fmt.bucket_tags(text)

    def test_http_4xx(self, fmt):
        text = '[11/Mar/2025 10:15:33] "GET /missing HTTP/1.1" 404 0'
        assert "HTTP" in fmt.bucket_tags(text)

    def test_http_5xx(self, fmt):
        text = '[11/Mar/2025 10:15:33] "GET /crash HTTP/1.1" 500 0'
        assert "HTTP" in fmt.bucket_tags(text)

    def test_celery_task_failed(self, fmt):
        text = "celery.app.trace - ERROR - Task myapp.tasks.send_email failed"
        assert "Celery" in fmt.bucket_tags(text)

    def test_worker_lost(self, fmt):
        text = "WorkerLostError: Worker exited prematurely: signal 9 (SIGKILL)"
        assert "Celery" in fmt.bucket_tags(text)

    def test_soft_time_limit(self, fmt):
        text = "SoftTimeLimitExceeded: soft time limit exceeded"
        assert "Celery" in fmt.bucket_tags(text)

    def test_memory_error(self, fmt):
        text = "MemoryError: unable to allocate array"
        assert "OOM" in fmt.bucket_tags(text)

    def test_killed_process(self, fmt):
        text = "Killed process 1234 (python)"
        assert "OOM" in fmt.bucket_tags(text)

    def test_java_oom_also_tagged(self, fmt):
        text = "java.lang.OutOfMemoryError: Java heap space"
        assert "OOM" in fmt.bucket_tags(text)

    def test_no_tags_clean_log(self, fmt):
        text = "2025-03-11 10:15:33,123 - myapp - INFO - Server started"
        assert len(fmt.bucket_tags(text)) == 0

    def test_multiple_tags(self, fmt):
        text = (
            "ImportError: No module named 'psycopg2'\n"
            "django.db.utils.OperationalError: could not connect\n"
            "MemoryError"
        )
        tags = fmt.bucket_tags(text)
        assert "Import" in tags
        assert "DB" in tags
        assert "OOM" in tags


# ── Integration: Registry ─────────────────────────────────────────────

class TestRegistry:
    def test_python_format_registered(self):
        """PythonFormat can be registered and retrieved."""
        from logpilot.formats import register_format, _FORMAT_MAP
        py_fmt = PythonFormat()
        register_format(py_fmt)
        assert "python" in _FORMAT_MAP
        assert _FORMAT_MAP["python"].name == "python"

    def test_detect_stdlib_log(self):
        """Detection works when PythonFormat is registered."""
        from logpilot.formats import register_format, detect_format, _FORMATS, _FORMAT_MAP
        # Ensure registered
        if "python" not in _FORMAT_MAP:
            register_format(PythonFormat())
        lines = [
            "2025-03-11 10:15:33,123 - myapp.views - ERROR - Request failed",
            "2025-03-11 10:15:34,456 - myapp.views - INFO - Recovered",
            "2025-03-11 10:15:35,789 - myapp.models - WARNING - Slow query",
        ]
        detected = detect_format(lines)
        assert detected.name == "python"

    def test_detect_django_log(self):
        """Django access logs detected as python format."""
        from logpilot.formats import register_format, detect_format, _FORMAT_MAP
        if "python" not in _FORMAT_MAP:
            register_format(PythonFormat())
        lines = [
            '[11/Mar/2025 10:15:33] "GET /admin/ HTTP/1.1" 200 5432',
            '[11/Mar/2025 10:15:34] "POST /api/users/ HTTP/1.1" 201 123',
            '[11/Mar/2025 10:15:35] "DELETE /api/users/1/ HTTP/1.1" 204 0',
        ]
        detected = detect_format(lines)
        assert detected.name == "python"

    def test_detect_gunicorn_log(self):
        """Gunicorn logs detected as python format."""
        from logpilot.formats import register_format, detect_format, _FORMAT_MAP
        if "python" not in _FORMAT_MAP:
            register_format(PythonFormat())
        lines = [
            "[2025-03-11 10:15:33 +0000] [1234] [INFO] Starting gunicorn 21.2.0",
            "[2025-03-11 10:15:33 +0000] [1234] [INFO] Listening at: http://0.0.0.0:8000",
            "[2025-03-11 10:15:33 +0000] [1235] [INFO] Booting worker with pid: 1235",
        ]
        detected = detect_format(lines)
        assert detected.name == "python"
