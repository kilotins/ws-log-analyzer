"""Tests for PostgreSQL log format plugin."""
from __future__ import annotations

from pathlib import Path

import pytest

from logpilot.formats.postgresql import PostgreSQLFormat, PG_LINE_RE
from logpilot.parser import parse_file
from logpilot.formats import detect_format

FIXTURE = Path(__file__).parent / "fixtures" / "postgresql-sample.log"
FMT = PostgreSQLFormat()


class TestDetection:
    def test_detect_postgresql_log(self):
        lines = FIXTURE.read_text().splitlines()[:50]
        score = FMT.detect(lines)
        assert score > 0.5

    def test_bonus_for_pg_specific_levels(self):
        lines = [
            "2026-03-22 08:30:00.000 UTC [1] LOG:  database system is ready",
            "2026-03-22 08:30:01.000 UTC [2] DETAIL:  some detail",
            "2026-03-22 08:30:02.000 UTC [3] NOTICE:  table does not exist",
        ]
        score = FMT.detect(lines)
        # LOG, DETAIL, NOTICE are PG-unique → high score
        assert score > 0.8

    def test_not_detect_log4j(self):
        lines = [
            "2026-03-22 08:30:00.000 INFO  [main] com.example.App - Starting",
        ]
        assert FMT.detect(lines) == 0.0

    def test_auto_detect_fixture(self):
        fmt = detect_format(FIXTURE)
        assert fmt.name == "postgresql"

    def test_detect_empty(self):
        assert FMT.detect([]) == 0.0

    def test_detect_extended_format(self):
        lines = [
            "2026-03-22 08:30:00.000 UTC [1234] appuser@mydb LOG:  statement: SELECT 1",
            "2026-03-22 08:30:01.000 UTC [1234] appuser@mydb ERROR:  permission denied",
        ]
        score = FMT.detect(lines)
        assert score > 0.3


class TestTimestamp:
    def test_extract_ts(self):
        line = "2026-03-22 08:30:00.000 UTC [1] LOG:  database system is ready"
        assert FMT.extract_ts(line) == "2026-03-22 08:30:00.000"

    def test_extract_ts_none_for_tab_line(self):
        assert FMT.extract_ts("\tProcess 201 waits for ShareLock") is None


class TestLevel:
    @pytest.mark.parametrize("level_str,expected", [
        ("LOG", "INFO"),
        ("ERROR", "ERROR"),
        ("FATAL", "ERROR"),
        ("PANIC", "FATAL"),
        ("WARNING", "WARNING"),
        ("INFO", "INFO"),
        ("NOTICE", "INFO"),
        ("DEBUG1", "DEBUG"),
    ])
    def test_level_mapping(self, level_str, expected):
        line = f"2026-03-22 08:30:00.000 UTC [1] {level_str}:  test message"
        assert FMT.extract_level(line) == expected

    def test_continuation_levels_return_none(self):
        for level in ("DETAIL", "HINT", "STATEMENT", "CONTEXT"):
            line = f"2026-03-22 08:30:00.000 UTC [1] {level}:  continuation text"
            assert FMT.extract_level(line) is None


class TestContinuation:
    def test_new_event_not_continuation(self):
        line = "2026-03-22 08:30:00.000 UTC [1] LOG:  database system is ready"
        assert FMT.is_continuation(line) is False

    def test_detail_is_continuation(self):
        line = "2026-03-22 08:35:00.001 UTC [200] DETAIL:  Process 200 waits for ShareLock"
        assert FMT.is_continuation(line) is True

    def test_hint_is_continuation(self):
        line = "2026-03-22 08:35:00.002 UTC [200] HINT:  See server log for query details."
        assert FMT.is_continuation(line) is True

    def test_statement_is_continuation(self):
        line = "2026-03-22 08:35:00.003 UTC [200] STATEMENT:  UPDATE accounts SET balance = 0"
        assert FMT.is_continuation(line) is True

    def test_tab_indented_is_continuation(self):
        assert FMT.is_continuation("\tProcess 201 waits for ShareLock") is True

    def test_empty_not_continuation(self):
        assert FMT.is_continuation("") is False


class TestClassify:
    def test_classify_error(self):
        text = "2026-03-22 08:35:00.000 UTC [200] ERROR:  deadlock detected"
        result = FMT.classify_event(text)
        assert result["level"] == "ERROR"
        assert result["thread_id"] == "200"
        assert "PG/Lock" in result["tags"]

    def test_classify_fatal(self):
        text = "2026-03-22 08:35:10.100 UTC [300] FATAL:  sorry, too many clients already"
        result = FMT.classify_event(text)
        assert result["level"] == "ERROR"
        assert "PG/Conn" in result["tags"]

    def test_classify_with_detail(self):
        text = (
            "2026-03-22 08:35:00.000 UTC [200] ERROR:  deadlock detected\n"
            "2026-03-22 08:35:00.001 UTC [200] DETAIL:  Process 200 waits for ShareLock\n"
            "\tProcess 201 waits for ShareLock on transaction 78233; blocked by process 200.\n"
            "2026-03-22 08:35:00.002 UTC [200] HINT:  See server log for query details.\n"
            "2026-03-22 08:35:00.003 UTC [200] STATEMENT:  UPDATE accounts SET balance = 0"
        )
        result = FMT.classify_event(text)
        assert result["level"] == "ERROR"
        assert "PG/Lock" in result["tags"]
        assert "deadlock detected" in result["exception"]

    def test_classify_auth_failure(self):
        text = "2026-03-22 08:35:25.000 UTC [202] FATAL:  password authentication failed for user \"admin\""
        result = FMT.classify_event(text)
        assert "PG/Auth" in result["tags"]

    def test_classify_shutdown(self):
        text = "2026-03-22 08:35:31.000 UTC [1] LOG:  shutting down"
        result = FMT.classify_event(text)
        assert "PG/Shutdown" in result["tags"]

    def test_classify_replication(self):
        text = "2026-03-22 08:37:00.500 UTC [1] LOG:  redo starts at 0/5A000028"
        result = FMT.classify_event(text)
        assert "PG/Replication" in result["tags"]

    def test_classify_slow_query(self):
        text = "2026-03-22 08:35:15.000 UTC [200] LOG:  duration: 30005.123 ms  statement: SELECT * FROM orders"
        result = FMT.classify_event(text)
        assert "PG/SlowQuery" in result["tags"]

    def test_classify_disk(self):
        text = "2026-03-22 08:35:20.001 UTC [1] WARNING:  temporary file size 536870912 exceeds temp_file_limit"
        result = FMT.classify_event(text)
        assert "PG/Disk" in result["tags"]

    def test_classify_vacuum(self):
        text = '2026-03-22 08:35:15.500 UTC [23] WARNING:  autovacuum worker started but database "production" has 12847 dead tuples needing cleanup'
        result = FMT.classify_event(text)
        assert "PG/Vacuum" in result["tags"]


class TestSignalTags:
    def test_conn_tag(self):
        tags = FMT.bucket_tags("sorry, too many clients already")
        assert "PG/Conn" in tags

    def test_lock_tag(self):
        tags = FMT.bucket_tags("deadlock detected between processes")
        assert "PG/Lock" in tags

    def test_disk_tag(self):
        tags = FMT.bucket_tags("temporary file size exceeds temp_file_limit")
        assert "PG/Disk" in tags

    def test_no_tags(self):
        tags = FMT.bucket_tags("duration: 2.345 ms  statement: SELECT 1")
        assert len(tags) == 0


class TestParsing:
    def test_parse_fixture(self):
        events = parse_file(FIXTURE)
        assert len(events) > 0

    def test_event_count(self):
        events = parse_file(FIXTURE)
        assert len(events) >= 20

    def test_error_events(self):
        events = parse_file(FIXTURE)
        errors = [e for e in events if e.level == "ERROR"]
        assert len(errors) >= 4

    def test_multiline_deadlock(self):
        """Deadlock event should merge with DETAIL/HINT/STATEMENT."""
        events = parse_file(FIXTURE)
        deadlock = [e for e in events if "deadlock" in (e.text or "").lower()]
        assert len(deadlock) >= 1
        evt = deadlock[0]
        assert "DETAIL" in evt.text
        assert "HINT" in evt.text
        assert "STATEMENT" in evt.text

    def test_signal_tags_present(self):
        events = parse_file(FIXTURE)
        all_tags = set()
        for e in events:
            all_tags.update(e.tags or [])
        assert "PG/Lock" in all_tags
        assert "PG/Conn" in all_tags
        assert "PG/Disk" in all_tags
        assert "PG/Shutdown" in all_tags

    def test_bank_scenario_detected_as_postgresql(self):
        """The bank scenario postgresql log should now detect as postgresql format."""
        bank_pg = Path(__file__).parent / "fixtures" / "scenario-bank" / "postgresql-coredb.log"
        if bank_pg.exists():
            fmt = detect_format(bank_pg)
            assert fmt.name == "postgresql"
