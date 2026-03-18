"""Edge case tests for logpilot/splunk.py."""
from __future__ import annotations

import pytest
from logpilot.event import LogEvent
from logpilot.splunk import suggested_splunk_queries, hung_thread_drilldown, _extract_hung_thread_name, _extract_stack_sample

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_event(text="", level="ERROR", thread_id=None, ts=None, tags=None):
    return LogEvent(
        text=text,
        level=level,
        thread_id=thread_id,
        ts=ts or "2024/01/15 10:00:00:000",
        file="test.log",
        tags=tags or [],
    )


def empty_summary():
    return {"exceptions": [], "codes": [], "tags": []}


# ===========================================================================
# suggested_splunk_queries
# ===========================================================================

class TestSuggestedSplunkQueriesBasic:
    def test_empty_events_returns_base_query(self):
        """Empty summary/causes/hist always returns at least the base error query."""
        result = suggested_splunk_queries({}, [], [])
        assert len(result) >= 1
        descriptions = [q["description"] for q in result]
        assert any("error" in d.lower() or "severe" in d.lower() for d in descriptions)

    def test_empty_summary_no_hist_no_causes(self):
        """No exceptions, codes, tags, or hist — only base query, no timeline."""
        result = suggested_splunk_queries(empty_summary(), [], [])
        queries_text = " ".join(q["query"] for q in result)
        assert "timechart" not in queries_text

    def test_all_queries_have_required_keys(self):
        result = suggested_splunk_queries(empty_summary(), [], [("10:00", 5)])
        for q in result:
            assert "description" in q
            assert "query" in q

    def test_returns_at_most_8_queries(self):
        """Hard cap of 8 queries."""
        summary = {
            "exceptions": [
                ("com.example.FooException", 10),
                ("com.example.BarException", 5),
                ("com.example.BazException", 3),
                ("com.example.QuxException", 2),
            ],
            "codes": [
                ("CWOBJ1234E", 8), ("SRVE0068E", 6), ("WSVR0001I", 4),
                ("CWPKI0022E", 2), ("CWWKS1001A", 1),
            ],
            "tags": [("SSL/TLS", 3), ("OOM/GC", 2), ("DB/Pool", 1), ("HungThreads", 5)],
        }
        result = suggested_splunk_queries(summary, [], [("10:00", 99)])
        assert len(result) <= 8


class TestSuggestedSplunkQueriesExceptions:
    def test_exceptions_generate_queries(self):
        summary = {
            "exceptions": [("java.lang.NullPointerException", 7)],
            "codes": [],
            "tags": [],
        }
        result = suggested_splunk_queries(summary, [], [])
        queries_text = " ".join(q["query"] for q in result)
        assert "NullPointerException" in queries_text

    def test_exception_uses_short_name(self):
        """Only the simple class name (after last '.') should appear, not the FQCN."""
        summary = {
            "exceptions": [("com.ibm.ws.some.deep.package.CustomException", 3)],
            "codes": [],
            "tags": [],
        }
        result = suggested_splunk_queries(summary, [], [])
        queries_text = " ".join(q["query"] for q in result)
        assert "CustomException" in queries_text
        assert "com.ibm.ws" not in queries_text

    def test_at_most_3_exception_queries(self):
        """Only the first 3 exceptions should produce queries."""
        summary = {
            "exceptions": [
                ("a.ExcA", 10), ("b.ExcB", 9), ("c.ExcC", 8), ("d.ExcD", 7),
            ],
            "codes": [],
            "tags": [],
        }
        result = suggested_splunk_queries(summary, [], [])
        exc_queries = [q for q in result if "seen" in q["description"]]
        assert len(exc_queries) == 3
        assert not any("ExcD" in q["query"] for q in result)

    def test_exception_count_in_description(self):
        summary = {"exceptions": [("foo.MyException", 42)], "codes": [], "tags": []}
        result = suggested_splunk_queries(summary, [], [])
        exc_q = next(q for q in result if "MyException" in q["query"])
        assert "42" in exc_q["description"]


class TestSuggestedSplunkQueriesCodes:
    def test_codes_generate_prefix_queries(self):
        summary = {"exceptions": [], "codes": [("CWOBJ1234E", 5)], "tags": []}
        result = suggested_splunk_queries(summary, [], [])
        queries_text = " ".join(q["query"] for q in result)
        assert "CWOBJ*" in queries_text

    def test_duplicate_prefix_not_repeated(self):
        """Two codes with the same prefix should produce only one prefix query."""
        summary = {
            "exceptions": [],
            "codes": [("CWOBJ1234E", 5), ("CWOBJ5678W", 3)],
            "tags": [],
        }
        result = suggested_splunk_queries(summary, [], [])
        cwobj_queries = [q for q in result if "CWOBJ*" in q["query"]]
        assert len(cwobj_queries) == 1

    def test_at_most_3_code_prefix_queries(self):
        """Only first 3 distinct prefixes should appear."""
        summary = {
            "exceptions": [],
            "codes": [
                ("CWOBJ1234E", 5), ("SRVE0068E", 4), ("WSVR0605W", 3),
                ("CWWKE0701E", 2), ("CWPKI0022E", 1),
            ],
            "tags": [],
        }
        result = suggested_splunk_queries(summary, [], [])
        prefix_queries = [q for q in result if q["description"].endswith("message codes")]
        assert len(prefix_queries) <= 3

    def test_code_without_alpha_prefix_skipped(self):
        """Codes starting with digits (unlikely but defensive) should not break."""
        summary = {"exceptions": [], "codes": [("1234ABCD", 1)], "tags": []}
        result = suggested_splunk_queries(summary, [], [])
        # Should not raise; base query always present
        assert len(result) >= 1

    def test_at_most_5_codes_consumed(self):
        """Only first 5 codes are processed even if more exist."""
        summary = {
            "exceptions": [],
            "codes": [
                ("AAAA0001E", 9), ("BBBB0002E", 8), ("CCCC0003E", 7),
                ("DDDD0004E", 6), ("EEEE0005E", 5), ("FFFF0006E", 4),
            ],
            "tags": [],
        }
        result = suggested_splunk_queries(summary, [], [])
        queries_text = " ".join(q["query"] for q in result)
        assert "FFFF*" not in queries_text


class TestSuggestedSplunkQueriesTags:
    def test_ssl_tag_generates_ssl_query(self):
        summary = {"exceptions": [], "codes": [], "tags": [("SSL/TLS", 2)]}
        result = suggested_splunk_queries(summary, [], [])
        queries_text = " ".join(q["query"] for q in result)
        assert "SSLHandshakeException" in queries_text

    def test_oom_tag_generates_oom_query(self):
        summary = {"exceptions": [], "codes": [], "tags": [("OOM/GC", 1)]}
        result = suggested_splunk_queries(summary, [], [])
        queries_text = " ".join(q["query"] for q in result)
        assert "OutOfMemoryError" in queries_text

    def test_db_pool_tag_generates_pool_query(self):
        summary = {"exceptions": [], "codes": [], "tags": [("DB/Pool", 3)]}
        result = suggested_splunk_queries(summary, [], [])
        queries_text = " ".join(q["query"] for q in result)
        assert "J2CA" in queries_text or "pool exhausted" in queries_text

    def test_hung_threads_tag_generates_hung_query(self):
        summary = {"exceptions": [], "codes": [], "tags": [("HungThreads", 4)]}
        result = suggested_splunk_queries(summary, [], [])
        queries_text = " ".join(q["query"] for q in result)
        assert "WSVR0605W" in queries_text or "ThreadMonitor" in queries_text

    def test_unknown_tag_ignored(self):
        summary = {"exceptions": [], "codes": [], "tags": [("UnknownTag", 1)]}
        result = suggested_splunk_queries(summary, [], [])
        # Should not raise; base query always present
        assert len(result) >= 1

    def test_multiple_tags_all_added(self):
        summary = {
            "exceptions": [],
            "codes": [],
            "tags": [("SSL/TLS", 1), ("OOM/GC", 1)],
        }
        result = suggested_splunk_queries(summary, [], [])
        queries_text = " ".join(q["query"] for q in result)
        assert "SSLHandshakeException" in queries_text
        assert "OutOfMemoryError" in queries_text


class TestSuggestedSplunkQueriesHistogram:
    def test_hist_adds_timechart_query(self):
        result = suggested_splunk_queries(empty_summary(), [], [("10:00", 3)])
        queries_text = " ".join(q["query"] for q in result)
        assert "timechart" in queries_text

    def test_empty_hist_no_timechart(self):
        result = suggested_splunk_queries(empty_summary(), [], [])
        queries_text = " ".join(q["query"] for q in result)
        assert "timechart" not in queries_text

    def test_all_queries_use_splunk_prefix(self):
        summary = {
            "exceptions": [("foo.Bar", 1)],
            "codes": [("CWOBJ1234E", 1)],
            "tags": [("SSL/TLS", 1)],
        }
        result = suggested_splunk_queries(summary, [], [("t", 1)])
        for q in result:
            assert q["query"].startswith("index=APP sourcetype=WAS")


# ===========================================================================
# hung_thread_drilldown
# ===========================================================================

_HUNG_TEXT = (
    'WSVR0605W: Thread "WebContainer : 3" (0x0000dead) has been active for 610,000 '
    'milliseconds and may be hung. There is 1 thread in total in the server that may be hung.\n'
    '    at com.example.Foo.bar(Foo.java:42)\n'
    '    at com.example.Baz.run(Baz.java:10)\n'
)

_STUCK_TEXT = (
    'WSVR0605W: Thread "WebContainer : 5" (0x0000beef) has been active for 800,000 '
    'milliseconds and may be hung.\n'
)

_LIBERTY_TEXT = (
    'CWWKE0701E: Thread "Default Executor-thread-12" (0x0000cafe) has been active for '
    '620,000 milliseconds and may be hung.\n'
    '    at java.net.SocketInputStream.read(SocketInputStream.java:182)\n'
)


class TestHungThreadDrilldownEmpty:
    def test_empty_list_returns_empty(self):
        assert hung_thread_drilldown([]) == []

    def test_no_hung_thread_events_returns_empty(self):
        events = [
            make_event("Normal INFO message"),
            make_event("ERROR: something failed"),
        ]
        assert hung_thread_drilldown(events) == []

    def test_event_without_text_returns_empty(self):
        event = make_event("")
        assert hung_thread_drilldown([event]) == []


class TestHungThreadDrilldownSingleThread:
    def test_single_hung_event_returns_one_entry(self):
        event = make_event(_HUNG_TEXT, thread_id="0000dead")
        result = hung_thread_drilldown([event])
        assert len(result) == 1
        assert result[0]["count"] == 1

    def test_thread_name_extracted_from_quoted_name(self):
        event = make_event(_HUNG_TEXT, thread_id="0000dead")
        result = hung_thread_drilldown([event])
        assert result[0]["thread_name"] == "WebContainer : 3"

    def test_hex_id_stored(self):
        event = make_event(_HUNG_TEXT, thread_id="0000dead")
        result = hung_thread_drilldown([event])
        assert "0000dead" in result[0]["hex_ids"]

    def test_splunk_query_contains_thread_name(self):
        event = make_event(_HUNG_TEXT, thread_id="0000dead")
        result = hung_thread_drilldown([event])
        assert "WebContainer : 3" in result[0]["splunk_query"]

    def test_stack_sample_extracted(self):
        event = make_event(_HUNG_TEXT, thread_id="0000dead")
        result = hung_thread_drilldown([event])
        sample = result[0]["stack_sample"]
        assert len(sample) > 0
        assert any("com.example.Foo" in line for line in sample)

    def test_stack_sample_max_5_lines(self):
        # Build a text with more than 5 stack lines
        stack_lines = "\n".join(f"    at com.example.X.m{i}(X.java:{i})" for i in range(10))
        text = "WSVR0605W: Thread \"WebContainer : 9\" has been active for 600,000 ms.\n" + stack_lines
        event = make_event(text, thread_id="abcd1234")
        result = hung_thread_drilldown([event])
        assert len(result[0]["stack_sample"]) <= 5

    def test_timestamps_set_correctly(self):
        event = make_event(_HUNG_TEXT, ts="2024/01/15 10:30:00:000")
        result = hung_thread_drilldown([event])
        assert result[0]["first_ts"] == "2024/01/15 10:30:00:000"
        assert result[0]["last_ts"] == "2024/01/15 10:30:00:000"

    def test_event_without_thread_id_uses_unknown(self):
        text = "WSVR0605W: hung thread detected\n"
        event = make_event(text, thread_id=None)
        result = hung_thread_drilldown([event])
        assert len(result) == 1
        assert result[0]["thread_name"] == "unknown"

    def test_event_with_thread_id_but_no_name_uses_hex(self):
        text = "WSVR0605W: hung thread detected\n"
        event = make_event(text, thread_id="deadbeef")
        result = hung_thread_drilldown([event])
        assert len(result) == 1
        assert result[0]["thread_name"] == "0xdeadbeef"


class TestHungThreadDrilldownMultipleThreads:
    def test_two_different_threads_two_entries(self):
        e1 = make_event(_HUNG_TEXT, thread_id="0000dead")
        e2 = make_event(_STUCK_TEXT, thread_id="0000beef")
        result = hung_thread_drilldown([e1, e2])
        assert len(result) == 2

    def test_same_thread_recurring_counted(self):
        """Same thread name across two events → single entry with count=2."""
        e1 = make_event(_HUNG_TEXT, thread_id="0000dead", ts="2024/01/15 10:00:00:000")
        # Same thread name "WebContainer : 3"
        e2 = make_event(_HUNG_TEXT, thread_id="0000dead", ts="2024/01/15 10:05:00:000")
        result = hung_thread_drilldown([e1, e2])
        assert len(result) == 1
        assert result[0]["count"] == 2

    def test_recurring_thread_timestamps_span(self):
        e1 = make_event(_HUNG_TEXT, ts="2024/01/15 10:00:00:000")
        e2 = make_event(_HUNG_TEXT, ts="2024/01/15 10:10:00:000")
        result = hung_thread_drilldown([e1, e2])
        assert result[0]["first_ts"] == "2024/01/15 10:00:00:000"
        assert result[0]["last_ts"] == "2024/01/15 10:10:00:000"

    def test_sorted_by_count_descending(self):
        """Entry with more occurrences appears first."""
        e_high = [make_event(_HUNG_TEXT, thread_id="0000dead") for _ in range(3)]
        e_low = [make_event(_STUCK_TEXT, thread_id="0000beef")]
        result = hung_thread_drilldown(e_high + e_low)
        assert result[0]["count"] >= result[-1]["count"]

    def test_multiple_hex_ids_for_same_thread(self):
        """Same thread name with different hex IDs (thread pool reuse) — both collected."""
        text_a = 'WSVR0605W: Thread "WebContainer : 3" (0x0000aaaa) has been active for 600,000 ms.\n'
        text_b = 'WSVR0605W: Thread "WebContainer : 3" (0x0000bbbb) has been active for 700,000 ms.\n'
        e1 = make_event(text_a, thread_id="0000aaaa")
        e2 = make_event(text_b, thread_id="0000bbbb")
        result = hung_thread_drilldown([e1, e2])
        assert len(result) == 1
        assert "0000aaaa" in result[0]["hex_ids"]
        assert "0000bbbb" in result[0]["hex_ids"]

    def test_hex_ids_are_sorted(self):
        text_a = 'WSVR0605W: Thread "WebContainer : 3" (0x0000zzzz) has been active for 600,000 ms.\n'
        text_b = 'WSVR0605W: Thread "WebContainer : 3" (0x0000aaaa) has been active for 700,000 ms.\n'
        e1 = make_event(text_a, thread_id="0000zzzz")
        e2 = make_event(text_b, thread_id="0000aaaa")
        result = hung_thread_drilldown([e1, e2])
        ids = result[0]["hex_ids"]
        assert ids == sorted(ids)

    def test_stack_sample_only_from_first_event(self):
        """stack_sample is captured from the first occurrence and not overwritten."""
        text_first = (
            'WSVR0605W: Thread "WebContainer : 3" has been active for 600,000 ms.\n'
            '    at com.example.FirstFrame.run(First.java:1)\n'
        )
        text_second = (
            'WSVR0605W: Thread "WebContainer : 3" has been active for 700,000 ms.\n'
            '    at com.example.SecondFrame.run(Second.java:2)\n'
        )
        e1 = make_event(text_first)
        e2 = make_event(text_second)
        result = hung_thread_drilldown([e1, e2])
        sample = result[0]["stack_sample"]
        assert any("FirstFrame" in line for line in sample)
        assert not any("SecondFrame" in line for line in sample)


class TestHungThreadDrilldownLiberty:
    def test_liberty_executor_thread_name_extracted(self):
        event = make_event(_LIBERTY_TEXT, thread_id="0000cafe")
        result = hung_thread_drilldown([event])
        assert len(result) == 1
        assert result[0]["thread_name"] == "Default Executor-thread-12"

    def test_liberty_stack_in_sample(self):
        event = make_event(_LIBERTY_TEXT, thread_id="0000cafe")
        result = hung_thread_drilldown([event])
        assert any("SocketInputStream" in line for line in result[0]["stack_sample"])


class TestHungThreadDrilldownMixedEvents:
    def test_non_hung_events_ignored(self):
        hung = make_event(_HUNG_TEXT, thread_id="0000dead")
        normal = make_event("INFO: application started normally")
        err = make_event("ERROR: NullPointerException at line 5")
        result = hung_thread_drilldown([hung, normal, err])
        assert len(result) == 1

    def test_all_non_hung_returns_empty(self):
        events = [make_event("INFO msg"), make_event("WARNING msg"), make_event("ERROR msg")]
        assert hung_thread_drilldown(events) == []


# ===========================================================================
# _extract_hung_thread_name (private helper — tested directly for coverage)
# ===========================================================================

class TestExtractHungThreadName:
    def test_quoted_thread_name(self):
        text = 'Thread "WebContainer : 3" has been active'
        assert _extract_hung_thread_name(text) == "WebContainer : 3"

    def test_single_quoted_thread_name(self):
        text = "Thread 'SomeThread' has been active"
        assert _extract_hung_thread_name(text) == "SomeThread"

    def test_webcontainer_unquoted(self):
        text = "thread WebContainer : 5 has been active"
        assert _extract_hung_thread_name(text) == "WebContainer : 5"

    def test_liberty_the_default_executor(self):
        text = "submitted to the Default Executor-thread-42"
        assert _extract_hung_thread_name(text) == "Default Executor-thread-42"

    def test_liberty_thread_default_executor(self):
        text = "thread Default Executor-thread-7 has been active"
        assert _extract_hung_thread_name(text) == "Default Executor-thread-7"

    def test_no_match_returns_none(self):
        assert _extract_hung_thread_name("unrelated log line") is None

    def test_empty_string_returns_none(self):
        assert _extract_hung_thread_name("") is None


# ===========================================================================
# _extract_stack_sample (private helper — tested directly for coverage)
# ===========================================================================

class TestExtractStackSample:
    def test_extracts_at_lines(self):
        text = "Error occurred\n    at com.example.Foo.bar(Foo.java:10)\n    at com.example.Baz.qux(Baz.java:5)\n"
        lines = _extract_stack_sample(text)
        assert len(lines) == 2
        assert "com.example.Foo.bar" in lines[0]

    def test_extracts_caused_by(self):
        text = "Exception\n    at A.run(A.java:1)\nCaused by: java.io.IOException: timeout\n    at B.call(B.java:2)\n"
        lines = _extract_stack_sample(text)
        assert any("Caused by" in l for l in lines)

    def test_respects_max_lines(self):
        stack = "\n".join(f"    at X.m{i}(X.java:{i})" for i in range(20))
        lines = _extract_stack_sample(stack, max_lines=3)
        assert len(lines) == 3

    def test_no_stack_returns_empty(self):
        assert _extract_stack_sample("Nothing here") == []

    def test_empty_string_returns_empty(self):
        assert _extract_stack_sample("") == []

    def test_strips_leading_whitespace(self):
        text = "    at com.example.A.b(A.java:1)\n"
        lines = _extract_stack_sample(text)
        assert lines[0] == "at com.example.A.b(A.java:1)"
