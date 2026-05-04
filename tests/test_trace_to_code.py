"""M50 P1: Tests for logpilot/trace_to_code.py

Tests CodeLocation dataclass, _parse_line(), and extract_code_locations()
covering Java frames, Python frames, framework filtering, deduplication,
and integration with real scenario fixture events.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from logpilot.event import LogEvent
from logpilot.trace_to_code import (
    CodeLocation,
    extract_code_locations,
    _parse_line,
)


SCENARIO_DIR = Path(__file__).parent / "fixtures" / "scenario"


# ── Helpers ───────────────────────────────────────────────────────────


def _event(text: str, level: str = "ERROR") -> LogEvent:
    return LogEvent(text=text, level=level)


# ── _parse_line: Java frames ──────────────────────────────────────────


class TestParseLineJava:
    def test_java_frame_with_line_number(self):
        line = "    at com.myapp.dao.OrderDAO.save(OrderDAO.java:67)"
        loc = _parse_line(line)
        assert loc is not None
        assert loc.file_hint == "OrderDAO.java"
        assert loc.line == 67
        assert loc.class_name == "com.myapp.dao.OrderDAO"
        assert loc.method == "save"
        assert loc.language == "java"

    def test_java_frame_without_line_number(self):
        line = "    at com.myapp.Main.run(Main.java)"
        loc = _parse_line(line)
        assert loc is not None
        assert loc.file_hint == "Main.java"
        assert loc.line is None
        assert loc.class_name == "com.myapp.Main"
        assert loc.method == "run"

    def test_java_frame_init_method(self):
        line = "    at com.myapp.Foo.<init>(Foo.java:10)"
        loc = _parse_line(line)
        assert loc is not None
        assert loc.method == "<init>"
        assert loc.line == 10
        assert loc.class_name == "com.myapp.Foo"

    def test_java_frame_source_line_stripped(self):
        line = "        at com.myapp.Service.handle(Service.java:99)"
        loc = _parse_line(line)
        assert loc is not None
        assert loc.source_line == "at com.myapp.Service.handle(Service.java:99)"

    def test_java_frame_nested_class_with_dollar(self):
        line = "    at com.myapp.Outer$Inner.call(Outer.java:55)"
        loc = _parse_line(line)
        assert loc is not None
        assert loc.class_name == "com.myapp.Outer$Inner"
        assert loc.method == "call"

    def test_java_frame_deep_package(self):
        line = "    at com.myapp.service.payment.dao.impl.OrderDAOImpl.persist(OrderDAOImpl.java:200)"
        loc = _parse_line(line)
        assert loc is not None
        assert loc.file_hint == "OrderDAOImpl.java"
        assert loc.line == 200


# ── _parse_line: Framework filtering ─────────────────────────────────


class TestParseLineJavaFrameworkFilter:
    def test_java_lang_filtered(self):
        line = "    at java.lang.Thread.run(Thread.java:750)"
        assert _parse_line(line) is None

    def test_java_util_filtered(self):
        line = "    at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)"
        assert _parse_line(line) is None

    def test_sun_reflect_filtered(self):
        line = "    at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)"
        assert _parse_line(line) is None

    def test_ibm_ws_filtered(self):
        line = "    at com.ibm.ws.webcontainer.filter.FilterChain.doFilter(FilterChain.java:100)"
        assert _parse_line(line) is None

    def test_ibm_io_filtered(self):
        line = "    at com.ibm.io.async.AsyncChannelGroup.processEvents(AsyncChannelGroup.java:342)"
        assert _parse_line(line) is None

    def test_apache_catalina_filtered(self):
        line = "    at org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:167)"
        assert _parse_line(line) is None

    def test_spring_cglib_filtered(self):
        line = "    at org.springframework.cglib.proxy.MethodProxy.invoke(MethodProxy.java:218)"
        assert _parse_line(line) is None

    def test_eclipse_jetty_filtered(self):
        line = "    at org.eclipse.jetty.server.HttpChannel.handle(HttpChannel.java:374)"
        assert _parse_line(line) is None

    def test_user_spring_not_filtered(self):
        # org.springframework.web is NOT in the skip list — user code can use that package
        line = "    at org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1089)"
        loc = _parse_line(line)
        # org.springframework.web is not blocked, only .cglib. and .aop.
        assert loc is not None


# ── _parse_line: Python frames ────────────────────────────────────────


class TestParseLinePython:
    def test_python_frame_with_function(self):
        line = '  File "/app/orders/tasks.py", line 45, in process_order'
        loc = _parse_line(line)
        assert loc is not None
        assert loc.file_hint == "tasks.py"
        assert loc.line == 45
        assert loc.method == "process_order"
        assert loc.language == "python"
        assert loc.class_name is None

    def test_python_frame_without_function(self):
        line = '  File "/app/main.py", line 1'
        loc = _parse_line(line)
        assert loc is not None
        assert loc.file_hint == "main.py"
        assert loc.line == 1
        assert loc.method is None

    def test_python_frame_source_line_preserved(self):
        line = '  File "/app/orders/tasks.py", line 45, in process_order'
        loc = _parse_line(line)
        assert loc is not None
        assert loc.source_line == 'File "/app/orders/tasks.py", line 45, in process_order'

    def test_python_stdlib_filtered(self):
        line = '  File "/usr/lib/python3.11/importlib/__init__.py", line 88, in import_module'
        assert _parse_line(line) is None

    def test_python_site_packages_filtered(self):
        line = '  File "/app/venv/lib/python3.11/site-packages/flask/app.py", line 100, in wsgi_app'
        assert _parse_line(line) is None

    def test_python_dist_packages_filtered(self):
        line = '  File "/usr/local/lib/python3.9/dist-packages/celery/app/trace.py", line 412, in trace_task'
        assert _parse_line(line) is None

    def test_python_frozen_filtered(self):
        line = '  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed'
        assert _parse_line(line) is None


# ── _parse_line: Non-stacktrace lines ────────────────────────────────


class TestParseLineNonStacktrace:
    def test_plain_log_line_returns_none(self):
        assert _parse_line("2025-03-15 14:30:12 ERROR Something went wrong") is None

    def test_caused_by_line_returns_none(self):
        # Caused by: lines are not stack frames
        assert _parse_line("    Caused by: java.sql.SQLException: Timeout") is None

    def test_exception_class_line_returns_none(self):
        assert _parse_line("java.lang.NullPointerException: null") is None

    def test_empty_string_returns_none(self):
        assert _parse_line("") is None

    def test_whitespace_only_returns_none(self):
        assert _parse_line("   ") is None


# ── CodeLocation dataclass ────────────────────────────────────────────


class TestCodeLocationDataclass:
    def test_key_uniqueness_different_line(self):
        a = CodeLocation(file_hint="Foo.java", line=10, method="doStuff", language="java")
        b = CodeLocation(file_hint="Foo.java", line=11, method="doStuff", language="java")
        assert a.key() != b.key()

    def test_key_uniqueness_different_method(self):
        a = CodeLocation(file_hint="Foo.java", line=10, method="doStuff", language="java")
        b = CodeLocation(file_hint="Foo.java", line=10, method="doOther", language="java")
        assert a.key() != b.key()

    def test_key_same_for_identical_location(self):
        a = CodeLocation(file_hint="Foo.java", line=10, method="doStuff", language="java")
        b = CodeLocation(file_hint="Foo.java", line=10, method="doStuff", language="java")
        assert a.key() == b.key()

    def test_search_terms_returns_method_and_short_class(self):
        loc = CodeLocation(
            file_hint="OrderDAO.java",
            line=67,
            class_name="com.myapp.dao.OrderDAO",
            method="save",
            language="java",
        )
        terms = loc.search_terms()
        assert "save" in terms
        assert "OrderDAO" in terms

    def test_search_terms_skips_init(self):
        loc = CodeLocation(
            file_hint="Foo.java",
            line=5,
            class_name="com.myapp.Foo",
            method="<init>",
            language="java",
        )
        terms = loc.search_terms()
        assert "<init>" not in terms
        assert "Foo" in terms

    def test_search_terms_skips_dunder_init(self):
        loc = CodeLocation(
            file_hint="tasks.py",
            line=1,
            method="__init__",
            language="python",
        )
        terms = loc.search_terms()
        assert "__init__" not in terms

    def test_search_terms_no_method_no_class(self):
        loc = CodeLocation(file_hint="tasks.py", line=1, language="python")
        assert loc.search_terms() == []

    def test_search_terms_short_class_name_skipped_if_too_short(self):
        # class name fragment of 2 chars or fewer should be excluded
        loc = CodeLocation(
            file_hint="A.java",
            line=1,
            class_name="com.myapp.AB",
            method="doSomething",
            language="java",
        )
        terms = loc.search_terms()
        # "AB" is only 2 chars — should be excluded per implementation (len > 2)
        assert "AB" not in terms
        assert "doSomething" in terms


# ── extract_code_locations ────────────────────────────────────────────


class TestExtractCodeLocations:
    def test_empty_events_returns_empty(self):
        assert extract_code_locations([]) == []

    def test_event_with_no_stacktrace(self):
        events = [_event("INFO  Something happened normally")]
        assert extract_code_locations(events) == []

    def test_event_with_none_text_skipped(self):
        events = [LogEvent(text="", level="ERROR")]
        assert extract_code_locations(events) == []

    def test_single_java_frame_extracted(self):
        text = (
            "ERROR Something failed\n"
            "    at com.myapp.dao.OrderDAO.save(OrderDAO.java:67)\n"
            "    at java.lang.Thread.run(Thread.java:750)\n"
        )
        locs = extract_code_locations([_event(text)])
        assert len(locs) == 1
        assert locs[0].file_hint == "OrderDAO.java"
        assert locs[0].line == 67

    def test_deduplication_same_file_and_line(self):
        frame = "    at com.myapp.Service.handle(Service.java:10)\n"
        events = [_event("Error A\n" + frame), _event("Error B\n" + frame)]
        locs = extract_code_locations(events)
        assert len(locs) == 1

    def test_no_dedup_different_lines(self):
        events = [
            _event("Error\n    at com.myapp.Service.handle(Service.java:10)"),
            _event("Error\n    at com.myapp.Service.handle(Service.java:20)"),
        ]
        locs = extract_code_locations(events)
        assert len(locs) == 2

    def test_max_locations_limit(self):
        frames = "\n".join(
            f"    at com.myapp.Service.method{i}(Service.java:{i})"
            for i in range(200)
        )
        events = [_event("Error\n" + frames)]
        locs = extract_code_locations(events, max_locations=5)
        assert len(locs) == 5

    def test_multiple_events_combined(self):
        events = [
            _event("Error A\n    at com.myapp.ServiceA.doX(ServiceA.java:1)"),
            _event("Error B\n    at com.myapp.ServiceB.doY(ServiceB.java:2)"),
        ]
        locs = extract_code_locations(events)
        assert len(locs) == 2
        hints = {l.file_hint for l in locs}
        assert hints == {"ServiceA.java", "ServiceB.java"}

    def test_mixed_java_and_python_events(self):
        java_event = _event(
            "ERROR Java failed\n"
            "    at com.myapp.OrderService.process(OrderService.java:88)\n"
        )
        python_event = _event(
            "ERROR Python failed\n"
            '  File "/app/worker/tasks.py", line 55, in run_task\n'
        )
        locs = extract_code_locations([java_event, python_event])
        languages = {l.language for l in locs}
        assert "java" in languages
        assert "python" in languages
        assert len(locs) == 2

    def test_framework_frames_excluded_entirely(self):
        text = (
            "ERROR DB pool exhausted\n"
            "    at java.lang.Thread.run(Thread.java:750)\n"
            "    at com.ibm.ws.webcontainer.filter.FilterChain.doFilter(FilterChain.java:100)\n"
            "    at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\n"
        )
        locs = extract_code_locations([_event(text)])
        assert locs == []

    def test_chronological_order_preserved(self):
        events = [
            _event("E1\n    at com.myapp.Alpha.first(Alpha.java:1)"),
            _event("E2\n    at com.myapp.Beta.second(Beta.java:2)"),
            _event("E3\n    at com.myapp.Gamma.third(Gamma.java:3)"),
        ]
        locs = extract_code_locations(events)
        assert locs[0].file_hint == "Alpha.java"
        assert locs[1].file_hint == "Beta.java"
        assert locs[2].file_hint == "Gamma.java"


# ── Integration: real scenario fixture ───────────────────────────────


class TestExtractCodeLocationsIntegration:
    @pytest.fixture(scope="class")
    def scenario_events(self):
        from logpilot.parser import parse_file
        events = []
        for f in sorted(SCENARIO_DIR.iterdir()):
            if f.is_file() and f.suffix == ".log":
                events.extend(parse_file(f))
        return events

    def test_scenario_extracts_locations(self, scenario_events):
        locs = extract_code_locations(scenario_events)
        # Scenario has Java stacktraces — should find at least one user-code location
        assert len(locs) > 0

    def test_scenario_locations_are_user_code(self, scenario_events):
        locs = extract_code_locations(scenario_events)
        for loc in locs:
            # No location should be from framework packages
            if loc.language == "java" and loc.class_name:
                assert not loc.class_name.startswith("java.")
                assert not loc.class_name.startswith("sun.")
                assert not loc.class_name.startswith("com.ibm.ws.")

    def test_scenario_deduplication_applied(self, scenario_events):
        locs = extract_code_locations(scenario_events)
        keys = [loc.key() for loc in locs]
        assert len(keys) == len(set(keys)), "Duplicate keys found — dedup failed"

    def test_scenario_payment_dao_found(self, scenario_events):
        """payment-api.log has com.example.payment.dao.PaymentDAO frame."""
        locs = extract_code_locations(scenario_events)
        files = {l.file_hint for l in locs}
        # PaymentDAO.java appears in the payment-api stacktrace
        assert "PaymentDAO.java" in files

    def test_scenario_stripe_client_found(self, scenario_events):
        """payment-api.log has com.example.payment.gateway.StripeClient frame."""
        locs = extract_code_locations(scenario_events)
        files = {l.file_hint for l in locs}
        assert "StripeClient.java" in files
