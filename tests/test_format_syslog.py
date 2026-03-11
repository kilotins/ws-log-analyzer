"""Tests for the syslog / journald log format plugin."""
import pytest

from logpilot.formats.syslog import SyslogFormat


@pytest.fixture
def fmt():
    return SyslogFormat()


# ── Sample log lines ──────────────────────────────────────────────────

# RFC 3164 (BSD syslog)
RFC3164_BASIC = "Mar 11 10:15:33 webserver sshd[12345]: Accepted password for user1 from 192.168.1.100 port 22 ssh2"
RFC3164_NO_PID = "Mar 11 10:15:33 webserver kernel: [  123.456789] Out of memory: Kill process 9876"
RFC3164_CRON = "Mar  1 06:25:00 db01 CRON[5678]: (root) CMD (/usr/local/bin/backup.sh)"
RFC3164_SYSLOG = "Mar 11 10:15:33 webserver rsyslogd: message repeated 5 times"
RFC3164_SINGLE_DIGIT_DAY = "Mar  3 10:15:33 host1 sudo:   user1 : COMMAND=/bin/systemctl restart nginx"

# RFC 5424
RFC5424_INFO = "<134>1 2025-03-11T10:15:33.123Z webserver nginx 1234 ID47 [exampleSDID@32473 iut=\"3\"] GET /api/users 200"
RFC5424_ERROR = "<131>1 2025-03-11T10:15:33Z webserver app 5678 ERR001 - Connection refused to database"
RFC5424_EMERG = "<128>1 2025-03-11T10:15:33.000Z webserver kernel - - - kernel panic - not syncing: Fatal exception"
RFC5424_DEBUG = "<143>1 2025-03-11T10:15:33.456+01:00 devbox myapp 999 - - Debug: processing request"
RFC5424_NO_SD = "<134>1 2025-03-11T10:15:33Z host app 123 MSGID - Normal message"
RFC5424_DASH_PID = "<134>1 2025-03-11T10:15:33Z host app - - - No PID message"

# journald short
JOURNALD_KERNEL = "Mar 11 10:15:33 webserver kernel: [  456.789012] eth0: link down"
JOURNALD_SYSTEMD = "Mar 11 10:15:33 webserver systemd[1]: Failed to start Nginx HTTP Server."
JOURNALD_AUDIT = "Mar 11 10:15:33 webserver audit[9999]: USER_AUTH pid=1234 uid=0 msg='op=PAM:authentication'"

# journald with priority
JOURNALD_PRI_INFO = "<6>Mar 11 10:15:33 webserver sshd[1234]: Server listening on port 22"
JOURNALD_PRI_ERR = "<3>Mar 11 10:15:33 webserver myapp[5678]: Failed to connect to database"
JOURNALD_PRI_EMERG = "<0>Mar 11 10:15:33 webserver kernel: kernel panic - not syncing"
JOURNALD_PRI_WARN = "<4>Mar 11 10:15:33 webserver smartd[999]: Device /dev/sda: SMART warning"
JOURNALD_PRI_DEBUG = "<7>Mar 11 10:15:33 webserver myapp[100]: Entering debug mode"

# Kernel stack traces / continuation lines
KERNEL_TRACE_1 = " [  123.456789] Call Trace:"
KERNEL_TRACE_2 = " [  123.456790] ? schedule+0x3e/0xb0"
KERNEL_TRACE_3 = "    at java.lang.Object.wait(Native Method)"

# Non-syslog lines
PLAIN_TEXT = "This is just some random log text with no specific format."
WAS_LINE = "[3/5/25 12:00:00:000 UTC] 0000001a Component I CWWKF0001I: Feature installed."
NGINX_ACCESS = '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /api HTTP/1.1" 200 1234'
JSON_LINE = '{"timestamp":"2025-03-11T10:15:33","level":"INFO","message":"hello"}'

# OOM events
OOM_KILLER = "Mar 11 10:15:33 webserver kernel: [  789.012345] Out of memory: Kill process 9876 (java) score 850 or sacrifice child"
OOM_CGROUP = "Mar 11 10:15:33 webserver kernel: memory cgroup out of memory"
OOM_INVOKED = "Mar 11 10:15:33 webserver kernel: [  789.012] myapp invoked oom-killer: gfp_mask=0x280da, order=0"

# Auth events
AUTH_FAIL = "Mar 11 10:15:33 webserver sshd[12345]: Failed password for root from 10.0.0.1 port 22 ssh2"
AUTH_INVALID = "Mar 11 10:15:33 webserver sshd[12345]: Invalid user admin from 10.0.0.1 port 22"
AUTH_SUDO = "Mar 11 10:15:33 webserver sudo:   user1 : COMMAND=/bin/cat /etc/shadow"
AUTH_PAM = "Mar 11 10:15:33 webserver sshd[12345]: pam_unix(sshd:auth): authentication failure; logname= uid=0"

# Disk events
DISK_FULL = "Mar 11 10:15:33 webserver kernel: [  100.200] EXT4-fs error (device sda1): ext4_journal_check_start"
DISK_NO_SPACE = "Mar 11 10:15:33 webserver rsyslogd: No space left on device"
DISK_IO_ERROR = "Mar 11 10:15:33 webserver kernel: [  200.300] blk_update_request: I/O error, dev sdb"

# Network events
NET_LINK_DOWN = "Mar 11 10:15:33 webserver kernel: [  456.789012] eth0: link down"
NET_REFUSED = "Mar 11 10:15:33 webserver myapp[5678]: connection refused to 10.0.0.1:3306"
NET_UNREACHABLE = "Mar 11 10:15:33 webserver kernel: net_ratelimit: 5 callbacks suppressed. destination unreachable"
NET_FIREWALL = "Mar 11 10:15:33 webserver kernel: iptables: DROP IN=eth0 OUT= SRC=10.0.0.99 DST=192.168.1.1"

# Service events
SVC_FAIL_START = "Mar 11 10:15:33 webserver systemd[1]: Failed to start Nginx HTTP Server."
SVC_FAILED_STATE = "Mar 11 10:15:33 webserver systemd[1]: nginx.service entered failed state."
SVC_SEGFAULT = "Mar 11 10:15:33 webserver kernel: [  999.111] myapp[12345]: segfault at 0000000000000000 ip 00007f rsp 00007f error 4"

# Kernel events
KERNEL_PANIC = "Mar 11 10:15:33 webserver kernel: kernel panic - not syncing: Fatal exception"
KERNEL_BUG = "Mar 11 10:15:33 webserver kernel: BUG: soft lockup - CPU#0 stuck for 22s!"
KERNEL_OOPS = "Mar 11 10:15:33 webserver kernel: [  500.600] Oops: 0002 [#1] SMP"
KERNEL_HW = "Mar 11 10:15:33 webserver kernel: [  700.800] hardware error: corrected error"


# ── Detection ─────────────────────────────────────────────────────────

class TestDetect:
    def test_rfc3164_lines_score_high(self, fmt):
        lines = [RFC3164_BASIC, RFC3164_NO_PID, RFC3164_CRON, RFC3164_SYSLOG]
        assert fmt.detect(lines) > 0.9

    def test_rfc5424_lines_score_high(self, fmt):
        lines = [RFC5424_INFO, RFC5424_ERROR, RFC5424_EMERG, RFC5424_DEBUG]
        assert fmt.detect(lines) > 0.9

    def test_journald_lines_score_high(self, fmt):
        lines = [JOURNALD_KERNEL, JOURNALD_SYSTEMD, JOURNALD_AUDIT]
        assert fmt.detect(lines) > 0.9

    def test_journald_pri_lines_score_high(self, fmt):
        lines = [JOURNALD_PRI_INFO, JOURNALD_PRI_ERR, JOURNALD_PRI_EMERG,
                 JOURNALD_PRI_WARN, JOURNALD_PRI_DEBUG]
        assert fmt.detect(lines) > 0.9

    def test_mixed_rfc3164_and_5424_score_high(self, fmt):
        lines = [RFC3164_BASIC, RFC5424_INFO, JOURNALD_PRI_ERR,
                 RFC3164_CRON, RFC5424_ERROR] * 3
        assert fmt.detect(lines) > 0.9

    def test_plain_text_scores_low(self, fmt):
        lines = [PLAIN_TEXT] * 5
        assert fmt.detect(lines) < 0.1

    def test_was_lines_score_low(self, fmt):
        lines = [WAS_LINE] * 5
        assert fmt.detect(lines) < 0.1

    def test_nginx_lines_score_low(self, fmt):
        lines = [NGINX_ACCESS] * 5
        assert fmt.detect(lines) < 0.1

    def test_json_lines_score_low(self, fmt):
        lines = [JSON_LINE] * 5
        assert fmt.detect(lines) < 0.1

    def test_empty_scores_zero(self, fmt):
        assert fmt.detect([]) == 0.0

    def test_mixed_with_some_plain_moderate(self, fmt):
        lines = [RFC3164_BASIC, PLAIN_TEXT, RFC3164_CRON, PLAIN_TEXT]
        score = fmt.detect(lines)
        assert 0.3 < score < 0.9

    def test_single_digit_day(self, fmt):
        lines = [RFC3164_SINGLE_DIGIT_DAY] * 5
        assert fmt.detect(lines) > 0.9


# ── Timestamp extraction ──────────────────────────────────────────────

class TestExtractTs:
    def test_rfc3164_timestamp(self, fmt):
        ts = fmt.extract_ts(RFC3164_BASIC)
        assert ts == "Mar 11 10:15:33"

    def test_rfc3164_single_digit_day(self, fmt):
        ts = fmt.extract_ts(RFC3164_SINGLE_DIGIT_DAY)
        assert ts == "Mar  3 10:15:33"

    def test_rfc5424_timestamp_with_ms(self, fmt):
        ts = fmt.extract_ts(RFC5424_INFO)
        assert ts == "2025-03-11T10:15:33.123Z"

    def test_rfc5424_timestamp_no_ms(self, fmt):
        ts = fmt.extract_ts(RFC5424_ERROR)
        assert ts == "2025-03-11T10:15:33Z"

    def test_rfc5424_timestamp_with_tz(self, fmt):
        ts = fmt.extract_ts(RFC5424_DEBUG)
        assert ts == "2025-03-11T10:15:33.456+01:00"

    def test_journald_pri_timestamp(self, fmt):
        ts = fmt.extract_ts(JOURNALD_PRI_INFO)
        assert ts == "Mar 11 10:15:33"

    def test_journald_kernel_timestamp(self, fmt):
        ts = fmt.extract_ts(JOURNALD_KERNEL)
        assert ts == "Mar 11 10:15:33"

    def test_plain_text_no_timestamp(self, fmt):
        assert fmt.extract_ts(PLAIN_TEXT) is None

    def test_rfc3164_cron_timestamp(self, fmt):
        ts = fmt.extract_ts(RFC3164_CRON)
        assert ts == "Mar  1 06:25:00"


# ── Level extraction ──────────────────────────────────────────────────

class TestExtractLevel:
    def test_rfc5424_info_priority(self, fmt):
        # <134> = facility 16 * 8 + severity 6 = INFO
        assert fmt.extract_level(RFC5424_INFO) == "INFO"

    def test_rfc5424_error_priority(self, fmt):
        # <131> = facility 16 * 8 + severity 3 = ERROR
        assert fmt.extract_level(RFC5424_ERROR) == "ERROR"

    def test_rfc5424_emerg_priority(self, fmt):
        # <128> = facility 16 * 8 + severity 0 = FATAL
        assert fmt.extract_level(RFC5424_EMERG) == "FATAL"

    def test_rfc5424_debug_priority(self, fmt):
        # <143> = facility 17 * 8 + severity 7 = DEBUG
        assert fmt.extract_level(RFC5424_DEBUG) == "DEBUG"

    def test_journald_pri_info(self, fmt):
        # <6> = severity 6 = INFO
        assert fmt.extract_level(JOURNALD_PRI_INFO) == "INFO"

    def test_journald_pri_error(self, fmt):
        # <3> = severity 3 = ERROR
        assert fmt.extract_level(JOURNALD_PRI_ERR) == "ERROR"

    def test_journald_pri_emerg(self, fmt):
        # <0> = severity 0 = FATAL
        assert fmt.extract_level(JOURNALD_PRI_EMERG) == "FATAL"

    def test_journald_pri_warning(self, fmt):
        # <4> = severity 4 = WARNING
        assert fmt.extract_level(JOURNALD_PRI_WARN) == "WARNING"

    def test_journald_pri_debug(self, fmt):
        # <7> = severity 7 = DEBUG
        assert fmt.extract_level(JOURNALD_PRI_DEBUG) == "DEBUG"

    def test_rfc3164_error_from_message(self, fmt):
        # No priority, but message contains error indicator
        level = fmt.extract_level(SVC_SEGFAULT)
        assert level == "ERROR"

    def test_rfc3164_kernel_panic_fatal(self, fmt):
        assert fmt.extract_level(KERNEL_PANIC) == "FATAL"

    def test_plain_text_no_level(self, fmt):
        assert fmt.extract_level(PLAIN_TEXT) is None

    def test_priority_5_is_info(self, fmt):
        # <5> = severity 5 (Notice) -> INFO
        line = "<5>Mar 11 10:15:33 host daemon: Notice level message"
        assert fmt.extract_level(line) == "INFO"

    def test_priority_1_is_fatal(self, fmt):
        # <1> = severity 1 (Alert) -> FATAL
        line = "<1>Mar 11 10:15:33 host daemon: Alert level message"
        assert fmt.extract_level(line) == "FATAL"

    def test_priority_2_is_critical(self, fmt):
        # <2> = severity 2 (Critical) -> CRITICAL
        line = "<2>Mar 11 10:15:33 host daemon: Critical level message"
        assert fmt.extract_level(line) == "CRITICAL"


# ── is_continuation ───────────────────────────────────────────────────

class TestIsContinuation:
    def test_kernel_call_trace(self, fmt):
        assert fmt.is_continuation(KERNEL_TRACE_1) is True

    def test_kernel_trace_function(self, fmt):
        assert fmt.is_continuation(KERNEL_TRACE_2) is True

    def test_indented_line(self, fmt):
        assert fmt.is_continuation("    continuation of previous message") is True

    def test_tab_indented_line(self, fmt):
        assert fmt.is_continuation("\tmore data here") is True

    def test_normal_rfc3164_not_continuation(self, fmt):
        assert fmt.is_continuation(RFC3164_BASIC) is False

    def test_normal_rfc5424_not_continuation(self, fmt):
        assert fmt.is_continuation(RFC5424_INFO) is False

    def test_empty_line_not_continuation(self, fmt):
        assert fmt.is_continuation("") is False

    def test_journald_pri_not_continuation(self, fmt):
        assert fmt.is_continuation(JOURNALD_PRI_INFO) is False


# ── classify_event ────────────────────────────────────────────────────

class TestClassifyEvent:
    def test_rfc3164_basic(self, fmt):
        result = fmt.classify_event(RFC3164_BASIC)
        assert result["process"] == "sshd"
        assert result["pid"] == "12345"
        assert result["thread_id"] is None
        assert result["exception"] is None
        assert result["root_cause"] is None
        assert isinstance(result["tags"], list)

    def test_rfc5424_with_msgid(self, fmt):
        result = fmt.classify_event(RFC5424_ERROR)
        assert result["level"] == "ERROR"
        assert result["code"] == "ERR001"
        assert result["process"] == "app"
        assert result["pid"] == "5678"

    def test_rfc5424_dash_msgid(self, fmt):
        result = fmt.classify_event(RFC5424_NO_SD)
        assert result["code"] == "MSGID"

    def test_rfc5424_dash_pid(self, fmt):
        result = fmt.classify_event(RFC5424_DASH_PID)
        assert result["pid"] is None

    def test_journald_pri_classify(self, fmt):
        result = fmt.classify_event(JOURNALD_PRI_ERR)
        assert result["level"] == "ERROR"
        assert result["process"] == "myapp"
        assert result["pid"] == "5678"

    def test_rfc3164_no_pid(self, fmt):
        result = fmt.classify_event(RFC3164_NO_PID)
        assert result["process"] == "kernel"
        assert result["pid"] is None

    def test_oom_event_has_oom_tag(self, fmt):
        result = fmt.classify_event(OOM_KILLER)
        assert "OOM" in result["tags"]

    def test_auth_event_has_auth_tag(self, fmt):
        result = fmt.classify_event(AUTH_FAIL)
        assert "Auth" in result["tags"]

    def test_service_failure_has_tag(self, fmt):
        result = fmt.classify_event(SVC_FAIL_START)
        assert "Service" in result["tags"]

    def test_kernel_panic_has_tag(self, fmt):
        result = fmt.classify_event(KERNEL_PANIC)
        assert "Kernel" in result["tags"]

    def test_disk_error_has_tag(self, fmt):
        result = fmt.classify_event(DISK_FULL)
        assert "Disk" in result["tags"]

    def test_network_down_has_tag(self, fmt):
        result = fmt.classify_event(NET_LINK_DOWN)
        assert "Network" in result["tags"]

    def test_tags_are_sorted(self, fmt):
        result = fmt.classify_event(OOM_KILLER)
        assert result["tags"] == sorted(result["tags"])

    def test_plain_text_fallback(self, fmt):
        result = fmt.classify_event(PLAIN_TEXT)
        assert result["level"] is None
        assert result["code"] is None
        assert result["process"] is None


# ── bucket_tags ───────────────────────────────────────────────────────

class TestBucketTags:
    # OOM
    def test_oom_killer_tag(self, fmt):
        assert "OOM" in fmt.bucket_tags(OOM_KILLER)

    def test_oom_cgroup_tag(self, fmt):
        assert "OOM" in fmt.bucket_tags(OOM_CGROUP)

    def test_oom_invoked_tag(self, fmt):
        assert "OOM" in fmt.bucket_tags(OOM_INVOKED)

    # Auth
    def test_auth_failed_password(self, fmt):
        assert "Auth" in fmt.bucket_tags(AUTH_FAIL)

    def test_auth_invalid_user(self, fmt):
        assert "Auth" in fmt.bucket_tags(AUTH_INVALID)

    def test_auth_sudo(self, fmt):
        assert "Auth" in fmt.bucket_tags(AUTH_SUDO)

    def test_auth_pam(self, fmt):
        assert "Auth" in fmt.bucket_tags(AUTH_PAM)

    # Disk
    def test_disk_ext4_error(self, fmt):
        assert "Disk" in fmt.bucket_tags(DISK_FULL)

    def test_disk_no_space(self, fmt):
        assert "Disk" in fmt.bucket_tags(DISK_NO_SPACE)

    def test_disk_io_error(self, fmt):
        assert "Disk" in fmt.bucket_tags(DISK_IO_ERROR)

    # Network
    def test_network_link_down(self, fmt):
        assert "Network" in fmt.bucket_tags(NET_LINK_DOWN)

    def test_network_connection_refused(self, fmt):
        assert "Network" in fmt.bucket_tags(NET_REFUSED)

    def test_network_unreachable(self, fmt):
        assert "Network" in fmt.bucket_tags(NET_UNREACHABLE)

    def test_network_firewall(self, fmt):
        assert "Network" in fmt.bucket_tags(NET_FIREWALL)

    # Service
    def test_service_fail_start(self, fmt):
        assert "Service" in fmt.bucket_tags(SVC_FAIL_START)

    def test_service_failed_state(self, fmt):
        assert "Service" in fmt.bucket_tags(SVC_FAILED_STATE)

    def test_service_segfault(self, fmt):
        assert "Service" in fmt.bucket_tags(SVC_SEGFAULT)

    # Kernel
    def test_kernel_panic_tag(self, fmt):
        assert "Kernel" in fmt.bucket_tags(KERNEL_PANIC)

    def test_kernel_bug_tag(self, fmt):
        assert "Kernel" in fmt.bucket_tags(KERNEL_BUG)

    def test_kernel_oops_tag(self, fmt):
        assert "Kernel" in fmt.bucket_tags(KERNEL_OOPS)

    def test_kernel_hw_error_tag(self, fmt):
        assert "Kernel" in fmt.bucket_tags(KERNEL_HW)

    # No false positives
    def test_normal_info_no_tags(self, fmt):
        tags = fmt.bucket_tags(RFC3164_SYSLOG)
        assert len(tags) == 0

    def test_normal_cron_no_tags(self, fmt):
        tags = fmt.bucket_tags(RFC3164_CRON)
        assert len(tags) == 0


# ── Registry integration ──────────────────────────────────────────────

class TestRegistry:
    def test_syslog_format_implements_protocol(self):
        from logpilot.formats.base import LogFormat
        fmt = SyslogFormat()
        assert isinstance(fmt, LogFormat)

    def test_syslog_has_required_attributes(self):
        fmt = SyslogFormat()
        assert fmt.name == "syslog"
        assert fmt.description == "syslog (RFC 3164/5424, journald)"

    def test_detect_returns_float(self, fmt):
        score = fmt.detect([RFC3164_BASIC])
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0
