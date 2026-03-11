"""Tests for the nginx / Apache log format plugin."""
import pytest

from logpilot.formats.nginx import NginxFormat


@pytest.fixture
def fmt():
    return NginxFormat()


# ── Sample log lines ──────────────────────────────────────────────────

NGINX_ACCESS_200 = '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /api/users HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0 (X11; Linux)"'
NGINX_ACCESS_404 = '10.0.0.1 - frank [11/Mar/2025:10:16:00 +0100] "GET /missing HTTP/1.1" 404 162 "-" "curl/7.81.0"'
NGINX_ACCESS_502 = '172.16.0.5 - - [11/Mar/2025:10:17:01 +0100] "POST /api/submit HTTP/1.1" 502 0 "https://app.example.com/form" "Mozilla/5.0"'
NGINX_ACCESS_504 = '172.16.0.5 - - [11/Mar/2025:10:17:30 +0100] "GET /api/slow HTTP/1.1" 504 0 "-" "Mozilla/5.0"'
NGINX_ACCESS_429 = '10.0.0.99 - - [11/Mar/2025:10:18:00 +0100] "GET /api/search HTTP/1.1" 429 0 "-" "bot/1.0"'

NGINX_ERROR = '2025/03/11 10:15:33 [error] 1234#5678: *99 connect() failed (111: Connection refused) while connecting to upstream, client: 192.168.1.1, server: example.com, request: "GET /api HTTP/1.1", upstream: "http://10.0.0.5:8080/api"'
NGINX_ERROR_CRIT = '2025/03/11 10:20:00 [crit] 1234#5678: *100 SSL_do_handshake() failed (SSL: error:14094410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure)'
NGINX_ERROR_WARN = '2025/03/11 10:21:00 [warn] 1234#0: worker_connections are not enough'
NGINX_ERROR_EMERG = '2025/03/11 10:22:00 [emerg] 1#1: bind() to 0.0.0.0:80 failed (98: Address already in use)'

APACHE_ACCESS = '10.0.0.2 - admin [11/Mar/2025:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 5432 "-" "Mozilla/5.0"'
APACHE_ERROR = '[Tue Mar 11 10:15:33.123456 2025] [proxy:error] [pid 12345] message from proxy'
APACHE_ERROR_WARN = '[Tue Mar 11 10:16:00.000000 2025] [mpm_prefork:notice] [pid 1] Apache/2.4 configured'

PLAIN_TEXT = "This is just some random log text with no specific format."
WAS_LINE = "[3/5/25 12:00:00:000 UTC] 0000001a Component I CWWKF0001I: Feature installed."


# ── Detection ─────────────────────────────────────────────────────────

class TestDetect:
    def test_all_nginx_access_lines_score_high(self, fmt):
        lines = [NGINX_ACCESS_200, NGINX_ACCESS_404, NGINX_ACCESS_502]
        assert fmt.detect(lines) > 0.9

    def test_all_nginx_error_lines_score_high(self, fmt):
        lines = [NGINX_ERROR, NGINX_ERROR_CRIT, NGINX_ERROR_WARN, NGINX_ERROR_EMERG]
        assert fmt.detect(lines) > 0.9

    def test_mixed_access_and_error_score_high(self, fmt):
        lines = [NGINX_ACCESS_200, NGINX_ERROR, NGINX_ACCESS_502, NGINX_ERROR_CRIT,
                 NGINX_ACCESS_404]
        assert fmt.detect(lines) > 0.9

    def test_apache_access_scores_high(self, fmt):
        lines = [APACHE_ACCESS] * 5
        assert fmt.detect(lines) > 0.9

    def test_apache_error_scores_high(self, fmt):
        lines = [APACHE_ERROR, APACHE_ERROR_WARN, APACHE_ERROR]
        assert fmt.detect(lines) > 0.9

    def test_plain_text_scores_low(self, fmt):
        lines = [PLAIN_TEXT] * 5
        assert fmt.detect(lines) < 0.1

    def test_was_lines_score_low(self, fmt):
        lines = [WAS_LINE] * 5
        assert fmt.detect(lines) < 0.1

    def test_empty_scores_zero(self, fmt):
        assert fmt.detect([]) == 0.0

    def test_mixed_with_some_plain_moderate(self, fmt):
        lines = [NGINX_ACCESS_200, PLAIN_TEXT, NGINX_ACCESS_404, PLAIN_TEXT]
        score = fmt.detect(lines)
        assert 0.3 < score < 0.9


# ── Timestamp extraction ──────────────────────────────────────────────

class TestExtractTs:
    def test_clf_timestamp(self, fmt):
        ts = fmt.extract_ts(NGINX_ACCESS_200)
        assert ts == "11/Mar/2025:10:15:33 +0100"

    def test_nginx_error_timestamp(self, fmt):
        ts = fmt.extract_ts(NGINX_ERROR)
        assert ts == "2025/03/11 10:15:33"

    def test_apache_error_timestamp(self, fmt):
        ts = fmt.extract_ts(APACHE_ERROR)
        assert ts == "Tue Mar 11 10:15:33.123456 2025"

    def test_apache_error_warn_timestamp(self, fmt):
        ts = fmt.extract_ts(APACHE_ERROR_WARN)
        assert ts == "Tue Mar 11 10:16:00.000000 2025"

    def test_plain_text_no_timestamp(self, fmt):
        assert fmt.extract_ts(PLAIN_TEXT) is None

    def test_clf_404_timestamp(self, fmt):
        ts = fmt.extract_ts(NGINX_ACCESS_404)
        assert ts == "11/Mar/2025:10:16:00 +0100"


# ── Level extraction ──────────────────────────────────────────────────

class TestExtractLevel:
    def test_access_200_is_info(self, fmt):
        assert fmt.extract_level(NGINX_ACCESS_200) == "INFO"

    def test_access_404_is_warning(self, fmt):
        assert fmt.extract_level(NGINX_ACCESS_404) == "WARNING"

    def test_access_502_is_error(self, fmt):
        assert fmt.extract_level(NGINX_ACCESS_502) == "ERROR"

    def test_access_504_is_error(self, fmt):
        assert fmt.extract_level(NGINX_ACCESS_504) == "ERROR"

    def test_access_429_is_warning(self, fmt):
        assert fmt.extract_level(NGINX_ACCESS_429) == "WARNING"

    def test_nginx_error_level(self, fmt):
        assert fmt.extract_level(NGINX_ERROR) == "ERROR"

    def test_nginx_crit_level(self, fmt):
        assert fmt.extract_level(NGINX_ERROR_CRIT) == "CRITICAL"

    def test_nginx_warn_level(self, fmt):
        assert fmt.extract_level(NGINX_ERROR_WARN) == "WARNING"

    def test_nginx_emerg_level(self, fmt):
        assert fmt.extract_level(NGINX_ERROR_EMERG) == "FATAL"

    def test_apache_error_level(self, fmt):
        assert fmt.extract_level(APACHE_ERROR) == "ERROR"

    def test_apache_notice_level(self, fmt):
        assert fmt.extract_level(APACHE_ERROR_WARN) == "INFO"

    def test_plain_text_no_level(self, fmt):
        assert fmt.extract_level(PLAIN_TEXT) is None


# ── is_continuation ───────────────────────────────────────────────────

class TestIsContinuation:
    def test_always_false(self, fmt):
        assert fmt.is_continuation(NGINX_ACCESS_200) is False
        assert fmt.is_continuation(NGINX_ERROR) is False
        assert fmt.is_continuation(PLAIN_TEXT) is False
        assert fmt.is_continuation("    at java.lang.Thread.run(Thread.java:748)") is False


# ── classify_event ────────────────────────────────────────────────────

class TestClassifyEvent:
    def test_access_200(self, fmt):
        result = fmt.classify_event(NGINX_ACCESS_200)
        assert result["level"] == "INFO"
        assert result["code"] == "HTTP_200"
        assert result["exception"] is None
        assert result["thread_id"] is None
        assert result["method"] == "GET"
        assert result["path"] == "/api/users"
        assert result["status"] == 200

    def test_access_502(self, fmt):
        result = fmt.classify_event(NGINX_ACCESS_502)
        assert result["level"] == "ERROR"
        assert result["code"] == "HTTP_502"
        assert result["status"] == 502
        assert "HTTP" in result["tags"]

    def test_access_404(self, fmt):
        result = fmt.classify_event(NGINX_ACCESS_404)
        assert result["level"] == "WARNING"
        assert result["code"] == "HTTP_404"
        assert result["status"] == 404
        assert "HTTP" in result["tags"]
        assert result["referrer"] == "-"

    def test_access_429(self, fmt):
        result = fmt.classify_event(NGINX_ACCESS_429)
        assert result["level"] == "WARNING"
        assert result["code"] == "HTTP_429"
        assert "HTTP" in result["tags"]

    def test_nginx_error_upstream(self, fmt):
        result = fmt.classify_event(NGINX_ERROR)
        assert result["level"] == "ERROR"
        assert result["exception"] is None
        assert "Upstream" in result["tags"]

    def test_nginx_error_ssl(self, fmt):
        result = fmt.classify_event(NGINX_ERROR_CRIT)
        assert result["level"] == "CRITICAL"
        assert "SSL/TLS" in result["tags"]

    def test_apache_error(self, fmt):
        result = fmt.classify_event(APACHE_ERROR)
        assert result["level"] == "ERROR"
        assert result["thread_id"] is None
        assert result["exception"] is None

    def test_fallback_plain_text(self, fmt):
        result = fmt.classify_event(PLAIN_TEXT)
        assert result["level"] is None
        assert result["code"] is None


# ── bucket_tags ───────────────────────────────────────────────────────

class TestBucketTags:
    def test_5xx_tags_http(self, fmt):
        tags = fmt.bucket_tags(NGINX_ACCESS_502)
        assert "HTTP" in tags

    def test_4xx_tags_http(self, fmt):
        tags = fmt.bucket_tags(NGINX_ACCESS_404)
        assert "HTTP" in tags

    def test_upstream_tag(self, fmt):
        tags = fmt.bucket_tags(NGINX_ERROR)
        assert "Upstream" in tags

    def test_ssl_tag(self, fmt):
        tags = fmt.bucket_tags(NGINX_ERROR_CRIT)
        assert "SSL/TLS" in tags

    def test_timeout_tag(self, fmt):
        text = 'upstream timed out (110: Connection timed out) while reading response header'
        tags = fmt.bucket_tags(text)
        assert "Timeout" in tags
        assert "Upstream" in tags

    def test_rate_limit_tag(self, fmt):
        text = '2025/03/11 10:15:33 [error] 1234#0: *5 limiting requests, excess: 5.432 by zone "api"'
        tags = fmt.bucket_tags(text)
        assert "RateLimit" in tags

    def test_disk_full_tag(self, fmt):
        text = 'open() "/var/log/nginx/access.log" failed (28: No space left on device)'
        tags = fmt.bucket_tags(text)
        assert "DiskFull" in tags

    def test_permission_tag(self, fmt):
        text = 'open() "/var/www/html/index.html" failed (13: Permission denied)'
        tags = fmt.bucket_tags(text)
        assert "Permission" in tags

    def test_200_access_no_error_tags(self, fmt):
        tags = fmt.bucket_tags(NGINX_ACCESS_200)
        assert "HTTP" not in tags
        assert "Upstream" not in tags
        assert "SSL/TLS" not in tags

    def test_504_has_timeout_tag(self, fmt):
        tags = fmt.bucket_tags(NGINX_ACCESS_504)
        assert "HTTP" in tags
        assert "Timeout" in tags


# ── Registry integration ──────────────────────────────────────────────

class TestRegistry:
    def test_nginx_in_list_formats(self):
        from logpilot.formats import list_formats
        names = [f["name"] for f in list_formats()]
        assert "nginx" in names

    def test_get_format_nginx(self):
        from logpilot.formats import get_format
        fmt = get_format("nginx")
        assert fmt.name == "nginx"

    def test_detect_format_picks_nginx(self):
        from logpilot.formats import detect_format
        lines = [NGINX_ACCESS_200, NGINX_ACCESS_404, NGINX_ACCESS_502,
                 NGINX_ERROR, NGINX_ERROR_CRIT] * 5
        fmt = detect_format(lines)
        assert fmt.name == "nginx"

    def test_detect_format_does_not_pick_nginx_for_was(self):
        from logpilot.formats import detect_format
        lines = [WAS_LINE] * 10
        fmt = detect_format(lines)
        assert fmt.name != "nginx"
