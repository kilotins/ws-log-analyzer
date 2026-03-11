"""Tests for the Enonic XP log format plugin."""
import pytest

from logpilot.formats.enonic import EnonicFormat
from logpilot.formats.log4j import Log4jFormat


@pytest.fixture
def fmt():
    return EnonicFormat()


@pytest.fixture
def log4j_fmt():
    return Log4jFormat()


# ── Detection ──────────────────────────────────────────────────────────

class TestDetect:
    def test_enonic_server_log_scores_high(self, fmt):
        lines = [
            "2025-03-11 10:15:33.123 INFO  [main] c.e.xp.core.CoreService - Starting Enonic XP",
            "2025-03-11 10:15:34.456 INFO  [main] c.e.xp.repo.RepositoryService - Initializing repositories",
            "2025-03-11 10:15:35.789 INFO  [main] c.e.xp.cluster.ClusterService - Cluster health: GREEN",
        ]
        assert fmt.detect(lines) > 0.5

    def test_enonic_abbreviated_logger(self, fmt):
        lines = [
            "2025-03-11 10:15:33.123 INFO  [main] c.e.x.core.Service - Starting",
            "2025-03-11 10:15:34.456 WARN  [main] c.e.x.repo.RepoService - Slow",
        ]
        assert fmt.detect(lines) > 0.5

    def test_enonic_full_package_logger(self, fmt):
        lines = [
            "2025-03-11 10:15:33.123 INFO  [main] com.enonic.xp.core.CoreService - Initializing",
            "2025-03-11 10:15:34.456 INFO  [main] com.enonic.xp.repo.RepoService - Ready",
        ]
        assert fmt.detect(lines) > 0.5

    def test_enonic_keywords_boost_score(self, fmt):
        lines = [
            "2025-03-11 10:15:33.123 INFO  [main] c.e.xp.repo.Repo - blobStore initialized",
            "2025-03-11 10:15:34.456 INFO  [main] c.e.xp.cluster.Health - cluster.health: GREEN",
            "2025-03-11 10:15:35.789 INFO  [main] c.e.xp.repo.Repo - repository system ready",
        ]
        assert fmt.detect(lines) > 0.7

    def test_ncsa_jetty_lines_detected(self, fmt):
        lines = [
            '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /site/default/draft/_/asset/com.enonic.xp/style.css HTTP/1.1" 200 1234',
            '192.168.1.1 - - [11/Mar/2025:10:15:34 +0100] "POST /site/default/draft/_/service/com.enonic.xp/upload HTTP/1.1" 201 0',
        ]
        assert fmt.detect(lines) > 0.3

    def test_enonic_beats_log4j_for_enonic_content(self, fmt, log4j_fmt):
        """Enonic format must score higher than plain Log4j for Enonic logs."""
        lines = [
            "2025-03-11 10:15:33.123 INFO  [main] c.e.xp.core.CoreService - Starting Enonic XP",
            "2025-03-11 10:15:34.456 INFO  [main] c.e.xp.repo.RepositoryService - Initializing",
            "2025-03-11 10:15:35.789 WARN  [pool-1] c.e.xp.elasticsearch.Client - Cluster YELLOW",
            "2025-03-11 10:15:36.012 INFO  [main] c.e.xp.app.AppService - Application started",
            "2025-03-11 10:15:37.345 ERROR [pool-2] c.e.xp.content.ContentService - Publish failed",
        ]
        enonic_score = fmt.detect(lines)
        log4j_score = log4j_fmt.detect(lines)
        assert enonic_score > log4j_score

    def test_enonic_beats_log4j_with_full_package(self, fmt, log4j_fmt):
        lines = [
            "2025-03-11 10:15:33.123 INFO  [main] com.enonic.xp.core.CoreService - Starting",
            "2025-03-11 10:15:34.456 INFO  [main] com.enonic.xp.repo.RepositoryService - Init",
        ]
        assert fmt.detect(lines) > log4j_fmt.detect(lines)

    def test_plain_log4j_scores_zero(self, fmt):
        """Plain Log4j logs without Enonic markers should score 0."""
        lines = [
            "2025-03-11 10:15:33,123 ERROR [main] com.example.App - Connection failed",
            "2025-03-11 10:15:34,456 INFO  [main] com.example.App - Retrying",
        ]
        assert fmt.detect(lines) == 0.0

    def test_spring_boot_scores_zero(self, fmt):
        lines = [
            "2025-03-11 10:15:33.123  INFO 12345 --- [main] c.e.app.MyApplication : Starting",
            "2025-03-11 10:15:34.456  INFO 12345 --- [main] c.e.app.MyApplication : Started",
        ]
        assert fmt.detect(lines) == 0.0

    def test_was_format_scores_zero(self, fmt):
        lines = [
            "[3/5/25 12:00:00:000 UTC] 0000001a Component I SRVE0242I: Starting",
            "[3/5/25 12:00:01:000 UTC] 0000001a Component E CWWKE0701E: Error",
        ]
        assert fmt.detect(lines) == 0.0

    def test_empty_scores_zero(self, fmt):
        assert fmt.detect([]) == 0.0

    def test_mixed_enonic_and_jetty_lines(self, fmt):
        lines = [
            "2025-03-11 10:15:33.123 INFO  [main] c.e.xp.core.CoreService - Starting",
            '192.168.1.1 - - [11/Mar/2025:10:15:34 +0100] "GET /site/default/draft/ HTTP/1.1" 200 5678',
            "2025-03-11 10:15:35.789 ERROR [pool-1] c.e.xp.repo.RepositoryService - Failed",
        ]
        assert fmt.detect(lines) > 0.5

    def test_enonic_elasticsearch_keyword(self, fmt):
        lines = [
            "2025-03-11 10:15:33.123 INFO  [main] c.e.xp.elastic.ESClient - elasticsearch cluster ready",
        ]
        assert fmt.detect(lines) > 0.3


# ── Timestamp Extraction ──────────────────────────────────────────────

class TestExtractTs:
    def test_logback_full_iso_dot(self, fmt):
        line = "2025-03-11 10:15:33.123 INFO  [main] c.e.xp.core.Service - Starting"
        assert fmt.extract_ts(line) == "2025-03-11 10:15:33.123"

    def test_logback_full_iso_comma(self, fmt):
        line = "2025-03-11 10:15:33,123 ERROR [main] c.e.xp.core.Service - Failed"
        assert fmt.extract_ts(line) == "2025-03-11 10:15:33,123"

    def test_logback_iso_t_separator(self, fmt):
        line = "2025-03-11T10:15:33.123 INFO  [main] c.e.xp.core.Service - OK"
        assert fmt.extract_ts(line) == "2025-03-11T10:15:33.123"

    def test_logback_time_only(self, fmt):
        line = "10:15:33.123 INFO  c.e.xp.core.Service - Starting"
        assert fmt.extract_ts(line) == "10:15:33.123"

    def test_ncsa_bracket_timestamp(self, fmt):
        line = '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /site/default/draft/ HTTP/1.1" 200 1234'
        assert fmt.extract_ts(line) == "11/Mar/2025:10:15:33 +0100"

    def test_no_timestamp(self, fmt):
        line = "\tat com.enonic.xp.core.Service.init(Service.java:42)"
        assert fmt.extract_ts(line) is None

    def test_stacktrace_no_timestamp(self, fmt):
        line = "Caused by: java.lang.NullPointerException: value is null"
        assert fmt.extract_ts(line) is None


# ── Level Extraction ──────────────────────────────────────────────────

class TestExtractLevel:
    @pytest.mark.parametrize("level", ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"])
    def test_all_logback_levels(self, fmt, level):
        line = f"2025-03-11 10:15:33.123 {level} [main] c.e.xp.core.Service - message"
        assert fmt.extract_level(line) == level

    def test_ncsa_200_is_info(self, fmt):
        line = '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /site/ HTTP/1.1" 200 1234'
        assert fmt.extract_level(line) == "INFO"

    def test_ncsa_301_is_info(self, fmt):
        line = '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /old HTTP/1.1" 301 0'
        assert fmt.extract_level(line) == "INFO"

    def test_ncsa_404_is_warn(self, fmt):
        line = '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /missing HTTP/1.1" 404 0'
        assert fmt.extract_level(line) == "WARN"

    def test_ncsa_403_is_warn(self, fmt):
        line = '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /admin HTTP/1.1" 403 0'
        assert fmt.extract_level(line) == "WARN"

    def test_ncsa_500_is_error(self, fmt):
        line = '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /api HTTP/1.1" 500 0'
        assert fmt.extract_level(line) == "ERROR"

    def test_ncsa_503_is_error(self, fmt):
        line = '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /api HTTP/1.1" 503 0'
        assert fmt.extract_level(line) == "ERROR"

    def test_no_level(self, fmt):
        line = "\tat com.enonic.xp.core.Service.init(Service.java:42)"
        assert fmt.extract_level(line) is None


# ── Continuation Detection ────────────────────────────────────────────

class TestIsContinuation:
    def test_stacktrace_line(self, fmt):
        assert fmt.is_continuation("\tat com.enonic.xp.core.Service.init(Service.java:42)")

    def test_caused_by(self, fmt):
        assert fmt.is_continuation("Caused by: java.lang.NullPointerException: value is null")

    def test_plain_continuation(self, fmt):
        assert fmt.is_continuation("    some continued message text")

    def test_new_logback_event_not_continuation(self, fmt):
        assert not fmt.is_continuation(
            "2025-03-11 10:15:33.123 ERROR [main] c.e.xp.core.Service - Failed"
        )

    def test_new_logback_short_not_continuation(self, fmt):
        assert not fmt.is_continuation(
            "10:15:33.123 INFO  c.e.xp.core.Service - Started"
        )

    def test_ncsa_line_not_continuation(self, fmt):
        assert not fmt.is_continuation(
            '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /site/ HTTP/1.1" 200 1234'
        )

    def test_multiline_message_is_continuation(self, fmt):
        assert fmt.is_continuation("  Error details: connection refused to host")

    def test_suppressed_is_continuation(self, fmt):
        assert fmt.is_continuation("\t... 42 more")


# ── Event Classification ──────────────────────────────────────────────

class TestClassifyEvent:
    def test_basic_enonic_event(self, fmt):
        text = "2025-03-11 10:15:33.123 ERROR [pool-1] c.e.xp.repo.RepositoryService - Repository init failed"
        result = fmt.classify_event(text)
        assert result["level"] == "ERROR"
        assert result["thread_id"] == "pool-1"
        assert result["code"] is None
        assert result["logger"] == "c.e.xp.repo.RepositoryService"

    def test_enonic_event_with_exception(self, fmt):
        text = (
            "2025-03-11 10:15:33.123 ERROR [pool-1] c.e.xp.repo.RepositoryService - Failed\n"
            "com.enonic.xp.repository.RepositoryNotFoundException: Repository not found: my-repo\n"
            "\tat com.enonic.xp.repo.impl.RepositoryServiceImpl.get(RepositoryServiceImpl.java:42)\n"
            "\tat com.enonic.xp.repo.impl.RepositoryServiceImpl.init(RepositoryServiceImpl.java:10)"
        )
        result = fmt.classify_event(text)
        assert result["level"] == "ERROR"
        assert result["exception"] == "com.enonic.xp.repository.RepositoryNotFoundException"
        assert result["root_cause"] is None

    def test_enonic_event_with_caused_by(self, fmt):
        text = (
            "2025-03-11 10:15:33.123 ERROR [pool-1] c.e.xp.index.IndexService - Index update failed\n"
            "com.enonic.xp.index.IndexException: Failed to update index\n"
            "\tat com.enonic.xp.index.impl.IndexServiceImpl.update(IndexServiceImpl.java:55)\n"
            "Caused by: org.elasticsearch.ElasticsearchException: cluster not ready\n"
            "\tat org.elasticsearch.client.RestClient.send(RestClient.java:200)\n"
            "Caused by: java.net.ConnectException: Connection refused\n"
            "\tat java.net.Socket.connect(Socket.java:100)"
        )
        result = fmt.classify_event(text)
        assert result["exception"] == "com.enonic.xp.index.IndexException"
        assert result["root_cause"] == "java.net.ConnectException"

    def test_ncsa_event_classification(self, fmt):
        text = '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /site/default/draft/ HTTP/1.1" 500 0'
        result = fmt.classify_event(text)
        assert result["level"] == "ERROR"
        # Thread should not pick up the NCSA timestamp bracket
        assert result["thread_id"] is None

    def test_ncsa_200_event(self, fmt):
        text = '10.0.0.1 - admin [11/Mar/2025:10:15:33 +0100] "GET /admin/tool HTTP/1.1" 200 4567'
        result = fmt.classify_event(text)
        assert result["level"] == "INFO"

    def test_event_with_full_package_logger(self, fmt):
        text = "2025-03-11 10:15:33.123 INFO  [main] com.enonic.xp.core.CoreService - Enonic XP started"
        result = fmt.classify_event(text)
        assert result["level"] == "INFO"
        assert result["logger"] == "com.enonic.xp.core.CoreService"

    def test_event_tags_included(self, fmt):
        text = (
            "2025-03-11 10:15:33.123 ERROR [pool-1] c.e.xp.repo.RepoService - blobStore error\n"
            "com.enonic.xp.repository.RepositoryNotFoundException: Not found"
        )
        result = fmt.classify_event(text)
        assert "Enonic/Repo" in result["tags"]

    def test_event_no_logger(self, fmt):
        text = "2025-03-11 10:15:33.123 INFO  [main] - Simple message"
        result = fmt.classify_event(text)
        assert result["level"] == "INFO"


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
        assert "SSL/TLS" in fmt.bucket_tags(text)

    def test_ssl_cert_expired(self, fmt):
        text = "SSL certificate expired for host example.com"
        assert "SSL/TLS" in fmt.bucket_tags(text)

    def test_cluster_health_tag(self, fmt):
        text = "Cluster health changed to RED: cluster.health status"
        assert "Enonic/Cluster" in fmt.bucket_tags(text)

    def test_cluster_node_disconnected(self, fmt):
        text = "Node disconnected from cluster: node.disconnected event"
        assert "Enonic/Cluster" in fmt.bucket_tags(text)

    def test_cluster_no_node_available(self, fmt):
        text = "org.elasticsearch.client.transport.NoNodeAvailableException: No node available"
        assert "Enonic/Cluster" in fmt.bucket_tags(text)

    def test_cluster_elasticsearch_red(self, fmt):
        text = "elasticsearch cluster status is red"
        assert "Enonic/Cluster" in fmt.bucket_tags(text)

    def test_repo_tag(self, fmt):
        text = "com.enonic.xp.repository.RepositoryNotFoundException: Repository not found"
        assert "Enonic/Repo" in fmt.bucket_tags(text)

    def test_repo_blobstore(self, fmt):
        text = "Failed to read from blobStore segment"
        assert "Enonic/Repo" in fmt.bucket_tags(text)

    def test_repo_snapshot(self, fmt):
        text = "Creating snapshot of repository system"
        assert "Enonic/Repo" in fmt.bucket_tags(text)

    def test_repo_vacuum(self, fmt):
        text = "Running vacuum on repository data"
        assert "Enonic/Repo" in fmt.bucket_tags(text)

    def test_index_tag(self, fmt):
        text = "com.enonic.xp.index.IndexException: Failed to create index"
        assert "Enonic/Index" in fmt.bucket_tags(text)

    def test_index_reindex(self, fmt):
        text = "Starting reindex of branch master"
        tags = fmt.bucket_tags(text)
        assert "Enonic/Index" in tags

    def test_index_search_exception(self, fmt):
        text = "SearchException: Query failed for content type"
        assert "Enonic/Index" in fmt.bucket_tags(text)

    def test_content_publish(self, fmt):
        text = "content.publish completed for 5 items"
        assert "Enonic/Content" in fmt.bucket_tags(text)

    def test_content_not_found(self, fmt):
        text = "ContentNotFoundException: Content /my-site/page not found"
        assert "Enonic/Content" in fmt.bucket_tags(text)

    def test_content_access_exception(self, fmt):
        text = "ContentAccessException: User does not have access to /admin"
        assert "Enonic/Content" in fmt.bucket_tags(text)

    def test_http_jetty_tag(self, fmt):
        text = "org.eclipse.jetty.server.HttpChannel - Request processing error"
        assert "Enonic/HTTP" in fmt.bucket_tags(text)

    def test_http_jetty_eof(self, fmt):
        text = "org.eclipse.jetty.io.EofException: Early EOF"
        assert "Enonic/HTTP" in fmt.bucket_tags(text)

    def test_http_ncsa_500(self, fmt):
        text = '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /api HTTP/1.1" 500 0'
        assert "Enonic/HTTP" in fmt.bucket_tags(text)

    def test_http_ncsa_404(self, fmt):
        text = '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /missing HTTP/1.1" 404 0'
        assert "Enonic/HTTP" in fmt.bucket_tags(text)

    def test_ncsa_200_no_http_tag(self, fmt):
        text = '192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /site/ HTTP/1.1" 200 1234'
        assert "Enonic/HTTP" not in fmt.bucket_tags(text)

    def test_no_tags(self, fmt):
        text = "2025-03-11 10:15:33.123 INFO [main] c.e.xp.core.Service - Started successfully"
        tags = fmt.bucket_tags(text)
        assert len(tags) == 0

    def test_multiple_tags(self, fmt):
        text = (
            "com.enonic.xp.repository.RepositoryNotFoundException: Repo error\n"
            "java.lang.OutOfMemoryError: Java heap space"
        )
        tags = fmt.bucket_tags(text)
        assert "Enonic/Repo" in tags
        assert "OOM/GC" in tags


# ── Integration: Registry ─────────────────────────────────────────────

class TestRegistry:
    def test_enonic_registered(self):
        from logpilot.formats import register_format, list_formats, get_format
        fmt = EnonicFormat()
        register_format(fmt)
        names = [f["name"] for f in list_formats()]
        assert "enonic" in names
        retrieved = get_format("enonic")
        assert retrieved.name == "enonic"

    def test_detect_enonic_log(self):
        from logpilot.formats import register_format, detect_format
        # Ensure registered
        try:
            from logpilot.formats import get_format
            get_format("enonic")
        except KeyError:
            register_format(EnonicFormat())

        lines = [
            "2025-03-11 10:15:33.123 INFO  [main] c.e.xp.core.CoreService - Starting Enonic XP",
            "2025-03-11 10:15:34.456 INFO  [main] c.e.xp.repo.RepositoryService - Initializing",
            "2025-03-11 10:15:35.789 WARN  [pool-1] c.e.xp.elasticsearch.Client - Cluster YELLOW",
            "2025-03-11 10:15:36.012 INFO  [main] c.e.xp.app.AppService - App started",
            "2025-03-11 10:15:37.345 ERROR [pool-2] c.e.xp.content.ContentService - Publish failed",
        ]
        detected = detect_format(lines)
        assert detected.name == "enonic"

    def test_detect_plain_log4j_not_enonic(self):
        from logpilot.formats import detect_format
        lines = [
            "2025-03-11 10:15:33,123 ERROR [main] com.example.App - Connection failed",
            "2025-03-11 10:15:34,456 INFO  [main] com.example.App - Retrying",
            "2025-03-11 10:15:35,789 WARN  [pool-1] com.example.Pool - Timeout",
        ]
        detected = detect_format(lines)
        assert detected.name != "enonic"
