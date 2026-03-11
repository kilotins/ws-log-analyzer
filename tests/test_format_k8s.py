"""Tests for CRI-O / Kubernetes log format plugin."""
import json
import pytest

from logpilot.formats.crio import CRIOFormat


@pytest.fixture
def fmt():
    return CRIOFormat()


# ---------------------------------------------------------------------------
# Sample log lines
# ---------------------------------------------------------------------------

CRIO_FULL = '2025-03-11T10:15:33.123456789+01:00 stderr F Problem: connection refused to database'
CRIO_STDOUT = '2025-03-11T10:15:33.123456789+01:00 stdout F Request handled successfully'
CRIO_PARTIAL_1 = '2025-03-11T10:15:33.123000000Z stdout P This is a very long log line that has been sp'
CRIO_PARTIAL_2 = '2025-03-11T10:15:33.123000000Z stdout F lit across two entries'
CRIO_WITH_LEVEL = '2025-03-11T10:15:33.123456789+01:00 stderr F ERROR com.example.App - NullPointerException'

KLOG_INFO = 'I0311 10:15:33.123456  1 controller.go:123] Reconciling ClusterLogging instance'
KLOG_WARNING = 'W0311 10:15:33.123456  1 reflector.go:789] watch of *v1.Pod ended with: too old resource version'
KLOG_ERROR = 'E0311 10:15:33.123456  1 controller.go:456] Failed to reconcile: context deadline exceeded'
KLOG_FATAL = 'F0311 10:15:33.123456  1 main.go:42] Unable to start controller'

K8S_JSON_LINE = json.dumps({
    "@timestamp": "2025-03-11T10:15:33.123Z",
    "message": "Connection refused",
    "level": "error",
    "hostname": "worker-1.ocp.example.com",
    "kubernetes": {
        "namespace_name": "my-namespace",
        "pod_name": "myapp-abc123",
        "container_name": "myapp",
    },
})

PLAIN_TEXT = 'Just a regular log line with no special format'
JAVA_STACK = '    at com.example.App.handle(App.java:42)'
CAUSED_BY = 'Caused by: java.sql.SQLException: Connection refused'

CRASHLOOP_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F Back-off restarting failed container: CrashLoopBackOff'
OOM_KILLED_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F Container killed due to OOMKilled'
IMAGE_PULL_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F Failed to pull image: ImagePullBackOff'
EVICTED_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F Pod was Evicted due to disk pressure'
FAILED_SCHED_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F FailedScheduling: insufficient cpu'

NETWORK_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F dial tcp 10.0.0.5:5432: connection refused'
DNS_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F dial tcp: lookup mydb.svc.cluster.local: no such host'
TIMEOUT_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F dial tcp 10.0.0.5:5432: i/o timeout'

STORAGE_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F FailedMount: Unable to attach or mount volumes'
PROVISION_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F ProvisioningFailed: storageclass not found'

AUTH_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F Unauthorized: user not authenticated'
FORBIDDEN_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F Forbidden: insufficient permissions'
CERT_EXPIRED_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F certificate has expired or is not yet valid'

HAPROXY_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F HAProxy: backend has no server available'
ROUTE_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F route not admitted: wildcard policy not allowed'

OOM_JAVA_LINE = '2025-03-11T10:15:33.123456789+01:00 stderr F java.lang.OutOfMemoryError: Java heap space'


# ---------------------------------------------------------------------------
# Detection tests
# ---------------------------------------------------------------------------

class TestDetect:
    def test_crio_lines_score_high(self, fmt):
        lines = [CRIO_FULL, CRIO_STDOUT, CRIO_WITH_LEVEL]
        score = fmt.detect(lines)
        assert score >= 0.8

    def test_klog_lines_score_high(self, fmt):
        lines = [KLOG_INFO, KLOG_WARNING, KLOG_ERROR, KLOG_FATAL]
        score = fmt.detect(lines)
        assert score >= 0.8

    def test_k8s_json_scores_high(self, fmt):
        lines = [K8S_JSON_LINE]
        score = fmt.detect(lines)
        assert score >= 0.8

    def test_plain_text_scores_zero(self, fmt):
        lines = [PLAIN_TEXT, 'Another plain line', 'Nothing special']
        score = fmt.detect(lines)
        assert score == 0.0

    def test_mixed_crio_klog_scores_high(self, fmt):
        lines = [CRIO_FULL, KLOG_INFO, CRIO_STDOUT, KLOG_ERROR]
        score = fmt.detect(lines)
        assert score >= 0.8

    def test_empty_lines(self, fmt):
        assert fmt.detect([]) == 0.0


# ---------------------------------------------------------------------------
# Timestamp extraction
# ---------------------------------------------------------------------------

class TestExtractTs:
    def test_crio_timestamp(self, fmt):
        ts = fmt.extract_ts(CRIO_FULL)
        assert ts == '2025-03-11T10:15:33.123456789+01:00'

    def test_crio_utc_timestamp(self, fmt):
        ts = fmt.extract_ts(CRIO_PARTIAL_1)
        assert ts == '2025-03-11T10:15:33.123000000Z'

    def test_klog_timestamp(self, fmt):
        ts = fmt.extract_ts(KLOG_INFO)
        assert ts == '0311 10:15:33.123456'

    def test_k8s_json_timestamp(self, fmt):
        ts = fmt.extract_ts(K8S_JSON_LINE)
        assert ts == '2025-03-11T10:15:33.123Z'

    def test_plain_text_no_timestamp(self, fmt):
        assert fmt.extract_ts(PLAIN_TEXT) is None

    def test_stacktrace_no_timestamp(self, fmt):
        assert fmt.extract_ts(JAVA_STACK) is None


# ---------------------------------------------------------------------------
# Level extraction
# ---------------------------------------------------------------------------

class TestExtractLevel:
    def test_klog_info(self, fmt):
        assert fmt.extract_level(KLOG_INFO) == 'INFO'

    def test_klog_warning(self, fmt):
        assert fmt.extract_level(KLOG_WARNING) == 'WARNING'

    def test_klog_error(self, fmt):
        assert fmt.extract_level(KLOG_ERROR) == 'ERROR'

    def test_klog_fatal(self, fmt):
        assert fmt.extract_level(KLOG_FATAL) == 'FATAL'

    def test_crio_stderr_default_warning(self, fmt):
        # stderr without level keyword in message -> WARNING
        assert fmt.extract_level(CRIO_FULL) == 'WARNING'

    def test_crio_stdout_default_info(self, fmt):
        assert fmt.extract_level(CRIO_STDOUT) == 'INFO'

    def test_crio_with_level_keyword(self, fmt):
        # Message contains ERROR keyword -> should return ERROR
        assert fmt.extract_level(CRIO_WITH_LEVEL) == 'ERROR'

    def test_k8s_json_level(self, fmt):
        assert fmt.extract_level(K8S_JSON_LINE) == 'ERROR'


# ---------------------------------------------------------------------------
# Continuation / partial detection
# ---------------------------------------------------------------------------

class TestIsContinuation:
    def test_crio_partial_flag(self, fmt):
        assert fmt.is_continuation(CRIO_PARTIAL_1) is True

    def test_crio_full_flag(self, fmt):
        assert fmt.is_continuation(CRIO_FULL) is False

    def test_java_stacktrace(self, fmt):
        assert fmt.is_continuation(JAVA_STACK) is True

    def test_caused_by(self, fmt):
        assert fmt.is_continuation(CAUSED_BY) is True

    def test_plain_text(self, fmt):
        assert fmt.is_continuation(PLAIN_TEXT) is False


# ---------------------------------------------------------------------------
# Event classification
# ---------------------------------------------------------------------------

class TestClassifyEvent:
    def test_crio_stderr_level(self, fmt):
        result = fmt.classify_event(CRIO_FULL)
        assert result['level'] == 'WARNING'

    def test_klog_error_level(self, fmt):
        result = fmt.classify_event(KLOG_ERROR)
        assert result['level'] == 'ERROR'

    def test_crashloop_code(self, fmt):
        result = fmt.classify_event(CRASHLOOP_LINE)
        assert result['code'] == 'CrashLoopBackOff'
        assert 'K8s/Pod' in result['tags']

    def test_oomkilled_code(self, fmt):
        result = fmt.classify_event(OOM_KILLED_LINE)
        assert result['code'] == 'OOMKilled'
        assert 'K8s/Pod' in result['tags']
        assert 'OOM/GC' in result['tags']

    def test_imagepullbackoff_code(self, fmt):
        result = fmt.classify_event(IMAGE_PULL_LINE)
        assert result['code'] == 'ImagePullBackOff'
        assert 'K8s/Pod' in result['tags']

    def test_evicted_code(self, fmt):
        result = fmt.classify_event(EVICTED_LINE)
        assert result['code'] == 'Evicted'

    def test_failed_scheduling_code(self, fmt):
        result = fmt.classify_event(FAILED_SCHED_LINE)
        assert result['code'] == 'FailedScheduling'

    def test_k8s_json_metadata(self, fmt):
        result = fmt.classify_event(K8S_JSON_LINE)
        assert result['level'] == 'ERROR'
        assert result.get('namespace') == 'my-namespace'
        assert result.get('pod_name') == 'myapp-abc123'

    def test_java_exception_extraction(self, fmt):
        text = CRIO_WITH_LEVEL + '\n' + JAVA_STACK + '\n' + CAUSED_BY
        result = fmt.classify_event(text)
        assert result['exception'] is not None
        assert result['root_cause'] == 'java.sql.SQLException'

    def test_oom_java(self, fmt):
        result = fmt.classify_event(OOM_JAVA_LINE)
        assert 'OOM/GC' in result['tags']


# ---------------------------------------------------------------------------
# Bucket tags
# ---------------------------------------------------------------------------

class TestBucketTags:
    def test_pod_lifecycle_tag(self, fmt):
        tags = fmt.bucket_tags(CRASHLOOP_LINE)
        assert 'K8s/Pod' in tags

    def test_network_tag_connection_refused(self, fmt):
        tags = fmt.bucket_tags(NETWORK_LINE)
        assert 'K8s/Network' in tags

    def test_network_tag_dns(self, fmt):
        tags = fmt.bucket_tags(DNS_LINE)
        assert 'K8s/Network' in tags

    def test_network_tag_timeout(self, fmt):
        tags = fmt.bucket_tags(TIMEOUT_LINE)
        assert 'K8s/Network' in tags

    def test_storage_tag_failedmount(self, fmt):
        tags = fmt.bucket_tags(STORAGE_LINE)
        assert 'K8s/Storage' in tags

    def test_storage_tag_provisioning(self, fmt):
        tags = fmt.bucket_tags(PROVISION_LINE)
        assert 'K8s/Storage' in tags

    def test_auth_tag_unauthorized(self, fmt):
        tags = fmt.bucket_tags(AUTH_LINE)
        assert 'K8s/Auth' in tags

    def test_auth_tag_forbidden(self, fmt):
        tags = fmt.bucket_tags(FORBIDDEN_LINE)
        assert 'K8s/Auth' in tags

    def test_auth_tag_cert_expired(self, fmt):
        tags = fmt.bucket_tags(CERT_EXPIRED_LINE)
        assert 'K8s/Auth' in tags

    def test_oom_tag(self, fmt):
        tags = fmt.bucket_tags(OOM_JAVA_LINE)
        assert 'OOM/GC' in tags

    def test_oomkilled_tag(self, fmt):
        tags = fmt.bucket_tags(OOM_KILLED_LINE)
        assert 'OOM/GC' in tags
        assert 'K8s/Pod' in tags

    def test_openshift_route_haproxy(self, fmt):
        tags = fmt.bucket_tags(HAPROXY_LINE)
        assert 'OpenShift/Route' in tags

    def test_openshift_route_not_admitted(self, fmt):
        tags = fmt.bucket_tags(ROUTE_LINE)
        assert 'OpenShift/Route' in tags

    def test_plain_text_no_tags(self, fmt):
        tags = fmt.bucket_tags(PLAIN_TEXT)
        assert len(tags) == 0


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------

class TestRegistryIntegration:
    def test_crio_in_list_formats(self):
        from logpilot.formats import list_formats
        names = [f['name'] for f in list_formats()]
        assert 'crio' in names

    def test_get_format_crio(self):
        from logpilot.formats import get_format
        fmt = get_format('crio')
        assert fmt.name == 'crio'

    def test_detect_format_crio_lines(self):
        from logpilot.formats import detect_format
        lines = [CRIO_FULL, CRIO_STDOUT, CRIO_WITH_LEVEL, CRASHLOOP_LINE]
        detected = detect_format(lines)
        assert detected.name == 'crio'

    def test_detect_format_klog_lines(self):
        from logpilot.formats import detect_format
        lines = [KLOG_INFO, KLOG_WARNING, KLOG_ERROR, KLOG_FATAL]
        detected = detect_format(lines)
        assert detected.name == 'crio'
