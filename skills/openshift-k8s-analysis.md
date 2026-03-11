# OpenShift / Kubernetes Log Analysis

## Overview

OpenShift is Red Hat's enterprise Kubernetes platform. Logs come from three main sources: application pods, infrastructure components, and audit trails. The underlying format is typically JSON (CRI-O container runtime) or plain text, depending on the application.

## Log Categories

| Category | Source | Location |
|----------|--------|----------|
| **Application logs** | Regular pods (`stdout`/`stderr`) | `/var/log/pods/<ns>_<pod>_<uid>/<container>/` |
| **Infrastructure logs** | System pods (`openshift-*`, `kube-*`, `default` namespaces) + node journald | journald, `/var/log/pods/` |
| **Audit logs** | API server, OAuth server, node auditd | `/var/log/audit/audit.log`, API server logs |

## Container Log Format (CRI-O)

OpenShift uses CRI-O as container runtime. Log format:

```
2025-03-11T10:15:33.123456789+01:00 stderr F Error: connection refused to database
2025-03-11T10:15:33.123456789+01:00 stdout F {"level":"info","msg":"request handled","status":200}
```

| Field | Meaning |
|-------|---------|
| Timestamp | RFC 3339 with nanoseconds |
| Stream | `stdout` or `stderr` |
| Flag | `F` (full line) or `P` (partial, continued on next line) |
| Message | The actual log line from the container |

**Note**: The message field may itself be JSON (double-encoded), plain text, or any application log format.

### Partial Lines

CRI-O splits long lines (>16KB) into partial entries:
```
2025-03-11T10:15:33.123Z stdout P This is a very long log line that has been sp
2025-03-11T10:15:33.123Z stdout F lit across two entries
```

Reassemble `P` lines before parsing the application log.

## kubectl / oc logs Output

```bash
oc logs pod/myapp-abc123 -n my-namespace
```

Output is raw application logs without CRI-O envelope:
```
2025-03-11 10:15:33,123 ERROR com.example.App - Connection refused
Traceback (most recent call last):
  File "app.py", line 42, in handle
    db.connect()
ConnectionError: Connection refused
```

The format depends entirely on the application — could be any format LogPilot supports (JSON, Log4j, Python, plain text).

## OpenShift-Specific Log Sources

### API Server Audit Log

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Metadata",
  "auditID": "abc-123",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/default/pods",
  "verb": "create",
  "user": {"username": "system:serviceaccount:myns:mysa"},
  "sourceIPs": ["10.0.0.5"],
  "objectRef": {"resource": "pods", "namespace": "default", "name": "myapp-abc123"},
  "responseStatus": {"code": 201},
  "requestReceivedTimestamp": "2025-03-11T10:15:33.123456Z",
  "stageTimestamp": "2025-03-11T10:15:33.456789Z"
}
```

### OpenShift OAuth / Authentication

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "verb": "create",
  "requestURI": "/oauth/authorize",
  "user": {"username": "developer"},
  "responseStatus": {"code": 302}
}
```

### Operator Logs

```
I0311 10:15:33.123456  1 controller.go:123] Reconciling ClusterLogging instance
E0311 10:15:33.123456  1 controller.go:456] Failed to reconcile: context deadline exceeded
W0311 10:15:33.123456  1 reflector.go:789] watch of *v1.Pod ended with: too old resource version
```

klog format: `[IWEF]MMDD HH:MM:SS.ffffff  pid file:line] message`

Level prefix: `I`=Info, `W`=Warning, `E`=Error, `F`=Fatal.

## Common Error Patterns

### Pod Lifecycle

| Pattern | Meaning | Check |
|---------|---------|-------|
| `CrashLoopBackOff` | Container crashing repeatedly | Check container logs, exit code |
| `OOMKilled` | Container exceeded memory limit | Increase `resources.limits.memory` |
| `ImagePullBackOff` | Can't pull container image | Registry auth, image exists, network |
| `CreateContainerConfigError` | Bad container config | Missing ConfigMap/Secret, mount errors |
| `Evicted` | Pod evicted by kubelet | Node disk pressure, memory pressure |
| `FailedScheduling` | No node can run the pod | Resource constraints, taints, affinity |

### Networking

| Pattern | Meaning |
|---------|---------|
| `connection refused` | Target pod/service not ready |
| `no route to host` | Network policy blocking, SDN issue |
| `dial tcp: lookup ... no such host` | DNS resolution failed |
| `TLS handshake error` | Certificate mismatch, expired cert |
| `i/o timeout` | Network partition, firewall, slow endpoint |

### Storage / PVC

| Pattern | Meaning |
|---------|---------|
| `FailedMount` | PV/PVC mount failed |
| `ProvisioningFailed` | StorageClass can't create PV |
| `NodeUnschedulable` | Node cordoned/drained |
| `VolumeInUse` | PV still attached to another pod |

### Routes / Ingress

| Pattern | Meaning |
|---------|---------|
| `503 Service Unavailable` | No ready endpoints for route |
| `HAProxy: backend has no server available` | All pods for service are down |
| `Connection reset by peer` | Upstream pod terminated during request |
| `route not admitted` | Route rejected by router (wildcard/cert issue) |

### Cluster Operators

| Pattern | Meaning |
|---------|---------|
| `ClusterOperator ... Degraded=True` | Operator component unhealthy |
| `ClusterOperator ... Available=False` | Operator component down |
| `upgrade precondition failed` | Cluster upgrade blocked |
| `certificate has expired` | Internal cert rotation failed |

## Signal Tags

| Tag | Detection pattern |
|-----|-------------------|
| `K8s/Pod` | `CrashLoopBackOff`, `OOMKilled`, `ImagePull`, `Evicted`, `FailedScheduling` |
| `K8s/Network` | `connection refused`, `no route to host`, `dns.*no such host`, `i/o timeout` |
| `K8s/Storage` | `FailedMount`, `ProvisioningFailed`, `VolumeInUse` |
| `K8s/Auth` | `Unauthorized`, `Forbidden`, `oauth`, `certificate.*expired` |
| `K8s/Operator` | `Degraded=True`, `Available=False`, `Reconcil` |
| `OOM` | `OOMKilled`, `OutOfMemoryError`, `memory cgroup out of memory` |
| `OpenShift/Route` | `HAProxy`, `503.*no server`, `route not admitted` |

## Log Collection Stack

### Cluster Logging Operator (CLO)

OpenShift's built-in log collection:
- **Collector**: Vector or Fluentd (daemonset on every node)
- **Store**: Elasticsearch (internal) or forwarded to external (Splunk, Loki, CloudWatch)
- **Visualization**: Kibana (internal) or Grafana

### ClusterLogForwarder

```yaml
apiVersion: logging.openshift.io/v1
kind: ClusterLogForwarder
metadata:
  name: instance
spec:
  outputs:
    - name: splunk
      type: splunk
      url: https://splunk.example.com:8088
      secret:
        name: splunk-token
  pipelines:
    - name: app-logs
      inputRefs: [application]
      outputRefs: [splunk]
```

### Exported Log Format

When logs are forwarded, they're wrapped in a metadata envelope:
```json
{
  "@timestamp": "2025-03-11T10:15:33.123Z",
  "message": "Connection refused",
  "level": "error",
  "hostname": "worker-1.ocp.example.com",
  "kubernetes": {
    "namespace_name": "my-namespace",
    "pod_name": "myapp-abc123",
    "container_name": "myapp",
    "labels": {"app": "myapp", "version": "v1.2.3"}
  },
  "openshift": {
    "cluster_id": "abc-123-def",
    "labels": {"logging": "app"}
  }
}
```

## Triage Strategy

1. **Check pod status** — `oc get pods` for CrashLoopBackOff, OOMKilled, Evicted
2. **Read pod logs** — `oc logs pod/name --previous` for crash logs
3. **Check events** — `oc get events --sort-by=lastTimestamp` for scheduling/mount failures
4. **Cluster operators** — `oc get co` for degraded/unavailable operators
5. **Node health** — `oc adm top nodes` for resource pressure
6. **Network policy** — `oc get networkpolicy -n namespace` for blocked traffic
7. **Route/ingress** — `oc get route` for not-admitted routes, `oc logs router-default` for HAProxy errors

## Useful Splunk Queries

```spl
# Pod crash loops
index=k8s sourcetype=openshift "CrashLoopBackOff" | stats count by namespace pod_name

# OOM kills
index=k8s sourcetype=openshift "OOMKilled" OR "memory cgroup" | timechart count by namespace

# API server errors
index=k8s sourcetype=openshift_audit responseStatus.code>=400 | stats count by verb requestURI responseStatus.code

# Failed deployments
index=k8s sourcetype=openshift "FailedCreate" OR "replica.*failed" | stats count by namespace deployment

# Route 503s
index=k8s sourcetype=haproxy status=503 | top limit=20 backend_name
```
