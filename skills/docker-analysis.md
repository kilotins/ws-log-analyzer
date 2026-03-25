# Docker / Containerd Log Analysis

## Format

Docker JSON log driver writes one JSON object per line:

```json
{"log":"2026-03-23 10:30:00 ERROR Something failed\n","stream":"stderr","time":"2026-03-23T10:30:00.123456789Z"}
{"log":"  at com.example.Foo.bar(Foo.java:42)\n","stream":"stderr","time":"2026-03-23T10:30:00.123456790Z"}
```

Required fields: `log`, `stream`, `time`. Optional: `attrs` (container name, tag).

### Stream Mapping

| Stream | Default Level | Meaning |
|--------|--------------|---------|
| `stderr` | WARNING | Error/diagnostic output |
| `stdout` | INFO | Normal application output |

The actual level is extracted from the embedded `log` message if it contains keywords (ERROR, WARN, FATAL, etc.).

## Common Container Errors

### OOMKilled (Exit 137)

Container killed by kernel OOM killer or cgroup memory limit.

**Patterns:**
- `OOMKilled` — Kubernetes event annotation
- `oom-kill` — kernel dmesg/syslog
- `cgroup.*oom` — cgroup memory controller
- `exit code: 137` — SIGKILL (128 + 9)

**Signal tag:** `OOM/GC`, `K8s/Pod`

**Root cause:** Container memory limit too low, or application has a memory leak.

**Fixes:**
- Check `resources.limits.memory` in pod spec
- Profile application memory usage
- Look for heap dumps or GC logs in adjacent events

### CrashLoopBackOff

Container repeatedly crashes and restarts.

**Patterns:**
- `CrashLoopBackOff` — K8s pod status
- `Back-off restarting failed container` — kubelet
- Rapid succession of `Started container` → `Error` events

**Root cause:** Application fails at startup — missing config, failed health check, dependency unavailable.

**Fixes:**
- Check container logs for the actual startup error
- Verify ConfigMaps/Secrets are mounted
- Check if dependent services (DB, message queue) are ready

### ImagePullBackOff

Container image cannot be pulled.

**Patterns:**
- `ImagePullBackOff` — K8s event
- `Failed to pull image` — kubelet
- `unauthorized` — registry auth failure
- `manifest unknown` — wrong tag

**Fixes:**
- Verify image name and tag exist in registry
- Check imagePullSecrets configuration
- Verify registry credentials

## Network Errors

**Patterns:**
- `connection refused` / `ECONNREFUSED` — target not listening
- `connection reset` — remote closed connection
- `no such host` / `NXDOMAIN` — DNS failure

**Signal tag:** `Network`

## SSL/TLS in Containers

**Patterns:**
- `SSLHandshakeException` — Java apps
- `certificate.*expired` — expired cert
- `PKIX path building failed` — missing CA in truststore

**Signal tag:** `SSL/TLS`

**Common cause:** Container truststore doesn't include internal CA certs. Fix: mount CA bundle or add to Dockerfile.

## Database Connection Issues

**Patterns:**
- `pool.*exhaust` — connection pool drained
- `connection.*timeout` — DB unreachable
- `HikariPool` — HikariCP pool errors

**Signal tag:** `DB/Pool`

**Common cause in containers:** DB hostname changed, service not ready, network policy blocking traffic.

## HTTP Errors

**Patterns:**
- `4xx` + `error`/`fail` — client errors (auth, not found)
- `5xx` + `error`/`fail` — server errors (upstream down, timeout)

**Signal tag:** `HTTP`

## Container Lifecycle Events

Normal lifecycle (not errors, useful for context):

| Event | Meaning |
|-------|---------|
| `Created container` | Container created, not yet started |
| `Started container` | Container running |
| `Killing container` | Graceful shutdown (SIGTERM) |
| `Stopped container` | Container exited |

**Rapid `Started` → `Stopped` cycles** indicate CrashLoopBackOff.

## Cross-System Correlation

Docker logs often wrap application logs. When analyzing:

1. **Unwrap** the `log` field to get the actual application message
2. **Use `time`** (Docker timestamp) for timeline, but check for app-level timestamps in the log message
3. **Correlate** container names/tags with K8s pod names for cross-system analysis
4. **Check `stream`** — `stderr` errors from one container may explain `connection refused` in another
