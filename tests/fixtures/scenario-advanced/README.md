# Scenario: Healthcare Platform — TLS Certificate Expiry Cascade

## Incident Summary

A wildcard TLS certificate (`*.health.internal`) expires at 08:15 UTC on the internal service mesh of a healthcare platform. The nginx reverse proxy begins rejecting SSL handshakes, causing cascading failures through 6 downstream systems. Within 10 minutes, patient portal is fully unavailable, notification workers are crashing, and the Kubernetes orchestrator is OOM-killing pods.

## Systems

| System | Format | Log file | Role |
|--------|--------|----------|------|
| nginx | `nginx` | `nginx-gateway.log` | Reverse proxy / TLS termination |
| Patient API | `log4j` | `patient-api.log` | Spring Boot REST service (HikariCP, JPA) |
| PostgreSQL | `postgresql` | `postgresql-patientdb.log` | Patient database |
| Notification Service | `python_log` | `notification-service.log` | FastAPI + Celery worker |
| Container Runtime | `docker_json` | `docker-containers.log` | Docker JSON container logs |
| Kubernetes | `crio` | `k8s-cluster.log` | CRI-O pod lifecycle + kube events |
| Linux Host | `syslog` | `syslog-host.log` | systemd, OOM killer, kernel |

## Timeline (UTC 2026-03-25)

```
08:00-08:14  Phase 1 — HEALTHY BASELINE
             Normal traffic, health checks passing, DB queries < 50ms
             ~40 healthy events across all systems

08:15:00     Phase 2 — TRIGGER
             TLS cert *.health.internal expires
             nginx: SSL_do_handshake() failed (certificate has expired)

08:15-08:20  Phase 3 — CASCADE
             08:15:02  nginx: upstream connection refused, 502 responses
             08:15:05  Patient API: connection timeouts to downstream services
             08:15:08  Patient API: HikariCP pool exhaustion (30/30 active)
             08:15:12  PostgreSQL: max connections reached (100/100)
             08:15:15  Notification: ConnectionError to Patient API
             08:15:20  Celery workers: task failures, retry storms
             08:15:30  K8s: liveness probe failures, pod restarts
             08:16:00  Docker: container OOM kills
             08:17:00  syslog: OOM killer invoked on host

08:20-08:30  Phase 4 — FULL OUTAGE
             All services returning errors
             Burst: 60+ errors in 2 min window
             K8s CrashLoopBackOff on notification pods

08:30:00     Phase 5 — RECOVERY
             Cert renewed, nginx reloaded
             Services recover in reverse cascade order
             08:30-08:35: connections drain, pools refill, health checks pass
```

## Cascade Path

```
TLS cert expiry
  --> nginx SSL handshake failures (502 to clients)
    --> Patient API upstream timeouts
      --> HikariCP connection pool exhaustion
        --> PostgreSQL max_connections reached
          --> Notification service can't reach API
            --> Celery retry storms (exponential backoff fails)
              --> K8s pod restarts (liveness probe timeout)
                --> Docker OOM kills
                  --> Linux OOM killer
```

## Cross-System Correlation

- **Trace IDs**: `req-a1b2c3d4`, `req-e5f6a7b8`, `req-c9d0e1f2` appear in nginx, Patient API, and Notification Service
- **IP addresses**: `10.0.5.20` (patient-api), `10.0.5.30` (notification-svc), `10.0.5.10` (postgresql)
- **Shared error pattern**: SSL/TLS errors propagate from nginx through all HTTPS-dependent services

## Expected Heuristic Triggers

- `ssl-error` — certificate expired
- `connection-pool-exhaustion` — HikariCP 30/30
- `pg-conn-limit` — PostgreSQL max connections
- `oom-kill` — kernel OOM killer
- `hung-threads` — Spring Boot threads blocked on pool
- `timeout-generic` — upstream timeouts
- `http-5xx` — nginx 502/503 responses
- `repeated-exception` — SSLHandshakeException repeated
- `k8s-crashloop` — CrashLoopBackOff
- `celery-task-failure` — Celery task retries

## Expected Incident Groups

1. **Primary: SSL/TLS Infrastructure Failure** (trigger: cert expiry)
2. **Connection Pool / Database Saturation** (effect of upstream SSL)
3. **Application Crash Loop** (effect of pool + timeout cascade)

## M68b Edge Cases Added

The scenario now includes additional parser and triage edge cases appended to the existing fixture files:

- **Malformed log lines**
  - truncated nginx error/access lines
  - malformed PostgreSQL collector line
  - malformed Docker JSON sidecar record with a missing closing brace
- **Timezone mismatches**
  - nginx access line written as `+0200`
  - Docker and Kubernetes records emitted as `+02:00`
  - PostgreSQL records emitted as `+0100`
  - syslog sidecar/mesh line logged in local time style
- **Partial writes**
  - CRI-O partial `P` + `F` split event
  - Docker split message across two adjacent records
  - patient-api, notification-service, and syslog lines cut mid-message
- **Interleaved / out-of-order timestamps**
  - baseline and delayed telemetry lines appended after recovery data
  - older `08:14:58-08:14:59` entries appended after later events
- **Log rotation markers**
  - explicit rotation markers in nginx, patient-api, notification-service, Docker, Kubernetes, PostgreSQL, and syslog streams
- **Red herrings**
  - harmless favicon 404 after recovery
  - PostgreSQL WAL archive warning marked as expected in test env
  - dry-run backfill failure in patient-api
  - sandbox-only canary/operator failures that look severe but are operationally harmless

These additions are intentionally noisy so the advanced scenario exercises:
- parser resilience to broken lines
- timestamp normalization across mixed zones
- handling of partial / rotated logs
- incident grouping despite out-of-order data
- rejection of scary but non-causal red herrings

## Symptom Description (for AI input)

"Patient portal has been returning 502 errors since 08:15 UTC. Doctors cannot access patient records. The notification system is also down — appointment reminders are not being sent. Multiple pods are restarting in Kubernetes."
