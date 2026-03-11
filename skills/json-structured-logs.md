# JSON Structured Log Analysis

## Overview

JSON structured logging is the dominant format in modern infrastructure: Docker, Kubernetes, cloud-native apps, and most logging libraries support it natively. Each log line is a self-contained JSON object.

## Common Libraries & Their Field Names

### Node.js

| Library | Level field | Message field | Timestamp field | Extra |
|---------|-------------|---------------|-----------------|-------|
| **Bunyan** | `level` (int: 10-60) | `msg` | `time` (ISO 8601) | `name`, `hostname`, `pid`, `v` |
| **Pino** | `level` (int: 10-60) | `msg` | `time` (epoch ms) | `name`, `hostname`, `pid` |
| **Winston** | `level` (string) | `message` | `timestamp` | `service`, `metadata` |

Bunyan/Pino level mapping:
```
10=trace, 20=debug, 30=info, 40=warn, 50=error, 60=fatal
```

### Python

| Library | Level field | Message field | Timestamp field | Extra |
|---------|-------------|---------------|-----------------|-------|
| **structlog** | `level` | `event` | `timestamp` | Arbitrary extra keys |
| **python-json-logger** | `levelname` | `message` | `asctime` or `timestamp` | `name`, `funcName`, `lineno` |
| **loguru** (JSON sink) | `record.level.name` | `text` | `record.time` | Nested `record` object |

### Go

| Library | Level field | Message field | Timestamp field | Extra |
|---------|-------------|---------------|-----------------|-------|
| **zap** | `level` | `msg` | `ts` (epoch float) | `caller`, `stacktrace` |
| **zerolog** | `level` | `message` | `time` (ISO 8601) | `caller` |
| **logrus** | `level` | `msg` | `time` (ISO 8601) | `func`, `file` |

### Java

| Library | Level field | Message field | Timestamp field | Extra |
|---------|-------------|---------------|-----------------|-------|
| **Logback JSON** | `level` | `message` | `timestamp` | `thread_name`, `logger_name`, `stack_trace` |
| **Log4j2 JSON** | `level` | `message` | `instant.epochSecond` | `thread`, `loggerName`, `thrown` |

## Docker/Kubernetes Wrapper Format

Docker wraps application output in a JSON envelope:

```json
{"log":"2025-03-11T10:15:33.123Z ERROR Connection timeout\n","stream":"stderr","time":"2025-03-11T10:15:33.123456789Z"}
```

| Field | Content |
|-------|---------|
| `log` | The actual log line (may itself be JSON — double-encoded) |
| `stream` | `stdout` or `stderr` |
| `time` | Docker's capture timestamp (RFC 3339 nano) |

### Double-encoded JSON

Common pattern in K8s: the `log` field contains a JSON string:
```json
{"log":"{\"level\":\"error\",\"msg\":\"timeout\",\"ts\":\"2025-03-11T10:15:33Z\"}\n","stream":"stderr","time":"..."}
```

Detection: if `log` field starts with `{`, try parsing it as JSON.

## CloudWatch Logs Export Format

```json
{
  "@timestamp": "2025-03-11T10:15:33.123Z",
  "@message": "{\"level\":\"error\",\"msg\":\"connection refused\"}",
  "@logStream": "app/web/abc123",
  "@log": "123456789012:/aws/ecs/my-service"
}
```

## GCP Cloud Logging Export

```json
{
  "severity": "ERROR",
  "textPayload": "Connection refused to database",
  "timestamp": "2025-03-11T10:15:33.123456Z",
  "resource": {"type": "gce_instance", "labels": {"instance_id": "123"}},
  "labels": {"k8s-pod/app": "web-server"}
}
```

Or with `jsonPayload` instead of `textPayload` for structured messages.

## Detection Heuristics

A file is JSON structured logs if:
1. First non-empty line starts with `{` and is valid JSON
2. Contains a recognizable level field (`level`, `severity`, `levelname`)
3. Contains a recognizable message field (`msg`, `message`, `event`, `textPayload`)

Score high (0.9+) if multiple lines parse as JSON with consistent field names.

## Common Patterns & Issues

### Connection Problems
```json
{"level":"error","msg":"connection refused","host":"db.internal","port":5432}
{"level":"error","msg":"dial tcp 10.0.0.5:6379: i/o timeout"}
{"level":"error","msg":"no healthy upstream","service":"auth-api"}
```

### Rate Limiting / Circuit Breaker
```json
{"level":"warn","msg":"rate limit exceeded","client_ip":"203.0.113.1","limit":"100/min"}
{"level":"error","msg":"circuit breaker open","service":"payment-api","failures":5}
```

### OOM / Resource Exhaustion
```json
{"level":"fatal","msg":"out of memory","allocated_mb":2048,"limit_mb":2048}
{"level":"error","msg":"too many open files","current":1024,"limit":1024}
```

### Authentication Failures
```json
{"level":"warn","msg":"authentication failed","user":"admin","reason":"invalid_password","ip":"198.51.100.1"}
{"level":"error","msg":"token expired","sub":"user-123","exp":"2025-03-10T23:59:59Z"}
```

## Signal Tags for JSON Logs

| Tag | Detection pattern |
|-----|-------------------|
| `OOM/GC` | `out of memory`, `oom`, `heap`, `gc overhead` in message |
| `Timeout` | `timeout`, `timed out`, `deadline exceeded` in message |
| `Connection` | `connection refused`, `connection reset`, `dial tcp.*timeout` |
| `Auth` | `authentication failed`, `unauthorized`, `403`, `token expired` |
| `RateLimit` | `rate limit`, `too many requests`, `429` |
| `CircuitBreaker` | `circuit breaker`, `circuit open` |
| `DiskFull` | `no space left`, `disk full`, `ENOSPC` |
| `DNS` | `no such host`, `dns lookup failed`, `NXDOMAIN` |

## Triage Strategy

1. **Group by level** — focus on `error` and `fatal` first
2. **Group by message pattern** — normalize messages (strip IDs, IPs, timestamps) to find clusters
3. **Check timestamps** — sudden spike = incident, gradual increase = degradation
4. **Cross-reference fields** — `service`, `host`, `pod` narrow down the failing component
5. **Look for cascading failures** — timeouts in service A often caused by failures in service B
