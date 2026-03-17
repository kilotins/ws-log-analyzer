# Cross-System Analysis

## Trace ID / Correlation ID Patterns

Common field names and formats for request tracing across systems:

| Field Name | Format | Systems |
|-----------|--------|---------|
| `X-Request-Id` | UUID | nginx, HAProxy, API gateways |
| `trace_id` / `traceId` | 32-char hex | OpenTelemetry, Jaeger, Zipkin |
| `correlation_id` / `correlationId` | UUID | WAS, Liberty, Spring |
| `request_id` / `requestId` | UUID | Express, Flask, Django |
| `span_id` / `spanId` | 16-char hex | OpenTelemetry |

### Tracing a Request Across Systems

1. Find the trace/correlation ID in the error event
2. Search ALL log sources for the same ID
3. Sort matched events by timestamp → request flow
4. Identify where the failure originated (earliest error in the chain)

## Cross-System Cascade Patterns

When errors in one system cause errors in another:

| Upstream Error | Downstream Effect | Typical Delay | Example |
|---------------|-------------------|---------------|---------|
| Database timeout/pool exhaustion | HTTP 500/503 | 1-30s | DB connection pool empty → servlet can't query → 500 to client |
| SSL/TLS handshake failure | Connection refused | 0-10s | Expired cert → backend unreachable → gateway 502 |
| OOM / GC pressure | Thread starvation | 5-60s | Heap full → GC pauses → threads blocked → hung thread alerts |
| Memory pressure | HTTP timeouts | 10-60s | OOM → slow responses → upstream gateway timeout |
| DB pool exhaustion | Hung threads | 5-30s | All connections busy → threads waiting → WSVR0605W |
| Hung threads | HTTP errors | 5-15s | No threads available → request queue full → 503 |

### Identifying the Root Cause in a Cascade

The root cause is typically the **earliest error in the first affected system**:

1. Sort all errors by UTC timestamp across all sources
2. The first error is likely the trigger
3. Subsequent errors in other systems within seconds are downstream effects
4. Fix the upstream cause — downstream errors resolve automatically

## Multi-Source Triage Checklist

When analyzing logs from multiple systems:

1. **Establish timeline**: sort all events by UTC timestamp
2. **Identify the blast radius**: which systems have errors?
3. **Find the first error**: which system failed first?
4. **Trace the cascade**: do errors propagate from source to downstream?
5. **Check for correlation IDs**: can you link specific requests across systems?
6. **Look for "what changed"**: deploy events, config changes, traffic spikes just before the first error
7. **Prioritize**: fix the upstream root cause, not the downstream symptoms

## Common Multi-System Architectures

### Gateway → App Server → Database
```
nginx/HAProxy → Liberty/WAS → DB
     502          SRVE0777E     J2CA0045W
```
Root cause: Usually database (rightmost). Fix: Check connection pool, query performance.

### Microservices Chain
```
API Gateway → Service A → Service B → External API
     504          timeout       ECONNREFUSED
```
Root cause: Usually the external dependency. Fix: Circuit breaker, fallback, retry with backoff.

### Message Queue Pattern
```
Producer → Queue (JMS/Kafka) → Consumer → Database
                                  OOM        slow queries
```
Root cause: Consumer backpressure from slow DB. Fix: Tune consumer concurrency, optimize queries.
