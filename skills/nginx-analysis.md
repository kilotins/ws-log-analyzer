# nginx Log Analysis

## Log Types

nginx produces two types of logs with different formats and purposes.

### Access Log (default: Combined Log Format)

```
192.168.1.1 - frank [11/Mar/2025:10:15:33 +0100] "GET /api/users HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0..."
```

| Field | Position | Meaning |
|-------|----------|---------|
| `$remote_addr` | 1 | Client IP |
| `$remote_user` | 3 | HTTP auth user (usually `-`) |
| `$time_local` | 4 (brackets) | Timestamp `[dd/Mon/yyyy:HH:MM:SS +zone]` |
| `$request` | 5 (quotes) | Method + URI + protocol |
| `$status` | 6 | HTTP status code |
| `$body_bytes_sent` | 7 | Response body size |
| `$http_referer` | 8 (quotes) | Referer header |
| `$http_user_agent` | 9 (quotes) | User-Agent |

### Custom log_format

Many deployments add `$request_time`, `$upstream_response_time`, `$upstream_addr`:
```
192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /api HTTP/1.1" 200 1234 0.052 0.050 "10.0.0.5:8080"
```

### Error Log

```
2025/03/11 10:15:33 [error] 1234#5678: *99 connect() failed (111: Connection refused) while connecting to upstream, client: 192.168.1.1, server: example.com, request: "GET /api HTTP/1.1", upstream: "http://10.0.0.5:8080/api"
```

Format: `YYYY/MM/DD HH:MM:SS [level] pid#tid: *connection_id message`

Levels: `debug`, `info`, `notice`, `warn`, `error`, `crit`, `alert`, `emerg`

## Detection Heuristics

**Access log**: Line matches Combined Log Format regex — IP, brackets timestamp, quoted request, numeric status.

**Error log**: Line starts with `YYYY/MM/DD HH:MM:SS [level]` pattern.

Score 0.9+ if >60% of first 50 lines match either pattern.

## HTTP Status Code Analysis

### 4xx Client Errors

| Code | Meaning | Common cause |
|------|---------|--------------|
| **400** | Bad Request | Malformed request, oversized headers, invalid URL encoding |
| **401** | Unauthorized | Missing/invalid auth credentials |
| **403** | Forbidden | ACL/permission denied, blocked by geo/IP rule |
| **404** | Not Found | Missing resource, wrong URL, deleted content |
| **405** | Method Not Allowed | POST to GET-only endpoint |
| **408** | Request Timeout | Client too slow sending request body |
| **413** | Payload Too Large | Upload exceeds `client_max_body_size` |
| **429** | Too Many Requests | Rate limiting (`limit_req`/`limit_conn`) |
| **444** | No Response (nginx) | Connection closed without response (block bots) |
| **499** | Client Closed Request (nginx) | Client disconnected before response — often timeout upstream |

### 5xx Server Errors

| Code | Meaning | Common cause |
|------|---------|--------------|
| **500** | Internal Server Error | Application crash, uncaught exception upstream |
| **502** | Bad Gateway | Upstream returned invalid response, crashed, or refused connection |
| **503** | Service Unavailable | Upstream pool exhausted, maintenance mode, overloaded |
| **504** | Gateway Timeout | Upstream didn't respond within `proxy_read_timeout` |

### Critical pattern: 499 + 502/504

A burst of 499s followed by 502/504s usually means:
1. Upstream becomes slow → clients timeout (499)
2. Upstream stops responding → nginx gets 502/504
3. Root cause is upstream, not nginx

## Common Error Patterns

### Upstream Connection Issues
```
connect() failed (111: Connection refused) while connecting to upstream
no live upstreams while connecting to upstream
upstream timed out (110: Connection timed out) while reading response header
```

**Cause**: Backend server down, overloaded, or misconfigured upstream block.

### Worker Connection Limits
```
worker_connections are not enough
accept() failed (24: Too many open files)
```

**Cause**: `worker_connections` too low or system `ulimit` hit.

### SSL/TLS Errors
```
SSL_do_handshake() failed (SSL: error:... alert handshake failure)
no "ssl_certificate" is defined
SSL: error:0A000086:SSL routines::certificate verify failed
```

### Request Size Limits
```
client intended to send too large body: 52428800 bytes
upstream sent too big header while reading response header
```

**Fix**: Adjust `client_max_body_size`, `proxy_buffer_size`, `large_client_header_buffers`.

### Permission Errors
```
open() "/var/www/html/index.html" failed (13: Permission denied)
stat() "/var/www/html/" failed (13: Permission denied)
```

**Cause**: nginx worker user (usually `www-data`) lacks read permissions.

## Signal Tags

| Tag | Detection pattern |
|-----|-------------------|
| `HTTP/5xx` | Status 500-599 in access log |
| `HTTP/4xx` | Status 400-499 in access log |
| `Upstream` | `upstream`, `connect() failed`, `no live upstreams` in error log |
| `SSL/TLS` | `SSL`, `ssl_certificate`, `handshake` in error log |
| `Timeout` | `timed out`, `408`, `504`, `499` |
| `RateLimit` | `limiting requests`, `429`, `limit_req` |
| `DiskFull` | `No space left on device`, `ENOSPC` |
| `Permission` | `Permission denied`, `(13:` |

## Performance Analysis

When `$request_time` and `$upstream_response_time` are logged:

- **request_time >> upstream_response_time**: Network latency between client and nginx
- **upstream_response_time high**: Backend is slow
- **request_time high, no upstream_response_time**: Static file I/O issue or client-side slowness

### Slow Request Thresholds
- API endpoints: >1s is concerning, >5s is critical
- Static assets: >100ms is concerning
- WebSocket upgrades: long `request_time` is expected

## Triage Strategy

1. **Group by status code** — 5xx first, then 4xx spikes
2. **Group by endpoint** — `/api/search` has 90% of 504s → specific upstream issue
3. **Check upstream addresses** — one backend generating all errors → single node problem
4. **Timeline** — sudden spike vs gradual degradation
5. **Correlate access + error logs** — match by timestamp and connection ID (`*NNN`)
6. **Check request_time distribution** — p50 vs p99 reveals tail latency

## Useful Splunk Queries

```spl
# Top 5xx endpoints
index=web sourcetype=nginx_access status>=500 | top limit=20 uri

# Upstream errors
index=web sourcetype=nginx_error "upstream" | timechart count by upstream_addr

# Slow requests (>5s)
index=web sourcetype=nginx_access request_time>5 | stats count avg(request_time) by uri

# 499 + 502 correlation (cascade detection)
index=web sourcetype=nginx_access (status=499 OR status=502) | timechart span=1m count by status

# Rate limiting hits
index=web sourcetype=nginx_error "limiting requests" | timechart count span=5m
```
