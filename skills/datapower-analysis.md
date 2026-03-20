# IBM DataPower Gateway Log Analysis

## Log Format

DataPower uses a consistent log format across all service types:

```
YYYYMMDDTHHMMSS.sssZ [domain][level][error-code] message
```

### Examples
```
20260320T141542.123Z [default][error][0x80e00001] Connection refused to backend service 'https://api.example.com/v1'
20260320T141543.456Z [apiconnect][warn][0x80e00234] Rate limit threshold at 80% for plan 'gold'
20260320T141544.789Z [mpgw][info][0x00000000] Transaction completed: 200 OK (45ms)
20260320T141545.012Z [xmlparse][error][0x80c00001] XML parsing failed: not well-formed at line 23
20260320T141546.345Z [ssl][error][0x80e00011] SSL handshake failed: certificate expired
```

### Fields
- **Timestamp**: ISO 8601 compact format `YYYYMMDDTHHMMSS.sssZ` (always UTC)
- **Domain**: Processing domain — `default`, `apiconnect`, `mpgw`, `xmlparse`, `ssl`, `crypto`, `aaa`, `network`, `multistep`, `webgui`
- **Level**: `emergency`, `alert`, `critical`, `error`, `warn`, `notice`, `info`, `debug`
- **Error code**: Hex code `0x80eXXXXX` — the first nibble after `0x` indicates the subsystem
- **Message**: Free-text, may include backend URLs, HTTP status, durations

### Multiline Events
DataPower logs can be multiline for:
- Stack traces (Java-based processing policies)
- XML/JSON payload dumps (in debug mode)
- Certificate details (SSL errors)
- Transaction flow details

Continuation lines typically start with whitespace or lack the timestamp prefix.

## Error Code Structure

DataPower error codes are 32-bit hex values. The structure:

```
0x AABB CCCC
     │  │  │
     │  │  └── Specific error within module
     │  └───── Module/subsystem
     └──────── Category (00=info, 80=error, 81=warning)
```

### Key Error Code Prefixes

| Prefix | Subsystem | Examples |
|--------|-----------|---------|
| `0x80e0` | Network/connectivity | Connection refused, timeout, DNS failure |
| `0x80e1` | SSL/TLS | Handshake failure, cert expired, chain incomplete |
| `0x80c0` | XML processing | Parse error, schema validation, XSLT failure |
| `0x80d0` | Authentication/AAA | Auth failed, token expired, LDAP unreachable |
| `0x80b0` | API Connect gateway | Rate limit, plan exceeded, catalog error |
| `0x80a0` | Crypto | Key generation failure, algorithm not supported |
| `0x8060` | Multistep policy | Processing policy action failed |
| `0x0000` | Success/info | Transaction completed, service started |

## High-Impact Error Codes

### Connectivity (0x80e0xxxx)
| Code | Meaning | Typical cause |
|------|---------|---------------|
| `0x80e00001` | Connection refused | Backend service down or wrong port |
| `0x80e00002` | Connection timeout | Backend slow or firewall blocking |
| `0x80e00003` | DNS resolution failed | DNS server unreachable or bad hostname |
| `0x80e00004` | Connection reset | Backend crashed mid-request |
| `0x80e00010` | No route to host | Network misconfiguration |

### SSL/TLS (0x80e1xxxx)
| Code | Meaning | Typical cause |
|------|---------|---------------|
| `0x80e10001` | SSL handshake failed | Protocol mismatch or cipher suite |
| `0x80e10002` | Certificate expired | Server or client cert past validity |
| `0x80e10003` | Certificate not trusted | Missing CA in trust store |
| `0x80e10004` | Client cert required | mTLS not configured on client |
| `0x80e10005` | CRL check failed | CRL unreachable or cert revoked |

### XML Processing (0x80c0xxxx)
| Code | Meaning | Typical cause |
|------|---------|---------------|
| `0x80c00001` | XML not well-formed | Invalid XML in request/response |
| `0x80c00002` | Schema validation failed | Payload doesn't match WSDL/XSD |
| `0x80c00003` | XSLT transform failed | Error in transformation stylesheet |
| `0x80c00004` | XPath evaluation failed | Expression matches nothing or is invalid |

### Authentication/AAA (0x80d0xxxx)
| Code | Meaning | Typical cause |
|------|---------|---------------|
| `0x80d00001` | Authentication failed | Bad credentials or token |
| `0x80d00002` | Authorization denied | User lacks required group/role |
| `0x80d00003` | Token expired | JWT/OAuth token past expiry |
| `0x80d00004` | LDAP connection failed | LDAP server unreachable |
| `0x80d00005` | Token validation error | Invalid signature or issuer |

### API Connect (0x80b0xxxx)
| Code | Meaning | Typical cause |
|------|---------|---------------|
| `0x80b00001` | Rate limit exceeded | Client exceeded plan quota |
| `0x80b00002` | Plan not found | Invalid or deleted API plan |
| `0x80b00003` | API key invalid | Revoked or misformatted key |
| `0x80b00004` | Catalog unavailable | API catalog sync issue |

## Domains and Their Significance

| Domain | What it handles | Key error patterns |
|--------|----------------|-------------------|
| `default` | Default processing, system events | Startup/shutdown, memory, general errors |
| `apiconnect` | API Connect gateway processing | Rate limits, plans, analytics |
| `mpgw` | Multi-Protocol Gateway | Routing, transformation, backend calls |
| `xmlparse` | XML/JSON parsing | Validation, schema, transform |
| `ssl` | SSL/TLS termination | Handshake, certificates, ciphers |
| `crypto` | Cryptographic operations | Key management, encryption/decryption |
| `aaa` | Authentication, Authorization, Auditing | Login, LDAP, OAuth, SAML |
| `network` | Network layer | TCP connections, DNS, load balancing |
| `multistep` | Processing policy execution | Policy actions, flow control |
| `webgui` | WebGUI management interface | Admin login, config changes |

## Detection Regex

```python
# Timestamp: YYYYMMDDTHHMMSS.sssZ
DP_TS_RE = re.compile(r'^\d{8}T\d{6}\.\d{3}Z\s+')

# Full line: timestamp [domain][level][code] message
DP_FULL_RE = re.compile(
    r'^(?P<ts>\d{8}T\d{6}\.\d{3}Z)\s+'
    r'\[(?P<domain>[^\]]+)\]'
    r'\[(?P<level>[^\]]+)\]'
    r'\[(?P<code>0x[0-9a-fA-F]+)\]\s+'
    r'(?P<message>.*)'
)

# Level mapping
DP_LEVELS = {
    'emergency': 'FATAL', 'alert': 'FATAL', 'critical': 'ERROR',
    'error': 'ERROR', 'warn': 'WARNING', 'notice': 'INFO',
    'info': 'INFO', 'debug': 'DEBUG',
}
```

## Signal Tags

| Tag | Trigger patterns |
|-----|-----------------|
| `SSL/TLS` | domain=ssl, 0x80e1xxxx codes, "handshake", "certificate" |
| `DB/Pool` | "connection pool", "backend.*timeout", 0x80e00002 |
| `HTTP` | HTTP status 4xx/5xx in message, "rate limit" |
| `Auth` | domain=aaa, 0x80d0xxxx codes, "authentication", "authorization" |
| `Network` | domain=network, 0x80e0xxxx codes, "connection refused", "DNS" |

## Common Incident Patterns

### Backend Service Cascade
```
[mpgw][error][0x80e00001] Connection refused to backend 'serviceA'
[mpgw][error][0x80e00001] Connection refused to backend 'serviceA'  (repeated 50x)
[mpgw][warn][0x80e00002] Connection timeout to backend 'serviceB'   (cascade starts)
[default][error][0x80e00001] Health check failed for service pool 'backend-pool'
```
**Pattern**: One backend fails → requests queue → timeout cascade to other backends.

### Certificate Expiry Cascade
```
[ssl][error][0x80e10002] Certificate expired: CN=api.example.com, Not After=2026-03-19
[ssl][error][0x80e10001] SSL handshake failed with client 192.168.1.100
[aaa][error][0x80d00001] mTLS authentication failed: client certificate not valid
```
**Pattern**: Server cert expires → all SSL connections fail → auth fails.

### API Rate Limit Storm
```
[apiconnect][warn][0x80b00001] Rate limit at 80% for client 'app-xyz' plan 'gold'
[apiconnect][warn][0x80b00001] Rate limit at 95% for client 'app-xyz' plan 'gold'
[apiconnect][error][0x80b00001] Rate limit exceeded for client 'app-xyz' plan 'gold'
[mpgw][error] HTTP 429 returned to client 192.168.1.50
```
**Pattern**: Gradual rate limit approach → hard cutoff → client errors.

## Related Skills
- `skills/security-analysis.md` — SSL/TLS patterns, auth failures
- `skills/cross-system-analysis.md` — cascade detection across DataPower + backend systems
- `skills/message-codes.md` — WAS message codes (DataPower often fronts WAS)
