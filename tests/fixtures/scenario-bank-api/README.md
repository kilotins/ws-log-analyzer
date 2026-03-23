# Bank Scenario: Folkeregisteret API Failure — External API Root Cause

## Storyline

A Norwegian bank (KLP-like) routes all external API calls through IBM DataPower.
At 09:04 on March 22, 2026, Skatteetaten's Folkeregisteret API starts returning 503
errors and has silently upgraded from schema v3.2 to v4.0 — removing the required
field 'bostedsadresse' and adding 'adressegradering'. This breaks KYC verification,
customer onboarding, and address lookups.

The key insight: NAV, AML, and VPS APIs continue working fine — only Folkeregisteret
is affected. DataPower probe payloads would confirm the exact request/response causing
the failure.

## Timeline

- **09:01-09:03** — All systems healthy. KYC, onboarding, AML screening working.
- **09:04:00** — Folkeregisteret responses slow down (4-5s, threshold 3s)
- **09:04:02** — First timeout (30s) on batch person lookup
- **09:04:03** — Schema mismatch: field 'bostedsadresse' missing, new field 'adressegradering'
- **09:04:03** — HTML 503 error page received instead of JSON
- **09:04:05** — NullPointerException in KYC service (missing bostedsadresse)
- **09:04:07** — Circuit breaker OPEN for folkereg-proxy
- **09:04:10** — KYC fallback to cached data (stale 18h), new customers blocked
- **09:05:00** — Batch KYC fails: 23/45 unverified
- **09:06:00** — 67 onboarding requests queued for manual review
- **09:07:00** — Health check confirms: 503 + schema v4.0 (expected v3.2)

## Root Cause

**Skatteetaten upgraded Folkeregisteret API from v3.2 to v4.0** during maintenance,
causing:
1. **503 Service Unavailable** during the migration window
2. **Schema breaking change**: `bostedsadresse` removed, `adressegradering` added
3. Bank's JSON deserializer fails on unknown fields + NPE on missing required fields

## What LogPilot Should Detect

1. **Timeout/connectivity cascade** from Folkeregisteret timeouts
2. **XML/schema validation errors** (content-type mismatch, schema mismatch)
3. **Only Folkeregisteret affected** — NAV, AML, VPS still 200 OK
4. **Root cause pointer**: DataPower logs show exact endpoint and schema change

## Missing Logs (what LogPilot should ask for)

The key diagnostic: **DataPower probe payload** for the Folkeregisteret API calls.

```
To confirm the root cause, please provide:

1. DataPower transaction probe for folkereg-proxy
   - Time range: 2026-03-22 09:04:00 - 09:05:00
   - Endpoint: folkeregisteret.api.skatteetaten.no
   - Export: probe → Export Transaction → include request + response payloads
   - Expected: The exact request sent and the 503/v4.0 response received
   - This will confirm whether the issue is a schema change, auth failure, or service outage

2. Skatteetaten status page or incident notification
   - Check: https://skatteetaten.github.io/api-dokumentasjon/
   - Expected: Planned maintenance or version upgrade announcement
```

## Systems

| Log file | Format | System |
|----------|--------|--------|
| datapower-gateway.log | DataPower | API gateway — routes to Folkeregisteret, NAV, AML, VPS |
| kyc-service.log | Log4j | Spring Boot KYC/onboarding service |
| nginx-frontend.log | nginx | Advisor-facing load balancer |

## Fix

1. Update `PersonResponse` model to handle both v3.2 and v4.0 schemas
2. Add `@JsonIgnoreProperties(ignoreUnknown = true)` to DTOs
3. Map `adressegradering` → `bostedsadresse` compatibility layer
4. Contact Skatteetaten about breaking change without deprecation notice
