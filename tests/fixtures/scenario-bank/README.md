# Bank Scenario: KLP-style Payment Processing Outage

## Storyline

A Norwegian bank (KLP-like) uses IBM DataPower as API gateway for all external integrations.
At 08:35 on March 21, 2026, the core banking database (PostgreSQL) hits a deadlock on the
salary batch job, causing connection pool exhaustion that cascades through all systems.

## Timeline

- **08:30** — All systems healthy. Gateway, core banking, database operational.
- **08:31** — Normal traffic: balance lookups, payments, pension queries.
- **08:34** — JWT token expiry warning for batch processor.
- **08:35:00** — PostgreSQL deadlock on salary batch → lock timeout cascade.
- **08:35:10** — PostgreSQL max_connections=200 reached → "too many clients"
- **08:35:25** — Database smart shutdown (temp file overflow 512MB > 256MB limit)
- **08:35:30** — Core banking WAS: JDBC pool exhausted (J2CA0045E), hung threads
- **08:35:30** — DataPower: connection refused to core-banking backend
- **08:35:30** — nginx: 502/504 to bank customers
- **08:36:00** — DataPower: NAV API timeout, VPS SSL error, AML DNS failure
- **08:36:00** — Salary batch fails: 234/1500 payments unprocessed
- **08:36:10** — DataPower: circuit breaker OPEN for core-banking
- **08:36:30** — OOM in WAS session cache
- **08:37:00** — PostgreSQL recovers
- **08:38:00** — All systems recover, salary batch retries

## Systems

| Log file | Format | System |
|----------|--------|--------|
| datapower-gateway.log | DataPower | API gateway — routes to VPS, NAV, AML, core-banking |
| core-banking-was.log | WAS | WebSphere application server — payment processing |
| core-banking-app.log | Log4j | Spring Boot services — accounts, payments, integrations |
| nginx-frontend.log | nginx | Customer-facing nettbank load balancer |
| postgresql-coredb.log | PostgreSQL* | Core banking database |

*PostgreSQL format detected as syslog/generic — dedicated plugin in M57.

## Root Cause

PostgreSQL deadlock between salary batch (process 200) and a concurrent payment (process 201)
led to lock timeout, temp file overflow, and smart shutdown. The 2-minute DB downtime cascaded
through WAS connection pools, DataPower backend connectivity, and nginx to customers.

## External Services Affected

- **NAV** (nav-api.nav.no) — income/benefits lookup timeout (independent issue or DNS cascade)
- **VPS** (api.vps.no) — TLS version mismatch (pre-existing, exposed during incident)
- **AML register** (aml-register.finanstilsynet.no) — cert expired + DNS failure
- **LDAP** (ldap.klpbank.no) — auth timeout during incident
