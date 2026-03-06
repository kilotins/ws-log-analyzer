# WAS Message Code Reference

## Code Format

WebSphere messages follow the pattern `PPPPNNNNs` where:
- `PPPP` = component prefix (4 chars)
- `NNNN` = numeric ID (4 digits)
- `s` = severity: I (info), W (warning), E (error), A (audit)

## Common Prefixes

| Prefix | Component |
|--------|-----------|
| SRVE | Servlet engine |
| SESN | Session manager |
| WSVR | Server runtime |
| CWWKZ | Liberty app manager |
| CWWKS | Liberty security |
| CWWKF | Liberty feature manager |
| CWPKI | PKI/SSL certificates |
| DCSV | DCS (cluster) |
| HMGR | HAManager |
| WTRN | Transaction manager |
| CHFW | Channel framework |
| TCPC | TCP channel |
| HTTC | HTTP channel |
| DSRA | Data source / JDBC |
| J2CA | J2C connection manager |
| CNTR | EJB container |
| ODCF | ODC framework |

## High-Impact Codes

### Servlet Engine (SRVE)
- **SRVE0255E** — Uncaught servlet exception, check stacktrace for root cause
- **SRVE0293E** — Servlet not found (404), verify URL mapping and app deployment
- **SRVE0068E** — Could not invoke servlet destroy(), possible resource leak
- **SRVE0207E** — Servlet initialization failed, check init-param and dependencies
- **SRVE0242I** — Servlet loaded successfully (informational)
- **SRVE0190E** — Servlet request/response error, often timeout or broken pipe

### Session Manager (SESN)
- **SESN0066E** — Session serialization failed, object in session not Serializable
- **SESN0008E** — Session cannot be persisted to database
- **SESN0176I** — Session invalidated (informational)

### Server Runtime (WSVR)
- **WSVR0001I** — Server starting
- **WSVR0024I** — Server is open for e-business (fully started)
- **WSVR0605W** — Thread stuck, potential hung thread

### Data Source (DSRA)
- **DSRA8020E** — JDBC connection failed, check DB host/port/credentials
- **DSRA0010E** — SQL exception during operation
- **DSRA0080E** — Connection pool exhausted, all connections in use
- **DSRA7600I** — Data source cleanup (informational)

### SSL/PKI (CWPKI)
- **CWPKI0022E** — Certificate chain validation failed
- **CWPKI0033E** — Certificate expired
- **CWPKI0823E** — Certificate not trusted, missing from truststore

### Transaction Manager (WTRN)
- **WTRN0006W** — Transaction timeout
- **WTRN0074W** — Transaction rolled back due to timeout
- **WTRN0062E** — Unresolved transaction, potential data inconsistency

### Liberty App Manager (CWWKZ)
- **CWWKZ0001I** — Application started
- **CWWKZ0003I** — Application updated
- **CWWKZ0009I** — Application stopped
- **CWWKZ0013E** — Application failed to start

### Liberty Security (CWWKS)
- **CWWKS1100A** — Authentication failed
- **CWWKS3005E** — LDAP connection failed
- **CWWKS4105I** — LTPA key generated

## Triage Priority

1. **E-suffix codes** with stacktraces — immediate investigation
2. **W-suffix codes** recurring in bursts — likely systemic issue
3. **A-suffix codes** — audit trail, review for unauthorized access
4. **I-suffix codes** — context only, skip unless correlated with errors
