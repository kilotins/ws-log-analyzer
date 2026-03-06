# WebSphere Liberty Analysis

## Liberty vs Traditional WAS

Liberty uses a feature-based, lightweight architecture:
- `server.xml` — central config (replaces dozens of tWAS admin console settings)
- Features loaded on demand, not monolithic
- Fast startup (seconds vs minutes for tWAS)
- Logs to `messages.log` (not SystemOut.log by default)

## Key Message Prefixes

| Prefix | Component |
|--------|-----------|
| CWWKE | Kernel |
| CWWKF | Feature manager |
| CWWKZ | App manager |
| CWWKS | Security |
| CWWKT | Transport (HTTP) |
| CWWKC | Config |
| CWWJP | JPA |
| CWWWC | Web container |
| CWNEN | JNDI/naming |

## Feature Issues

### Feature Not Found
```
CWWKF0001E: Feature <name> not found
```
Check: Typo in `server.xml`, feature not installed, wrong Liberty version.

### Feature Conflict
```
CWWKF0033E: Singleton conflict
```
Two features providing the same capability (e.g., `servlet-3.1` and `servlet-4.0`).
Fix: Remove one from `server.xml`.

### Feature Dependency Missing
```
CWWKF0032E: Feature <A> requires <B>
```
Add the required feature to `server.xml`.

## Config Errors

### Dynamic Config Update
Liberty reloads `server.xml` changes without restart. Watch for:
```
CWWKG0017I: Config update complete
CWWKG0018I: Config update processing
CWWKG0028A: Config validation error
```

### Common Config Mistakes
- Wrong JNDI name in datasource config
- Missing `library` reference for JDBC driver
- SSL config pointing to nonexistent keystore
- `host="*"` when you mean `host="0.0.0.0"`

## Liberty-Specific Patterns

### MicroProfile Health
```
CWMMH0052W: Health check <name> failed
CWMMH0053W: Health check reported DOWN
```
Application health endpoint returning unhealthy. Check:
- Database connectivity (readiness probe)
- Downstream service availability
- Custom health check logic

### MicroProfile Config
```
CWMCG0007E: Config property <name> not found
```
Missing required config property. Check:
- `microprofile-config.properties`
- Environment variables
- `server.xml` variables

### LTPA Token Issues
```
CWWKS4105I: LTPA keys created (normal on first start)
CWWKS4106A: LTPA config modified
CWWKS1100A: Authentication failed
```
If CWWKS1100A after CWWKS4105I on restart:
- LTPA keys regenerated, invalidating existing tokens
- Users must re-authenticate
- Fix: Share LTPA keys across cluster members

## Log Format

Liberty default JSON logging:
```json
{"datetime":"2024-01-15T10:30:00.000+0000","message":"...","loglevel":"ERROR","module":"com.ibm.ws.kernel"}
```

Enable with:
```xml
<logging messageFormat="json" consoleFormat="json"/>
```

When analyzing JSON logs, parse the `loglevel` and `module` fields for filtering.
