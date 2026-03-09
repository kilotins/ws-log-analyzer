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

## MicroProfile Reactive Messaging

### Message Processing Failures
```
CWMRX1100E: Reactive messaging channel <name> encountered an error
CWMRX0101W: Message acknowledgement failed on channel <name>
```
Causes:
- Message deserialization failure (wrong schema/format)
- Downstream consumer not available (Kafka broker down)
- Processing method threw an exception

### Kafka Connector Errors
```
CWMRX1003E: Kafka connection failed for channel <name>
```
Check:
- Kafka broker connectivity (bootstrap.servers config)
- Topic existence and ACLs
- SSL/SASL config if using secure Kafka

## MicroProfile Metrics Failures

```
CWMMC0007E: Metrics endpoint error
CWMMC0013W: Metric registration failed
```
Usually non-critical but indicates monitoring gaps:
- Duplicate metric names across applications
- Unsupported metric type for the registry
- Metrics endpoint blocked by security config

## OSGi Bundle Resolution Errors

Liberty is built on OSGi. Bundle errors surface as:
```
CWWKE0702E: Could not resolve module: <bundle> [id]
  Unresolved requirement: Import-Package: com.ibm.ws.something; version="[1.0,2.0)"
```
This differs from app ClassNotFoundException:
- **App ClassNotFoundException**: missing JAR in WEB-INF/lib
- **OSGi resolution error**: Liberty runtime feature conflict or missing feature

Fix: Add the required feature to `server.xml` or resolve version conflicts.

## Liberty on Non-Default JDKs

### Eclipse Temurin / AdoptOpenJDK
- Thread dump format differs slightly (no `1CIJAVAVERSION` section)
- GC log format: use `-Xlog:gc*` (not `-verbose:gc`)
- Crypto providers may differ (affects SSL initialization)

### Java 17+ Considerations
```
WARNING: A restricted reflective access operation has occurred
WARNING: --add-opens may be required
```
Liberty on Java 17+ needs JVM args for reflection access:
```
-XX:+IgnoreUnrecognizedVMOptions
--add-opens=java.base/java.lang=ALL-UNNAMED
```
These warnings are noisy but important — if the access is blocked (not just warned), features break silently.

## Graceful Shutdown Patterns

Normal shutdown:
```
CWWKE1100I: Quiescing server
CWWKZ0009I: Application <name> stopped
CWWKE0036I: Server stopped after X seconds
```

Forced/ungraceful shutdown:
- No CWWKE1100I before CWWKE0001I (restart without shutdown)
- CWWKE0036I missing → process was killed (kill -9)
- Active requests interrupted → check for partial transactions (WTRN0062E)

## Incident Response Playbook

### Scenario: Liberty Server Not Responding
1. Check if CWWKF0011I ("ready to run") ever appeared → if not, startup failed
2. If running, take thread dump: `server javadump <name>`
3. Check health endpoint: `/health/ready` → if DOWN, check which health check failed
4. Check metrics endpoint: `/metrics` → look for active request count
5. If no response at all → check if process is alive (`ps aux | grep liberty`)
6. Check messages.log (not SystemOut.log) — Liberty logs there by default
