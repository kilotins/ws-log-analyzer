# Log4j / Logback Analysis (Java/Spring Boot)

## Log Format Patterns

### Log4j2 Default
```
2025-03-11 10:15:33,123 ERROR [main] com.example.App - Connection failed
```
Pattern: `%d{yyyy-MM-dd HH:mm:ss,SSS} %-5level [%thread] %logger - %msg%n`

### Logback / Spring Boot Default
```
2025-03-11 10:15:33.123  ERROR 12345 --- [nio-8080-exec-1] c.e.controller.UserController : Failed to fetch user
```
Pattern: `%d{yyyy-MM-dd HH:mm:ss.SSS} %5level %pid --- [%thread] %logger : %msg%n`

Spring Boot's distinctive marker: ` --- ` (three dashes surrounded by spaces).

### Log4j 1.x Legacy
```
2025-03-11 10:15:33,123 ERROR com.example.App - Something failed
```
Pattern: `%d %-5p %c - %m%n`

### Common Variations
- MDC context: `[userId=123, requestId=abc-def]` before or after thread
- Pattern with method: `%M` adds method name
- JSON layout: see `skills/json-structured-logs.md`

## Detection Heuristics

Score high if:
1. Timestamp in `yyyy-MM-dd HH:mm:ss[,.]SSS` format
2. Followed by level: `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE`, `FATAL`
3. Thread name in brackets: `[thread-name]`
4. Logger class in dot notation: `com.example.module.Class`
5. Spring Boot marker: ` --- ` with PID

## Level Mapping

| Log4j/Logback | Normalized | Note |
|---------------|------------|------|
| `FATAL` | `ERROR` | Log4j only (Logback doesn't have FATAL) |
| `ERROR` | `ERROR` | |
| `WARN` | `WARN` | |
| `INFO` | `INFO` | |
| `DEBUG` | `DEBUG` | |
| `TRACE` | `DEBUG` | Finest granularity |

## Spring Boot Specific Patterns

### Startup Sequence
```
  .   ____          _            __ _ _
 /\\ / ___'_ __ _ _(_)_ __  __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/  ___)| |_)| | | | | || (_| |  ) ) ) )
  '  |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/
 :: Spring Boot ::                (v3.2.0)

Started MyApplication in 4.567 seconds (process running for 5.123)
```

### Startup Failures

| Pattern | Meaning | Fix |
|---------|---------|-----|
| `APPLICATION FAILED TO START` | Fatal startup error | Read the description and action below it |
| `BeanCreationException` | Spring can't create a bean | Missing dependency, config error |
| `UnsatisfiedDependencyException` | Injection failed | Missing bean, circular dependency |
| `PortInUseException` | Port already bound | Kill other process or change `server.port` |
| `DataSourceBeanCreationException` | DB connection failed at startup | Check datasource URL, credentials |
| `NoSuchBeanDefinitionException` | Missing bean | Missing `@Component`, wrong package scan |

### Auto-Configuration
```
Negative matches:
   AopAutoConfiguration.AspectJAutoProxyingConfiguration:
      Did not match:
         - @ConditionalOnClass did not find required class 'org.aspectj.weaver.Advice'
```

Negative matches at DEBUG level are normal — they show what was NOT auto-configured.

### Actuator Health
```
Readiness probe failed: HTTP probe failed with statuscode: 503
Liveness probe failed: HTTP probe failed with statuscode: 503
```

## Common Exception Patterns

### Database / JPA / Hibernate

| Exception | Meaning | Check |
|-----------|---------|-------|
| `CannotCreateTransactionException` | Can't start DB transaction | Connection pool exhausted, DB down |
| `JDBCConnectionException` | JDBC connection failed | DB host/port, credentials, firewall |
| `QueryTimeoutException` | SQL query too slow | Slow query, missing index, full table scan |
| `DataIntegrityViolationException` | Constraint violation | Unique key, FK, NOT NULL |
| `OptimisticLockingFailureException` | Concurrent update conflict | Retry logic needed |
| `LazyInitializationException` | Hibernate session closed | N+1 query problem, add `@Transactional` |
| `StaleObjectStateException` | Row updated by another tx | Optimistic locking conflict |

### Connection Pool (HikariCP)

```
HikariPool-1 - Connection is not available, request timed out after 30000ms.
HikariPool-1 - Pool stats (total=10, active=10, idle=0, waiting=5)
```

**Critical**: `active=total` and `waiting>0` = pool exhausted. Root cause: slow queries, connection leaks, or pool too small.

### Spring Security

| Pattern | Meaning |
|---------|---------|
| `Access is denied` | Authorization failure (has auth but lacks permission) |
| `Full authentication is required` | No auth provided for protected endpoint |
| `Bad credentials` | Wrong username/password |
| `JWT expired` | Token past expiration |
| `CORS rejected` | Cross-origin request blocked |

### Spring Web / MVC

| Pattern | Meaning |
|---------|---------|
| `HttpMessageNotReadableException` | Can't deserialize request body (bad JSON) |
| `MethodArgumentNotValidException` | `@Valid` validation failed |
| `HttpRequestMethodNotSupportedException` | Wrong HTTP method |
| `NoHandlerFoundException` | No controller mapped for URL |
| `AsyncRequestTimeoutException` | Async request exceeded timeout |

## Kafka Broker & Client Logs

### Broker
```
[Controller id=0] Processing automatic preferred leader election  (kafka.controller.KafkaController)
Disconnecting node 2 due to socket timeout (org.apache.kafka.clients.NetworkClient)
```

### Consumer
```
[Consumer clientId=app-1, groupId=my-group] Revoking previously assigned partitions [topic-0, topic-1]
CommitFailedException: Commit cannot be completed since the group has already rebalanced
```

| Pattern | Meaning |
|---------|---------|
| `Rebalancing` | Consumer group membership change — temporary but causes lag |
| `CommitFailedException` | Consumer too slow, session timed out |
| `RecordTooLargeException` | Message exceeds `max.message.bytes` |
| `NotLeaderOrFollowerException` | Broker leadership change, transient |
| `OutOfOrderSequenceException` | Idempotent producer duplicate detection |

## Signal Tags

| Tag | Detection pattern |
|-----|-------------------|
| `DB/Pool` | `HikariPool`, `connection pool`, `DataSource`, `JDBC`, `connection not available` |
| `OOM/GC` | `OutOfMemoryError`, `GC overhead`, `Java heap space` |
| `SpringBoot` | `APPLICATION FAILED TO START`, `BeanCreation`, `AutoConfiguration` |
| `Kafka` | `Rebalancing`, `CommitFailed`, `kafka.controller` |
| `Auth` | `Access is denied`, `Bad credentials`, `JWT expired` |
| `Timeout` | `timed out`, `QueryTimeout`, `SocketTimeout`, `request timed out` |
| `HungThreads` | `ThreadMonitor`, `stuck thread`, `deadlock detected` |

## Triage Strategy

1. **Check startup** — did the app start successfully? Look for `Started ... in X seconds`
2. **Group by logger** — same logger = same component causing issues
3. **Root cause chain** — follow `Caused by:` to the deepest exception
4. **Check thread names** — `nio-8080-exec-*` = HTTP request threads, `scheduling-*` = background tasks
5. **Connection pool stats** — `active=total` is the #1 Spring Boot production issue
6. **Correlate by MDC** — `requestId`, `userId`, `traceId` tie events together across services
