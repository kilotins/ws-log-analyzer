# Java/WAS Stacktrace Analysis

## Stacktrace Structure

```
com.ibm.ws.SomeException: Error message
    at com.ibm.ws.module.Class.method(Class.java:123)
    at com.ibm.ws.module.Caller.invoke(Caller.java:45)
    ... 15 more
Caused by: java.sql.SQLException: Connection refused
    at oracle.jdbc.driver.T4CConnection.logon(T4CConnection.java:489)
    at com.ibm.ws.rsadapter.jdbc.WSJdbcConnection.init(WSJdbcConnection.java:78)
```

## Reading Strategy

1. **Start at the bottom** — the deepest `Caused by:` is the root cause
2. **Find the boundary** between framework and application code
3. **Note the exception type** — it tells you the failure category
4. **Check the message** — often contains the specific resource that failed

## Common Root Cause Exceptions

| Exception | Meaning | Check |
|-----------|---------|-------|
| `NullPointerException` | Null reference | Application bug, check the line number |
| `ClassNotFoundException` | Missing class at runtime | Classpath, missing JAR, classloader |
| `NoClassDefFoundError` | Class found at compile, missing at runtime | Classloader isolation, shared libs |
| `OutOfMemoryError` | Heap or metaspace exhausted | Heap dump, memory leak |
| `StackOverflowError` | Infinite recursion | Recursive call chain in trace |
| `SQLException` | Database operation failed | Connection, query, schema |
| `ConnectException` | TCP connection refused | Target host/port down |
| `SocketTimeoutException` | TCP read/connect timeout | Network latency, target overloaded |
| `SSLHandshakeException` | TLS negotiation failed | Certs, protocol version, cipher mismatch |
| `IllegalStateException` | Object in wrong state | Lifecycle bug, concurrent modification |
| `ConcurrentModificationException` | Collection modified during iteration | Thread safety issue |

## WAS-Specific Patterns

### Classloader Chain
WAS uses a hierarchical classloader: Bootstrap -> Extensions -> App -> WAR/Module.
`ClassNotFoundException` in WAS often means:
- JAR in wrong classloader scope (app vs shared)
- Parent-first vs parent-last misconfiguration
- Duplicate JARs at different classloader levels

### Connection Pool Exhaustion
```
Caused by: com.ibm.websphere.ce.cm.ConnectionWaitTimeoutException
```
All connections in use. Check: pool max size, connection leak (missing close()), slow queries.

### Transaction Timeout
```
Caused by: com.ibm.websphere.ce.cm.StaleConnectionException
```
Transaction exceeded timeout, connection invalidated. Check: `totalTranLifetimeTimeout`, long-running queries.

### Thread Dump Correlation
When a stacktrace appears with WSVR0605W (hung thread):
1. The stacktrace shows what the thread is stuck doing
2. Look for lock contention (`waiting to lock`, `BLOCKED`)
3. Check if multiple threads are stuck at the same point (systemic issue)

## Noise vs Signal

**Skip these** (framework internals, not actionable):
- `at sun.reflect.NativeMethodAccessorImpl.invoke`
- `at com.ibm.ws.webcontainer.servlet.ServletWrapper.service`
- `at java.lang.Thread.run`

**Focus on these** (application and integration boundaries):
- Lines with your application's package name
- JDBC driver classes (connection issues)
- JNDI lookup classes (resource configuration)
- SSL/TLS classes (certificate issues)
