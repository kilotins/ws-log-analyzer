# Thread Correlation Analysis

## WAS Thread Naming

WebSphere threads follow naming conventions:
- `WebContainer : N` — HTTP request processing threads
- `Default Executor-thread-N` — Liberty managed threads
- `SIBJMSRAThreadPool : N` — JMS/messaging threads
- `ORB.thread.pool : N` — IIOP/RMI threads
- `TimerThread-N` — Scheduled task threads
- `HAManager.thread.pool : N` — High availability threads
- `server.startup : N` — Server startup threads

## Hung Thread Detection

WAS logs WSVR0605W when a thread exceeds the hung thread threshold (default 10 min).

### Correlation Steps

1. **Find the thread name** in the WSVR0605W message
2. **Search for the same thread name** in surrounding log entries
3. **Build a timeline**: what was the thread doing before it hung?
4. **Check the stacktrace**: where is it stuck?

### Common Hung Thread Causes

| Stuck At | Likely Cause | Fix |
|----------|-------------|-----|
| `java.net.SocketInputStream.read` | Waiting for remote response | Check target service, add timeouts |
| `java.lang.Object.wait` | Waiting for lock/notify | Thread contention, deadlock |
| `oracle.jdbc.driver.T4C*` | Waiting for DB response | Slow query, DB overloaded |
| `com.ibm.ws.rsadapter.*` | Connection pool wait | Pool exhausted, increase max or fix leak |
| `javax.naming.InitialContext` | JNDI lookup hanging | LDAP/naming service down |

## Thread Pool Exhaustion

When all WebContainer threads are busy:
- New HTTP requests queue up
- Clients see timeouts
- Log pattern: many concurrent WSVR0605W for `WebContainer` threads

### Diagnosis
```
Count threads by state:
- RUNNABLE at same method = systemic bottleneck
- BLOCKED on same lock = lock contention
- WAITING at Object.wait = resource exhaustion
```

## Cross-Thread Correlation

Events from the same request may span threads (async processing):
1. Look for request IDs or correlation IDs in the log message
2. Match timestamps within a narrow window
3. Follow the chain: WebContainer -> EJB -> JMS -> Timer

## Liberty Thread Dumps

Liberty uses `server javadump <serverName>` to produce thread dumps.
The dump file contains:
- All thread stacks
- Lock information
- Memory summary

Key sections:
- `1LKDEADLOCK` — deadlock detected (critical)
- `3XMTHREADBLOCK` — thread blocked waiting for lock
- `2LKMONINUSE` — monitors currently held
