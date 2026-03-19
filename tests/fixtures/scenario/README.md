# E-Commerce Checkout Outage Scenario

Synthetic log files simulating a cascading database pool exhaustion across 6 systems.

## Timeline (2025-03-15 UTC)

| Time  | System          | Event                                      |
|-------|-----------------|--------------------------------------------|
| 14:25 | All             | Normal operations                          |
| 14:30 | checkout-was    | DB pool exhausted (J2CA0045E)              |
| 14:30 | checkout-was    | Hung threads (WSVR0605W)                   |
| 14:30 | checkout-was    | Transaction timeouts (WTRN0006W)           |
| 14:30 | payment-api     | HikariCP pool exhausted                    |
| 14:30 | payment-api     | SocketTimeoutException to payment gateway  |
| 14:30 | frontend-lb     | 502 Bad Gateway, upstream timed out        |
| 14:30 | order-service   | ECONNREFUSED to database, circuit breaker  |
| 14:30 | payment-pod     | OOMKilled, CrashLoopBackOff                |
| 14:30 | order-worker    | Celery SoftTimeLimitExceeded               |
| 14:30 | order-worker    | psycopg2 Connection refused                |
| 14:31 | frontend-lb     | 429 rate limiting                          |
| 14:35 | checkout-was    | OutOfMemoryError, session serialization    |
| 14:40 | All             | Gradual recovery                           |

## Shared trace ID

`a1b2c3d4-1234-5678-9abc-def012345678` appears in checkout-was, frontend-lb, and order-service.

## Files

| File               | Format | Key triggers                              |
|--------------------|--------|-------------------------------------------|
| checkout-was.log   | WAS    | db-pool, hung-threads, oom-gc, session    |
| frontend-lb.log    | nginx  | nginx-502, http-5xx, rate-limit           |
| payment-api.log    | Log4j  | hikari-pool, timeout-generic              |
| order-service.log  | JSON   | json-fatal, ECONNREFUSED, connection-refused |
| payment-pod.log    | CRI-O  | k8s-oomkilled, k8s-crashloop             |
| order-worker.log   | Python | celery-task-fail, django-db               |
