# Python Logging Analysis (Django/Flask/FastAPI)

## Log Format Patterns

### stdlib logging (default)
```
WARNING:root:Something happened
ERROR:django.request:Internal Server Error: /api/users
```
Pattern: `%(levelname)s:%(name)s:%(message)s`

### stdlib logging (with format)
```
2025-03-11 10:15:33,123 ERROR django.request Internal Server Error: /api/users
2025-03-11 10:15:33,123 - myapp.views - ERROR - Connection refused
```
Common patterns:
- `%(asctime)s %(levelname)s %(name)s %(message)s`
- `%(asctime)s - %(name)s - %(levelname)s - %(message)s`

### uvicorn / gunicorn
```
INFO:     127.0.0.1:54321 - "GET /api/users HTTP/1.1" 200 OK
[2025-03-11 10:15:33 +0100] [12345] [ERROR] Worker timeout (pid:12346)
```

### structlog (key=value)
```
2025-03-11 10:15:33 [info     ] request_started    method=GET path=/api/users
2025-03-11 10:15:33 [error    ] request_failed     method=GET path=/api/users status=500 exc_info=True
```

## Detection Heuristics

Score high if:
1. Level names match Python conventions: `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG`
2. Logger names use dot notation: `django.request`, `myapp.views`
3. Timestamp uses comma before milliseconds: `2025-03-11 10:15:33,123`
4. Python tracebacks present: `Traceback (most recent call last):`
5. `File "..."` references with `.py` extensions

## Python Traceback Structure

```
Traceback (most recent call last):
  File "/app/views.py", line 42, in get_user
    user = User.objects.get(pk=user_id)
  File "/venv/lib/python3.11/site-packages/django/db/models/manager.py", line 87, in manager_method
    return getattr(self.get_queryset(), name)(*args, **kwargs)
  File "/venv/lib/python3.11/site-packages/django/db/models/query.py", line 637, in get
    raise self.model.DoesNotExist(...)
myapp.models.User.DoesNotExist: User matching query does not exist.
```

### Key Differences from Java Stacktraces

| Feature | Python | Java |
|---------|--------|------|
| Direction | **Most recent call LAST** (bottom is closest to error) | Most recent call first |
| Format | `File "path", line N, in func` | `at package.Class.method(File.java:N)` |
| Chaining | `__cause__` / `__context__` with headers | `Caused by:` |
| Multiple | `During handling... another exception occurred:` | Single `Caused by:` chain |

### Exception Chaining

```
Traceback (most recent call last):
  File "app.py", line 10, in connect
    db.connect()
ConnectionError: Connection refused

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "app.py", line 15, in handle_request
    connect()
RuntimeError: Database unavailable

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "app.py", line 20, in main
    handle_request()
ServiceError: Service initialization failed
```

Three chaining headers:
- `During handling of the above exception, another exception occurred:` — implicit chaining (`__context__`)
- `The above exception was the direct cause of the following exception:` — explicit chaining (`raise X from Y`)

**Root cause**: The FIRST traceback (topmost) is usually the root cause.

## Django Specific Patterns

### Request Errors
```
ERROR django.request Internal Server Error: /api/users
Traceback (most recent call last):
  ...
django.http.Http404: No User matches the given query.
```

### Common Django Exceptions

| Exception | Meaning | Check |
|-----------|---------|-------|
| `DoesNotExist` | Object not found in DB | 404 handling, data integrity |
| `MultipleObjectsReturned` | `.get()` matched multiple rows | Unique constraint missing |
| `OperationalError` | DB connection/query failure | DB availability, query syntax |
| `IntegrityError` | Constraint violation | Unique, FK, NOT NULL |
| `ImproperlyConfigured` | Settings misconfiguration | Check settings.py |
| `PermissionDenied` | Authorization failure | View permissions, object-level perms |
| `SuspiciousOperation` | Security violation | CSRF, Host header, file upload path |
| `DisallowedHost` | Host header not in ALLOWED_HOSTS | Add hostname to settings |
| `TemplateDoesNotExist` | Template file not found | Template path, DIRS setting |
| `ValidationError` | Form/serializer validation failed | Input data, field constraints |

### Django ORM Warnings
```
WARNING django.db.backends (0.150) SELECT ... ; args=(...)
```

Slow query warnings when `DEBUG=True` or with django-querycount.

### Migration Errors
```
django.db.utils.ProgrammingError: relation "myapp_user" does not exist
django.db.migrations.exceptions.InconsistentMigrationHistory
```

## Flask / FastAPI Specific

### Flask
```
ERROR flask.app Exception on /api/users [GET]
werkzeug.exceptions.NotFound: 404 Not Found: The requested URL was not found
```

### FastAPI / uvicorn
```
ERROR:    Exception in ASGI application
INFO:     127.0.0.1:54321 - "POST /api/users HTTP/1.1" 422 Unprocessable Entity
```

| FastAPI Status | Meaning |
|----------------|---------|
| 422 | Pydantic validation error (common, not a bug) |
| 500 | Unhandled exception |
| 307 | Redirect (trailing slash) |

### Pydantic Validation Errors
```
pydantic.error_wrappers.ValidationError: 2 validation errors for UserCreate
  email
    value is not a valid email address (type=value_error.email)
  age
    ensure this value is greater than 0 (type=value_error.number.not_gt)
```

## Celery / Background Tasks

```
[2025-03-11 10:15:33,123: ERROR/ForkPoolWorker-1] Task myapp.tasks.send_email[abc-123] raised unexpected: ConnectionError('Connection refused')
[2025-03-11 10:15:33,123: WARNING/ForkPoolWorker-1] Task myapp.tasks.process[def-456] retry: Retry in 60s
```

| Pattern | Meaning |
|---------|---------|
| `raised unexpected` | Task failed with unhandled exception |
| `retry: Retry in Ns` | Task will be retried |
| `max retries exceeded` | All retries exhausted |
| `WorkerLostError` | Worker process crashed (OOM, segfault) |
| `TimeLimitExceeded` | Task exceeded `time_limit` |

## Signal Tags

| Tag | Detection pattern |
|-----|-------------------|
| `Django` | `django.request`, `django.db`, `django.security` |
| `Flask` | `flask.app`, `werkzeug` |
| `FastAPI` | `uvicorn`, `fastapi`, `starlette` |
| `Celery` | `celery.worker`, `ForkPoolWorker`, `Task.*raised` |
| `DB` | `OperationalError`, `IntegrityError`, `ProgrammingError` |
| `Auth` | `PermissionDenied`, `SuspiciousOperation`, `401`, `403` |
| `Timeout` | `TimeoutError`, `TimeLimitExceeded`, `ConnectionTimeout` |
| `Import` | `ImportError`, `ModuleNotFoundError` |
| `OOM` | `MemoryError`, `WorkerLostError`, `Killed` |

## Triage Strategy

1. **Read tracebacks bottom-up** (last frame is closest to the error)
2. **Distinguish app code from framework** — focus on files in `/app/`, not `/venv/`
3. **Check exception chaining** — root cause is often the FIRST traceback
4. **Group by logger name** — `django.request` = view errors, `django.db` = DB errors
5. **Check for patterns** — same exception across multiple endpoints = systemic issue
6. **Celery**: Check if tasks are retrying indefinitely → downstream service is down
