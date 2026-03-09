# Security Log Analysis

## Authentication Failures

### Pattern: Brute Force / Credential Stuffing
```
CWWKS1100A: Authentication did not succeed for user <id>
```
High volume of CWWKS1100A for different usernames = credential stuffing.
High volume for same username = brute force.

Splunk detection:
```spl
index=websphere msg_code="CWWKS1100A"
| timechart span=1m count
| where count > 50
```

### Pattern: Account Lockout
Repeated CWWKS1100A followed by CWWKS1101A (account locked).
Check if legitimate user or attack.

### LTPA Token Issues
```
CWWKS4104A: LTPA token not valid
CWWKS1106A: LTPA token expired
```
Causes:
- Token expired (normal after timeout)
- LTPA keys rotated (all tokens invalidated)
- Token from different cluster (key mismatch)
- Tampered token (security concern)

## SSL/TLS Issues

### Certificate Expiry
```
CWPKI0033E: Certificate with alias <name> has expired
```
Action: Renew certificate immediately. Check all certs in the chain.

### Trust Failure
```
CWPKI0022E: SSL certificate chain could not be verified
CWPKI0823E: Certificate not trusted
```
Causes:
- Self-signed cert not in truststore
- Intermediate CA missing from chain
- CA root cert not in truststore
- Certificate revoked

### Protocol/Cipher Mismatch
```
SSLHandshakeException: no cipher suites in common
SSLHandshakeException: protocol version not supported
```
Client and server disagree on TLS version or cipher suite.
Check: `ssl-1.0` feature config, JVM security.properties.

## Authorization Failures

### Forbidden Access
```
CWWKS9104A: Authorization check failed for user <id> accessing <resource>
```
User authenticated but lacks required role.
Check: `application-bnd` in `server.xml`, role mapping.

### JAAS Login Failures
```
CWWKS1102E: JAAS login failed
```
Custom login module error. Check the `Caused by:` chain.

## Security Audit Trail

Important audit events to monitor:
| Code | Event |
|------|-------|
| CWWKS1100A | Authentication failure |
| CWWKS1101A | Account locked |
| CWWKS9104A | Authorization denied |
| CWWKS4104A | Invalid token |
| CWPKI0033E | Cert expired |
| CWPKI0022E | Cert untrusted |

## OAuth2 / OpenID Connect (Liberty)

### Token Validation Failures
```
CWWKS1616E: The OpenID Connect client received an invalid token
CWWKS1617E: Token signature verification failed
CWWKS1631E: The OAuth endpoint could not validate the access token
```
Causes:
- Token expired or issued by a different provider
- JWKS endpoint unreachable (cannot fetch public key)
- Clock skew between provider and WAS server (> 5 min drift)

### Provider Connectivity
```
CWWKS1708E: Unable to contact the OpenID Connect provider
CWWKS1524E: The OIDC client failed to obtain an access token
```
Check:
- Network/firewall between WAS and the identity provider
- DNS resolution of the provider URL
- Provider certificate in WAS truststore (if HTTPS)

### Splunk Detection for OAuth Failures
```spl
index=websphere msg_code IN ("CWWKS1616E","CWWKS1617E","CWWKS1631E","CWWKS1708E")
| timechart span=5m count by msg_code
```

## Mutual TLS (mTLS) Errors

### Client Certificate Failures
```
CWPKI0035E: The client certificate was not trusted
CWPKI0036W: Client certificate chain incomplete
```
Differs from server-side cert issues:
- **Server-side** (CWPKI0022E): WAS can't verify the _remote_ server's cert
- **Client-side** (CWPKI0035E): WAS can't verify the _client's_ cert presented during mTLS

Triage:
1. Verify client cert is signed by a CA in the WAS truststore
2. Check if the client cert has expired
3. Ensure the full cert chain is sent (root + intermediates)

## API Key / Service Account Failures

Service-to-service authentication often uses API keys or service accounts:
```
CWWKS1100A: Authentication did not succeed for user <service-account>
```
Distinguish from user attacks:
- Service account names follow patterns (`svc-*`, `api-*`, `system-*`)
- Failures from internal IPs = credential rotation issue, not attack
- Failures from external IPs = potential credential compromise

## Suspicious Patterns

1. **Off-hours authentication** — logins outside business hours
2. **Geographic anomaly** — logins from unexpected IPs (correlate with access logs)
3. **Privilege escalation** — CWWKS9104A followed by successful access to same resource
4. **Certificate probing** — rapid CWPKI errors from same source
5. **Session hijacking** — same session ID from different source IPs
6. **Token replay** — same token used from multiple IPs within a short window
7. **Credential rotation failure** — service account CWWKS1100A spikes after deployment (forgot to update secrets)

## Incident Response Playbook

### Scenario: Suspected Brute Force
1. Count unique usernames in CWWKS1100A — if many, it's credential stuffing
2. Extract source IPs (access logs) and check geo-location
3. Enable account lockout if not already active (`maxLoginFailures`)
4. Block offending IPs at WAF/load balancer
5. Check if any accounts were actually compromised (CWWKS1100A followed by successful login)

### Scenario: Certificate Emergency
1. Identify which cert expired (alias in CWPKI0033E message)
2. Check all certs: `keytool -list -v -keystore trust.p12 | grep -A2 "Valid"`
3. Renew from CA, import with `keytool -import`
4. Restart affected servers (certs are cached in memory)
5. Verify with `openssl s_client -connect host:port`
