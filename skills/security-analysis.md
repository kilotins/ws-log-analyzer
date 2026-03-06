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

## Suspicious Patterns

1. **Off-hours authentication** — logins outside business hours
2. **Geographic anomaly** — logins from unexpected IPs (correlate with access logs)
3. **Privilege escalation** — CWWKS9104A followed by successful access to same resource
4. **Certificate probing** — rapid CWPKI errors from same source
5. **Session hijacking** — same session ID from different source IPs
