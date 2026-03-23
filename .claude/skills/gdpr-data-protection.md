# GDPR & Data Protection for LogPilot

## Core Principle

LogPilot processes log data that may contain personal data (PII). All data must be redacted before it leaves the user's control — especially before sending to external AI providers.

## What Must Be Redacted

### Already Implemented (parser.py SECRET_REPLACERS)
- Bearer tokens, JWT tokens
- API keys, secrets, passwords, credentials
- AWS access keys (AKIA...)
- PEM private keys
- Basic/Digest auth headers
- Signature parameters

### Needs Implementation (PII)

| Category | Pattern | Example | Replacement |
|----------|---------|---------|-------------|
| Norwegian personnummer | 11 digits (DDMMYYnnnnn) | 15038812345 | [PERSONNR] |
| Norwegian org.nummer | 9 digits | 912345678 | [ORGNR] |
| Email addresses | user@domain.tld | erik@klpbank.no | [EMAIL] |
| IP addresses (v4) | x.x.x.x | 10.0.1.50 | [IP:10.0.1.x] (keep subnet) |
| IP addresses (v6) | full/compressed | 2001:db8::1 | [IPv6] |
| Credit card numbers | 13-19 digits | 4532015112830366 | [CARD] |
| IBAN | CC + 2 check + up to 30 | NO9386011117947 | [IBAN] |
| Phone numbers (NO) | +47/0047 + 8 digits | +4791234567 | [PHONE] |
| UUID (optional) | 8-4-4-4-12 hex | a1b2c3d4-... | Keep (needed for trace correlation) |

### Context-Dependent (configurable)
- **Hostnames**: May be internal infrastructure names — redact in SaaS, keep in self-service
- **Usernames**: In log entries like `user=erik.hansen` — redact in SaaS
- **File paths**: May contain usernames `/home/erik/...` — redact user part
- **Database values**: Query parameters in STATEMENT lines — redact values

## Redaction Strategy

### When to Redact

1. **At parse time** (current): secrets stripped from event text before storage
2. **Before AI** (critical): PII stripped from all text sent to external AI providers
3. **In exports** (important): HTML/MD/PDF reports should use redacted text
4. **In API responses** (platform): configurable per workspace

### Redaction Levels

| Level | What's redacted | Use case |
|-------|----------------|----------|
| **none** | Nothing | Local laptop, no external AI |
| **secrets** | Tokens, keys, passwords | Default — current behavior |
| **standard** | Secrets + PII (personnummer, email, phone, cards) | Recommended for AI calls |
| **strict** | Standard + IPs, hostnames, usernames, DB values | Financial/government, SaaS |

### Implementation Pattern

```python
# Configurable redaction level
REDACTION_LEVELS = {
    "none": [],
    "secrets": SECRET_REPLACERS,
    "standard": SECRET_REPLACERS + PII_REPLACERS,
    "strict": SECRET_REPLACERS + PII_REPLACERS + INFRA_REPLACERS,
}

def redact(text: str, level: str = "secrets") -> str:
    """Redact sensitive data at the specified level."""
    for rx, repl in REDACTION_LEVELS[level]:
        text = rx.sub(repl, text)
    return text
```

### IP Address Special Handling

IP addresses are diagnostic — keep the subnet but mask the host:
- `10.0.1.50` → `[IP:10.0.1.x]` (keeps network topology visible)
- `192.168.1.100` → `[IP:192.168.1.x]`
- External IPs: full redact `159.171.100.25` → `[EXT_IP]`

Private ranges (10.x, 172.16-31.x, 192.168.x) keep subnet. Public IPs fully redacted.

## GDPR Articles Relevant to LogPilot

| Article | Requirement | How LogPilot Addresses |
|---------|-------------|----------------------|
| Art. 5(1)(c) | Data minimization | Redact PII at parse time; only store what's needed |
| Art. 5(1)(e) | Storage limitation | Session expiry; workspace data retention policies |
| Art. 17 | Right to erasure | Cascading delete of workspace/session/events |
| Art. 15 | Right to access | Export endpoint: `GET /api/workspace/export` |
| Art. 25 | Data protection by design | RedactedText newtype (platform); redaction levels |
| Art. 28 | Processor agreements | AI providers are sub-processors; document in DPA |
| Art. 32 | Security of processing | Encryption at rest, TLS in transit, audit log |
| Art. 33 | Breach notification | Audit log tracks all AI calls and data access |
| Art. 44-49 | International transfers | EU-default SaaS hosting; AI provider EU endpoints |

## AI Provider Data Processing

| Provider | Data location | DPA available | EU endpoint |
|----------|--------------|---------------|-------------|
| Anthropic (Claude) | US, EU available | Yes | eu.anthropic.com |
| Google (Gemini) | EU available | Yes (via Google Cloud) | europe-west regions |
| OpenAI | US, EU available | Yes | eu.openai.com (coming) |
| Local AI | On-premise | N/A — no data leaves | localhost |

### Recommendation for Sensitive Customers
1. Use Local AI (no data leaves the network)
2. Or use EU endpoints with DPA signed
3. Always enable "standard" or "strict" redaction level
4. Disable external AI entirely (`ai_external_enabled: false`)

## Norwegian-Specific Regulations

- **Personopplysningsloven**: Norwegian implementation of GDPR
- **Datatilsynet**: Norwegian DPA — must be notified of breaches within 72h
- **Normen (Norm for informasjonssikkerhet)**: Health sector security standard
  - Relevant for HelseNorge integration scenarios
  - Requires encryption, access control, audit logging
- **Finanstilsynet**: Financial sector regulations
  - Cloud outsourcing notification requirements
  - Data must be accessible for supervisory review

## Workspace Settings (Platform)

```yaml
workspace:
  data_protection:
    redaction_level: "standard"      # none | secrets | standard | strict
    ai_external_enabled: true        # false = only local AI
    ai_preferred_region: "eu"        # eu | us | any
    data_retention_days: 90          # auto-delete sessions after N days
    export_redaction: true           # redact PII in exported reports
    audit_log_enabled: true          # log all AI calls and data access
```
