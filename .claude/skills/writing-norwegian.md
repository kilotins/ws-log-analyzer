# Writing Norwegian (Bokmål) — LogPilot Conventions

## When to Use

- All customer-facing documentation should exist in both English and Norwegian
- Norwegian versions target Nordic/European customers, especially Item Consulting's network
- English is the source — Norwegian is translated from English, never the other way

## Technical Terms: Keep in English

These terms are always kept in English, even in Norwegian text. They are standard in Norwegian IT:

### Infrastructure & Tools
DevOps, SaaS, API, SDK, CLI, CI/CD, Docker, Kubernetes, Helm, Redis, PostgreSQL, SQLite, ClickHouse, DuckDB, Parquet, MinIO, S3, Nginx, Apache, Tomcat

### Frameworks & Libraries
FastAPI, React, TypeScript, Tailwind, shadcn/ui, Tanstack Query, Vite, Pydantic, PyO3, Rust, structlog, Alembic, Playwright, Vitest, pytest, httpx

### Security & Auth
OIDC, SSO, SCIM, JWT, CORS, RLS, GDPR, CSRF, bcrypt, OAuth, SAML, mTLS, PKCE

### AI & Data
RAG, SSE, NDJSON, JSONB, pgvector, embedding, token, prompt, streaming

### Product & Brand Names
LogPilot, Item Consulting, Datadog, Splunk, Sentry, ChatGPT, Claude, OpenAI, Gemini, Anthropic, GitHub, GitLab, Jira, Linear, Slack, PagerDuty, Stripe, Vipps, Enonic XP, Hacker News, LinkedIn

### Development Concepts
webhook, pipeline, endpoint, middleware, adapter, protocol, plugin, backend, frontend, deploy, release, sprint, refactor, monorepo, scaffolding, boilerplate

### Product / UX Concepts
workspace, self-service, runbook, redaction, on-call, changelog, deployment, self-hosted, customer-hosted, trade-off, edge case

## Terms to Translate

| English | Norwegian (bokmål) |
|---------|-------------------|
| organization | organisasjon |
| member | medlem |
| user | bruker |
| setting(s) | innstilling(er) |
| incident | hendelse |
| event (log) | hendelse (logg) |
| heuristic | heuristikk |
| evidence | bevis |
| root cause | rotårsak |
| cascade | kaskade |
| timeline | tidslinje |
| report | rapport |
| upload | opplasting |
| session | økt |
| audit log | revisjonslogg |
| billing | fakturering |
| pricing | prising |
| trial | prøveperiode |
| milestone | milepæl |
| open source | open source (keep English) |
| dead code | død kode |
| technical debt | teknisk gjeld |
| blast radius | skadeomfang |
| bottleneck | flaskehals |

## Sentence Structure

### Keep it natural
Don't translate word-for-word. Norwegian has different sentence structure:
- English: "The system must support hosting outside the US"
- Bad: "Systemet må støtte hosting utenfor USA"
- Good: "Systemet må kunne driftes utenfor USA"

### Passive vs active
Norwegian prefers active voice more than English:
- English: "Logs are parsed by the engine"
- Norwegian: "Motoren parser loggene"

### Compound words
Norwegian creates compound words where English uses spaces:
- log file → loggfil
- error code → feilkode
- database connection → databasetilkobling
- format plugin → formatplugin
- time series → tidsserie
- workspace member → arbeidsområdemedlem

## What NOT to Translate

- **Code blocks** — all code stays in English (including comments)
- **ASCII diagrams** — keep exactly as they are
- **File paths** — `logpilot/parser.py` stays as-is
- **CLI commands** — `docker compose up` stays as-is
- **HTML/CSS** — all attributes, classes, IDs stay in English
- **URLs** — all links stay as-is
- **API paths** — `/api/v1/workspaces/{slug}/export` stays as-is
- **Error codes** — `ORA-00060`, `CWWKE0701E`, `SQLCODE -904` stay as-is
- **Configuration keys** — `LOGPILOT_DATABASE_URL` stays as-is

## HTML Document Conventions

When translating HTML documents:
- Change `lang="en"` to `lang="nb"`
- Translate title and subtitle
- Change date format: "March 2026" → "Mars 2026"
- Change footer: "Generated with Claude Code" → "Generert med Claude Code"
- Keep all CSS, classes, IDs, and structure identical
- Keep `&mdash;`, `&rarr;`, `&ldquo;`, `&rdquo;` entities unchanged

## Month Names
| English | Norwegian |
|---------|-----------|
| January | Januar |
| February | Februar |
| March | Mars |
| April | April |
| May | Mai |
| June | Juni |
| July | Juli |
| August | August |
| September | September |
| October | Oktober |
| November | November |
| December | Desember |

## Quality Checklist

Before delivering a Norwegian translation:
- [ ] All section headings translated
- [ ] All table headers translated
- [ ] All callout titles and body text translated
- [ ] All list items (descriptions, not code) translated
- [ ] Code blocks untouched
- [ ] ASCII diagrams untouched
- [ ] Technical terms in English where appropriate
- [ ] `lang="nb"` set
- [ ] Date in Norwegian format
- [ ] Footer in Norwegian
- [ ] No machine-translation artifacts (unnatural phrasing)
- [ ] Compound words correctly formed (loggfil, not logg fil)
