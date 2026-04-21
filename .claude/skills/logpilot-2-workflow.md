---
name: logpilot-2-workflow
description: Workflow för att bygga features till LogPilot 2.0 — orchestrerar planning-skills, expert-lenses, grill-me, implementation, review, code-health och debrief. Använd när en ny 2.0-feature ska planeras och byggas från idé till merge.
---

# LogPilot 2.0 Feature Workflow

Standardiserad sekvens för att bygga features till LogPilot 2.0. Orkestrerar befintliga skills i rätt ordning. Opus är orkestrerare; Sonnet-agenter exekverar välspecificerade steg.

## När denna skill används

- Ny 2.0-feature med oklart scope
- Större refactor som rör flera moduler
- Arkitektur-beslut som påverkar framtida features

**Används INTE för:**
- Små fixes (<20 rader) — kör direkt
- Bug triage — iterativt, inte planerbart upfront
- UI-tweaks — live-dialog bättre
- Dokumentation — skriv direkt

## Fas-sekvens

```
1. Scope & context      →  2. Grill the plan     →  3. Lenses
4. Implement (Sonnet)   →  5. Review (Sonnet)    →  6. Code-health
7. Debrief              →  8. LEARNINGS.md
```

### Fas 1: Scope & context

Använd planning-skills där de finns under `.claude/skills/planning/`. Aktivera dem genom att flytta upp relevanta subdirs till `.claude/skills/`-roten vid behov.

Minst obligatoriskt:
- `user-stories/SKILL.md` — vem och varför
- `architecture-review/SKILL.md` — tech-val, versions-pinning, API-konventioner

Output: kort spec-dokument i `docs/plan/<feature>.md` med:
- Persona + user story
- Domain-entiteter som berörs
- API-kontrakt (om backend)
- UX-skiss (om frontend)
- Test-strategi

### Fas 2: Grill the plan

Invoke `grill-me` (global skill). Claude intervjuar dig djup-först genom beslutsträdet. Varje fråga har rekommenderat svar.

**Gate:** spec:en måste överleva grillningen utan öppna beslut innan Fas 3.

### Fas 3: Expert lenses

Invoke `expert-lenses` (global skill). Flera experter (security, performance, UX, maintainability) debatterar specens trade-offs.

**Output:** lista med trade-offs + beslut "så här gör vi". Uppdatera spec-dokumentet.

**Gate:** inget röd-flagg som är oaccepterat.

### Fas 4: Implement

Spawn **Sonnet-agent** med:

```
Model: sonnet
Prompt: full spec från fas 1-3, tydlig filväg, formatkrav,
        "implementera enligt spec, inga extra features"
```

För parallella delar: spawn flera agenter samtidigt i samma meddelande.

### Fas 5: Review

Spawn **separat Sonnet-agent** (ren context) med:

```
Model: sonnet
Prompt: spec från fas 1-3 + diff från fas 4, granska mot
        säkerhet, korrekthet, edge cases, spec-avvikelser.
        Rapportera under 400 ord.
```

Opus läser review-rapporten och beslutar: accept, iterate, eller revert.

### Fas 6: Code-health

Invoke `code-health` (global skill). Scannar HELA codebase (inte bara diff) för:
- Arkitektur-drift från ursprungliga beslut
- Maintainability-issues
- Dead code
- Dependency-risker
- Test-gaps

**Gate:** high-severity findings blockerar merge tills åtgärdade.

### Fas 7: Debrief

Invoke `debrief` (global skill) — använd "mid-development correction" eller "version debrief" efter behov.

Output: skill-uppdateringar om process brast någonstans.

### Fas 8: LEARNINGS.md

Lägg till daterad entry i `LEARNINGS.md` (skapa om den inte finns — se `memory/project_learnings_md.md`):

```markdown
## YYYY-MM-DD: <feature-namn>

{En rad om vad som byggdes.}
Key learning: {det viktigaste som lärdes.}
Skills updated: {vilka skills som justerades, om några.}
```

## Agent-delegation (se `feedback_opus_sonnet_delegation.md`)

| Fas | Utförare |
|---|---|
| 1 Scope | Opus (dialog med Eric) |
| 2 Grill | Opus (interaktivt) |
| 3 Lenses | Opus (skill kör staged debate) |
| 4 Implement | Sonnet-agent |
| 5 Review | Sonnet-agent (separat context) |
| 6 Code-health | Opus eller Sonnet-agent |
| 7 Debrief | Opus (dialog) |
| 8 LEARNINGS | Opus (skriv kort entry) |

## Exit criteria för feature

- [ ] Spec:en finns i `docs/plan/<feature>.md`
- [ ] Spec har överlevt grill-me + expert-lenses
- [ ] Kod implementerad av Sonnet-agent
- [ ] Review-rapport från separat Sonnet-agent
- [ ] Code-health körd, inga high-severity findings
- [ ] Debrief gjord om något gick oväntat
- [ ] LEARNINGS.md uppdaterad
- [ ] PR mergad till main
