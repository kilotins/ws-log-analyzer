---
name: planning-checklist
description: Gate between planning phases - ensures each phase is complete before moving to the next. Covers user stories, domain encoding, architecture, UX, and dev workflow. Prevents the common problem of starting to code too early.
---

# Planning Checklist

This skill gates transitions between planning phases. Do not move to the next phase until the current phase passes its checklist. Do not start implementation until all phases pass.

## Planning phases in order

```
User Stories → Domain Encoding → Architecture (incl. tool versions, API conventions) → Testing Strategy → UX Layout (revisit stories) → Dev Workflow → Implementation Plan → Debrief (use debrief skill)
```

Each phase builds on the previous. Skipping or rushing a phase creates problems that are expensive to fix later.

The **Debrief** at the end reviews the planning process itself: what worked, what was missed, and whether skills need updating before starting implementation.

## Phase 1: User Stories

Run the `user-stories` skill, then verify:

- [ ] User types identified
- [ ] Personas created (2-4 named fictional users)
- [ ] Existing tool audited (if replacing one)
- [ ] Functional stories written with action and benefit
- [ ] Non-functional requirements discussed (performance, security, error handling)
- [ ] Stories prioritized (must/should/nice)
- [ ] Must-have and should-have stories have acceptance criteria
- [ ] No combined stories - each story is one need
- [ ] Stories describe needs, not solutions
- [ ] Story map created — no journey gaps
- [ ] "What could go wrong?" pass completed for must-have stories
- [ ] User confirms the stories capture what they want to build

**Gate question:** "Do these stories cover everything the application needs to do? Does the story map have any gaps?"

If no → elicit more stories or re-prioritize.

## Phase 2: Domain Encoding

Run the `domain-encoding` skill, then verify:

- [ ] Domain model has 5-7 or fewer core entities
- [ ] Claude can explain the domain back to the user correctly
- [ ] Every entity has a clear, one-sentence reason to exist
- [ ] Over-specialization has been checked explicitly
- [ ] No entities exist because of workflow descriptions rather than domain concepts
- [ ] Validation rules defined for entities with user input
- [ ] Domain model supports all must-have user stories
- [ ] User confirms the model matches their understanding

**Gate question:** "Can you explain this domain to someone unfamiliar in 2 minutes?"

If no → go back to domain encoding.

## Phase 3: Architecture

Run the `architecture-review` skill, then verify:

- [ ] Tech stack decisions are made with rationale for each
- [ ] Tool versions pinned to current stable releases
- [ ] API conventions defined (if frontend-backend split)
- [ ] Project structure is defined and maps to the domain model
- [ ] Architecture complexity matches the project scale
- [ ] No speculative complexity
- [ ] Key decisions documented (ADRs for significant trade-offs)
- [ ] User confirms the architecture makes sense

**Gate question:** "Is this the simplest architecture that could work for this project?"

If no → simplify and re-verify.

## Phase 3b: Testing Strategy

Run the `testing-strategy` skill, then verify:

- [ ] Test levels identified (which layers get tested)
- [ ] Test tools chosen for each level
- [ ] When to write tests is agreed
- [ ] Test file location and naming conventions defined
- [ ] User understands and agrees to the strategy

**Gate question:** "Do we know what gets tested, how, and when?"

If no → clarify the strategy.

## Phase 4: UX Layout

Run the `ux-layout` skill, then verify:

- [ ] User goals identified (3-5 main goals)
- [ ] User journeys mapped for each goal
- [ ] Screen inventory exists with navigation map
- [ ] Most common task reachable in minimal steps
- [ ] UX is NOT a 1:1 mirror of the domain model
- [ ] User confirms the experience matches how they'd want to use the app

**Revisit user stories:**
- [ ] Every must-have story is served by the UX
- [ ] No screens exist that don't serve any story
- [ ] Highest-priority stories are the easiest to accomplish in the UX

**Gate question:** "Would a first-time user know what to do?"

If no → simplify the UX and re-verify.

## Phase 5: Dev Workflow

Run the `dev-workflow` skill, then verify:

- [ ] Branching strategy decided
- [ ] Versioning scheme agreed
- [ ] Review and acceptance flow defined
- [ ] Commit practices established
- [ ] User understands and agrees to the workflow

**Gate question:** "Do we both know exactly what happens when a sub-phase is done?"

If no → clarify the workflow.

## Project Setup

All five phases pass. Before writing feature code, set up the project:

- [ ] Initialize git repo
- [ ] Add LICENSE
- [ ] Create README.md (project description, tech stack, how to run - from planning outputs)
- [ ] Create CLAUDE.md (navigation hub: project overview, build commands, pointers to skills and docs)
- [ ] Create LEARNINGS.md (empty, grows during development with discoveries and gotchas)
- [ ] Create CHANGELOG.md (follows [Keep a Changelog](https://keepachangelog.com/) format, maintained from v0.0.0 onward)
- [ ] Create domain skills in .claude/skills/ (encode domain model and architecture decisions)
- [ ] Create initial project structure (directories and skeleton from architecture phase)
- [ ] Store planning artifacts in docs/plan/ (user stories, screen maps, phase breakdown)
- [ ] First commit and tag: `v0.0.0` - project skeleton

## Create the implementation plan

Break the work into phases and sub-phases:
- Map user stories to phases (must-have stories in early phases)
- Define what each sub-phase delivers
- Assign version numbers to each sub-phase
- Include documentation as one of the final phases (user guide, API guide if applicable)
- Start with Phase 1, sub-phase 1

**Rules for sub-phases:**
- Never combine sub-phases, no matter how small they are. Each sub-phase is planned, implemented, tested, and accepted independently.
- Each sub-phase gets its own plan before coding starts.
- Tagging happens only after the user has tested and accepted the sub-phase.

## Pre-release gate

Before tagging a release (v1.0.0 or any major/minor version):

- [ ] Run `code-health` skill and address all high-severity findings
- [ ] All automated tests pass
- [ ] Documentation is up to date (CLAUDE.md, API docs, planning docs)
- [ ] CHANGELOG.md updated with release date

## When to re-run this checklist

- When you feel lost during implementation → which phase assumption was wrong?
- When the user identifies a problem → which phase needs revisiting?
- When scope changes → re-run from the affected phase forward
