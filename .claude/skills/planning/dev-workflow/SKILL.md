---
name: dev-workflow
description: Define the development workflow before the first commit - branching strategy, versioning, review gates, and how code moves from idea to main. Use during planning, before implementation starts.
---

# Development Workflow

Establish how development will be conducted before writing any code. These decisions are easy to make up front and painful to retrofit.

## Process

### Step 1: Branching strategy

Decide between two approaches:

**Option A: Feature branches (recommended for phased projects)**
- Each phase/sub-phase gets its own branch
- Work happens on the branch
- User reviews and tests at each sub-phase boundary
- Merge to main when the sub-phase is accepted
- Main always contains accepted, working code

**Option B: Trunk-based (working directly on main)**
- All work happens on main
- Suitable for solo projects with very small increments
- Requires discipline to never leave main broken

Discuss trade-offs with the user and decide.

### Step 2: Versioning

For planned, phased projects, use phase-based versioning:

**During initial development (greenfield to first release):**

```
v0.{phase}.{subphase}
```

- `v0.1.0` - Phase 1 starts
- `v0.1.1` - Phase 1, sub-phase 1 complete
- `v0.1.2` - Phase 1, sub-phase 2 complete
- `v0.2.0` - Phase 2 starts (sub-phase resets)
- `v1.0.0` - Plan fully implemented, first release

**Post-release development (v1.1, v2.0, etc.):**

Work is split into phases just like greenfield, but tagged as snapshots:

```
v{major}.{minor}-snapshot-{N}
```

- `v1.1-snapshot-1` - Phase 1 accepted
- `v1.1-snapshot-2` - Phase 2 accepted
- `v1.1-snapshot-3` - Phase 3 accepted
- `v1.1.0` - All phases complete, version released

Snapshots are development checkpoints — reviewed, tested, and accepted like greenfield sub-phases. The final release drops the snapshot suffix.

For patch releases (e.g. `v1.0.1`) that don't need phased development, tag directly without snapshots.

Version is updated when the user accepts a phase or sub-phase, not on every commit.

### Step 3: Sub-phase planning

Before starting each sub-phase, create a plan:

1. Scope what the sub-phase will deliver
2. List the files to create/modify
3. Define verification steps and manual test checklist
4. Get user approval of the plan before writing code

This ensures each sub-phase is well-scoped and avoids wasted work. Never combine multiple sub-phases into one plan — each sub-phase is planned and delivered independently, no matter how small.

### Step 4: Review and acceptance flow

Define the workflow for each sub-phase:

1. Create branch from main (if using feature branches)
2. Plan the sub-phase (Step 3 above)
3. Implement the sub-phase
4. Commit and push code
5. Present to user for review with a manual test checklist
6. User tests what's available
7. If accepted: tag with version, push tag
8. If not accepted: discuss issues, fix, return to step 5

**Important:** Tagging happens only after the user has tested and accepted the sub-phase. Do not tag immediately after coding — the user's acceptance is the gate.

### Step 4b: Test data strategy

Agree at the start of the project on:
- **Shared test accounts** — standard credentials everyone uses (e.g. admin@test.com / password1)
- **When to wipe** — only when schema changes require it, not on every rebuild
- **When to preserve** — don't use `docker compose down -v` unless necessary; the user's manual test data should survive rebuilds
- **Who creates test data** — the developer creates standard accounts via API; the user can also use them

### Step 4c: Development practices

Follow the `dev-practices` skill during all implementation work. It covers testing gates, scope discipline, triaging small fixes, handling failed features, and maintaining LEARNINGS.md.

### Step 5: Commit practices

- Commit messages: `type: description` (feat, fix, refactor, test, docs, chore)
- Small commits: one logical change per commit
- Never commit broken code to main
- Tag accepted sub-phases: `git tag v0.1.1`

### Step 5b: Changelog

Maintain a `CHANGELOG.md` in the project root using [Keep a Changelog](https://keepachangelog.com/) format.

**When to create:** At project setup, alongside README.md and LEARNINGS.md.

**How to maintain:**
- Add entries under `[Unreleased]` as you work — don't batch them at the end
- When a version is tagged, rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`
- Add a new empty `[Unreleased]` section above it
- Update the changelog before the tag, not after

**What to include:**
- User-facing changes (features, fixes, breaking changes)
- Infrastructure changes that affect how the project is built or tested
- Categorize entries: Added, Changed, Fixed, Removed

**What to exclude:**
- Trivial refactors that don't change behavior
- Work-in-progress commits

### Step 6: Document the workflow

Write down the agreed workflow so it's followed consistently throughout the project. Include:
- Branching strategy chosen and why
- Versioning scheme
- Review/acceptance process
- Commit message format

## Exit criteria

- [ ] Branching strategy decided
- [ ] Versioning scheme agreed
- [ ] Review and acceptance flow defined
- [ ] Commit practices established
- [ ] User understands and agrees to the workflow
