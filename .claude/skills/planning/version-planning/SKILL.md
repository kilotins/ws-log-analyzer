---
name: version-planning
description: Plan the next version of an existing product. Gathers inputs, decides scope, challenges minor vs major, runs impact analysis, and orchestrates the right planning phases. Use when the current version is complete and you're deciding what to build next.
---

# Version Planning

Plan the next version of an existing product. Unlike greenfield planning, there is existing code, users, data, and an established architecture. This skill orchestrates the planning process — it decides what needs doing and delegates to existing skills for the detailed work.

## Process

### Step 1: Gather inputs

The next version starts from what already exists, not a blank slate. Collect:

- **Backlog** — review `docs/plan/backlog.md` for deferred items and ideas
- **Debrief notes** — check LEARNINGS.md for debrief summaries that flagged gaps
- **User feedback** — what has the user discovered from actually using the product?
- **Technical debt** — are there known issues, missing tests, or architectural concerns? Run the `code-health` skill to get a concrete assessment of the codebase. High-severity findings should be addressed before or alongside the new version's features.

If the backlog is thin, run a **brainstorming session** before proceeding. The goal is to have a healthy list of candidate features and improvements to choose from — don't plan a version from a near-empty backlog.

### Step 2: Review and update personas

Show the existing personas from the user stories document. Ask:

- Are these personas still accurate?
- Has using the product revealed a new type of user?
- Has any persona's goal or frustration changed?

Add or update personas before eliciting new stories. New stories should be grounded in who will use them.

### Step 3: Elicit new stories

Delegate to the `user-stories` skill, but with context:

- Skip user identification and persona creation (done in Step 2)
- Start from eliciting stories against the updated personas
- Include backlog items — convert relevant backlog entries into proper user stories
- Prioritize alongside the backlog: some backlog items may be more important than new ideas

The output is a combined list of new and backlog stories, prioritized.

### Step 4: Decide version scope

Not everything goes into the next version. Decide what's in and what stays in the backlog:

- **Must-have** stories go in this version
- **Should-have** stories go in if they don't bloat the scope
- **Nice-to-have** stories stay in the backlog

**Guide the decision:**
- Can this version be described in one sentence? If not, it's too big.
- How many must-have stories? More than 3-4 for a minor version is a warning sign.
- Are there dependencies between stories? Group dependent stories together.
- What's the smallest useful version? Ship that, put the rest in the backlog.

Update `docs/plan/backlog.md` — move selected stories out, keep the rest.

### Step 5: Challenge minor vs major

Before proceeding, explicitly decide: is this a minor version (v1.1) or a major version (v2.0)?

**Minor version (v1.x):**
- Additive features that fit within existing architecture and UX
- New fields or entities that extend the domain model without restructuring
- Database migrations that are straightforward (add column, add table)
- Users don't need to relearn the application
- API changes are backwards-compatible (new fields, new endpoints)

**Major version (v2.0):**
- Breaking changes to existing behavior or data model
- Fundamental UX restructuring — users need to relearn workflows
- New user types or a significant shift in who the product serves
- Architectural changes that affect how the application is built or deployed
- API breaking changes that require frontend/client updates

**Challenge the decision:** If the user says v2.0, push back. Most features that feel big are actually minor — they touch many files but don't break the fundamental model. Ask:
- Does any existing feature stop working?
- Does the user need to relearn anything they already know?
- Does the architecture need to change, or just extend?

If the answers are all "no," it's a minor version regardless of how many files change.

### Step 6: Impact analysis

For each must-have story, map the impact on the existing system:

- **Domain model** — which existing entities change? Are new entities needed?
- **Database** — what migrations are required? What happens to existing data?
- **API** — do existing endpoints change? Are new endpoints needed?
- **UI** — which existing screens are affected? Are new screens needed?
- **Tests** — do existing tests need updating? What new tests are needed?

This replaces the greenfield architecture phase for minor versions. The architecture is set — the question is whether it holds.

**Migration and compatibility:**
- What happens to existing data when the schema changes?
- Can the migration run safely? (data loss, constraint violations)
- Is there a rollback path if something goes wrong?

**Visual interaction check:**
When multiple visual changes are planned, consider how they interact together — not just individually. If two features add colour or visual weight to the same area (e.g. label-tinted cards + coloured column backgrounds), flag it for review before implementation. Combined effects are hard to predict without seeing them together.

### Step 7: Decide which planning phases to run

Based on the version scope and impact analysis, decide which existing skills are needed:

| Situation | Run these skills |
|-----------|-----------------|
| New entities or entity restructuring | `domain-encoding` (extend mode) |
| Architecture limits are pushed | `architecture-review` |
| New screens or navigation changes | `ux-layout` |
| New test levels or tools needed | `testing-strategy` |
| Always | `dev-workflow` (implementation plan + sub-phases) |

For a typical minor version, you'll skip domain-encoding, architecture-review, and testing-strategy. The UX skill is needed only if new screens are added. The implementation plan is always needed.

When delegating to a skill, provide context about what already exists so the skill doesn't start from scratch.

### Step 8: Regression check

Before starting implementation, review:

- Which existing user stories could be affected by the planned changes?
- Do the current tests cover the areas being changed?
- Are there integration points where new and existing features interact?

Flag any existing stories that need re-testing after the version is complete.

### Step 9: Create the implementation plan

Break the version into phases and sub-phases, following the same rules as the `planning-checklist`:

- Each sub-phase is planned, implemented, tested, and accepted independently
- Never combine sub-phases
- Must-have stories in early phases
- Include a documentation phase if user-facing behavior changes
- Add `[Unreleased]` entries to CHANGELOG.md as you plan

### Step 10: Update planning documents

- Update `docs/plan/user-stories.md` with new and updated stories
- Update `docs/plan/backlog.md` — remove items now in scope, keep the rest
- Update `docs/plan/implementation-plan.md` with the new version's phases
- Update any other planning docs affected by the changes

## Exit criteria

- [ ] Inputs gathered (backlog, feedback, debt)
- [ ] Personas reviewed and updated
- [ ] New stories elicited and prioritized with backlog items
- [ ] Version scope decided — clear in/out boundary
- [ ] Minor vs major challenged and decided
- [ ] Impact analysis completed for must-have stories
- [ ] Required planning phases identified and delegated
- [ ] Regression risks flagged
- [ ] Implementation plan created with sub-phases
- [ ] Planning documents updated
