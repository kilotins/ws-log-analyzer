---
name: dev-practices
description: Behaviour guidelines during implementation — how to handle small fixes, scope decisions, failed features, and user feedback. Referenced by dev-workflow. Use when coding is underway.
---

# Development Practices

How to behave during implementation. The dev-workflow skill defines the process (branching, versioning, review gates). This skill defines how to make good decisions while the work is happening.

## Scope discipline

Do what was asked. Don't embellish.

- Implement the plan as approved. If you see an improvement opportunity, mention it — don't just do it.
- Don't add features, refactor surrounding code, or "improve" things beyond the scope.
- If the plan turns out to need adjustment, discuss the change before making it.

## Triaging small fixes

When a small issue surfaces during development or after a version ships (icon change, font tweak, minor bug):

1. Acknowledge it's a small thing
2. Suggest it could be handled as a patch version
3. Ask: do it now, or add it to the backlog?

Don't jump straight into fixing. The user decides when work happens. A quick fix is still a decision about priorities.

## When a feature doesn't work out

Sometimes an implementation looks wrong once you see it running. When the user says "this isn't working" or "I don't like this":

1. **Revert cleanly** — don't try to salvage a bad approach with more code
2. **Discuss alternatives** — present 2-3 different approaches to the same problem
3. **Don't force it** — if none of the alternatives appeal, the feature can be dropped or deferred

The column background tinting in v1.1 is a good example: it was implemented, looked too heavy with the label-tinted cards, was reverted, and replaced with a lighter approach (icons + board background).

Reverting is not failure. Shipping something that doesn't work is.

## Responding to visual feedback

UI work is inherently iterative. When the user gives visual feedback:

- Make the change and let them review again — don't over-discuss visual tweaks
- Small adjustments (spacing, font size, colour shade) can be done immediately
- Larger changes (different layout, different approach) should be discussed first
- Always let the user see the result before committing

## Testing gate

Automated tests must pass before presenting work for review:

- Run `go test ./...` (or equivalent) before pushing
- If the testing strategy says tests are required, they must exist and pass
- Manual test checklist is for the user; automated tests are for the developer
- Don't present broken code for review — fix it first

## Pre-review self-check

Before presenting code for review, run through this checklist:

- **Transactions:** Are multi-step destructive operations (deletes, cascades, multi-table updates) wrapped in a single transaction? If one step fails, does the database stay consistent?
- **Error handling:** Are all store call errors handled? No `result, _ := store.SomeFunc(...)` on calls where the error matters.
- **Pattern consistency:** Does the new code follow patterns established by previous fixes? If you fixed something last version, don't repeat the old pattern in new code.

This checklist exists because v1.2 shipped user deletion without a transaction and with swallowed errors — both patterns that had already been fixed elsewhere in the codebase.

## LEARNINGS.md

Update LEARNINGS.md during development whenever you discover something surprising or useful:

**What to capture:**
- Library incompatibilities (e.g. "svelte-dnd-action doesn't work with Svelte 5 $state proxies")
- Framework quirks (e.g. "PostgreSQL 18 changed the default volume mount path")
- Workarounds that aren't obvious (e.g. "UNIQUE constraints need temporary negative values during reorder")
- Things that looked simple but weren't (e.g. "click vs drag detection needs distance-based approach")
- Patterns that emerged during development

**Format:** Date, topic, what happened, what the solution was.

**When to review:**
- During the project debrief — check if learnings should become skill updates
- Before starting the next version — refresh your memory on gotchas
- When onboarding someone new to the project

## Exit criteria

This skill doesn't have a one-time exit. These practices apply continuously during all implementation work.
