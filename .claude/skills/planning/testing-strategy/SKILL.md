---
name: testing-strategy
description: Define the testing strategy for the project - what to test, how, what tools, when to write tests. Use after architecture is defined, since the tech stack determines available test tools.
---

# Testing Strategy

Define how the project will be tested before writing any code. Testing decisions made up front lead to consistent quality. Testing decisions made during implementation lead to inconsistent coverage and skipped tests.

## Process

### Step 1: What needs testing?

Map the application layers to test types:

| Layer | Test type | Purpose |
|---|---|---|
| Domain logic / business rules | Unit tests | Verify core logic in isolation |
| Database access / queries | Integration tests | Verify data is stored and retrieved correctly |
| API endpoints | API / integration tests | Verify request/response contracts |
| UI components | Component tests | Verify rendering and interaction |
| User workflows | End-to-end tests | Verify complete flows work |

Not every project needs all levels. Ask:
- What's the riskiest part of this application? (Test that the most)
- What would be most painful to break? (Test that first)
- What's trivial and unlikely to break? (Maybe skip testing that)

### Step 2: Choose test tools

Based on the tech stack from the architecture phase, select test tools for each level:
- What's the standard/built-in test tool for the backend language?
- What's the standard test tool for the frontend framework?
- Do we need a separate tool for integration or end-to-end tests?
- Do we need a test database strategy (test containers, in-memory, separate instance)?

Prefer built-in and standard tools over exotic ones. Fewer dependencies = less friction.

### Step 3: When to write tests

Decide on the approach:

**Option A: Test after each sub-phase**
- Build the sub-phase, then write tests before acceptance
- Pragmatic, lets the design settle before testing
- Risk: tests get skipped under time pressure

**Option B: Test during development (TDD-lite)**
- Write tests alongside code, not strictly before
- Tests evolve with the implementation
- Better coverage but slower initial progress

**Option C: Test critical paths only**
- Identify the riskiest parts and test those
- Skip testing trivial CRUD or simple UI
- Efficient but requires discipline about what's "critical"

Discuss with the user and choose.

### Step 4: Test conventions

Define:
- Where do test files live? (next to source, separate directory, or both?)
- Naming convention for test files
- How to run tests (single command)
- Should tests run before every commit, or on demand?

### Step 5: Document the strategy

Capture:
- Test levels and what each covers
- Tools chosen and why
- When tests are written (the approach from Step 3)
- How to run them
- What is explicitly NOT tested and why

## Enforcement

A strategy that isn't enforced is useless. The dev-workflow must include:
- Automated tests must pass before a sub-phase is presented for acceptance
- The final review (before release) must verify test coverage matches the strategy
- If the strategy says "write tests during development", tests must exist — not deferred to "later"

**Lesson learned:** In the kanban board project, the testing strategy was planned but automated tests were never written. Manual testing by the user caught bugs, but this doesn't scale to team development. Enforce the strategy through the dev-workflow gates.

## Exit criteria

- [ ] Test levels identified (which layers get tested)
- [ ] Test tools chosen for each level
- [ ] When to write tests is agreed
- [ ] Test file location and naming conventions defined
- [ ] Enforcement mechanism agreed (when must tests pass?)
- [ ] User understands and agrees to the strategy
