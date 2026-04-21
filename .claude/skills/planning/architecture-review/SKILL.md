---
name: architecture-review
description: Review and define the technical architecture - tech stack, patterns, project structure, and code organization. Use after domain encoding is complete, before UX design.
---

# Architecture Review

Define the technical architecture for the project. This happens after the domain model is agreed, so architectural decisions are grounded in the actual domain, not assumptions.

## Process

### Step 1: Constraints and context

Ask the user:
- What tech are you already committed to? (language, framework, platform)
- What are you familiar with vs. learning new?
- What are the hard constraints? (hosting, budget, team size, timeline)
- Is this a greenfield project or extending something existing?

### Step 2: Tech stack decisions

For each layer, propose options and trade-offs:
- **Frontend**: framework, rendering approach (SSR, SPA, hybrid)
- **Backend**: language, framework, API style (REST, GraphQL, RPC)
- **Data**: database type, ORM/query approach, schema strategy
- **Infrastructure**: hosting, CI/CD, deployment model

For each decision, state:
- The recommendation and why
- What you're trading away
- When you'd revisit this choice

If a decision has significant trade-offs, suggest writing an ADR.

### Step 2b: Pin tool versions

For every tool in the tech stack, look up the current stable version and pin it:
- Language/runtime version
- Framework version
- Database version
- Any significant libraries

This prevents version drift and ensures reproducible builds. Search the web to confirm latest stable versions rather than guessing.

### Step 2c: API conventions

If the application has a frontend-backend split, define upfront:
- API style: REST, GraphQL, RPC, or other
- URL structure conventions (e.g. `/api/v1/resource`)
- Response format (JSON structure, error format)
- Authentication mechanism on the API (cookies, tokens, etc.)
- Any naming conventions (camelCase vs snake_case in JSON)

These don't need to be exhaustive - just enough to be consistent from the first endpoint. Details evolve during implementation.

### Step 2d: Library vetting

Before choosing any third-party library, check:

**Compatibility:**
- Does it work with our framework version? (e.g. Svelte 5 runes, Go 1.26)
- Search for known issues with the specific version combination
- Check GitHub issues for the library + framework version

**Maintenance:**
- When was the last release?
- Are issues being responded to?
- How many open issues vs closed?

**Security:**
- Run `npm audit` for Node.js dependencies
- Check Go vulnerability database for Go dependencies
- Review the dependency tree — what does this library pull in?

**Lesson learned:** Choosing a library that hasn't been tested with the latest framework version (e.g. svelte-dnd-action + Svelte 5) can cost significant debugging time. Verify compatibility before committing.

### Step 2e: API documentation approach

If the application has an API, create `docs/api.md` with the first endpoint and keep it updated during development. Don't defer to the end — the developer knows the API best while building it.

### Step 3: Patterns and structure

Propose the project structure:
- Directory layout with clear responsibilities
- Where domain model code lives
- Where UI code lives
- Where tests live
- Separation of concerns approach

Map the domain model (from domain-encoding) to the project structure:
- Which entities become which files/modules?
- How do relationships translate to code?

### Step 4: Challenge the architecture

Ask yourself and the user:
- Is this the simplest architecture that could work?
- Are we introducing complexity for problems we don't have yet?
- Does the architecture match the scale of the project? (don't build a microservice architecture for a personal tool)
- Can a new developer understand this structure in 10 minutes?

### Step 5: Document decisions

Capture the agreed architecture:
- Tech stack with rationale
- Project structure
- Key patterns chosen and why
- What was explicitly rejected and why

## Exit criteria

- [ ] Tech stack decisions are made with rationale
- [ ] Tool versions pinned to current stable releases
- [ ] API conventions defined (if frontend-backend split)
- [ ] Project structure is defined and maps clearly to the domain model
- [ ] Architecture complexity matches the project scale
- [ ] No speculative complexity ("we might need this later")
- [ ] User confirms the architecture makes sense
