---
name: user-stories
description: Elicit and define user stories as the starting point of planning. Captures what users need before domain modeling, architecture, or UX design. Stories are revisited during UX layout to ensure the experience serves them.
---

# User Stories

User stories are the foundation of the plan. They capture what the user needs to accomplish, independent of how the system is built. Start here before domain encoding, architecture, or UX.

## Process

### Step 1: Identify the users

Ask:
- Who will use this application?
- Are there different types of users with different needs?
- Which user type is the primary audience?

Keep it simple. Most applications have 1-3 user types.

### Step 1b: Audit the existing tool (if replacing one)

If the application replaces an existing tool, explicitly map the current workflow before writing stories:
- What tool are you replacing? (e.g. Jira, Trello, spreadsheet)
- Walk me through a typical day using that tool — what do you do?
- What features do you use regularly?
- What features do you never use?
- What's missing or broken in the current tool?

This prevents designing from scratch and missing things the user takes for granted in their current workflow.

### Step 1c: Create personas

Create 2-4 named fictional users that represent the real user types. For each persona:
- **Name** — a real name makes them memorable
- **Role** — what they do (e.g. "developer", "project lead", "occasional user")
- **Goal** — what they want to achieve with this application
- **Frustration** — what annoys them about the current approach
- **Typical day** — a sentence about how they'd use the app

Example:
> **Lisa, Team Lead.** Manages a team of 5 developers. Wants to see at a glance what everyone is working on and what's blocked. Frustrated that Jira requires too many clicks to get a simple status overview. Uses the board every morning to plan the day.

Personas help spot missing stories: "What would Lisa do when a team member is sick?" reveals stories about reassigning tasks.

Use personas throughout the remaining steps — elicit stories from each persona's perspective.

### Step 2: Elicit stories

For each persona, ask:
- What do they need to accomplish with this application?
- What problems are they trying to solve?
- What would make them choose this tool over their current approach?

Capture each need as a user story:

```
As a [persona/user type], I want to [action] so that [benefit].
```

Focus on the **benefit** - it reveals the real need behind the request. If you can't articulate the benefit, the story isn't understood well enough.

### Step 2b: Non-functional requirements

After functional stories, explicitly ask about qualities of the system:

- **Performance** — how fast should key actions be? (e.g. board loads in under 2 seconds)
- **Security** — authentication, session management, data protection
- **Error handling** — what happens when things go wrong? (API down, network lost, invalid data)
- **Data limits** — maximum items? (tasks per project, columns per board, team size)
- **Accessibility** — keyboard navigation, screen reader support
- **Browser support** — which browsers and devices?

These can be written as stories:
```
As a user, I want the board to load in under 2 seconds so that I can work efficiently.
As an admin, I want user sessions to expire after 7 days so that unattended devices are secure.
```

Or captured as constraints in a separate section. The important thing is to discuss them explicitly — they're easy to miss.

### Step 3: Prioritize

Not all stories are equal. Sort them:

1. **Must have** - the application is useless without these
2. **Should have** - important but the app works without them
3. **Nice to have** - valuable but can wait

Be ruthless. Most projects have 3-5 must-have stories. If you have more than 7, you're probably not prioritizing hard enough.

### Step 4: Add acceptance criteria

For each must-have and should-have story, define:
- How do we know this story is done?
- What are the specific conditions that must be true?
- What are the edge cases?

```
Story: As a user, I want to create a task so that I can track my work.

Acceptance criteria:
- User can enter a task title
- Task appears on the board after creation
- Empty title is not allowed
```

Keep criteria concrete and testable.

**Important:** When a story involves user input, define the validation rules as part of the acceptance criteria. For example:
- Password policies (length, character requirements)
- Email format
- Required fields and length limits
- Allowed characters

These are easy to overlook but affect both backend and frontend implementation. If not caught here, they become ad-hoc decisions during coding.

### Step 5: Challenge the stories

- Are any stories really two stories combined? Split them.
- Are any stories solving the same need differently? Merge them.
- Does every must-have story genuinely block the application from being useful?
- Are you describing the solution instead of the need? ("I want a dropdown" vs "I want to categorize tasks")
- **How would you test this story?** If you can't describe a test, the story isn't clear enough.

### Step 5b: Story mapping

Map the stories to the user's journey:

1. Across the top (left to right): the major steps in the user's journey with the application (e.g. "Set up account → Create project → Add tasks → Manage board → Collaborate")
2. Under each step: the stories that belong to that step, prioritized top to bottom
3. Draw a horizontal line: above the line = must-have (v1.0), below = later versions

**Look for gaps:** If a journey step has no stories, something is missing. If a step has too many stories, consider splitting the step.

This map becomes input to the UX layout phase — the journey steps map to screens and navigation.

### Step 5c: "What could go wrong?" pass

For each must-have story, explicitly ask:
- What happens if the user does something unexpected?
- What happens if the system fails during this action?
- What happens when related data is deleted? (e.g. delete a user who owns projects)
- What happens with concurrent access? (e.g. two users edit the same task)
- What are the boundary conditions? (e.g. empty list, maximum items, very long text)

This surfaces error handling stories and edge cases that are otherwise discovered during implementation (too late to plan for).

## When to revisit

Stories are revisited during **UX Layout**:
- Do the screens and journeys serve every must-have story?
- Are there screens that don't map to any story? (Why do they exist?)
- Does the navigation make the highest-priority stories the easiest to accomplish?
- Did the UX design reveal new stories? (e.g. onboarding, settings screens)
- If new stories were discovered, add them and re-prioritize.

**Important:** The UX phase often uncovers stories that weren't obvious during initial elicitation. This is expected and healthy. Update the stories document when this happens.

Stories also feed into **implementation planning**:
- Must-have stories become early phases
- Should-have stories become later phases
- Nice-to-have stories go in a backlog

## Backlog for future versions

Maintain a `docs/plan/backlog.md` file for ideas and stories that aren't in the current version:
- During any phase, if an idea comes up that's out of scope, add it to the backlog
- During user testing, if the user spots something for "later", add it
- Before planning the next version, review the backlog as input
- The backlog is checked but not committed to until a version is planned

## Exit criteria

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
