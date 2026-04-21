---
name: ux-layout
description: Design the user experience independently from the domain model - screens, navigation, user journeys. Use after architecture is defined, before implementation planning.
---

# UX Layout

Design the user experience as an independent concern. The domain model describes what exists; the UX describes how the user interacts with it. These are not the same thing, and mapping them 1:1 is a common mistake.

## Why UX is independent from the domain

A domain model with 5 entities does NOT mean 5 screens. The user's mental model of the application is different from the data model:
- Multiple entities might appear on one screen
- One entity might span multiple screens
- Navigation follows user tasks, not entity relationships
- The best UX often hides domain complexity from the user

**Trap to avoid:** "We have a Point entity, so we need a Point screen." No - you need screens for what the user wants to *do*, not for what the data looks like.

## Process

### Step 1: User goals

Ask the user:
- Who uses this application?
- What are the 3-5 main things they want to accomplish?
- What's the most common task? (This should be the easiest to do)
- What's the most important task? (This should be the most prominent)

### Step 2: User journeys

Use the **story map** from the user stories phase as input. The journey steps across the top of the story map become the starting point for UX journeys.

For each main goal, map the journey:
1. Where does the user start?
2. What steps do they take?
3. What information do they need at each step?
4. Where do they end up?

Use the **personas** to walk through each journey: "How would Lisa do this? How would Tom?"

Keep journeys short. If a common task takes more than 3 steps, question whether it can be simpler.

### Step 3: Screen inventory

Based on the journeys, identify the screens:
- What screens are needed?
- What does each screen show?
- What actions are available on each screen?
- How does the user move between screens?

Draw a simple navigation map: boxes for screens, arrows for navigation paths.

### Step 4: Challenge the UX

- Can any two screens be combined?
- Is the most common task reachable in one click from the start?
- Are there dead ends where the user gets stuck?
- Does the navigation feel natural, or does it follow the data model?
- Would a first-time user know what to do?

### Step 4b: Check for feature removal

When redesigning an existing component, explicitly list any existing features that will be removed or replaced. Removals should be as deliberate as additions — don't silently drop functionality during a visual refresh.

Present the list to the user and confirm before proceeding. "The progress counter will be replaced by an icon — is losing the count OK?"

### Step 5: Validate against domain

Check that the UX covers the domain:
- Can the user access all domain entities they need?
- Are CRUD operations available where needed?
- Does the UX support the relationships in the domain model?

But do NOT let the domain dictate the UX structure.

## Exit criteria

- [ ] User goals are identified (3-5 main goals)
- [ ] User journeys are mapped for each goal
- [ ] Screen inventory exists with navigation map
- [ ] Most common task is reachable in minimal steps
- [ ] UX is not a 1:1 mirror of the domain model
- [ ] User confirms the experience matches how they'd want to use the app
