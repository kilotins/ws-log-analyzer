---
name: domain-encoding
description: Transfer domain knowledge from user to Claude, force simplification of the domain model, and validate understanding before any code is written. Use when starting a new project or when the domain model feels over-complicated.
---

# Domain Encoding

Facilitate a structured domain knowledge transfer. The goal: build a shared, simplified domain model before any code exists.

## Process

### Step 1: Elicit the domain

Ask the user to describe the domain in plain language:
- What is the core problem being solved?
- Who are the users?
- What are the key concepts they work with?
- How do these concepts relate to each other?

Do NOT start designing classes or data structures. Stay in the problem space.

### Step 2: Play it back

Restate the domain model you understood. List:
- The core entities (aim for 5-7 max)
- Their relationships
- What each entity represents in the user's world

Ask: "Is this what you mean? What did I get wrong?"

### Step 3: Challenge over-specialization

For each entity in the model, ask:
- Could this be an attribute of another entity instead of its own thing?
- Are there two entities that are really the same thing with different attributes?
- Does this entity exist because the user described a *workflow step*, not a *domain concept*?

**Common trap:** The user describes how they *use* the system ("I pick a hotel, then I pick restaurants nearby"), and you model the workflow literally (HotelPoint, RestaurantPoint) instead of the simpler abstraction (Point with location + type attribute).

### Step 4: Define validation rules

For entities that involve user input, define the validation rules:
- What are the constraints on key fields? (length, format, required vs optional)
- Are there policies that apply? (e.g. password policy, email format)
- What are the allowed values for constrained fields? (e.g. priority: none/low/medium/high)

Document these alongside the entity fields. Validation rules affect both backend and frontend and should not be left as ad-hoc decisions during implementation.

### Step 5: The napkin test

The domain model must fit on a napkin:
- Max 5-7 core entities
- Each entity has a clear, one-sentence reason to exist
- Relationships are simple and obvious
- If you can't draw it simply, it's too complex

Present the napkin-level model and ask the user to confirm.

### Step 6: Iterate

If the user identifies problems:
1. Note what's wrong and *why* the model drifted there
2. Simplify
3. Check if the simplification reveals further simplifications
4. Repeat the napkin test

Only move on when the user confirms the model is right.

## Exit criteria

- [ ] Domain model has 5-7 or fewer core entities
- [ ] Claude can explain the domain back correctly
- [ ] Every entity has a clear reason to exist
- [ ] No over-specialization (checked explicitly)
- [ ] Validation rules defined for entities with user input
- [ ] User confirms the model matches their understanding
