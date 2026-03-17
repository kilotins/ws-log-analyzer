# Documentation Skill

Reusable skill for generating structured, high-quality documentation for any feature, system, or codebase component.

## When to Use

- Documenting a new feature or module
- Writing user-facing guides
- Creating architecture/design docs
- Generating API reference documentation
- Explaining complex systems to different audiences

## Project Context

| Field | Value |
|-------|-------|
| Project | LogPilot |
| Domain | Log analysis, multi-format parsing, AI-assisted triage |
| Stack | Python 3.9+ (stdlib core), Streamlit (GUI), Anthropic/Gemini/OpenAI (AI) |
| Audience | Developers, ops engineers, end users |

## Documentation Structure

Always produce **three levels**, adapted to the target audience:

### Level 1: User Documentation (How to use it)

- **What** the feature/system does
- **When** to use it and what problem it solves
- **Step-by-step** usage with real examples
- **Expected output** — what the user will see
- **Common mistakes** and how to avoid them

### Level 2: System/Concept Documentation (How it works)

- **Purpose** within the larger system
- **Architecture overview** — where it sits, what it talks to
- **Data flow**: input → processing → output
- **Key concepts** the reader needs to understand
- **Dependencies** — what it requires, what requires it

### Level 3: Technical/Implementation Documentation

- **Internal structure** — modules, classes, functions
- **Data models** — dataclasses, schemas, dict shapes
- **APIs/interfaces** — function signatures, parameters, return types
- **Detection logic / rules** — regex patterns, heuristics, scoring
- **Tradeoffs and limitations** — why it was built this way
- **Code examples** — real or pseudo-code when useful

## Output Template

```markdown
# [Title]

## TL;DR
[1-3 sentence summary of what this is and why it matters]

## 1. User Guide

### What It Does
...

### When to Use
...

### How to Use
1. Step one
2. Step two
3. Step three

### Examples
...

## 2. How It Works

### Architecture
...

### Data Flow
```
input → step1 → step2 → output
```

### Key Concepts
...

## 3. Technical Details

### Module Structure
...

### Data Models
...

### API Reference
...

### Detection Logic / Rules
...

## 4. Notes

### Edge Cases
...

### Performance Considerations
...

### Future Improvements
...
```

## Writing Rules

1. **Be concise but complete** — no walls of text, no filler
2. **Use structured formatting** — headers, bullets, tables, code blocks
3. **Prefer bullet points** over paragraphs for technical content
4. **Include real examples** — not hypothetical, use actual project data when possible
5. **Highlight assumptions** — state what you're assuming about the reader's knowledge
6. **Use tables** for comparisons, option lists, field descriptions
7. **Add diagrams** as ASCII/text art when they clarify architecture
8. **Link to source** — reference file paths and line numbers (e.g., `parser.py:213`)
9. **Keep TL;DR mandatory** — always include, always first after title
10. **Match audience level** — senior engineers need less handholding, users need more context

## Section Selection

Not every document needs all sections. Choose based on audience:

| Audience | Level 1 (User) | Level 2 (System) | Level 3 (Technical) |
|----------|:-:|:-:|:-:|
| End users | Required | Optional | Skip |
| Ops/DevOps | Required | Required | Optional |
| Developers | Optional | Required | Required |
| New contributors | Required | Required | Required |

## LogPilot-Specific Conventions

- **Format plugins**: Document detect → extract_ts → extract_level → classify_event → bucket_tags
- **Heuristics**: Include id, pattern, fix text, severity, and which formats it applies to
- **AI prompts**: Document system prompt structure, skill selection, and sanitization
- **Test coverage**: Note test file and approximate test count for documented feature
- **Streamlit widgets**: Document session_state keys and callback patterns
- **Event fields**: Reference `LogEvent` dataclass fields (text, ts, level, code, exception, root_cause, tags, etc.)

## Quality Checklist

Before finalizing documentation, verify:

- [ ] TL;DR present and accurate
- [ ] All code examples actually work
- [ ] File paths and line numbers are current
- [ ] No stale information from previous versions
- [ ] Audience-appropriate level of detail
- [ ] Examples use real project data, not lorem ipsum
- [ ] Edge cases mentioned where relevant
- [ ] Links to related docs/skills included
