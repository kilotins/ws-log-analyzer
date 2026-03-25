# Gemini CLI Instructions for LogPilot

## HTML Report Rendering

When you generate a review, audit, or report as Markdown (.md), tell the user to render it as branded HTML by running:

```bash
python3 report_renderer.py <filename>.md --open
```

This converts any Markdown file to a self-contained, branded HTML page with:
- Item Consulting branding (purple/green theme)
- Collapsible sections
- Syntax-highlighted code blocks
- Dark mode support
- Print-friendly layout

**Workflow:**
1. Save your output as `<name>.md` in the project root
2. Tell the user: "Run `python3 report_renderer.py <name>.md --open` to view as branded HTML"

## Project Context

See CLAUDE.md for full project context (architecture, skills, structure). The same information applies here.
