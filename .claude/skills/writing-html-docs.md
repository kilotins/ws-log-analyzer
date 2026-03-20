# Writing HTML Documentation — LogPilot Style Guide

## When to Use

When creating standalone HTML documents for LogPilot — architecture docs, strategy documents, reports, presentations. These are self-contained files (no external CSS/JS) that can be opened in any browser, printed to PDF, or shared via email.

## Brand

- **Company**: Item Consulting
- **Purple**: `#7C3AED` (primary accent)
- **Green**: `#34D399` (success, highlights)
- **Dark**: `#0F172A` (text, backgrounds)
- **Font**: `system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif`
- **Code font**: `'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace`

## CSS Variables

Always use these variables — never hardcode colors:

```css
:root {
  --purple: #7C3AED;
  --purple-light: #EDE9FE;
  --green: #34D399;
  --green-light: #D1FAE5;
  --dark: #0F172A;
  --gray-50: #F8FAFC;
  --gray-100: #F1F5F9;
  --gray-200: #E2E8F0;
  --gray-300: #CBD5E1;
  --gray-400: #94A3B8;
  --gray-500: #64748B;
  --gray-600: #475569;
  --gray-700: #334155;
  --gray-800: #1E293B;
  --orange-light: #FFF7ED;
  --orange: #F97316;
  --blue-light: #EFF6FF;
  --blue: #3B82F6;
  --red-light: #FEF2F2;
  --red: #EF4444;
}
```

## Document Structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LogPilot — Document Title</title>
<style>
  /* All CSS inline — no external files */
</style>
</head>
<body>
<div class="page">

<!-- HEADER -->
<div class="header">
  <div class="brand">Item Consulting</div>
  <h1>Document Title</h1>
  <div class="subtitle">Subtitle — Description</div>
  <div class="date">March 2026</div>
</div>

<!-- VISION BOX (optional) -->
<div class="vision">
  Core message with <em>highlighted terms</em> in green.
</div>

<!-- TABLE OF CONTENTS -->
<div class="toc">
  <h2>Contents</h2>
  <ol>
    <li><a href="#section-id">Section Name</a></li>
  </ol>
</div>

<!-- SECTIONS -->
<section id="section-id">
<h2><span class="num">1.</span> Section Title</h2>
<!-- content -->
</section>

<!-- FOOTER -->
<div class="footer">
  <p><strong>Document Title</strong> — Item Consulting — March 2026</p>
  <p>Generated with Claude Code</p>
</div>

</div>
</body>
</html>
```

## Component Library

### Header

```html
<div class="header">
  <div class="brand">Item Consulting</div>
  <h1>Main Title</h1>
  <div class="subtitle">Subtitle text</div>
  <div class="date">March 2026</div>
</div>
```

### Vision Box (purple gradient)

```html
<div class="vision">
  Main message. <em>Highlighted text</em> appears in green (#34D399).
</div>
```

CSS:
```css
.vision {
  background: linear-gradient(135deg, var(--purple), #6D28D9);
  color: white;
  padding: 1.75rem 2rem;
  border-radius: 12px;
  margin-bottom: 2.5rem;
  font-size: 1.1rem;
  font-weight: 500;
  line-height: 1.6;
}
.vision em { font-style: normal; color: var(--green); font-weight: 700; }
```

### Table of Contents

```html
<div class="toc">
  <h2>Contents</h2>
  <ol>
    <li><a href="#section-id">Section Name</a></li>
  </ol>
</div>
```

Two-column layout via `columns: 2; column-gap: 2rem;` on the `ol`.

### Section Headings

```html
<h2><span class="num">1.</span> Section Title</h2>
```

The `.num` span is colored purple. Sections have a light purple bottom border.

### Tables

```html
<table>
  <thead>
    <tr><th>Column 1</th><th>Column 2</th></tr>
  </thead>
  <tbody>
    <tr><td>Data</td><td>Data</td></tr>
  </tbody>
</table>
```

- Header: dark background (`--gray-800`), white text, rounded top corners
- Rows: alternating background (`--gray-50`), purple hover
- First/last header cells have border-radius

### Callout Boxes

Five variants:

```html
<!-- Purple — insights, key principles -->
<div class="callout callout-insight">
  <div class="callout-title">Title text</div>
  <p>Body text.</p>
</div>

<!-- Orange — warnings, important caveats -->
<div class="callout callout-warning">...</div>

<!-- Blue — informational, notes -->
<div class="callout callout-info">...</div>

<!-- Green — success, positive outcomes -->
<div class="callout callout-success">...</div>

<!-- Red — danger, critical risks -->
<div class="callout callout-danger">...</div>
```

CSS pattern:
```css
.callout {
  border-radius: 10px;
  padding: 1.25rem 1.5rem;
  margin: 1.25rem 0;
}
.callout-title {
  font-weight: 700;
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  margin-bottom: 0.5rem;
}
.callout-insight { background: var(--purple-light); border-left: 4px solid var(--purple); }
.callout-warning { background: var(--orange-light); border-left: 4px solid var(--orange); }
.callout-info { background: var(--blue-light); border-left: 4px solid var(--blue); }
.callout-success { background: var(--green-light); border-left: 4px solid var(--green); }
.callout-danger { background: var(--red-light); border-left: 4px solid var(--red); }
```

### Code Blocks

```html
<pre><code><span class="comment"># Comment</span>
<span class="keyword">class</span> <span class="type">MyClass</span>:
    name: str = <span class="string">"value"</span></code></pre>
```

CSS:
```css
pre {
  background: var(--gray-800);
  color: #E2E8F0;
  padding: 1.25rem 1.5rem;
  border-radius: 10px;
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 0.82rem;
  line-height: 1.6;
}
pre .comment { color: #64748B; }
pre .keyword { color: #C084FC; }
pre .string { color: #34D399; }
pre .type { color: #38BDF8; }
```

### ASCII Diagrams

```html
<div class="diagram">
Box 1 ──── Box 2 ──── Box 3
  │           │
  ▼           ▼
Result      Result
</div>
```

CSS:
```css
.diagram {
  background: var(--dark);
  color: #CBD5E1;
  padding: 1.5rem;
  border-radius: 12px;
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 0.78rem;
  line-height: 1.5;
  overflow-x: auto;
  white-space: pre;
}
```

### Blockquotes (for positioning statements)

```html
<blockquote>
  "LogPilot helps operations teams understand production incidents..."
</blockquote>
```

CSS:
```css
blockquote {
  background: var(--gray-100);
  border-left: 4px solid var(--purple);
  padding: 1rem 1.25rem;
  border-radius: 0 8px 8px 0;
  font-size: 1.05rem;
  font-weight: 500;
  color: var(--gray-700);
}
```

### Footer

```html
<div class="footer">
  <p><strong>Document Title</strong> — Item Consulting — March 2026</p>
  <p>Generated with Claude Code</p>
</div>
```

## Print Styles

Always include:

```css
@media print {
  body { background: white; }
  .page { padding: 1rem 0; max-width: 100%; }
  pre, .diagram { font-size: 0.72rem; }
  section { break-inside: avoid; }
  h2 { break-after: avoid; }
  .toc { break-after: page; }
}
```

## Norwegian Variant

When creating a Norwegian version:
- Change `lang="en"` to `lang="nb"`
- Translate header subtitle and date (see `writing-norwegian.md` skill)
- Translate footer: "Generated with Claude Code" → "Generert med Claude Code"
- All CSS, classes, IDs, structure stay identical
- See `writing-norwegian.md` for full translation conventions

## Sizing Guidelines

- Page max-width: `900px`
- Body font: `1rem` (browser default ~16px)
- H2: `1.6rem`, H3: `1.15rem`, H4: `1rem`
- Table font: `0.9rem`
- Code font: `0.82rem`
- Diagram font: `0.78rem`
- Line height: `1.7` (body), `1.6` (code)

## Checklist for New Documents

- [ ] All CSS inline (no external files)
- [ ] CSS variables used (no hardcoded colors)
- [ ] Header with brand, title, subtitle, date
- [ ] Table of contents with anchor links
- [ ] Numbered section headings with `.num` span
- [ ] Tables with dark header, alternating rows, hover
- [ ] Callouts for key messages (use appropriate variant)
- [ ] Code blocks with syntax highlighting spans
- [ ] Footer with title, company, date
- [ ] Print styles included
- [ ] Works in any browser without dependencies
- [ ] Can be printed to PDF with Cmd+P
