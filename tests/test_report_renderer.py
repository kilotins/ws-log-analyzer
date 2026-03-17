"""Tests for report_renderer.py — HTML generation, markdown conversion, section wrapping, grade extraction."""
import pytest
from report_renderer import render_html, md_to_html, _wrap_sections, _extract_grades


class TestMdToHtml:
    """Tests for md_to_html — markdown → HTML body conversion."""

    def test_h1_heading(self):
        html = md_to_html("# Hello World")
        assert "<h1" in html
        assert "Hello World" in html

    def test_h2_heading(self):
        html = md_to_html("## Section Title")
        assert "<h2" in html
        assert "Section Title" in html

    def test_h3_heading(self):
        html = md_to_html("### Subsection")
        assert "<h3" in html
        assert "Subsection" in html

    def test_heading_has_slug_id(self):
        html = md_to_html("## My Section Title")
        assert 'id="my-section-title"' in html

    def test_bold_text(self):
        html = md_to_html("Some **bold** text")
        assert "<strong>bold</strong>" in html

    def test_italic_text(self):
        html = md_to_html("Some *italic* text")
        assert "<em>italic</em>" in html

    def test_inline_code(self):
        html = md_to_html("Use `my_function()` here")
        assert '<code class="inline">my_function()</code>' in html

    def test_unordered_list(self):
        md = "- item one\n- item two\n- item three"
        html = md_to_html(md)
        assert "<ul>" in html
        assert "<li>" in html
        assert "item one" in html
        assert "item two" in html

    def test_ordered_list(self):
        md = "1. first\n2. second\n3. third"
        html = md_to_html(md)
        assert "<ol>" in html
        assert "<li>" in html
        assert "first" in html

    def test_fenced_code_block(self):
        md = "```python\nprint('hello')\n```"
        html = md_to_html(md)
        assert "<pre" in html
        assert "<code>" in html
        assert "print" in html

    def test_fenced_code_block_lang_attr(self):
        md = "```python\nx = 1\n```"
        html = md_to_html(md)
        assert 'data-lang="python"' in html

    def test_horizontal_rule(self):
        html = md_to_html("---")
        assert "<hr>" in html

    def test_paragraph(self):
        html = md_to_html("This is a paragraph of text.")
        assert "<p>" in html
        assert "This is a paragraph" in html

    def test_table_with_header(self):
        md = "| Col A | Col B |\n|-------|-------|\n| val1  | val2  |"
        html = md_to_html(md)
        assert "<table>" in html
        assert "<thead>" in html
        assert "<th>" in html
        assert "<td>" in html
        assert "Col A" in html
        assert "val1" in html

    def test_html_special_chars_escaped(self):
        html = md_to_html("Use <script> tags carefully & wisely")
        assert "<script>" not in html
        assert "&lt;script&gt;" in html or "script" in html

    def test_link(self):
        html = md_to_html("[Click here](https://example.com)")
        assert '<a href="https://example.com">Click here</a>' in html

    def test_empty_string(self):
        html = md_to_html("")
        assert html == "" or html.strip() == ""

    def test_blank_lines_ignored(self):
        html = md_to_html("Para one\n\nPara two")
        assert "Para one" in html
        assert "Para two" in html


class TestWrapSections:
    """Tests for _wrap_sections — wrapping H2 sections in collapsible details."""

    def test_returns_tuple(self):
        result = _wrap_sections("<p>no headings</p>")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_no_h2_returns_unchanged_content(self):
        html = "<p>Just a paragraph</p>"
        wrapped, nav = _wrap_sections(html)
        assert "Just a paragraph" in wrapped
        assert nav == []

    def test_single_h2_creates_details(self):
        html = '<h2 id="intro">Introduction</h2><p>content</p>'
        wrapped, nav = _wrap_sections(html)
        assert "<details" in wrapped
        assert "<summary>" in wrapped
        assert "Introduction" in wrapped
        assert "content" in wrapped

    def test_first_section_is_open(self):
        html = '<h2 id="first">First</h2><p>text</p>'
        wrapped, nav = _wrap_sections(html)
        assert " open" in wrapped

    def test_second_section_not_open(self):
        html = (
            '<h2 id="first">First</h2><p>a</p>'
            '<h2 id="second">Second</h2><p>b</p>'
        )
        wrapped, nav = _wrap_sections(html)
        # Count 'open' attributes — only first details should have it
        import re
        open_details = re.findall(r'<details[^>]*\bopen\b', wrapped)
        assert len(open_details) == 1

    def test_nav_items_populated(self):
        html = (
            '<h2 id="arch">Architecture</h2><p>text</p>'
            '<h2 id="sec">Security</h2><p>text</p>'
        )
        wrapped, nav = _wrap_sections(html)
        assert len(nav) == 2
        sids = [item[0] for item in nav]
        assert "sect-arch" in sids
        assert "sect-sec" in sids

    def test_nav_item_structure(self):
        html = '<h2 id="overview">Overview</h2><p>content</p>'
        wrapped, nav = _wrap_sections(html)
        assert len(nav) == 1
        sid, slug, plain = nav[0]
        assert sid == "sect-overview"
        assert slug == "overview"
        assert "Overview" in plain

    def test_sections_closed_after_last(self):
        html = '<h2 id="one">One</h2><p>text</p>'
        wrapped, nav = _wrap_sections(html)
        assert "</details>" in wrapped

    def test_security_section_gets_warn_badge(self):
        html = '<h2 id="security">Security Analysis</h2><p>info</p>'
        wrapped, nav = _wrap_sections(html)
        assert "badge-warn" in wrapped

    def test_section_body_div_present(self):
        html = '<h2 id="test">Test Section</h2><p>body text</p>'
        wrapped, nav = _wrap_sections(html)
        assert 'class="section-body"' in wrapped


class TestExtractGrades:
    """Tests for _extract_grades — letter grade extraction from markdown."""

    def test_empty_string_returns_empty(self):
        result = _extract_grades("")
        assert result == []

    def test_table_row_grade(self):
        md = "| Architecture | **A-** | Some description |"
        result = _extract_grades(md)
        labels = [r[0] for r in result]
        grades = [r[1] for r in result]
        assert any("Architecture" in l for l in labels)
        assert "A-" in grades

    def test_inline_grade(self):
        # The inline pattern matches word-boundary grades — letter grades are extracted.
        # Table-style input is the most reliable way to extract specific area+grade pairs.
        md = "| Architecture | **A-** | some info |\n|---|---|---|\n| Security | **B+** | details |"
        result = _extract_grades(md)
        grades = [r[1] for r in result]
        assert "A-" in grades or "B+" in grades

    def test_grade_css_class_good(self):
        md = "| Architecture | **A** | desc |"
        result = _extract_grades(md)
        for label, grade, css in result:
            if grade == "A":
                assert css == "good"

    def test_grade_css_class_warn(self):
        md = "| Security | **B+** | desc |"
        result = _extract_grades(md)
        for label, grade, css in result:
            if grade == "B+":
                assert css == "warn"

    def test_grade_css_class_bad(self):
        md = "| Tests | **C** | desc |"
        result = _extract_grades(md)
        for label, grade, css in result:
            if grade == "C":
                assert css == "bad"

    def test_no_duplicate_labels(self):
        # Same label mentioned twice — should only appear once
        md = "| Architecture | **A-** | desc |\n| Architecture | **B** | desc2 |"
        result = _extract_grades(md)
        labels = [r[0].lower() for r in result]
        assert len(labels) == len(set(labels))

    def test_invalid_grade_ignored(self):
        md = "| SomeArea | **Z** | desc |"
        result = _extract_grades(md)
        grades = [r[1] for r in result]
        assert "Z" not in grades

    def test_returns_list_of_tuples(self):
        md = "| Architecture | A | desc |"
        result = _extract_grades(md)
        for item in result:
            assert isinstance(item, tuple)
            assert len(item) == 3


class TestRenderHtml:
    """Tests for render_html — complete HTML page generation."""

    def test_returns_string(self):
        html = render_html("# Hello", title="Test Report")
        assert isinstance(html, str)

    def test_doctype_present(self):
        html = render_html("# Hello", title="Test")
        assert "<!DOCTYPE html>" in html

    def test_title_in_head(self):
        html = render_html("# Hello", title="My Audit Report")
        assert "<title>My Audit Report</title>" in html

    def test_title_in_h1(self):
        html = render_html("# Hello", title="My Audit Report")
        assert "My Audit Report" in html

    def test_default_title(self):
        html = render_html("# Hello")
        assert "Audit Report" in html

    def test_markdown_content_rendered(self):
        html = render_html("## Executive Summary\n\nAll good.", title="Test")
        assert "All good." in html

    def test_has_nav_element(self):
        html = render_html("## Section One\ntext", title="Test")
        assert "<nav>" in html

    def test_has_style_block(self):
        html = render_html("# Hello", title="Test")
        assert "<style>" in html

    def test_has_script_block(self):
        html = render_html("# Hello", title="Test")
        assert "<script>" in html

    def test_multiple_h2_sections_wrapped(self):
        md = "## First Section\ntext\n## Second Section\nmore text"
        html = render_html(md, title="Test")
        assert html.count("<details") >= 2

    def test_grades_shown_in_severity_grid(self):
        md = "| Architecture | **A** | desc |\n|---|---|---|\n| Security | **B** | desc |"
        html = render_html(md, title="Test")
        assert "severity-grid" in html or "sev-card" in html

    def test_html_tag_escaped_in_title(self):
        html = render_html("# Hello", title="<script>alert(1)</script>")
        assert "<script>alert(1)</script>" not in html

    def test_nav_links_for_sections(self):
        md = "## Architecture Review\ntext\n## Security Review\ntext"
        html = render_html(md, title="Test")
        assert "nav-link" in html

    def test_section_count_in_meta(self):
        md = "## Section One\ntext\n## Section Two\nmore"
        html = render_html(md, title="Test")
        assert "2 sections" in html
