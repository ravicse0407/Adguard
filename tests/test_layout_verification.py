import re
from html.parser import HTMLParser

def test_html_tag_nesting():
    class TagChecker(HTMLParser):
        def __init__(self):
            super().__init__()
            self.stack = []
            self.void_tags = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}
            self.mismatches = []
            self.views_parent = {}

        def handle_starttag(self, tag, attrs):
            if tag not in self.void_tags:
                d = dict(attrs)
                tag_id = d.get('id', '')
                tag_class = d.get('class', '')
                pos = self.getpos()
                
                if 'view-panel' in tag_class:
                    # Record immediate parent
                    parent = self.stack[-1] if self.stack else None
                    self.views_parent[tag_id] = parent

                self.stack.append((tag, tag_id, tag_class, pos))

        def handle_endtag(self, tag):
            if tag in self.void_tags:
                return
            if not self.stack:
                self.mismatches.append(f"Unexpected end tag </{tag}> at line {self.getpos()[0]}")
                return
            last_tag, tag_id, tag_class, pos = self.stack.pop()
            if last_tag != tag:
                self.mismatches.append(f"Mismatched tag at line {self.getpos()[0]}: expected </{last_tag}> (from {pos[0]}), got </{tag}>")

    with open('frontend/index.html', encoding='utf-8') as f:
        html = f.read()

    checker = TagChecker()
    checker.feed(html)

    assert not checker.mismatches, f"HTML tag mismatches found: {checker.mismatches}"
    assert len(checker.stack) == 0, f"Unclosed tags remaining: {checker.stack}"

    # Verify that ALL view-panels have 'app-canvas' as their direct parent!
    for view_id, parent in checker.views_parent.items():
        assert parent is not None, f"View {view_id} has no parent!"
        assert parent[0] == 'main', f"View {view_id} parent tag is {parent[0]}, expected 'main'"
        assert parent[1] == 'app-canvas', f"View {view_id} parent ID is {parent[1]}, expected 'app-canvas'"

def test_css_scrolling_rules():
    with open('frontend/style.css', encoding='utf-8') as f:
        css = f.read()

    # Verify body/html does not have overflow: hidden
    # html, body { ... }
    m_body = re.search(r'html,\s*body\s*\{([^}]+)\}', css)
    assert m_body, "html, body rule not found in style.css"
    body_content = m_body.group(1)
    assert 'overflow: hidden' not in body_content, "html, body must NOT have overflow: hidden"
    assert 'min-height: 100%' in body_content, "html, body should have min-height: 100%"

    # Verify body has overflow-y: auto
    m_body_only = re.search(r'(?<!,\s)(?<!,)body\s*\{([^}]+)\}', css)
    assert m_body_only, "body rule not found in style.css"
    assert 'overflow-y: auto' in m_body_only.group(1), "body must have overflow-y: auto"

    # Verify .app-layout has min-height: 100vh and NOT overflow: hidden
    m_layout = re.search(r'\.app-layout\s*\{([^}]+)\}', css)
    assert m_layout, ".app-layout rule not found in style.css"
    layout_content = m_layout.group(1)
    assert 'overflow: hidden' not in layout_content, ".app-layout must NOT have overflow: hidden"
    assert 'min-height: 100vh' in layout_content, ".app-layout must have min-height: 100vh"

    # Verify .app-sidebar is sticky with 100vh height
    m_sidebar = re.search(r'\.app-sidebar\s*\{([^}]+)\}', css)
    assert m_sidebar, ".app-sidebar rule not found in style.css"
    sidebar_content = m_sidebar.group(1)
    assert 'position: sticky' in sidebar_content, ".app-sidebar should be position: sticky"
    assert 'top: 0' in sidebar_content, ".app-sidebar should have top: 0"
    assert 'height: 100vh' in sidebar_content, ".app-sidebar should have height: 100vh"
    assert 'overflow-y: auto' in sidebar_content, ".app-sidebar should have overflow-y: auto"

    # Verify .app-main-wrap allows natural height expansion
    m_main = re.search(r'\.app-main-wrap[^{]*\{([^}]+)\}', css)
    assert m_main, ".app-main-wrap rule not found in style.css"
    main_content = m_main.group(1)
    assert 'overflow: hidden' not in main_content, ".app-main-wrap must NOT have overflow: hidden"
    assert 'min-height: 100vh' in main_content, ".app-main-wrap should have min-height: 100vh"

    # Verify .app-canvas has visible overflow-y for natural page scrolling
    m_canvas = re.search(r'\.app-canvas[^{]*\{([^}]+)\}', css)
    assert m_canvas, ".app-canvas rule not found in style.css"
    canvas_content = m_canvas.group(1)
    assert 'overflow-y: visible' in canvas_content, ".app-canvas must have overflow-y: visible"

if __name__ == '__main__':
    test_html_tag_nesting()
    print("[PASS] test_html_tag_nesting PASSED: All views are inside <main id='app-canvas'> and 100% tags match!")
    test_css_scrolling_rules()
    print("[PASS] test_css_scrolling_rules PASSED: Natural vertical scrolling architecture verified!")
