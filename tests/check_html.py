from html.parser import HTMLParser

class TagChecker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.void_tags = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}

    def handle_starttag(self, tag, attrs):
        if tag not in self.void_tags:
            attrs_dict = dict(attrs)
            tag_id = attrs_dict.get('id', '')
            tag_class = attrs_dict.get('class', '')
            self.stack.append((tag, tag_id, tag_class, self.getpos()))

    def handle_endtag(self, tag):
        if tag in self.void_tags:
            return
        if not self.stack:
            print(f"Unexpected end tag </{tag}> at line {self.getpos()[0]}")
            return
        last_tag, tag_id, tag_class, pos = self.stack.pop()
        if last_tag != tag:
            print(f"Mismatched tag at line {self.getpos()[0]}: expected </{last_tag}> (opened at {pos[0]} id={tag_id} class={tag_class}), got </{tag}>")

with open('frontend/index.html', encoding='utf-8') as f:
    html = f.read()

checker = TagChecker()
checker.feed(html)
if checker.stack:
    print(f"Unclosed tags left ({len(checker.stack)}):")
    for t in checker.stack:
        print(f"  <{t[0]}> opened at line {t[3][0]} id='{t[1]}' class='{t[2]}'")
else:
    print("All HTML tags are 100% properly closed!")



