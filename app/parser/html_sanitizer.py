"""HTML safety policy.

Requirements addressed:
* HTML is only *stored*, never executed; what we retain is sanitized with an
  element/attribute allow-list (``sanitize_html``).
* Remote resources are stripped: only ``cid:`` URIs survive on ``<img>`` and
  only ``http``/``https``/``mailto`` survive on anchors. No ``src`` pointing
  at the network is ever emitted.
* ``escape_html`` provides full escaping for clients that prefer no markup.
* ``strip_to_text`` gives script-free plain text for search indexing.

The implementation is intentionally stdlib-only (``html.parser``).
"""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

# Structural / formatting tags whose content and presence is safe.
ALLOWED_TAGS: frozenset[str] = frozenset(
    {
        "a", "abbr", "address", "article", "aside", "b", "blockquote", "br",
        "caption", "cite", "code", "col", "colgroup", "dd", "del", "details",
        "dfn", "div", "dl", "dt", "em", "figcaption", "figure", "footer",
        "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "i", "img",
        "ins", "kbd", "li", "main", "mark", "nav", "ol", "p", "pre", "q",
        "s", "samp", "section", "small", "span", "strong", "sub", "summary",
        "sup", "table", "tbody", "td", "tfoot", "th", "thead", "time", "tr",
        "u", "ul", "var",
    }
)

# Everything inside these tags is dropped (including text).
DROP_CONTENT_TAGS: frozenset[str] = frozenset(
    {"script", "style", "iframe", "object", "embed", "template", "noscript", "title"}
)

# Allowed generic attributes; everything else is removed.
GLOBAL_ATTRS: frozenset[str] = frozenset({"lang", "title", "colspan", "rowspan", "alt"})

# Explicitly dangerous attributes that are always rejected even if a future
# allow-list change widens GLOBAL_ATTRS (defense in depth).
FORBIDDEN_ATTRS: frozenset[str] = frozenset(
    {
        "style", "class", "id", "srcset", "poster", "background", "data",
        "formaction", "action", "ping", "onload", "onerror",
    }
)

LINK_SCHEMES: frozenset[str] = frozenset({"http", "https", "mailto"})


def _normalize_url(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    # Strip whitespace/control characters that browsers ignore (bypass tricks).
    value = "".join(ch for ch in value if ord(ch) > 31 and ch not in "\t\r\n")
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    # Protocol-relative ("//host/...") and URLs with any host are remote: deny.
    if value.startswith("//") or parts.netloc:
        return None
    if scheme == "cid":
        cid = unquote(value[4:]).strip()
        # cid values look like <local@domain> or local@domain; angle brackets
        # and surrounding whitespace are tolerated, nothing else.
        cid = cid.strip("<>")
        return f"cid:{cid}" if cid else None
    if scheme in LINK_SCHEMES:
        # Only allow same-document or relative http(s) targets without host.
        # Absolute http(s) URLs are remote resources/navigation targets and are
        # intentionally rejected by this archive policy.
        return None
    if scheme == "mailto":  # pragma: no cover - urlsplit maps mailto in path
        return None
    if scheme == "":
        # Relative reference; refuse anything that still smells like a host.
        if parts.path.startswith("\\\\") or parts.path.startswith("//"):
            return None
        return value
    return None  # data:, vbscript:, file:, javascript:, ...


def _link_href(value: str) -> str | None:
    """Allow absolute http(s)/mailto only on anchors (navigation, not loading)."""
    value = "".join(ch for ch in value if ord(ch) > 31 and ch not in "\t\r\n").strip()
    if not value:
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if value.startswith("//") or parts.username or parts.password:
        return None
    scheme = parts.scheme.lower()
    if scheme in LINK_SCHEMES:
        return value
    if scheme == "":
        if parts.path.startswith(("//", "\\\\")):
            return None
        return value
    return None


class _Sanitizer(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self._skip_depth = 0  # >0 while inside a DROP_CONTENT_TAGS element
        self.cids: set[str] = set()

    # -- helpers -----------------------------------------------------------
    def _safe_attrs(self, tag: str, attrs: list[tuple[str, str | None]]) -> str:
        kept: list[str] = []
        for name, value in attrs:
            name = name.lower()
            if value is None:
                continue  # boolean/unknown valueless attributes are dropped
            if name in GLOBAL_ATTRS and name not in FORBIDDEN_ATTRS:
                kept.append(f'{name}="{_attr_escape(value)}"')
                continue
            if tag == "a" and name == "href":
                href = _link_href(value)
                if href is not None:
                    kept.append(f'href="{_attr_escape(href)}"')
                continue
            if tag == "img" and name == "src":
                src = _normalize_url(value)
                if src is not None and src.startswith("cid:"):
                    self.cids.add(src[4:])
                    kept.append(f'src="{_attr_escape(src)}"')
                continue
            # anything else (onerror=, style=, data-* remote, ...) is dropped
        return (" " + " ".join(kept)) if kept else ""

    # -- HTMLParser hooks --------------------------------------------------
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in DROP_CONTENT_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag not in ALLOWED_TAGS:
            return
        if tag == "img":
            # Only an inline cid: resource survives. Anything else (remote
            # http(s), protocol-relative, data:, missing src) drops the whole
            # element; its alt text (already safe) is preserved.
            safe = self._safe_attrs(tag, attrs)
            if 'src="cid:' in safe:
                self.out.append(f"<{tag}{safe} />")
            else:
                alt = next((v for n, v in attrs if n.lower() == "alt" and v), None)
                if alt:
                    self.out.append(_text_escape(alt))
            return
        self.out.append(f"<{tag}{self._safe_attrs(tag, attrs)}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in DROP_CONTENT_TAGS:
            return
        if self._skip_depth or tag not in ALLOWED_TAGS:
            return
        safe = self._safe_attrs(tag, attrs)
        if tag == "img":
            if 'src="cid:' in safe:
                self.out.append(f"<{tag}{safe} />")
            else:
                alt = next((v for n, v in attrs if n.lower() == "alt" and v), None)
                if alt:
                    self.out.append(_text_escape(alt))
            return
        self.out.append(f"<{tag}{safe} />")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in DROP_CONTENT_TAGS:
            if self._skip_depth:
                self._skip_depth -= 1
            return
        if self._skip_depth or tag not in ALLOWED_TAGS:
            return
        self.out.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.out.append(_text_escape(data))

    def handle_entityref(self, name: str) -> None:  # convert_charrefs handles it
        if not self._skip_depth:
            self.out.append(f"&{name};")

    def handle_pi(self, data: str) -> None:  # drop processing instructions
        return

    def handle_decl(self, decl: str) -> None:  # drop <!DOCTYPE ...>
        return

    def unknown_decl(self, data: str) -> None:  # drop <![CDATA[...]]>
        return

    def handle_comment(self, data: str) -> None:  # comments can hide payloads
        return


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs):
        if tag in DROP_CONTENT_TAGS:
            self._skip_depth += 1
        elif tag in ("p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6"):
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in DROP_CONTENT_TAGS and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.parts.append(data)


def _text_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _attr_escape(value: str) -> str:
    return _text_escape(value).replace('"', "&quot;").replace("'", "&#x27;")


def escape_html(value: str) -> str:
    """Fully escape a document so it cannot carry any executable markup."""
    return (
        _text_escape(value)
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def sanitize_html(value: str) -> tuple[str, list[str]]:
    """Return ``(safe_html, referenced_cids)``.

    Tags/attributes not on the allow-list are removed; scripts and style
    content disappear entirely; every URL that would load a remote resource
    (http/https/protocol-relative/data/...) is stripped from loading tags.
    """
    parser = _Sanitizer()
    parser.feed(value)
    parser.close()
    return "".join(parser.out), sorted(parser.cids)


def strip_to_text(value: str) -> str:
    """Extract readable text (script/style content excluded)."""
    parser = _TextExtractor()
    parser.feed(value)
    parser.close()
    text = "".join(parser.parts)
    # collapse runs of blank lines
    lines = [line.strip() for line in text.splitlines()]
    out: list[str] = []
    blank = True
    for line in lines:
        if line:
            out.append(line)
            blank = False
        elif not blank:
            out.append("")
            blank = True
    return "\n".join(out).strip()
