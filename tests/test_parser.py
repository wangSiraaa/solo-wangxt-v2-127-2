import hashlib

from app.parser import ParseStatus, parse_eml
from app.parser.html_sanitizer import escape_html, sanitize_html, strip_to_text
from conftest import SAMPLES


def read_sample(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


# ---------- structure / multibyte ----------

def test_multilayer_mime_structure_and_charsets():
    p = parse_eml(read_sample("01_multibyte.eml"))
    assert p.status is ParseStatus.OK
    assert p.message_id == "multi-01@example.com"
    assert p.references == ["root-00@example.com", "parent-01@example.com"]
    assert p.in_reply_to == ["parent-01@example.com"]

    # tree: mixed -> alternative -> (plain, gb18030 plain, related(html, gif))
    tree = p.tree
    assert tree.content_type == "multipart/mixed"
    alt = tree.children[0]
    assert alt.content_type == "multipart/alternative"
    related = alt.children[2]
    assert related.content_type == "multipart/related"
    assert related.children[0].mime_path == "1.3.1"

    # embedded message/rfc822 is a structural node with its own child part
    embedded = tree.children[1]
    assert embedded.is_embedded_message
    assert embedded.children[0].content_type == "text/plain"

    types = {b.mime_path: b for b in p.bodies}
    assert "1.1" in types and "1.2" in types and "1.3.1" in types and "2.1" in types
    assert types["1.2"].declared_charset == "gb18030"
    assert "GB18030" in types["1.2"].plain_text
    assert types["2.1"].charset == "shift_jis"
    assert "埋め込み" in types["2.1"].plain_text

    # inline related image kept as attachment-like binary with cid linkage
    cids = {a.content_id: a for a in p.attachments}
    assert "banner1" in cids
    html = types["1.3.1"]
    assert "banner1" in html.referenced_cids


def test_rfc2047_headers_decode():
    p = parse_eml(read_sample("01_multibyte.eml"))
    assert p.subject == "多编码测试 — éπü"
    assert p.from_[0].display_name.startswith("老王")
    assert {a.address for a in p.to} == {"cn@example.com", "jp@example.com"}


def test_attachment_filename_rfc2231_decoded():
    p = parse_eml(read_sample("01_multibyte.eml"))
    pdf = next(a for a in p.attachments if a.content_type == "application/pdf")
    assert pdf.filename == "文本.pdf"
    assert pdf.checksum_sha256 == hashlib.sha256(
        b"%PDF-1.4\nfake pdf content bytes\n"
    ).hexdigest()


# ---------- defects / corruption ----------

def test_corrupt_boundary_is_defective_with_located_defect():
    p = parse_eml(read_sample("06_corrupt_boundary.eml"))
    assert p.status is ParseStatus.DEFECTIVE
    assert p.message_id == "corrupt-01@example.com"  # headers still usable
    assert any(d.level == "CloseBoundaryNotFoundDefect" for d in p.defects)
    assert all(d.stage for d in p.defects)


def test_unknown_charset_falls_back_and_records():
    p = parse_eml(read_sample("03_missing_id.eml"))
    assert p.status is ParseStatus.DEFECTIVE
    assert p.message_id is None
    levels = [d.level for d in p.defects]
    assert "UnknownCharsetError" in levels
    assert "CharsetFallback" in levels
    # latin-1 fallback still yields readable text, lossless enough to search
    assert "hello" in p.bodies[0].plain_text


def test_bad_base64_payload_still_extracted():
    p = parse_eml(read_sample("07_bad_cte.eml"))
    # bytes survive even if the cte is bogus; it becomes an attachment
    assert len(p.attachments) == 1
    assert p.attachments[0].filename == "bin.dat"


def test_completely_garbage_returns_failed_not_raises():
    p = parse_eml(b"")
    assert p.status is ParseStatus.FAILED
    assert p.defects[0].level == "FatalParseError"
    assert p.raw_sha256 == hashlib.sha256(b"").hexdigest()


# ---------- html safety ----------

def test_html_script_and_remote_resources_removed():
    p = parse_eml(read_sample("09_html_xss.eml"))
    html = p.bodies[0]
    out = html.safe_html
    assert "<script" not in out
    assert "onerror" not in out and "onclick" not in out
    assert "javascript:" not in out
    assert "http://evil" not in out and "//evil" not in out
    assert "<iframe" not in out and "<style" not in out
    # inline cid resource survives
    assert 'src="cid:inline1"' in out
    # text content is retained
    assert "hello" in out and "safealt" in out
    # plain text extraction strips scripts
    plain = strip_to_text(p.bodies[0].text)
    assert "fetch(" not in plain
    assert "hello" in plain


def test_sanitizer_unit_rules():
    cases = {
        '<img src="http://x/y.png">': "",
        '<img src="//x/y.png">': "",
        '<img src="data:image/png;base64,AAAA">': "",
        '<img src="cid:foo@bar">': '<img src="cid:foo@bar" />',
        '<a href="https://ok.example/">x</a>': '<a href="https://ok.example/">x</a>',
        '<a href="javascript:alert(1)">x</a>': "<a>x</a>",
        '<p style="x">t</p>': "<p>t</p>",
        '<script>bad</script>ok': "ok",
    }
    for src, expected in cases.items():
        got, _ = sanitize_html(src)
        assert got == expected, (src, got)


def test_escape_html_is_total():
    assert escape_html('<b>"&\'</b>') == "&lt;b&gt;&quot;&amp;&#x27;&lt;/b&gt;"


def test_invalid_date_is_located_defect():
    p = parse_eml(b"Message-ID: <d1@x>\nDate: not a date\nSubject: x\n\nbody")
    assert p.status is ParseStatus.DEFECTIVE
    assert p.date is None
    assert any(d.level == "InvalidDate" and d.stage == "0:date" for d in p.defects)


def test_more_remote_url_bypasses_stripped():
    hostile = [
        '<img src=" java\tscript:alert(1)">',
        '<img src="/https://evil/x.png">',
        '<img/src=x onerror=alert(1)>',
        '<img src="HTTPS://EVIL/x.png">',
        '<image href="http://evil/x.png">',
        '<body background="http://evil/bg.png">x</body>',
        '<a href="  javascript:alert(1)">x</a>',
        '<img src="cid:ok@host" onerror="x()">',
    ]
    for src in hostile:
        out, cids = sanitize_html(src)
        assert "http" not in out.replace("&", ""), (src, out)
        assert "onerror" not in out and "background" not in out
        assert "javascript" not in out

