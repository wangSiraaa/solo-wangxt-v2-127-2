"""Parse EML bytes into :class:`ParsedMessage`.

Stdlib only (``email`` package, default/``SMTP`` policy). The parser is
defensive: malformed messages yield ``DEFECTIVE`` or ``FAILED`` results with
defects tagged by MIME path instead of raising into the API layer.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from email import message_from_bytes
from email.message import Message
from email.policy import SMTP
from email.utils import getaddresses, parsedate_to_datetime

from .html_sanitizer import sanitize_html, strip_to_text
from .models import (
    Address,
    Attachment,
    BodyPart,
    ContentDisposition,
    Defect,
    Header,
    ParseStatus,
    PartNode,
    ParsedMessage,
)

# Message-ID / msg-id token: <left@right> or, for In-Reply-To legacy forms,
# bare tokens. Capture angle-bracketed ids first, then fall back to bare atoms.
_MSGID_RE = re.compile(r"<([^<>@\s]+@[^<>\s]+)>")
_BARE_MSGID_RE = re.compile(r"([A-Za-z0-9_.+\-]+@[A-Za-z0-9_.\-]+)")

# Character sets to try in order when the declared charset fails. GB18030 is a
# superset of GBK/GB2312 and covers most Chinese mail in the wild.
FALLBACK_CHARSETS = ("utf-8", "gb18030", "big5", "shift_jis", "iso-8859-1")


class ParseFailure(Exception):
    """Raised only when even a partial structure cannot be produced."""


def _disposition(msg: Message) -> ContentDisposition:
    disp = (msg.get_content_disposition() or "").lower()
    if disp == "inline":
        return ContentDisposition.INLINE
    if disp == "attachment":
        return ContentDisposition.ATTACHMENT
    return ContentDisposition.UNKNOWN


def _extract_message_ids(value: str | None) -> list[str]:
    if not value:
        return []
    ids = _MSGID_RE.findall(value)
    if not ids:
        # Legacy In-Reply-To may contain a bare id plus quoting text.
        ids = _BARE_MSGID_RE.findall(value)
    # Preserve order, drop case-insensitive duplicates.
    seen: set[str] = set()
    out: list[str] = []
    for mid in ids:
        key = mid.strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(mid.strip())
    return out


def _collect_defects(obj: object, stage: str) -> list[Defect]:
    found: list[Defect] = []
    for defect in getattr(obj, "defects", []) or []:
        found.append(
            Defect(
                stage=stage,
                level=type(defect).__name__,
                message=str(defect),
            )
        )
    return found


def _decode_charset(raw: bytes, declared: str | None, stage: str) -> tuple[str, str | None, list[Defect]]:
    """Decode a text payload.

    Returns ``(text, effective_charset, defects)``. The declared charset is
    honored when it works; otherwise a multi-encoding fallback ladder is used
    and every substitution is recorded as a defect so mislabeled mail stays
    traceable.
    """
    defects: list[Defect] = []
    candidates: list[str] = []
    if declared:
        try:
            codecs_name = declared
            import codecs

            codecs.lookup(codecs_name)
            candidates.append(codecs_name)
        except LookupError:
            defects.append(
                Defect(stage=stage, level="UnknownCharsetError", message=f"unknown charset {declared!r}")
            )
    candidates.extend(c for c in FALLBACK_CHARSETS if c not in candidates)
    for charset in candidates:
        try:
            text = raw.decode(charset)
        except (UnicodeDecodeError, LookupError):
            continue
        if declared and charset != declared:
            defects.append(
                Defect(
                    stage=stage,
                    level="CharsetFallback",
                    message=f"declared {declared!r} failed; decoded with {charset!r}",
                )
            )
        return text, charset, defects
    # Last resort: latin-1 never fails; record it explicitly.
    defects.append(
        Defect(stage=stage, level="CharsetReplacement", message="all charsets failed; used latin-1 with replacement")
    )
    return raw.decode("latin-1", errors="replace"), "latin-1", defects


def _addresses(header_value: str | None) -> list[Address]:
    if not header_value:
        return []
    result: list[Address] = []
    for name, addr in getaddresses([header_value]):
        addr = addr.strip()
        if not addr and not name:
            continue
        result.append(Address(display_name=name.strip(), address=addr, raw=f"{name} <{addr}>".strip()))
    return result


def _decode_header_value(msg: Message, name: str) -> tuple[str | None, str | None]:
    """Return (RFC2047-decoded value, raw value) for the first occurrence."""
    raw = msg.get(name)
    if raw is None:
        return None, None
    # With SMTP policy the header subclass renders RFC2047 words decoded as
    # str(); the original encoded spelling is read from the raw item list.
    decoded = str(raw)
    try:
        original = next(value for key, value in msg.raw_items() if key == name)
    except StopIteration:
        original = decoded
    return decoded, original


def _parse_date(value: str | None, stage: str) -> tuple[datetime | None, list[Defect]]:
    if not value:
        return None, []
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError) as exc:
        return None, [Defect(stage=stage, level="InvalidDate", message=str(exc))]
    if dt is not None and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt, []


def _wrap_specific_content_type(msg: Message) -> str:
    """Best-effort full content type without raising on broken parameters."""
    try:
        return msg.get_content_type()
    except (LookupError, TypeError, ValueError):
        return (msg.get("Content-Type", "text/plain").split(";", 1)[0].strip().lower() or "text/plain")


def _get_filename(msg: Message) -> tuple[str | None, str | None]:
    """Return (decoded filename, raw filename) without raising on bad encodings."""
    raw = None
    decoded = None
    try:
        decoded = msg.get_filename()  # honors filename*/name params, RFC2231
    except (UnicodeDecodeError, LookupError, TypeError, ValueError):
        decoded = None
    ctype = msg.get("Content-Type", "")
    cdisp = msg.get("Content-Disposition", "")
    m = re.search(r'filename\*?=(?:([^\'\']*)\'[^\']*\'|")?([^";\n]+)"?', cdisp)
    if not m:
        m = re.search(r'name\*?=(?:([^\'\']*)\'[^\']*\'|")?([^";\n]+)"?', ctype)
    if m:
        candidate = m.group(2).strip().strip('"')
        raw = candidate
        if decoded is None:
            decoded = candidate
    if decoded and raw is None:
        raw = decoded
    return decoded, raw


def _payload_bytes(msg: Message, stage: str) -> tuple[bytes | None, list[Defect]]:
    try:
        payload = msg.get_payload(decode=True)
    except (RuntimeError, ValueError, LookupError, TypeError) as exc:
        return None, [Defect(stage=stage, level="PayloadDecodeError", message=str(exc))]
    if payload is None:
        # multipart or message/* without decodable bytes
        if msg.is_multipart():
            return None, []
        return None, [Defect(stage=stage, level="MissingPayload", message="no decodable payload")]
    return payload, []


def _iter_all_parts(root: Message):
    """Yield (mime_path, msg) for every part, recursing into message/rfc822.

    ``walk()`` on the default policy emits the embedded message of a
    message/rfc822 part as a separate entity; we mirror that and give it a
    distinct path suffix so the structure remains explicit.
    """
    def recurse(msg: Message, path: str):
        yield path, msg
        if msg.is_multipart():
            for idx, part in enumerate(msg.get_payload(), start=1):
                child_path = f"{path}.{idx}" if path else str(idx)
                yield from recurse(part, child_path)
        elif _wrap_specific_content_type(msg) in ("message/rfc822", "message/global"):
            # The payload is a list of Message objects (undecodable as bytes).
            inner = msg.get_payload()
            if isinstance(inner, list):
                for idx, part in enumerate(inner, start=1):
                    yield from recurse(part, f"{path}.m{idx}")

    yield from recurse(root, "")


def _build_tree(msg: Message, path: str = "") -> PartNode:
    ctype = _wrap_specific_content_type(msg)
    disp = _disposition(msg)
    filename, _ = _get_filename(msg)
    raw, _ = _payload_bytes(msg, path or "root")
    node = PartNode(
        mime_path=path or "0",
        content_type=ctype,
        disposition=disp,
        filename=filename,
        is_multipart=msg.is_multipart(),
        is_embedded_message=ctype in ("message/rfc822", "message/global"),
        byte_size=len(raw or b""),
    )
    if msg.is_multipart():
        for idx, part in enumerate(msg.get_payload(), start=1):
            child_path = f"{path}.{idx}" if path else str(idx)
            node.children.append(_build_tree(part, child_path))
    elif node.is_embedded_message:
        inner = msg.get_payload()
        if isinstance(inner, list):
            for idx, part in enumerate(inner, start=1):
                node.children.append(_build_tree(part, f"{path}.m{idx}"))
    return node


def parse_eml(data: bytes) -> ParsedMessage:
    """Parse raw EML bytes into a structured result (never raises for content)."""
    if not isinstance(data, (bytes, bytearray)):  # pragma: no cover - type guard
        raise ParseFailure("EML input must be bytes")
    data = bytes(data)
    raw_sha = hashlib.sha256(data).hexdigest()

    defects: list[Defect] = []
    if not data.strip():
        return _failed_result("empty input: no RFC822 message present", raw_sha, len(data))
    try:
        root = message_from_bytes(data, policy=SMTP)
    except Exception as exc:  # truly catastrophic: still record identity-less failure
        return _failed_result(str(exc), raw_sha, len(data))

    defects.extend(_collect_defects(root, "0"))

    # ---- Identity headers ------------------------------------------------
    mid_value = root.get("Message-ID")
    message_id = _extract_message_ids(mid_value)[0] if mid_value else None
    if mid_value and not message_id:
        defects.append(
            Defect(stage="0:message-id", level="MalformedMessageID", message=mid_value[:200])
        )
    references = _extract_message_ids(root.get("References"))
    in_reply_to = _extract_message_ids(root.get("In-Reply-To"))

    subject, raw_subject = _decode_header_value(root, "Subject")
    date, date_defects = _parse_date(root.get("Date"), "0:date")
    defects.extend(date_defects)

    def first_header(name: str) -> str | None:
        value = root.get(name)
        return str(value) if value is not None else None

    headers: list[Header] = []
    for ordinal, (name, value) in enumerate(root.raw_items()):
        raw_value = value if isinstance(value, str) else str(value)
        try:
            decoded_value = str(root.get(name, raw_value))
        except Exception:
            decoded_value = raw_value
        headers.append(Header(name=name, value=decoded_value, raw_value=raw_value, ordinal=ordinal))

    # ---- Walk parts ------------------------------------------------------
    bodies: list[BodyPart] = []
    attachments: list[Attachment] = []

    for path, part in _iter_all_parts(root):
        stage = path or "0"
        if part is root and _wrap_specific_content_type(part).startswith("multipart/"):
            continue
        defects.extend(_collect_defects(part, stage))

        ctype = _wrap_specific_content_type(part)
        disp = _disposition(part)
        filename, raw_filename = _get_filename(part)
        cid_header = part.get("Content-ID")
        cid = cid_header.strip().strip("<>") if cid_header else None
        content_location = part.get("Content-Location")

        raw, payload_defects = _payload_bytes(part, stage)
        defects.extend(payload_defects)
        if raw is None:
            continue  # container / embedded message node (covered by tree)

        # Explicit attachment disposition, or has a filename, or binary type.
        is_attachment = (
            disp is ContentDisposition.ATTACHMENT
            or (filename is not None and not (disp is ContentDisposition.INLINE and cid))
            or (not ctype.startswith("text/") and ctype not in ("message/rfc822",))
        )

        if is_attachment:
            attachments.append(
                Attachment(
                    mime_path=stage,
                    content_type=ctype,
                    charset=part.get_content_charset(),
                    disposition=disp,
                    filename=filename,
                    raw_filename=raw_filename,
                    content_id=cid,
                    content_location=content_location,
                    byte_size=len(raw),
                    checksum_sha256=hashlib.sha256(raw).hexdigest(),
                    bytes_to_persist=raw,
                    storage_path=None,
                )
            )
            continue

        # Text-bearing inline part.
        declared_charset = part.get_content_charset()
        text, effective_charset, cs_defects = _decode_charset(raw, declared_charset, stage)
        defects.extend(cs_defects)

        body = BodyPart(
            mime_path=stage,
            content_type=ctype,
            charset=effective_charset,
            declared_charset=declared_charset,
            disposition=disp,
            content_id=cid,
            content_location=content_location,
            byte_size=len(raw),
            text=text,
        )
        if ctype == "text/html":
            body.safe_html, body.referenced_cids = sanitize_html(text)
            body.plain_text = strip_to_text(text)
        elif ctype == "text/plain":
            body.plain_text = text
        bodies.append(body)

    status = ParseStatus.OK if not defects else ParseStatus.DEFECTIVE
    tree = _build_tree(root)

    return ParsedMessage(
        message_id=message_id,
        references=references,
        in_reply_to=in_reply_to,
        subject=subject,
        raw_subject=raw_subject,
        date=date,
        from_=_addresses(first_header("From")),
        to=_addresses(first_header("To")),
        cc=_addresses(first_header("Cc")),
        bcc=_addresses(first_header("Bcc")),
        reply_to=_addresses(first_header("Reply-To")),
        sender=_addresses(first_header("Sender")),
        headers=headers,
        tree=tree,
        bodies=bodies,
        attachments=attachments,
        defects=defects,
        status=status,
        fatal_error=None,
        raw_sha256=raw_sha,
        raw_size=len(data),
    )


def _failed_result(error: str, raw_sha: str, raw_size: int) -> ParsedMessage:
    return ParsedMessage(
        message_id=None,
        references=[],
        in_reply_to=[],
        subject=None,
        raw_subject=None,
        date=None,
        from_=[],
        to=[],
        cc=[],
        bcc=[],
        reply_to=[],
        sender=[],
        headers=[],
        tree=None,
        bodies=[],
        attachments=[],
        defects=[Defect(stage="0", level="FatalParseError", message=error)],
        status=ParseStatus.FAILED,
        fatal_error=error,
        raw_sha256=raw_sha,
        raw_size=raw_size,
    )
