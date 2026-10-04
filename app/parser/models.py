"""Structured result types produced by the EML parser.

The parser only *describes* a message; persistence, sanitization policy and
threading live in other modules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class ParseStatus(str, Enum):
    OK = "ok"
    DEFECTIVE = "defective"  # parsed, but the email library reported defects
    FAILED = "failed"  # could not produce even a partial structure


class ContentDisposition(str, Enum):
    INLINE = "inline"
    ATTACHMENT = "attachment"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Address:
    display_name: str
    address: str
    raw: str


@dataclass(frozen=True)
class Defect:
    """One parser defect (boundary mismatch, bad encoding, ...).

    ``stage`` is where it was observed so failures can be located back to a
    specific MIME part or processing step.
    """

    stage: str
    level: str  # defect class name, e.g. StartBoundaryNotFoundDefect
    message: str


@dataclass
class BodyPart:
    """A displayable text part (text/plain or text/html)."""

    mime_path: str  # e.g. "1.2" — location inside the MIME tree
    content_type: str  # e.g. "text/html"
    charset: str | None
    declared_charset: str | None  # what the header said, before substitution
    disposition: ContentDisposition
    content_id: str | None
    content_location: str | None
    byte_size: int
    text: str
    # html variants are None for text/plain; see sanitize_html()
    safe_html: str | None = None
    plain_text: str | None = None
    # Inline resource cids this html part references (via cid: URIs)
    referenced_cids: list[str] = field(default_factory=list)


@dataclass
class Attachment:
    """A non-displayable part saved to the controlled directory."""

    mime_path: str
    content_type: str
    charset: str | None
    disposition: ContentDisposition
    filename: str | None  # decoded, sanitized display name (may be None)
    raw_filename: str | None  # exactly as encoded in the header
    content_id: str | None
    content_location: str | None
    byte_size: int
    checksum_sha256: str
    # Filled in by the storage layer; parser leaves both as None.
    storage_path: str | None = None  # path relative to the controlled root
    bytes_to_persist: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True)
class Header:
    name: str
    value: str  # RFC2047-decoded
    raw_value: str  # original encoded text
    ordinal: int


@dataclass
class PartNode:
    """Structural node of the (possibly nested / message/rfc822) MIME tree."""

    mime_path: str
    content_type: str
    disposition: ContentDisposition
    filename: str | None
    is_multipart: bool
    is_embedded_message: bool
    byte_size: int
    children: list["PartNode"] = field(default_factory=list)


@dataclass
class ParsedMessage:
    # Identity
    message_id: str | None
    references: list[str]
    in_reply_to: list[str]
    subject: str | None
    raw_subject: str | None
    date: datetime | None
    from_: list[Address]
    to: list[Address]
    cc: list[Address]
    bcc: list[Address]
    reply_to: list[Address]
    sender: list[Address]
    headers: list[Header]
    # Structure
    tree: PartNode | None
    bodies: list[BodyPart]
    attachments: list[Attachment]
    # Provenance / quality
    defects: list[Defect]
    status: ParseStatus
    fatal_error: str | None = None
    # Filled by caller (parser operates on bytes only)
    raw_sha256: str | None = None
    raw_size: int | None = None
