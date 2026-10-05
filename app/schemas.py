"""Pydantic response/request schemas (no frontend, JSON API only)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AddressOut(BaseModel):
    display_name: str
    address: str
    raw: str


class DefectOut(BaseModel):
    stage: str
    level: str
    message: str


class AttachmentSummary(BaseModel):
    mime_path: str
    filename: str | None = None
    content_type: str | None = None
    stored: bool
    storage_path: str | None = None
    byte_size: int
    sha256: str | None = None
    error: str | None = None


class IngestResponse(BaseModel):
    ingest_id: int
    message_pk: int | None
    status: str
    raw_sha256: str
    raw_size: int
    defects_count: int
    fatal_error: str | None = None
    attachments: list[AttachmentSummary]
    threads: dict[str, Any] = Field(default_factory=dict)


class BatchEntryOut(BaseModel):
    """One archive member's outcome; ``name`` is the in-archive path and is
    only a provenance label — it is never used as a filesystem path."""

    name: str
    status: str  # ok | defective | failed | rejected | skipped
    declared_size: int | None = None
    ingest_id: int | None = None
    message_pk: int | None = None
    raw_sha256: str | None = None
    defects_count: int = 0
    error: str | None = None


class BatchImportResponse(BaseModel):
    archive_name: str | None
    archive_sha256: str
    archive_size: int
    members_total: int
    ok: int
    defective: int
    failed: int
    rejected: int
    skipped: int
    entries: list[BatchEntryOut]
    threads: dict[str, Any] = Field(default_factory=dict)


class MessageSummary(BaseModel):
    id: int
    ingest_id: int
    message_id: str | None
    subject: str | None
    date: datetime | None
    from_json: list[dict[str, Any]]
    thread_key: str | None
    raw_sha256: str
    missing_id: bool


class BodyOut(BaseModel):
    mime_path: str
    content_type: str
    charset: str | None
    declared_charset: str | None
    disposition: str
    content_id: str | None
    byte_size: int
    text: str | None = None
    safe_html: str | None = None
    escaped_html: str | None = None
    plain_text: str | None = None
    referenced_cids: list[str] = Field(default_factory=list)


class AttachmentOut(BaseModel):
    id: int
    message_pk: int
    mime_path: str
    content_type: str
    filename: str | None
    raw_filename: str | None
    content_id: str | None
    byte_size: int
    checksum_sha256: str
    storage_path: str | None
    stored: bool


class HeaderOut(BaseModel):
    ordinal: int
    name: str
    value: str
    raw_value: str


class MessageDetail(MessageSummary):
    raw_subject: str | None
    to_json: list[dict[str, Any]]
    cc_json: list[dict[str, Any]]
    bcc_json: list[dict[str, Any]]
    reply_to_json: list[dict[str, Any]]
    sender_json: list[dict[str, Any]]
    tree_json: dict[str, Any] | None
    raw_path: str | None
    bodies: list[BodyOut]
    attachments: list[AttachmentOut]
    defects: list[DefectOut]


class SearchResponse(BaseModel):
    query: str
    count: int
    results: list[dict[str, Any]]


class FailureOut(BaseModel):
    ingest_id: int
    received_at: datetime
    source_name: str | None
    status: str
    raw_sha256: str
    raw_size: int
    fatal_error: str | None
    defect_count: int
    defects: list[DefectOut]


class ThreadSummary(BaseModel):
    thread_key: str
    message_count: int
    started_at: datetime | None
    last_at: datetime | None
    has_missing_id: bool
    distinct_message_ids: int


class ThreadDetail(BaseModel):
    thread_key: str
    messages: list[dict[str, Any]]


class IngestDetail(BaseModel):
    id: int
    received_at: datetime
    source_name: str | None
    status: str
    raw_sha256: str
    raw_size: int
    raw_path: str | None
    fatal_error: str | None
    defect_count: int
    defects: list[DefectOut]
    message_pk: int | None


class Health(BaseModel):
    status: str
    backend: str
    storage_roots: dict[str, str]
