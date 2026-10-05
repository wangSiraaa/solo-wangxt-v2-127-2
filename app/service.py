"""Application services: orchestrate parse, controlled storage, persistence."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.batch import BundleLimits, iter_members, plan_zip
from app.parser import ParseStatus, parse_eml
from app.repository import Repository
from app.storage import ControlledStorage, safe_basename

log = logging.getLogger("emlarchive.service")


@dataclass
class IngestResult:
    ingest_id: int
    message_pk: int | None
    status: str
    raw_sha256: str
    raw_size: int
    defects_count: int
    fatal_error: str | None
    attachments: list[dict[str, Any]]
    threads: dict[str, Any]


@dataclass
class BatchItemResult:
    """Per-member outcome; the archive path is provenance text only."""

    index: int
    path: str
    outcome: str  # "ingested" | "rejected" | "error"
    ingest_id: int | None = None
    message_pk: int | None = None
    status: str | None = None  # parser status for ingested members
    raw_sha256: str | None = None
    raw_size: int | None = None
    defects_count: int | None = None
    fatal_error: str | None = None
    error: str | None = None
    attachments: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class BatchResult:
    package: str | None
    total: int
    ingested: int
    rejected: int
    errors: int
    threads: dict[str, Any]
    items: list[BatchItemResult]


class IngestService:
    def __init__(self, repo: Repository, raw_storage: ControlledStorage, attachment_storage: ControlledStorage) -> None:
        self._repo = repo
        self._raw = raw_storage
        self._att = attachment_storage

    def ingest(self, data: bytes, *, source_name: str | None = None, recompute_threads: bool = True) -> IngestResult:
        # Parse first so even catastrophic failures have a digest.
        parsed = parse_eml(data)

        raw_relpath: str | None = None
        if parsed.status is not ParseStatus.FAILED:
            try:
                _, raw_relpath = self._raw.store_raw(data)
            except Exception as exc:  # storage failure must not be swallowed
                log.error("raw eml storage failed sha256=%s: %s", parsed.raw_sha256, exc)
                raise

        stored: list[tuple[Any, str]] = []
        att_summaries: list[dict[str, Any]] = []
        for att in parsed.attachments:
            if att.bytes_to_persist is None:
                continue
            try:
                rel = self._att.store_attachment(
                    att.bytes_to_persist,
                    att.checksum_sha256,
                    att.filename,
                )
            except Exception as exc:
                # Keep parse metadata but mark the attachment as not stored so
                # the failure is locatable; never log bytes.
                log.error(
                    "attachment storage failed part=%s content_type=%s bytes=%d sha256=%s: %s",
                    att.mime_path,
                    att.content_type,
                    att.byte_size,
                    att.checksum_sha256,
                    exc,
                )
                att_summaries.append(
                    {
                        "mime_path": att.mime_path,
                        "filename": att.filename,
                        "stored": False,
                        "error": str(exc),
                        "byte_size": att.byte_size,
                    }
                )
                continue
            stored.append((att, rel))
            att.storage_path = rel
            att.bytes_to_persist = None  # free memory; bytes are on disk now
            att_summaries.append(
                {
                    "mime_path": att.mime_path,
                    "filename": att.filename,
                    "content_type": att.content_type,
                    "stored": True,
                    "storage_path": rel,
                    "byte_size": att.byte_size,
                    "sha256": att.checksum_sha256,
                }
            )

        saved = self._repo.save_ingest(
            parsed,
            raw_relpath=raw_relpath,
            stored_attachments=stored,
            source_name=source_name,
            status=parsed.status.value,
            fatal_error=parsed.fatal_error,
        )

        threads: dict[str, Any] = {}
        if recompute_threads and saved.get("message_id") is not None:
            threads = self._repo.rebuild_threads()

        return IngestResult(
            ingest_id=saved["ingest_id"],
            message_pk=saved.get("message_id"),
            status=parsed.status.value,
            raw_sha256=parsed.raw_sha256 or "",
            raw_size=parsed.raw_size or len(data),
            defects_count=len(parsed.defects),
            fatal_error=parsed.fatal_error,
            attachments=att_summaries,
            threads=threads,
        )

    # -- batch (offline ZIP package) --------------------------------------
    def ingest_zip(
        self,
        data: bytes,
        *,
        package_name: str | None = None,
        limits: BundleLimits,
        recompute_threads: bool = True,
    ) -> BatchResult:
        """Validate and ingest every ``.eml`` member of an offline package.

        Package-level violations (bad ZIP, traversal paths, non-EML members,
        zip-bomb shape) are raised from :func:`plan_zip` before anything is
        persisted. Individual member failures (oversize, decompression error,
        storage hiccup, defective/failed parse) are reported per item and do
        not stop the remaining members. Threads are rebuilt at most once,
        after every member has been processed.
        """
        planned = plan_zip(data, limits)

        package_base = safe_basename(package_name or "") or None
        items: list[BatchItemResult] = []
        any_message = False

        for member, payload, error in iter_members(data, planned, limits):
            source = f"{package_base}!{member.path}" if package_base else member.path
            if payload is None:
                log.warning("batch member rejected source=%r: %s", source, error)
                items.append(
                    BatchItemResult(
                        index=member.index,
                        path=member.path,
                        outcome="rejected",
                        error=error,
                    )
                )
                continue
            if not payload:
                items.append(
                    BatchItemResult(
                        index=member.index,
                        path=member.path,
                        outcome="rejected",
                        error="empty .eml member",
                    )
                )
                continue
            try:
                result = self.ingest(payload, source_name=source, recompute_threads=False)
            except Exception as exc:
                # Storage failure or anything unexpected: keep the rest of the
                # package alive; metadata only in logs, never member bytes.
                log.error("batch member failed source=%r: %s", source, exc)
                items.append(
                    BatchItemResult(
                        index=member.index,
                        path=member.path,
                        outcome="error",
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
                continue
            if result.message_pk is not None:
                any_message = True
            items.append(
                BatchItemResult(
                    index=member.index,
                    path=member.path,
                    outcome="ingested",
                    ingest_id=result.ingest_id,
                    message_pk=result.message_pk,
                    status=result.status,
                    raw_sha256=result.raw_sha256,
                    raw_size=result.raw_size,
                    defects_count=result.defects_count,
                    fatal_error=result.fatal_error,
                    attachments=result.attachments,
                )
            )

        threads: dict[str, Any] = {}
        if recompute_threads and any_message:
            threads = self._repo.rebuild_threads()

        ingested = sum(1 for i in items if i.outcome == "ingested")
        rejected = sum(1 for i in items if i.outcome == "rejected")
        errors = sum(1 for i in items if i.outcome == "error")
        return BatchResult(
            package=package_base,
            total=len(items),
            ingested=ingested,
            rejected=rejected,
            errors=errors,
            threads=threads,
            items=items,
        )
