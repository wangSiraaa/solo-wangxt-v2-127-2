"""Application services: orchestrate parse, controlled storage, persistence."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.batch import (
    ArchivePlan,
    BatchLimits,
    EmlMember,
    MemberRejection,
    log_safe_name,
)
from app.parser import ParseStatus, parse_eml
from app.repository import Repository
from app.storage import ControlledStorage

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
class BatchEntryResult:
    """Per-member outcome of a batch import (one row in the report)."""

    name: str  # in-archive path — provenance label only
    status: str  # ok | defective | failed | rejected | skipped
    declared_size: int | None
    ingest_id: int | None
    message_pk: int | None
    raw_sha256: str | None
    defects_count: int
    error: str | None


@dataclass
class BatchImportResult:
    entries: list[BatchEntryResult] = field(default_factory=list)
    members_total: int = 0
    threads: dict[str, Any] = field(default_factory=dict)


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

    def ingest_batch(
        self, archive: bytes, *, archive_name: str | None, limits: BatchLimits
    ) -> BatchImportResult:
        """Import every acceptable ``.eml`` member of a ZIP archive.

        Each member runs through the exact single-message pipeline (parse,
        raw digest/storage, attachment storage, persistence). A member that
        blows up is recorded as ``failed`` and the batch continues. Threads
        are rebuilt once at the end via the same repository routine the
        single ingest uses.
        """
        result = BatchImportResult()
        saved_message = False
        with ArchivePlan(archive, limits) as plan:
            result.members_total = plan.members_total
            for outcome in plan:
                if isinstance(outcome, MemberRejection):
                    log.info(
                        "batch member %s: name=%r reason=%s",
                        outcome.status,
                        log_safe_name(outcome.name),
                        outcome.reason,
                    )
                    result.entries.append(
                        BatchEntryResult(
                            name=outcome.name,
                            status=outcome.status,
                            declared_size=outcome.declared_size,
                            ingest_id=None,
                            message_pk=None,
                            raw_sha256=None,
                            defects_count=0,
                            error=outcome.reason,
                        )
                    )
                    continue
                assert isinstance(outcome, EmlMember)
                source = f"{archive_name}::{outcome.name}" if archive_name else outcome.name
                try:
                    one = self.ingest(outcome.data, source_name=source, recompute_threads=False)
                except Exception as exc:  # one bad message must not lose the rest
                    log.exception(
                        "batch member ingest failed name=%r: %s",
                        log_safe_name(outcome.name),
                        exc,
                    )
                    result.entries.append(
                        BatchEntryResult(
                            name=outcome.name,
                            status="failed",
                            declared_size=len(outcome.data),
                            ingest_id=None,
                            message_pk=None,
                            raw_sha256=None,
                            defects_count=0,
                            error=f"ingest error: {exc}",
                        )
                    )
                    continue
                saved_message = saved_message or one.message_pk is not None
                result.entries.append(
                    BatchEntryResult(
                        name=outcome.name,
                        status=one.status,
                        declared_size=len(outcome.data),
                        ingest_id=one.ingest_id,
                        message_pk=one.message_pk,
                        raw_sha256=one.raw_sha256,
                        defects_count=one.defects_count,
                        error=one.fatal_error,
                    )
                )
        if saved_message:
            result.threads = self._repo.rebuild_threads()
        return result
