"""FastAPI application: ingest EML, inspect facts, download attachments.

No frontend. The only requests that accept file bytes are ``POST /ingest``
(single message) and ``POST /ingest/batch`` (offline ZIP package); both are
bounded by explicit streaming caps.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import FileResponse, Response

from app.batch import BatchFormatError, BatchLimits, BatchLimitError
from app.config import Settings, get_settings
from app.memory_repository import MemoryRepository
from app.pg_repository import PgRepository
from app.repository import Repository
from app.schemas import (
    BatchEntryOut,
    BatchImportResponse,
    FailureOut,
    Health,
    IngestDetail,
    IngestResponse,
    MessageDetail,
    MessageSummary,
    SearchResponse,
    ThreadDetail,
    ThreadSummary,
)
from app.service import IngestService
from app.storage import ControlledStorage, StorageError

log = logging.getLogger("emlarchive.api")

_CHUNK = 1024 * 1024


class AppState:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.raw_storage = ControlledStorage(settings.raw_dir, file_mode=settings.file_mode)
        self.attachment_storage = ControlledStorage(settings.attachment_dir, file_mode=settings.file_mode)
        if settings.database_dsn:
            self.repo: Repository = PgRepository(settings.database_dsn)
            self.backend = "postgresql"
        else:
            self.repo = MemoryRepository()
            self.backend = "memory"
        self.repo.init_schema()
        self.service = IngestService(self.repo, self.raw_storage, self.attachment_storage)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    app = FastAPI(
        title="EML Archive",
        version="1.0.0",
        description="Parse EML files into searchable mail facts. No script execution, no remote resources.",
    )
    app.state.arch = AppState(settings)

    def get_state(request: Request) -> AppState:
        return request.app.state.arch

    async def _read_limited(file: UploadFile, limit: int) -> bytes:
        """Stream upload into memory with a hard cap; never log the bytes."""
        buf = bytearray()
        while True:
            chunk = await file.read(_CHUNK)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > limit:
                # Metadata only.
                log.warning("upload rejected: exceeded %d bytes (source=%r)", limit, file.filename)
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=f"upload exceeds maximum of {limit} bytes",
                )
        return bytes(buf)

    # ---- ingest ----------------------------------------------------------
    @app.post("/ingest", response_model=IngestResponse, status_code=201, tags=["ingest"])
    async def ingest_eml(
        request: Request,
        file: UploadFile | None = None,
        recompute_threads: bool = True,
    ) -> IngestResponse:
        st = get_state(request)
        if file is None:
            raise HTTPException(status_code=422, detail="multipart form field 'file' is required")
        data = await _read_limited(file, st.settings.max_upload_bytes)
        if not data:
            raise HTTPException(status_code=422, detail="empty upload")
        try:
            result = st.service.ingest(
                data, source_name=file.filename, recompute_threads=recompute_threads
            )
        except StorageError as exc:
            raise HTTPException(status_code=500, detail=f"storage error: {exc}")
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("ingest failed for sha256=<unavailable>: %s", exc)
            raise HTTPException(status_code=500, detail="internal ingest failure")
        return IngestResponse(
            ingest_id=result.ingest_id,
            message_pk=result.message_pk,
            status=result.status,
            raw_sha256=result.raw_sha256,
            raw_size=result.raw_size,
            defects_count=result.defects_count,
            fatal_error=result.fatal_error,
            attachments=result.attachments,
            threads=result.threads,
        )

    @app.post(
        "/ingest/batch",
        response_model=BatchImportResponse,
        status_code=201,
        tags=["ingest"],
    )
    async def ingest_batch(request: Request, file: UploadFile | None = None) -> BatchImportResponse:
        """Import an offline ZIP package of ``.eml`` files, one report row per member."""
        st = get_state(request)
        if file is None:
            raise HTTPException(status_code=422, detail="multipart form field 'file' is required")
        data = await _read_limited(file, st.settings.max_batch_bytes)
        if not data:
            raise HTTPException(status_code=422, detail="empty upload")
        limits = BatchLimits(
            max_files=st.settings.max_batch_files,
            max_expanded_bytes=st.settings.max_batch_expanded_bytes,
            max_member_bytes=st.settings.max_upload_bytes,
        )
        try:
            result = st.service.ingest_batch(data, archive_name=file.filename, limits=limits)
        except BatchFormatError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        except BatchLimitError as exc:
            log.warning("batch archive rejected: %s (source=%r)", exc, file.filename)
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=str(exc)
            )
        counts = {"ok": 0, "defective": 0, "failed": 0, "rejected": 0, "skipped": 0}
        for entry in result.entries:
            counts[entry.status] = counts.get(entry.status, 0) + 1
        return BatchImportResponse(
            archive_name=file.filename,
            archive_sha256=hashlib.sha256(data).hexdigest(),
            archive_size=len(data),
            members_total=result.members_total,
            ok=counts["ok"],
            defective=counts["defective"],
            failed=counts["failed"],
            rejected=counts["rejected"],
            skipped=counts["skipped"],
            entries=[BatchEntryOut(**vars(entry)) for entry in result.entries],
            threads=result.threads,
        )

    @app.post("/threads/rebuild", tags=["threads"])
    def rebuild_threads(request: Request) -> dict[str, Any]:
        return get_state(request).repo.rebuild_threads()

    # ---- messages --------------------------------------------------------
    @app.get("/messages", response_model=list[MessageSummary], tags=["messages"])
    def list_messages(
        request: Request,
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> list[dict[str, Any]]:
        return get_state(request).repo.list_messages(limit, offset)

    @app.get("/messages/{pk}", response_model=MessageDetail, tags=["messages"])
    def get_message(request: Request, pk: int) -> dict[str, Any]:
        msg = get_state(request).repo.get_message(pk)
        if msg is None:
            raise HTTPException(status_code=404, detail="message not found")
        return msg

    @app.get("/search", response_model=SearchResponse, tags=["messages"])
    def search(
        request: Request,
        q: str = Query(..., min_length=1, description="substring over subject/ids/headers/plain text"),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        return get_state(request).repo.search_messages(q, limit, offset)

    # ---- ingests / failures ---------------------------------------------
    @app.get("/ingests/{ingest_id}", response_model=IngestDetail, tags=["ingest"])
    def get_ingest(request: Request, ingest_id: int) -> dict[str, Any]:
        ing = get_state(request).repo.get_ingest(ingest_id)
        if ing is None:
            raise HTTPException(status_code=404, detail="ingest not found")
        return ing

    @app.get("/failures", response_model=list[FailureOut], tags=["ingest"])
    def list_failures(
        request: Request,
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> list[dict[str, Any]]:
        return get_state(request).repo.list_failures(limit, offset)

    # ---- threads ---------------------------------------------------------
    @app.get("/threads", response_model=list[ThreadSummary], tags=["threads"])
    def list_threads(
        request: Request,
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> list[dict[str, Any]]:
        return get_state(request).repo.list_threads(limit, offset)

    @app.get("/threads/{thread_key:path}", response_model=ThreadDetail, tags=["threads"])
    def get_thread(request: Request, thread_key: str) -> dict[str, Any]:
        thread = get_state(request).repo.get_thread(thread_key)
        if thread is None:
            raise HTTPException(status_code=404, detail="thread not found")
        return thread

    # ---- attachments -----------------------------------------------------
    @app.get("/messages/{pk}/attachments/{attachment_id}/download", tags=["attachments"])
    def download_attachment(request: Request, pk: int, attachment_id: int) -> Response:
        st = get_state(request)
        att = st.repo.get_attachment(attachment_id)
        if att is None or att["message_pk"] != pk or not att.get("storage_path"):
            raise HTTPException(status_code=404, detail="attachment not found")
        try:
            # resolve() re-validates the stored relative path against the root;
            # a tampered DB value containing traversal is rejected here.
            path = st.attachment_storage.resolve(att["storage_path"])
        except StorageError as exc:
            log.error(
                "attachment path rejected id=%d relpath_tampered: %s", attachment_id, exc
            )
            raise HTTPException(status_code=400, detail="invalid attachment path")
        if not path.is_file():
            raise HTTPException(status_code=410, detail="attachment bytes missing on disk")
        # Serve under the *sanitized* basename: raw header names may contain
        # traversal sequences or CRLF header-injection bytes. The original name
        # is still preserved in the database for forensics.
        from app.storage import safe_basename

        safe_name = safe_basename(att.get("filename") or "") or f"attachment-{attachment_id}.bin"
        # FileResponse streams from disk; we never put content into a log line.
        return FileResponse(
            path,
            media_type=att.get("content_type") or "application/octet-stream",
            filename=safe_name,
        )

    @app.get("/health", response_model=Health, tags=["meta"])
    def health(request: Request) -> Health:
        st = get_state(request)
        return Health(
            status="ok",
            backend=st.backend,
            storage_roots={
                "raw": str(st.settings.raw_dir),
                "attachments": str(st.settings.attachment_dir),
            },
        )

    return app


app = create_app()
