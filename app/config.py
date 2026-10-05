"""Runtime configuration loaded from environment variables.

Everything security relevant (storage roots, upload caps) is resolved here so
the rest of the code never accepts such paths as request parameters.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


@dataclass(frozen=True)
class Settings:
    database_dsn: str | None
    attachment_dir: Path
    raw_dir: Path
    max_upload_bytes: int
    file_mode: int
    # Batch (ZIP) import caps. The compressed archive is capped by
    # max_batch_bytes; expanded total and member count are enforced by
    # app.batch. Each member must also fit the single-message cap
    # (max_upload_bytes).
    max_batch_bytes: int = 100 * 1024 * 1024
    max_batch_expanded_bytes: int = 250 * 1024 * 1024
    max_batch_files: int = 1000

    @staticmethod
    def load() -> "Settings":
        attachment_dir = Path(_env("EMLARCH_ATTACHMENT_DIR", "./data/attachments")).resolve()
        raw_dir = Path(_env("EMLARCH_RAW_DIR", "./data/raw")).resolve()
        mode_s = _env("EMLARCH_FILE_MODE", "0o600")
        try:
            file_mode = int(mode_s, 0)
        except ValueError:
            file_mode = 0o600
        return Settings(
            database_dsn=_env("EMLARCH_DATABASE_DSN"),
            attachment_dir=attachment_dir,
            raw_dir=raw_dir,
            max_upload_bytes=int(_env("EMLARCH_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024))),
            file_mode=file_mode,
            max_batch_bytes=int(_env("EMLARCH_MAX_BATCH_BYTES", str(100 * 1024 * 1024))),
            max_batch_expanded_bytes=int(
                _env("EMLARCH_MAX_BATCH_EXPANDED_BYTES", str(250 * 1024 * 1024))
            ),
            max_batch_files=int(_env("EMLARCH_MAX_BATCH_FILES", "1000")),
        )


def get_settings() -> Settings:
    return Settings.load()
