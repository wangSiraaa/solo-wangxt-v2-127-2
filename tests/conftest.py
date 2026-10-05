"""Shared test fixtures: memory-backed and (optional) PostgreSQL-backed app."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

PG_DSN = os.environ.get(
    "EMLARCH_TEST_DSN",
    "postgresql://postgres@/postgres?host=/tmp/pgsock&port=55432",
)


def _settings(tmp_path: Path, dsn: str | None, **overrides) -> Settings:
    defaults = dict(
        database_dsn=dsn,
        attachment_dir=(tmp_path / "attachments").resolve(),
        raw_dir=(tmp_path / "raw").resolve(),
        max_upload_bytes=10 * 1024 * 1024,
        file_mode=0o600,
        zip_max_upload_bytes=10 * 1024 * 1024,
        zip_max_entries=200,
        zip_max_eml=100,
        zip_max_total_bytes=2 * 1024 * 1024,
        zip_max_member_bytes=1024 * 1024,
        zip_max_compression_ratio=20,
    )
    defaults.update(overrides)
    return Settings(**defaults)


@pytest.fixture
def client(tmp_path):
    app = create_app(_settings(tmp_path, None))
    with TestClient(app) as c:
        yield c, app.state.arch


@pytest.fixture
def pg_dsn():
    if not os.environ.get("EMLARCH_RUN_PG_TESTS"):
        pytest.skip("set EMLARCH_RUN_PG_TESTS=1 to run PostgreSQL integration tests")
    try:
        import psycopg

        with psycopg.connect(PG_DSN) as conn:
            conn.execute("select 1")
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"PostgreSQL not reachable at {PG_DSN}: {exc}")
    # isolate each test run in its own schema
    import uuid

    schema = f"t_{uuid.uuid4().hex[:12]}"
    dsn = f"{PG_DSN}&options=-csearch_path%3D{schema}" if "?" in PG_DSN else f"{PG_DSN}?options=-csearch_path={schema}"
    import psycopg

    with psycopg.connect(PG_DSN, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
    yield dsn
    with psycopg.connect(PG_DSN, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA {schema} CASCADE")


@pytest.fixture
def pg_client(tmp_path, pg_dsn):
    app = create_app(_settings(tmp_path, pg_dsn))
    with TestClient(app) as c:
        yield c, app.state.arch
