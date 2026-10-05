"""End-to-end checks against the real PostgreSQL schema/SQL.

These run only when EMLARCH_RUN_PG_TESTS=1 and the test DSN is reachable.
They re-ingest representative samples and exercise SQL that has no in-memory
equivalent (JSONB aggregates, LATERAL identifier rollups, ILIKE joins).
"""
import io
import zipfile

import pytest

from conftest import SAMPLES

pytestmark = pytest.mark.pg


def _post(c, name, **params):
    data = (SAMPLES / name).read_bytes()
    return c.post(
        "/ingest",
        files={"file": (name, data, "message/rfc822")},
        params=params,
    )


def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in files.items():
            zf.writestr(name, payload)
    return buf.getvalue()


def test_health_reports_pg(pg_client):
    c, _ = pg_client
    assert c.get("/health").json()["backend"] == "postgresql"


def test_schema_persists_nested_multipart(pg_client):
    c, _ = pg_client
    r = _post(c, "01_multibyte.eml")
    assert r.status_code == 201, r.text
    pk = r.json()["message_pk"]
    msg = c.get(f"/messages/{pk}").json()
    assert msg["message_id"] == "multi-01@example.com"
    assert msg["tree_json"]["content_type"] == "multipart/mixed"
    # all four textual parts (incl. embedded message/rfc822 body)
    ctypes = sorted(b["content_type"] for b in msg["bodies"])
    assert ctypes.count("text/plain") == 3
    assert "text/html" in ctypes
    # binary attachments: inline gif + pdf
    atts = {(a["mime_path"], a["stored"]) for a in msg["attachments"]}
    assert ("1.3.2", True) in atts
    assert ("3", True) in atts
    # provenance: ingest id links raw digest to parsed result
    ing = c.get(f"/ingests/{msg['ingest_id']}").json()
    assert ing["raw_sha256"] == msg["raw_sha256"]


def test_failed_and_defective_rows_queryable(pg_client):
    c, _ = pg_client
    _post(c, "06_corrupt_boundary.eml")
    _post(c, "03_missing_id.eml")
    fails = c.get("/failures").json()
    assert len(fails) == 2
    # defect stages are populated for location
    assert all(d["stage"] for f in fails for d in f["defects"])


def test_threading_sql_roundtrip(pg_client):
    c, _ = pg_client
    for n in ["02_cycle_a.eml", "02_cycle_b.eml", "04_duplicate_id_a.eml",
              "04_duplicate_id_b.eml", "05_same_subject_root.eml",
              "05_same_subject_other.eml", "01_multibyte.eml"]:
        _post(c, n, recompute_threads=False)
    rebuilt = c.post("/threads/rebuild").json()
    assert rebuilt["threads"] >= 4
    assert any({"cycle-a@example.com", "cycle-b@example.com"} <= set(cyc)
               for cyc in rebuilt["cycles"])
    assert "dup-1@example.com" in rebuilt["duplicate_ids"]
    assert any(w["reason"] == "subject_match_only" for w in rebuilt["weak_suggestions"])

    # thread detail via LATERAL identifier rollup
    threads = c.get("/threads").json()
    cycle_thread = next(t for t in threads if t["message_count"] == 2)
    detail = c.get(f"/threads/{cycle_thread['thread_key']}").json()
    assert len(detail["messages"]) == 2
    # multibyte message is in parent-root thread, with refs rollups present
    multi = c.get("/search", params={"q": "multi-01"}).json()["results"][0]
    md = c.get(f"/messages/{multi['id']}").json()
    assert md["thread_key"]


def test_search_sql_joins(pg_client):
    c, _ = pg_client
    _post(c, "01_multibyte.eml")
    _post(c, "09_html_xss.eml")
    assert c.get("/search", params={"q": "GB18030"}).json()["count"] == 1
    assert c.get("/search", params={"q": "café"}).json()["count"] >= 1
    # header value search (From)
    assert c.get("/search", params={"q": "sigs@example.com"}).json()["count"] == 1
    assert c.get("/search", params={"q": "nothing-matches-zzz"}).json()["count"] == 0


def test_idempotent_schema_init(pg_client):
    c, arch = pg_client
    # creating a second repository over the same DSN must not error on DDL
    arch.repo.init_schema()
    assert c.get("/health").status_code == 200


def test_batch_zip_roundtrip_and_denials_pg(pg_client):
    c, _ = pg_client
    good = (SAMPLES / "01_multibyte.eml").read_bytes()
    broken = (SAMPLES / "06_corrupt_boundary.eml").read_bytes()
    pkg = _zip({"incoming/good.eml": good, "incoming/broken.eml": broken,
                "incoming/dup.eml": good})
    r = c.post(
        "/ingest/batch",
        files={"file": ("bundle.zip", pkg, "application/zip")},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ingested"] == 3 and body["rejected"] == 0

    # each item is traceable through the real ingests table
    for item in body["items"]:
        detail = c.get(f"/ingests/{item['ingest_id']}").json()
        assert detail["source_name"].endswith(item["path"])
        assert detail["raw_sha256"] == item["raw_sha256"]

    # search and attachment download still work after batch import
    assert c.get("/search", params={"q": "multi-01"}).json()["count"] == 2
    pk = body["items"][0]["message_pk"]
    meta = c.get(f"/messages/{pk}").json()["attachments"]
    pdf = next(a for a in meta if a["content_type"] == "application/pdf")
    dl = c.get(f"/messages/{pk}/attachments/{pdf['id']}/download")
    assert dl.status_code == 200 and dl.content.startswith(b"%PDF")

    # traversal rejected before persistence against the real backend too
    evil = _zip({"../escape.eml": good})
    denied = c.post(
        "/ingest/batch",
        files={"file": ("evil.zip", evil, "application/zip")},
    )
    assert denied.status_code == 422
