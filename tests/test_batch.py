"""Batch (ZIP) import tests: per-member traceability, bombs, traversal."""
from __future__ import annotations

import io
import os
import stat
import struct
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from conftest import SAMPLES


def _make_zip(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _post_batch(client, data: bytes, name: str = "bundle.zip"):
    return client.post("/ingest/batch", files={"file": (name, data, "application/zip")})


@pytest.fixture
def make_client(tmp_path):
    """Build a client with overridden settings (caps etc.)."""

    def _make(**overrides):
        base = dict(
            database_dsn=None,
            attachment_dir=(tmp_path / "attachments").resolve(),
            raw_dir=(tmp_path / "raw").resolve(),
            max_upload_bytes=10 * 1024 * 1024,
            file_mode=0o600,
        )
        base.update(overrides)
        app = create_app(Settings(**base))
        return TestClient(app)

    return _make


def test_batch_mixed_archive_is_traceable_per_member(client):
    c, arch = client
    ok_bytes = (SAMPLES / "01_multibyte.eml").read_bytes()
    corrupt_bytes = (SAMPLES / "06_corrupt_boundary.eml").read_bytes()
    archive = _make_zip(
        [
            ("folder/", b""),  # directory entry: not reported, counted
            ("folder/01_multibyte.eml", ok_bytes),
            ("06_corrupt_boundary.eml", corrupt_bytes),
            ("dup/01_copy.eml", ok_bytes),  # duplicate raw content
            ("notes.txt", b"read me"),  # not an .eml -> skipped
        ]
    )
    r = _post_batch(c, archive)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["archive_name"] == "bundle.zip"
    assert body["archive_size"] == len(archive)
    assert body["members_total"] == 5  # directory entry included
    assert (body["ok"], body["defective"], body["failed"]) == (2, 1, 0)
    assert body["skipped"] == 1 and body["rejected"] == 0

    entries = body["entries"]
    assert [e["name"] for e in entries] == [
        "folder/01_multibyte.eml",
        "06_corrupt_boundary.eml",
        "dup/01_copy.eml",
        "notes.txt",
    ]
    by_name = {e["name"]: e for e in entries}

    first = by_name["folder/01_multibyte.eml"]
    assert first["status"] == "ok" and first["ingest_id"] and first["message_pk"]
    defect = by_name["06_corrupt_boundary.eml"]
    assert defect["status"] == "defective" and defect["defects_count"] > 0
    dupe = by_name["dup/01_copy.eml"]
    # duplicate raw bytes: same digest, distinct ingest rows — both traceable
    assert dupe["raw_sha256"] == first["raw_sha256"]
    assert dupe["ingest_id"] != first["ingest_id"]
    skipped = by_name["notes.txt"]
    assert skipped["status"] == "skipped" and skipped["ingest_id"] is None

    # provenance: ingest rows name the archive *and* the in-archive path
    detail = c.get(f"/ingests/{first['ingest_id']}").json()
    assert detail["source_name"] == "bundle.zip::folder/01_multibyte.eml"
    assert detail["raw_sha256"] == first["raw_sha256"]
    defect_detail = c.get(f"/ingests/{defect['ingest_id']}").json()
    assert defect_detail["status"] == "defective" and defect_detail["defects"]

    # batch triggered one thread rebuild; report is attached to the response
    assert "duplicate_ids" in body["threads"]

    # single-message flows still work on batch-imported mail: search + download
    hits = c.get("/search", params={"q": "multi-01@example.com"}).json()
    assert hits["count"] == 2  # original + duplicate copy
    msg = c.get(f"/messages/{first['message_pk']}").json()
    att = next(a for a in msg["attachments"] if a["stored"])
    dl = c.get(f"/messages/{first['message_pk']}/attachments/{att['id']}/download")
    assert dl.status_code == 200 and dl.content


def test_batch_traversal_entries_rejected_and_nothing_escapes(client, tmp_path):
    c, arch = client
    good = (SAMPLES / "03_missing_id.eml").read_bytes()
    archive = _make_zip(
        [
            ("../evil.eml", good),
            ("sub/../../escape.eml", good),
            ("..\\windows\\temp\\x.eml", good),
            ("/abs/path.eml", good),
            ("C:/drive.eml", good),
            ("ok/good.eml", good),
        ]
    )
    r = _post_batch(c, archive)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["rejected"] == 5
    assert body["defective"] == 1  # 03_missing_id parses with defects
    for entry in body["entries"]:
        if entry["name"] == "ok/good.eml":
            assert entry["status"] == "defective" and entry["ingest_id"]
        else:
            assert entry["status"] == "rejected"
            assert "unsafe archive path" in entry["error"]
            assert entry["ingest_id"] is None

    # every file on disk lives under one of the two controlled roots
    raw_root = arch.settings.raw_dir
    att_root = arch.settings.attachment_dir
    for path in Path(tmp_path).rglob("*"):
        if path.is_file():
            resolved = path.resolve()
            assert resolved.is_relative_to(raw_root) or resolved.is_relative_to(att_root), path


def test_batch_declared_bomb_rejected_before_any_ingest(make_client):
    c = make_client(max_batch_expanded_bytes=1024 * 1024)
    bomb = _make_zip([("zeros.eml", b"\x00" * (2 * 1024 * 1024))])  # ~2KB compressed
    assert len(bomb) < 100 * 1024
    r = _post_batch(c, bomb)
    assert r.status_code == 413
    assert "expanded" in r.json()["detail"]
    # nothing was imported
    assert c.get("/messages").json() == []
    assert c.get("/failures").json() == []


def test_batch_forged_size_member_is_contained(make_client):
    """A central directory lying about the uncompressed size cannot cause an
    unbounded inflate: the stdlib truncates at the declared size, the CRC
    check then fails, and the member is reported failed — the rest of the
    batch is still imported."""
    c = make_client(max_batch_expanded_bytes=1000)
    good = (SAMPLES / "03_missing_id.eml").read_bytes()
    archive = bytearray(_make_zip([("forged.eml", b"A" * 5000), ("good.eml", good)]))
    cd = archive.find(b"PK\x01\x02")
    assert cd != -1
    struct.pack_into("<I", archive, cd + 24, 10)  # claim 10 bytes uncompressed
    r = _post_batch(c, bytes(archive))
    assert r.status_code == 201
    body = r.json()
    by_name = {e["name"]: e for e in body["entries"]}
    assert by_name["forged.eml"]["status"] == "failed"
    assert by_name["forged.eml"]["ingest_id"] is None
    assert by_name["good.eml"]["ingest_id"] is not None


def test_batch_too_many_members_rejected(make_client):
    c = make_client(max_batch_files=2)
    eml = (SAMPLES / "03_missing_id.eml").read_bytes()
    archive = _make_zip([("a.eml", eml), ("b.eml", eml), ("c.eml", eml)])
    r = _post_batch(c, archive)
    assert r.status_code == 413
    assert "limit is 2" in r.json()["detail"]
    assert c.get("/messages").json() == []


def test_batch_per_member_size_cap_rejects_only_that_member(make_client):
    c = make_client(max_upload_bytes=2048)
    small = (SAMPLES / "03_missing_id.eml").read_bytes()
    assert len(small) <= 2048
    big = b"Subject: too big\r\n\r\n" + b"x" * 4096
    archive = _make_zip([("big.eml", big), ("small.eml", small)])
    body = _post_batch(c, archive).json()
    by_name = {e["name"]: e for e in body["entries"]}
    assert by_name["big.eml"]["status"] == "rejected"
    assert "per-message cap" in by_name["big.eml"]["error"]
    assert by_name["small.eml"]["ingest_id"] is not None


def test_batch_compressed_upload_cap(make_client):
    c = make_client(max_batch_bytes=4096)
    # incompressible payload so the *compressed* archive exceeds the cap
    archive = _make_zip([("a.eml", os.urandom(60000))])
    assert len(archive) > 4096
    r = _post_batch(c, archive)
    assert r.status_code == 413
    assert c.get("/messages").json() == []


def test_batch_not_a_zip_rejected(client):
    c, _ = client
    r = _post_batch(c, b"this is not a zip archive at all")
    assert r.status_code == 422


def test_batch_empty_upload_rejected(client):
    c, _ = client
    r = _post_batch(c, b"")
    assert r.status_code == 422


def test_batch_garbage_member_fails_but_others_import(client):
    c, _ = client
    good = (SAMPLES / "05_same_subject_root.eml").read_bytes()
    archive = _make_zip(
        [
            ("garbage.eml", b"\x00\xff\xfe not an email " * 50),
            ("good.eml", good),
        ]
    )
    body = _post_batch(c, archive).json()
    by_name = {e["name"]: e for e in body["entries"]}
    bad = by_name["garbage.eml"]
    assert bad["status"] in ("defective", "failed")
    assert bad["ingest_id"] is not None  # failure is locatable via ingest row
    assert by_name["good.eml"]["status"] == "ok"
    # the good message is searchable afterwards
    assert c.get("/search", params={"q": "Quarterly"}).json()["count"] == 1


def test_batch_policy_entries_skipped_or_rejected(client):
    c, _ = client
    good = (SAMPLES / "03_missing_id.eml").read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        link = zipfile.ZipInfo("link.eml")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(link, b"/etc/passwd")
        zf.writestr("empty.eml", b"")
        zf.writestr("UPPER.EML", good)  # extension match is case-insensitive
    body = _post_batch(c, buf.getvalue()).json()
    by_name = {e["name"]: e for e in body["entries"]}
    assert by_name["link.eml"]["status"] == "skipped"
    assert by_name["empty.eml"]["status"] == "rejected"
    assert by_name["UPPER.EML"]["status"] == "defective"


def test_batch_encrypted_member_rejected(client):
    c, _ = client
    good = (SAMPLES / "03_missing_id.eml").read_bytes()
    archive = bytearray(_make_zip([("secret.eml", good), ("plain.eml", good)]))
    cd = archive.find(b"PK\x01\x02")  # first central header == secret.eml
    assert cd != -1
    struct.pack_into("<H", archive, cd + 8, 0x1)  # set the encrypted flag bit
    body = _post_batch(c, bytes(archive)).json()
    by_name = {e["name"]: e for e in body["entries"]}
    assert by_name["secret.eml"]["status"] == "rejected"
    assert "encrypted" in by_name["secret.eml"]["error"]
    assert by_name["plain.eml"]["status"] == "defective"
