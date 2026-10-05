"""Controlled ZIP batch import: /ingest/batch."""
from __future__ import annotations

import io
import zipfile

import pytest

from conftest import SAMPLES

from app.batch import BundleLimits, plan_zip, safe_member_path
from app.config import Settings
from app.main import create_app
from fastapi.testclient import TestClient

GOOD = (SAMPLES / "01_multibyte.eml").read_bytes()
CORRUPT = (SAMPLES / "06_corrupt_boundary.eml").read_bytes()
GARBAGE = b"\x00\xff\xfe not an email " * 50


def make_zip(entries: dict[str, bytes], *, compress=zipfile.ZIP_DEFLATED, raw_infos=None) -> bytes:
    """Build an in-memory ZIP. entries: archive path -> bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload, compress_type=compress)
        for info, payload in raw_infos or []:
            zf.writestr(info, payload)
    return buf.getvalue()


def _post_batch(client, data, name="bundle.zip", **params):
    return client.post(
        "/ingest/batch",
        files={"file": (name, data, "application/zip")},
        params=params,
    )


# ---------------------------------------------------------------- outcomes
def test_batch_mixed_package_each_item_traceable(client):
    """Normal, defective-boundary and duplicate-raw members all land separately."""
    c, arch = client
    pkg = make_zip(
        {
            "ok/01_multibyte.eml": GOOD,
            "broken/06_corrupt_boundary.eml": CORRUPT,
            "dup/again.eml": GOOD,  # identical raw bytes -> same digest, new ingest
            "junk.eml": GARBAGE,
        }
    )
    r = _post_batch(c, pkg)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 4
    assert body["ingested"] == 4  # defective/failed parse still creates an ingest row
    assert body["rejected"] == 0 and body["errors"] == 0

    by_path = {item["path"]: item for item in body["items"]}
    good = by_path["ok/01_multibyte.eml"]
    broken = by_path["broken/06_corrupt_boundary.eml"]
    dup = by_path["dup/again.eml"]

    assert good["status"] == "ok" and good["ingest_id"] and good["message_pk"]
    assert broken["status"] == "defective" and broken["defects_count"] >= 1
    # same raw content ...
    assert dup["raw_sha256"] == good["raw_sha256"]
    # ... but distinct, independently traceable ingest ids/message rows
    assert dup["ingest_id"] != good["ingest_id"]
    assert dup["message_pk"] != good["message_pk"]

    # provenance: every ingest id resolves and carries the package!path source
    for item in body["items"]:
        detail = c.get(f"/ingests/{item['ingest_id']}").json()
        assert detail["id"] == item["ingest_id"]
        assert detail["source_name"].endswith(item["path"])
        assert detail["raw_sha256"] == item["raw_sha256"]

    # threads rebuilt once over the package (duplicate Message-IDs conflict)
    assert body["threads"]["messages"] >= 3
    dup_ids = body["threads"]["duplicate_ids"]
    assert "multi-01@example.com" in dup_ids


def test_batch_single_member_failure_keeps_others(client):
    """An oversize member is rejected; the other member still ingests."""
    c, _ = client
    # > 1 MiB member cap but still under the 2 MiB package-total cap.
    big = b"Subject: big\r\n\r\n" + b"x" * (1100 * 1024)
    pkg = make_zip({"small.eml": GOOD, "toobig.eml": big}, compress=zipfile.ZIP_STORED)
    r = _post_batch(c, pkg)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ingested"] == 1 and body["rejected"] == 1
    rejected = next(i for i in body["items"] if i["outcome"] == "rejected")
    assert rejected["path"] == "toobig.eml"
    assert rejected["ingest_id"] is None
    assert "limit" in rejected["error"]
    kept = next(i for i in body["items"] if i["outcome"] == "ingested")
    assert kept["path"] == "small.eml"

    # the failed member left no ingest row; the good one is traceable
    fails = c.get("/failures").json()
    assert all(f["source_name"] != "bundle.zip!toobig.eml" for f in fails)
    assert c.get(f"/ingests/{kept['ingest_id']}").status_code == 200


def test_batch_empty_member_rejected_not_fatal(client):
    c, _ = client
    pkg = make_zip({"empty.eml": b"", "real.eml": GOOD})
    body = _post_batch(c, pkg).json()
    assert body["ingested"] == 1 and body["rejected"] == 1
    empty = next(i for i in body["items"] if i["path"] == "empty.eml")
    assert empty["outcome"] == "rejected" and "empty" in empty["error"]


# ----------------------------------------------------------------- denial
def test_batch_path_traversal_rejected(client):
    c, _ = client
    for evil in ("../escape.eml", "a/../../b.eml", "/abs.eml", "..\\win.eml",
                 "C:\\drive.eml", "a/./../x.eml", "nul\x00.eml", "a//../b.eml"):
        pkg = make_zip({evil: GOOD})
        r = _post_batch(c, pkg)
        assert r.status_code == 422, (evil, r.status_code, r.text)
        assert r.json()["detail"]  # reason surfaced
    # nothing was ingested from the rejected packages
    assert c.get("/messages", params={"limit": 1}).json() == []


def test_batch_non_eml_member_rejects_whole_package(client):
    c, _ = client
    pkg = make_zip({"mail.eml": GOOD, "notes.txt": b"not mail"})
    r = _post_batch(c, pkg)
    assert r.status_code == 422
    assert "not a .eml" in r.json()["detail"]
    assert c.get("/messages", params={"limit": 1}).json() == []


def test_batch_directory_entries_are_allowed(client):
    """Structural dir entries are skipped; only regular files count."""
    c, _ = client
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("docs/", b"")
        zf.writestr("docs/mail.eml", GOOD)
    r = _post_batch(c, buf.getvalue())
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 1


def test_batch_not_a_zip(client):
    c, _ = client
    r = _post_batch(c, b"this is definitely not a zip file")
    assert r.status_code == 422
    assert "zip" in r.json()["detail"].lower()


def test_batch_missing_field_and_empty(client):
    c, _ = client
    assert c.post("/ingest/batch").status_code == 422
    r = _post_batch(c, b"")
    assert r.status_code == 422


def test_batch_archive_upload_cap(tmp_path):
    settings = Settings(
        database_dsn=None,
        attachment_dir=(tmp_path / "att").resolve(),
        raw_dir=(tmp_path / "raw").resolve(),
        max_upload_bytes=10 * 1024 * 1024,
        file_mode=0o600,
        zip_max_upload_bytes=1024,
        zip_max_entries=200,
        zip_max_eml=100,
        zip_max_total_bytes=10 * 1024 * 1024,
        zip_max_member_bytes=1024 * 1024,
        zip_max_compression_ratio=20,
    )
    app = create_app(settings)
    with TestClient(app) as c:
        pkg = make_zip({"x.eml": GOOD})
        r = c.post(
            "/ingest/batch",
            files={"file": ("bundle.zip", pkg, "application/zip")},
        )
        assert r.status_code == 413


def test_batch_declared_zip_bomb_rejected(tmp_path):
    """Huge declared uncompressed total (metadata-level bomb screen)."""
    settings = Settings(
        database_dsn=None,
        attachment_dir=(tmp_path / "att").resolve(),
        raw_dir=(tmp_path / "raw").resolve(),
        max_upload_bytes=50 * 1024 * 1024,
        file_mode=0o600,
        zip_max_upload_bytes=50 * 1024 * 1024,
        zip_max_entries=200,
        zip_max_eml=100,
        zip_max_total_bytes=2 * 1024 * 1024,
        zip_max_member_bytes=10 * 1024 * 1024,
        zip_max_compression_ratio=200,
    )
    app = create_app(settings)
    with TestClient(app) as c:
        # High-ratio compressible payload: ~10 MB zeros compresses tiny.
        bomb = b"Subject: bomb\r\n\r\n" + b"0" * (10 * 1024 * 1024)
        r = c.post(
            "/ingest/batch",
            files={"file": ("b.zip", make_zip({"bomb.eml": bomb}), "application/zip")},
        )
        assert r.status_code == 413
        assert "total" in r.json()["detail"].lower()


def _spoof_local_size(pkg: bytes, real_size: int, fake_size: int) -> bytes:
    """Rewrite the uncompressed-size field in a one-entry ZIP's local header.

    The central directory keeps the true size so :func:`plan_zip` passes its
    metadata screen; the local header (used by the decompressor) lies. This
    emulates a metadata-tampering bomb that only real inflation can expose.
    """
    # Local file header: sig(4) ver(2) flags(2) method(2) time(2) date(2)
    # crc(4) csize(4) usize(4) ... -> usize offset is 18.
    lfh_sig = b"PK\x03\x04"
    pos = pkg.index(lfh_sig)
    out = bytearray(pkg)
    out[pos + 18 : pos + 22] = fake_size.to_bytes(4, "little")
    return bytes(out)


def test_batch_actual_inflation_bomb_caught(client):
    """Local header lies about size; the real inflation counters must stop it."""
    c, _ = client
    payload = b"Subject: bomb\r\n\r\n" + b"0" * (1500 * 1024)  # > 1 MiB member cap
    real_pkg = make_zip({"bomb.eml": payload}, compress=zipfile.ZIP_STORED)
    spoofed = _spoof_local_size(real_pkg, len(payload), 10)
    r = _post_batch(c, spoofed)
    # Single member is skipped at inflation time, nothing ingested.
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ingested"] == 0 and body["rejected"] == 1
    item = body["items"][0]
    assert item["path"] == "bomb.eml" and item["ingest_id"] is None
    assert "limit" in item["error"]


def test_batch_corrupt_member_does_not_block_package(client):
    """A CRC-failing member is reported per item; the good member ingests."""
    c, _ = client
    pkg = bytearray(make_zip({"bad.eml": GOOD, "good.eml": GOOD}))
    # Flip a payload byte to break the CRC of the first member (past its
    # 30-byte local header + filename "bad.eml" (7)).
    pos = bytes(pkg).index(b"PK\x03\x04")
    pkg[pos + 30 + 7] ^= 0xFF
    body = _post_batch(c, bytes(pkg)).json()
    outcomes = {i["path"]: i["outcome"] for i in body["items"]}
    assert outcomes["good.eml"] == "ingested"
    assert outcomes["bad.eml"] in ("rejected", "error")


def test_batch_storage_error_on_one_member_keeps_others(client):
    """An exception while storing a member is an item error, not a failure of
    the whole package."""
    c, arch = client

    def boom(_data):
        raise RuntimeError("disk full")

    arch.raw_storage.store_raw = boom  # instance attr shadows the bound method
    try:
        r = _post_batch(c, make_zip({"a.eml": GOOD, "b.eml": GOOD}))
        assert r.status_code == 200, r.text
        body = r.json()
    finally:
        del arch.raw_storage.store_raw  # restore the class method

    assert body["total"] == 2 and body["errors"] == 2 and body["ingested"] == 0
    for item in body["items"]:
        assert item["outcome"] == "error"
        assert item["ingest_id"] is None
        assert "disk full" in item["error"]

    # a normal package ingests afterwards on the same service
    again = _post_batch(c, make_zip({"ok.eml": GOOD})).json()
    assert again["ingested"] == 1


def test_batch_duplicate_member_path_rejected(client):
    c, _ = client
    pkg = make_zip({"a.eml": GOOD, "A.EML": GOOD})  # case-insensitive collision
    r = _post_batch(c, pkg)
    assert r.status_code == 422
    assert "duplicate" in r.json()["detail"].lower()


def test_batch_symlink_member_rejected(client):
    c, _ = client
    info = zipfile.ZipInfo("link.eml")
    info.create_system = 3
    info.external_attr = (0o120777 << 16)  # S_IFLNK
    pkg = make_zip({}, raw_infos=[(info, b"targets-something")])
    r = _post_batch(c, pkg)
    assert r.status_code == 422
    assert "symlink" in r.json()["detail"].lower() or "special" in r.json()["detail"].lower()


# ------------------------------------------------------- post-batch parity
def test_batch_download_and_search_still_work(client):
    c, arch = client
    pkg = make_zip({"folder/01_multibyte.eml": GOOD})
    body = _post_batch(c, pkg).json()
    item = body["items"][0]
    pk = item["message_pk"]

    # single-message detail view
    msg = c.get(f"/messages/{pk}").json()
    assert msg["raw_sha256"] == item["raw_sha256"]
    assert arch.raw_storage.exists(msg["raw_path"])

    # search over the ingested content
    hits = c.get("/search", params={"q": "GB18030"}).json()
    assert hits["count"] == 1 and hits["results"][0]["id"] == pk

    # attachment download path re-validation still in place
    meta = c.get(f"/messages/{pk}").json()["attachments"]
    pdf = next(a for a in meta if a["content_type"] == "application/pdf")
    dl = c.get(f"/messages/{pk}/attachments/{pdf['id']}/download")
    assert dl.status_code == 200
    assert dl.content.startswith(b"%PDF")

    # and the ordinary single-message endpoint still behaves
    single = c.post(
        "/ingest",
        files={"file": ("01_multibyte.eml", GOOD, "message/rfc822")},
    )
    assert single.status_code == 201
    assert c.get("/messages", params={"limit": 10}).json() and len(
        c.get("/messages", params={"limit": 10}).json()
    ) == 2


def test_batch_recompute_threads_false_defers(client):
    c, _ = client
    body = _post_batch(c, make_zip({"m.eml": GOOD}), recompute_threads=False).json()
    assert body["threads"] == {}
    # explicit rebuild still works afterwards
    rebuilt = c.post("/threads/rebuild").json()
    assert rebuilt["messages"] == 1


def test_batch_logs_never_contain_member_bytes(client, caplog):
    import logging

    c, _ = client
    with caplog.at_level(logging.INFO):
        _post_batch(c, make_zip({"d/m.eml": GOOD}))
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "%PDF-1.4" not in text
    assert "GIF89aFAKEGIFDATA" not in text


# --------------------------------------------------------- pure validator
@pytest.mark.parametrize(
    "name",
    ["a.eml", "dir/sub/mail.eml", "a/./b.eml", "x/y/.eml", "UPPER.EML",
     "weird but ok-name.01.eml", "a//b.eml", "./relative.eml", "trail/"],
)
def test_safe_member_path_accepts(name):
    assert safe_member_path(name) is not None


@pytest.mark.parametrize(
    "name",
    ["../a.eml", "a/../b.eml", "a/../../b.eml", "/etc/a.eml", "..",
     "../", "a/..", "C:/a.eml", "C:\\a.eml", "\\\\server\\share",
     "a/\x00.eml", "a/\nb.eml", "", "..\\a.eml"],
)
def test_safe_member_path_rejects(name):
    assert safe_member_path(name) is None


def test_plan_zip_enforces_eml_count():
    from app.batch import BundleError

    pkg = make_zip({"a.eml": GOOD, "b.eml": GOOD})
    loose = BundleLimits(
        max_entries=100, max_eml=2, max_total_bytes=10**9,
        max_member_bytes=10**9, max_compression_ratio=10_000,
    )
    planned = plan_zip(pkg, loose)
    assert [m.path for m in planned] == ["a.eml", "b.eml"]

    tight = BundleLimits(
        max_entries=100, max_eml=1, max_total_bytes=10**9,
        max_member_bytes=10**9, max_compression_ratio=10_000,
    )
    with pytest.raises(BundleError) as exc:
        plan_zip(pkg, tight)
    assert exc.value.reason == "too_many_eml"


def test_plan_zip_enforces_entry_count():
    from app.batch import BundleError

    entries = {f"d{i}/": b"" for i in range(5)}
    entries["m.eml"] = GOOD
    pkg = make_zip(entries)
    limits = BundleLimits(
        max_entries=3, max_eml=10, max_total_bytes=10**9,
        max_member_bytes=10**9, max_compression_ratio=10_000,
    )
    with pytest.raises(BundleError) as exc:
        plan_zip(pkg, limits)
    assert exc.value.reason == "too_many_entries"


def test_plan_zip_metdata_size_screen():
    """Declared oversized total rejects the whole package pre-inflation."""
    from app.batch import BundleError

    limits = BundleLimits(
        max_entries=100, max_eml=10, max_total_bytes=1000,
        max_member_bytes=10**9, max_compression_ratio=10_000,
    )
    with pytest.raises(BundleError) as exc:
        plan_zip(make_zip({"a.eml": GOOD}), limits)
    assert exc.value.reason == "total_size_exceeded"
    assert exc.value.status_code == 413
