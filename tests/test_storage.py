import logging
from pathlib import Path

import pytest

from app.storage import ControlledStorage, StorageError, safe_basename


@pytest.mark.parametrize(
    "hostile,expected",
    [
        ("../../etc/passwd", "passwd"),  # directory traversal collapses to safe leaf
        ("/etc/cron.d/pwned", "pwned"),
        ("..\\..\\windows\\system32\\x.dll", "x.dll"),
        ("\\\\server\\share\\f.txt", "f.txt"),
        ("normal report.pdf", "normal report.pdf"),
        ("a/b/c.bin", "c.bin"),
        ("..", ""),
        (".", ""),
        ("", ""),
        ("with\x00nul.txt", "with_nul.txt"),
        ("C:\\Windows\\win.ini", "win.ini"),
        ("foo..bar", "foo__bar"),
    ],
)
def test_safe_basename(hostile, expected):
    assert safe_basename(hostile) == expected


def test_stored_file_stays_inside_root(tmp_path):
    store = ControlledStorage(tmp_path / "root")
    payload = b"PAYLOAD-BYTES"
    rel = store.store_attachment(payload, "a" * 64, "../../../../etc/passwd")
    dest = store.resolve(rel)
    assert str(dest).startswith(str(store.root))
    assert dest.read_bytes() == payload
    # nothing was written outside
    assert not Path("/etc/passwd.local-copy").exists()


def test_resolve_rejects_traversal(tmp_path):
    store = ControlledStorage(tmp_path / "root")
    for evil in ("../x", "../../etc/passwd", "/etc/passwd", "\\..\\x", ""):
        with pytest.raises(StorageError):
            store.resolve(evil)


def test_file_mode_is_restrictive(tmp_path):
    store = ControlledStorage(tmp_path / "root", file_mode=0o600)
    rel = store.store_attachment(b"x", "b" * 64, "f.txt")
    mode = (store.root / rel).stat().st_mode & 0o777
    assert mode == 0o600


def test_content_dedup(tmp_path):
    store = ControlledStorage(tmp_path / "root")
    r1 = store.store_attachment(b"same", "c" * 64, "one.txt")
    r2 = store.store_attachment(b"same", "c" * 64, "one.txt")
    assert r1 == r2  # identical content+name shares one file


def test_attachment_bytes_never_logged(tmp_path, caplog):
    store = ControlledStorage(tmp_path / "root")
    secret = b"SECRET-ATTACHMENT-CONTENT-XYZ"
    with caplog.at_level(logging.INFO, logger="emlarchive.storage"):
        store.store_attachment(secret, "d" * 64, "doc.bin")
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert "SECRET-ATTACHMENT-CONTENT-XYZ" not in blob
    assert "doc.bin" in blob  # metadata is fine
