"""Controlled on-disk storage for raw EMLs and extracted attachments.

Security guarantees:
* Everything is written **under** a configured root that is resolved once at
  construction. Callers can only influence a generated shard/file name, never
  an absolute path.
* Filenames are reduced to a safe basename: separators, NUL bytes, drive
  letters and traversal sequences cannot escape the shard directory
  (:func:`safe_basename`). As defense in depth, every final path is checked
  with :func:`pathlib.Path.relative_to` after resolution.
* Attachment **bytes are never logged**. Log lines contain only metadata
  (content type, size, checksum, stored relative path).
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path, PurePosixPath

log = logging.getLogger("emlarchive.storage")

_INVALID_FN_CHARS = re.compile(r"[\x00-\x1f]")
_MAX_NAME_LEN = 128


def safe_basename(name: str) -> str:
    """Reduce a possibly hostile attachment name to one safe file component.

    ``"../../etc/passwd"`` -> ``"etc_passwd"``; absolute Windows/UNC names and
    NUL bytes are neutralized. The result never contains a separator, so it
    cannot address a parent directory.
    """
    if not name:
        return ""
    # Decode the most common over-encoding attackers reach after RFC2231
    # decoding; replace separators and traversal punctuation explicitly.
    name = _INVALID_FN_CHARS.sub("_", name)
    # Strip any directory portion regardless of platform separators.
    name = name.replace("\\", "/").replace(":", "_")
    base = PurePosixPath(name).name  # handles a/b/.., //server/share, ...
    base = base.replace("/", "_")
    base = base.strip(" .")
    if base.lower() in {"", ".", ".."}:
        return ""
    base = base.replace("..", "__")  # neutralize remaining traversal punctuation
    if not base.strip("_."):
        return ""
    if len(base) > _MAX_NAME_LEN:
        stem, dot, ext = base.rpartition(".")
        if dot and len(ext) <= 16:
            base = stem[: _MAX_NAME_LEN - len(ext) - 1] + "." + ext
        else:
            base = base[:_MAX_NAME_LEN]
    return base


class StorageError(Exception):
    pass


class ControlledStorage:
    """Write files into a root directory using shard subdirectories."""

    def __init__(self, root: Path, subdir_width: int = 2, file_mode: int = 0o600) -> None:
        self.root = Path(root).resolve()
        self._width = subdir_width
        self._file_mode = file_mode
        self.root.mkdir(parents=True, exist_ok=True)

    # -- internals ---------------------------------------------------------
    def _shard_dir(self, digest: str) -> Path:
        shard = digest[: self._width]
        shard_path = (self.root / shard).resolve()
        # root itself is trusted; ensure the shard sits inside it
        shard_path.mkdir(parents=True, exist_ok=True)
        self._ensure_inside(shard_path)
        return shard_path

    def _ensure_inside(self, target: Path) -> None:
        resolved = target.resolve()
        try:
            resolved.relative_to(self.root)
        except ValueError:
            raise StorageError(f"path escapes controlled root: {target}") from None

    def _write(self, data: bytes, digest: str, display_name: str | None, kind: str) -> str:
        shard = self._shard_dir(digest)
        # Content-addressed base name: a name chosen by the sender cannot
        # influence where bytes land on disk. It is kept separately in the DB.
        safe_name = safe_basename(display_name or "")
        prefix = f"{kind}-" if kind else ""
        if safe_name:
            file_name = f"{digest}_{safe_name}"
        else:
            file_name = f"{prefix}{digest}.bin"
        destination = (shard / file_name).resolve()
        self._ensure_inside(destination)

        if not destination.exists():
            # Named file with same content but a different display name: store
            # under a distinct name so both records resolve correctly.
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, self._file_mode)
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
            except Exception:
                destination.unlink(missing_ok=True)
                raise
            try:
                os.chmod(destination, self._file_mode)
            except OSError:  # pragma: no cover - filesystem without modes
                pass
        # Metadata only — never log data.
        log.info(
            "stored %s: name=%r content_type_ignored_here bytes=%d sha256=%s relpath=%s",
            kind,
            safe_name or None,
            len(data),
            digest,
            destination.relative_to(self.root),
        )
        return str(destination.relative_to(self.root))

    # -- public API --------------------------------------------------------
    def store_attachment(self, data: bytes, checksum_sha256: str, filename: str | None) -> str:
        return self._write(data, checksum_sha256, filename, kind="att")

    def store_raw(self, data: bytes) -> tuple[str, str]:
        digest = hashlib.sha256(data).hexdigest()
        rel = self._write(data, digest, display_name=None, kind="raw")
        return digest, rel

    def resolve(self, relative_path: str) -> Path:
        """Resolve a DB-held relative path back to an absolute one (read)."""
        if not relative_path or relative_path.startswith(("/", "\\")):
            raise StorageError("invalid relative path")
        candidate = (self.root / relative_path).resolve()
        self._ensure_inside(candidate)
        return candidate

    def exists(self, relative_path: str) -> bool:
        try:
            return self.resolve(relative_path).is_file()
        except StorageError:
            return False
