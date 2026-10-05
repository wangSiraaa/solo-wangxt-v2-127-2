"""Controlled batch import of ``.eml`` files from an offline ZIP package.

Security guarantees mirror the single-message upload path:

* The archive itself is bounded by an upload cap before this module runs;
  here the **expanded** total and the member count are capped as well, so
  decompression bombs are rejected from central-directory metadata *before*
  anything is inflated — and again with hard runtime caps while reading.
* Members are decompressed **in memory only**. Nothing is ever extracted to
  the filesystem, so an in-archive path cannot write outside the storage
  roots; the path is kept purely as a provenance label in the report.
  Absolute paths, drive-letter/UNC names and ``..`` traversal entries are
  rejected outright.
* Only plain (regular-file, unencrypted) ``.eml`` members are accepted.
  Everything else is reported as skipped/rejected, never silently dropped.
* One bad member never aborts the batch: per-member failures are reported
  with their archive path and the remaining messages are still imported.
"""
from __future__ import annotations

import io
import logging
import re
import stat
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass

log = logging.getLogger("emlarchive.batch")

_READ_CHUNK = 1024 * 1024
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class BatchArchiveError(Exception):
    """The archive as a whole is unacceptable; nothing is imported."""


class BatchFormatError(BatchArchiveError):
    """Not a readable ZIP archive."""


class BatchLimitError(BatchArchiveError):
    """Archive-level resource cap exceeded (members / expanded bytes)."""


class MemberReadError(Exception):
    """A single member could not be decompressed; the batch continues."""


@dataclass(frozen=True)
class BatchLimits:
    max_files: int  # max archive entries *and* max accepted .eml members
    max_expanded_bytes: int  # sum of uncompressed bytes over all .eml members
    max_member_bytes: int  # per-message uncompressed cap


@dataclass
class EmlMember:
    """One accepted ``.eml`` member, decompressed under the caps."""

    name: str  # in-archive path — a report label, never a filesystem path
    data: bytes


@dataclass
class MemberRejection:
    """A member the batch policy refused (reported, not imported)."""

    name: str
    status: str  # "rejected" | "skipped" | "failed"
    reason: str
    declared_size: int | None = None


def log_safe_name(name: str) -> str:
    """Neutralize control chars so an archive name cannot forge log lines."""
    return _CONTROL_CHARS.sub("?", name)


def unsafe_archive_name(name: str) -> str | None:
    """Return why an in-archive path is unsafe, or ``None`` if it is benign.

    The name is only ever used as a report label (members are inflated in
    memory, never extracted), but rejecting hostile names here keeps the
    provenance log trustworthy and documents the rejection to the archivist.
    """
    if not name or "\x00" in name:
        return "empty or NUL-containing name"
    norm = name.replace("\\", "/")
    if norm.startswith("/"):
        return "absolute path"
    if _DRIVE_RE.match(norm):
        return "drive-letter path"
    parts = [p for p in norm.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return "parent-directory traversal"
    return None


def _read_member_bounded(zf: zipfile.ZipFile, info: zipfile.ZipInfo, cap: int) -> bytes:
    """Inflate one member with a hard byte cap, regardless of declared size."""
    try:
        with zf.open(info) as fh:
            buf = bytearray()
            while True:
                chunk = fh.read(_READ_CHUNK)
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > cap:
                    raise MemberReadError(
                        f"decompressed data exceeds per-message cap of {cap} bytes"
                    )
    except MemberReadError:
        raise
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, zlib.error) as exc:
        raise MemberReadError(f"cannot decompress member: {exc}") from exc
    return bytes(buf)


class ArchivePlan:
    """An inspected ZIP archive ready for capped, in-order member iteration.

    Construction runs the metadata pre-flight (nothing inflated yet) and
    raises :class:`BatchArchiveError` if the archive as a whole is
    unacceptable. Iterating inflates one member at a time under runtime caps.
    """

    def __init__(self, archive: bytes, limits: BatchLimits) -> None:
        try:
            self._zf = zipfile.ZipFile(io.BytesIO(archive))
            self._infos = self._zf.infolist()
        except zipfile.BadZipFile as exc:
            raise BatchFormatError(f"not a ZIP archive: {exc}") from exc
        self._limits = limits
        try:
            self._decisions = self._preflight(limits)
        except Exception:
            self._zf.close()
            raise

    def __enter__(self) -> "ArchivePlan":
        return self

    def __exit__(self, *exc: object) -> None:
        self._zf.close()

    @property
    def members_total(self) -> int:
        """Every entry in the archive, including directory entries."""
        return len(self._infos)

    def _preflight(self, limits: BatchLimits) -> list[MemberRejection | None]:
        if len(self._infos) > limits.max_files:
            raise BatchLimitError(
                f"archive holds {len(self._infos)} entries; limit is {limits.max_files}"
            )
        decisions: list[MemberRejection | None] = []
        candidates = 0
        expanded_declared = 0
        for info in self._infos:
            decision: MemberRejection | None = None
            if info.is_dir():
                decisions.append(None)  # directory entries carry no content
                continue
            mode = info.external_attr >> 16
            # Type bits are often absent (0) in cross-platform zips; only an
            # explicitly non-regular type (symlink, fifo, ...) is skipped.
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                decision = MemberRejection(info.filename, "skipped", "not a regular file", info.file_size)
            else:
                reason = unsafe_archive_name(info.filename)
                if reason is not None:
                    decision = MemberRejection(
                        info.filename, "rejected", f"unsafe archive path: {reason}", info.file_size
                    )
                elif not info.filename.lower().endswith(".eml"):
                    decision = MemberRejection(info.filename, "skipped", "not an .eml file", info.file_size)
                elif info.flag_bits & 0x1:
                    decision = MemberRejection(
                        info.filename, "rejected", "encrypted members are not supported", info.file_size
                    )
                elif info.file_size <= 0:
                    decision = MemberRejection(info.filename, "rejected", "empty member", info.file_size)
                elif info.file_size > limits.max_member_bytes:
                    decision = MemberRejection(
                        info.filename,
                        "rejected",
                        f"member exceeds per-message cap of {limits.max_member_bytes} bytes",
                        info.file_size,
                    )
                else:
                    candidates += 1
                    expanded_declared += info.file_size
            decisions.append(decision)

        if candidates > limits.max_files:
            raise BatchLimitError(
                f"archive holds {candidates} .eml members; limit is {limits.max_files}"
            )
        if expanded_declared > limits.max_expanded_bytes:
            raise BatchLimitError(
                f"declared expanded size {expanded_declared} bytes exceeds "
                f"limit of {limits.max_expanded_bytes}"
            )
        return decisions

    def __iter__(self) -> Iterator[EmlMember | MemberRejection]:
        # Declared sizes are metadata, so reads are still bounded at runtime
        # (per member and cumulatively) as defense in depth.
        read_total = 0
        for info, decision in zip(self._infos, self._decisions):
            if decision is not None:
                yield decision
                continue
            if info.is_dir():
                continue
            try:
                data = _read_member_bounded(self._zf, info, self._limits.max_member_bytes)
            except MemberReadError as exc:
                yield MemberRejection(info.filename, "failed", str(exc), info.file_size)
                continue
            read_total += len(data)
            if read_total > self._limits.max_expanded_bytes:
                raise BatchLimitError(
                    "expanded bytes exceeded limit while reading the archive"
                )
            yield EmlMember(info.filename, data)
