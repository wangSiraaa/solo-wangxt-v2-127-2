"""Controlled inspection of offline ZIP bundles before any member is ingested.

The archive is treated as untrusted input. Nothing here writes to disk and
member paths are **only** carried forward as report strings — they never reach
the storage layer (raw/attachment bytes are content-addressed by
:mod:`app.storage`, so a sender-chosen name cannot influence where bytes land).

Two-phase design:

1. :func:`plan_zip` reads the central directory and validates the *shape* of
   the package: it must be a readable ZIP, every entry must stay inside the
   virtual root (no ``../``, no absolute/UNC paths, no NUL/control bytes),
   only regular ``.eml`` files (and harmless directory entries) are accepted,
   and aggregate limits (entry counts, declared total size, compression
   ratio) are enforced. Any violation rejects the **whole** package before a
   single message is persisted.
2. :func:`iter_members` inflates the planned members one at a time with the
   actual byte counters enforced during decompression (central-directory
   metadata is attacker-controlled, so the limits are re-checked against real
   output and the CRC-32 is verified by stdlib at end-of-stream), yielding data
   to the per-message ingest pipeline. A member that exceeds the per-message
   or running-total cap, or fails decompression, is *skipped* (reported, not
   ingested) so the remaining messages still land.
"""
from __future__ import annotations

import io
import logging
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import PurePosixPath

log = logging.getLogger("emlarchive.batch")

# Methods stdlib can decode without third-party code.
_ALLOWED_COMPRESSIONS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}

# Inflation happens in bounded chunks; never materialize more than this at once
# beyond the (already capped) member accumulator.
_INFLATE_CHUNK = 256 * 1024


class BundleError(Exception):
    """Package-level rejection: no member may be ingested."""

    def __init__(self, reason: str, *, status_code: int = 422, detail: str | None = None) -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.status_code = status_code
        self.detail = detail or reason


@dataclass(frozen=True)
class BundleLimits:
    max_entries: int
    max_eml: int
    max_total_bytes: int
    max_member_bytes: int
    max_compression_ratio: int

    @classmethod
    def from_settings(cls, settings) -> "BundleLimits":
        return cls(
            max_entries=settings.zip_max_entries,
            max_eml=settings.zip_max_eml,
            max_total_bytes=settings.zip_max_total_bytes,
            max_member_bytes=settings.zip_max_member_bytes,
            max_compression_ratio=settings.zip_max_compression_ratio,
        )


@dataclass(frozen=True)
class PlannedMember:
    """One accepted ``.eml`` member, located by its (report-only) archive path."""

    index: int            # ordinal among regular .eml members (1-based)
    info: zipfile.ZipInfo
    path: str             # normalized POSIX path as it appears in the report
    declared_size: int    # central-directory uncompressed size (untrusted)
    compressed_size: int


def safe_member_path(raw_name: str) -> str | None:
    """Validate a ZIP member name against the virtual extraction root.

    Returns the normalized POSIX path, or ``None`` when the name attempts
    traversal, is absolute/UNC, contains NUL/control bytes, or is otherwise
    not a simple relative file path. Backslashes are accepted as (POSIX)
    separators — ZIP tooling on Windows emits them — but a Windows drive
    prefix is rejected.
    """
    if not raw_name:
        return None
    # NUL and other C0 controls are never legal in a report path (NUL would
    # also truncate downstream string handling).
    if any(ord(ch) < 32 for ch in raw_name):
        return None
    name = raw_name.replace("\\", "/")
    # Windows drive / UNC leftovers after separator normalization.
    if len(name) >= 2 and name[1] == ":":
        return None
    if name.startswith("/"):
        return None
    # PurePosixPath collapses "//" but keeps ".." components; check the raw
    # components explicitly so e.g. "a//b" is normalized and "../x" rejected.
    parts = name.split("/")
    clean: list[str] = []
    for part in parts:
        if part in ("", "."):
            # Trailing/duplicate separators and "." components are harmless in
            # a *report* path, but duplicate separators make provenance strings
            # ambiguous — normalize by dropping them.
            continue
        if part == "..":
            return None
        clean.append(part)
    if not clean:
        return None
    normalized = str(PurePosixPath(*clean))
    # Defense in depth: the resolved path must have no parent reference left.
    if ".." in PurePosixPath(normalized).parts:
        return None
    return normalized


def _is_unix_symlink(info: zipfile.ZipInfo) -> bool:
    # Unix mode lives in external_attr >> 16 when create_system == 3 (Unix).
    # Symbolic links are S_IFLNK (0o120000); they never appear as real files.
    if info.create_system != 3:
        return False
    mode = info.external_attr >> 16
    return (mode & 0o170000) == 0o120000


def _entry_kind(info: zipfile.ZipInfo) -> str:
    """Classify an entry as ``dir``, ``file`` or ``special`` (reject specials)."""
    name = info.filename.replace("\\", "/")
    if name.endswith("/"):
        return "dir"
    if _is_unix_symlink(info):
        return "special"
    if info.create_system == 3:
        mode = info.external_attr >> 16
        ftype = mode & 0o170000
        # A zero file-type field means no Unix metadata (e.g. entries written
        # by Windows tooling carry only FILE_ATTRIBUTE bits) — assume regular.
        if ftype and ftype not in (0o100000, 0o040000):
            return "special"  # fifo/socket/device/block
    return "file"


def plan_zip(data: bytes, limits: BundleLimits) -> list[PlannedMember]:
    """Validate the whole package and return its planned ``.eml`` members.

    Raises :class:`BundleError` (whole-package rejection) on any structural or
    policy violation — including a zip-bomb signature detected from the
    central-directory metadata.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data), mode="r", allowZip64=True)
    except zipfile.BadZipFile as exc:
        raise BundleError("invalid_zip", detail=f"not a valid zip archive: {exc}") from None

    with zf:
        # Force central-directory parsing; a truncated archive raises here.
        try:
            infos = zf.infolist()
        except Exception as exc:  # pragma: no cover - BadZipFile subclasses vary
            raise BundleError("invalid_zip", detail=f"unreadable central directory: {exc}") from None

        if len(infos) > limits.max_entries:
            raise BundleError(
                "too_many_entries",
                status_code=422,
                detail=f"archive has {len(infos)} entries; limit is {limits.max_entries}",
            )

        planned: list[PlannedMember] = []
        seen_paths: set[str] = set()
        declared_total = 0

        for info in infos:
            kind = _entry_kind(info)
            if kind == "special":
                raise BundleError(
                    "unsupported_entry",
                    detail=f"entry {info.filename!r} is a symlink or special file; only regular files are accepted",
                )
            if kind == "dir":
                # Validate directory names too: a "../" entry carries no bytes
                # but a traversal-shaped name should still reject the package.
                if safe_member_path(info.filename) is None:
                    raise BundleError(
                        "unsafe_path",
                        detail=f"entry path {info.filename!r} escapes the archive root or is malformed",
                    )
                continue

            path = safe_member_path(info.filename)
            if path is None:
                raise BundleError(
                    "unsafe_path",
                    detail=f"entry path {info.filename!r} escapes the archive root or is malformed",
                )
            lowered = path.lower()
            if lowered in seen_paths:
                raise BundleError(
                    "duplicate_entry",
                    detail=f"archive contains duplicate member path {path!r}",
                )
            seen_paths.add(lowered)

            if not lowered.endswith(".eml"):
                raise BundleError(
                    "non_eml_member",
                    detail=f"entry {path!r} is not a .eml file",
                )

            if info.compress_type not in _ALLOWED_COMPRESSIONS:
                raise BundleError(
                    "unsupported_compression",
                    detail=f"entry {path!r} uses an unsupported compression method {info.compress_type}",
                )
            # Traditional-flag encrypted entries can never be decoded safely;
            # reject the package rather than ingest ciphertext.
            if info.flag_bits & 0x1:
                raise BundleError(
                    "encrypted_member",
                    detail=f"entry {path!r} is encrypted; encrypted archives are not supported",
                )

            # Metadata-level bomb screen. CRC/size tampering is caught again
            # against real inflation output in iter_members().
            declared_total += info.file_size
            if declared_total > limits.max_total_bytes:
                raise BundleError(
                    "total_size_exceeded",
                    status_code=413,
                    detail=(
                        f"declared uncompressed total {declared_total} bytes exceeds limit "
                        f"of {limits.max_total_bytes} bytes"
                    ),
                )
            ratio = _declared_ratio(info)
            if ratio is not None and ratio > limits.max_compression_ratio:
                raise BundleError(
                    "compression_bomb",
                    status_code=422,
                    detail=(
                        f"entry {path!r} compresses {info.compress_size} -> {info.file_size} bytes "
                        f"(ratio {ratio}:1 > {limits.max_compression_ratio}:1)"
                    ),
                )
            planned.append(
                PlannedMember(
                    index=len(planned) + 1,
                    info=info,
                    path=path,
                    declared_size=info.file_size,
                    compressed_size=info.compress_size,
                )
            )

        # NOTE: we deliberately do NOT call ZipFile.testzip() here: it inflates
        # every member without our size caps, defeating the bomb screen. CRC
        # verification happens per member under the caps in iter_members().

    if not planned:
        raise BundleError("empty_bundle", detail="archive contains no .eml files")
    if len(planned) > limits.max_eml:
        raise BundleError(
            "too_many_eml",
            status_code=422,
            detail=f"archive contains {len(planned)} .eml files; limit is {limits.max_eml}",
        )
    return planned


def _declared_ratio(info: zipfile.ZipInfo) -> int | None:
    """Integer inflation ratio from metadata once past a noise floor."""
    # Ignore tiny entries: 10 -> 200 bytes is not a bomb even at 20:1.
    if info.file_size < 1024 * 1024 or info.compress_size == 0:
        return None
    return info.file_size // info.compress_size


def iter_members(
    data: bytes,
    planned: list[PlannedMember],
    limits: BundleLimits,
):
    """Inflate planned members lazily.

    Yields ``(member, payload_or_None, error_or_None)`` tuples in central
    directory order. ``payload is None`` with an error means the member was
    **skipped** (per-message/running cap or a decompression error): the caller
    reports it as rejected/failed and continues with the next member.
    """
    running_total = 0
    with zipfile.ZipFile(io.BytesIO(data), mode="r", allowZip64=True) as zf:
        for member in planned:
            if member.declared_size > limits.max_member_bytes:
                yield member, None, (
                    f"member declares {member.declared_size} bytes; per-message limit is "
                    f"{limits.max_member_bytes}"
                )
                continue
            if running_total + member.declared_size > limits.max_total_bytes:
                yield member, None, (
                    f"skipping member: inflated total would exceed {limits.max_total_bytes} bytes"
                )
                continue
            try:
                payload, real_size = _inflate_capped(zf, member, limits, running_total)
            except BundleError as exc:
                # Metadata lied about the size (or the stream corrupts): the
                # single member is bad, the package as already planned is fine.
                log.warning("zip member skipped path=%r: %s", member.path, exc.detail)
                yield member, None, exc.detail
                continue
            except (zipfile.BadZipFile, zlib.error, EOFError, RuntimeError) as exc:
                # CRC mismatch, truncated deflate stream, bad local header —
                # per-member failure; keep going with the rest of the package.
                detail = f"corrupt member {member.path!r}: {type(exc).__name__}: {exc}"
                log.warning("zip member skipped path=%r: %s", member.path, detail)
                yield member, None, detail
                continue
            running_total += real_size
            yield member, payload, None


def _inflate_capped(
    zf: zipfile.ZipFile,
    member: PlannedMember,
    limits: BundleLimits,
    running_total: int,
) -> tuple[bytes, int]:
    buf = bytearray()
    with zf.open(member.info, pwd=None) as fh:
        while True:
            chunk = fh.read(_INFLATE_CHUNK)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > limits.max_member_bytes:
                raise BundleError(
                    "member_size_exceeded",
                    status_code=413,
                    detail=(
                        f"member {member.path!r} exceeds per-message limit of "
                        f"{limits.max_member_bytes} bytes"
                    ),
                )
            if running_total + len(buf) > limits.max_total_bytes:
                raise BundleError(
                    "total_size_exceeded",
                    status_code=413,
                    detail=(
                        f"inflated total exceeds package limit of {limits.max_total_bytes} bytes "
                        f"while reading {member.path!r}"
                    ),
                )
    return bytes(buf), len(buf)
