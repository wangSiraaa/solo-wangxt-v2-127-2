"""PostgreSQL-backed repository (psycopg3, parameterized SQL only)."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import psycopg
from psycopg.types.json import Jsonb

from app.parser.html_sanitizer import escape_html
from app.parser.models import ParsedMessage
from app.threads import ThreadInput, compute_threads

_SCHEMA_PATH = Path(__file__).parent / "sql" / "schema.sql"


def _dt(value: datetime | None):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def _addr_json(addrs) -> list[dict[str, Any]]:
    return [asdict(a) for a in addrs]


class PgRepository:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    def connect(self) -> psycopg.Connection:
        return psycopg.connect(self._dsn, autocommit=False)

    def init_schema(self) -> None:
        ddl = _SCHEMA_PATH.read_text(encoding="utf-8")
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(ddl)
            conn.commit()

    # -- ingest ------------------------------------------------------------
    def save_ingest(
        self,
        parsed: ParsedMessage,
        *,
        raw_relpath: str | None,
        stored_attachments: Sequence[tuple[Any, str]],
        source_name: str | None,
        status: str,
        fatal_error: str | None,
    ) -> dict[str, Any]:
        stored_by_path = {}
        for att, rel in stored_attachments:
            stored_by_path[id(att)] = rel
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ingests (source_name, status, raw_sha256, raw_size, raw_path,
                                     fatal_error, defect_count)
                VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id
                """,
                (
                    source_name,
                    status,
                    parsed.raw_sha256,
                    parsed.raw_size,
                    raw_relpath,
                    fatal_error,
                    len(parsed.defects),
                ),
            )
            ingest_id = cur.fetchone()[0]

            message_pk: int | None = None
            if status != "failed":
                cur.execute(
                    """
                    INSERT INTO messages (ingest_id, message_id, subject, raw_subject, date,
                        from_json, to_json, cc_json, bcc_json, reply_to_json, sender_json,
                        tree_json, raw_sha256, raw_path, missing_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id
                    """,
                    (
                        ingest_id,
                        parsed.message_id,
                        parsed.subject,
                        parsed.raw_subject,
                        _dt(parsed.date),
                        Jsonb(_addr_json(parsed.from_)),
                        Jsonb(_addr_json(parsed.to)),
                        Jsonb(_addr_json(parsed.cc)),
                        Jsonb(_addr_json(parsed.bcc)),
                        Jsonb(_addr_json(parsed.reply_to)),
                        Jsonb(_addr_json(parsed.sender)),
                        Jsonb(asdict(parsed.tree) if parsed.tree else None),
                        parsed.raw_sha256,
                        raw_relpath,
                        parsed.message_id is None,
                    ),
                )
                message_pk = cur.fetchone()[0]

                cur.executemany(
                    "INSERT INTO message_headers (message_id, ordinal, name, value, raw_value) VALUES (%s,%s,%s,%s,%s)",
                    [(message_pk, h.ordinal, h.name, h.value, h.raw_value) for h in parsed.headers],
                )
                idents: list[tuple[int, str, str, int]] = []
                if parsed.message_id:
                    idents.append((message_pk, "message_id", parsed.message_id, 0))
                idents.extend((message_pk, "references", v, i) for i, v in enumerate(parsed.references))
                idents.extend((message_pk, "in_reply_to", v, i) for i, v in enumerate(parsed.in_reply_to))
                if idents:
                    cur.executemany(
                        "INSERT INTO message_identifiers (message_pk, kind, value, ordinal) VALUES (%s,%s,%s,%s)",
                        idents,
                    )

                for body in parsed.bodies:
                    escaped = escape_html(body.text) if body.content_type == "text/html" else None
                    cur.execute(
                        """
                        INSERT INTO bodies (message_pk, mime_path, content_type, charset,
                            declared_charset, disposition, content_id, content_location,
                            byte_size, text, safe_html, escaped_html, plain_text, referenced_cids)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (
                            message_pk,
                            body.mime_path,
                            body.content_type,
                            body.charset,
                            body.declared_charset,
                            body.disposition.value,
                            body.content_id,
                            body.content_location,
                            body.byte_size,
                            body.text if body.content_type == "text/plain" else None,
                            body.safe_html,
                            escaped,
                            body.plain_text,
                            Jsonb(body.referenced_cids),
                        ),
                    )

                for att in parsed.attachments:
                    rel = att.storage_path
                    cur.execute(
                        """
                        INSERT INTO attachments (message_pk, mime_path, content_type, charset,
                            disposition, filename, raw_filename, content_id, content_location,
                            byte_size, checksum_sha256, storage_path, stored)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (
                            message_pk,
                            att.mime_path,
                            att.content_type,
                            att.charset,
                            att.disposition.value,
                            att.filename,
                            att.raw_filename,
                            att.content_id,
                            att.content_location,
                            att.byte_size,
                            att.checksum_sha256,
                            rel,
                            rel is not None,
                        ),
                    )

            cur.executemany(
                "INSERT INTO defects (ingest_id, message_pk, stage, level, message) VALUES (%s,%s,%s,%s,%s)",
                [(ingest_id, message_pk, d.stage, d.level, d.message) for d in parsed.defects],
            )
            conn.commit()
        return {"ingest_id": ingest_id, "message_id": message_pk}

    # -- threads -----------------------------------------------------------
    def rebuild_threads(self) -> dict[str, Any]:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT m.id, m.message_id, m.subject,
                       EXTRACT(EPOCH FROM m.date),
                       (SELECT jsonb_agg(jsonb_build_object('kind', kind, 'value', value) ORDER BY ordinal)
                          FROM message_identifiers i WHERE i.message_pk = m.id) AS idents
                FROM messages m ORDER BY m.id
                """
            )
            rows = cur.fetchall()
            inputs: list[ThreadInput] = []
            for pk, mid, subject, ts, idents in rows:
                refs, irt = [], []
                for item in idents or []:
                    if item["kind"] == "references":
                        refs.append(item["value"])
                    elif item["kind"] == "in_reply_to":
                        irt.append(item["value"])
                inputs.append(ThreadInput(pk, mid, refs, irt, subject, ts))
            result = compute_threads(inputs)
            cur.executemany(
                "UPDATE messages SET thread_key = %s WHERE id = %s",
                [(key, pk) for pk, key in result.thread_of.items()],
            )
            cur.execute(
                """
                INSERT INTO thread_runs (duplicate_ids, dangling, cycles, weak_suggestions)
                VALUES (%s,%s,%s,%s) RETURNING id
                """,
                (
                    Jsonb(result.duplicate_ids),
                    Jsonb(result.dangling_references),
                    Jsonb(result.cycles),
                    Jsonb(result.weak_suggestions),
                ),
            )
            run_id = cur.fetchone()[0]
            conn.commit()
        return {
            "thread_run_id": run_id,
            "messages": len(inputs),
            "threads": len(set(result.thread_of.values())),
            "duplicate_ids": result.duplicate_ids,
            "dangling_references": result.dangling_references,
            "cycles": result.cycles,
            "weak_suggestions": result.weak_suggestions,
        }

    # -- reads -------------------------------------------------------------
    def _fetch_message(self, cur, pk: int) -> dict[str, Any] | None:
        cur.execute("SELECT * FROM messages WHERE id = %s", (pk,))
        row = cur.fetchone()
        if not row:
            return None
        cols = [c.name for c in cur.description]
        msg = dict(zip(cols, row))
        for table, key in (
            ("bodies", "bodies"),
            ("attachments", "attachments"),
            ("defects", "defects"),
        ):
            cur.execute(f"SELECT * FROM {table} WHERE message_pk = %s ORDER BY id", (pk,))
            c = [x.name for x in cur.description]
            msg[key] = [dict(zip(c, r)) for r in cur.fetchall()]
        cur.execute("SELECT raw_path FROM ingests WHERE id = %s", (msg["ingest_id"],))
        r = cur.fetchone()
        msg["raw_path"] = r[0] if r else None
        return _jsonify(msg)

    def get_message(self, pk: int) -> dict[str, Any] | None:
        with self.connect() as conn, conn.cursor() as cur:
            return self._fetch_message(cur, pk)

    def get_ingest(self, ingest_id: int) -> dict[str, Any] | None:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM ingests WHERE id = %s", (ingest_id,))
            row = cur.fetchone()
            if not row:
                return None
            cols = [c.name for c in cur.description]
            out = dict(zip(cols, row))
            cur.execute("SELECT stage, level, message FROM defects WHERE ingest_id = %s ORDER BY id", (ingest_id,))
            out["defects"] = [dict(zip(["stage", "level", "message"], r)) for r in cur.fetchall()]
            cur.execute("SELECT id FROM messages WHERE ingest_id = %s", (ingest_id,))
            out["message_pk"] = cur.fetchone()
            out["message_pk"] = out["message_pk"][0] if out["message_pk"] else None
            return _jsonify(out)

    def list_messages(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, message_id, subject, date, from_json, thread_key, raw_sha256,
                       missing_id, ingest_id
                FROM messages ORDER BY id DESC LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )
            cols = [c.name for c in cur.description]
            return _jsonify([dict(zip(cols, r)) for r in cur.fetchall()])

    def search_messages(self, query: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        like = f"%{query}%"
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT m.id, m.message_id, m.subject, m.date, m.from_json,
                       m.thread_key, m.raw_sha256, m.missing_id, m.ingest_id
                FROM messages m
                LEFT JOIN message_headers h ON h.message_id = m.id
                LEFT JOIN bodies b ON b.message_pk = m.id
                WHERE m.subject ILIKE %s
                   OR m.message_id ILIKE %s
                   OR h.value ILIKE %s
                   OR b.plain_text ILIKE %s
                ORDER BY m.date DESC NULLS LAST
                LIMIT %s OFFSET %s
                """,
                (like, like, like, like, limit, offset),
            )
            cols = [c.name for c in cur.description]
            items = _jsonify([dict(zip(cols, r)) for r in cur.fetchall()])
        return {"query": query, "count": len(items), "results": items}

    def get_thread(self, thread_key: str) -> dict[str, Any] | None:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, message_id, subject, date, from_json, in_reply_to_agg.references,
                       in_reply_to_agg.in_reply_to
                FROM messages m
                LEFT JOIN LATERAL (
                    SELECT jsonb_agg(value) FILTER (WHERE kind='references') AS references,
                           jsonb_agg(value) FILTER (WHERE kind='in_reply_to') AS in_reply_to
                    FROM message_identifiers WHERE message_pk = m.id
                ) in_reply_to_agg ON TRUE
                WHERE m.thread_key = %s
                ORDER BY m.date ASC NULLS LAST, m.id ASC
                """,
                (thread_key,),
            )
            rows = cur.fetchall()
            if not rows:
                return None
            cols = [c.name for c in cur.description]
            return _jsonify({"thread_key": thread_key, "messages": [dict(zip(cols, r)) for r in rows]})

    def list_threads(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT thread_key, count(*) AS message_count,
                       min(date) AS started_at, max(date) AS last_at,
                       bool_or(missing_id) AS has_missing_id,
                       count(DISTINCT message_id) FILTER (WHERE message_id IS NOT NULL)
                           AS distinct_message_ids
                FROM messages WHERE thread_key IS NOT NULL
                GROUP BY thread_key
                ORDER BY max(date) DESC NULLS LAST, thread_key
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )
            cols = [c.name for c in cur.description]
            return _jsonify([dict(zip(cols, r)) for r in cur.fetchall()])

    def list_failures(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT i.id AS ingest_id, i.received_at, i.source_name, i.status,
                       i.raw_sha256, i.raw_size, i.fatal_error, i.defect_count,
                       (SELECT jsonb_agg(jsonb_build_object('stage', d.stage, 'level', d.level,
                                                            'message', d.message))
                          FROM defects d WHERE d.ingest_id = i.id) AS defects
                FROM ingests i
                WHERE i.status = 'failed' OR i.defect_count > 0
                ORDER BY i.id DESC LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )
            cols = [c.name for c in cur.description]
            return _jsonify([dict(zip(cols, r)) for r in cur.fetchall()])

    def get_attachment(self, attachment_id: int) -> dict[str, Any] | None:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM attachments WHERE id = %s", (attachment_id,))
            row = cur.fetchone()
            if not row:
                return None
            cols = [c.name for c in cur.description]
            return _jsonify(dict(zip(cols, row)))


def _jsonify(value: Any) -> Any:
    """Decode Jsonb values already parsed by psycopg (dicts/lists) — pass through."""
    return value
