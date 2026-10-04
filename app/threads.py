"""Conversation threading.

Identity rules (per the archive requirements):
* Edges come only from ``Message-ID`` / ``References`` / ``In-Reply-To``.
* Matching subjects are *weak candidates*: they can join messages that already
  touch the same id graph or be reported as suggestions — they never silently
  merge independent threads.
* Missing ids are not invented: a message with no Message-ID is threaded only
  through its reference tokens (or stands alone).
* Duplicate Message-IDs are kept as a *conflict*, the messages are not merged
  into one record; the id is still usable as an edge target.
* Cycles in the reference graph are detected and reported; traversal never
  hangs (visited sets / union-find bound the work).

The algorithm is a plain function over normalized inputs so it is trivially
unit-testable and independent of the database.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

# Strip a leading sequence of Re:/Fwd:/Aw:/... reply markers and whitespace.
_SUBJECT_FWD_RE = re.compile(
    r"^\s*(?:(?:re|fwd?|aw|sv|wg|rvg|tr|res|antw|na|efs)\s*(\[\d+\])?\s*:\s*)+",
    re.IGNORECASE,
)
_WS_RE = re.compile(r"\s+")


def normalize_subject(subject: str | None) -> str:
    if not subject:
        return ""
    s = _SUBJECT_FWD_RE.sub("", subject)
    s = _WS_RE.sub(" ", s).strip().lower()
    return s


@dataclass
class ThreadInput:
    """One stored message as seen by the threader."""

    message_pk: int  # stable storage key (used when message_id is missing)
    message_id: str | None  # already extracted / trimmed by parser
    references: list[str]
    in_reply_to: list[str]
    subject: str | None
    timestamp: float | None = None  # epoch seconds, used only for weak hints


@dataclass
class ThreadResult:
    # message_pk -> stable thread key
    thread_of: dict[int, str]
    # thread key -> root message_id (None when the graph only has synthetic pks)
    roots: dict[str, str | None]
    # message ids used by more than one message_pk (duplicate-id conflicts)
    duplicate_ids: dict[str, list[int]]
    # reference tokens that never matched a known Message-ID
    dangling_references: list[dict[str, object]]
    # cycles found in the id-level reference graph (lists of ids)
    cycles: list[list[str]]
    # subject-based *weak* suggestions, never auto-merged
    weak_suggestions: list[dict[str, object]]
    # parent edge per message pk (strong headers only), for inspection
    strong_edges: dict[int, list[str]] = field(default_factory=dict)


class _DSU:
    def __init__(self) -> None:
        self.p: dict[str, dict] = {}

    def node(self, key: str, kind: str) -> dict:
        if key not in self.p:
            self.p[key] = {"key": key, "kind": kind}
        return self.p[key]
    def find(self, x: str) -> str:
        root = x
        while self.p[root]["key"] != root:
            root = self.p[root]["key"]
        node = x
        while self.p[node]["key"] != node:
            nxt = self.p[node]["key"]
            self.p[node] = {"key": root}  # path compression
            node = nxt
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb]["key"] = ra


def compute_threads(
    messages: list[ThreadInput],
    *,
    weak_subject_window_days: float | None = 30.0,
) -> ThreadResult:
    dsu = _DSU()
    id_to_pks: dict[str, list[int]] = defaultdict(list)
    pk_node: dict[int, str] = {}
    strong_edges: dict[int, list[str]] = {}
    # id -> set of ids it references (for cycle detection)
    id_graph: dict[str, set[str]] = defaultdict(set)

    # 1) Register every message and its own id.
    for m in messages:
        dsu.node(f"pk:{m.message_pk}", "pk")
        pk_node[m.message_pk] = f"pk:{m.message_pk}"
        if m.message_id:
            mid = m.message_id.lower()
            dsu.node(f"id:{mid}", "id")
            id_to_pks[mid].append(m.message_pk)
            dsu.union(f"pk:{m.message_pk}", f"id:{mid}")

    # 2) Strong edges from References / In-Reply-To.
    dangling: list[dict[str, object]] = []
    for m in messages:
        edges: list[str] = []
        for source, tokens in (
            ("references", m.references),
            ("in_reply_to", m.in_reply_to),
        ):
            for tok in tokens:
                tid = tok.lower()
                edges.append(tid)
                id_graph.setdefault(m.message_id.lower() if m.message_id else f"pk:{m.message_pk}", set())
                if m.message_id:
                    id_graph[m.message_id.lower()].add(tid)
                target = f"id:{tid}"
                if tid not in id_to_pks:
                    # Reference to an unknown message: keep the token as a node
                    # so chains still link, but report it.
                    dsu.node(target, "id")
                    dangling.append(
                        {"message_pk": m.message_pk, "header": source, "message_id": tok}
                    )
                dsu.union(f"pk:{m.message_pk}", target)
        strong_edges[m.message_pk] = edges

    # 3) Detect cycles in the id-level graph (DFS with three-color marks).
    cycles = _find_cycles(id_graph)

    # 4) Duplicate Message-ID conflicts (same id claimed by multiple messages).
    duplicates = {mid: pks for mid, pks in id_to_pks.items() if len(set(pks)) > 1}

    # 5) Weak subject candidates. Same normalized subject only *suggests* a
    #    relation; enforce a recency window to limit fan-out. Suggestions are
    #    returned, never applied.
    by_subject: dict[str, list[ThreadInput]] = defaultdict(list)
    for m in messages:
        norm = normalize_subject(m.subject)
        if norm and len(norm) >= 8:
            by_subject[norm].append(m)
    weak: list[dict[str, object]] = []
    window = weak_subject_window_days
    for norm, group in by_subject.items():
        if len(group) < 2:
            continue
        # If all members already share a strong component, the subject agrees;
        # not a conflict. Only surface suggestions that span components.
        comps = {dsu.find(pk_node[m.message_pk]) for m in group}
        if len(comps) == 1:
            continue
        for i, a in enumerate(group):
            for b in group[i + 1 :]:
                if window is not None and a.timestamp is not None and b.timestamp is not None:
                    if abs(a.timestamp - b.timestamp) > window * 86400:
                        continue
                weak.append(
                    {
                        "subject": norm,
                        "message_pk_a": a.message_pk,
                        "message_pk_b": b.message_pk,
                        "reason": "subject_match_only",
                    }
                )

    # 6) Assign stable thread keys per component. The human-readable root is a
    #    *predecessor* in the reference direction: a known id that no other
    #    known message points to (the start of the chain). Lexicographic order
    #    only breaks ties. Components without a known id get a synthetic key.
    by_pk = {m.message_pk: m for m in messages}
    thread_of: dict[int, str] = {}
    members: dict[str, list[int]] = defaultdict(list)
    for m in messages:
        comp = dsu.find(pk_node[m.message_pk])
        members[comp].append(m.message_pk)
    roots: dict[str, str | None] = {}
    for comp, pks in members.items():
        known = {by_pk[pk].message_id.lower(): pk for pk in pks if by_pk[pk].message_id}
        # Direction: References/In-Reply-To name a message's *predecessors*.
        # A root references no other *known* message (it may dangle); among
        # several roots (branched history) choose lexicographically. In a pure
        # cycle every node has an outgoing edge, so fall back to stable order.
        outgoing_known: dict[str, set[str]] = defaultdict(set)
        for pk in pks:
            own = by_pk[pk].message_id
            if not own:
                continue  # missing-id message cannot be a named root
            mid = own.lower()
            for tok in strong_edges[pk]:
                if tok.lower() in known:
                    outgoing_known[mid].add(tok.lower())
        candidates = sorted(mid for mid in known if not outgoing_known.get(mid))
        if candidates:
            root_id = candidates[0]
            key = "thread-" + root_id
            roots[key] = root_id
        elif known:
            # everyone references everyone else (pure cycle): choose stably
            root_id = sorted(known)[0]
            key = "thread-" + root_id
            roots[key] = root_id
        else:
            digest = hashlib.sha1(",".join(map(str, sorted(pks))).encode()).hexdigest()[:16]
            key = f"thread-synthetic-{digest}"
            roots[key] = None
        for pk in pks:
            thread_of[pk] = key

    return ThreadResult(
        thread_of=thread_of,
        roots=roots,
        duplicate_ids=dict(duplicates),
        dangling_references=dangling,
        cycles=cycles,
        weak_suggestions=weak,
        strong_edges=strong_edges,
    )


def _find_cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    """Return cycles (as id lists) using iterative three-color DFS.

    A node turns BLACK only after *all* its descendants have been explored;
    gray nodes are exactly the current DFS path, so an edge to a gray node
    closes a cycle.
    """
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = defaultdict(int)
    cycles: list[list[str]] = []
    seen_cycle_sigs: set[tuple[str, ...]] = set()

    for start in list(graph.keys()):
        if color[start] != WHITE:
            continue
        color[start] = GRAY
        # frames hold (node, current path, iterator over successors)
        stack: list[tuple[str, list[str], Any]] = [
            (start, [start], iter(sorted(graph.get(start, ()))))
        ]
        while stack:
            node, path, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                color[node] = BLACK
                stack.pop()
                continue
            if nxt in path:  # edge back into the active path -> cycle
                cyc = path[path.index(nxt) :] + [nxt]
                sig = tuple(sorted(cyc))
                if sig not in seen_cycle_sigs:
                    seen_cycle_sigs.add(sig)
                    cycles.append(cyc)
                continue
            if color[nxt] == GRAY:
                # gray but not on this path: previously reported via that path
                continue
            if color[nxt] == BLACK:
                continue
            color[nxt] = GRAY
            stack.append((nxt, path + [nxt], iter(sorted(graph.get(nxt, ())))))
    return cycles
