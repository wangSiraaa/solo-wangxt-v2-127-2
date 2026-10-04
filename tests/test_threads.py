from app.threads import ThreadInput, compute_threads, normalize_subject


def test_thread_chain_via_references_and_in_reply_to():
    msgs = [
        ThreadInput(1, "root@x", [], [], "start", 0.0),
        ThreadInput(2, "child@x", ["root@x"], ["root@x"], "Re: start", 1.0),
        ThreadInput(3, "grand@x", ["root@x", "child@x"], ["child@x"], "Re: start", 2.0),
    ]
    r = compute_threads(msgs)
    assert r.thread_of[1] == r.thread_of[2] == r.thread_of[3]
    assert r.roots[r.thread_of[1]] == "root@x"
    assert r.cycles == []
    assert r.duplicate_ids == {}

def test_circular_references_detected_without_hanging():
    msgs = [
        ThreadInput(1, "a@x", ["b@x"], ["b@x"], "A"),
        ThreadInput(2, "b@x", ["a@x"], ["a@x"], "B"),
    ]
    r = compute_threads(msgs)
    assert r.thread_of[1] == r.thread_of[2]  # still linked
    assert r.cycles, "cycle must be reported"
    cyc = r.cycles[0]
    assert cyc[0] == cyc[-1] and set(cyc[:-1]) == {"a@x", "b@x"}


def test_self_reference_is_a_cycle():
    r = compute_threads([ThreadInput(1, "self@x", ["self@x"], [], "s")])
    assert any("self@x" in c for c in r.cycles)


def test_duplicate_message_id_is_conflict_not_merge():
    r = compute_threads(
        [
            ThreadInput(1, "dup@x", [], [], "first"),
            ThreadInput(2, "dup@x", [], [], "second"),
        ]
    )
    assert r.duplicate_ids == {"dup@x": [1, 2]}
    # both pks are retained (not merged into one record); same id links them
    assert r.thread_of[1] == r.thread_of[2]
    assert set(r.thread_of.values()) == {"thread-dup@x"}


def test_missing_id_threads_only_via_references():
    r = compute_threads(
        [
            ThreadInput(1, "root@x", [], [], "root"),
            ThreadInput(2, None, ["root@x"], ["root@x"], "no id"),
            ThreadInput(3, None, [], [], "isolated no-id"),
        ]
    )
    assert r.thread_of[1] == r.thread_of[2]
    assert r.thread_of[3] != r.thread_of[1]


def test_subject_match_is_only_weak_suggestion():
    r = compute_threads(
        [
            ThreadInput(1, "a@x", [], [], "Quarterly report", 0.0),
            ThreadInput(2, "b@x", [], [], "Re: Quarterly report", 86400.0),
        ]
    )
    assert r.thread_of[1] != r.thread_of[2]  # NOT merged
    assert r.weak_suggestions
    assert r.weak_suggestions[0]["reason"] == "subject_match_only"


def test_weak_suggestion_respects_time_window():
    r = compute_threads(
        [
            ThreadInput(1, "a@x", [], [], "identical long subject here", 0.0),
            ThreadInput(2, "b@x", [], [], "identical long subject here", 100 * 86400.0),
        ],
        weak_subject_window_days=30,
    )
    assert r.weak_suggestions == []


def test_dangling_reference_recorded():
    r = compute_threads([ThreadInput(1, "m@x", ["ghost@x"], [], "x")])
    assert r.dangling_references[0]["message_id"] == "ghost@x"
    assert r.dangling_references[0]["header"] == "references"


def test_subject_normalization_strips_reply_markers():
    assert normalize_subject("Re: Fwd: Hello") == "hello"
    assert normalize_subject("  RE[2]:   Weekly  Sync ") == "weekly sync"
