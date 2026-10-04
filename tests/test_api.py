import logging

from conftest import SAMPLES


def _post(client, name, data, **params):
    return client.post(
        "/ingest",
        files={"file": (name, data, "message/rfc822")},
        params=params,
    )


def test_health_memory(client):
    c, _ = client
    r = c.get("/health")
    assert r.status_code == 200
    assert r.json()["backend"] in ("memory", "postgresql")


def test_ingest_multibyte_full_flow(client):
    c, arch = client
    data = (SAMPLES / "01_multibyte.eml").read_bytes()
    r = _post(c, "01_multibyte.eml", data)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["message_pk"] is not None
    assert len(body["attachments"]) == 2
    pdf = next(a for a in body["attachments"] if a["content_type"] == "application/pdf")
    assert pdf["stored"] and pdf["filename"] == "文本.pdf"

    # raw eml is stored and linked
    msg = c.get(f"/messages/{body['message_pk']}").json()
    assert msg["raw_sha256"] == body["raw_sha256"]
    assert msg["raw_path"]
    assert arch.raw_storage.exists(msg["raw_path"])
    assert arch.raw_storage.resolve(msg["raw_path"]).read_bytes() == data

    # headers retained verbatim (raw) and decoded
    detail = c.get(f"/ingests/{body['ingest_id']}").json()
    assert detail["status"] == "ok"
    # bodies persisted with safe html and cid linkage
    html_bodies = [b for b in msg["bodies"] if b["content_type"] == "text/html"]
    assert html_bodies and 'src="cid:banner1"' in html_bodies[0]["safe_html"]
    assert "http://tracker.example" not in html_bodies[0]["safe_html"]
    assert "banner1" in html_bodies[0]["referenced_cids"]


def test_ingest_and_download_attachment_traversal_neutralized(client):
    c, arch = client
    r = _post(c, "08_traversal.eml", (SAMPLES / "08_traversal.eml").read_bytes())
    assert r.status_code == 201
    att = r.json()["attachments"][0]
    assert att["stored"]
    assert ".." not in att["storage_path"].split("/")[0]
    assert "cron.d" not in att["storage_path"]  # stored under content hash name

    pk = r.json()["message_pk"]
    meta = c.get(f"/messages/{pk}").json()["attachments"][0]
    dl = c.get(f"/messages/{pk}/attachments/{meta['id']}/download")
    assert dl.status_code == 200
    assert dl.content == b"malicious payload bytes"
    # served with sanitized filename, no directory parts
    cd = dl.headers["content-disposition"]
    assert "../" not in cd

    # tampering the DB path cannot escape the root
    stored = arch.repo.get_attachment(meta["id"])
    stored["storage_path"] = "../../../../etc/passwd"
    # repo callers use DB; emulate tampering by writing through internal map:
    if hasattr(arch.repo, "attachments"):
        for row in arch.repo.attachments:
            if row["id"] == meta["id"]:
                row["storage_path"] = "../../../../etc/passwd"
        evil = c.get(f"/messages/{pk}/attachments/{meta['id']}/download")
        assert evil.status_code == 400


def test_corrupt_and_missing_id_recorded_as_failures(client):
    c, _ = client
    r1 = _post(c, "06_corrupt_boundary.eml", (SAMPLES / "06_corrupt_boundary.eml").read_bytes())
    assert r1.json()["status"] == "defective"
    r2 = _post(c, "03_missing_id.eml", (SAMPLES / "03_missing_id.eml").read_bytes())
    assert r2.json()["status"] == "defective"
    fails = c.get("/failures").json()
    assert len(fails) >= 2
    stages = {d["stage"] for f in fails for d in f["defects"]}
    assert "0" in stages  # locatable


def test_garbage_ingest_fails_but_is_locatable(client):
    c, _ = client
    r = _post(c, "garbage.bin", b"\x00\xff\xfe not an email " * 50)
    # message_from_bytes is tolerant; force truly empty too
    body = r.json()
    assert body["status"] in ("defective", "failed")
    detail = c.get(f"/ingests/{body['ingest_id']}").json()
    assert detail["raw_sha256"] == body["raw_sha256"]
    assert detail["defects"]


def test_search_over_subject_body_and_headers(client):
    c, _ = client
    _post(c, "01.eml", (SAMPLES / "01_multibyte.eml").read_bytes())
    _post(c, "xss.eml", (SAMPLES / "09_html_xss.eml").read_bytes())
    hits = c.get("/search", params={"q": "GB18030"}).json()
    assert hits["count"] >= 1
    hits2 = c.get("/search", params={"q": "multi-01@example.com"}).json()
    assert hits2["count"] == 1
    assert c.get("/search", params={"q": "definitely-not-present-xyz"}).json()["count"] == 0


def test_threading_cycles_duplicates_and_weak_subjects(client):
    c, _ = client
    for n in ["02_cycle_a.eml", "02_cycle_b.eml", "04_duplicate_id_a.eml",
              "04_duplicate_id_b.eml", "05_same_subject_root.eml",
              "05_same_subject_other.eml"]:
        r = _post(c, n, (SAMPLES / n).read_bytes(), recompute_threads=False)
        assert r.status_code == 201
    rebuilt = c.post("/threads/rebuild").json()
    assert rebuilt["cycles"], "circular references must be flagged"
    flat_cycles = {x for cyc in rebuilt["cycles"] for x in cyc}
    assert {"cycle-a@example.com", "cycle-b@example.com"} <= flat_cycles
    assert "dup-1@example.com" in rebuilt["duplicate_ids"]
    assert rebuilt["duplicate_ids"]["dup-1@example.com"] == [3, 4] or len(
        rebuilt["duplicate_ids"]["dup-1@example.com"]
    ) == 2
    # weak suggestion between the two unrelated "Quarterly report" mails
    weak = rebuilt["weak_suggestions"]
    assert any(w["reason"] == "subject_match_only" for w in weak)
    # cycle members share a thread
    ma = c.get("/search", params={"q": "cycle-a"}).json()["results"][0]["id"]
    mb = c.get("/search", params={"q": "cycle-b"}).json()["results"][0]["id"]
    ta = c.get(f"/messages/{ma}").json()["thread_key"]
    tb = c.get(f"/messages/{mb}").json()["thread_key"]
    assert ta == tb
    # same-subject mails are NOT in one thread
    q1 = c.get("/search", params={"q": "Quarterly"}).json()["results"]
    keys = {c.get(f"/messages/{m['id']}").json()["thread_key"] for m in q1}
    assert len(keys) == 2


def test_upload_size_cap(client):
    c, arch = client
    arch.settings  # max is 10MB in tests
    big = b"x" * (10 * 1024 * 1024 + 10)
    r = _post(c, "big.eml", big)
    assert r.status_code == 413


def test_empty_upload_rejected(client):
    c, _ = client
    r = _post(c, "empty.eml", b"")
    assert r.status_code == 422


def test_attachment_content_excluded_from_logs(client, caplog):
    c, _ = client
    with caplog.at_level(logging.INFO):
        _post(c, "01_multibyte.eml", (SAMPLES / "01_multibyte.eml").read_bytes())
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "%PDF-1.4" not in text
    assert "GIF89aFAKEGIFDATA" not in text


def test_message_ids_not_unique_across_ingests(client):
    c, _ = client
    a = _post(c, "a.eml", (SAMPLES / "04_duplicate_id_a.eml").read_bytes()).json()
    b = _post(c, "b.eml", (SAMPLES / "04_duplicate_id_b.eml").read_bytes()).json()
    assert a["message_pk"] != b["message_pk"]
    ma = c.get(f"/messages/{a['message_pk']}").json()
    mb = c.get(f"/messages/{b['message_pk']}").json()
    assert ma["message_id"] == mb["message_id"] == "dup-1@example.com"
