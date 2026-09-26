import json
from pathlib import Path

import plamen_driver as D


def _row(fid: str, severity: str) -> dict[str, str]:
    return {
        "queue #": "1",
        "finding id": fid,
        "severity": severity,
        "title": f"{fid} title",
        "bug class": "logic",
        "preferred tag": "CODE-TRACE",
        "location": f"src/{fid}.sol:L1",
        "primary artifact": "findings_inventory.md",
        "poc class": "structural",
    }


def test_verification_queue_parser_prefers_json_sidecar_when_markdown_is_broken(tmp_path: Path):
    sp = tmp_path
    rows = [_row("H-1", "High"), _row("M-1", "** Medium")]
    D._write_queue_subset_manifest(sp / "verification_queue.md", rows)
    # Simulate a later Markdown formatting corruption. The JSON sidecar is the
    # machine contract and should keep downstream shard/coverage phases stable.
    (sp / "verification_queue.md").write_text(
        "# Verification Queue\n\nNo parseable table here.\n",
        encoding="utf-8",
    )

    parsed = D.parse_verification_queue_rows(sp)

    assert [r["finding id"] for r in parsed] == ["H-1", "M-1"]
    assert [r["severity"] for r in parsed] == ["High", "Medium"]


def test_verify_shard_manifests_write_json_sidecars(tmp_path: Path):
    sp = tmp_path
    rows = [_row("H-1", "High"), _row("H-2", "Critical"), _row("M-1", "Medium")]
    D._write_queue_subset_manifest(sp / "verification_queue.md", rows)

    shards = D.ensure_sc_verify_shard_manifests(sp)

    assert shards["sc_verify_crithigh"]
    assert (sp / "verification_queue_crithigh.json").exists()
    assert (sp / "verification_queue_medium_a.json").exists()
    payload = (sp / "verification_queue_crithigh.json").read_text(encoding="utf-8")
    assert '"schema_version": "plamen.verification_queue.v1"' in payload
    assert '"finding id": "H-1"' in payload
    assert '"finding id": "H-2"' in payload


def test_sealed_live_queue_shard_replay_is_read_only(tmp_path: Path):
    sp = tmp_path
    rows = [_row("H-1", "High"), _row("M-1", "Medium")]
    D._write_queue_subset_manifest(sp / "verification_queue.md", rows)
    expected = D.ensure_sc_verify_shard_manifests(sp)
    sibling = next(
        path
        for path in (
            sp / "compound_verification_delivery_receipt.json",
            sp / "compound_verification_delivery_debt.json",
        )
        if path.is_file()
    )
    sibling.write_bytes(b"sealed T9 sibling bytes\n")
    (sp / "verify_queue_transaction.receipt.json").write_text(
        json.dumps({
            "schema_version": "plamen.live_verify_queue_receipt.v1",
            "state": "OUTPUT_COMMITTED",
            "pipeline": "sc",
            "run_id": "run-sealed-replay",
        }) + "\n",
        encoding="utf-8",
    )
    before = {
        path.relative_to(sp).as_posix(): path.read_bytes()
        for path in sp.rglob("*")
        if path.is_file()
    }

    replay = D.ensure_sc_verify_shard_manifests(sp)

    after = {
        path.relative_to(sp).as_posix(): path.read_bytes()
        for path in sp.rglob("*")
        if path.is_file()
    }
    assert replay == expected
    assert after == before


def test_verification_queue_writer_never_emits_blank_verify_filename(tmp_path: Path):
    sp = tmp_path
    rows = [
        _row("", "High"),
        {
            "queue #": "2",
            "finding id": "   ",
            "severity": "Low",
            "title": "blank id title",
        },
        _row("CC-28", "** Critical"),
    ]

    D._write_queue_subset_manifest(sp / "verification_queue.md", rows)
    text = (sp / "verification_queue.md").read_text(encoding="utf-8")
    json_text = (sp / "verification_queue.json").read_text(encoding="utf-8")

    assert "verify_.md" not in text
    assert "verify_.md" not in json_text
    assert "verify_CC-28.md" in text
    assert '"row_count": 1' in json_text
    assert [r["finding id"] for r in D.parse_verification_queue_rows(sp)] == ["CC-28"]
