"""Machine-check the portable Plamen-v3 research and goal handoff."""

import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTINUATION = ROOT / "docs" / "continuation"
RESEARCH = CONTINUATION / "research"


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def test_research_manifest_reconciles_every_source_and_portable_byte():
    manifest = _json(CONTINUATION / "CORPUS_MANIFEST.json")
    assert manifest["schema"] == "plamen.continuation.corpus-manifest.v2"
    denominator = manifest["discovery_denominator"]
    rows = manifest["source_inventory"]
    assert denominator["current_relevant_union"] == {
        "file_count": 131,
        "total_bytes": 5_372_712,
    }
    assert denominator["semantic_requirements_extracted"] is True
    assert len(rows) == denominator["current_relevant_union"]["file_count"]
    assert sum(row["source_bytes"] for row in rows) == 5_372_712
    assert len({row["source_identity"] for row in rows}) == len(rows)
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", row["source_sha256"])
        for row in rows
    )

    modes = {
        "EXACT", "SANITIZED", "SANITIZED_WITH_PRIVATE_RAW_GAP",
        "EXCLUDED_GAP",
    }
    portable_paths = set()
    gap_rows = []
    staged_blobs = {}
    if (ROOT / ".git").exists():
        for entry in subprocess.check_output(
            ["git", "ls-files", "--stage", "-z"], cwd=ROOT,
        ).split(b"\0"):
            if not entry:
                continue
            metadata, relative = entry.split(b"\t", 1)
            staged_blobs[relative.decode("utf-8")] = metadata.split()[1].decode(
                "ascii"
            )
    for row in rows:
        assert row["source_locator"] == "Downloads/" + row["source_identity"]
        publication = row["publication"]
        assert publication["mode"] in modes
        portable = publication["portable_path"]
        if portable is None:
            assert publication["mode"] == "EXCLUDED_GAP"
            assert publication["portable_bytes"] is None
            assert publication["portable_sha256"] is None
        else:
            path = (ROOT / portable).resolve()
            assert path.parent == RESEARCH.resolve()
            raw = path.read_bytes()
            assert len(raw) == publication["portable_bytes"]
            assert _sha256(raw) == publication["portable_sha256"]
            if staged_blobs:
                relative = path.relative_to(ROOT).as_posix()
                git_blob = hashlib.sha1(
                    b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw,
                ).hexdigest()
                assert staged_blobs[relative] == git_blob
            assert portable not in portable_paths
            portable_paths.add(portable)
            if publication["mode"] == "EXACT":
                assert publication["portable_bytes"] == row["source_bytes"]
                assert publication["portable_sha256"] == row["source_sha256"]
            else:
                assert publication["redactions"]
        if "gap_id" in publication:
            gap_rows.append(row)

    reconciliation = manifest["portable_reconciliation"]
    assert len(portable_paths) == reconciliation["portable_source_file_count"]
    assert reconciliation["portable_source_file_count"] == 127
    assert reconciliation["semantic_completion_claim"] is True
    assert reconciliation["raw_byte_completion_claim"] is False
    assert reconciliation["raw_only_gap_count"] == 4
    assert set(RESEARCH.iterdir()) == {
        *(ROOT / relative for relative in portable_paths),
        RESEARCH / "PRIVATE_GAP_INDEX.json",
    }

    gaps = _json(RESEARCH / "PRIVATE_GAP_INDEX.json")
    assert gaps["gap_count"] == len(gap_rows) == 10
    indexed = {row["gap_id"]: row for row in gaps["gaps"]}
    assert len(indexed) == len(gaps["gaps"])
    for row in gap_rows:
        publication = row["publication"]
        gap = indexed[publication["gap_id"]]
        assert gap["source_identity"] == row["source_identity"]
        assert gap["source_bytes"] == row["source_bytes"]
        assert gap["source_sha256"] == row["source_sha256"]


def test_goal_and_requirement_ledger_are_complete_and_portable():
    goal = (CONTINUATION / "GOAL.md").read_text(encoding="utf-8")
    assert "Status: **ACTIVE**" in goal
    assert "comparative quality benchmarking" in goal
    normalized_goal = " ".join(goal.split())
    assert "POSIX dispatcher plus keeper/recovery adapter" in normalized_goal
    assert "At least one fresh, non-ground-truth end-to-end audit" in normalized_goal
    assert "at least one completes on Claude" in normalized_goal

    requirements = [
        json.loads(line)
        for line in (CONTINUATION / "REQUIREMENTS.jsonl")
        .read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ids = {row["id"] for row in requirements if row.get("id")}
    assert {f"B-{index}" for index in range(1, 8)} <= ids
    assert {f"P-{index}" for index in range(1, 24)} <= ids
    assert {"P0-0", "P0-1", "P0-2", "P0-AM", "P1-M"} <= ids
    assert len(ids) == sum(bool(row.get("id")) for row in requirements)

    portable = b"\n".join(
        path.read_bytes()
        for path in sorted(CONTINUATION.rglob("*"))
        if path.is_file()
    ).lower()
    for forbidden in (
        b"c:\\users\\plmnt", b"c:/users/plmnt", b"d:\\programming",
    ):
        assert forbidden not in portable
