from __future__ import annotations

import json
from pathlib import Path

import pytest

from axis_canonical_prior import capture_axis_canonical_prior_authority
from exploration_clear_lifecycle import (
    compile_initial_receipt,
    write_lifecycle_artifacts,
)
import plamen_mechanical


RUN_ID = "8bc3bca7-f4e0-4bcc-92af-d83168071b8f"
WORKLIST_HASH = "a" * 64


def _write_queue(root: Path, *, evidence: str | None) -> Path:
    project = root.parent
    source = root / "exploration_skeptic_findings.md"
    row = (
        f"| INV-1 | sibling path | alternate branch | NO-GAP | {evidence} |\n"
        if evidence is not None
        else ""
    )
    source.write_text(
        "# Exploration\n\n"
        "## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        f"{row}",
        encoding="utf-8",
    )
    receipt = compile_initial_receipt(
        source,
        production_root=project,
        canonical_prior_ids={},
    )
    write_lifecycle_artifacts(root, receipt)
    return root / "exploration_clear_obligations.json"


def _capture(root: Path, queue: Path):
    return capture_axis_canonical_prior_authority(
        root,
        run_id=RUN_ID,
        worklist_hash=WORKLIST_HASH,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        source_paths=[queue],
    )


@pytest.mark.parametrize(
    ("evidence", "expected_count"),
    (
        ("generic wording only", 1),
        (None, 0),
    ),
)
def test_typed_obligation_queue_is_validated_but_not_finding_aliased(
    tmp_path: Path,
    evidence: str | None,
    expected_count: int,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    (project / "contracts").mkdir()
    (project / "contracts" / "Unit.sol").write_text(
        "contract Unit {}\n", encoding="utf-8"
    )
    queue = _write_queue(root, evidence=evidence)
    assert json.loads(queue.read_text(encoding="utf-8"))["count"] == expected_count

    authority = _capture(root, queue)

    assert authority.status == "EXACT"
    assert authority.aliases == {}
    assert authority.snapshot["record_count"] == 0
    assert authority.snapshot["source_artifacts"] == [{
        "capture_state": "CAPTURED",
        "issue": "",
        "relative_path": "exploration_clear_obligations.json",
        "sha256": __import__("hashlib").sha256(queue.read_bytes()).hexdigest(),
        "size_bytes": len(queue.read_bytes()),
    }]
    assert plamen_mechanical._canonical_identity_records_from_artifact(queue) == []


def test_malformed_typed_obligation_queue_remains_fail_closed(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    queue = _write_queue(root, evidence="generic wording only")
    payload = json.loads(queue.read_text(encoding="utf-8"))
    payload["count"] += 1
    queue.write_text(json.dumps(payload), encoding="utf-8")

    authority = _capture(root, queue)

    assert authority.status == "DEGRADED"
    assert authority.aliases == {}
    assert authority.snapshot["source_artifacts"][0]["capture_state"] == (
        "UNAVAILABLE"
    )
    assert authority.debt == (
        "SOURCE_PROJECTION_FAILED:exploration_clear_obligations.json:"
        "TypedProducerActionError",
    )
    with pytest.raises(Exception, match="queue does not exactly match"):
        plamen_mechanical._canonical_identity_records_from_artifact(queue)
