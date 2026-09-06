"""P1-M live driver boundary for crash-safe P0-AF v2 queue delivery."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact_ledger import (  # noqa: E402
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from p0af_v2_queue_adapter import CANDIDATE_FILE  # noqa: E402
from p0af_v2_queue_runtime import (  # noqa: E402
    DEBT_FILE,
    JOURNAL_FILE,
    RECEIPT_FILE,
    STATUS_FILE,
    P0AFV2QueueRuntimeError,
    p0af_v2_upstream_contract_and_launch,
    run_p0af_v2_queue_delivery,
)
from plamen_parsers import (  # noqa: E402
    ensure_sc_verify_shard_manifests,
    _read_typed_queue_work_items,
    _write_queue_subset_manifest,
    parse_verification_queue_rows,
)
import plamen_driver as DRIVER  # noqa: E402
from queue_work_items import queue_record_set_digest  # noqa: E402
from test_p0af_v2_queue_adapter_p1_m import (  # noqa: E402
    _artifacts,
    _canonical_ids,
)


_UPSTREAM_INPUT_PATHS = (
    "arm_before_trust_chain_analysis.input.json",
    "arm_before_trust_composition_obligations.json",
    "authentication_role_authority.json",
    "_canonical_finding_ids.json",
)
_UPSTREAM_OUTPUT_PATHS = (
    CANDIDATE_FILE,
    "arm_before_trust_compound_work_plan.json",
    "arm_before_trust_p0af_route_debt.json",
)


def _config(root: Path) -> dict[str, object]:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(root),
        "_run_id": "RUN-P1M-0001",
    }


def _initial_queue(root: Path) -> None:
    _write_queue_subset_manifest(
        root / "verification_queue.md",
        [{
            "queue #": "1",
            "finding id": "M-01",
            "severity": "Medium",
            "title": "Independent ordinary work",
            "bug class": "state-transition",
            "preferred tag": "CODE-TRACE",
            "location": "findings_inventory.md",
            "primary artifact": "findings_inventory.md",
            "poc class": "structural",
        }],
    )


def _materialize_upstream_inputs(root: Path) -> dict[str, bytes]:
    for name in (
        "arm_before_trust_chain_analysis.input.json",
        "arm_before_trust_composition_obligations.json",
        "authentication_role_authority.json",
    ):
        (root / name).write_text("{}\n", encoding="utf-8")
    _canonical_ids(root)
    return {name: (root / name).read_bytes() for name in _UPSTREAM_INPUT_PATHS}


def _record_upstream(root: Path, config: dict[str, object]) -> None:
    input_bytes = _materialize_upstream_inputs(root)
    assert all(not (root / name).exists() for name in _UPSTREAM_OUTPUT_PATHS)
    physical_paths = [
        os.path.normcase(str((root / name).resolve(strict=name in input_bytes)))
        for name in (*_UPSTREAM_INPUT_PATHS, *_UPSTREAM_OUTPUT_PATHS)
    ]
    assert len(physical_paths) == len(set(physical_paths))
    contract, launch = p0af_v2_upstream_contract_and_launch(config)
    record_work_unit_inputs(
        root, root, contract, launch, run_id=str(config["_run_id"])
    )
    armed = read_artifact_ledger(root)["work_units"][contract.key]
    assert armed["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert armed["semantic_status"] == "INPUTS_BOUND"
    assert set(armed["output_prestates"]) == {
        spec.identity for spec in contract.outputs
    }
    assert {
        row["status"] for row in armed["output_prestates"].values()
    } == {"ABSENT"}
    assert validate_work_unit_inputs(
        root, root, contract, launch, run_id=str(config["_run_id"])
    ) == []

    _artifacts(root)
    assert {
        name: (root / name).read_bytes() for name in _UPSTREAM_INPUT_PATHS
    } == input_bytes
    record_work_unit_artifacts(
        root,
        root,
        contract,
        launch,
        run_id=str(config["_run_id"]),
        actor="DRIVER",
    )
    committed = read_artifact_ledger(root)["work_units"][contract.key]
    assert committed["execution_state"] == "OUTPUT_COMMITTED"
    assert committed["semantic_status"] == "ACTIVE"
    assert set(committed["artifacts"]) == {
        spec.identity for spec in contract.outputs
    }
    assert {
        row["status"] for row in committed["artifacts"].values()
    } == {"ACTIVE"}
    assert committed["commit_authority"]["state"] == "ACTIVE"
    for spec in contract.outputs:
        raw = (root / spec.path).read_bytes()
        record = committed["artifacts"][spec.identity]
        assert record["size"] == len(raw)
        assert record["sha256"] == hashlib.sha256(raw).hexdigest()
    assert validate_work_unit_artifacts(
        root,
        root,
        contract,
        launch,
        run_id=str(config["_run_id"]),
        actor="DRIVER",
    ) == []


def _ready(root: Path) -> dict[str, object]:
    config = _config(root)
    _record_upstream(root, config)
    _initial_queue(root)
    return config


def _queue_bytes(root: Path) -> dict[str, bytes]:
    return {
        name: (root / name).read_bytes()
        for name in (
            "verification_queue.md",
            "verification_queue.json",
            "verification_queue.work_items.json",
        )
    }


def test_missing_upstream_phase_io_preserves_queue_and_emits_visible_debt(
    tmp_path: Path,
) -> None:
    _artifacts(tmp_path)
    _initial_queue(tmp_path)
    before = _queue_bytes(tmp_path)

    outcome = run_p0af_v2_queue_delivery(tmp_path, _config(tmp_path))

    assert outcome.committed is False
    assert outcome.issues
    assert _queue_bytes(tmp_path) == before
    status = json.loads((tmp_path / STATUS_FILE).read_text(encoding="utf-8"))
    assert status["state"] == "COMPLETED_WITH_DEBT"
    assert status["proof_authority"] == "NONE"


def test_prepublished_upstream_output_quarantines_bundle_and_preserves_queue(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    _materialize_upstream_inputs(tmp_path)
    (tmp_path / CANDIDATE_FILE).write_text("{}\n", encoding="utf-8")
    contract, launch = p0af_v2_upstream_contract_and_launch(config)
    record_work_unit_inputs(
        tmp_path,
        tmp_path,
        contract,
        launch,
        run_id=str(config["_run_id"]),
    )
    armed = read_artifact_ledger(tmp_path)["work_units"][contract.key]
    candidate_identity = next(
        spec.identity for spec in contract.outputs if spec.path == CANDIDATE_FILE
    )
    assert armed["output_prestates"][candidate_identity]["status"] != "ABSENT"

    _artifacts(tmp_path)
    record_work_unit_artifacts(
        tmp_path,
        tmp_path,
        contract,
        launch,
        run_id=str(config["_run_id"]),
        actor="DRIVER",
    )
    rejected = read_artifact_ledger(tmp_path)["work_units"][contract.key]
    assert rejected["execution_state"] == "OUTPUT_QUARANTINED"
    assert rejected["semantic_status"] == "QUARANTINED"
    assert {
        row["status"] for row in rejected["artifacts"].values()
    } == {"QUARANTINED"}

    _initial_queue(tmp_path)
    before = _queue_bytes(tmp_path)
    outcome = run_p0af_v2_queue_delivery(tmp_path, config)

    assert outcome.committed is False
    assert outcome.issues
    assert _queue_bytes(tmp_path) == before
    assert json.loads((tmp_path / STATUS_FILE).read_text(encoding="utf-8"))[
        "state"
    ] == "COMPLETED_WITH_DEBT"


def test_live_delivery_commits_queue_trio_and_exact_successor_authority(
    tmp_path: Path,
) -> None:
    config = _ready(tmp_path)
    source_before = (tmp_path / CANDIDATE_FILE).read_bytes()

    outcome = run_p0af_v2_queue_delivery(tmp_path, config)

    assert outcome.committed is True
    assert outcome.issues == ()
    assert (tmp_path / CANDIDATE_FILE).read_bytes() == source_before
    items = _read_typed_queue_work_items(tmp_path / "verification_queue.md")
    assert {item.work_item_id for item in items} == {"M-01", "CH-17"}
    assert queue_record_set_digest(items) == outcome.status["after_queue_digest"]
    assert {row["finding id"] for row in parse_verification_queue_rows(tmp_path)} == {
        "M-01", "CH-17",
    }
    assert json.loads((tmp_path / RECEIPT_FILE).read_text(encoding="utf-8"))[
        "proof_authority"
    ] == "NONE"
    assert json.loads((tmp_path / DEBT_FILE).read_text(encoding="utf-8"))[
        "state"
    ] == "INACTIVE"
    assert json.loads((tmp_path / JOURNAL_FILE).read_text(encoding="utf-8"))[
        "state"
    ] == "COMMITTED"


def test_committed_resume_is_byte_exact_and_does_not_rebind(
    tmp_path: Path,
) -> None:
    config = _ready(tmp_path)
    first = run_p0af_v2_queue_delivery(tmp_path, config)
    before = {
        **_queue_bytes(tmp_path),
        **{
            name: (tmp_path / name).read_bytes()
            for name in (RECEIPT_FILE, DEBT_FILE, STATUS_FILE, JOURNAL_FILE)
        },
    }

    second = run_p0af_v2_queue_delivery(tmp_path, config)

    after = {
        **_queue_bytes(tmp_path),
        **{
            name: (tmp_path / name).read_bytes()
            for name in (RECEIPT_FILE, DEBT_FILE, STATUS_FILE, JOURNAL_FILE)
        },
    }
    assert first.status == second.status
    assert before == after


def test_prepared_multifile_commit_recovers_deterministically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _ready(tmp_path)
    original_replace = os.replace
    calls = 0

    def interrupt_once(source, destination):
        nonlocal calls
        destination_path = Path(destination)
        if destination_path.parent == tmp_path and destination_path.name.startswith(
            "verification_queue"
        ):
            calls += 1
            if calls == 2:
                raise OSError("fixture crash after first queue replacement")
        return original_replace(source, destination)

    monkeypatch.setattr(os, "replace", interrupt_once)
    with pytest.raises(P0AFV2QueueRuntimeError):
        run_p0af_v2_queue_delivery(tmp_path, config)
    assert json.loads((tmp_path / JOURNAL_FILE).read_text(encoding="utf-8"))[
        "state"
    ] == "PREPARED"

    monkeypatch.setattr(os, "replace", original_replace)
    recovered = run_p0af_v2_queue_delivery(tmp_path, config)

    assert recovered.committed is True
    assert {item.work_item_id for item in _read_typed_queue_work_items(
        tmp_path / "verification_queue.md"
    )} == {"M-01", "CH-17"}
    assert json.loads((tmp_path / JOURNAL_FILE).read_text(encoding="utf-8"))[
        "state"
    ] == "COMMITTED"


def test_upstream_byte_drift_cannot_be_reblessed_or_mutate_queue(
    tmp_path: Path,
) -> None:
    config = _ready(tmp_path)
    before = _queue_bytes(tmp_path)
    (tmp_path / CANDIDATE_FILE).write_bytes(
        (tmp_path / CANDIDATE_FILE).read_bytes() + b" "
    )

    outcome = run_p0af_v2_queue_delivery(tmp_path, config)

    assert outcome.committed is False
    assert outcome.issues
    assert _queue_bytes(tmp_path) == before
    assert json.loads((tmp_path / STATUS_FILE).read_text(encoding="utf-8"))[
        "state"
    ] == "COMPLETED_WITH_DEBT"


def test_committed_status_tamper_fails_visible_without_queue_mutation(
    tmp_path: Path,
) -> None:
    config = _ready(tmp_path)
    run_p0af_v2_queue_delivery(tmp_path, config)
    before = _queue_bytes(tmp_path)
    status = json.loads((tmp_path / STATUS_FILE).read_text(encoding="utf-8"))
    status["after_queue_digest"] = "f" * 64
    (tmp_path / STATUS_FILE).write_text(json.dumps(status), encoding="utf-8")

    outcome = run_p0af_v2_queue_delivery(tmp_path, config)

    assert outcome.committed is False
    assert outcome.issues
    assert _queue_bytes(tmp_path) == before


def test_real_driver_boundary_delivers_before_live_legacy_claude_sharding(
    tmp_path: Path,
) -> None:
    config = _ready(tmp_path)

    safe, issues = DRIVER._run_p0af_v2_live_queue_boundary(tmp_path, config)
    shards = ensure_sc_verify_shard_manifests(
        tmp_path, p0af_runtime_config=config
    )

    assert safe is True
    assert issues == []
    assert {
        str(row.get("finding id") or "")
        for rows in shards.values()
        for row in rows
    } >= {"M-01", "CH-17"}
