"""P0-G: late-delivery state is derived from recovery execution authority."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import plamen_driver as DRIVER
from assurance_limitations import project_assurance_limitations
from test_verification_operator_consumers_p0_ai_g import _dispatch_and_receipt
from test_verification_recovery_contract_p0_ai import _emit_recovery_outputs, _row
from verification_operator_consumers import (
    build_verifier_operator_consumer_authority,
    write_or_validate_verifier_operator_consumer_authority,
)


def _write_delivery(
    scratchpad: Path,
    *,
    authority: dict[str, object],
    state: str,
) -> str:
    candidate = authority["candidates"][0]
    work = authority["late_verification_shards"][0]["rows"][0]
    candidate_id = candidate["candidate_id"]
    verify_path = scratchpad / f"verify_{candidate_id}.md"
    row = {
        "candidate_id": candidate_id,
        "delivery_state": state,
        "verify_artifact": verify_path.name,
        "verify_sha256": hashlib.sha256(verify_path.read_bytes()).hexdigest(),
        "source_candidate_digest": candidate["candidate_digest"],
        "source_work_item_id": candidate["source_work_item_id"],
        "source_operator_receipt": candidate["source_operator_receipt"],
        "source_operator_receipt_sha256": candidate[
            "source_operator_receipt_sha256"
        ],
        "source_operator_receipt_digest": candidate[
            "source_operator_receipt_digest"
        ],
        "finding_lifecycle_obligation_id": work[
            "finding_lifecycle_obligation_id"
        ],
    }
    payload = {
        "schema_version": "plamen.post_verify_late_delivery.v1",
        "proof_authority": "NONE",
        "row_count": 1,
        "rows": [row],
    }
    payload["receipt_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    (scratchpad / "post_verify_late_delivery.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    return str(candidate_id)


def _project(scratchpad: Path) -> dict[str, object]:
    report = scratchpad / "AUDIT_REPORT.md"
    report.write_text("# Report\n", encoding="utf-8")
    checkpoint = SimpleNamespace(run_id="run-1", phase_commits={}, degraded=[])
    project_assurance_limitations(checkpoint, scratchpad, report)
    return json.loads(
        (scratchpad / "assurance_limitations.json").read_text(encoding="utf-8")
    )


def test_self_consistent_delivery_state_flip_cannot_manufacture_verification(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "repo"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _dispatch, receipt_path = _dispatch_and_receipt(scratchpad)
    authority = build_verifier_operator_consumer_authority(
        run_id="run-1", receipt_paths=[receipt_path], scratchpad=scratchpad
    )
    write_or_validate_verifier_operator_consumer_authority(
        scratchpad / "verification_operator_consumer_authority.json", authority
    )
    work = authority["late_verification_shards"][0]["rows"][0]

    def unresolved_execution(spec, *, prompt_path, scratchpad, **_kwargs):
        _emit_recovery_outputs(
            spec, prompt_path=prompt_path, scratchpad=scratchpad
        )
        (scratchpad / f"verify_{work['work_item_id']}.operator_application.json").unlink()
        return 0

    monkeypatch.setattr(
        DRIVER, "_execute_dynamic_verifier_launch", unresolved_execution
    )
    config = {
        "scratchpad": str(scratchpad),
        "project_root": str(project),
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "claude",
        "mode": "core",
        "_run_id": "run-1",
        "_verification_recovery_kind": "POST_VERIFY_SIDE_OBSERVATION",
    }
    assert DRIVER._run_verify_recovery_shard(
        config, [(str(work["work_item_id"]), dict(work))]
    ) == [work["work_item_id"]]

    candidate_id = _write_delivery(
        scratchpad, authority=authority, state="UNVERIFIED_HUMAN_REVIEW"
    )
    initial = _project(scratchpad)
    assert any(
        row["gate_id"] == "verification_operator_candidate_unresolved"
        and candidate_id in row["affected_identities"]
        for row in initial["rows"]
    )

    # The delivery file and its digest are both driver-owned. Rewriting only
    # that state used to suppress the human-review row even though the exact
    # recovery execution receipt still records this candidate as unresolved.
    _write_delivery(
        scratchpad,
        authority=authority,
        state="INDEPENDENT_VERIFICATION_RECORDED",
    )
    tampered = _project(scratchpad)
    assert any(
        row["gate_id"] == "verification_operator_delivery_state_unbound"
        and candidate_id in row["affected_identities"]
        for row in tampered["rows"]
    )
    assert any(
        row["gate_id"] == "verification_operator_candidate_unresolved"
        and candidate_id in row["affected_identities"]
        for row in tampered["rows"]
    )


def test_human_review_state_is_never_auto_upgraded_by_recovery_authority(
    tmp_path: Path,
) -> None:
    """The conservative delivery state remains monotonic even without recovery."""

    _dispatch, receipt_path = _dispatch_and_receipt(tmp_path)
    authority = build_verifier_operator_consumer_authority(
        run_id="run-1", receipt_paths=[receipt_path], scratchpad=tmp_path
    )
    write_or_validate_verifier_operator_consumer_authority(
        tmp_path / "verification_operator_consumer_authority.json", authority
    )
    candidate_id = authority["candidates"][0]["candidate_id"]
    verify_path = tmp_path / f"verify_{candidate_id}.md"
    verify_path.write_text("# Human review fallback\n", encoding="utf-8")
    _write_delivery(
        tmp_path, authority=authority, state="UNVERIFIED_HUMAN_REVIEW"
    )

    projected = _project(tmp_path)
    assert any(
        row["gate_id"] == "verification_operator_candidate_unresolved"
        and candidate_id in row["affected_identities"]
        for row in projected["rows"]
    )


def test_exact_resolved_recovery_authorizes_positive_delivery_but_not_upgrade(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "repo"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _dispatch, receipt_path = _dispatch_and_receipt(scratchpad)
    authority = build_verifier_operator_consumer_authority(
        run_id="run-1", receipt_paths=[receipt_path], scratchpad=scratchpad
    )
    write_or_validate_verifier_operator_consumer_authority(
        scratchpad / "verification_operator_consumer_authority.json", authority
    )
    work = authority["late_verification_shards"][0]["rows"][0]

    def resolved_execution(spec, *, prompt_path, scratchpad, **_kwargs):
        _emit_recovery_outputs(
            spec, prompt_path=prompt_path, scratchpad=scratchpad
        )
        return 0

    monkeypatch.setattr(DRIVER, "_execute_dynamic_verifier_launch", resolved_execution)
    config = {
        "scratchpad": str(scratchpad),
        "project_root": str(project),
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "claude",
        "mode": "core",
        "_run_id": "run-1",
        "_verification_recovery_kind": "POST_VERIFY_SIDE_OBSERVATION",
    }
    assert DRIVER._run_verify_recovery_shard(
        config, [(str(work["work_item_id"]), dict(work))]
    ) == []

    candidate_id = _write_delivery(
        scratchpad,
        authority=authority,
        state="INDEPENDENT_VERIFICATION_RECORDED",
    )
    verified = _project(scratchpad)
    assert not any(
        candidate_id in row["affected_identities"] for row in verified["rows"]
    )

    # Even valid recovery evidence cannot silently replace the delivery
    # writer's conservative request for human review.
    _write_delivery(
        scratchpad, authority=authority, state="UNVERIFIED_HUMAN_REVIEW"
    )
    conservative = _project(scratchpad)
    assert any(
        row["gate_id"] == "verification_operator_candidate_unresolved"
        and candidate_id in row["affected_identities"]
        for row in conservative["rows"]
    )


def test_rewritten_output_and_delivery_digests_do_not_replay_execution(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "repo"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _dispatch, receipt_path = _dispatch_and_receipt(scratchpad)
    authority = build_verifier_operator_consumer_authority(
        run_id="run-1", receipt_paths=[receipt_path], scratchpad=scratchpad
    )
    write_or_validate_verifier_operator_consumer_authority(
        scratchpad / "verification_operator_consumer_authority.json", authority
    )
    work = authority["late_verification_shards"][0]["rows"][0]

    monkeypatch.setattr(
        DRIVER,
        "_execute_dynamic_verifier_launch",
        lambda spec, *, prompt_path, scratchpad, **_kwargs: (
            _emit_recovery_outputs(
                spec, prompt_path=prompt_path, scratchpad=scratchpad
            )
            or 0
        ),
    )
    config = {
        "scratchpad": str(scratchpad),
        "project_root": str(project),
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "claude",
        "mode": "core",
        "_run_id": "run-1",
        "_verification_recovery_kind": "POST_VERIFY_SIDE_OBSERVATION",
    }
    assert DRIVER._run_verify_recovery_shard(
        config, [(str(work["work_item_id"]), dict(work))]
    ) == []
    candidate_id = str(work["work_item_id"])
    (scratchpad / f"verify_{candidate_id}.md").write_text(
        "# Rewritten verifier projection\n", encoding="utf-8"
    )
    _write_delivery(
        scratchpad,
        authority=authority,
        state="INDEPENDENT_VERIFICATION_RECORDED",
    )

    projected = _project(scratchpad)
    assert any(
        row["gate_id"] == "verification_operator_delivery_state_unbound"
        and candidate_id in row["affected_identities"]
        for row in projected["rows"]
    )


def test_legacy_late_delivery_is_bound_to_its_exact_recovery_execution(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "repo"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    work_id = "VER-1"
    work = _row(work_id)
    monkeypatch.setattr(
        DRIVER,
        "_execute_dynamic_verifier_launch",
        lambda spec, *, prompt_path, scratchpad, **_kwargs: (
            _emit_recovery_outputs(
                spec, prompt_path=prompt_path, scratchpad=scratchpad
            )
            or 0
        ),
    )
    config = {
        "scratchpad": str(scratchpad),
        "project_root": str(project),
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "claude",
        "mode": "core",
        "_run_id": "run-1",
        "_verification_recovery_kind": "POST_VERIFY_SIDE_OBSERVATION",
    }
    assert DRIVER._run_verify_recovery_shard(config, [(work_id, work)]) == []
    verify_path = scratchpad / f"verify_{work_id}.md"
    delivery_row = {
        "candidate_id": work_id,
        "delivery_state": "INDEPENDENT_VERIFICATION_RECORDED",
        "verify_artifact": verify_path.name,
        "verify_sha256": hashlib.sha256(verify_path.read_bytes()).hexdigest(),
        "source_candidate_digest": None,
        "source_work_item_id": None,
        "source_operator_receipt": None,
        "source_operator_receipt_sha256": None,
        "source_operator_receipt_digest": None,
        "finding_lifecycle_obligation_id": None,
    }
    payload = {
        "schema_version": "plamen.post_verify_late_delivery.v1",
        "proof_authority": "NONE",
        "row_count": 1,
        "rows": [delivery_row],
    }
    payload["receipt_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    (scratchpad / "post_verify_late_delivery.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    clean = _project(scratchpad)
    assert not any(
        row["gate_id"] == "verification_operator_delivery_state_unbound"
        and work_id in row["affected_identities"]
        for row in clean["rows"]
    )

    next((scratchpad / "_verification_recovery").glob("VREC-*/execution_receipt.json")).unlink()
    degraded = _project(scratchpad)
    assert any(
        row["gate_id"] == "verification_operator_delivery_state_unbound"
        and work_id in row["affected_identities"]
        for row in degraded["rows"]
    )
