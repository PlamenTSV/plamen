"""P0-AI/P0-G: verifier proposals and method debt have live consumers."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import uuid

import pytest

import verification_method_compiler as V
import plamen_driver as DRIVER
from assurance_limitations import (
    VERIFICATION_CONFIDENCE,
    project_assurance_limitations,
)
from queue_work_items import queue_records_to_json
from verification_operator_consumers import (
    ConsumerAuthorityError,
    build_verifier_operator_consumer_authority,
    validate_verifier_operator_consumer_authority,
    write_or_validate_verifier_operator_consumer_authority,
)


ROOT = Path(__file__).resolve().parent.parent


def _dispatch_and_receipt(
    tmp_path: Path,
    *,
    work_id: str = "H-01",
    pipeline: str = "sc",
    ecosystem: str = "evm",
    backend: str = "claude",
    blocked: bool = False,
    observations: int = 1,
) -> tuple[dict[str, object], Path]:
    queue_path = tmp_path / "verification_queue.work_items.json"
    if not queue_path.is_file():
        queue_path.write_text(
            queue_records_to_json(()) + "\n",
            encoding="utf-8",
        )
    packet_unsigned = {
        "packet_id": f"VCTX-{work_id}",
        "work_item_id": work_id,
        "state": "RESOLVED",
        "seed_locations": ["src/Vault.sol:10-20:settle"],
        "graph_matches": [{
            "artifact": "caller_map.md",
            "line": 2,
            "excerpt": "settle <- finalize",
        }],
        "expansion_candidates": ["src/Router.sol"],
        "hub_truncated": False,
        "fanout_limit": 8,
        "primary_artifact_bindings": [],
        "primary_artifact_binding_complete": True,
        "graph_binding_complete": True,
    }
    packet = {
        **packet_unsigned,
        "packet_digest": V.stable_digest(packet_unsigned),
    }
    row = {
        "work_item_id": work_id,
        "poc_class": "unit",
        "bug_class": "state-accounting",
    }
    dispatch = V.compile_verification_method_dispatch(
        pipeline=pipeline,
        ecosystem=ecosystem,
        backend=backend,
        rows=[row],
        context_packets={work_id: packet},
        manifest_path="verification_queue_recovery.md",
        scratchpad_path=str(tmp_path),
        root=ROOT,
    )
    dispatch_row = dispatch["rows"][0]
    operators = []
    for index, operator_id in enumerate(dispatch_row["operator_ids"]):
        if blocked and index == 0:
            operators.append({
                "operator_id": operator_id,
                "status": "BLOCKED",
                "evidence": [],
                "predicate": None,
                "debt_code": "EVIDENCE_UNAVAILABLE",
                "blocker_evidence": ["toolchain unavailable"],
            })
        else:
            operators.append({
                "operator_id": operator_id,
                "status": "APPLIED",
                "evidence": [{
                    "source": "src/Vault.sol:10-20",
                    "detail": "Traced the assigned transition and its caller.",
                }],
                "predicate": None,
                "debt_code": None,
                "blocker_evidence": [],
            })
    proposal = {
        "schema_version": V.OPERATOR_PROPOSAL_SCHEMA,
        "work_item_id": work_id,
        "method_dispatch_id": dispatch["dispatch_id"],
        "selected_module_hashes": dispatch_row["module_hashes"],
        "context_packet_digest": dispatch_row["context_packet_digest"],
        "context_status": "RESOLVED",
        "context_expansion": [],
        "operators": operators,
        "new_observations": [
            {
                "title": f"Separate transition {index}",
                "mechanism": "A distinct transition is outside the assigned proof scope.",
                "location": f"src/Vault.sol:{40 + index}",
                "evidence": f"src/Vault.sol:{40 + index}",
            }
            for index in range(observations)
        ],
    }
    proposal_path = tmp_path / f"verify_{work_id}.operator_application.json"
    verify_path = tmp_path / f"verify_{work_id}.md"
    receipt_path = tmp_path / f"verify_{work_id}.operator_receipt.json"
    proposal_path.write_text(json.dumps(proposal), encoding="utf-8")
    verify_path.write_text(
        "# Verification\n\n**Verdict**: CONTESTED\n", encoding="utf-8"
    )
    V.bind_operator_application_receipt(
        proposal_path=proposal_path,
        verify_path=verify_path,
        receipt_path=receipt_path,
        dispatch=dispatch,
        launch_digest="a" * 64,
        verdict="CONTESTED",
        root=ROOT,
    )
    return dispatch, receipt_path


@pytest.mark.parametrize(
    "pipeline,ecosystem,backend",
    [
        ("sc", "evm", "claude"),
        ("sc", "soroban", "codex"),
        ("l1", "go", "claude"),
        ("l1", "mixed", "codex"),
    ],
)
def test_new_observation_enters_distinct_bounded_late_queue(
    tmp_path: Path, pipeline: str, ecosystem: str, backend: str
) -> None:
    _dispatch, receipt_path = _dispatch_and_receipt(
        tmp_path,
        pipeline=pipeline,
        ecosystem=ecosystem,
        backend=backend,
    )
    authority = build_verifier_operator_consumer_authority(
        run_id="run-1",
        receipt_paths=[receipt_path],
        scratchpad=tmp_path,
        max_rows_per_shard=4,
    )

    assert authority["status"] == "LATE_VERIFICATION_REQUIRED"
    assert authority["source_receipt_count"] == 1
    assert authority["candidate_count"] == 1
    candidate = authority["candidates"][0]
    assert candidate["candidate_state"] == "PROPOSED_REQUIRES_INDEPENDENT_VERIFICATION"
    assert candidate["terminal_authority"] is False
    assert candidate["severity_proposal"] == "Unknown"
    assert candidate["source_work_item_id"] == "H-01"
    work = authority["late_verification_shards"][0]["rows"][0]
    assert work["work_item_id"] == candidate["candidate_id"]
    assert work["source_candidate_digest"] == candidate["candidate_digest"]
    assert work["independent_discriminator_required"] is True
    assert work["producer_identity"] != work["required_discriminator_identity"]
    assert len(authority["late_verification_shards"]) == 1


def test_blocked_operator_becomes_exact_report_visible_assurance_debt(
    tmp_path: Path,
) -> None:
    _dispatch, receipt_path = _dispatch_and_receipt(
        tmp_path, blocked=True, observations=0
    )
    authority = build_verifier_operator_consumer_authority(
        run_id="run-1", receipt_paths=[receipt_path], scratchpad=tmp_path
    )

    assert authority["status"] == "ASSURANCE_DEBT_ONLY"
    assert authority["candidate_count"] == 0
    assert authority["assurance_debt_count"] == 1
    debt = authority["assurance_debts"][0]
    assert debt["debt_code"] == "EVIDENCE_UNAVAILABLE"
    assert debt["report_visible"] is True
    assert debt["terminal_authority"] is False
    assert debt["verification_confidence_effect"] == "REDUCED"
    assert debt["affected_work_item_id"] == "H-01"
    assert debt["source_operator_receipt_sha256"] == hashlib.sha256(
        receipt_path.read_bytes()
    ).hexdigest()


def test_late_queue_is_lossless_and_bounded_without_touching_primary_plan(
    tmp_path: Path,
) -> None:
    primary = tmp_path / "verification_queue_work_plan.json"
    primary.write_bytes(b"primary-plan-must-not-change\n")
    receipts = []
    for index in range(3):
        _dispatch, path = _dispatch_and_receipt(
            tmp_path,
            work_id=f"H-{index + 1:02d}",
            observations=3,
        )
        receipts.append(path)
    before = primary.read_bytes()

    authority = build_verifier_operator_consumer_authority(
        run_id="run-1",
        receipt_paths=receipts,
        scratchpad=tmp_path,
        max_rows_per_shard=4,
    )

    assert [len(row["rows"]) for row in authority["late_verification_shards"]] == [4, 4, 1]
    flattened = [
        row["work_item_id"]
        for shard in authority["late_verification_shards"]
        for row in shard["rows"]
    ]
    assert len(flattened) == len(set(flattened)) == 9
    assert primary.read_bytes() == before


def test_consumer_authority_is_idempotent_and_fails_closed_on_tamper(
    tmp_path: Path,
) -> None:
    _dispatch, receipt_path = _dispatch_and_receipt(tmp_path)
    authority = build_verifier_operator_consumer_authority(
        run_id="run-1", receipt_paths=[receipt_path], scratchpad=tmp_path
    )
    target = tmp_path / "verification_operator_consumer_authority.json"
    assert write_or_validate_verifier_operator_consumer_authority(target, authority)
    before = target.stat().st_mtime_ns
    assert not write_or_validate_verifier_operator_consumer_authority(target, authority)
    assert target.stat().st_mtime_ns == before

    tampered = copy.deepcopy(authority)
    tampered["candidates"][0]["title"] = "changed"
    with pytest.raises(ConsumerAuthorityError, match="digest"):
        validate_verifier_operator_consumer_authority(tampered)
    receipt_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ConsumerAuthorityError, match="source receipt"):
        write_or_validate_verifier_operator_consumer_authority(target, authority)


def test_validator_recomputes_every_derived_projection_from_bound_receipts(
    tmp_path: Path,
) -> None:
    _dispatch, receipt_path = _dispatch_and_receipt(tmp_path)
    authority = build_verifier_operator_consumer_authority(
        run_id="run-1", receipt_paths=[receipt_path], scratchpad=tmp_path
    )
    tampered = copy.deepcopy(authority)
    shard = tampered["late_verification_shards"][0]
    shard["rows"][0]["title"] = "locally re-digested but source-unbound title"
    shard_unsigned = {key: value for key, value in shard.items() if key != "shard_digest"}
    shard["shard_digest"] = hashlib.sha256(
        json.dumps(
            shard_unsigned, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    authority_unsigned = {
        key: value for key, value in tampered.items() if key != "authority_digest"
    }
    tampered["authority_digest"] = hashlib.sha256(
        json.dumps(
            authority_unsigned, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ConsumerAuthorityError, match="recomputed|source"):
        validate_verifier_operator_consumer_authority(
            tampered, scratchpad=tmp_path
        )


def test_duplicate_or_malformed_receipt_cannot_create_terminal_candidate(
    tmp_path: Path,
) -> None:
    _dispatch, receipt_path = _dispatch_and_receipt(tmp_path)
    with pytest.raises(ConsumerAuthorityError, match="duplicate"):
        build_verifier_operator_consumer_authority(
            run_id="run-1",
            receipt_paths=[receipt_path, receipt_path],
            scratchpad=tmp_path,
        )
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    payload["new_observations"][0]["terminal_authority"] = True
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ConsumerAuthorityError, match="receipt digest|terminal"):
        build_verifier_operator_consumer_authority(
            run_id="run-1", receipt_paths=[receipt_path], scratchpad=tmp_path
        )


def test_cross_platform_source_path_is_canonical_relative_identity(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "units" / "verify-0001"
    nested.mkdir(parents=True)
    _dispatch, original = _dispatch_and_receipt(tmp_path)
    moved = nested / original.name
    moved.write_bytes(original.read_bytes())
    original.unlink()

    authority = build_verifier_operator_consumer_authority(
        run_id="run-1", receipt_paths=[moved], scratchpad=tmp_path
    )
    assert authority["source_receipts"][0]["path"] == (
        "units/verify-0001/verify_H-01.operator_receipt.json"
    )
    assert "\\" not in authority["source_receipts"][0]["path"]


def test_source_receipt_change_invalidates_exact_consumer_authority(
    tmp_path: Path,
) -> None:
    _dispatch, receipt_path = _dispatch_and_receipt(tmp_path)
    authority = build_verifier_operator_consumer_authority(
        run_id="run-1", receipt_paths=[receipt_path], scratchpad=tmp_path
    )
    target = tmp_path / "verification_operator_consumer_authority.json"
    write_or_validate_verifier_operator_consumer_authority(target, authority)
    receipt_path.write_bytes(receipt_path.read_bytes() + b" ")
    with pytest.raises(ConsumerAuthorityError, match="source receipt"):
        write_or_validate_verifier_operator_consumer_authority(target, authority)


def test_live_consumer_routes_observation_without_mutating_primary_authority(
    tmp_path: Path, monkeypatch
) -> None:
    _dispatch, receipt_path = _dispatch_and_receipt(tmp_path)
    primary_queue = tmp_path / "verification_queue.md"
    primary_plan = tmp_path / "verification_queue_work_plan.json"
    primary_roster = tmp_path / "verification_runtime_roster.json"
    primary_queue.write_bytes(b"primary queue\n")
    primary_plan.write_bytes(b"primary plan\n")
    primary_roster.write_bytes(b"primary roster\n")
    before = {
        path: path.read_bytes()
        for path in (primary_queue, primary_plan, primary_roster)
    }
    monkeypatch.setattr(
        DRIVER,
        "_initial_verifier_operator_receipt_denominator",
        lambda _scratchpad: [receipt_path],
    )
    calls = []

    def recover(config, missing):
        calls.append((config["_verification_recovery_kind"], list(missing)))
        return []

    monkeypatch.setattr(DRIVER, "_run_verify_recovery_shard", recover)
    result = DRIVER._consume_verifier_operator_receipts({
        "scratchpad": str(tmp_path), "project_root": str(tmp_path),
        "pipeline": "sc", "language": "evm", "cli_backend": "claude",
        "mode": "core", "_run_id": "run-1",
    })
    assert len(result["promoted"]) == 1
    assert result["verified"] == result["promoted"]
    assert result["unresolved"] == []
    assert calls[0][0] == "POST_VERIFY_SIDE_OBSERVATION"
    assert calls[0][1][0][0].startswith("VER-")
    authority = validate_verifier_operator_consumer_authority(
        json.loads(
            (tmp_path / "verification_operator_consumer_authority.json")
            .read_text(encoding="utf-8")
        )
    )
    assert authority["candidate_count"] == 1
    assert authority["candidates"][0]["terminal_authority"] is False
    assert {path: path.read_bytes() for path in before} == before


def test_operator_only_late_candidate_reaches_full_fallback_delivery_and_review(
    tmp_path: Path, monkeypatch
) -> None:
    _dispatch, receipt_path = _dispatch_and_receipt(tmp_path)
    authority = build_verifier_operator_consumer_authority(
        run_id="run-1", receipt_paths=[receipt_path], scratchpad=tmp_path
    )
    write_or_validate_verifier_operator_consumer_authority(
        tmp_path / "verification_operator_consumer_authority.json", authority
    )
    candidate = authority["candidates"][0]
    candidate_id = candidate["candidate_id"]
    monkeypatch.setattr(
        DRIVER, "_consume_verifier_operator_receipts",
        lambda _config: {
            "promoted": [candidate_id], "verified": [], "unresolved": [candidate_id]
        },
    )
    monkeypatch.setattr(DRIVER, "_generate_verify_core_if_missing", lambda _root: None)

    result = DRIVER._route_post_verify_late_candidates({
        "scratchpad": str(tmp_path), "project_root": str(tmp_path),
        "pipeline": "sc", "language": "evm", "cli_backend": "claude",
        "mode": "core", "_run_id": "run-1",
    })

    assert result["unresolved"] == [candidate_id]
    fallback = (tmp_path / f"verify_{candidate_id}.md").read_text(encoding="utf-8")
    assert candidate["mechanism"] in fallback
    assert candidate["evidence"] in fallback
    assert candidate["candidate_digest"] in fallback
    delivery = json.loads(
        (tmp_path / "post_verify_late_delivery.json").read_text(encoding="utf-8")
    )
    row = delivery["rows"][0]
    assert row["candidate_id"] == candidate_id
    assert row["delivery_state"] == "UNVERIFIED_HUMAN_REVIEW"
    assert row["source_candidate_digest"] == candidate["candidate_digest"]
    assert row["source_operator_receipt"] == candidate["source_operator_receipt"]

    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text("# Report\n", encoding="utf-8")
    checkpoint = SimpleNamespace(run_id="run-1", phase_commits={}, degraded=[])
    assert project_assurance_limitations(checkpoint, tmp_path, report) >= 1
    projected = json.loads(
        (tmp_path / "assurance_limitations.json").read_text(encoding="utf-8")
    )
    review = next(
        item for item in projected["rows"]
        if candidate_id in item["affected_identities"]
    )
    assert review["gate_id"] == "verification_operator_candidate_unresolved"


def test_late_delivery_cannot_hide_operator_debt_with_self_consistent_tampering(
    tmp_path: Path, monkeypatch
) -> None:
    _dispatch, receipt_path = _dispatch_and_receipt(tmp_path)
    authority = build_verifier_operator_consumer_authority(
        run_id="run-1", receipt_paths=[receipt_path], scratchpad=tmp_path
    )
    write_or_validate_verifier_operator_consumer_authority(
        tmp_path / "verification_operator_consumer_authority.json", authority
    )
    candidate = authority["candidates"][0]
    candidate_id = candidate["candidate_id"]
    monkeypatch.setattr(
        DRIVER,
        "_consume_verifier_operator_receipts",
        lambda _config: {
            "promoted": [candidate_id],
            "verified": [],
            "unresolved": [candidate_id],
        },
    )
    monkeypatch.setattr(DRIVER, "_generate_verify_core_if_missing", lambda _root: None)
    DRIVER._route_post_verify_late_candidates({
        "scratchpad": str(tmp_path), "project_root": str(tmp_path),
        "pipeline": "sc", "language": "evm", "cli_backend": "claude",
        "mode": "core", "_run_id": "run-1",
    })

    delivery_path = tmp_path / "post_verify_late_delivery.json"
    delivery = json.loads(delivery_path.read_text(encoding="utf-8"))
    delivery["rows"][0]["source_candidate_digest"] = "0" * 64
    unsigned = {
        key: value for key, value in delivery.items()
        if key != "receipt_sha256"
    }
    delivery["receipt_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    delivery_path.write_text(json.dumps(delivery), encoding="utf-8")

    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text("# Report\n", encoding="utf-8")
    checkpoint = SimpleNamespace(run_id="run-1", phase_commits={}, degraded=[])
    project_assurance_limitations(checkpoint, tmp_path, report)
    projected = json.loads(
        (tmp_path / "assurance_limitations.json").read_text(encoding="utf-8")
    )
    invalid = next(
        item for item in projected["rows"]
        if item["gate_id"] == "verification_operator_delivery_invalid"
    )
    assert invalid["affected_identities"] == [candidate_id]
    assert not any(
        item["gate_id"] == "verification_operator_candidate_unresolved"
        and candidate_id in item["affected_identities"]
        for item in projected["rows"]
    )


def test_operator_summary_cannot_bypass_recovery_execution_authority(
    tmp_path: Path, monkeypatch
) -> None:
    _dispatch, receipt_path = _dispatch_and_receipt(tmp_path)
    authority = build_verifier_operator_consumer_authority(
        run_id="run-1", receipt_paths=[receipt_path], scratchpad=tmp_path
    )
    write_or_validate_verifier_operator_consumer_authority(
        tmp_path / "verification_operator_consumer_authority.json", authority
    )
    candidate = authority["candidates"][0]
    candidate_id = candidate["candidate_id"]
    (tmp_path / f"verify_{candidate_id}.md").write_text(
        "# Independent verification\n\n**Severity**: Medium\n"
        "**Evidence Tag**: [CODE-TRACE]\n**Verdict**: CONTESTED\n\n"
        + ("bounded independent evidence\n" * 8),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        DRIVER, "_consume_verifier_operator_receipts",
        lambda _config: {
            "promoted": [candidate_id], "verified": [candidate_id], "unresolved": []
        },
    )
    monkeypatch.setattr(DRIVER, "_generate_verify_core_if_missing", lambda _root: None)
    mechanical_calls = []
    monkeypatch.setitem(
        sys.modules,
        "mechanical_verify",
        SimpleNamespace(
            run_phase5b_mechanical_verify=lambda *args: mechanical_calls.append(args)
        ),
    )

    result = DRIVER._route_post_verify_late_candidates({
        "scratchpad": str(tmp_path), "project_root": str(tmp_path),
        "pipeline": "sc", "language": "evm", "cli_backend": "claude",
        "mode": "core", "_run_id": "run-1",
    })

    assert result["verified"] == []
    assert result["unresolved"] == [candidate_id]
    assert mechanical_calls == []
    delivery = json.loads(
        (tmp_path / "post_verify_late_delivery.json").read_text(encoding="utf-8")
    )
    assert delivery["proof_authority"] == "NONE"
    assert delivery["rows"][0]["delivery_state"] == (
        "UNVERIFIED_HUMAN_REVIEW"
    )
    assert delivery["rows"][0]["source_candidate_digest"] == candidate[
        "candidate_digest"
    ]


def test_primary_operator_denominator_is_current_exact_and_missing_is_debt(
    tmp_path: Path, monkeypatch
) -> None:
    from test_dynamic_verifier_runtime_integration_p0_ak import (
        _bind_sc_shared_context_producer, _ignore_poc_gate, _proposal_bytes,
        _setup_plan, _verify_bytes, _write_operator_application,
    )
    from verifier_work_roster import build_verifier_runtime_policy, build_verifier_work_roster

    scratchpad, phase_name, items, plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    phase = next(item for item in DRIVER.SC_PHASES if item.name == phase_name)
    roster = build_verifier_work_roster(
        plan, pipeline="sc", ecosystem="evm", mode="thorough",
        runtime_policy=build_verifier_runtime_policy(
            backend="claude", model="sonnet", transport="pty",
            timeout_seconds=60, source_root=str(tmp_path.resolve()),
        ),
        method_registry_digest="1" * 64, context_packet_digest="2" * 64,
    )
    (scratchpad / DRIVER._DYNAMIC_VERIFIER_ROSTER_NAME).write_text(
        roster.to_json(), encoding="utf-8"
    )
    unit = roster.work_units[0]

    def fake_execute(spec, **_kwargs):
        item = items[0]
        (scratchpad / item.expected_output_file).write_bytes(_verify_bytes(item.work_item_id))
        (scratchpad / f"verify_{item.work_item_id}.severity_proposal.json").write_bytes(
            _proposal_bytes(item)
        )
        _write_operator_application(scratchpad, unit.work_unit_id, item.work_item_id)
        return 0

    monkeypatch.setattr(DRIVER, "_execute_dynamic_verifier_launch", fake_execute)
    _ignore_poc_gate(monkeypatch)
    config = {
        "pipeline": "sc", "mode": "thorough", "language": "evm",
        "cli_backend": "claude", "claude_exec_mode": "pty",
        "project_root": str(tmp_path.resolve()), "scratchpad": str(scratchpad),
        "_run_id": str(uuid.uuid4()),
    }
    _bind_sc_shared_context_producer(
        scratchpad,
        tmp_path,
        items,
        run_id=config["_run_id"],
    )
    assert DRIVER._run_dynamic_verifier_unit(
        phase, scratchpad, config, roster, unit
    ) == []
    assert DRIVER._initial_verifier_operator_receipt_denominator(scratchpad) == [
        scratchpad / "verify_H-01.operator_receipt.json"
    ]

    (scratchpad / "verify_H-01.operator_receipt.json").unlink()
    assert DRIVER._initial_verifier_operator_receipt_denominator(scratchpad) == []
    denominator = json.loads(
        (scratchpad / "verification_operator_denominator_authority.json")
        .read_text(encoding="utf-8")
    )
    assert denominator["status"] == "COMPLETED_WITH_DEBT"
    assert denominator["expected_work_item_ids"] == ["H-01"]
    debt = denominator["debts"][0]
    assert debt["debt_code"] == "EXPECTED_OPERATOR_RECEIPT_MISSING_OR_UNBOUND"
    assert debt["affected_work_item_ids"] == ["H-01"]


def test_operator_debt_reaches_driver_owned_human_review_projection(
    tmp_path: Path,
) -> None:
    _dispatch, receipt_path = _dispatch_and_receipt(
        tmp_path, blocked=True, observations=0
    )
    authority = build_verifier_operator_consumer_authority(
        run_id="run-1", receipt_paths=[receipt_path], scratchpad=tmp_path
    )
    write_or_validate_verifier_operator_consumer_authority(
        tmp_path / "verification_operator_consumer_authority.json", authority
    )
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text("# Report\n", encoding="utf-8")
    checkpoint = SimpleNamespace(run_id="run-1", phase_commits={}, degraded=[])

    assert project_assurance_limitations(checkpoint, tmp_path, report) == 1
    projected = json.loads(
        (tmp_path / "assurance_limitations.json").read_text(encoding="utf-8")
    )
    row = projected["rows"][0]
    assert row["assurance_impact"] == VERIFICATION_CONFIDENCE
    assert row["gate_class"] == "METHODOLOGY_APPLICATION"
    assert row["affected_identities"] == ["H-01"]
    assert "operator" in report.read_text(encoding="utf-8").lower()
