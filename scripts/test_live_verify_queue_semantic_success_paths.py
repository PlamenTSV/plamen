"""Authoritative success-path fixtures for the live T0--T9 queue transaction.

The broad semantic-closure fixture proves topology and publication ownership.
These fixtures exercise the production semantic executor with real typed
producer artifacts for the additive branches that a placeholder-only run
cannot cover:

* a non-empty mandatory-reverification delta;
* the SC P0-AF evidence-fact composition receipt;
* the L1 typed composition receipt; and
* the generic SC chain-composition receipt.

Every case runs through both backends.  Backend-neutrality is semantic rather
than byte identity because the plan and final receipt intentionally bind the
backend identity.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

import pytest

import chain_tail_authority as CHAIN_AUTHORITY
from artifact_ledger import (
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from finding_producer_registry import (
    write_application_skeptic_proposal_projection,
)
import l1_composition_runtime as L1R
import live_verify_queue_prearm_inputs as PREARM
import live_verify_queue_semantics as SEMANTICS
from live_verify_queue_semantics import (
    build_live_verify_queue_semantic_executor,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import plamen_validators as V
import preverify_frozen_projection as FROZEN
from preverify_inventory_successor import (
    build_preverify_successor_payloads,
    encode_successor_payload,
)
import security_obligation_authority as SO
import test_chain_tail_compound_delivery_p0_t as CHAIN_FIXTURE
import test_live_verify_queue_transaction_semantic_closure as LIVE
import test_mandatory_reverification_nc5 as MANDATORY_FIXTURE
import test_p0af_v2_queue_adapter_p1_m as P0AF_FIXTURE
import verify_queue_transaction as TRANSACTION


PRIVATE = Path("_live_verify_queue_transaction")


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _runtime(
    *,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    run_id: str,
) -> dict[str, str]:
    return {
        **LIVE.RUNTIME_AUTHORITY_BASE,
        "pipeline": pipeline,
        "mode": mode,
        "ecosystem": ecosystem,
        "backend": backend,
        "run_id": run_id,
    }


def _resolve_plan(
    *,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    run_id: str,
    upstream: set[str],
    prearm_resolution: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    return TRANSACTION.resolve_live_verify_queue_transaction_plan(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase_name=(
            "sc_verify_queue" if pipeline == "sc" else "verify_queue"
        ),
        run_id=run_id,
        upstream_inputs=tuple(sorted(upstream)),
        runtime_authority=_runtime(
            pipeline=pipeline,
            mode=mode,
            ecosystem=ecosystem,
            backend=backend,
            run_id=run_id,
        ),
        shard_manifests=LIVE._shard_manifests(pipeline),
        context_capture=LIVE.CONTEXT_CAPTURE,
        prearm_resolution=prearm_resolution,
        preverify_frozen_projection=LIVE._frozen_projection(
            pipeline, backend, run_id=run_id
        ),
        preverify_chain_pair_projection=LIVE._chain_pair_projection(
            pipeline, backend, run_id=run_id
        ),
    )


def _empty_proposal_sources(root: Path) -> None:
    write_application_skeptic_proposal_projection(root, [])
    write_application_skeptic_proposal_projection(
        root,
        [],
        projection_name="candidate_negative_skeptic_proposals.md",
    )


def _fill_upstream_placeholders(root: Path, upstream: set[str]) -> None:
    for relative in sorted(upstream):
        path = root / relative
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = (
            b"# Authoritative success-path fixture\n"
            if path.suffix == ".md"
            else _canonical_bytes({"artifact": relative})
        )
        path.write_bytes(raw)


def _materialize_frozen_inventory_pair(
    root: Path,
    *,
    pipeline: str,
    backend: str,
    run_id: str,
) -> None:
    projection = LIVE._frozen_projection(
        pipeline,
        backend,
        run_id=run_id,
    )
    aliases = projection["logical_to_physical"]
    inventory_raw = (root / "findings_inventory.md").read_bytes()
    inventory_path = root / str(aliases["findings_inventory.md"])
    records_path = root / str(aliases["finding_records.json"])
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    inventory_path.write_bytes(inventory_raw)
    records_path.write_bytes(FROZEN._records_bytes(inventory_raw))


def _claim_upstream_authority(
    *,
    root: Path,
    project: Path,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    run_id: str,
    upstream: set[str],
) -> None:
    """Record the exact already-built fixture bytes under one PhaseIO owner."""

    phase = "preverify_success_path_fixture"
    work_unit_id = "typed_upstream"
    owner = canonical_work_unit_key(
        pipeline,
        mode,
        ecosystem,
        backend,
        phase,
        work_unit_id,
    )
    postimage = {
        relative: (root / relative).read_bytes()
        for relative in sorted(upstream)
    }
    for relative in postimage:
        (root / relative).unlink()
    contract = PhaseIOContract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase=phase,
        work_unit_id=work_unit_id,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="fixture.live-success-upstream.v1",
                minimum_gate="FIXTURE_EXACT_BYTES",
                consumers=(
                    (
                        "sc_verify_queue"
                        if pipeline == "sc"
                        else "verify_queue"
                    )
                    + "/t0.live_upstream_authority",
                    "sc_verify_queue/prearm_dynamic_inputs",
                ),
            )
            for relative in sorted(upstream)
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        model="fixture-driver",
        timeout_s=60,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
    )
    for relative, raw in postimage.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )


def _write_context_inputs(root: Path, project: Path) -> None:
    for relative in LIVE.CONTEXT_INPUTS:
        if relative.startswith("project::"):
            path = project / relative[len("project::"):]
            raw = b"// exact fixture source\n"
        else:
            path = root / relative
            raw = _canonical_bytes({"artifact": relative})
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)


def _inventory(*rows: tuple[str, str]) -> str:
    blocks = ["# Findings Inventory", ""]
    for index, (identity, severity) in enumerate(rows, start=1):
        blocks.extend(
            (
                f"### Finding [{identity}]: Candidate {identity}",
                f"**Source IDs**: [{identity}]",
                f"**Severity**: {severity}",
                f"**Location**: src/Unit.sol:L{index}",
                "**Preferred Tag**: CODE-TRACE",
                "**Primary Artifact**: breadth_findings.md",
                "",
                "**Description**: A bounded security candidate.",
                "**Impact**: A protected state property may be violated.",
                "",
            )
        )
    return "\n".join(blocks)


def _build_mandatory(
    root: Path,
    *,
    run_id: str,
) -> None:
    (root / "findings_inventory.md").write_text(
        MANDATORY_FIXTURE._seed_inventory(),
        encoding="utf-8",
    )
    write_application_skeptic_proposal_projection(
        root,
        [MANDATORY_FIXTURE._proposal("A", "Live mandatory delta")],
    )
    assert V._promote_depth_findings_to_inventory(root) == ["ASKP-1"]
    inventory_path = root / "findings_inventory.md"
    inventory = inventory_path.read_text(encoding="utf-8")
    old = (
        "### Finding [INV-002]: Live mandatory delta\n"
        "**Source IDs**: [ASKP-1, SHA-256]\n"
        "**Severity**: Medium"
    )
    new = old.rsplit("Medium", 1)[0] + "Low"
    assert old in inventory
    inventory = inventory.replace(old, new, 1)
    inventory_path.write_text(inventory, encoding="utf-8")
    write_application_skeptic_proposal_projection(
        root,
        [],
        projection_name="candidate_negative_skeptic_proposals.md",
    )
    scan = V._scan_registered_finding_delivery_sources(root)
    delivery = V._build_registered_finding_delivery_receipt_payload(
        root,
        scan,
        inventory,
    )
    final, registered = build_preverify_successor_payloads(
        root,
        run_id=run_id,
        delivery_payload=delivery,
        producer_artifacts=tuple(
            str(row["artifact"]) for row in scan["artifacts"]
        ),
    )
    (root / "preverify_inventory_successor.json").write_bytes(
        encode_successor_payload(final)
    )
    (root / "finding_delivery_successor.json").write_bytes(
        encode_successor_payload(registered)
    )


def _build_p0af(root: Path) -> None:
    P0AF_FIXTURE._artifacts(root, subject="CH-17", with_work=True)
    (root / "findings_inventory.md").write_text(
        _inventory(("INV-001", "Medium")),
        encoding="utf-8",
    )
    _empty_proposal_sources(root)


def _build_l1(root: Path, *, run_id: str) -> None:
    snapshot = LIVE.RUNTIME_AUTHORITY_BASE["audit_snapshot_digest"]
    context = {
        "pipeline": "l1",
        "mode": "thorough",
        "language": "rust",
        "run_id": run_id,
        "snapshot_digest": snapshot,
    }
    (root / L1R.INVENTORY_NAME).write_text(
        _inventory(("L1-H-1", "Medium"), ("L1-M-1", "Medium")),
        encoding="utf-8",
    )
    worklist = L1R.write_l1_composition_fact_worklist(root, **context)
    by_id = {
        str(row["candidate_id"]): row
        for row in worklist["occurrences"]
    }
    assert set(by_id) == {"L1-H-1", "L1-M-1"}
    atom = {"kind": "STATE", "atom_id": "ledger.commit"}
    typed = {
        "schema_version": L1R.TYPED_RECORDS_SCHEMA,
        "run_id": run_id,
        "snapshot_digest": snapshot,
        "producer_identity": "fact-worker",
        "producer_invocation_id": "fact-invocation",
        "records": [
            {
                "candidate_id": by_id[identity]["candidate_id"],
                "source_artifact": by_id[identity]["source_artifact"],
                "source_block_sha256": by_id[identity][
                    "source_block_sha256"
                ],
                "language": "RUST",
                "layer": (
                    "execution" if identity == "L1-H-1" else "consensus"
                ),
                "subsystem": (
                    "execution" if identity == "L1-H-1" else "consensus"
                ),
                "root_cause_id": f"ROOT-{identity}",
                "candidate_state": (
                    "REFUTED" if identity == "L1-H-1" else "CONFIRMED"
                ),
                "requires": [] if identity == "L1-H-1" else [atom],
                "produces": [atom] if identity == "L1-H-1" else [],
                "touches": [],
            }
            for identity in ("L1-H-1", "L1-M-1")
        ],
    }
    (root / L1R.TYPED_RECORDS_NAME).write_text(
        json.dumps(typed, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert L1R.validate_l1_composition_fact_records(
        root, **context
    ) == []
    runtime = L1R.write_l1_composition_runtime(root, **context)
    assert len(runtime["work_packets"]) == 1
    dispositions = {
        "schema_version": L1R.MODEL_DISPOSITIONS_SCHEMA,
        "run_id": run_id,
        "snapshot_digest": snapshot,
        "producer_identity": "disposition-worker",
        "producer_invocation_id": "disposition-invocation",
        "runtime_digest": runtime["runtime_digest"],
        "graph_digest": runtime["graph"]["graph_digest"],
        "work_packets_digest": runtime["work_packets_digest"],
        "dispositions": [
            {
                "obligation_id": runtime["work_packets"][0][
                    "obligation_id"
                ],
                "disposition": "COMPOUND_CANDIDATE",
                "rationale": (
                    "Independent composed reachability requires verification."
                ),
            }
        ],
    }
    (root / L1R.MODEL_DISPOSITIONS_NAME).write_text(
        json.dumps(dispositions, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    receipt = L1R.write_l1_composition_receipt(
        root, runtime, dispositions
    )
    assert len(receipt["compound_handoffs"]) == 1
    _empty_proposal_sources(root)


def _build_generic_compound(root: Path, project: Path) -> None:
    source_project = project / "_typed_chain_source"
    source_root = source_project / ".scratchpad"
    source_root.mkdir(parents=True)
    CHAIN_FIXTURE._publish_composition_candidate(
        source_project,
        source_root,
        heading="## CH-77 composed transition",
        evidence=(
            "CH-77 links the exact postcondition to the dependent precondition."
        ),
    )
    for relative in (
        "chain_composition_verification_candidates.json",
        "chain_tail_terminal_snapshot.json",
    ):
        (root / relative).write_bytes((source_root / relative).read_bytes())
    (root / "findings_inventory.md").write_text(
        _inventory(("H-1", "High"), ("M-1", "Medium")),
        encoding="utf-8",
    )
    _empty_proposal_sources(root)


def _prepare_case(
    project: Path,
    *,
    case: str,
    backend: str,
) -> tuple[Path, Mapping[str, Any], str]:
    pipeline = "l1" if case == "l1" else "sc"
    mode = "core" if case == "mandatory" else "thorough"
    ecosystem = "rust" if pipeline == "l1" else "evm"
    # Hold the audit/run identity constant while varying only transport/model
    # backend.  Otherwise a run-derived work identity would make a backend
    # neutrality comparison meaningless even when semantics are identical.
    run_id = f"live-{case}-backend-neutral"
    root = project / ".scratchpad"
    root.mkdir(parents=True)

    if case == "mandatory":
        _build_mandatory(root, run_id=run_id)
    elif case == "p0af":
        _build_p0af(root)
    elif case == "l1":
        _build_l1(root, run_id=run_id)
    elif case == "compound":
        _build_generic_compound(root, project)
    else:  # pragma: no cover - fixture programmer error
        raise AssertionError(f"unknown success-path case: {case}")

    upstream = set(LIVE._upstream_inputs(pipeline))
    if case == "p0af":
        upstream.add("authentication_role_fact_authority.json")
        upstream.add("_canonical_finding_ids.json")
    _fill_upstream_placeholders(root, upstream)
    _materialize_frozen_inventory_pair(
        root,
        pipeline=pipeline,
        backend=backend,
        run_id=run_id,
    )
    _claim_upstream_authority(
        root=root,
        project=project,
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        run_id=run_id,
        upstream=upstream,
    )

    resolution: Mapping[str, Any] | None = None
    if case == "p0af":
        resolution = PREARM.prepare_sc_prearm_dynamic_inputs(
            scratchpad=root,
            project_root=project,
            config={
                "pipeline": "sc",
                "mode": mode,
                "ecosystem": ecosystem,
                "backend": backend,
                "phase_name": "sc_verify_queue",
            },
            run_id=run_id,
        )
        assert resolution["state"] == "RESOLVED"
        upstream.update(map(str, resolution["t0_additional_inputs"]))

    plan = _resolve_plan(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        run_id=run_id,
        upstream=upstream,
        prearm_resolution=resolution,
    )
    _write_context_inputs(root, project)
    return root, plan, run_id


def _json(root: Path, relative: str) -> Mapping[str, Any]:
    value = json.loads((root / relative).read_text(encoding="utf-8"))
    assert isinstance(value, Mapping)
    return value


def _record_ids(payload: Mapping[str, Any]) -> set[str]:
    return {
        str(row["work_item_id"])
        for row in payload.get("rows") or ()
    }


def _delta_path(stage: int) -> str:
    return (
        PRIVATE
        / f"t{stage}"
        / "queue_delta.work_items.json"
    ).as_posix()


def _assert_source_partition(
    root: Path,
    *,
    target_source: str,
) -> tuple[set[str], dict[str, tuple[str, ...]]]:
    active = _json(
        root,
        (PRIVATE / "t2" / "active_queue.work_items.json").as_posix(),
    )
    excluded = _json(
        root,
        (PRIVATE / "t2" / "evidence_excluded.work_items.json").as_posix(),
    )
    deltas = {
        "mandatory": _json(root, _delta_path(3)),
        "pipeline": _json(root, _delta_path(4)),
        "compound": _json(root, _delta_path(5)),
    }
    accounting = _json(
        root,
        (
            PRIVATE
            / "t6"
            / "source_obligation_accounting.json"
        ).as_posix(),
    )
    final = _json(
        root,
        (PRIVATE / "t6" / "final_work_items.json").as_posix(),
    )
    final_ids = _record_ids(final)
    active_ids = _record_ids(active)
    excluded_ids = _record_ids(excluded)
    delta_ids = {
        source: tuple(sorted(_record_ids(payload)))
        for source, payload in deltas.items()
    }

    expected_rows = {
        ("policy_active", identity)
        for identity in active_ids
    }
    expected_rows.update(
        ("policy_excluded", identity)
        for identity in excluded_ids
    )
    expected_rows.update(
        (source, identity)
        for source, identities in delta_ids.items()
        for identity in identities
    )
    observed_rows = {
        (str(row["source"]), str(row["work_item_id"]))
        for row in accounting["rows"]
    }
    assert observed_rows == expected_rows
    assert accounting["exact_partition"] is True
    assert set(accounting["active_ids"]) == final_ids
    assert set(accounting["authorized_excluded_ids"]) <= excluded_ids
    assert final_ids.isdisjoint(accounting["authorized_excluded_ids"])
    assert accounting["visible_debt_ids"] == []
    assert all(
        row["disposition"] in {
            "ACTIVE", "AUTHORIZED_EXCLUDED", "VISIBLE_DEBT"
        }
        for row in accounting["rows"]
    )
    assert delta_ids[target_source]
    assert final_ids == set().union(active_ids, *map(set, delta_ids.values()))
    return final_ids, delta_ids


def _assert_context_and_shards(
    root: Path,
    final_ids: set[str],
) -> tuple[tuple[str, ...], ...]:
    context = _json(
        root,
        (
            PRIVATE
            / "t7"
            / "verification_context_packets.json"
        ).as_posix(),
    )
    shards = _json(
        root,
        (PRIVATE / "t7" / "shard_plan.json").as_posix(),
    )
    packet_ids = {
        str(row["work_item_id"]) for row in context["packets"]
    }
    assignments = tuple(
        sorted(
            (
                str(row["work_item_id"]),
                str(row["shard_id"]),
            )
            for row in shards["assignments"]
        )
    )
    assert context["packet_count"] == len(final_ids)
    assert packet_ids == final_ids
    assert set(shards["exact_work_item_ids"]) == final_ids
    assert {row[0] for row in assignments} == final_ids
    assert len(assignments) == len(final_ids)
    return assignments


def _assert_t8_t9_parity(
    root: Path,
    plan: Mapping[str, Any],
) -> tuple[str, ...]:
    bundle = _json(
        root,
        (
            PRIVATE
            / "t8"
            / "validated_publication.bundle.json"
        ).as_posix(),
    )
    active = tuple(bundle["active_output_denominator"])
    assert set(active) == set(bundle["files"])
    assert set(bundle["public_output_denominator"]) == set(
        plan["public_output_denominator"]
    )
    for relative, row in bundle["files"].items():
        raw = base64.b64decode(row["content_b64"], validate=True)
        assert row["sha256"] == _sha(raw)
        assert row["size"] == len(raw)
        assert (root / relative).read_bytes() == raw
    inactive = (
        set(plan["public_output_denominator"])
        - set(bundle["active_output_denominator"])
    )
    assert all(not (root / relative).exists() for relative in inactive)
    assert bundle["publication_order"][-1] == LIVE.FINAL_RECEIPT
    assert (root / LIVE.FINAL_RECEIPT).is_file()
    return tuple(sorted(active))


def _assert_branch(
    root: Path,
    *,
    case: str,
    delta_ids: Mapping[str, tuple[str, ...]],
) -> None:
    if case == "mandatory":
        disposition = _json(
            root,
            (
                PRIVATE
                / "t3"
                / "mandatory_reverification_disposition.json"
            ).as_posix(),
        )
        assert disposition["status"] == "APPLIED"
        assert tuple(disposition["delta_ids"]) == delta_ids["mandatory"]
        assert delta_ids["mandatory"] == ("INV-002",)
    elif case == "p0af":
        disposition = _json(
            root,
            (
                PRIVATE
                / "t4"
                / "composition_disposition.json"
            ).as_posix(),
        )
        receipt = _json(
            root,
            (PRIVATE / "t4" / "p0af_delivery_receipt.json").as_posix(),
        )
        assert disposition["selected_successor"] == "RECEIPT"
        assert disposition["issues"] == []
        assert receipt["status"] == "DELIVERED"
        assert delta_ids["pipeline"] == ("CH-17",)
    elif case == "l1":
        disposition = _json(
            root,
            (
                PRIVATE
                / "t4"
                / "composition_disposition.json"
            ).as_posix(),
        )
        receipt = _json(
            root,
            (PRIVATE / "t4" / "l1_delivery_receipt.json").as_posix(),
        )
        assert disposition["selected_successor"] == "RECEIPT"
        assert disposition["issues"] == []
        assert receipt["status"] == "DELIVERED"
        assert len(delta_ids["pipeline"]) == 1
        assert delta_ids["pipeline"][0].startswith("L1CH-")
    elif case == "compound":
        disposition = _json(
            root,
            (
                PRIVATE
                / "t5"
                / "compound_delivery_disposition.json"
            ).as_posix(),
        )
        receipt = _json(
            root,
            (
                PRIVATE
                / "t5"
                / "compound_delivery_receipt.json"
            ).as_posix(),
        )
        assert disposition["selected_successor"] == "RECEIPT"
        assert disposition["issues"] == []
        assert receipt["status"] == "DELIVERED"
        assert delta_ids["compound"] == ("CH-77",)


def _run_case(
    project: Path,
    *,
    case: str,
    backend: str,
) -> Mapping[str, Any]:
    root, plan, run_id = _prepare_case(
        project,
        case=case,
        backend=backend,
    )
    public = set(plan["public_output_denominator"])
    observed_pre_t9 = False

    def failpoint(label: str) -> None:
        nonlocal observed_pre_t9
        if label == "after_t8_commit":
            observed_pre_t9 = True
            assert all(
                not (root / relative).exists() for relative in public
            )

    result = TRANSACTION.execute_live_verify_queue_transaction(
        scratchpad=root,
        project_root=project,
        plan=plan,
        run_id=run_id,
        semantic_executor=build_live_verify_queue_semantic_executor(plan),
        failpoint=failpoint,
    )
    assert observed_pre_t9 is True
    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["safe_to_consume"] is True

    target = {
        "mandatory": "mandatory",
        "p0af": "pipeline",
        "l1": "pipeline",
        "compound": "compound",
    }[case]
    final_ids, delta_ids = _assert_source_partition(
        root,
        target_source=target,
    )
    if case == "mandatory":
        accounting = _json(
            root,
            (
                PRIVATE
                / "t6"
                / "source_obligation_accounting.json"
            ).as_posix(),
        )
        by_occurrence = {
            (str(row["source"]), str(row["work_item_id"])): str(
                row["disposition"]
            )
            for row in accounting["rows"]
        }
        reactivated = set(delta_ids["mandatory"]) & {
            identity
            for source, identity in by_occurrence
            if source == "policy_excluded"
        }
        assert reactivated, (
            "fixture must exercise an AUTHORIZED_EXCLUDED policy occurrence "
            "that a mandatory independent-verification delta reactivates"
        )
        for identity in reactivated:
            assert by_occurrence[("policy_excluded", identity)] == (
                "AUTHORIZED_EXCLUDED"
            )
            assert by_occurrence[("mandatory", identity)] == "ACTIVE"
            assert identity in final_ids
    assignments = _assert_context_and_shards(root, final_ids)
    active_public = _assert_t8_t9_parity(root, plan)
    _assert_branch(root, case=case, delta_ids=delta_ids)
    public_queue = _json(root, "verification_queue.work_items.json")
    assert _record_ids(public_queue) == final_ids
    return {
        "final_ids": tuple(sorted(final_ids)),
        "delta_ids": {
            key: value for key, value in sorted(delta_ids.items())
        },
        "assignments": assignments,
        "active_public": active_public,
    }


def _direct_t5_frozen(
    *,
    payload: Mapping[str, Any],
    snapshot: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, bytes]]:
    plan = LIVE._plan("sc")
    unit = LIVE._child_map(plan)[LIVE.CHILD_IDS[5]]
    items = tuple(
        SEMANTICS.QueueWorkItem.from_legacy_row({
            "queue #": str(priority),
            "finding id": identity,
            "candidate identity": identity,
            "severity": severity,
            "title": f"Fixture constituent {identity}",
            "evidence class": "fixture",
            "bug class": "fixture",
            "preferred tag": "CODE-TRACE",
            "location": f"contracts/Fixture.sol#{identity}",
            "primary artifact": "findings_inventory.md",
            "poc class": "sequence",
            "constituents": "",
            "evidence debt": "fixture constituent requires verification",
            "effective evidence scope": "ANALYTICAL",
            "effective proof scope": "NONE",
            "effective harm scope": "UNPROVEN",
        })
        for priority, identity, severity in (
            (1, "H-1", "High"),
            (2, "M-1", "Medium"),
        )
    )
    bundle: dict[str, Any] = {
        "schema_version": SEMANTICS.INPUT_BUNDLE_SCHEMA,
        "pipeline": "sc",
        "mode": "thorough",
        "files": {
            "chain_composition_verification_candidates.json":
                SEMANTICS._bytes_row(_canonical_bytes(payload)),
            "chain_tail_terminal_snapshot.json":
                SEMANTICS._bytes_row(_canonical_bytes(snapshot)),
        },
    }
    bundle["bundle_digest"] = SEMANTICS._digest(bundle)
    frozen = {
        next(
            path for path in unit["exact_inputs"]
            if str(path).endswith("/input_bundle.json")
        ): _canonical_bytes(bundle),
        next(
            path for path in unit["exact_inputs"]
            if str(path).endswith("/active_queue.work_items.json")
        ): SEMANTICS._recordset_bytes(items),
    }
    return unit, frozen


def _seal_terminal_snapshot(snapshot: dict[str, Any]) -> None:
    snapshot["snapshot_sha256"] = SEMANTICS._field_digest(
        snapshot,
        "snapshot_sha256",
    )


def test_t5_rejects_every_noncanonical_terminal_snapshot_v2_variant(
    tmp_path: Path,
) -> None:
    source_project = tmp_path / "source"
    source_root = source_project / ".scratchpad"
    source_root.mkdir(parents=True)
    CHAIN_FIXTURE._publish_composition_candidate(
        source_project,
        source_root,
        heading="## CH-77 composed transition",
        evidence=(
            "CH-77 links the exact postcondition to the dependent "
            "precondition."
        ),
    )
    payload = json.loads(
        (source_root / "chain_composition_verification_candidates.json")
        .read_text(encoding="utf-8", errors="strict")
    )
    snapshot = json.loads(
        (source_root / "chain_tail_terminal_snapshot.json")
        .read_text(encoding="utf-8", errors="strict")
    )
    assert snapshot["schema_version"] == (
        CHAIN_AUTHORITY.TERMINAL_SNAPSHOT_SCHEMA
    )
    assert CHAIN_AUTHORITY._terminal_snapshot_generation(snapshot)

    variants: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

    def add_snapshot_variant(
        label: str,
        mutate: Callable[[dict[str, Any]], None],
        *,
        reseal: bool = True,
    ) -> None:
        changed = copy.deepcopy(snapshot)
        mutate(changed)
        if reseal:
            _seal_terminal_snapshot(changed)
        variants.append((label, copy.deepcopy(payload), changed))

    add_snapshot_variant(
        "legacy-v1",
        lambda value: value.__setitem__(
            "schema_version",
            "plamen.chain_tail.terminal_snapshot.v1",
        ),
    )
    add_snapshot_variant(
        "generation-missing",
        lambda value: value.pop("terminal_generation"),
    )
    add_snapshot_variant(
        "generation-extra",
        lambda value: value["terminal_generation"].__setitem__(
            "extra",
            1,
        ),
    )
    add_snapshot_variant(
        "generation-not-mapping",
        lambda value: value.__setitem__("terminal_generation", []),
    )
    add_snapshot_variant(
        "pass-index-bool",
        lambda value: value["terminal_generation"].__setitem__(
            "pass_index",
            True,
        ),
    )
    add_snapshot_variant(
        "pass-index-negative",
        lambda value: value["terminal_generation"].__setitem__(
            "pass_index",
            -1,
        ),
    )
    add_snapshot_variant(
        "shard-count-out-of-range",
        lambda value: value["terminal_generation"].__setitem__(
            "shard_count",
            CHAIN_AUTHORITY.MAX_TERMINAL_GENERATION_COMPONENT + 1,
        ),
    )
    add_snapshot_variant(
        "generation-id-wrong",
        lambda value: value["terminal_generation"].__setitem__(
            "generation_id",
            "p9999.s9999",
        ),
    )

    def mismatch_semantic_generation(value: dict[str, Any]) -> None:
        generation = value["terminal_generation"]
        generation["pass_index"] += 1
        generation["generation_id"] = CHAIN_AUTHORITY.chain_tail_generation_id(
            generation["pass_index"],
            generation["shard_count"],
        )

    add_snapshot_variant(
        "semantic-generation-mismatch",
        mismatch_semantic_generation,
    )
    add_snapshot_variant(
        "snapshot-digest-stale",
        lambda value: value.__setitem__("non_authoritative_extra", True),
        reseal=False,
    )
    add_snapshot_variant(
        "semantic-ledger-malformed",
        lambda value: value.__setitem__("semantic_ledger", []),
    )

    manifest_payload = copy.deepcopy(payload)
    manifest_payload["manifest_sha256"] = "0" * 64
    variants.append(
        ("candidate-manifest-mismatch", manifest_payload, copy.deepcopy(snapshot))
    )
    ledger_payload = copy.deepcopy(payload)
    ledger_payload["ledger_sha256"] = "0" * 64
    variants.append(
        ("candidate-ledger-mismatch", ledger_payload, copy.deepcopy(snapshot))
    )

    cross_project = tmp_path / "cross-source"
    cross_root = cross_project / ".scratchpad"
    cross_root.mkdir(parents=True)
    CHAIN_FIXTURE._publish_composition_candidate(
        cross_project,
        cross_root,
        heading="## CH-88 cross-pair transition",
        evidence="CH-88 is deliberately foreign to the frozen snapshot.",
    )
    cross_payload = json.loads(
        (cross_root / "chain_composition_verification_candidates.json")
        .read_text(encoding="utf-8", errors="strict")
    )
    variants.append(("cross-pair", cross_payload, copy.deepcopy(snapshot)))

    for label, candidate, terminal in variants:
        unit, frozen = _direct_t5_frozen(
            payload=candidate,
            snapshot=terminal,
        )
        result = SEMANTICS._t5(unit, frozen)
        outputs = result["outputs"]
        disposition_path = next(
            path for path in outputs
            if path.endswith("/compound_delivery_disposition.json")
        )
        delta_path = next(
            path for path in outputs
            if path.endswith("/queue_delta.work_items.json")
        )
        assert result["state"] == "COMMITTED_DEBT_SAFE_BASE", label
        debt_path = next(
            path for path in outputs
            if path.endswith("/compound_delivery_debt.json")
        )
        disposition = json.loads(outputs[disposition_path])
        assert disposition["selected_successor"] == "DEBT", label
        assert disposition["delta_ids"] == [], label
        assert disposition["issues"], label
        assert SEMANTICS._recordset(outputs[delta_path], label) == ()
        assert json.loads(outputs[debt_path])["status"] == (
            "COMPLETED_WITH_DEBT"
        )
        assert not any(
            path.endswith("/compound_delivery_receipt.json")
            for path in outputs
        ), label



@pytest.mark.parametrize(
    "case",
    ("mandatory", "p0af", "l1", "compound"),
)
def test_live_authoritative_success_paths_are_backend_neutral_and_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    # This fixture isolates the application-skeptic reopen branch.  P1-C has
    # its own typed lifecycle fixtures; an absent P1-C source must not turn
    # this focused test into an unrelated SO-000 authority-debt exercise.
    monkeypatch.setattr(
        SO,
        "read_pending_security_obligation_verification",
        lambda _scratchpad: [],
    )

    claude = _run_case(
        tmp_path / "claude",
        case=case,
        backend="claude",
    )
    codex = _run_case(
        tmp_path / "codex",
        case=case,
        backend="codex",
    )

    assert claude == codex
