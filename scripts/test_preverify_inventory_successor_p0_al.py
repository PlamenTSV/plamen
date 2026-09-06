"""P0-AL: final inventory -> registered delivery -> queue successor ordering."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import uuid

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

from artifact_ledger import (  # noqa: E402
    arm_semantic_mutation,
    finalize_semantic_mutation,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import plamen_driver as D  # noqa: E402
import plamen_validators as V  # noqa: E402
from preverify_inventory_successor import (  # noqa: E402
    PreverifyInventorySuccessorError,
    build_preverify_successor_payloads,
    validate_preverify_successor_payloads,
)
from preverify_frozen_projection import (  # noqa: E402
    prepare_preverify_frozen_projection,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _inventory(title: str = "candidate") -> str:
    return (
        "# Finding Inventory\n\n"
        f"### Finding [INV-001]: {title}\n"
        "**Severity**: Medium\n"
        "**Location**: src/A.sol:L10\n"
        "**Preferred Tag**: [CODE-TRACE]\n"
        "**Source IDs**: DCI-1\n"
        "**Primary Artifact**: depth_consensus_invariant_findings.md\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Root Cause**: exact mechanism\n"
        "**Description**: exact mechanism remains candidate-bearing\n"
        "**Impact**: material effect if confirmed\n"
    )


def _bare_id_inventory(title: str = "candidate") -> str:
    return _inventory(title).replace(
        "**Primary Artifact**: depth_consensus_invariant_findings.md\n", ""
    )


def _depth() -> str:
    return (
        "# Depth findings\n\n"
        "### Finding [DCI-1]: candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/A.sol:L10\n"
        "**Preferred Tag**: [CODE-TRACE]\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Description**: exact mechanism remains candidate-bearing\n"
        "**Impact**: material effect if confirmed\n"
    )


def _config(project: Path, scratch: Path) -> dict:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratch),
        "_run_id": str(uuid.uuid4()),
    }


def _seed(
    root: Path, *, inventory_text: str | None = None,
) -> tuple[dict, dict]:
    (root / "findings_inventory.md").write_text(
        inventory_text if inventory_text is not None else _inventory(),
        encoding="utf-8",
    )
    assert D._write_finding_records_from_inventory(root) == 1
    (root / "depth_consensus_invariant_findings.md").write_text(
        _depth(), encoding="utf-8"
    )
    scan = V._scan_registered_finding_delivery_sources(root)
    delivery = V._build_registered_finding_delivery_receipt_payload(
        root,
        scan,
        (root / "findings_inventory.md").read_text(encoding="utf-8"),
    )
    return scan, delivery


def _claim_seed_authority(root: Path, config: dict) -> None:
    """Give driver-path fixtures the upstream authority production requires."""

    run_id = str(config["_run_id"])
    groups = (
        (
            "inventory",
            "paired_fixture",
            ("findings_inventory.md", "finding_records.json"),
        ),
        (
            "depth",
            "registered_fixture",
            ("depth_consensus_invariant_findings.md",),
        ),
    )
    for phase, work_unit_id, paths in groups:
        postimage = {
            path: (root / path).read_bytes()
            for path in paths
        }
        for path in paths:
            (root / path).unlink()
        owner = canonical_work_unit_key(
            "sc", "thorough", "evm", "claude", phase, work_unit_id
        )
        contract = PhaseIOContract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase=phase,
            work_unit_id=work_unit_id,
            outputs=tuple(
                ArtifactSpec(
                    root="scratchpad",
                    path=path,
                    owner_key=owner,
                    artifact_class="DRIVER_GENERATED",
                    writer="DRIVER",
                    write_mode="CREATE",
                    schema_version="plamen.fixture_upstream.v1",
                    minimum_gate="FIXTURE_EXACT_BYTES",
                )
                for path in paths
            ),
            model_invoked=False,
        )
        launch = LaunchSpec(
            work_unit_key=contract.key,
            pipeline=contract.pipeline,
            mode=contract.mode,
            ecosystem=contract.ecosystem,
            backend=contract.backend,
            model="fixture-driver",
            timeout_s=30,
            exec_mode="python",
        )
        record_work_unit_inputs(
            root, root.parent, contract, launch, run_id=run_id
        )
        for path, raw in postimage.items():
            (root / path).write_bytes(raw)
        record_work_unit_artifacts(
            root,
            root.parent,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
        )


def _freeze_preverify_sources(
    root: Path,
    config: dict,
) -> dict:
    """Publish the exact immutable source pair required by capture authority."""

    return prepare_preverify_frozen_projection(
        scratchpad=root,
        project_root=Path(config["project_root"]),
        pipeline=str(config["pipeline"]),
        mode=str(config["mode"]),
        ecosystem=str(config["language"]),
        backend=str(config["cli_backend"]),
        phase_name="sc_verify_queue",
        run_id=str(config["_run_id"]),
    )


def test_pure_successor_binds_exact_final_inventory_and_registered_actions(
    tmp_path: Path,
) -> None:
    scan, delivery = _seed(tmp_path)
    final, registered = build_preverify_successor_payloads(
        tmp_path,
        run_id="run-1",
        delivery_payload=delivery,
        producer_artifacts=tuple(
            str(row["artifact"]) for row in scan["artifacts"]
        ),
    )

    assert final["inventory_sha256"] == _sha(
        (tmp_path / "findings_inventory.md").read_bytes()
    )
    assert final["producer_artifact_count"] == 1
    assert V._inventory_structural_source_action_referents(_inventory()) == {
        ("depth_consensus_invariant_findings.md", "DCI-1"): {"INV-001"}
    }
    assert delivery["status"] == "CLEAN"
    assert delivery["source_action_count"] == 1
    assert delivery["accounted_action_count"] == 1
    assert delivery["residual_debt_count"] == 0
    assert delivery["residual_debt"] == []
    assert [row["disposition"] for row in delivery["actions"]] == [
        "PROMOTED_FINDING"
    ]
    assert registered["final_inventory_receipt_digest"] == final[
        "receipt_digest"
    ]
    assert registered["delivery_payload"]["inventory_sha256"] == (
        "sha256:" + final["inventory_sha256"]
    )
    validate_preverify_successor_payloads(
        tmp_path,
        final_payload=final,
        delivery_payload=registered,
        run_id="run-1",
    )


def test_bare_local_source_id_remains_residual_delivery_debt(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    config = _config(project, scratch)
    _scan, delivery = _seed(
        scratch, inventory_text=_bare_id_inventory()
    )

    assert delivery["status"] == "DEGRADED"
    assert delivery["source_action_count"] == 1
    assert delivery["accounted_action_count"] == 0
    assert delivery["residual_debt_count"] == 1
    assert [row["disposition"] for row in delivery["actions"]] == [
        "RESIDUAL_DEBT"
    ]
    detail = (
        "depth_consensus_invariant_findings.md:DCI-1: content-bearing "
        "registered action has no inventory referent or review disposition"
    )
    assert delivery["residual_debt"] == [detail]

    _claim_seed_authority(scratch, config)
    frozen = _freeze_preverify_sources(scratch, config)
    assert D._finalize_preverify_inventory_successors(
        scratch,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen,
    ) == []
    assert V._validate_registered_finding_delivery_receipt(scratch) == [
        "registered finding delivery has residual parser/delivery debt: "
        + detail
    ]


def test_inventory_mutation_makes_both_receipts_stale_not_clean(
    tmp_path: Path,
) -> None:
    scan, delivery = _seed(tmp_path)
    final, registered = build_preverify_successor_payloads(
        tmp_path,
        run_id="run-1",
        delivery_payload=delivery,
        producer_artifacts=tuple(
            str(row["artifact"]) for row in scan["artifacts"]
        ),
    )
    (tmp_path / "findings_inventory.md").write_text(
        _inventory("later mutation"), encoding="utf-8"
    )

    with pytest.raises(
        PreverifyInventorySuccessorError,
        match="final inventory.*stale",
    ):
        validate_preverify_successor_payloads(
            tmp_path,
            final_payload=final,
            delivery_payload=registered,
            run_id="run-1",
        )


def test_producer_artifact_mutation_invalidates_registered_delivery(
    tmp_path: Path,
) -> None:
    scan, delivery = _seed(tmp_path)
    final, registered = build_preverify_successor_payloads(
        tmp_path,
        run_id="run-1",
        delivery_payload=delivery,
        producer_artifacts=tuple(
            str(row["artifact"]) for row in scan["artifacts"]
        ),
    )
    source = tmp_path / "depth_consensus_invariant_findings.md"
    source.write_text(source.read_text(encoding="utf-8") + "\nchanged\n")

    with pytest.raises(
        PreverifyInventorySuccessorError,
        match="producer artifact.*stale",
    ):
        validate_preverify_successor_payloads(
            tmp_path,
            final_payload=final,
            delivery_payload=registered,
            run_id="run-1",
        )


def test_delivery_payload_cannot_bind_a_different_inventory(
    tmp_path: Path,
) -> None:
    scan, delivery = _seed(tmp_path)
    delivery["inventory_sha256"] = "sha256:" + "0" * 64

    with pytest.raises(
        PreverifyInventorySuccessorError,
        match="delivery payload inventory binding",
    ):
        build_preverify_successor_payloads(
            tmp_path,
            run_id="run-1",
            delivery_payload=delivery,
            producer_artifacts=tuple(
                str(row["artifact"]) for row in scan["artifacts"]
            ),
        )


@pytest.mark.parametrize("phase_name", ["verify_queue", "sc_verify_queue"])
def test_queue_contract_requires_both_successor_receipts(
    tmp_path: Path, phase_name: str
) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        _inventory(), encoding="utf-8"
    )
    (tmp_path / "preverify_inventory_successor.json").write_text("{}\n")
    (tmp_path / "finding_delivery_successor.json").write_text("{}\n")
    config = {
        "pipeline": "l1" if phase_name == "verify_queue" else "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
    }

    contract, _launch = D._typed_verify_queue_routing_contract_and_launch(
        phase_name, tmp_path, config
    )

    assert {
        "scratchpad:preverify_inventory_successor.json",
        "scratchpad:finding_delivery_successor.json",
    }.issubset(set(contract.immutable_inputs))
    assert "scratchpad:findings_inventory.md" in set(
        contract.immutable_inputs
    )


@pytest.mark.parametrize(
    ("phase_name", "pipeline"),
    (("verify_queue", "l1"), ("sc_verify_queue", "sc")),
)
def test_queue_omits_unowned_or_noncurrent_optional_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase_name: str,
    pipeline: str,
) -> None:
    """Stale chain bytes cannot halt or silently enter either queue path."""

    active = tmp_path / "hypotheses.md"
    quarantined = tmp_path / "chain_composition_verification_candidates.json"
    unbound = tmp_path / "chain_equivalence_proposals.json"
    active.write_text("# current\n", encoding="utf-8")
    quarantined.write_text('{"candidate":"quarantined"}\n', encoding="utf-8")
    unbound.write_text('{"proposal":"legacy fixture"}\n', encoding="utf-8")
    for relative in (
        "preverify_inventory_successor.json",
        "finding_delivery_successor.json",
    ):
        (tmp_path / relative).write_text("{}\n", encoding="utf-8")

    run_id = "optional-context-test"
    active_owner = f"{pipeline}/thorough/evm/claude/chain/active"
    quarantined_owner = (
        f"{pipeline}/thorough/evm/claude/chain/quarantined"
    )
    ledger = {
        "artifact_bindings": {
            "scratchpad:hypotheses.md": {
                "status": "ACTIVE",
                "sha256": _sha(active.read_bytes()),
                "size": active.stat().st_size,
                "run_id": run_id,
                "owner_key": active_owner,
            },
            "scratchpad:chain_composition_verification_candidates.json": {
                "status": "QUARANTINED",
                "sha256": _sha(quarantined.read_bytes()),
                "size": quarantined.stat().st_size,
                "run_id": run_id,
                "owner_key": quarantined_owner,
            },
        },
        "work_units": {
            active_owner: {
                "execution_state": "OUTPUT_COMMITTED",
                "semantic_status": "ACTIVE",
                "run_id": run_id,
            },
            quarantined_owner: {
                "execution_state": "OUTPUT_COMMITTED",
                "semantic_status": "QUARANTINED",
                "run_id": run_id,
            },
        },
    }
    monkeypatch.setattr(D, "read_artifact_ledger", lambda _root: ledger)
    config = {
        "pipeline": pipeline,
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "_run_id": run_id,
    }

    contract, _launch = D._typed_verify_queue_routing_contract_and_launch(
        phase_name, tmp_path, config
    )
    bound = set(contract.immutable_inputs)

    assert "scratchpad:hypotheses.md" not in bound
    assert "scratchpad:chain_equivalence_proposals.json" not in bound
    assert (
        "scratchpad:chain_composition_verification_candidates.json"
        not in bound
    )

    # ACTIVE labels are insufficient after the bytes drift.
    active.write_text("# changed after commit\n", encoding="utf-8")
    contract, _launch = D._typed_verify_queue_routing_contract_and_launch(
        phase_name, tmp_path, config
    )
    assert "scratchpad:hypotheses.md" not in set(
        contract.immutable_inputs
    )


@pytest.mark.parametrize(
    ("phase_name", "pipeline"),
    (("verify_queue", "l1"), ("sc_verify_queue", "sc")),
)
def test_queue_records_typed_optional_context_omission_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase_name: str,
    pipeline: str,
) -> None:
    optional = tmp_path / "chain_composition_verification_candidates.json"
    optional.write_text('{"candidate":"held for review"}\n', encoding="utf-8")
    owner_key = f"{pipeline}/thorough/evm/claude/chain/context"
    run_id = "optional-context-debt-test"
    binding = {
        "status": "QUARANTINED",
        "sha256": _sha(optional.read_bytes()),
        "size": optional.stat().st_size,
        "run_id": run_id,
        "owner_key": owner_key,
    }
    owner = {
        "execution_state": "OUTPUT_COMMITTED",
        "semantic_status": "QUARANTINED",
        "run_id": run_id,
    }
    ledger = {
        "artifact_bindings": {
            "scratchpad:chain_composition_verification_candidates.json": (
                binding
            ),
        },
        "work_units": {owner_key: owner},
    }
    monkeypatch.setattr(D, "read_artifact_ledger", lambda _root: ledger)
    monkeypatch.setattr(
        D,
        "_validate_registered_finding_delivery_receipt",
        lambda _root, **_kwargs: [],
    )
    monkeypatch.setattr(
        D,
        "_arm_deterministic_driver_work_unit",
        lambda **_kwargs: (True, []),
    )
    config = {
        "pipeline": pipeline,
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path.parent),
        "_run_id": run_id,
    }

    execute, issues = D._arm_typed_verify_queue_routing_artifacts(
        phase_name, tmp_path, config
    )

    assert execute is True
    assert issues == []
    status = json.loads(
        (tmp_path / "verify_queue_context_input_status.json").read_text(
            encoding="utf-8"
        )
    )
    if pipeline == "l1":
        assert status["state"] == "COMMITTED_CLEAN_NOOP"
        assert (
            "chain_composition_verification_candidates.json"
            in status["not_applicable_artifacts"]
        )
    else:
        assert status["state"] == "COMPLETED_WITH_DEBT_SAFE_BASE"
        assert any(
            row.get("artifact")
            == "chain_composition_verification_candidates.json"
            for row in status["omitted_artifacts"]
        )
    assert not (tmp_path / "chain.degraded").exists()


def test_driver_transaction_is_ledger_bound_and_repairs_stale_successor(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    config = _config(project, scratch)
    _seed(scratch)
    _claim_seed_authority(scratch, config)
    first_frozen = _freeze_preverify_sources(scratch, config)

    first = D._finalize_preverify_inventory_successors(
        scratch,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=first_frozen,
    )

    assert first == []
    first_receipt = json.loads(
        (scratch / "preverify_inventory_successor.json").read_text(
            encoding="utf-8"
        )
    )
    ledger = read_artifact_ledger(scratch)
    unit = ledger["work_units"][
        "sc/thorough/evm/claude/sc_verify_queue/preverify_successors"
    ]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["artifacts"][
        "scratchpad:finding_delivery_successor.json"
    ]["status"] == "ACTIVE"
    assert V._validate_registered_finding_delivery_receipt(scratch) == []

    # A later inventory write must invalidate the old receipt. The bounded
    # finalizer repairs it rather than letting queue routing consume stale
    # authority.
    inventory_event = arm_semantic_mutation(
        scratch,
        project,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="FIXTURE_AUTHORIZED_INVENTORY_REFRESH",
        run_id=config["_run_id"],
    )
    root_records_before = (scratch / "finding_records.json").read_bytes()
    root_records_binding_before = read_artifact_ledger(scratch)[
        "artifact_bindings"
    ]["scratchpad:finding_records.json"]
    (scratch / "findings_inventory.md").write_text(
        _inventory("later mutation"), encoding="utf-8"
    )
    finalize_semantic_mutation(
        scratch,
        project,
        inventory_event["event_id"],
        run_id=config["_run_id"],
        affected_record_ids=("INV-001",),
    )
    assert (scratch / "finding_records.json").read_bytes() == root_records_before
    root_records_binding_after = read_artifact_ledger(scratch)[
        "artifact_bindings"
    ]["scratchpad:finding_records.json"]
    assert root_records_binding_after["status"] == "ACTIVE"
    assert root_records_binding_after["owner_key"] == (
        "sc/thorough/evm/claude/inventory/paired_fixture"
    )
    assert root_records_binding_after["sha256"] == _sha(root_records_before)
    assert root_records_binding_after == root_records_binding_before
    second_frozen = _freeze_preverify_sources(scratch, config)
    assert second_frozen["generation_digest"] != first_frozen["generation_digest"]
    second_frozen_receipt = json.loads(
        (scratch / second_frozen["receipt_path"]).read_text(
            encoding="utf-8", errors="strict"
        )
    )
    inventory_authority = second_frozen_receipt["source_authorities"][
        "inventory"
    ]
    assert inventory_authority["authority_kind"] == (
        "CONTIGUOUS_SEMANTIC_MUTATION_CHAIN"
    )
    assert inventory_event["event_id"] in json.dumps(
        inventory_authority, sort_keys=True
    )
    refreshed_frozen_inventory = (
        scratch
        / second_frozen["logical_to_physical"]["findings_inventory.md"]
    ).read_bytes()
    refreshed_frozen_records = json.loads(
        (
            scratch
            / second_frozen["logical_to_physical"]["finding_records.json"]
        ).read_text(encoding="utf-8", errors="strict")
    )
    assert refreshed_frozen_records["source_sha256"] == _sha(
        refreshed_frozen_inventory
    )
    second = D._finalize_preverify_inventory_successors(
        scratch,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=second_frozen,
    )

    assert second == []
    repaired = json.loads(
        (scratch / "preverify_inventory_successor.json").read_text(
            encoding="utf-8"
        )
    )
    assert repaired["inventory_sha256"] != first_receipt["inventory_sha256"]
    assert repaired["inventory_sha256"] == _sha(
        (scratch / "findings_inventory.md").read_bytes()
    )
    assert V._validate_registered_finding_delivery_receipt(scratch) == []


def test_post_freeze_canonical_mutation_cannot_replace_successor_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    config = _config(project, scratch)
    _seed(scratch)
    _claim_seed_authority(scratch, config)
    frozen = _freeze_preverify_sources(scratch, config)
    assert D._finalize_preverify_inventory_successors(
        scratch,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen,
    ) == []
    (scratch / "findings_inventory.md").write_text(
        _inventory("post-receipt mutation"), encoding="utf-8"
    )

    issues = V._validate_registered_finding_delivery_receipt(scratch)
    successor = json.loads(
        (scratch / "preverify_inventory_successor.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    frozen_inventory = (
        scratch / frozen["logical_to_physical"]["findings_inventory.md"]
    ).read_bytes()

    # Mutable canonical bytes are no longer the queue denominator.  They may
    # change after the frozen generation without either staling or silently
    # replacing the already-authenticated successor.
    assert issues == []
    assert successor["inventory_sha256"] == _sha(frozen_inventory)
    assert successor["inventory_sha256"] != _sha(
        (scratch / "findings_inventory.md").read_bytes()
    )


def test_queue_arm_rejects_unowned_successor_even_when_json_is_well_formed(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    config = _config(project, scratch)
    scan, delivery = _seed(scratch)
    final, registered = build_preverify_successor_payloads(
        scratch,
        run_id=config["_run_id"],
        delivery_payload=delivery,
        producer_artifacts=tuple(
            str(row["artifact"]) for row in scan["artifacts"]
        ),
    )
    (scratch / "preverify_inventory_successor.json").write_text(
        json.dumps(final), encoding="utf-8"
    )
    (scratch / "finding_delivery_successor.json").write_text(
        json.dumps(registered), encoding="utf-8"
    )

    execute, issues = D._arm_typed_verify_queue_routing_artifacts(
        "sc_verify_queue", scratch, config
    )

    assert execute is False
    assert any("ledger authority" in issue.lower() for issue in issues)


def test_driver_refuses_forged_unowned_successor_outputs(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    config = _config(project, scratch)
    _seed(scratch)
    _claim_seed_authority(scratch, config)
    frozen = _freeze_preverify_sources(scratch, config)
    (scratch / "preverify_inventory_successor.json").write_text(
        '{"forged":true}\n', encoding="utf-8"
    )
    (scratch / "finding_delivery_successor.json").write_text(
        '{"forged":true}\n', encoding="utf-8"
    )

    issues = D._finalize_preverify_inventory_successors(
        scratch,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen,
    )

    assert issues
    assert any("unowned" in issue.lower() for issue in issues)
