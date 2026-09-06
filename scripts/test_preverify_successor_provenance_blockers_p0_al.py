"""Adversarial fixtures for the rejected preverify-successor cutover.

These fixtures encode the independent 2026-07-25 blocking review.  A
content-addressed payload is not provenance when the bytes used to construct
it were never part of an armed input denominator, and queue routing may not
read live inventory bytes after arming without binding them.
"""
from __future__ import annotations

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
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)
import plamen_driver as D  # noqa: E402
from preverify_frozen_projection import (  # noqa: E402
    prepare_preverify_frozen_projection,
)
from preverify_inventory_successor import (  # noqa: E402
    PreverifyInventorySuccessorError,
    build_preverify_capture_plan,
    validate_preverify_capture_plan,
)


def _inventory(title: str = "candidate") -> str:
    return (
        "# Finding Inventory\n\n"
        f"### Finding [INV-001]: {title}\n"
        "**Severity**: Medium\n"
        "**Location**: src/A.sol:L10\n"
        "**Preferred Tag**: [CODE-TRACE]\n"
        "**Source IDs**: DCI-1\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Root Cause**: exact mechanism\n"
        "**Description**: exact mechanism remains candidate-bearing\n"
        "**Impact**: material effect if confirmed\n"
    )


def _producer(local_id: str = "DCI-1") -> str:
    return (
        "# Depth findings\n\n"
        f"### Finding [{local_id}]: candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/A.sol:L10\n"
        "**Preferred Tag**: [CODE-TRACE]\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Description**: exact mechanism remains candidate-bearing\n"
        "**Impact**: material effect if confirmed\n"
    )


def _config(project: Path, scratch: Path) -> dict[str, str]:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratch),
        "_run_id": str(uuid.uuid4()),
    }


def _claim_seed_authority(
    scratch: Path, config: dict[str, str]
) -> None:
    """Model the active upstream owners present in a real pipeline run."""

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
            path: (scratch / path).read_bytes()
            for path in paths
        }
        for path in paths:
            (scratch / path).unlink()
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
            scratch,
            scratch.parent,
            contract,
            launch,
            run_id=config["_run_id"],
        )
        for path, raw in postimage.items():
            (scratch / path).write_bytes(raw)
        record_work_unit_artifacts(
            scratch,
            scratch.parent,
            contract,
            launch,
            run_id=config["_run_id"],
            actor="DRIVER",
        )


def _seed(project: Path) -> tuple[Path, dict[str, str]]:
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    (scratch / "findings_inventory.md").write_text(
        _inventory(), encoding="utf-8"
    )
    assert D._write_finding_records_from_inventory(scratch) == 1
    (scratch / "depth_consensus_invariant_findings.md").write_text(
        _producer(), encoding="utf-8"
    )
    config = _config(project, scratch)
    _claim_seed_authority(scratch, config)
    return scratch, config


def _freeze_preverify_sources(
    scratch: Path,
    config: dict[str, str],
) -> dict:
    return prepare_preverify_frozen_projection(
        scratchpad=scratch,
        project_root=Path(config["project_root"]),
        pipeline=str(config["pipeline"]),
        mode=str(config["mode"]),
        ecosystem=str(config["language"]),
        backend=str(config["cli_backend"]),
        phase_name="sc_verify_queue",
        run_id=str(config["_run_id"]),
    )


def _capture_plan(scratch: Path, run_id: str):
    return build_preverify_capture_plan(
        scratch,
        run_id=run_id,
        producer_artifacts=("depth_consensus_invariant_findings.md",),
        mutation_authority_candidates=(
            "inventory_reemit_receipt.json",
        ),
        control_artifact_candidates=(
            "enumgap_worklist.json",
            "enumgap_disposition_receipt.json",
        ),
        registry_digest="1" * 64,
        trusted_code_digest="2" * 64,
    )


def test_capture_plan_binds_present_bytes_and_absent_candidate_vector(
    tmp_path: Path,
) -> None:
    scratch, config = _seed(tmp_path)
    plan = _capture_plan(scratch, config["_run_id"])

    assert plan.exact_inputs == (
        "depth_consensus_invariant_findings.md",
        "finding_records.json",
        "findings_inventory.md",
    )
    presence = {
        row["artifact"]: row["status"]
        for row in plan.payload["scratchpad_presence"]
    }
    assert presence["inventory_reemit_receipt.json"] == "ABSENT"
    assert presence["enumgap_worklist.json"] == "ABSENT"
    validate_preverify_capture_plan(scratch, plan)


def test_capture_plan_rejects_candidate_appearance_after_arm(
    tmp_path: Path,
) -> None:
    scratch, config = _seed(tmp_path)
    plan = _capture_plan(scratch, config["_run_id"])
    (scratch / "inventory_reemit_receipt.json").write_text(
        '{"later":true}\n', encoding="utf-8"
    )

    with pytest.raises(
        PreverifyInventorySuccessorError,
        match="denominator drifted",
    ):
        validate_preverify_capture_plan(scratch, plan)


def test_capture_plan_rejects_missing_paired_finding_records(
    tmp_path: Path,
) -> None:
    """B5/T0b: queue capture cannot synthesize the inventory projection."""

    scratch, config = _seed(tmp_path)
    (scratch / "finding_records.json").unlink()

    with pytest.raises(
        PreverifyInventorySuccessorError,
        match="paired finding-record projection is unavailable",
    ):
        _capture_plan(scratch, config["_run_id"])


def test_capture_plan_rejects_stale_paired_finding_records(
    tmp_path: Path,
) -> None:
    """B5/T0b: both inventory projections advance under one prior owner."""

    scratch, config = _seed(tmp_path)
    (scratch / "findings_inventory.md").write_text(
        _inventory("new inventory bytes"),
        encoding="utf-8",
    )

    with pytest.raises(
        PreverifyInventorySuccessorError,
        match="paired finding-record projection is stale or invalid",
    ):
        _capture_plan(scratch, config["_run_id"])


def test_capture_binds_inventory_and_materialized_producer_preimages(
    tmp_path: Path,
) -> None:
    """B1: zero-input capture cannot certify a scan-derived generation."""

    scratch, config = _seed(tmp_path)
    frozen = _freeze_preverify_sources(scratch, config)
    assert D._finalize_preverify_inventory_successors(
        scratch,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen,
    ) == []

    ledger = read_artifact_ledger(scratch)
    captures = [
        unit
        for key, unit in ledger["work_units"].items()
        if "/sc_verify_queue/preverify_capture." in key
    ]
    assert len(captures) == 1
    bound = set(captures[0]["input_bindings"])
    assert (
        "scratchpad:"
        + frozen["logical_to_physical"]["findings_inventory.md"]
    ) in bound
    assert (
        "scratchpad:"
        + frozen["logical_to_physical"]["finding_records.json"]
    ) in bound
    assert "scratchpad:" + frozen["receipt_path"] in bound
    assert "scratchpad:findings_inventory.md" not in bound
    assert "scratchpad:depth_consensus_invariant_findings.md" in bound
    assert captures[0]["input_receipt_kind"] != "EXPLICIT_ZERO_INPUT"


def test_new_registered_producer_after_capture_arm_aborts_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """B1: a producer-roster appearance race must not commit old coverage."""

    scratch, config = _seed(tmp_path)
    frozen = _freeze_preverify_sources(scratch, config)
    original_arm = D._arm_deterministic_driver_work_unit
    injected = False

    def _arm_then_inject(**kwargs):
        nonlocal injected
        result = original_arm(**kwargs)
        contract = kwargs["contract"]
        if (
            not injected
            and "/sc_verify_queue/preverify_capture." in contract.key
            and result[0] is True
        ):
            injected = True
            (scratch / "analysis_late_registered.md").write_text(
                _producer("B1-1"), encoding="utf-8"
            )
        return result

    monkeypatch.setattr(
        D, "_arm_deterministic_driver_work_unit", _arm_then_inject
    )
    issues = D._finalize_preverify_inventory_successors(
        scratch,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen,
    )

    assert injected is True
    assert issues
    assert any(
        "producer" in issue.lower()
        and any(
            token in issue.lower()
            for token in ("denominator", "roster", "appeared", "drift")
        )
        for issue in issues
    )


def test_present_ledger_missing_optional_binding_omits_with_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """B3: legacy inclusion applies only when no ledger exists at all."""

    optional = tmp_path / "chain_equivalence_proposals.json"
    optional.write_text('{"proposal":"unbound"}\n', encoding="utf-8")
    monkeypatch.setattr(
        D,
        "read_artifact_ledger",
        lambda _root: {
            "artifact_bindings": {
                "scratchpad:some_other_artifact.json": {
                    "status": "ACTIVE",
                }
            },
            "work_units": {},
        },
    )
    included, debt = D._resolve_verify_queue_optional_context_inputs(
        tmp_path,
        {
            "pipeline": "sc",
            "mode": "thorough",
            "language": "evm",
            "cli_backend": "claude",
            "_run_id": "run-present-ledger",
        },
    )

    assert included == set()
    assert any(
        "chain_equivalence_proposals.json" in issue
        and any(
            token in issue.lower()
            for token in ("binding", "policy", "excluded")
        )
        for issue in debt
    )


def test_queue_contract_binds_live_inventory_if_routing_reads_it(
    tmp_path: Path,
) -> None:
    """B2: the current router reads inventory, so it is a mandatory input."""

    for name in (
        "findings_inventory.md",
        "preverify_inventory_successor.json",
        "finding_delivery_successor.json",
    ):
        (tmp_path / name).write_text("{}\n", encoding="utf-8")
    contract, _launch = D._typed_verify_queue_routing_contract_and_launch(
        "sc_verify_queue",
        tmp_path,
        {
            "pipeline": "sc",
            "mode": "thorough",
            "language": "evm",
            "cli_backend": "claude",
        },
    )

    assert "scratchpad:findings_inventory.md" in set(
        contract.immutable_inputs
    )


def test_queue_phaseio_resolver_rejects_empty_mandatory_input_pair() -> None:
    """B4: no implicit findings_inventory fallback may weaken the resolver."""

    with pytest.raises(ValueError, match="mandatory|successor|input"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="sc_verify_queue",
            work_unit_id="routing",
            exact_inputs=(),
            exact_outputs=("verification_queue.md",),
        )


def test_runtime_queue_rejects_canonical_only_legacy_successor(
    tmp_path: Path,
) -> None:
    """B2: a current queue cannot silently fall back to mutable root bytes."""

    scratch, config = _seed(tmp_path)
    # The stronger current contract rejects a canonical-only capture before a
    # queue routing capability can be armed; the old fixture expected that
    # same rejection one layer later.
    successor_issues = D._finalize_preverify_inventory_successors(
        scratch,
        config,
        phase_name="sc_verify_queue",
    )
    assert successor_issues
    assert any(
        "exact non-empty capture denominator" in issue.lower()
        for issue in successor_issues
    ), json.dumps(successor_issues, indent=2)
