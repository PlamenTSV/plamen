"""Fixture-first REDs for Cut-4 dependency and canonical-recon authority.

The required graph is:

``obligations -> unresolved baseline -> MODEL | explicit absence -> reconcile``

followed by a DRIVER canonical merge which binds every raw worker generation,
every selected prepass prestate, and the signal-transform receipt.  Current
production registers only the late MODEL/reconcile leaves and an under-bound
eleven-output merge.  These tests use executable resolver, renderer, crash,
resume, and consumer-selection checks; they are not regex/source-text claims.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import artifact_ledger as AL  # noqa: E402
import dependency_obligations as DO  # noqa: E402
import plamen_driver as D  # noqa: E402
import plamen_mechanical as M  # noqa: E402
from phase_io_contracts import resolve_phase_io_contract  # noqa: E402


WORKER_SHARDS = (
    "recon_build_static.md",
    "recon_design_context.md",
    "recon_inventory_surface.md",
    "recon_templates_patterns.md",
)

CANONICAL_RECON = (
    "recon_summary.md",
    "design_context.md",
    "attack_surface.md",
    "state_variables.md",
    "function_list.md",
    "contract_inventory.md",
    "template_recommendations.md",
    "detected_patterns.md",
    "setter_list.md",
    "emit_list.md",
    "build_status.md",
)

CANONICAL_POSTIMAGE = (*CANONICAL_RECON, "recon_signal_transform_receipt.json")

DEPENDENCY_CAPTURE_INPUTS = (
    "audit_snapshot.json",
    "recon_dependency_source_closure.json",
    "recon_dependency_manifest_closure.json",
    "recon_dependency_config_authority.json",
)


def _resolve(work_unit_id: str, *, inputs=(), outputs=(), writer="DRIVER"):
    return resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id=work_unit_id,
        exact_inputs=tuple(inputs),
        exact_outputs=tuple(outputs),
        exact_writer=writer,
    )


def _output_paths(contract: object) -> set[str]:
    return {
        output.identity.split(":", 1)[1]
        for output in contract.outputs
    }


def _write_merge_inputs(root: Path, *, tag: str = "g1") -> None:
    for name in WORKER_SHARDS:
        (root / name).write_text(
            f"# {name}\n\nworker generation {tag}\n" + ("x" * 180) + "\n",
            encoding="utf-8",
        )
    for name in CANONICAL_RECON:
        (root / name).write_text(
            f"# {name}\n\nprepass generation {tag}\n" + ("p" * 180) + "\n",
            encoding="utf-8",
        )


def _merge_config(root: Path) -> dict[str, object]:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(root.parent / "project"),
        "run_id": "cut4-recon-merge-red",
    }


def _fixture_obligations() -> dict[str, object]:
    return {
        "schema": DO.SCHEMA,
        "provider": "fixture",
        "obligations": [
            {
                "obligation_id": "DEP-AAAAAAAAAAAA",
                "dependency": "fixture-a",
                "source_location": "Fixture.sol:L1",
                "research_question": "What behavior is externally guaranteed?",
            },
            {
                "obligation_id": "DEP-BBBBBBBBBBBB",
                "dependency": "fixture-b",
                "source_location": "Fixture.sol:L2",
                "research_question": "What failure behavior is guaranteed?",
            },
        ],
        "observed_count": 2,
        "retained_count": 2,
        "truncated": False,
        "overflow_ids": [],
    }


def test_positive_control_zero_obligation_enumeration_is_explicit_data(
    tmp_path: Path,
) -> None:
    """Zero is representable; the missing piece is its producer authority."""

    project = tmp_path / "project"
    project.mkdir()
    payload = DO.enumerate_dependency_obligations(
        project,
        {"pipeline": "sc", "language": "evm"},
    )
    assert payload["obligations"] == []
    assert payload["observed_count"] == 0
    assert payload["retained_count"] == 0
    assert payload["truncated"] is False


def test_dependency_obligations_has_a_registered_source_bound_producer() -> None:
    contract = _resolve(
        "dependency_obligations",
        inputs=DEPENDENCY_CAPTURE_INPUTS,
        outputs=("external_dependency_obligations.json",),
    )
    assert _output_paths(contract) == {"external_dependency_obligations.json"}
    assert set(contract.immutable_inputs) == {
        f"scratchpad:{name}" for name in DEPENDENCY_CAPTURE_INPUTS
    }
    output = contract.outputs[0]
    assert output.writer == "DRIVER"
    assert output.schema_version == DO.SCHEMA


def test_zero_dependency_obligations_is_a_typed_terminal_child() -> None:
    contract = _resolve(
        "dependency_obligations.typed_zero",
        inputs=DEPENDENCY_CAPTURE_INPUTS,
        outputs=("external_dependency_obligations.json",),
    )
    output = contract.outputs[0]
    assert output.writer == "DRIVER"
    assert output.condition_id == "zero_dependency_obligations"
    assert "ZERO" in output.minimum_gate.upper()


def test_dependency_baseline_precedes_model_and_owns_limitation_poststate() -> None:
    contract = _resolve(
        "dependency_baseline",
        inputs=("external_dependency_obligations.json",),
        outputs=(
            "external_dependency_research.md",
            "report_semantic_dependency_research.md",
        ),
    )
    assert _output_paths(contract) == {
        "external_dependency_research.md",
        "report_semantic_dependency_research.md",
    }
    requirement = contract.input_authority(
        "scratchpad:external_dependency_obligations.json"
    )
    assert requirement.expected_writer == "DRIVER"
    assert requirement.require_same_run is True


def test_dependency_model_binds_obligation_and_baseline_generations() -> None:
    contract = _resolve(
        "dependency_research",
        inputs=(
            "external_dependency_obligations.json",
            "external_dependency_research.md",
            "report_semantic_dependency_research.md",
            *WORKER_SHARDS,
        ),
        outputs=("recon_external_dependency_research.md",),
        writer="MODEL",
    )
    identities = set(contract.immutable_inputs) | set(contract.bounded_lookup_inputs)
    assert {
        "scratchpad:external_dependency_obligations.json",
        "scratchpad:external_dependency_research.md",
        "scratchpad:report_semantic_dependency_research.md",
    }.issubset(identities)
    for identity in (
        "scratchpad:external_dependency_obligations.json",
        "scratchpad:external_dependency_research.md",
    ):
        requirement = contract.input_authority(identity)
        assert requirement.require_same_run is True
        assert requirement.expected_writer == "DRIVER"


@pytest.mark.parametrize(
    "reason",
    ("zero_obligations", "not_run", "model_failure", "malformed_model_output"),
)
def test_dependency_model_absence_and_debt_are_explicit(reason: str) -> None:
    contract = _resolve(
        f"dependency_research.explicit_absence.{reason}",
        inputs=(
            "external_dependency_obligations.json",
            "external_dependency_research.md",
        ),
        outputs=("recon_external_dependency_research.md",),
    )
    assert _output_paths(contract) == {"recon_external_dependency_research.md"}
    assert contract.outputs[0].writer == "DRIVER"
    assert contract.model_invoked is False


def test_dependency_reconcile_binds_baseline_and_one_exclusive_model_terminal() -> None:
    predecessor_inputs = (
        "external_dependency_obligations.json",
        "external_dependency_research.md",
        "report_semantic_dependency_research.md",
        "recon_external_dependency_research.md",
    )
    capture = _resolve(
        "dependency_reconcile.source_capture",
        inputs=predecessor_inputs,
        outputs=("recon_dependency_reconcile_source_manifest.json",),
    )
    assert {
        f"scratchpad:{name}" for name in predecessor_inputs
    } == set(capture.immutable_inputs)
    contract = _resolve(
        "dependency_reconcile",
        inputs=("recon_dependency_reconcile_source_manifest.json",),
        outputs=(
            "external_dependency_research.md",
            "report_semantic_dependency_research.md",
        ),
    )
    assert set(contract.immutable_inputs) == {
        "scratchpad:recon_dependency_reconcile_source_manifest.json"
    }
    assert _output_paths(contract) == {
        "external_dependency_research.md",
        "report_semantic_dependency_research.md",
    }


def test_positive_control_malformed_research_retains_every_unresolved_row(
    tmp_path: Path,
) -> None:
    """The fixture's recall-safe semantic expectation is already achievable."""

    obligations = _fixture_obligations()
    result = DO.reconcile_dependency_research_ledger(
        tmp_path,
        obligations,
        worker_text="malformed text without a dependency table",
    )
    ledger_text = (tmp_path / "external_dependency_research.md").read_text(
        encoding="utf-8"
    )
    assert result["unresolved"] == 2
    assert result["researched"] == 0
    assert "DEP-AAAAAAAAAAAA" in ledger_text
    assert "DEP-BBBBBBBBBBBB" in ledger_text
    assert (tmp_path / "report_semantic_dependency_research.md").is_file()
    ok, issues = DO.validate_dependency_ledger_parity(obligations, ledger_text)
    assert ok, issues


def test_direct_obligation_writer_cannot_be_consumed_without_producer_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = tmp_path / "scratchpad"
    project.mkdir()
    scratchpad.mkdir()
    (project / "Protocol.sol").write_text(
        'pragma solidity ^0.8.20;\n'
        'import "@vendor/pkg/External.sol";\n'
        "contract Fixture {}\n",
        encoding="utf-8",
    )
    payload = DO.write_dependency_obligations(
        scratchpad,
        project,
        {"pipeline": "sc", "language": "evm"},
    )
    assert (scratchpad / "external_dependency_obligations.json").is_file()
    assert payload["observed_count"] >= 1
    # File existence is not a producer.  Current direct writer leaves no unit.
    ledger = AL.read_artifact_ledger(scratchpad)
    key = "sc/thorough/evm/claude/recon/dependency_obligations"
    unit = ledger.get("work_units", {}).get(key)
    assert unit is not None
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"


def test_canonical_merge_source_capture_names_all_worker_and_prepass_generations() -> None:
    inputs = (*WORKER_SHARDS, *CANONICAL_RECON, "recon_prepass_finalize.json")
    contract = _resolve(
        "canonical_merge.source_capture",
        inputs=inputs,
        outputs=("recon_canonical_merge_source_manifest.json",),
    )
    assert set(contract.immutable_inputs) == {
        f"scratchpad:{name}" for name in inputs
    }
    assert _output_paths(contract) == {
        "recon_canonical_merge_source_manifest.json"
    }
    assert len(contract.input_authority_requirements) == len(inputs)


def test_canonical_merge_contract_owns_eleven_outputs_and_transform_receipt() -> None:
    contract = _resolve(
        "canonical_merge",
        inputs=("recon_canonical_merge_source_manifest.json",),
        outputs=CANONICAL_POSTIMAGE,
    )
    assert _output_paths(contract) == set(CANONICAL_POSTIMAGE)
    receipt = contract.output("scratchpad:recon_signal_transform_receipt.json")
    assert receipt.writer == "DRIVER"
    assert receipt.schema_version == "plamen.recon_signal_transform_set.v1"
    assert contract.input_authority(
        "scratchpad:recon_canonical_merge_source_manifest.json"
    ).require_same_run is True


def test_live_merge_does_not_omit_its_transform_receipt_from_the_postimage(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    _write_merge_inputs(scratchpad)
    returned = M._merge_recon_worker_shards(
        scratchpad,
        _merge_config(scratchpad),
    )
    observed = {
        name for name in CANONICAL_POSTIMAGE
        if (scratchpad / name).is_file()
    }
    # Positive control: current renderer really did create the receipt.
    assert observed == set(CANONICAL_POSTIMAGE)
    assert json.loads(
        (scratchpad / "recon_signal_transform_receipt.json").read_text(
            encoding="utf-8"
        )
    )["schema"] == "plamen.recon_signal_transform_set.v1"
    assert set(returned) == observed, (
        "live canonical merge wrote a semantic transform receipt that its "
        "returned/registered postimage omits"
    )


def test_prepass_prestate_drift_after_capture_cannot_be_silently_merged(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    _write_merge_inputs(scratchpad, tag="generation-1")
    source_manifest = {
        name: hashlib.sha256((scratchpad / name).read_bytes()).hexdigest()
        for name in (*WORKER_SHARDS, *CANONICAL_RECON)
    }
    (scratchpad / "recon_canonical_merge_source_manifest.json").write_text(
        json.dumps(source_manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    before = {
        name: hashlib.sha256((scratchpad / name).read_bytes()).hexdigest()
        for name in CANONICAL_RECON
    }
    (scratchpad / "design_context.md").write_text(
        "# mutated prepass generation after capture\n" + ("m" * 180) + "\n",
        encoding="utf-8",
    )
    before["design_context.md"] = hashlib.sha256(
        (scratchpad / "design_context.md").read_bytes()
    ).hexdigest()
    M._merge_recon_worker_shards(scratchpad, _merge_config(scratchpad))
    after = {
        name: hashlib.sha256((scratchpad / name).read_bytes()).hexdigest()
        for name in CANONICAL_RECON
    }
    # A registered caller must reject/supersede drift before publication.  A
    # prior committed prestate may remain visible, but it cannot be rewritten.
    assert before == after, "canonical merge consumed changed bytes after capture"


def test_worker_roster_drift_after_capture_cannot_be_silently_merged(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    _write_merge_inputs(scratchpad, tag="generation-1")
    (scratchpad / "recon_canonical_merge_source_manifest.json").write_text(
        "{}\n", encoding="utf-8"
    )
    (scratchpad / "recon_templates_patterns.md").unlink()
    (scratchpad / "recon_unselected_extra.md").write_text(
        "# unexpected worker\n", encoding="utf-8"
    )
    M._merge_recon_worker_shards(scratchpad, _merge_config(scratchpad))
    ledger = AL.read_artifact_ledger(scratchpad)
    key = "sc/thorough/evm/claude/recon/canonical_merge"
    unit = ledger.get("work_units", {}).get(key)
    assert unit is not None
    assert unit.get("semantic_status") in {"QUARANTINED", "STALE_INPUT"}
    assert unit.get("execution_state") != "OUTPUT_COMMITTED"


def test_canonical_merge_crash_never_adopts_a_mixed_public_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    _write_merge_inputs(scratchpad)
    original = Path.write_text
    writes = {"count": 0}

    def fail_mid_publication(self: Path, data: str, *args, **kwargs):
        if self.parent == scratchpad and self.name in CANONICAL_POSTIMAGE:
            writes["count"] += 1
            if writes["count"] == 5:
                original(self, "fixture partial successor\n", encoding="utf-8")
                raise OSError("cut4 merge crash fixture")
        return original(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_mid_publication)
    with pytest.raises(OSError, match="cut4 merge crash fixture"):
        M._merge_recon_worker_shards(scratchpad, _merge_config(scratchpad))
    assert writes["count"] == 5
    ledger = AL.read_artifact_ledger(scratchpad)
    key = "sc/thorough/evm/claude/recon/canonical_merge"
    unit = ledger.get("work_units", {}).get(key)
    assert unit is not None, "crash left mixed public bytes with no durable child"
    assert unit.get("semantic_status") in {"QUARANTINED", "STALE_INPUT"}
    assert unit.get("execution_state") != "OUTPUT_COMMITTED"


def test_exact_canonical_merge_resume_reuses_committed_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    _write_merge_inputs(scratchpad)
    first = M._merge_recon_worker_shards(scratchpad, _merge_config(scratchpad))
    assert set(CANONICAL_RECON).issubset(set(first))
    assert (scratchpad / "recon_signal_transform_receipt.json").is_file()
    before = {
        name: hashlib.sha256((scratchpad / name).read_bytes()).hexdigest()
        for name in CANONICAL_POSTIMAGE
    }
    original = Path.write_text
    rewrites = {"count": 0}

    def forbid_rewrite(self: Path, data: str, *args, **kwargs):
        if self.parent == scratchpad and self.name in CANONICAL_POSTIMAGE:
            rewrites["count"] += 1
            raise AssertionError("committed canonical generation rewritten")
        return original(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", forbid_rewrite)
    second = M._merge_recon_worker_shards(scratchpad, _merge_config(scratchpad))
    assert set(second) == set(CANONICAL_POSTIMAGE)
    assert rewrites["count"] == 0
    after = {
        name: hashlib.sha256((scratchpad / name).read_bytes()).hexdigest()
        for name in CANONICAL_POSTIMAGE
    }
    assert before == after


def test_supplementary_disposition_has_one_aggregate_typed_authority() -> None:
    contract = _resolve(
        "supplementary_disposition",
        inputs=CANONICAL_POSTIMAGE,
        outputs=("recon_supplementary_disposition.json",),
    )
    assert contract.model_invoked is False
    assert contract.outputs[0].writer == "DRIVER"
    assert (
        contract.outputs[0].schema_version
        == "plamen.recon_supplementary_disposition.v1"
    )


def test_instantiate_consumes_current_canonical_and_disposition_authorities(
    tmp_path: Path,
) -> None:
    required = (
        "skill_selection_catalog.json",
        "template_recommendations.md",
        "detected_patterns.md",
        "design_context.md",
        "attack_surface.md",
        "contract_inventory.md",
        "function_list.md",
        "state_variables.md",
    )
    additional = (
        "recon_prepass_finalize.json",
        "recon_signal_transform_receipt.json",
        "recon_supplementary_disposition.json",
    )
    for name in (*required, *additional):
        (tmp_path / name).write_text(
            "{}\n" if name.endswith(".json") else "# fixture\n",
            encoding="utf-8",
        )
    selected = set(D._instantiate_exact_inputs(tmp_path))
    assert set(additional).issubset(selected)


def test_instantiate_contract_requires_exact_canonical_driver_authority() -> None:
    """Tamper is rejected by producer CAS/identity, not Markdown inspection."""

    inputs = (
        "skill_selection_catalog.json",
        "template_recommendations.md",
        "detected_patterns.md",
        "design_context.md",
        "attack_surface.md",
        "contract_inventory.md",
        "function_list.md",
        "state_variables.md",
        "recon_prepass_finalize.json",
        "recon_signal_transform_receipt.json",
        "recon_supplementary_disposition.json",
    )
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="instantiate",
        work_unit_id="model",
        exact_inputs=inputs,
        exact_outputs=("spawn_manifest_proposal.md",),
        exact_writer="MODEL",
    )
    for name in (
        "recon_summary.md",
        "recon_signal_transform_receipt.json",
        "recon_supplementary_disposition.json",
    ):
        requirement = contract.input_authority(f"scratchpad:{name}")
        assert requirement.expected_writer == "DRIVER"
        assert requirement.require_same_run is True
        assert requirement.require_exact_contract is True
        assert requirement.require_exact_launch is True
