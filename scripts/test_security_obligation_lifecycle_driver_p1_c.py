"""Final P1-C lifecycle driver/PhaseIO/report-retention fixtures."""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

from artifact_ledger import (
    detect_semantic_input_drift,
    read_artifact_ledger,
    record_work_unit_inputs,
    semantic_dependency_invalidation_plan,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
import plamen_driver as D
import plamen_mechanical as M
import security_obligation_lifecycle as L
from test_security_obligation_lifecycle_p1_c import (
    RUN_ID,
    _apply_successor,
    _setup,
    _write_mandatory_chain,
)


def _config(root: Path) -> dict[str, str]:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(root.parent),
        "scratchpad": str(root),
        "_run_id": RUN_ID,
    }


def test_final_lifecycle_contract_is_exact_driver_owned() -> None:
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_index",
        work_unit_id="security_obligation_lifecycle.final",
        exact_inputs=("security_obligation_authority.json",),
        exact_outputs=(
            L.AUTHORITY_FILE,
            L.PROJECTION_FILE,
            L.REPORT_RETENTION_FILE,
        ),
    )

    assert contract.model_invoked is False
    assert contract.immutable_inputs == (
        "scratchpad:security_obligation_authority.json",
    )
    assert {row.identity for row in contract.outputs} == {
        f"scratchpad:{L.AUTHORITY_FILE}",
        f"scratchpad:{L.PROJECTION_FILE}",
        f"scratchpad:{L.REPORT_RETENTION_FILE}",
    }
    assert {row.writer for row in contract.outputs} == {"DRIVER"}


def test_driver_publishes_and_phaseio_binds_final_lifecycle(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="CONTESTED")
    config = _config(root)

    assert D._record_security_obligation_lifecycle_phase_io(root, config) == []
    assert D._validate_security_obligation_lifecycle_phase_io(root, config) == []

    contract, _launch = D._security_obligation_lifecycle_contract_and_launch(
        root, config
    )
    unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert unit["semantic_status"] == "ACTIVE"
    assert set(unit["artifacts"]) == {
        f"scratchpad:{L.AUTHORITY_FILE}",
        f"scratchpad:{L.PROJECTION_FILE}",
        f"scratchpad:{L.REPORT_RETENTION_FILE}",
    }
    retention = (root / L.REPORT_RETENTION_FILE).read_text(encoding="utf-8")
    assert aliases[0] in retention
    assert "VERIFIED_CONTESTED" in retention


def test_resume_validation_is_side_effect_free_and_detects_verifier_tamper(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    items = _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    config = _config(root)
    assert D._record_security_obligation_lifecycle_phase_io(root, config) == []
    authority_before = (root / L.AUTHORITY_FILE).read_bytes()
    projection_before = (root / L.PROJECTION_FILE).read_bytes()
    retention_before = (root / L.REPORT_RETENTION_FILE).read_bytes()

    verifier = root / items[0].expected_output_file
    verifier.write_bytes(verifier.read_bytes() + b"\nTAMPER\n")
    issues = D._validate_security_obligation_lifecycle_phase_io(root, config)

    assert issues
    assert any(
        "differs from current lifecycle inputs" in issue
        or "input binding" in issue.lower()
        or "changed" in issue.lower()
        for issue in issues
    )
    assert (root / L.AUTHORITY_FILE).read_bytes() == authority_before
    assert (root / L.PROJECTION_FILE).read_bytes() == projection_before
    assert (root / L.REPORT_RETENTION_FILE).read_bytes() == retention_before


def test_lifecycle_input_drift_directionally_invalidates_report_model(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    items = _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    config = _config(root)
    assert D._record_security_obligation_lifecycle_phase_io(root, config) == []
    config["_security_obligation_lifecycle_consumer_state"] = {
        "report_index": True
    }
    for name in (
        "report_index_coverage_seed.md",
        "candidate_semantic_facets.md",
        "candidate_semantic_facets.json",
    ):
        path = root / name
        if not path.exists():
            path.write_text("{}\n" if path.suffix == ".json" else "# seed\n", encoding="utf-8")
    phase = next(row for row in D.SC_PHASES if row.name == "report_index")
    report_contract, report_launch = D._typed_model_phase_contract_and_launch(
        phase, root, config
    )
    record_work_unit_inputs(
        root,
        root.parent,
        report_contract,
        report_launch,
        run_id=RUN_ID,
    )

    verifier = root / items[0].expected_output_file
    verifier.write_bytes(verifier.read_bytes() + b"\nchanged\n")
    drift = detect_semantic_input_drift(root, root.parent, run_id=RUN_ID)
    plan = semantic_dependency_invalidation_plan(
        read_artifact_ledger(root),
        drift["changed_input_identities"],
        run_id=RUN_ID,
    )

    lifecycle_contract, _ = D._security_obligation_lifecycle_contract_and_launch(
        root, config
    )
    assert lifecycle_contract.key in plan["invalidated_work_unit_keys"]
    assert report_contract.key in plan["invalidated_work_unit_keys"]


def test_report_human_review_surface_consumes_exact_retention_projection(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="REFUTED")
    D._record_security_obligation_lifecycle_phase_io(root, _config(root))

    appendix = M._build_human_review_appendix(root)

    assert "Security obligation lifecycle retention" in appendix
    assert "coverage-ref-" in appendix
    assert aliases[0] not in appendix
    assert "NEGATIVE_PROPOSAL_RETAINED" in appendix


def test_final_boundary_precedes_report_prework_and_model_binding() -> None:
    source = inspect.getsource(D.main)
    lifecycle_at = source.index(
        "_record_security_obligation_lifecycle_phase_io("
    )
    prework_at = source.index(
        "_record_report_index_prework_artifacts(", lifecycle_at
    )
    report_boundary_at = source.rfind(
        'if phase.name == "report_index":', 0, lifecycle_at
    )
    model_bind_at = source.index(
        "_bind_typed_model_phase_inputs(", prework_at
    )
    assert report_boundary_at >= 0
    assert lifecycle_at < prework_at
    assert prework_at < model_bind_at


def test_crash_bound_inputs_then_new_child_denominator_resume_converges(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    config = _config(root)
    before = L.security_obligation_lifecycle_input_artifacts(root)
    old_contract, old_launch = D._security_obligation_lifecycle_contract_and_launch(
        root, config, exact_inputs=before
    )
    old_unit = record_work_unit_inputs(
        root, root.parent, old_contract, old_launch, run_id=RUN_ID
    )
    bundle_root = root / "negative_closure_provider_bundles"
    bundle_root.mkdir()
    (bundle_root / "late-child.json").write_text("{}\n", encoding="utf-8")

    issues = D._record_security_obligation_lifecycle_phase_io(root, config)

    assert not any("transaction failed" in issue for issue in issues), issues
    new_contract, _ = D._security_obligation_lifecycle_contract_and_launch(root, config)
    unit = read_artifact_ledger(root)["work_units"][new_contract.key]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["input_set_digest"] != old_unit["input_set_digest"]
    assert unit["input_rebind_history"]
    assert D._validate_security_obligation_lifecycle_phase_io(root, config) == []


def test_crash_after_output_before_artifact_commit_resumes_idempotently(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    config = _config(root)
    contract, launch = D._security_obligation_lifecycle_contract_and_launch(
        root, config
    )
    unit = record_work_unit_inputs(
        root, root.parent, contract, launch, run_id=RUN_ID
    )
    expected = {
        identity.split(":", 1)[1]: row["sha256"]
        for identity, row in unit["input_bindings"].items()
    }
    L.write_security_obligation_lifecycle(
        root, expected_input_sha256=expected
    )

    assert D._record_security_obligation_lifecycle_phase_io(root, config) == []
    first = read_artifact_ledger(root)["work_units"][contract.key]
    assert first["semantic_status"] == "ACTIVE"
    assert D._record_security_obligation_lifecycle_phase_io(root, config) == []
    second = read_artifact_ledger(root)["work_units"][contract.key]
    assert second == first


def test_byte_mutation_between_bind_and_build_rebinds_before_commit(
    tmp_path: Path, monkeypatch
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    config = _config(root)
    bundle_root = root / "negative_closure_provider_bundles"
    bundle_root.mkdir()
    semantic_input = bundle_root / "current-child.json"
    semantic_input.write_text("{}\n", encoding="utf-8")
    real_write = L.write_security_obligation_lifecycle
    calls = 0

    def mutate_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            semantic_input.write_text('{"drift":true}\n', encoding="utf-8")
        return real_write(*args, **kwargs)

    monkeypatch.setattr(L, "write_security_obligation_lifecycle", mutate_once)

    issues = D._record_security_obligation_lifecycle_phase_io(root, config)

    assert calls >= 2
    assert not any("transaction failed" in issue for issue in issues), issues
    contract, _ = D._security_obligation_lifecycle_contract_and_launch(root, config)
    unit = read_artifact_ledger(root)["work_units"][contract.key]
    binding = unit["input_bindings"][
        "scratchpad:negative_closure_provider_bundles/current-child.json"
    ]
    assert binding["sha256"] == hashlib.sha256(semantic_input.read_bytes()).hexdigest()
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["input_rebind_history"]


def test_driver_run_mismatch_never_records_active_lifecycle_outputs(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    config = _config(root)
    config["_run_id"] = "different-run"

    issues = D._record_security_obligation_lifecycle_phase_io(root, config)

    assert any("run_id differs" in issue for issue in issues)
    contract, _ = D._security_obligation_lifecycle_contract_and_launch(root, config)
    unit = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    assert not isinstance(unit, dict) or unit.get("semantic_status") != "ACTIVE"
    assert D._validate_security_obligation_lifecycle_phase_io(root, config)


def _write_delivered_body(root: Path, *, finding_id: str, report_id: str = "M-01") -> None:
    (root / "report_records.json").write_text(
        json.dumps(
            {
                "schema_version": "plamen.report_records.v1",
                "source": "report_index.md",
                "active": [{
                    "report_id": report_id,
                    "finding_id": finding_id,
                    "candidate_ids": [],
                    "absorbed_finding_ids": [],
                    "report_blocked": False,
                }],
                "excluded": [],
                "consolidation_map": [],
            }
        ) + "\n",
        encoding="utf-8",
    )
    (root / "report_medium.md").write_text(
        f"## [{report_id}] Delivered exact finding\n\nMaterial body.\n",
        encoding="utf-8",
    )


def test_appendix_replays_json_when_markdown_cache_deleted_or_tampered(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="REFUTED")
    D._record_security_obligation_lifecycle_phase_io(root, _config(root))
    retention = root / L.REPORT_RETENTION_FILE

    retention.unlink()
    deleted = M._build_human_review_appendix(root)
    retention.write_text("forged SOT-AAAAAAAAAAAAAAAAAAAAAAAA\n", encoding="utf-8")
    tampered = M._build_human_review_appendix(root)

    for appendix in (deleted, tampered):
        assert "coverage-ref-" in appendix
        assert "STALE_OR_MISSING" in appendix
        assert "SOT-" not in appendix


def test_delivered_unique_positive_is_not_duplicated_but_dropped_one_is_retained(
    tmp_path: Path,
) -> None:
    (tmp_path / "delivered").mkdir()
    delivered_root, aliases = _setup(tmp_path / "delivered", count=1)
    items = _write_mandatory_chain(delivered_root, aliases, verdict="CONFIRMED")
    D._record_security_obligation_lifecycle_phase_io(
        delivered_root, _config(delivered_root)
    )
    _write_delivered_body(delivered_root, finding_id=items[0].work_item_id)
    assert "Security obligation lifecycle retention" not in M._build_human_review_appendix(
        delivered_root
    )

    (tmp_path / "dropped").mkdir()
    dropped_root, dropped_aliases = _setup(tmp_path / "dropped", count=1)
    _write_mandatory_chain(dropped_root, dropped_aliases, verdict="CONFIRMED")
    D._record_security_obligation_lifecycle_phase_io(dropped_root, _config(dropped_root))
    dropped = M._build_human_review_appendix(dropped_root)
    assert "Retained coverage obligations**: 1" in dropped
    assert "coverage-ref-" in dropped


def test_shared_work_item_never_suppresses_sibling_aliases_without_alias_receipt(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=2)
    items = _write_mandatory_chain(
        root, aliases, verdict="CONFIRMED", shared_work_item=True
    )
    D._record_security_obligation_lifecycle_phase_io(root, _config(root))
    _write_delivered_body(root, finding_id=items[0].work_item_id)

    appendix = M._build_human_review_appendix(root)

    assert "Retained coverage obligations**: 2" in appendix
    assert appendix.count("coverage-ref-") >= 2
    assert "SOT-" not in appendix


def test_open_alias_retention_is_uncapped_client_safe_and_idempotent(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=13)
    D._record_security_obligation_lifecycle_phase_io(root, _config(root))

    first = M._build_human_review_appendix(root)
    second = M._build_human_review_appendix(root)

    assert first == second
    assert "Retained coverage obligations**: 13" in first
    assert first.count("coverage-ref-") >= 13
    assert all(alias not in first for alias in aliases)
    assert "SOT-" not in first


def test_nonrow_or_malformed_lifecycle_debt_never_zero_cleans_appendix(
    tmp_path: Path,
) -> None:
    (tmp_path / "zero").mkdir()
    root, _aliases = _setup(tmp_path / "zero", count=0)
    D._record_security_obligation_lifecycle_phase_io(root, _config(root))
    zero = M._build_human_review_appendix(root)
    assert "Lifecycle authority debt" in zero
    assert "UNKNOWN" in zero or "DEGRADED" in zero

    (tmp_path / "malformed").mkdir()
    root2, aliases2 = _setup(tmp_path / "malformed", count=1)
    _write_mandatory_chain(root2, aliases2, verdict="CONFIRMED")
    D._record_security_obligation_lifecycle_phase_io(root2, _config(root2))
    source = root2 / "security_obligation_authority.json"
    source.write_bytes(source.read_bytes() + b"tamper")
    malformed = M._build_human_review_appendix(root2)
    assert "authoritative lifecycle/PhaseIO replay failed" in malformed


def test_selected_ledger_or_lifecycle_json_tamper_is_fail_visible_at_assembly(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    D._record_security_obligation_lifecycle_phase_io(root, _config(root))
    ledger = root / "_artifact_state.json"
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    key = next(
        key for key in payload["work_units"]
        if key.endswith("/report_index/security_obligation_lifecycle.final")
    )
    payload["work_units"][key]["semantic_status"] = "INPUTS_BOUND"
    ledger.write_text(json.dumps(payload), encoding="utf-8")

    appendix = M._build_human_review_appendix(root)

    assert "authoritative lifecycle/PhaseIO replay failed" in appendix


def test_driver_phaseio_binds_successor_receipt_not_transformed_model_output(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    items = _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    successor = _apply_successor(root, items[0].work_item_id)
    config = _config(root)

    assert D._record_security_obligation_lifecycle_phase_io(root, config) == []
    contract, _ = D._security_obligation_lifecycle_contract_and_launch(root, config)
    unit = read_artifact_ledger(root)["work_units"][contract.key]

    assert f"scratchpad:{successor.name}" in unit["input_bindings"]
    assert f"scratchpad:{items[0].expected_output_file}" not in unit["input_bindings"]
    assert D._validate_security_obligation_lifecycle_phase_io(root, config) == []
