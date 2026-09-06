"""Independent blocking fixtures for the 2026-07-25 preverify/context wave.

These tests do not prescribe an implementation.  They encode four authority
properties that the live queue boundary must satisfy:

* a content-addressed capture cannot upgrade unowned scratchpad bytes;
* a successor is isolated by pipeline/mode/ecosystem/backend/run;
* a mode-valid chain producer remains consumable by the compound adapter; and
* an undeclared delivery-debt file cannot become a committed causal input.

The final two tests retain green evidence for post-arm optional-input drift and
for queue-owned safe-base debt leaving ``chain.degraded`` byte-identical.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_inputs,
    write_artifact_ledger,
)
import chain_tail_authority as CTA
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
import plamen_driver as D
import plamen_parsers as P
from plamen_types import Phase
from preverify_frozen_projection import PreverifyFrozenProjectionError
import test_live_verify_queue_driver_adapter_cutover as ADAPTER_FIXTURE


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


def _producer() -> str:
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


def _config(
    project: Path,
    scratchpad: Path,
    *,
    pipeline: str = "sc",
    mode: str = "thorough",
    ecosystem: str = "evm",
    backend: str = "claude",
    run_id: str = "review-original-run",
) -> dict[str, object]:
    return {
        "pipeline": pipeline,
        "mode": mode,
        "language": ecosystem,
        "cli_backend": backend,
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": run_id,
    }


def _seed_preverify(project: Path) -> tuple[Path, dict[str, object]]:
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "findings_inventory.md").write_text(
        _inventory(), encoding="utf-8"
    )
    (scratchpad / "depth_consensus_invariant_findings.md").write_text(
        _producer(), encoding="utf-8"
    )
    assert D._write_finding_records_from_inventory(scratchpad) == 1
    return scratchpad, _config(project, scratchpad)


def _chain_phase() -> Phase:
    return Phase(
        "chain_iter2",
        ["fixture"],
        ["chain_iteration2.md"],
        base_timeout_s=30,
        modes={"thorough"},
        critical=False,
        model="sonnet",
    )


def _chain_hypothesis() -> str:
    return """### Chain Hypothesis CH-01 - ordered generic composition

**Blocked Finding (A)**
- **ID**: M-01
- **Original Verdict**: PARTIAL, **Missing Precondition**: shared state is enabled, **Type**: STATE

**Enabler Finding (B)**
- **ID**: M-02
- **Original Verdict**: CONFIRMED, **Postcondition Created**: shared state is enabled, **Type**: STATE

**Chain Match**
- **Match Strength**: STRONG

**Combined Attack Sequence**
1. [B] Execute the enabler transition.
2. [A] Execute the previously blocked transition.
3. [Impact] Observe the composed consequence.

**Severity Reassessment**
- Constituents: M-01,M-02 | Severity-Upgrade-Justified: YES | Combined-Impact: A distinct composed loss becomes reachable.
- **Proposed Chain Severity**: **High**
"""


def _queue_rows() -> list[dict[str, str]]:
    return [
        {
            "queue #": str(index),
            "finding id": finding_id,
            "expected output file": f"verify_{finding_id}.md",
            "severity": "Medium",
            "title": f"candidate {finding_id}",
            "bug class": "state-transition",
            "preferred tag": "CODE-TRACE",
            "location": f"src/A.sol:L{index}",
            "primary artifact": "findings_inventory.md",
            "poc class": "structural",
        }
        for index, finding_id in enumerate(("M-01", "M-02"), start=1)
    ]


def _seed_core_chain_authorities(
    project: Path,
    *,
    with_chain_agent2: bool,
) -> tuple[Path, dict[str, object]]:
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    for name, body in (
        ("composition_coverage.md", "# Composition Coverage\n"),
        ("chain_hypotheses.md", "# Chain Hypotheses\n"),
        ("findings_inventory.md", "# Findings Inventory\n"),
    ):
        (scratchpad / name).write_text(body, encoding="utf-8")
    config = _config(
        project,
        scratchpad,
        mode="core",
        run_id="review-core-chain-run",
    )
    config["_chain_state_resolution_initializes_tail"] = True
    contract, launch = D._chain_state_resolution_contract_and_launch(
        scratchpad=scratchpad,
        config=config,
        phase=_chain_phase(),
    )
    execute, issues = D._arm_deterministic_driver_work_unit(
        scratchpad=scratchpad,
        project_root=project,
        contract=contract,
        launch=launch,
        run_id=str(config["_run_id"]),
    )
    assert execute is True
    assert issues == []
    (scratchpad / "chain_state_resolution.json").write_text(
        '{"schema_version":"plamen.chain_state_resolution.v1"}\n',
        encoding="utf-8",
    )
    CTA.initialize_chain_tail(
        scratchpad, [], shard_size=1, activate_first_shard=False
    )
    # State resolution owns the complete initialization denominator.  The
    # tail helper writes its structured controls; materialize the neutral
    # non-tail outputs without later rewriting their committed bytes.
    for relative in D._CHAIN_TAIL_INITIALIZATION_OUTPUTS:
        path = scratchpad / relative
        if path.is_file():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            (
                '{"schema_version":"fixture.chain-state-resolution.v1"}\n'
                if path.suffix == ".json"
                else f"# Fixture state-resolution output: {relative}\n"
            ),
            encoding="utf-8",
        )
    assert D._commit_deterministic_driver_work_unit(
        scratchpad=scratchpad,
        project_root=project,
        contract=contract,
        launch=launch,
        run_id=str(config["_run_id"]),
    ) == []
    if not with_chain_agent2:
        return scratchpad, config

    # The remaining three inputs are not state-resolution outputs.  Preserve
    # the committed chain_candidate_pairs/variable map/enabler bytes so the
    # model consumes their exact active producer authority.
    for name in (
        "hypotheses.md",
        "finding_mapping.md",
        "precedent_context.md",
    ):
        (scratchpad / name).write_text("# model input\n", encoding="utf-8")
    for name in (
        "chain_hypotheses.md",
        "composition_coverage.md",
        "synthesis_full.md",
    ):
        (scratchpad / name).unlink(missing_ok=True)
    inputs = (
        "hypotheses.md",
        "finding_mapping.md",
        "enabler_results.md",
        "variable_finding_map.md",
        "chain_candidate_pairs.md",
        "findings_inventory.md",
        "precedent_context.md",
    )
    model_contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="chain_agent2",
        work_unit_id="model",
        exact_inputs=inputs,
    )
    model_launch = LaunchSpec(
        work_unit_key=model_contract.key,
        pipeline=model_contract.pipeline,
        mode=model_contract.mode,
        ecosystem=model_contract.ecosystem,
        backend=model_contract.backend,
        model="sonnet",
        timeout_s=30,
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad,
        project,
        model_contract,
        model_launch,
        run_id=str(config["_run_id"]),
    )
    (scratchpad / "chain_hypotheses.md").write_text(
        _chain_hypothesis(), encoding="utf-8"
    )
    (scratchpad / "composition_coverage.md").write_text(
        "# Composition Coverage\n", encoding="utf-8"
    )
    (scratchpad / "synthesis_full.md").write_text(
        "# Synthesis\n", encoding="utf-8"
    )
    record_work_unit_artifacts(
        scratchpad,
        project,
        model_contract,
        model_launch,
        run_id=str(config["_run_id"]),
        actor="MODEL",
    )
    return scratchpad, config


def test_capture_refuses_unowned_required_preimages_when_ledger_exists(
    tmp_path: Path,
) -> None:
    """B1: hashes without a producer/external-preimage authority are not roots."""

    scratchpad, config = _seed_preverify(tmp_path)
    write_artifact_ledger(
        scratchpad,
        {
            "version": 2,
            "artifacts": {},
            "artifact_bindings": {},
            "work_units": {},
        },
    )

    with pytest.raises(
        PreverifyFrozenProjectionError,
        match="producer|authority|unowned",
    ):
        D.prepare_preverify_frozen_projection(
            scratchpad=scratchpad,
            project_root=tmp_path,
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase_name="sc_verify_queue",
            run_id=str(config["_run_id"]),
            chain_pair_projection=None,
        )
    ledger = read_artifact_ledger(scratchpad)
    committed_captures = [
        unit
        for key, unit in ledger["work_units"].items()
        if (
            "/preverify_capture." in key
            and unit.get("execution_state") == "OUTPUT_COMMITTED"
            and unit.get("semantic_status") == "ACTIVE"
        )
    ]
    assert committed_captures == []


def test_capture_contract_rejects_mutable_root_pair_without_frozen_projection(
    tmp_path: Path,
) -> None:
    """Canonical mutable roots are never a substitute for a frozen pair."""

    scratchpad, config = _seed_preverify(tmp_path)
    issues = D._finalize_preverify_inventory_successors(
        scratchpad,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=None,
    )
    assert issues
    assert any(
        "paired findings_inventory.md and finding_records.json projections"
        in issue
        for issue in issues
    )


@pytest.mark.parametrize(
    ("phase_name", "changes"),
    (
        ("sc_verify_queue", {"cli_backend": "codex"}),
        ("sc_verify_queue", {"mode": "core"}),
        ("sc_verify_queue", {"language": "solana"}),
        ("verify_queue", {"pipeline": "l1", "language": "rust"}),
        ("sc_verify_queue", {"_run_id": "review-foreign-run"}),
    ),
    ids=("backend", "mode", "ecosystem", "pipeline", "run"),
)
def test_queue_arm_refuses_successor_from_foreign_runtime_dimension(
    tmp_path: Path,
    phase_name: str,
    changes: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-byte successor is not portable across runtime dimensions."""

    scratchpad, original = _seed_preverify(tmp_path)
    # This fixture targets the successor-to-queue authority boundary.  Seed
    # its inputs through real current-run PhaseIO owners and the exact frozen
    # pair contract so it cannot bypass the independent B1 capture-root gate.
    fixture_config = {
        **original,
        "backend": str(original["cli_backend"]),
        "ecosystem": str(original["language"]),
    }
    ADAPTER_FIXTURE._claim_group(
        root=scratchpad,
        project=tmp_path,
        config=fixture_config,
        run_id=str(original["_run_id"]),
        paths=(
            "findings_inventory.md",
            "finding_records.json",
            "depth_consensus_invariant_findings.md",
        ),
        work_unit_id="preverify_capture_sources",
    )
    frozen = D.prepare_preverify_frozen_projection(
        scratchpad=scratchpad,
        project_root=tmp_path,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=str(original["_run_id"]),
        chain_pair_projection=None,
    )
    assert D._finalize_preverify_inventory_successors(
        scratchpad,
        original,
        phase_name="sc_verify_queue",
        frozen_projection=frozen,
    ) == []
    foreign = dict(original)
    foreign.update(changes)

    execute, issues = D._arm_typed_verify_queue_routing_artifacts(
        phase_name, scratchpad, foreign
    )

    assert execute is False, (
        "queue routing armed before rejecting a successor produced for a "
        "different pipeline/mode/ecosystem/backend/run"
    )
    assert issues


def test_core_compound_adapter_consumes_mode_valid_final_authority(
    tmp_path: Path,
) -> None:
    """Core has no tail reconcile; its valid ChainAgent2 work must survive."""

    scratchpad, _config_payload = _seed_core_chain_authorities(
        tmp_path, with_chain_agent2=True
    )
    ledger = read_artifact_ledger(scratchpad)
    candidate_binding = ledger["artifact_bindings"][
        "scratchpad:chain_composition_verification_candidates.json"
    ]
    assert candidate_binding["owner_key"].endswith(
        "/chain/state_resolution"
    )
    P._write_queue_subset_manifest(
        scratchpad / "verification_queue.md", _queue_rows()
    )
    typed_items = P._read_typed_queue_work_items(
        scratchpad / "verification_queue.md"
    )

    try:
        candidates, _plan = P._write_or_validate_compound_adapter_artifacts(
            scratchpad, typed_items, "SC", mode="core"
        )
    except ValueError as exc:
        pytest.fail(
            "mode-valid Core compound authority was rejected instead of "
            f"routing committed ChainAgent2 work: {exc}"
        )

    assert candidates["source_artifact"] == "chain_hypotheses.md"
    assert candidates["candidate_count"] == 1
    assert candidates["candidates"][0]["chain_id"] == "CH-01"


def test_core_compound_adapter_rejects_stale_final_chain_agent_authority(
    tmp_path: Path,
) -> None:
    """Core never falls back to the earlier state-resolution bootstrap."""

    scratchpad, _config_payload = _seed_core_chain_authorities(
        tmp_path, with_chain_agent2=True
    )
    (scratchpad / "chain_hypotheses.md").write_text(
        _chain_hypothesis().replace("CH-01", "CH-02"),
        encoding="utf-8",
    )
    P._write_queue_subset_manifest(
        scratchpad / "verification_queue.md", _queue_rows()
    )
    typed_items = P._read_typed_queue_work_items(
        scratchpad / "verification_queue.md"
    )

    with pytest.raises(ValueError, match="authority|ancestry|digest"):
        P._write_or_validate_compound_adapter_artifacts(
            scratchpad, typed_items, "SC", mode="core"
        )


def test_thorough_compound_adapter_rejects_core_bootstrap_as_final_authority(
    tmp_path: Path,
) -> None:
    """Thorough retains its terminal tail-reconcile authority boundary."""

    scratchpad, _config_payload = _seed_core_chain_authorities(
        tmp_path, with_chain_agent2=True
    )
    P._write_queue_subset_manifest(
        scratchpad / "verification_queue.md", _queue_rows()
    )
    typed_items = P._read_typed_queue_work_items(
        scratchpad / "verification_queue.md"
    )

    with pytest.raises(ValueError, match="authority|ancestry|tail"):
        P._write_or_validate_compound_adapter_artifacts(
            scratchpad, typed_items, "SC", mode="thorough"
        )


def test_l1_compound_adapter_rejects_foreign_sc_chain_authority(
    tmp_path: Path,
) -> None:
    """L1 has no SC chain phase and cannot adopt its persisted residue."""

    scratchpad, _config_payload = _seed_core_chain_authorities(
        tmp_path, with_chain_agent2=True
    )
    P._write_queue_subset_manifest(
        scratchpad / "verification_queue.md", _queue_rows()
    )
    typed_items = P._read_typed_queue_work_items(
        scratchpad / "verification_queue.md"
    )

    with pytest.raises(ValueError, match="L1|SC chain"):
        P._write_or_validate_compound_adapter_artifacts(
            scratchpad, typed_items, "L1", mode="core"
        )


def test_compound_delivery_debt_cannot_be_hidden_input_to_committed_outputs(
    tmp_path: Path,
) -> None:
    """B7: causal debt bytes require a typed producer and input binding."""

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    for name in (
        "findings_inventory.md",
        "preverify_inventory_successor.json",
        "finding_delivery_successor.json",
    ):
        (scratchpad / name).write_text("{}\n", encoding="utf-8")
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="sc_verify_queue",
        work_unit_id="routing",
        exact_inputs=(
            "findings_inventory.md",
            "preverify_inventory_successor.json",
            "finding_delivery_successor.json",
        ),
        exact_outputs=(
            "compound_candidates.json",
            "compound_verification_work_plan.json",
        ),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
    )
    execute, arm_issues = D._arm_deterministic_driver_work_unit(
        scratchpad=scratchpad,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id="review-hidden-debt-run",
    )
    if not execute or arm_issues:
        # Rejecting the unowned predecessor before any output is also a valid
        # closure; only the currently reachable clean commit is forbidden.
        return
    debt: dict[str, object] = {
        "schema_version": (
            "plamen.compound_verification_delivery_debt.v1"
        ),
        "status": "COMPLETED_WITH_DEBT",
        "ordinary_verification_delivery_complete": False,
        "proof_authority": "NONE",
        "error_class": "FixtureDebt",
        "error": "optional source omitted",
    }
    debt["receipt_digest"] = hashlib.sha256(
        json.dumps(
            debt,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    debt_path = scratchpad / "compound_verification_delivery_debt.json"
    debt_path.write_text(
        json.dumps(debt, sort_keys=True) + "\n", encoding="utf-8"
    )
    P._write_empty_compound_adapter_artifacts_from_delivery_debt(
        scratchpad, (), "SC"
    )

    commit_issues = D._commit_deterministic_driver_work_unit(
        scratchpad=scratchpad,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id="review-hidden-debt-run",
    )

    assert commit_issues, (
        "B7: queue outputs committed even though their exact causal "
        "compound-verification debt bytes were neither an immutable input nor "
        "a separately committed child-producer output"
    )


def test_optional_context_drift_after_arm_is_commit_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The live PhaseIO denominator catches ordinary post-arm context drift."""

    scratchpad, config = _seed_core_chain_authorities(
        tmp_path, with_chain_agent2=False
    )
    for name in (
        "preverify_inventory_successor.json",
        "finding_delivery_successor.json",
    ):
        (scratchpad / name).write_text("{}\n", encoding="utf-8")
    optional = "chain_composition_verification_candidates.json"
    contract, launch = D._typed_verify_queue_routing_contract_and_launch(
        "sc_verify_queue",
        scratchpad,
        config,
        optional_inputs={optional},
    )
    # This fixture isolates PhaseIO's post-arm byte-drift check. Mandatory
    # successor provenance is covered independently above; bypass that stricter
    # queue-boundary predicate only while constructing this low-level arm.
    monkeypatch.setattr(
        D, "semantic_input_producer_authority_issues", lambda *_a, **_k: []
    )
    execute, issues = D._arm_deterministic_driver_work_unit(
        scratchpad=scratchpad,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id=str(config["_run_id"]),
    )
    assert execute is True
    assert issues == []

    with (scratchpad / optional).open("ab") as stream:
        stream.write(b"\npost-arm drift\n")
    drift = validate_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=str(config["_run_id"]),
    )

    assert any(optional in issue for issue in drift)


def test_safe_base_context_debt_never_mutates_chain_degraded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Queue context debt is queue-owned typed data, not chain-phase mutation."""

    chain_debt = tmp_path / "chain.degraded"
    original = b"[CHAIN_OWNER] preserve exact bytes\r\n"
    chain_debt.write_bytes(original)
    (tmp_path / "chain_equivalence_proposals.json").write_text(
        '{"unowned":true}\n', encoding="utf-8"
    )
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

    execute, issues = D._arm_typed_verify_queue_routing_artifacts(
        "sc_verify_queue",
        tmp_path,
        _config(tmp_path.parent, tmp_path),
    )

    assert execute is True
    assert issues == []
    assert chain_debt.read_bytes() == original
    status = json.loads(
        (tmp_path / "verify_queue_context_input_status.json").read_text(
            encoding="utf-8"
        )
    )
    assert status["state"] == "COMPLETED_WITH_DEBT_SAFE_BASE"
    assert status["safe_base_routing"] is True
    assert status["proof_authority"] == "NONE"
