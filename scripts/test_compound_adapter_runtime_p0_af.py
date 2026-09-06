"""Red S0 fixtures for compound-adapter queue-boundary integration.

These tests deliberately stop at deterministic adaptation and persistence.
Verifier prompt rendering, compound execution, and report gates belong to later
P0-AF slices and are not specified here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import plamen_driver as D
import plamen_parsers as P
from plamen_types import L1_VERIFY_SHARD_MANIFESTS, SC_VERIFY_SHARD_MANIFESTS


CANDIDATES_NAME = "compound_candidates.json"
WORK_PLAN_NAME = "compound_verification_work_plan.json"

CASES = (
    (
        "l1",
        "L1",
        "verify_queue",
        L1_VERIFY_SHARD_MANIFESTS,
        P.ensure_verify_shard_manifests,
    ),
    (
        "sc",
        "SC",
        "sc_verify_queue",
        SC_VERIFY_SHARD_MANIFESTS,
        P.ensure_sc_verify_shard_manifests,
    ),
)


def _row(
    number: int,
    finding_id: str,
    severity: str = "Medium",
    *,
    candidate_identity: str | None = None,
) -> dict[str, str]:
    row = {
        "queue #": str(number),
        "finding id": finding_id,
        "expected output file": f"verify_{finding_id}.md",
        "severity": severity,
        "title": f"Typed active item {finding_id}",
        "bug class": "state-transition",
        "preferred tag": "CODE-TRACE",
        "location": f"src/state.rs:{number}",
        "primary artifact": "findings_inventory.md",
        "poc class": "structural",
    }
    if candidate_identity is not None:
        row["candidate identity"] = candidate_identity
    return row


def _active_rows() -> list[dict[str, str]]:
    # Distinct candidate identities prove that the adapter consumes the final
    # typed active work-item IDs, not an upstream candidate/Markdown namespace.
    return [
        _row(1, "M-01", candidate_identity="INV-101"),
        _row(2, "M-02", candidate_identity="INV-102"),
    ]


def _write_queue(scratchpad: Path, rows: list[dict[str, str]] | None = None):
    P._write_queue_subset_manifest(
        scratchpad / "verification_queue.md",
        list(rows if rows is not None else _active_rows()),
    )
    return P._read_typed_queue_work_items(scratchpad / "verification_queue.md")


def _chain_section(
    chain_id: str = "CH-01",
    *,
    blocked: str = "M-01",
    enabler: str = "M-02",
    impact: str = "A distinct composed loss becomes reachable.",
    justified: str = "YES",
    severity: str = "High",
) -> str:
    return f"""### Chain Hypothesis {chain_id} - ordered generic composition

**Blocked Finding (A)**
- **ID**: {blocked}
- **Original Verdict**: PARTIAL, **Missing Precondition**: shared state is enabled, **Type**: STATE

**Enabler Finding (B)**
- **ID**: {enabler}
- **Original Verdict**: CONFIRMED, **Postcondition Created**: shared state is enabled, **Type**: STATE

**Chain Match**
- **Match Strength**: STRONG

**Combined Attack Sequence**
1. [B] Execute the enabler transition.
2. [A] Execute the previously blocked transition.
3. [Impact] Observe the composed consequence.

**Severity Reassessment**
- Constituents: {blocked},{enabler} | Severity-Upgrade-Justified: {justified} | Combined-Impact: {impact}
- **Proposed Chain Severity**: **{severity}**
"""


def _seed(
    tmp_path: Path,
    *,
    chain_text: str | None = None,
    rows: list[dict[str, str]] | None = None,
) -> Path:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_queue(scratchpad, rows)
    if chain_text is not None:
        _publish_core_chain_authority(scratchpad, chain_text)
    return scratchpad


def _publish_core_chain_authority(
    scratchpad: Path,
    chain_text: str,
) -> None:
    """Publish the actual Core final-chain owner, never bare Markdown."""

    config = {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": "claude",
    }
    (scratchpad / "config.json").write_text(
        json.dumps(config, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    owner = canonical_work_unit_key(
        "sc", "core", "evm", "claude", "chain_agent2", "model"
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="chain_agent2",
        work_unit_id="model",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="chain_hypotheses.md",
                owner_key=owner,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
                schema_version="unstructured.v1",
                minimum_gate="FIXTURE_FINAL_CHAIN_AUTHORITY",
            ),
        ),
        model_invoked=True,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="fixture-chain",
        timeout_s=30,
        exec_mode="pty",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad,
        scratchpad.parent,
        contract,
        launch,
        run_id="compound-adapter-runtime",
    )
    (scratchpad / "chain_hypotheses.md").write_text(
        chain_text,
        encoding="utf-8",
    )
    record_work_unit_artifacts(
        scratchpad,
        scratchpad.parent,
        contract,
        launch,
        run_id="compound-adapter-runtime",
        actor="MODEL",
    )


def _payloads(scratchpad: Path) -> tuple[dict, dict]:
    return (
        json.loads((scratchpad / CANDIDATES_NAME).read_text(encoding="utf-8")),
        json.loads((scratchpad / WORK_PLAN_NAME).read_text(encoding="utf-8")),
    )


def test_final_sc_queue_materialization_persists_queue_bound_compound_plan(
    tmp_path: Path,
):
    scratchpad = _seed(tmp_path, chain_text=_chain_section())
    typed_items = P._read_typed_queue_work_items(
        scratchpad / "verification_queue.md"
    )
    assert tuple(item.work_item_id for item in typed_items) == ("M-01", "M-02")
    assert tuple(item.candidate_identity for item in typed_items) == (
        "INV-101",
        "INV-102",
    )

    P.ensure_sc_verify_shard_manifests(scratchpad)
    candidates, plan = _payloads(scratchpad)

    assert candidates["schema_version"] == "plamen.compound_candidates.v1"
    assert candidates["source_artifact"] == "chain_hypotheses.md"
    assert candidates["candidate_count"] == 1
    assert candidates["candidates"][0]["chain_id"] == "CH-01"
    assert candidates["candidates"][0]["pipeline"] == "SC"
    assert plan["schema_version"] == "plamen.compound_adapter_work_plan.v1"
    assert plan["compound_candidates_digest"] == candidates["payload_digest"]
    assert plan["active_queue_identities"] == ["M-01", "M-02"]
    work = plan["compound_work_plan"]["work_items"]
    assert [item["subject_id"] for item in work] == ["CH-01"]
    assert work[0]["verification_identity"] == "verify_CH-01"
    assert work[0]["readiness"] == "READY"
    assert work[0]["missing_constituents"] == []


def test_malformed_chain_fields_persist_typed_adapter_debt_without_dropping_valid_rows(
    tmp_path: Path,
):
    malformed = _chain_section(
        "CH-02", blocked="M-03", enabler="M-04"
    ).replace(
        "**Missing Precondition**: shared state is enabled",
        "**Unstructured Note**: value omitted",
    )
    rows = [
        *_active_rows(),
        _row(3, "M-03", candidate_identity="INV-103"),
        _row(4, "M-04", candidate_identity="INV-104"),
    ]
    scratchpad = _seed(
        tmp_path,
        chain_text=_chain_section() + "\n---\n\n" + malformed,
        rows=rows,
    )

    P.ensure_sc_verify_shard_manifests(scratchpad)
    candidates, plan = _payloads(scratchpad)

    assert [item["chain_id"] for item in candidates["candidates"]] == ["CH-01"]
    debt = candidates["adapter_issues"]
    assert len(debt) == 1
    assert debt[0]["subject_id"] == "CH-02"
    assert debt[0]["code"] == "MISSING_BLOCKED_PRECONDITION"
    assert debt[0]["blocking"] is True
    assert len(debt[0]["section_digest"]) == 64
    assert plan["adapter_issues"] == debt
    assert [
        item["subject_id"]
        for item in plan["compound_work_plan"]["work_items"]
    ] == ["CH-01"]


@pytest.mark.parametrize(
    "pipeline,pipeline_label,phase_name,manifests,ensure", CASES
)
def test_absent_chain_source_materializes_explicit_deterministic_empty_bundle(
    tmp_path: Path,
    pipeline: str,
    pipeline_label: str,
    phase_name: str,
    manifests: dict[str, str],
    ensure,
):
    del pipeline, pipeline_label, phase_name, manifests
    scratchpad = _seed(tmp_path)

    ensure(scratchpad)
    candidates, plan = _payloads(scratchpad)

    assert candidates["source_artifact"] == "chain_hypotheses.md"
    assert candidates["source_digest"] == hashlib.sha256(b"").hexdigest()
    assert candidates["candidate_count"] == 0
    assert candidates["candidates"] == []
    assert candidates["adapter_issues"] == []
    assert plan["compound_candidates_digest"] == candidates["payload_digest"]
    assert plan["active_queue_identities"] == ["M-01", "M-02"]
    assert plan["compound_work_plan"] == {
        "schema_version": "plamen.compound_work_plan.v1",
        "work_items": [],
        "alias_relations": [],
        "issues": [],
        "blocked_candidates": [],
    }


@pytest.mark.parametrize(
    "pipeline,pipeline_label,phase_name,manifests,ensure", CASES
)
def test_empty_queue_materializes_schema_valid_compound_outputs_when_optional_source_is_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    pipeline_label: str,
    phase_name: str,
    manifests: dict[str, str],
    ensure,
):
    del pipeline, pipeline_label, phase_name, manifests
    scratchpad = _seed(tmp_path, rows=[])

    def fail_optional_source(*args, **kwargs):
        raise ValueError("optional compound source is quarantined")

    monkeypatch.setattr(
        P,
        "_write_or_validate_compound_adapter_artifacts",
        fail_optional_source,
    )

    ensure(scratchpad)
    candidates, plan = _payloads(scratchpad)

    debt_path = scratchpad / "compound_verification_delivery_debt.json"
    assert debt_path.is_file()
    assert candidates["schema_version"] == "plamen.compound_candidates.v1"
    assert candidates["source_artifact"] == debt_path.name
    assert candidates["source_digest"] == hashlib.sha256(
        debt_path.read_bytes()
    ).hexdigest()
    assert candidates["candidate_count"] == 0
    assert candidates["candidates"] == []
    assert plan["schema_version"] == "plamen.compound_adapter_work_plan.v1"
    assert plan["compound_candidates_digest"] == candidates["payload_digest"]
    assert plan["active_queue_identities"] == []
    assert plan["compound_work_plan"]["work_items"] == []

    paths = (scratchpad / CANDIDATES_NAME, scratchpad / WORK_PLAN_NAME)
    before = {path: path.read_bytes() for path in paths}
    mtimes = {path: path.stat().st_mtime_ns for path in paths}
    ensure(scratchpad)
    assert {path: path.read_bytes() for path in paths} == before
    assert {path: path.stat().st_mtime_ns for path in paths} == mtimes


def test_empty_queue_debt_fallback_refuses_tampered_existing_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    scratchpad = _seed(tmp_path, rows=[])
    monkeypatch.setattr(
        P,
        "_write_or_validate_compound_adapter_artifacts",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("optional compound source is quarantined")
        ),
    )
    P.ensure_sc_verify_shard_manifests(scratchpad)
    plan_path = scratchpad / WORK_PLAN_NAME
    plan_before = plan_path.read_bytes()
    (scratchpad / CANDIDATES_NAME).write_text(
        '{"schema_version":', encoding="utf-8"
    )

    with pytest.raises((ValueError, json.JSONDecodeError)):
        P.ensure_sc_verify_shard_manifests(scratchpad)

    assert plan_path.read_bytes() == plan_before


def test_compound_bundle_writes_are_atomic_and_unchanged_inputs_are_not_rewritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scratchpad = _seed(tmp_path, chain_text=_chain_section())
    real_replace = os.replace
    replacements: list[tuple[Path, Path]] = []

    def observed_replace(source, destination):
        replacements.append((Path(source), Path(destination)))
        return real_replace(source, destination)

    monkeypatch.setattr(P.os, "replace", observed_replace)
    P.ensure_sc_verify_shard_manifests(scratchpad)
    paths = (scratchpad / CANDIDATES_NAME, scratchpad / WORK_PLAN_NAME)
    first_bytes = {path: path.read_bytes() for path in paths}
    first_mtimes = {path: path.stat().st_mtime_ns for path in paths}
    compound_replaces = [pair for pair in replacements if pair[1] in paths]

    assert {destination for _, destination in compound_replaces} == set(paths)
    assert all(source.parent == scratchpad for source, _ in compound_replaces)
    first_count = len(compound_replaces)

    P.ensure_sc_verify_shard_manifests(scratchpad)
    second_compound_replaces = [pair for pair in replacements if pair[1] in paths]

    assert len(second_compound_replaces) == first_count
    assert {path: path.read_bytes() for path in paths} == first_bytes
    assert {path: path.stat().st_mtime_ns for path in paths} == first_mtimes
    assert not list(scratchpad.glob(".compound_*.tmp"))
    assert not list(scratchpad.glob("compound_*.tmp"))


def test_uncommitted_chain_drift_is_visible_debt_not_silently_rebuilt(
    tmp_path: Path,
):
    scratchpad = _seed(tmp_path, chain_text=_chain_section())
    P.ensure_sc_verify_shard_manifests(scratchpad)
    before_candidates, before_plan = _payloads(scratchpad)

    changed = _chain_section(
        impact="A different generic composed consequence becomes reachable."
    )
    (scratchpad / "chain_hypotheses.md").write_text(changed, encoding="utf-8")
    P.ensure_sc_verify_shard_manifests(scratchpad)
    after_candidates, after_plan = _payloads(scratchpad)

    assert after_candidates == before_candidates
    assert after_plan == before_plan
    debt = json.loads(
        (scratchpad / "compound_verification_delivery_debt.json").read_text(
            encoding="utf-8"
        )
    )
    assert debt["status"] == "COMPLETED_WITH_DEBT"
    assert debt["ordinary_verification_delivery_complete"] is False
    assert "digest is invalid" in debt["error"]


def test_changed_typed_active_queue_rebuilds_only_queue_bound_plan(tmp_path: Path):
    scratchpad = _seed(tmp_path, chain_text=_chain_section())
    P.ensure_sc_verify_shard_manifests(scratchpad)
    candidates_path = scratchpad / CANDIDATES_NAME
    candidate_bytes = candidates_path.read_bytes()
    candidate_mtime = candidates_path.stat().st_mtime_ns
    _, before_plan = _payloads(scratchpad)

    _write_queue(
        scratchpad,
        [
            *_active_rows(),
            _row(3, "M-03", candidate_identity="INV-103"),
        ],
    )
    P.ensure_sc_verify_shard_manifests(scratchpad)
    _, after_plan = _payloads(scratchpad)

    assert candidates_path.read_bytes() == candidate_bytes
    assert candidates_path.stat().st_mtime_ns == candidate_mtime
    assert before_plan["active_queue_identity_digest"] != after_plan[
        "active_queue_identity_digest"
    ]
    assert after_plan["active_queue_identities"] == ["M-01", "M-02", "M-03"]
    assert before_plan["payload_digest"] != after_plan["payload_digest"]


@pytest.mark.parametrize(
    ("target", "corruption"),
    (
        (CANDIDATES_NAME, "malformed"),
        (WORK_PLAN_NAME, "digest"),
    ),
)
def test_tampered_persisted_compound_json_repairs_then_degrades_without_repairing_companion(
    tmp_path: Path, target: str, corruption: str
):
    scratchpad = _seed(tmp_path, chain_text=_chain_section())
    P.ensure_sc_verify_shard_manifests(scratchpad)
    target_path = scratchpad / target
    companion = scratchpad / (
        WORK_PLAN_NAME if target == CANDIDATES_NAME else CANDIDATES_NAME
    )
    companion_before = companion.read_bytes()
    if corruption == "malformed":
        target_path.write_text('{"schema_version":', encoding="utf-8")
    else:
        payload = json.loads(target_path.read_text(encoding="utf-8"))
        payload["payload_digest"] = "0" * 64
        target_path.write_text(json.dumps(payload), encoding="utf-8")

    P.ensure_sc_verify_shard_manifests(scratchpad)

    assert companion.read_bytes() == companion_before
    debt = json.loads(
        (scratchpad / "compound_verification_delivery_debt.json").read_text(
            encoding="utf-8"
        )
    )
    assert debt["schema_version"] == "plamen.compound_verification_delivery_debt.v1"
    assert debt["status"] == "COMPLETED_WITH_DEBT"
    assert debt["ordinary_verification_delivery_complete"] is False
    assert debt["proof_authority"] == "NONE"
    assert debt["error_class"] in {"ValueError", "RuntimeError", "JSONDecodeError"}
    assert len(debt["receipt_digest"]) == 64
    assert not (scratchpad / "compound_verification_delivery_receipt.json").exists()


def _arm_routing(
    scratchpad: Path,
    phase_name: str,
    config: dict,
) -> None:
    inventory = (
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Fixture candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/A.sol:L1\n"
        "**Preferred Tag**: [CODE-TRACE]\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Root Cause**: fixture mechanism\n"
        "**Description**: fixture mechanism remains candidate-bearing\n"
        "**Impact**: material effect if confirmed\n"
    )
    owner = canonical_work_unit_key(
        str(config["pipeline"]),
        str(config["mode"]),
        str(config["language"]),
        str(config["cli_backend"]),
        "inventory",
        "fixture_source",
    )
    contract = PhaseIOContract(
        pipeline=str(config["pipeline"]),
        mode=str(config["mode"]),
        ecosystem=str(config["language"]),
        backend=str(config["cli_backend"]),
        phase="inventory",
        work_unit_id="fixture_source",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="findings_inventory.md",
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="unstructured.v1",
                minimum_gate="FIXTURE_FINAL_INVENTORY",
            ),
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
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad,
        Path(config["project_root"]),
        contract,
        launch,
        run_id=str(config["_run_id"]),
    )
    (scratchpad / "findings_inventory.md").write_text(
        inventory,
        encoding="utf-8",
    )
    record_work_unit_artifacts(
        scratchpad,
        Path(config["project_root"]),
        contract,
        launch,
        run_id=str(config["_run_id"]),
        actor="DRIVER",
    )
    frozen = D.prepare_preverify_frozen_projection(
        scratchpad=scratchpad,
        project_root=Path(config["project_root"]),
        pipeline=str(config["pipeline"]),
        mode=str(config["mode"]),
        ecosystem=str(config["language"]),
        backend=str(config["cli_backend"]),
        phase_name=phase_name,
        run_id=str(config["_run_id"]),
    )
    assert D._finalize_preverify_inventory_successors(
        scratchpad,
        config,
        phase_name=phase_name,
        frozen_projection=frozen,
    ) == []
    execute, issues = D._arm_typed_verify_queue_routing_artifacts(
        phase_name, scratchpad, config
    )
    assert execute is True
    assert issues == []


def _generate_routing_outputs_after_arm(
    scratchpad: Path,
    phase_name: str,
    ensure,
    config: dict,
) -> set[str]:
    # Exercise the production ordering: immutable input -> pre-arm -> queue
    # generation -> mandatory routing -> commit.  Handwritten "{}" sidecars
    # are not legitimate substitutes for the typed producer.
    _write_queue(scratchpad)
    ensure(scratchpad)
    D._prepare_mandatory_primary_reverification(scratchpad, config)
    contract, _launch = D._typed_verify_queue_routing_contract_and_launch(
        phase_name, scratchpad, config
    )
    return {
        spec.identity.split(":", 1)[1]
        for spec in contract.outputs
    }


@pytest.mark.parametrize(
    "pipeline,pipeline_label,phase_name,manifests,ensure", CASES
)
def test_queue_routing_ledger_denominator_binds_both_compound_artifacts(
    tmp_path: Path,
    pipeline: str,
    pipeline_label: str,
    phase_name: str,
    manifests: dict[str, str],
    ensure,
):
    del pipeline_label
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config = {
        "pipeline": pipeline,
        "mode": "thorough",
        "language": "rust" if pipeline == "l1" else "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path),
        "_run_id": f"compound-routing-{pipeline}",
    }
    _arm_routing(scratchpad, phase_name, config)
    outputs = _generate_routing_outputs_after_arm(
        scratchpad, phase_name, ensure, config
    )

    assert D._record_typed_verify_queue_routing_artifacts(
        phase_name, scratchpad, config
    ) == []
    key = (
        f"{pipeline}/thorough/{config['language']}/claude/"
        f"{phase_name}/routing"
    )
    artifacts = read_artifact_ledger(scratchpad)["work_units"][key]["artifacts"]

    assert set(artifacts) == {f"scratchpad:{relative}" for relative in outputs}
    assert artifacts[f"scratchpad:{CANDIDATES_NAME}"]["status"] == "ACTIVE"
    assert artifacts[f"scratchpad:{WORK_PLAN_NAME}"]["status"] == "ACTIVE"


@pytest.mark.parametrize("missing", [CANDIDATES_NAME, WORK_PLAN_NAME])
def test_missing_compound_artifact_is_queue_routing_debt_not_outside_denominator(
    tmp_path: Path, missing: str
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path),
        "_run_id": "compound-routing-missing",
    }
    _arm_routing(scratchpad, "sc_verify_queue", config)
    _generate_routing_outputs_after_arm(
        scratchpad,
        "sc_verify_queue",
        P.ensure_sc_verify_shard_manifests,
        config,
    )
    (scratchpad / missing).unlink()

    issues = D._record_typed_verify_queue_routing_artifacts(
        "sc_verify_queue", scratchpad, config
    )

    assert any(
        f"scratchpad:{missing}" in issue and "required output missing" in issue
        for issue in issues
    )
    key = "sc/thorough/evm/claude/sc_verify_queue/routing"
    record = read_artifact_ledger(scratchpad)["work_units"][key]["artifacts"][
        f"scratchpad:{missing}"
    ]
    assert record["status"] == "MISSING"


@pytest.mark.parametrize(
    "ensure_name",
    ["ensure_verify_shard_manifests", "ensure_sc_verify_shard_manifests"],
)
def test_both_ensure_paths_persist_compound_bundle_after_authoritative_queue_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ensure_name: str,
):
    scratchpad = _seed(tmp_path)
    events: list[str] = []
    real_delivery = P._deliver_compound_candidates_to_queue
    real_queue_plan = P._write_or_validate_queue_work_plan
    real_compound = P._write_or_validate_compound_adapter_artifacts

    def observed_delivery(*args, **kwargs):
        events.append("delivery")
        return real_delivery(*args, **kwargs)

    def observed_queue_plan(*args, **kwargs):
        events.append("queue-plan")
        return real_queue_plan(*args, **kwargs)

    def observed_compound(*args, **kwargs):
        events.append("compound")
        return real_compound(*args, **kwargs)

    monkeypatch.setattr(
        P, "_deliver_compound_candidates_to_queue", observed_delivery
    )
    monkeypatch.setattr(
        P, "_write_or_validate_queue_work_plan", observed_queue_plan
    )
    monkeypatch.setattr(
        P, "_write_or_validate_compound_adapter_artifacts", observed_compound
    )

    getattr(P, ensure_name)(scratchpad)

    assert events[0] == "delivery"
    assert events.count("queue-plan") == 1
    assert events[-1] == "compound"
    assert events.index("queue-plan") < len(events) - 1
    assert (scratchpad / CANDIDATES_NAME).is_file()
    assert (scratchpad / WORK_PLAN_NAME).is_file()


@pytest.mark.parametrize("pipeline,phase_name", (("l1", "verify_queue"), ("sc", "sc_verify_queue")))
def test_routing_authority_is_validated_before_queue_phase_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    phase_name: str,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phase = SimpleNamespace(name=phase_name)
    events: list[str] = []

    monkeypatch.setattr(
        D,
        "read_queue_work_plan",
        lambda _root: SimpleNamespace(ordered_work_item_ids=()),
    )
    monkeypatch.setattr(
        D,
        "_record_typed_verify_queue_routing_artifacts",
        lambda *_args, **_kwargs: events.append("routing") or ["routing debt"],
    )
    monkeypatch.setattr(
        D,
        "_append_phase_io_debt",
        lambda *_args, **_kwargs: events.append("debt"),
    )
    monkeypatch.setattr(
        D,
        "_commit_phase_from_disk_debt",
        lambda *_args, **_kwargs: events.append("commit") or "committed",
    )

    result = D._commit_verification_transaction(
        phase,
        object(),
        scratchpad,
        {
            "pipeline": pipeline,
            "mode": "thorough",
            "language": "rust" if pipeline == "l1" else "evm",
            "cli_backend": "claude",
            "project_root": str(tmp_path),
            "_run_id": f"fixture-{pipeline}",
        },
        [phase],
        clean_transients=True,
    )

    assert result == "committed"
    assert events == ["routing", "debt", "commit"]
