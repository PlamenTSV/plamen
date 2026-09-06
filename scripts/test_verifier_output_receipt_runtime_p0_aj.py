"""Red integration contracts for plan-owned verifier outputs and receipts.

The typed queue/work-plan substrate is already covered independently.  These
fixtures specify the live cutover: a policy-bearing verifier shard may consume
only the exact output identities owned by its persisted ``QueueWorkPlan`` and
must bind those bytes to immutable identity/receipt sidecars.  Legacy filename
variants remain available only to isolated callers that pass no execution
policy.

This file intentionally performs no model, compiler, network, or shell work.
"""
from __future__ import annotations

import ast
from dataclasses import replace
import inspect
import json
from pathlib import Path
import sys

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(REPO_ROOT))

import plamen_driver as D  # noqa: E402
import plamen_parsers as P  # noqa: E402
import plamen_validators as V  # noqa: E402
from plamen_types import (  # noqa: E402
    L1_VERIFY_SHARD_MANIFESTS,
    SC_VERIFY_SHARD_MANIFESTS,
)
from queue_work_items import (  # noqa: E402
    QueueWorkItem,
    VerifierOutputIdentity,
    VerifierOutputReceipt,
    build_queue_work_plan,
)
from verification_policy import (  # noqa: E402
    AuditMode,
    Backend,
    Ecosystem,
    Pipeline,
    Platform,
    resolve_execution_policy,
)


PLAN_NAME = "verification_queue.work_plan.json"
LAUNCH_DIGEST = "a" * 64


def _row(number: int, finding_id: str) -> dict[str, str]:
    return {
        "queue #": str(number),
        "finding id": finding_id,
        "expected output file": f"verify_{finding_id}.md",
        "severity": "High",
        "title": f"Generic state-transition candidate {number}",
        "bug class": "state-transition",
        "preferred tag": "POC-PASS",
        "location": f"src/module_{number}.ext:{number}",
        "primary artifact": "findings_inventory.md",
        "poc class": "property",
    }


def _verify_bytes(finding_id: str) -> bytes:
    return (
        f"# Verification: {finding_id}\n\n"
        f"**Finding ID**: {finding_id}\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Preferred Tag**: [POC-PASS]\n"
        "### PoC Attempt\n"
        "- PoC Class: property\n"
        "- Attempted: YES\n"
        "- Test File: tests/generic_verification_test.ext\n"
        "- Command: test-runner --case generic_verification\n"
        "### Execution Result\n"
        "- Compiled: YES\n"
        "- Result: PASS\n"
        "- Evidence Tag: [POC-PASS]\n"
    ).encode("utf-8")


def _proposal_bytes(item: QueueWorkItem) -> bytes:
    constituents = [item.work_item_id, *item.constituents]
    value = {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": item.work_item_id,
        "constituent_ids": constituents,
        "impact": {
            "class": "High",
            "harmed_asset": "protected asset",
            "harmed_capability": "asset integrity",
            "premise_id": f"PREM-{item.work_item_id}-IMPACT",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-{item.work_item_id}-IMPACT"],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "likelihood": {
            "class": "High",
            "actor": "unprivileged actor",
            "preconditions": ["reachable state"],
            "premise_id": f"PREM-{item.work_item_id}-LIKELIHOOD",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-{item.work_item_id}-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "modifiers": [],
        "proposed_severity": "High",
        "adjustment": None,
        "constituent_premise_outcomes": {
            value: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
            for value in constituents
        },
    }
    return json.dumps(value, sort_keys=True).encode("utf-8")


def _policy(pipeline: str, backend: Backend):
    if pipeline == "l1":
        return resolve_execution_policy(
            AuditMode.CORE,
            backend,
            Pipeline.L1,
            Ecosystem.RUST,
            Platform.WINDOWS,
        )
    return resolve_execution_policy(
        AuditMode.CORE,
        backend,
        Pipeline.SC,
        Ecosystem.EVM,
        Platform.WINDOWS,
    )


def _setup_plan(
    tmp_path: Path,
    pipeline: str,
    *,
    finding_ids: tuple[str, ...] = ("H-01",),
) -> tuple[Path, str, tuple[QueueWorkItem, ...], object]:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    rows = [_row(index, finding_id) for index, finding_id in enumerate(finding_ids, 1)]
    top = scratchpad / "verification_queue.md"
    P._write_queue_subset_manifest(top, rows)
    items = P._read_typed_queue_work_items(top)
    manifests = (
        L1_VERIFY_SHARD_MANIFESTS if pipeline == "l1" else SC_VERIFY_SHARD_MANIFESTS
    )
    phase_name = next(iter(manifests))
    partitions = {name: [] for name in manifests}
    partitions[phase_name] = rows
    for name, manifest in manifests.items():
        P._write_queue_subset_manifest(scratchpad / manifest, partitions[name])
    plan = P._write_or_validate_queue_work_plan(
        scratchpad,
        items,
        partitions,
        pipeline,
    )
    return scratchpad, phase_name, items, plan


def _sidecar_paths(scratchpad: Path, finding_id: str) -> tuple[Path, Path]:
    return (
        scratchpad / f"verify_{finding_id}.identity.json",
        scratchpad / f"verify_{finding_id}.receipt.json",
    )


def _write_manual_sidecars(
    scratchpad: Path,
    item: QueueWorkItem,
    plan,
    phase_name: str,
    *,
    backend: Backend = Backend.CLAUDE,
    identity: VerifierOutputIdentity | None = None,
) -> VerifierOutputReceipt:
    output = scratchpad / item.expected_output_file
    proposal_path = scratchpad / (
        f"verify_{item.work_item_id}.severity_proposal.json"
    )
    if not proposal_path.exists():
        proposal_path.write_bytes(_proposal_bytes(item))
    bound_identity = identity or VerifierOutputIdentity.for_assignment(
        item, plan, phase_name
    )
    receipt = VerifierOutputReceipt.bind(
        bound_identity,
        output.read_bytes(),
        severity_proposal=proposal_path.read_bytes(),
        launch_digest=LAUNCH_DIGEST,
        verifier_backend=backend.value,
    )
    identity_path, receipt_path = _sidecar_paths(scratchpad, item.work_item_id)
    identity_path.write_text(
        json.dumps(
            bound_identity.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    receipt_path.write_text(receipt.to_json(), encoding="utf-8")
    return receipt


def _completion(
    scratchpad: Path,
    phase_name: str,
    policy,
) -> list[str]:
    parameters = inspect.signature(V._validate_verify_completion).parameters
    assert "launch_digest" in parameters, (
        "live receipt validation must bind the expected phase launch digest"
    )
    assert parameters["launch_digest"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["launch_digest"].default is None, (
        "isolated no-policy callers retain compatibility without launch metadata"
    )
    return V._validate_verify_completion(
        scratchpad,
        phase_name,
        min_bytes=1,
        mode="core",
        execution_policy=policy,
        launch_digest=LAUNCH_DIGEST,
    )


def _persist(
    scratchpad: Path,
    phase_name: str,
    policy,
):
    plan = P.read_queue_work_plan(scratchpad)
    items = {
        item.work_item_id: item
        for item in P._read_typed_queue_work_items(
            scratchpad / "verification_queue.md"
        )
    }
    for work_item_id in plan.shard(phase_name).ordered_work_item_ids:
        proposal_path = scratchpad / (
            f"verify_{work_item_id}.severity_proposal.json"
        )
        if not proposal_path.exists():
            proposal_path.write_bytes(_proposal_bytes(items[work_item_id]))
    writer = getattr(V, "_persist_verifier_output_receipts", None)
    assert callable(writer), (
        "plamen_validators must expose one atomic/idempotent verifier-output "
        "identity+receipt persistence seam"
    )
    return writer(
        scratchpad,
        phase_name,
        execution_policy=policy,
        launch_digest=LAUNCH_DIGEST,
    )


def _ignore_poc_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(V, "_validate_poc_contract_for_rows", lambda *a, **k: [])


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
@pytest.mark.parametrize("backend", [Backend.CLAUDE, Backend.CODEX])
def test_live_shards_persist_and_read_backend_neutral_identity_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    backend: Backend,
) -> None:
    scratchpad, phase_name, items, plan = _setup_plan(tmp_path, pipeline)
    item = items[0]
    output = scratchpad / item.expected_output_file
    output.write_bytes(_verify_bytes(item.work_item_id))
    policy = _policy(pipeline, backend)
    _ignore_poc_gate(monkeypatch)

    paths = tuple(_persist(scratchpad, phase_name, policy))
    identity_path, receipt_path = _sidecar_paths(scratchpad, item.work_item_id)
    assert set(paths) == {identity_path, receipt_path}
    identity = VerifierOutputIdentity.from_dict(
        json.loads(identity_path.read_text(encoding="utf-8"))
    )
    receipt = VerifierOutputReceipt.from_json(receipt_path.read_text(encoding="utf-8"))
    assert identity == VerifierOutputIdentity.for_assignment(item, plan, phase_name)
    assert receipt.identity == identity
    assert receipt.verifier_backend == backend.value
    assert receipt.launch_digest == LAUNCH_DIGEST
    assert _completion(scratchpad, phase_name, policy) == []


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_live_plan_uses_only_current_owned_filename_and_never_repartitions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
) -> None:
    scratchpad, phase_name, items, plan = _setup_plan(tmp_path, pipeline)
    item = items[0]
    legacy = scratchpad / f"verify_F-{item.work_item_id}.md"
    legacy.write_bytes(_verify_bytes(item.work_item_id))
    # A receipt for legacy bytes cannot turn the alias into plan-owned output.
    canonical = scratchpad / item.expected_output_file
    canonical.write_bytes(legacy.read_bytes())
    _write_manual_sidecars(scratchpad, item, plan, phase_name)
    canonical.unlink()

    def forbidden_repartition(*args, **kwargs):
        raise AssertionError("live verifier completion must consume persisted plan membership")

    monkeypatch.setattr(V, "compute_verify_shards", forbidden_repartition)
    monkeypatch.setattr(V, "compute_sc_verify_shards", forbidden_repartition)
    _ignore_poc_gate(monkeypatch)
    issues = _completion(scratchpad, phase_name, _policy(pipeline, Backend.CLAUDE))
    assert issues
    joined = " ".join(issues).lower()
    assert "verify_h-01.md" in joined or "canonical" in joined or "owned" in joined


def test_isolated_no_policy_caller_keeps_legacy_filename_compatibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase_name, items, _plan = _setup_plan(tmp_path, "sc")
    item = items[0]
    (scratchpad / f"verify_F-{item.work_item_id}.md").write_bytes(
        _verify_bytes(item.work_item_id)
    )
    _ignore_poc_gate(monkeypatch)
    assert V._validate_verify_completion(
        scratchpad,
        phase_name,
        min_bytes=1,
        mode="core",
    ) == []


def test_live_completion_requires_exactly_one_receipt_per_assigned_item(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase_name, items, plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01", "H-02")
    )
    for item in items:
        (scratchpad / item.expected_output_file).write_bytes(
            _verify_bytes(item.work_item_id)
        )
    _write_manual_sidecars(scratchpad, items[0], plan, phase_name)
    duplicate = scratchpad / "verify_H-01.copy.receipt.json"
    duplicate.write_bytes(_sidecar_paths(scratchpad, "H-01")[1].read_bytes())
    _ignore_poc_gate(monkeypatch)

    issues = _completion(scratchpad, phase_name, _policy("sc", Backend.CLAUDE))
    joined = " ".join(issues).lower()
    assert "h-02" in joined and "receipt" in joined
    assert "duplicate" in joined and "h-01" in joined


def test_live_receipt_cardinality_is_exact_id_not_prefix_scoped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase_name, items, plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-1", "H-10")
    )
    for item in items:
        (scratchpad / item.expected_output_file).write_bytes(
            _verify_bytes(item.work_item_id)
        )
        _write_manual_sidecars(scratchpad, item, plan, phase_name)
    _ignore_poc_gate(monkeypatch)

    assert _completion(
        scratchpad, phase_name, _policy("sc", Backend.CLAUDE)
    ) == []


def test_unowned_verify_markdown_is_visible_but_never_authoritative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase_name, items, plan = _setup_plan(tmp_path, "sc")
    item = items[0]
    (scratchpad / item.expected_output_file).write_bytes(_verify_bytes(item.work_item_id))
    _write_manual_sidecars(scratchpad, item, plan, phase_name)
    (scratchpad / "verify_INV-999.md").write_bytes(_verify_bytes("INV-999"))
    _ignore_poc_gate(monkeypatch)

    issues = _completion(scratchpad, phase_name, _policy("sc", Backend.CLAUDE))
    assert issues, "unowned verifier output must be surfaced as non-authoritative debt"
    joined = " ".join(issues).lower()
    assert "unowned" in joined and "verify_inv-999.md" in joined


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ("plan", "work_plan"),
        ("shard", "shard"),
        ("work_item", "work_item"),
        ("queue_record", "queue_record"),
        ("output_identity", "output"),
    ],
)
def test_live_reader_rejects_wrong_identity_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected: str,
) -> None:
    scratchpad, phase_name, items, plan = _setup_plan(tmp_path, "sc")
    item = items[0]
    output = scratchpad / item.expected_output_file
    output.write_bytes(_verify_bytes(item.work_item_id))
    identity = VerifierOutputIdentity.for_assignment(item, plan, phase_name)
    if mutation == "plan":
        wrong = replace(identity, work_plan_digest="0" * 64)
    elif mutation == "shard":
        wrong = replace(identity, shard_id="wrong-shard")
    elif mutation == "work_item":
        wrong = replace(
            identity,
            work_item_id="H-99",
            expected_output_file="verify_H-99.md",
            expected_output_identity="scratchpad:verify_H-99.md",
        )
    elif mutation == "queue_record":
        wrong = replace(identity, queue_record_digest="0" * 64)
    else:
        wrong = identity
    _write_manual_sidecars(
        scratchpad,
        item,
        plan,
        phase_name,
        identity=wrong,
    )
    if mutation == "output_identity":
        identity_path, _receipt_path = _sidecar_paths(scratchpad, item.work_item_id)
        payload = json.loads(identity_path.read_text(encoding="utf-8"))
        payload["expected_output_identity"] = "scratchpad:verify_H-99.md"
        identity_path.write_text(json.dumps(payload), encoding="utf-8")
    _ignore_poc_gate(monkeypatch)

    issues = _completion(scratchpad, phase_name, _policy("sc", Backend.CLAUDE))
    joined = " ".join(issues).lower()
    assert issues and expected in joined


def test_live_reader_rejects_tampered_receipt_sidecar_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase_name, items, plan = _setup_plan(tmp_path, "sc")
    item = items[0]
    (scratchpad / item.expected_output_file).write_bytes(_verify_bytes(item.work_item_id))
    _write_manual_sidecars(scratchpad, item, plan, phase_name)
    _identity_path, receipt_path = _sidecar_paths(scratchpad, item.work_item_id)
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    payload["output_size_bytes"] += 1
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")
    _ignore_poc_gate(monkeypatch)

    issues = _completion(scratchpad, phase_name, _policy("sc", Backend.CLAUDE))
    joined = " ".join(issues).lower()
    assert issues and "receipt" in joined and "digest" in joined


def test_receipt_tamper_is_rejected_and_resume_never_reblesses_changed_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase_name, items, _plan = _setup_plan(tmp_path, "sc")
    item = items[0]
    output = scratchpad / item.expected_output_file
    output.write_bytes(_verify_bytes(item.work_item_id))
    policy = _policy("sc", Backend.CODEX)
    _ignore_poc_gate(monkeypatch)

    first_paths = tuple(_persist(scratchpad, phase_name, policy))
    first_bytes = {path: path.read_bytes() for path in first_paths}
    first_mtimes = {path: path.stat().st_mtime_ns for path in first_paths}
    assert tuple(_persist(scratchpad, phase_name, policy)) == first_paths
    assert {path: path.stat().st_mtime_ns for path in first_paths} == first_mtimes

    output.write_bytes(output.read_bytes() + b"\nTAMPERED\n")
    with pytest.raises((ValueError, RuntimeError), match="sha|digest|output|receipt"):
        _persist(scratchpad, phase_name, policy)
    assert {path: path.read_bytes() for path in first_paths} == first_bytes
    issues = _completion(scratchpad, phase_name, policy)
    assert issues and any("sha" in issue.lower() or "digest" in issue.lower() for issue in issues)


def test_windows_case_variant_cannot_satisfy_canonical_output_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase_name, items, _plan = _setup_plan(tmp_path, "sc")
    item = items[0]
    lower_name = item.expected_output_file.lower()
    (scratchpad / lower_name).write_bytes(_verify_bytes(item.work_item_id))
    _ignore_poc_gate(monkeypatch)
    issues = _completion(scratchpad, phase_name, _policy("sc", Backend.CLAUDE))
    assert issues
    joined = " ".join(issues).lower()
    assert "case" in joined or "collision" in joined or "canonical" in joined


def test_work_plan_rejects_casefolded_output_collision_before_launch() -> None:
    first = QueueWorkItem.from_legacy_row(_row(1, "H-01"))
    second = QueueWorkItem.from_legacy_row(_row(2, "h-01"))
    with pytest.raises(ValueError, match="collision|duplicate"):
        build_queue_work_plan(
            (first, second),
            {"verify-a": (first,), "verify-b": (second,)},
            planner_version="bounded-count-v1",
        )


def _calls_in(function, called_name: str) -> list[ast.Call]:
    tree = ast.parse(inspect.getsource(function))
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == called_name:
            calls.append(node)
        elif isinstance(node.func, ast.Attribute) and node.func.attr == called_name:
            calls.append(node)
    return calls


def test_driver_live_post_run_gate_persists_receipts_before_validation() -> None:
    calls = _calls_in(D._run_phase_validators, "_persist_verifier_output_receipts")
    assert calls, "driver must persist receipts after a live verifier shard returns"
    for call in calls:
        keyword_names = {keyword.arg for keyword in call.keywords}
        assert {"execution_policy", "launch_digest"} <= keyword_names
    source = inspect.getsource(D._run_phase_validators)
    assert source.index("_persist_verifier_output_receipts(") < source.index(
        "_validate_verify_completion("
    ), "receipt commit must precede the live completion gate"


def test_every_live_completion_call_binds_launch_digest() -> None:
    for function in (D.main, D._run_phase_validators, D._phase_content_gate_issues):
        calls = _calls_in(function, "_validate_verify_completion")
        assert calls
        assert all(
            "launch_digest" in {keyword.arg for keyword in call.keywords}
            for call in calls
        ), f"{function.__name__} has an unbound live verifier-completion call"
