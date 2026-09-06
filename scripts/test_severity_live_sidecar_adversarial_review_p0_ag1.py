"""Independent adversarial contracts for the AG-1 live severity sidecar.

These fixtures exercise only the live producer/commit boundary.  The pure
severity decision substrate has its own tests.  A verifier assignment is one
transaction: its canonical Markdown and typed severity proposal must both be
owned by the persisted work plan, validated, and digest-bound before either is
authoritative.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(REPO_ROOT))

import plamen_parsers as P  # noqa: E402
import plamen_validators as V  # noqa: E402
from plamen_prompt import build_phase_prompt  # noqa: E402
from plamen_types import (  # noqa: E402
    L1_PHASES,
    L1_VERIFY_PHASE_NAMES,
    L1_VERIFY_SHARD_MANIFESTS,
    SC_PHASES,
    SC_VERIFY_PHASE_NAMES,
    SC_VERIFY_SHARD_MANIFESTS,
    plamen_home,
)
from queue_work_items import VerifierOutputReceipt  # noqa: E402
from severity_decision_ledger import compile_severity_prompt_contract  # noqa: E402
from verification_policy import (  # noqa: E402
    AuditMode,
    Backend,
    Ecosystem,
    Pipeline,
    Platform,
    resolve_execution_policy,
)


LAUNCH_DIGEST = "a" * 64


def _receipt_digest(payload: dict[str, object]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "receipt_digest"}
    return hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _row(number: int, finding_id: str, *, constituents: str = "") -> dict[str, str]:
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
        "constituents": constituents,
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


def _proposal(
    finding_id: str,
    constituents: tuple[str, ...],
    *,
    proposed_severity: str = "High",
) -> dict[str, object]:
    return {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": finding_id,
        "constituent_ids": list(constituents),
        "impact": {
            "class": "High",
            "harmed_asset": "protected asset",
            "harmed_capability": "asset integrity",
            "premise_id": f"PREM-{finding_id}-IMPACT",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-{finding_id}-IMPACT"],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "likelihood": {
            "class": "High",
            "actor": "unprivileged actor",
            "preconditions": ["reachable state"],
            "premise_id": f"PREM-{finding_id}-LIKELIHOOD",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-{finding_id}-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "modifiers": [],
        "proposed_severity": proposed_severity,
        "adjustment": None,
        "constituent_premise_outcomes": {
            constituent: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
            for constituent in constituents
        },
    }


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
    pipeline: str = "sc",
    *,
    finding_ids: tuple[str, ...] = ("H-01",),
    constituents_by_id: dict[str, str] | None = None,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    constituent_map = constituents_by_id or {}
    rows = [
        _row(
            index,
            finding_id,
            constituents=constituent_map.get(finding_id, ""),
        )
        for index, finding_id in enumerate(finding_ids, 1)
    ]
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
        scratchpad, items, partitions, pipeline
    )
    return scratchpad, phase_name, items, plan


def _write_owned_pair(scratchpad: Path, item) -> Path:
    (scratchpad / item.expected_output_file).write_bytes(
        _verify_bytes(item.work_item_id)
    )
    proposal_path = (
        scratchpad / f"verify_{item.work_item_id}.severity_proposal.json"
    )
    proposal_path.write_text(
        json.dumps(
            # QueueWorkItem.constituents deliberately excludes the current
            # work_item_id.  The severity contract's non-empty constituent
            # universe includes the assessed candidate exactly once, followed
            # by any compound children.
            _proposal(
                item.work_item_id,
                (item.work_item_id, *tuple(item.constituents)),
            ),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return proposal_path


def _prevalidate(scratchpad: Path, phase_name: str, pipeline: str = "sc") -> list[str]:
    return V._validate_verifier_outputs_before_receipt(
        scratchpad,
        phase_name,
        min_bytes=1,
        mode="core",
        execution_policy=_policy(pipeline, Backend.CLAUDE),
        require_severity_proposals=True,
    )


def _ignore_poc_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(V, "_validate_poc_contract_for_rows", lambda *a, **k: [])


def test_every_live_verify_shard_gets_the_same_exact_contract_for_both_backends(
    tmp_path: Path,
) -> None:
    """Representative-only prompt tests can hide a pruned shard or backend."""

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    contract = compile_severity_prompt_contract()["markdown"]
    cases = (
        ("sc", "evm", SC_PHASES, SC_VERIFY_PHASE_NAMES, "plamen.md"),
        ("l1", "rust", L1_PHASES, L1_VERIFY_PHASE_NAMES, "plamen-l1.md"),
    )
    for pipeline, language, phases, verify_names, command_name in cases:
        phase_by_name = {phase.name: phase for phase in phases}
        assert set(verify_names) <= set(phase_by_name)
        for backend in ("claude", "codex"):
            for phase_name in verify_names:
                prompt = build_phase_prompt(
                    plamen_home() / "commands" / command_name,
                    phase_by_name[phase_name],
                    {
                        "project_root": str(tmp_path),
                        "scratchpad": str(scratchpad),
                        "language": language,
                        "mode": "thorough",
                        "pipeline": pipeline,
                        "backend": backend,
                        "proven_only": False,
                    },
                )
                assert prompt.count("SEVERITY PROPOSAL SIDECAR (MANDATORY)") == 1, (
                    pipeline,
                    backend,
                    phase_name,
                )
                assert prompt.count(contract) == 1, (pipeline, backend, phase_name)
                assert "verify_<finding_id>.severity_proposal.json" in prompt
                assert "driver-owned authority fields" in prompt


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
@pytest.mark.parametrize("backend", (Backend.CLAUDE, Backend.CODEX))
def test_exact_owned_pair_prevalidates_with_sc_l1_and_backend_parity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    backend: Backend,
) -> None:
    scratchpad, phase_name, items, _plan = _setup_plan(tmp_path, pipeline)
    _write_owned_pair(scratchpad, items[0])
    _ignore_poc_gate(monkeypatch)
    issues = V._validate_verifier_outputs_before_receipt(
        scratchpad,
        phase_name,
        min_bytes=1,
        mode="core",
        execution_policy=_policy(pipeline, backend),
        require_severity_proposals=True,
    )
    assert issues == []


def test_compound_constituent_binding_is_candidate_then_exact_queue_children(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase_name, items, _plan = _setup_plan(
        tmp_path,
        constituents_by_id={"H-01": "INV-1 INV-2"},
    )
    item = items[0]
    assert item.constituents == ("INV-1", "INV-2")
    proposal_path = _write_owned_pair(scratchpad, item)
    _ignore_poc_gate(monkeypatch)
    assert _prevalidate(scratchpad, phase_name) == []

    payload = json.loads(proposal_path.read_text(encoding="utf-8"))
    payload["constituent_ids"] = ["H-01", "INV-2", "INV-1"]
    proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    issues = _prevalidate(scratchpad, phase_name)
    assert issues
    assert "constituent identity mismatch" in " ".join(issues).casefold()


@pytest.mark.parametrize(
    ("mutation", "expected_fragment"),
    (
        ("missing", "missing"),
        ("extra", "unowned"),
        ("malformed", "schema invalid"),
        ("duplicate-key", "schema invalid"),
        ("candidate-mismatch", "candidate identity mismatch"),
        ("constituent-mismatch", "constituent identity mismatch"),
        ("empty-constituents", "schema invalid"),
        ("invalid-impact-class", "schema invalid"),
        ("invalid-proposed-severity", "schema invalid"),
        ("empty-evidence", "schema invalid"),
        ("numeric-impact-premise", "schema invalid"),
        ("numeric-impact-asset", "schema invalid"),
        ("numeric-evidence-id", "schema invalid"),
        ("numeric-precondition", "schema invalid"),
        ("numeric-likelihood-premise", "schema invalid"),
        ("numeric-likelihood-actor", "schema invalid"),
        ("numeric-likelihood-evidence", "schema invalid"),
        ("numeric-modifier-evidence", "schema invalid"),
        ("numeric-adjustment-premise", "schema invalid"),
        ("numeric-adjustment-evidence", "schema invalid"),
        ("case-mismatch", "case/collision mismatch"),
    ),
)
def test_precommit_rejects_missing_extra_malformed_duplicate_identity_and_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_fragment: str,
) -> None:
    scratchpad, phase_name, items, _plan = _setup_plan(tmp_path)
    item = items[0]
    proposal_path = _write_owned_pair(scratchpad, item)
    if mutation == "missing":
        proposal_path.unlink()
    elif mutation == "extra":
        (scratchpad / "verify_UNOWNED.severity_proposal.json").write_text(
            proposal_path.read_text(encoding="utf-8"), encoding="utf-8"
        )
    elif mutation == "malformed":
        proposal_path.write_text("{not-json", encoding="utf-8")
    elif mutation == "duplicate-key":
        valid = proposal_path.read_text(encoding="utf-8")
        proposal_path.write_text(
            '{"schema_version":"plamen.severity_proposal.v1",'
            '"schema_version":"plamen.severity_proposal.v1",'
            + valid.lstrip()[1:],
            encoding="utf-8",
        )
    elif mutation == "candidate-mismatch":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["candidate_id"] = "H-02"
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "constituent-mismatch":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["constituent_ids"] = ["H-02"]
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "empty-constituents":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["constituent_ids"] = []
        payload["constituent_premise_outcomes"] = {}
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "invalid-impact-class":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["impact"]["class"] = "Catastrophic"
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "invalid-proposed-severity":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["proposed_severity"] = "BANANA"
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "empty-evidence":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["impact"]["evidence_ids"] = []
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "numeric-impact-premise":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["impact"]["premise_id"] = 7
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "numeric-impact-asset":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["impact"]["harmed_asset"] = 7
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "numeric-evidence-id":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["impact"]["evidence_ids"] = [7]
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "numeric-precondition":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["likelihood"]["preconditions"] = [7]
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "numeric-likelihood-premise":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["likelihood"]["premise_id"] = 7
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "numeric-likelihood-actor":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["likelihood"]["actor"] = 7
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "numeric-likelihood-evidence":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["likelihood"]["evidence_ids"] = [7]
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "numeric-modifier-evidence":
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["modifiers"] = [{
            "kind": "VIEW_FUNCTION_ONLY",
            "applies": False,
            "applicability_predicate": "not applicable",
            "evidence_ids": [7],
            "proof_scope": "IN_SCOPE_EXECUTION",
        }]
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation in {"numeric-adjustment-premise", "numeric-adjustment-evidence"}:
        payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        payload["adjustment"] = {
            "direction": "UP",
            "premise_ids": [
                7 if mutation == "numeric-adjustment-premise" else "PREM-H-01-IMPACT"
            ],
            "evidence_ids": [
                7 if mutation == "numeric-adjustment-evidence" else "EVID-H-01-IMPACT"
            ],
            "proof_scope": "IN_SCOPE_EXECUTION",
            "rationale": "A bounded adjustment proposal.",
        }
        proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "case-mismatch":
        wrong_case = scratchpad / "VERIFY_h-01.SEVERITY_PROPOSAL.JSON"
        proposal_path.rename(wrong_case)
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(mutation)
    _ignore_poc_gate(monkeypatch)
    issues = _prevalidate(scratchpad, phase_name)
    assert issues
    assert expected_fragment in " ".join(issues).casefold()


def test_receipt_transaction_requires_and_digest_binds_the_severity_proposal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No validated-but-unbound proposal may cross the commit boundary."""

    scratchpad, phase_name, items, _plan = _setup_plan(tmp_path)
    proposal_path = _write_owned_pair(scratchpad, items[0])
    _ignore_poc_gate(monkeypatch)
    assert _prevalidate(scratchpad, phase_name) == []
    V._persist_verifier_output_receipts(
        scratchpad,
        phase_name,
        execution_policy=_policy("sc", Backend.CLAUDE),
        launch_digest=LAUNCH_DIGEST,
    )
    receipt = VerifierOutputReceipt.from_json(
        (scratchpad / "verify_H-01.receipt.json").read_text(encoding="utf-8")
    )
    payload = receipt.to_dict()
    assert "severity_proposal_sha256" in payload
    assert "severity_proposal_size_bytes" in payload

    # A schema-valid replacement must invalidate authority just like a changed
    # Markdown file; otherwise the assessor output is mutable after validation.
    changed = _proposal("H-01", ("H-01",), proposed_severity="Low")
    proposal_path.write_text(json.dumps(changed), encoding="utf-8")
    issues = V._validate_verifier_output_receipts(
        scratchpad,
        phase_name,
        P.read_queue_work_plan(scratchpad),
        {item.work_item_id: item for item in items},
        execution_policy=_policy("sc", Backend.CLAUDE),
        launch_digest=LAUNCH_DIGEST,
    )
    assert issues
    assert "severity" in " ".join(issues).casefold()
    assert "digest" in " ".join(issues).casefold()


def test_receipt_writer_cannot_commit_markdown_without_the_owned_proposal(
    tmp_path: Path,
) -> None:
    """The persistence seam itself closes the prevalidate/persist TOCTOU gap."""

    scratchpad, phase_name, items, _plan = _setup_plan(tmp_path)
    (scratchpad / items[0].expected_output_file).write_bytes(
        _verify_bytes(items[0].work_item_id)
    )
    with pytest.raises(ValueError, match="severity proposal"):
        V._persist_verifier_output_receipts(
            scratchpad,
            phase_name,
            execution_policy=_policy("sc", Backend.CLAUDE),
            launch_digest=LAUNCH_DIGEST,
        )
    assert not (scratchpad / "verify_H-01.receipt.json").exists()


@pytest.mark.parametrize("missing_name", ("identity", "receipt"))
def test_resume_repairs_a_valid_partial_receipt_transaction_without_a_halt_loop(
    tmp_path: Path,
    missing_name: str,
) -> None:
    scratchpad, phase_name, items, _plan = _setup_plan(tmp_path)
    _write_owned_pair(scratchpad, items[0])
    policy = _policy("sc", Backend.CLAUDE)
    V._persist_verifier_output_receipts(
        scratchpad,
        phase_name,
        execution_policy=policy,
        launch_digest=LAUNCH_DIGEST,
    )
    identity_path = scratchpad / "verify_H-01.identity.json"
    receipt_path = scratchpad / "verify_H-01.receipt.json"
    (identity_path if missing_name == "identity" else receipt_path).unlink()

    # A process crash between two same-directory renames must not make every
    # later retry hit the same permanent partial-transaction exception.
    V._persist_verifier_output_receipts(
        scratchpad,
        phase_name,
        execution_policy=policy,
        launch_digest=LAUNCH_DIGEST,
    )
    assert identity_path.is_file()
    assert receipt_path.is_file()


def test_receipt_keeps_markdown_immutable_after_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase_name, items, _plan = _setup_plan(tmp_path)
    _write_owned_pair(scratchpad, items[0])
    _ignore_poc_gate(monkeypatch)
    assert _prevalidate(scratchpad, phase_name) == []
    V._persist_verifier_output_receipts(
        scratchpad,
        phase_name,
        execution_policy=_policy("sc", Backend.CLAUDE),
        launch_digest=LAUNCH_DIGEST,
    )
    markdown = scratchpad / items[0].expected_output_file
    markdown.write_bytes(markdown.read_bytes() + b"\npost-commit mutation\n")
    issues = V._validate_verifier_output_receipts(
        scratchpad,
        phase_name,
        P.read_queue_work_plan(scratchpad),
        {item.work_item_id: item for item in items},
        execution_policy=_policy("sc", Backend.CLAUDE),
        launch_digest=LAUNCH_DIGEST,
    )
    assert issues
    assert "output_sha256 mismatch" in " ".join(issues)


@pytest.mark.parametrize(
    "corruption",
    (
        "identity-only-bad-identity",
        "identity-only-invalid-proposal",
        "receipt-only-changed-markdown",
        "receipt-only-changed-proposal",
        "receipt-only-corrupt-receipt",
    ),
)
def test_invalid_partial_transactions_fail_closed_and_are_not_reconstructed(
    tmp_path: Path,
    corruption: str,
) -> None:
    scratchpad, phase_name, items, _plan = _setup_plan(tmp_path)
    proposal_path = _write_owned_pair(scratchpad, items[0])
    policy = _policy("sc", Backend.CLAUDE)
    V._persist_verifier_output_receipts(
        scratchpad,
        phase_name,
        execution_policy=policy,
        launch_digest=LAUNCH_DIGEST,
    )
    identity_path = scratchpad / "verify_H-01.identity.json"
    receipt_path = scratchpad / "verify_H-01.receipt.json"

    if corruption.startswith("identity-only"):
        receipt_path.unlink()
        missing_path = receipt_path
        if corruption == "identity-only-bad-identity":
            payload = json.loads(identity_path.read_text(encoding="utf-8"))
            payload["queue_record_digest"] = "f" * 64
            identity_path.write_text(json.dumps(payload), encoding="utf-8")
        else:
            payload = json.loads(proposal_path.read_text(encoding="utf-8"))
            payload["proposed_severity"] = "BANANA"
            proposal_path.write_text(json.dumps(payload), encoding="utf-8")
    else:
        identity_path.unlink()
        missing_path = identity_path
        if corruption == "receipt-only-changed-markdown":
            markdown = scratchpad / items[0].expected_output_file
            markdown.write_bytes(markdown.read_bytes() + b"\nchanged\n")
        elif corruption == "receipt-only-changed-proposal":
            proposal_path.write_text(
                json.dumps(_proposal("H-01", ("H-01",), proposed_severity="Low")),
                encoding="utf-8",
            )
        else:
            payload = json.loads(receipt_path.read_text(encoding="utf-8"))
            payload["receipt_digest"] = "0" * 64
            receipt_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises((ValueError, TypeError)):
        V._persist_verifier_output_receipts(
            scratchpad,
            phase_name,
            execution_policy=policy,
            launch_digest=LAUNCH_DIGEST,
        )
    assert not missing_path.exists(), (
        "an invalid surviving half must not authorize reconstruction"
    )


def test_persistence_rejects_exact_plus_case_only_filename_collision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Case-sensitive hosts may contain both names; neither is authoritative."""

    expected = "verify_H-01.severity_proposal.json"

    class _Entry:
        def __init__(self, name: str):
            self.name = name

        def is_file(self) -> bool:
            return True

    monkeypatch.setattr(
        type(tmp_path),
        "iterdir",
        lambda _self: iter(
            (_Entry(expected), _Entry("VERIFY_h-01.SEVERITY_PROPOSAL.JSON"))
        ),
    )
    issue = V._canonical_output_case_issue(tmp_path, expected)
    assert issue
    assert "case" in issue.casefold()
    assert "collision" in issue.casefold()


@pytest.mark.parametrize(
    ("field", "expected_fragment"),
    (
        ("severity_proposal_file", "current-ID projection"),
        ("severity_proposal_size_bytes", "severity_proposal_size_bytes"),
        ("output_size_bytes", "output_size_bytes"),
    ),
)
def test_v2_receipt_independently_binds_canonical_name_and_both_sizes(
    tmp_path: Path,
    field: str,
    expected_fragment: str,
) -> None:
    scratchpad, phase_name, items, plan = _setup_plan(tmp_path)
    proposal_path = _write_owned_pair(scratchpad, items[0])
    policy = _policy("sc", Backend.CLAUDE)
    V._persist_verifier_output_receipts(
        scratchpad,
        phase_name,
        execution_policy=policy,
        launch_digest=LAUNCH_DIGEST,
    )
    payload = json.loads(
        (scratchpad / "verify_H-01.receipt.json").read_text(encoding="utf-8")
    )
    if field == "severity_proposal_file":
        payload[field] = "verify_H-02.severity_proposal.json"
    else:
        payload[field] += 1
    payload["receipt_digest"] = _receipt_digest(payload)

    if field == "severity_proposal_file":
        with pytest.raises(ValueError, match=expected_fragment):
            VerifierOutputReceipt.from_json(json.dumps(payload))
        return

    receipt = VerifierOutputReceipt.from_json(json.dumps(payload))
    with pytest.raises(ValueError, match=expected_fragment):
        receipt.validate_against(
            items[0],
            plan,
            (scratchpad / items[0].expected_output_file).read_bytes(),
            severity_proposal=proposal_path.read_bytes(),
            launch_digest=LAUNCH_DIGEST,
            verifier_backend=policy.backend.value,
        )
