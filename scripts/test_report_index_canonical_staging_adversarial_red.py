"""Adversarial RED fixtures for report-index staged canonicalization.

These tests encode three authority properties that must hold before the
canonical report-index successor can cut over:

* neither a late live rehash nor a late staged mutation can become DRIVER
  authority;
* deterministic staging consumes the exact policy/severity/trust denominator
  and therefore has the same semantics as the authenticated live preimage;
* verifier prose requires an active producer and cannot become authoritative
  merely because a matching file exists.

The active-producer verifier case is a positive control.  Production code is
intentionally not patched in this module.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from artifact_ledger import (
    read_artifact_ledger,
)
# Import the mechanical substrate before the driver.  The production module
# graph has a known lazy-import cycle in the opposite standalone order; the
# canonical A0 lane initializes it this way before loading the driver.
import plamen_mechanical as _mechanical  # noqa: F401
import plamen_driver as D
import plamen_validators as V
import test_report_index_canonical_successor_a0_blocking as A0
from test_l1_report_index_haltless_parity import (
    _write_queue as _write_typed_fixture_queue,
)


def _assert_not_active_canonical(root: Path, contract) -> None:
    unit = read_artifact_ledger(root)["work_units"].get(contract.key)
    assert not (
        isinstance(unit, dict)
        and unit.get("semantic_status") == "ACTIVE"
        and unit.get("execution_state") == "OUTPUT_COMMITTED"
    ), "arbitrary or unauthenticated bytes became canonical DRIVER authority"


def _commit_owned_verifier(
    root: Path,
    config: dict,
    *,
    finding_id: str = "H-1",
    severity: str = "Medium",
) -> str:
    """Run one fixture verifier through the current dynamic PhaseIO seam."""

    import plamen_parsers as P
    from plamen_types import SC_VERIFY_SHARD_MANIFESTS
    from test_dynamic_verifier_runtime_integration_p0_ak import (
        _bind_sc_shared_context_producer,
        _write_operator_application,
    )
    from test_verifier_output_receipt_runtime_p0_aj import (
        _ignore_poc_gate,
        _proposal_bytes,
    )
    from verifier_work_roster import (
        build_verifier_runtime_policy,
        build_verifier_work_roster,
    )

    output_name = f"verify_{finding_id}.md"
    items = P._read_typed_queue_work_items(root / "verification_queue.md")
    item_by_id = {item.work_item_id: item for item in items}
    assert finding_id in item_by_id
    phase_name = next(iter(SC_VERIFY_SHARD_MANIFESTS))
    partitions = {name: [] for name in SC_VERIFY_SHARD_MANIFESTS}
    partitions[phase_name] = [
        {"finding id": item.work_item_id}
        for item in items
    ]
    plan = P._write_or_validate_queue_work_plan(
        root,
        items,
        partitions,
        "sc",
    )
    runtime_policy = build_verifier_runtime_policy(
        backend=str(config.get("cli_backend") or "codex"),
        model="fixture-model",
        timeout_seconds=120,
        source_root=str(Path(config["project_root"]).resolve()),
    )
    roster = build_verifier_work_roster(
        plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=runtime_policy,
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    (root / D._DYNAMIC_VERIFIER_ROSTER_NAME).write_text(
        roster.to_json(),
        encoding="utf-8",
    )
    _bind_sc_shared_context_producer(
        root,
        Path(config["project_root"]),
        items,
        run_id=str(config["_run_id"]),
    )

    def fake_execute(spec, **_kwargs):
        unit = roster.work_unit(spec.work_unit_id)
        for work_id in unit.ordered_work_item_ids:
            (root / f"verify_{work_id}.md").write_text(
                f"# Verification: {work_id}\n\n"
                f"**Verdict**: CONFIRMED\n"
                f"**Severity**: {severity}\n"
                "**Location**: src/Mod.sol:L100-L140\n\n"
                "## Finding\n\n"
                "The fixture preserves a substantive code-trace verifier "
                "result while exercising the typed completion transaction.\n\n"
                "### PoC Attempt\n"
                "- PoC Required: NO\n"
                "- PoC Class: structural\n"
                "- Attempted: NO\n"
                "- PoC Not Attempted Because: PURE_SPEC_OR_DOCS_ONLY\n"
                "- Test File: N/A\n"
                "- Command: N/A\n\n"
                "### Execution Result\n"
                "- Compiled: N/A\n"
                "- Result: NOT_EXECUTED\n"
                "- Evidence Tag: [CODE-TRACE]\n",
                encoding="utf-8",
            )
            (root / f"verify_{work_id}.severity_proposal.json").write_bytes(
                _proposal_bytes(item_by_id[work_id])
            )
            _write_operator_application(root, spec.work_unit_id, work_id)
        return 0

    phase = next(item for item in D.SC_PHASES if item.name == phase_name)
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            D, "_execute_dynamic_verifier_launch", fake_execute
        )
        _ignore_poc_gate(monkeypatch)
        for unit in roster.work_units:
            assert D._run_dynamic_verifier_unit(
                phase, root, config, roster, unit
            ) == []
    assert V._verifier_completion_authority_issues(
        root, finding_id
    ) == []

    binding = read_artifact_ledger(root)["artifact_bindings"][
        f"scratchpad:{output_name}"
    ]
    assert binding["status"] == "ACTIVE"
    return output_name


def _policy_report_index_bytes() -> bytes:
    raw = A0._report_index_bytes(medium_summary=0, medium_master=0)
    text = raw.decode("utf-8")
    text = text.replace("| Low | 0 |", "| Low | 1 |")
    text = text.replace("| Total | 0 |", "| Total | 1 |")
    separator = (
        "|-----------|-------|----------|----------|--------------|"
        "------------|---------------------|\n"
    )
    assert separator in text
    text = text.replace(
        separator,
        separator
        + "| L-01 | code trace | Low | src/F.sol:L1 | "
        "VERIFIED [CODE-TRACE] | - | H-1 |\n",
        1,
    )
    return text.encode("utf-8")


def _prepare_typed_verifier_attempt(
    config: dict,
    *,
    report_index_bytes: bytes | None = None,
    report_coverage_bytes: bytes | None = None,
) -> None:
    """Arm report-model inputs over the typed queue before writing outputs."""

    root = Path(config["scratchpad"])
    for name, payload in {
        "report_index_coverage_seed.md": "# Coverage Seed\n",
        "candidate_semantic_facets.md": "# Candidate Facets\n",
        "candidate_semantic_facets.json": "{}\n",
    }.items():
        (root / name).write_text(payload, encoding="utf-8")
    _write_typed_fixture_queue(root, [("H-1", "Medium")])
    assert D._bind_typed_model_phase_inputs(A0._phase(), root, config) == []
    (root / "report_index.md").write_bytes(
        report_index_bytes
        if report_index_bytes is not None
        else A0._report_index_bytes(medium_summary=1, medium_master=1)
    )
    (root / "report_coverage.md").write_bytes(
        report_coverage_bytes
        if report_coverage_bytes is not None
        else A0._coverage_bytes()
    )


def _prepare_policy_attempt(config: dict) -> None:
    _prepare_typed_verifier_attempt(
        config,
        report_index_bytes=_policy_report_index_bytes(),
        report_coverage_bytes=A0._coverage_bytes().replace(
            b"PROMOTED M-01", b"PROMOTED L-01"
        ),
    )


def test_late_live_rehash_cannot_self_bless_at_commit_boundary(
    tmp_path: Path,
) -> None:
    """A live mutation after receipt publication must not become DRIVER output."""

    config = A0._config(tmp_path)
    root = Path(config["scratchpad"])
    phase = A0._phase()
    A0._prepare_model_attempt(
        config,
        A0._report_index_bytes(medium_summary=1, medium_master=2),
    )
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    receipt_name = D._report_index_canonical_receipt_name(contract)
    mutated = False

    def mutate_and_rehash(point: str) -> None:
        nonlocal mutated
        if point != f"after_publish:{receipt_name}" or mutated:
            return
        mutated = True
        report_path = root / "report_index.md"
        report_path.write_bytes(
            report_path.read_bytes() + b"\nFORGED IN FINAL COMMIT WINDOW\n"
        )

        journal_path = root / D._REPORT_INDEX_CANONICAL_JOURNAL
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        journal["states"][-1]["artifacts"] = D._report_index_bundle_state(
            root,
            D._report_index_canonical_state_names(contract),
        )
        journal["journal_digest"] = (
            D._report_index_canonical_journal_digest(journal)
        )
        journal_path.write_bytes(D._canonical_json_bytes(journal))

        receipt_path = root / receipt_name
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["outputs"] = D._report_index_bundle_records(
            root,
            [
                item.path
                for item in contract.outputs
                if item.path != receipt_name
            ],
        )
        unsigned = dict(receipt)
        unsigned.pop("receipt_digest", None)
        receipt["receipt_digest"] = D._stable_payload_digest(unsigned)
        receipt_path.write_bytes(D._canonical_json_bytes(receipt))

    issues = D._run_report_index_canonicalization_transaction(
        phase,
        root,
        config,
        fault_inject=mutate_and_rehash,
    )

    assert mutated
    assert issues, "a rehashed live bundle crossed the final commit boundary"
    _assert_not_active_canonical(root, contract)


def test_late_staged_tail_cannot_become_canonical_target(
    tmp_path: Path,
) -> None:
    """Staging is a cache, not authority for bytes outside the derivation."""

    config = A0._config(tmp_path)
    root = Path(config["scratchpad"])
    phase = A0._phase()
    A0._prepare_model_attempt(
        config,
        A0._report_index_bytes(medium_summary=1, medium_master=2),
    )
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    mutated = False

    def mutate_staged_target(point: str) -> None:
        nonlocal mutated
        if point != "after_summary_projection" or mutated:
            return
        mutated = True
        staged = (
            D._report_index_canonical_recovery_dir(root, contract)
            / "staged_target"
            / "report_index.md"
        )
        staged.write_bytes(staged.read_bytes() + b"\nFORGED STAGED TARGET\n")

    issues = D._run_report_index_canonicalization_transaction(
        phase,
        root,
        config,
        fault_inject=mutate_staged_target,
    )

    assert mutated
    assert issues, "an arbitrary staged tail became the receipt-bound target"
    _assert_not_active_canonical(root, contract)


def test_canonical_contract_binds_policy_shadow_and_trust_denominator(
    tmp_path: Path,
) -> None:
    """Every file consulted by severity policy is an exact staged input."""

    config = A0._config(tmp_path)
    root = Path(config["scratchpad"])
    A0._prepare_model_attempt(
        config,
        A0._report_index_bytes(medium_summary=1, medium_master=2),
    )
    for name, payload in {
        "config.json": {
            "cli_backend": "codex",
            "proven_only": True,
            "severity_authority_cutover": False,
        },
        "severity_decision_ledger.shadow.json": {
            "schema_version": "fixture.shadow.v1",
            "decisions": [],
        },
        "trust_evidence_authority.json": {
            "schema_version": "fixture.trust.v1",
            "records": [],
        },
        "trust_evidence_provider_receipt.json": {
            "schema_version": "fixture.trust-receipt.v1",
            "negative_authority": "NONE",
        },
    }.items():
        (root / name).write_text(
            json.dumps(payload, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    required = {
        "scratchpad:config.json",
        "scratchpad:severity_decision_ledger.shadow.json",
        "scratchpad:trust_evidence_authority.json",
        "scratchpad:trust_evidence_provider_receipt.json",
    }

    assert required <= set(contract.immutable_inputs), (
        "canonical severity/policy transforms can read files absent from their "
        f"PhaseIO denominator: {sorted(required - set(contract.immutable_inputs))}"
    )


def test_proven_only_policy_semantics_are_identical_in_staging(
    tmp_path: Path,
) -> None:
    """Authenticated proven-only policy cannot disappear in the staged root."""

    config = A0._config(tmp_path)
    root = Path(config["scratchpad"])
    (root / "config.json").write_text(
        json.dumps(
            {
                "cli_backend": "codex",
                "proven_only": True,
                "severity_authority_cutover": False,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _prepare_policy_attempt(config)
    _commit_owned_verifier(root, config)

    live_expected = V._expected_report_index_severities(root)
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )

    def stop_before_publication(point: str) -> None:
        if point == "before_publish:report_index.md":
            raise RuntimeError("inspect authenticated staged target")

    with pytest.raises(RuntimeError, match="inspect authenticated staged target"):
        D._run_report_index_canonicalization_transaction(
            A0._phase(),
            root,
            config,
            fault_inject=stop_before_publication,
        )

    staged = (
        D._report_index_canonical_recovery_dir(root, contract)
        / "staged_target"
    )
    staged_expected = V._expected_report_index_severities(staged)
    staged_report = (staged / "report_index.md").read_text(encoding="utf-8")

    assert live_expected == {"H-1": "Low"}
    assert staged_expected == live_expected, (
        "staging silently changed the authenticated proven-only severity policy"
    )
    assert "| L-01 | code trace | Low |" in staged_report
    assert "| M-01 | code trace | Medium |" not in staged_report


def test_unowned_verifier_prose_cannot_become_driver_authority(
    tmp_path: Path,
) -> None:
    """Bare verifier presence is not an authenticated canonical input."""

    config = A0._config(tmp_path)
    root = Path(config["scratchpad"])
    phase = A0._phase()
    A0._prepare_model_attempt(
        config,
        A0._report_index_bytes(medium_summary=1, medium_master=2),
    )
    (root / "verify_H-1.md").write_text(
        "# Verify H-1\n\n"
        "**Verdict**: CONFIRMED\n\n"
        "**Severity**: High\n\n"
        "**Evidence Tag**: [CODE-TRACE]\n\n"
        + ("unowned-verifier-prose " * 12)
        + "\n",
        encoding="utf-8",
    )
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )

    issues = D._run_report_index_canonicalization_transaction(
        phase, root, config
    )

    assert issues, "unowned verifier prose was accepted as a semantic input"
    _assert_not_active_canonical(root, contract)


def test_active_verifier_producer_remains_valid_positive_control(
    tmp_path: Path,
) -> None:
    """Producer enforcement must not reject an authenticated verifier output."""

    config = A0._config(tmp_path)
    root = Path(config["scratchpad"])
    phase = A0._phase()
    _prepare_typed_verifier_attempt(config)
    _commit_owned_verifier(root, config)

    assert D._run_report_index_canonicalization_transaction(
        phase, root, config
    ) == []
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
