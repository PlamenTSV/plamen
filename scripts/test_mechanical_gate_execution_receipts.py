from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from mechanical_gate_execution_receipts import (
    GateArtifactEvidence,
    GateCountReceipt,
    GateDebtRow,
    GateExecutionReceipt,
    GateReceiptError,
    ImmutableGateExecutionLedger,
    PhaseIOCommitLink,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _counts(**overrides: int) -> GateCountReceipt:
    values = {
        "raw_subjects": 5,
        "unique_subjects": 4,
        "eligible_subjects": 4,
        "evaluated_subjects": 4,
        "fired_subjects": 1,
        "clear_subjects": 3,
        "unknown_subjects": 0,
        "overflow_subjects": 0,
        "emitted_candidates": 1,
    }
    values.update(overrides)
    return GateCountReceipt(**values)


def _link(*, state: str = "ACTIVE") -> PhaseIOCommitLink:
    return PhaseIOCommitLink(
        work_unit_key="sc/thorough/evm/claude/recon/fixture.guard",
        contract_digest=SHA_A,
        launch_digest=SHA_B,
        input_set_digest=SHA_C,
        output_identities=(
            "scratchpad:_mechanical_gates/receipts/fixture.json",
        ),
        commit_state=state,
        commit_receipt_digest=SHA_A,
        reason_codes=(),
    )


def _receipt(**overrides: object) -> GateExecutionReceipt:
    values: dict[str, object] = {
        "execution_id": "fixture-run.fixture-gate.fixture-activation",
        "run_id": "fixture-run",
        "gate_id": "fixture.integrity_guard",
        "activation_id": "fixture.integrity_guard.recon",
        "registry_digest": SHA_A,
        "inventory_digest": SHA_B,
        "source_tree_digest": SHA_C,
        "pipeline": "SC",
        "mode": "THOROUGH",
        "ecosystem": "EVM",
        "backend": "CLAUDE",
        "phase": "RECON",
        "state": "COMMITTED",
        "decision": "FIRED",
        "authority_effect": "AUTHORITATIVE",
        "counts": _counts(),
        "input_evidence_digests": (SHA_A,),
        "output_evidence_digests": (SHA_B,),
        "debt_codes": (),
        "phase_io": _link(),
    }
    values.update(overrides)
    if "debt_rows" not in overrides:
        values["debt_rows"] = tuple(
            GateDebtRow(
                code=code,
                condition="receipt_failure",
                action="RETAIN_UPSTREAM_AND_FLAG",
            )
            for code in values["debt_codes"]  # type: ignore[union-attr]
        )
    return GateExecutionReceipt(**values)


def test_exact_count_equations_reject_loss_and_overflow_misstatement() -> None:
    with pytest.raises(GateReceiptError):
        _counts(evaluated_subjects=3)
    with pytest.raises(GateReceiptError):
        _counts(
            evaluated_subjects=3,
            fired_subjects=1,
            clear_subjects=3,
            overflow_subjects=1,
        )
    overflow = _counts(
        evaluated_subjects=3,
        fired_subjects=1,
        clear_subjects=2,
        overflow_subjects=1,
    )
    with pytest.raises(GateReceiptError):
        _receipt(
            decision="FIRED",
            counts=overflow,
            debt_codes=(),
        )
    receipt = _receipt(
        decision="FIRED",
        counts=overflow,
        debt_codes=("BUDGET_OVERFLOW",),
    )
    assert receipt.counts.eligible_subjects == 4


@pytest.mark.parametrize(
    ("decision", "counts"),
    (
        (
            "CLEAR",
            _counts(
                fired_subjects=0,
                clear_subjects=3,
                unknown_subjects=1,
                emitted_candidates=0,
            ),
        ),
        (
            "CLEAR",
            _counts(
                evaluated_subjects=3,
                fired_subjects=0,
                clear_subjects=3,
                overflow_subjects=1,
                emitted_candidates=0,
            ),
        ),
    ),
)
def test_missing_or_truncated_evidence_can_never_clear(
    decision: str,
    counts: GateCountReceipt,
) -> None:
    with pytest.raises(GateReceiptError):
        _receipt(
            decision=decision,
            counts=counts,
            debt_codes=("EVIDENCE_INCOMPLETE",),
        )


def test_invalid_destructive_authority_is_recall_open() -> None:
    receipt = _receipt(
        state="DEBT",
        decision="UNKNOWN",
        authority_effect="RETAIN_UPSTREAM_AND_FLAG",
        counts=_counts(
            fired_subjects=0,
            clear_subjects=0,
            unknown_subjects=4,
            emitted_candidates=0,
        ),
        debt_codes=("CALLER_IDENTITY_MISMATCH",),
        output_evidence_digests=(),
        phase_io=None,
    )
    assert receipt.authority_effect == "RETAIN_UPSTREAM_AND_FLAG"
    with pytest.raises(GateReceiptError):
        replace(receipt, authority_effect="DESTRUCTIVE")


def test_phaseio_link_rejects_active_commit_with_reason_codes() -> None:
    with pytest.raises(GateReceiptError):
        replace(_link(), reason_codes=("INPUT_MUTATION",))
    quarantined = replace(
        _link(),
        commit_state="QUARANTINED",
        reason_codes=("INPUT_MUTATION",),
    )
    assert quarantined.commit_state == "QUARANTINED"


def test_immutable_ledger_is_content_bound_and_resume_idempotent(
    tmp_path: Path,
) -> None:
    ledger = ImmutableGateExecutionLedger(tmp_path / "gate-ledger")
    receipt = _receipt()
    first = ledger.publish(receipt)
    second = ledger.publish(receipt)
    assert first.state == "CREATED"
    assert second.state == "EXACT_REPLAY"
    assert first.receipt_digest == second.receipt_digest == receipt.digest
    assert ledger.read(receipt.execution_id) == receipt

    divergent = replace(
        receipt,
        debt_codes=("DIVERGENT_REPLAY",),
        debt_rows=(
            GateDebtRow(
                code="DIVERGENT_REPLAY",
                condition="partial_resume",
                action="QUARANTINE_AND_RETRY",
            ),
        ),
        state="DEBT",
        decision="UNKNOWN",
        authority_effect="RETAIN_UPSTREAM_AND_FLAG",
        phase_io=None,
    )
    with pytest.raises(GateReceiptError):
        ledger.publish(divergent)


def test_ledger_detects_post_publish_mutation(tmp_path: Path) -> None:
    ledger = ImmutableGateExecutionLedger(tmp_path / "gate-ledger")
    receipt = _receipt()
    publication = ledger.publish(receipt)
    publication.path.chmod(0o666)
    publication.path.write_text("{}", encoding="utf-8")
    with pytest.raises(GateReceiptError):
        ledger.read(receipt.execution_id)


def test_lower_bound_denominator_requires_unknown_remainder_debt() -> None:
    counts = GateCountReceipt(
        raw_subjects=3,
        unique_subjects=3,
        eligible_subjects=3,
        evaluated_subjects=3,
        fired_subjects=1,
        clear_subjects=1,
        unknown_subjects=1,
        overflow_subjects=0,
        emitted_candidates=1,
        denominator_kind="LOWER_BOUND",
    )
    with pytest.raises(GateReceiptError):
        _receipt(
            counts=counts,
            decision="FIRED",
            debt_codes=("EVIDENCE_INCOMPLETE",),
        )
    receipt = _receipt(
        counts=counts,
        state="DEBT",
        decision="FIRED",
        authority_effect="ADD_ONLY",
        phase_io=None,
        debt_codes=("EVIDENCE_INCOMPLETE", "UNKNOWN_REMAINDER"),
    )
    assert receipt.counts.denominator_kind == "LOWER_BOUND"


def test_artifact_evidence_binds_identity_schema_size_and_digest() -> None:
    artifact = GateArtifactEvidence(
        artifact_identity=(
            "scratchpad:_mechanical_gates/inputs/fixture.json"
        ),
        schema_version="fixture.input.v1",
        sha256=SHA_A,
        size=17,
    )
    receipt = _receipt(
        input_artifacts=(artifact,),
        input_evidence_digests=(SHA_A,),
    )
    assert receipt.input_artifacts[0].size == 17
    with pytest.raises(GateReceiptError):
        _receipt(
            input_artifacts=(artifact,),
            input_evidence_digests=(SHA_B,),
        )


def test_concurrent_exact_publish_is_one_create_and_lossless_replay(
    tmp_path: Path,
) -> None:
    ledger = ImmutableGateExecutionLedger(tmp_path / "gate-ledger")
    receipt = _receipt()
    with ThreadPoolExecutor(max_workers=8) as pool:
        publications = list(
            pool.map(lambda _index: ledger.publish(receipt), range(32))
        )
    assert sum(row.state == "CREATED" for row in publications) == 1
    assert sum(row.state == "EXACT_REPLAY" for row in publications) == 31
    assert ledger.read(receipt.execution_id) == receipt


def test_ledger_rejects_symlink_or_reparse_ancestor(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")
    ledger = ImmutableGateExecutionLedger(alias / "gate-ledger")
    with pytest.raises(GateReceiptError):
        ledger.publish(_receipt())
    assert not (real / "gate-ledger").exists()
