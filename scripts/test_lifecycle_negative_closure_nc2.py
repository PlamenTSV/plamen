"""NC-2: lifecycle labels cannot self-issue destructive authority."""
from __future__ import annotations

import pytest

from test_finding_lifecycle_authority_p0_g_n_x_y_aa import (
    _build,
    _candidate,
    _decision,
    _obligation_kinds,
    _projection,
    _row,
)


@pytest.mark.parametrize(
    ("kind", "basis", "scope", "kwargs"),
    [
        ("REFUTED", "INDEPENDENT_ANALYSIS", "FULL_CLAIM", {}),
        ("REFUTED", "FORMAL_PROOF", "FULL_CLAIM", {}),
        ("REFUTED", "INDEPENDENT_EXECUTION", "FULL_CLAIM", {}),
        (
            "AUTHORIZED_ZERO_HARM",
            "INDEPENDENT_ANALYSIS",
            "FULL_CLAIM",
            {"reason_class": "ZERO_SECURITY_CONSEQUENCE"},
        ),
        (
            "AUTHORIZED_SCOPE_EXCLUSION",
            "EXACT_SCOPE_PREDICATE",
            "SCOPE_ONLY",
            {"scope_snapshot_sha256": "d" * 64},
        ),
    ],
)
def test_negative_label_and_arbitrary_digest_remain_unverified(
    kind: str, basis: str, scope: str, kwargs: dict[str, object]
) -> None:
    candidate = _candidate()
    decision = _decision(
        candidate,
        kind=kind,
        evidence_basis=basis,
        proof_scope=scope,
        **kwargs,
    )
    receipt = _build([candidate], [decision])
    row = _row(receipt)
    assert row["claim_state"] == "UNVERIFIED"
    assert row["retention_target"] == "BODY"
    assert row["terminal_complete"] is False
    assert "INDEPENDENT_VERIFICATION" in _obligation_kinds(receipt)
    assert receipt["rejected_decisions"]
    assert "TYPED" in receipt["rejected_decisions"][0]["reason"]


def test_typed_equivalence_label_without_applied_authority_does_not_alias() -> None:
    absorbed = _candidate("INV-001")
    survivor = _candidate("INV-002", source_record_sha256="e" * 64)
    decision = _decision(
        absorbed,
        kind="AUTHORIZED_ALIAS",
        evidence_basis="TYPED_EQUIVALENCE",
        proof_scope="FULL_CLAIM",
        alias_target_candidate_id="INV-002",
    )
    receipt = _build([absorbed, survivor], [decision])
    row = _row(receipt, "INV-001")
    assert row["claim_state"] == "UNVERIFIED"
    assert row["retention_target"] == "BODY"
    assert receipt["rejected_decisions"][0]["reason"] == (
        "ALIAS_REQUIRES_APPLIED_LOSSLESS_EQUIVALENCE_AUTHORITY"
    )


def test_deferred_routing_never_completes_verification_after_projection() -> None:
    candidate = _candidate()
    decision = _decision(
        candidate,
        kind="AUTHORIZED_DEFERRED",
        evidence_basis="INDEPENDENT_ANALYSIS",
        proof_scope="PARTIAL_CLAIM",
        next_action="complete independent verification",
        public_retention_target="HUMAN_REVIEW",
    )
    receipt = _build(
        [candidate], [decision], [_projection(candidate, kind="HUMAN_REVIEW")]
    )
    row = _row(receipt)
    assert row["claim_state"] == "DEFERRED_VISIBLE"
    assert row["delivery_state"] == "DELIVERED_HUMAN_REVIEW"
    assert row["terminal_complete"] is False
    assert row["visible_debt"] is True
    assert "INDEPENDENT_VERIFICATION" in _obligation_kinds(receipt)
