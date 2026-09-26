from __future__ import annotations

import base64
import copy
import inspect
from pathlib import Path

import pytest

import candidate_negative_authority as N


STAGED_OUTPUT = "scratchpad:depth_state_trace_findings.md"
STAGED_METHODOLOGY = b"# Run12 bound finding-output methodology\n"


def _staged_context() -> dict[str, object]:
    return N.compile_depth_candidate_negative_staged_context(
        STAGED_METHODOLOGY,
        STAGED_OUTPUT,
        "DEPTH_STATE_TRACE",
        invocation_id="RUN12-INVOCATION-1",
    )


def _validate_staged(text: str, context=None) -> tuple[str, ...]:
    return N.staged_depth_candidate_negative_receipt_validator(
        {STAGED_OUTPUT: text.encode("utf-8")},
        _staged_context() if context is None else context,
    )


def _run12_complete_depth_negative() -> str:
    return """### Finding [DE-1]: conservation candidate
**Disposition**: REFUTATION_PROPOSAL
**Location**: src/Vault.sol:L41
**Refutation Basis**: credited value equals settled value
**Invariant Commitment**: CI:CI-DE-1

committed-invariant [CI-DE-1]
Locus: src/Vault.sol:L41
Shape: CONSERVATION
Assertion: total credited value equals total settled value
Falsify Class: conservation
Provenance: DE-1

| Finding ID | Disposition | Notes |
|---|---|---|
| DE-1 | REFUTATION_PROPOSAL | summary only |
"""


def _build(tmp_path: Path, text: str, *, phase: str = "attention_repair"):
    methodology = tmp_path / "finding-output-format.md"
    methodology.write_text("# bound methodology\n", encoding="utf-8")
    return N.build_candidate_negative_ledger(
        phase=phase,
        artifacts=[
            N.ArtifactInput(
                relative_path="producer_findings.md",
                content=text.encode("utf-8"),
                producer_identity="RUN12-TEST",
                producer_invocation_id="INVOCATION-1",
            )
        ],
        methodology_path=methodology,
    )


def test_heading_and_matching_table_keep_only_richer_exact_event(
    tmp_path: Path,
) -> None:
    ledger = _build(
        tmp_path,
        """### Finding [DE-1]: conservation candidate
**Disposition**: REFUTATION_PROPOSAL
**Location**: src/Vault.sol:L41
**Refutation Basis**: credited value equals settled value
**Invariant Commitment**: CI:CI-DE-1

committed-invariant [CI-DE-1]
Locus: src/Vault.sol:L41
Shape: CONSERVATION
Assertion: total credited value equals total settled value
Falsify Class: conservation
Provenance: DE-1

| Finding ID | Disposition | Notes |
|---|---|---|
| DE-1 | REFUTATION_PROPOSAL | summary only |
""",
        phase="depth",
    )
    N.validate_candidate_negative_ledger(ledger)
    assert ledger["status"] == "CLEAN"
    assert ledger["event_count"] == 1
    assert ledger["events"][0]["source_item_id"] == "DE-1"
    assert ledger["events"][0]["identity_state"] == "EXACT"
    assert ledger["events"][0]["harvest_kind"] == "STRUCTURED_ENTITY_FIELD"
    assert ledger["events"][0]["invariant_commitment"]["status"] == "COMPLETE"


@pytest.mark.parametrize("header", ["Finding ID", "Candidate ID", "Issue ID", "ID"])
def test_table_only_explicit_bare_id_is_one_exact_event(
    tmp_path: Path, header: str
) -> None:
    ledger = _build(
        tmp_path,
        f"| {header} | Disposition | Notes |\n"
        "|---|---|---|\n"
        "| DE-1 | REFUTATION_PROPOSAL | guarded |\n",
    )
    assert ledger["status"] == "CLEAN"
    assert ledger["event_count"] == 1
    assert ledger["events"][0]["source_item_id"] == "DE-1"
    assert ledger["events"][0]["identity_state"] == "EXACT"


def test_table_never_derives_exact_id_from_arbitrary_columns(tmp_path: Path) -> None:
    ledger = _build(
        tmp_path,
        """| Target | Disposition | Notes |
|---|---|---|
| Finding [DE-1] | REFUTATION_PROPOSAL | Candidate [ST-9] |
""",
    )
    assert ledger["event_count"] == 1
    assert ledger["events"][0]["identity_state"] == "DERIVED"
    assert ledger["events"][0]["source_item_id"].startswith("ENTITY-")


@pytest.mark.parametrize("identity_cell", ["DE-1 candidate", "[A]/[B]", "DE-1 see ST-9"])
def test_explicit_identity_column_requires_an_unambiguous_token(
    tmp_path: Path, identity_cell: str
) -> None:
    """A cell that names more than the ID, or more than one ID, is DERIVED."""
    ledger = _build(
        tmp_path,
        "| Finding ID | Disposition |\n"
        "|---|---|\n"
        f"| {identity_cell} | REFUTATION_PROPOSAL |\n",
    )
    assert ledger["event_count"] == 1
    assert ledger["events"][0]["identity_state"] == "DERIVED"
    assert ledger["events"][0]["source_item_id"].startswith("ENTITY-")


@pytest.mark.parametrize(
    "identity_cell", ["DE-1", "[DE-1]", "Finding [DE-1]", "Candidate DE-1"]
)
def test_markdown_decoration_around_an_id_keeps_exact_identity(
    tmp_path: Path, identity_cell: str
) -> None:
    """Brackets and the role word are presentation, exactly as the heading
    recognizer already treats them (`### Finding [DE-1]`).  Charging a worker
    DERIVED debt for writing the ID the way every heading in the corpus writes
    it rejected whole artifacts over decoration."""
    ledger = _build(
        tmp_path,
        "| Finding ID | Disposition |\n"
        "|---|---|\n"
        f"| {identity_cell} | REFUTATION_PROPOSAL |\n",
    )
    assert ledger["event_count"] == 1
    assert ledger["events"][0]["identity_state"] == "EXACT"
    assert ledger["events"][0]["source_item_id"] == "DE-1"


def test_conflicting_heading_and_table_dispositions_are_visible_debt(
    tmp_path: Path,
) -> None:
    ledger = _build(
        tmp_path,
        """### Finding [DE-1]: live candidate
**Disposition**: REFUTATION_PROPOSAL

| Finding ID | Disposition | Notes |
|---|---|---|
| DE-1 | NOT_APPLICABLE_PROPOSAL | conflicting summary |
""",
    )
    assert ledger["status"] == "INPUT_DEBT"
    assert ledger["event_count"] == 2
    assert ledger["families"][0]["identity_state"] == "CONFLICTED"
    assert "CONFLICTING_REPRESENTATION" in {
        issue["code"] for issue in ledger["issues"]
    }
    assert "MIXED_CANDIDATE_PROPOSAL_DISPOSITIONS" in {
        issue["code"] for issue in ledger["issues"]
    }


@pytest.mark.parametrize("placeholder", ["—", "None new"])
@pytest.mark.parametrize("disposition", ["N/A", "NOT_APPLICABLE_PROPOSAL"])
def test_explicit_zero_candidate_na_table_row_is_not_an_event(
    tmp_path: Path, placeholder: str, disposition: str
) -> None:
    ledger = _build(
        tmp_path,
        "| Candidate ID | Disposition | Notes |\n"
        "|---|---|---|\n"
        f"| {placeholder} | {disposition} | no candidate proposed |\n",
    )
    assert ledger["status"] == "CLEAN"
    assert ledger["event_count"] == 0
    assert ledger["events"] == []


def test_zero_placeholder_is_recognised_under_any_identity_header(
    tmp_path: Path,
) -> None:
    """`Candidate` declares the identity column exactly as `Candidate ID`
    does, so the row is the same zero-candidate attestation in both layouts.

    Reading it otherwise minted a phantom candidate whose derived identity
    then discarded the artifact -- and the old two-string placeholder
    allowlist made the answer depend on which dash codepoint was used.
    """
    ledger = _build(
        tmp_path,
        """| Candidate | Disposition | Notes |
|---|---|---|
| None new | N/A | no candidate proposed |
""",
    )
    assert ledger["status"] == "CLEAN"
    assert ledger["event_count"] == 0


def test_real_explicit_candidate_na_remains_event_and_debt(tmp_path: Path) -> None:
    ledger = _build(
        tmp_path,
        """| Candidate ID | Disposition | Notes |
|---|---|---|
| ST-9 | N/A | candidate judged outside scope |
""",
    )
    assert ledger["event_count"] == 1
    assert ledger["events"][0]["source_item_id"] == "ST-9"
    assert ledger["events"][0]["identity_state"] == "EXACT"
    assert ledger["events"][0]["proposed_disposition"] == (
        "NOT_APPLICABLE_PROPOSAL"
    )
    assert "EVENT_NOT_APPLICABLE_WITH_NONZERO_DENOMINATOR" in {
        issue["code"] for issue in ledger["issues"]
    }


def test_heading_real_candidate_na_remains_event_and_debt(tmp_path: Path) -> None:
    ledger = _build(
        tmp_path,
        """### Candidate [ST-9]: explicit scoped candidate
**Disposition**: N/A
**Reason**: independently review whether this candidate is outside scope
""",
    )
    assert ledger["event_count"] == 1
    assert ledger["events"][0]["source_item_id"] == "ST-9"
    assert ledger["events"][0]["identity_state"] == "EXACT"
    assert ledger["events"][0]["proposed_disposition"] == (
        "NOT_APPLICABLE_PROPOSAL"
    )
    assert "EVENT_NOT_APPLICABLE_WITH_NONZERO_DENOMINATOR" in {
        issue["code"] for issue in ledger["issues"]
    }


def test_staged_context_is_plain_digest_bound_and_validator_is_top_level() -> None:
    context = _staged_context()

    assert context["methodology_base64"] == base64.b64encode(
        STAGED_METHODOLOGY
    ).decode("ascii")
    assert context["methodology_sha256"] == N._bytes_sha(STAGED_METHODOLOGY)
    assert context["output_identity"] == STAGED_OUTPUT
    assert context["producer_identity"] == "DEPTH_STATE_TRACE"
    assert context["producer_invocation_id"] == "RUN12-INVOCATION-1"
    assert "<locals>" not in N.staged_depth_candidate_negative_receipt_validator.__qualname__
    assert inspect.isfunction(N.staged_depth_candidate_negative_receipt_validator)
    assert all(isinstance(value, (str, list)) for value in context.values())


def test_staged_gate_accepts_real_run12_fixture_without_filesystem(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _staged_context()

    def forbidden_read(*_args, **_kwargs):
        raise AssertionError("staged candidate-negative validation read a path")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read)

    assert _validate_staged(_run12_complete_depth_negative(), context) == ()
    assert N.evaluate_staged_depth_candidate_negative_receipt(
        {STAGED_OUTPUT: _run12_complete_depth_negative().encode("utf-8")},
        context,
    ) == (True, ())


@pytest.mark.parametrize(
    "text",
    (
        "# Depth findings\nNo structured negative candidates were emitted.\n",
        """| Candidate ID | Disposition | Notes |
|---|---|---|
| None new | N/A | no candidate proposed |
""",
        """| Candidate ID | Disposition | Notes |
|---|---|---|
| — | NOT_APPLICABLE_PROPOSAL | zero denominator |
""",
    ),
)
def test_staged_gate_accepts_zero_events_and_canonical_zero_denominator(
    text: str,
) -> None:
    assert _validate_staged(text) == ()


def test_staged_gate_rejects_wrong_or_multiple_output_identity() -> None:
    context = _staged_context()
    validator = N.staged_depth_candidate_negative_receipt_validator

    assert validator(
        {"scratchpad:depth_other_findings.md": b"# none\n"}, context
    ) == ("staged candidate-negative output denominator mismatch",)
    assert validator(
        {
            STAGED_OUTPUT: b"# none\n",
            "scratchpad:depth_other_findings.md": b"# none\n",
        },
        context,
    ) == ("staged candidate-negative output denominator mismatch",)


@pytest.mark.parametrize(
    "field",
    (
        "schema_version",
        "phase",
        "methodology_identity",
        "methodology_base64",
        "methodology_sha256",
        "output_identity",
        "producer_identity",
        "producer_invocation_id",
        "context_digest",
    ),
)
def test_staged_gate_rejects_context_tamper(field: str) -> None:
    context = copy.deepcopy(_staged_context())
    context[field] = "tampered"

    assert _validate_staged("# none\n", context) == (
        "staged candidate-negative gate context is invalid",
    )


def test_staged_gate_rejects_resigned_methodology_byte_tamper() -> None:
    context = copy.deepcopy(_staged_context())
    context["methodology_base64"] = base64.b64encode(b"malicious").decode("ascii")
    context["context_digest"] = N._digest(
        {key: value for key, value in context.items() if key != "context_digest"}
    )

    assert _validate_staged("# none\n", context) == (
        "staged candidate-negative gate context is invalid",
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    (
        (
            """### Candidate without an explicit identity
**Disposition**: REFUTATION_PROPOSAL
**Reason**: prose-only identity
""",
            "derived identity",
        ),
        (
            """### Finding [DE-1]: first claim
**Disposition**: REFUTATION_PROPOSAL
**Invariant Commitment**: NOT_REQUIRED_NON_VALUE_BEARING: docs only
**Non-Value-Bearing Category**: DOCUMENTATION_ONLY

### Finding [DE-1]: different claim
**Disposition**: REFUTATION_PROPOSAL
**Invariant Commitment**: NOT_REQUIRED_NON_VALUE_BEARING: docs only
**Non-Value-Bearing Category**: DOCUMENTATION_ONLY
""",
            "duplicate representations",
        ),
        (
            """### Finding [DE-1]: live candidate
**Disposition**: REFUTATION_PROPOSAL

| Finding ID | Disposition | Notes |
|---|---|---|
| DE-1 | NOT_APPLICABLE_PROPOSAL | conflicting summary |
""",
            "conflicting structured dispositions",
        ),
        (
            """| Candidate ID | Disposition | Notes |
|---|---|---|
| DE-9 | N/A | actual candidate called out of scope |
""",
            "real depth candidate cannot use N/A",
        ),
    ),
)
def test_staged_gate_publishes_and_records_candidate_negative_debt(
    text: str, expected: str
) -> None:
    """Every code here is a PRESENTATION property (`format.*`), so it degrades
    with visible debt and a targeted repair hint instead of discarding the
    producer's whole artifact.

    `_candidate_negative_debt_reasons` now answers only "must this artifact be
    DISCARDED"; the debt itself lives on the ledger (`status: INPUT_DEBT` plus
    the issue row) and travels WITH the published artifact, so the candidate
    stays in front of an independent consumer.
    """

    assert _validate_staged(text) == ()

    artifact = N.ArtifactInput(
        relative_path=STAGED_OUTPUT,
        content=text.encode("utf-8"),
        producer_identity="DEPTH_STATE_TRACE",
        producer_invocation_id="i" * 32,
    )
    ledger = N._build_candidate_negative_ledger_from_bytes(
        phase="depth",
        artifacts=(artifact,),
        methodology_bytes=STAGED_METHODOLOGY,
        methodology_identity=N._STAGED_METHODOLOGY_IDENTITY,
    )
    assert ledger["status"] == "INPUT_DEBT", text
    result = N.candidate_negative_check_result(ledger, producer_phase="depth")
    assert result.should_discard is False
    assert result.debt_defects
    assert all(defect.repair_hint for defect in result.debt_defects)


@pytest.mark.parametrize(
    "output_identity",
    ("depth.md", "scratchpad:../depth.md", "scratchpad:depth.txt", ""),
)
def test_staged_context_compiler_rejects_noncanonical_output_identity(
    output_identity: str,
) -> None:
    with pytest.raises(ValueError, match="output identity"):
        N.compile_depth_candidate_negative_staged_context(
            STAGED_METHODOLOGY,
            output_identity,
            "DEPTH_STATE_TRACE",
        )


def test_staged_context_compiler_rejects_invalid_bindings() -> None:
    with pytest.raises(ValueError, match="methodology bytes"):
        N.compile_depth_candidate_negative_staged_context(
            b"", STAGED_OUTPUT, "DEPTH_STATE_TRACE"
        )
    with pytest.raises(ValueError, match="producer identity"):
        N.compile_depth_candidate_negative_staged_context(
            STAGED_METHODOLOGY, STAGED_OUTPUT, ""
        )
    with pytest.raises(ValueError, match="invocation identity"):
        N.compile_depth_candidate_negative_staged_context(
            STAGED_METHODOLOGY, STAGED_OUTPUT, "DEPTH_STATE_TRACE", " bad "
        )


def test_staged_validator_result_satisfies_runtime_sequence_contract() -> None:
    import posix_v2_compat_runtime as runtime

    result = _validate_staged(_run12_complete_depth_negative())

    assert result == ()
    assert runtime._bounded_staged_reasons(result) == []


def test_missing_committed_invariant_is_visible_debt_not_a_denial(
    tmp_path: Path,
) -> None:
    """The invariant requirement is enforced where disposition happens.

    A value-bearing refutation still owes one exact committed invariant, but
    that is checked by the adjudicator, which vetoes exclusion and REOPENS the
    candidate when the commitment carries debt.  Denying the producer's whole
    artifact here instead discarded the analysis AND the candidate it was
    meant to protect.  The debt stays on the ledger and the receipt.
    """
    body = """### Finding [DE-1]: missing CI
**Disposition**: REFUTATION_PROPOSAL
**Reason**: unsupported negative
"""
    ledger = _build(tmp_path, body, phase="depth")
    assert ledger["status"] == "INPUT_DEBT"
    codes = {str(issue.get("code")) for issue in ledger["issues"]}
    assert "DEPTH_COMMITTED_INVARIANT_DEBT" in codes
    # visible on the ledger, but the producer's artifact is not denied
    assert N._candidate_negative_debt_reasons(ledger) == ()
    # and the staged gate agrees
    assert _validate_staged(body) == ()


def test_identity_and_disposition_debt_is_recorded_not_silently_dropped(
    tmp_path: Path,
) -> None:
    """Control: degrading to debt must not degrade to SILENCE.

    A real candidate disposed with the legacy terminal `N/A` is published, but
    it is still an EXACT-identity event in the denominator, still
    `INPUT_DEBT`, and still carries
    EVENT_NOT_APPLICABLE_WITH_NONZERO_DENOMINATOR with a repair hint naming the
    nonterminal enum.  Nothing is closed.
    """
    body = """| Candidate ID | Disposition | Notes |
|---|---|---|
| DE-9 | N/A | actual candidate called out of scope |
"""
    ledger = _build(tmp_path, body, phase="depth")
    codes = {str(issue.get("code")) for issue in ledger["issues"]}
    assert "EVENT_NOT_APPLICABLE_WITH_NONZERO_DENOMINATOR" in codes
    assert ledger["events"][0]["source_item_id"] == "DE-9"
    assert ledger["events"][0]["identity_state"] == "EXACT"
    assert ledger["events"][0]["proposed_disposition"] == "NOT_APPLICABLE_PROPOSAL"
    assert ledger["events"][0]["requires_independent_consumer"] is True
    assert N._candidate_negative_debt_reasons(ledger) == ()
    assert _validate_staged(body) == ()
