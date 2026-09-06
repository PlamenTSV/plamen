"""P0-AH fixtures for the shared verification execution-policy substrate.

These tests intentionally exercise a backend-, pipeline-, ecosystem-, and OS-neutral
policy.  They do not invoke a model, compiler, shell, or protocol-specific harness.
"""

from dataclasses import FrozenInstanceError, replace

import pytest

from verification_policy import (
    AttemptResult,
    AuditMode,
    Backend,
    BlockerAuthority,
    BlockerCode,
    ClaimClass,
    Decision,
    Ecosystem,
    ExecutionBlocker,
    ExecutionReceipt,
    Pipeline,
    Platform,
    ProofScope,
    Severity,
    VerificationWorkItem,
    evaluate_obligation,
    make_budget_exhausted_receipt,
    make_execution_receipt,
    make_nonexecution_receipt,
    plan_retry,
    reconcile_receipts,
    resolve_execution_policy,
    runner_spec,
)


SC_ECOSYSTEMS = (
    Ecosystem.EVM,
    Ecosystem.SOLANA,
    Ecosystem.APTOS,
    Ecosystem.SUI,
    Ecosystem.SOROBAN,
)
L1_ECOSYSTEMS = (Ecosystem.GO, Ecosystem.RUST)


def policy(
    mode=AuditMode.THOROUGH,
    backend=Backend.CLAUDE,
    pipeline=Pipeline.SC,
    ecosystem=Ecosystem.EVM,
    platform=Platform.POSIX,
):
    return resolve_execution_policy(mode, backend, pipeline, ecosystem, platform)


def item(
    finding_id="H-01",
    severity=Severity.HIGH,
    claim_class=ClaimClass.UNIT,
    *,
    constituent_id="root",
    locally_testable=True,
    harness_available=True,
):
    return VerificationWorkItem(
        finding_id=finding_id,
        constituent_id=constituent_id,
        severity=severity,
        claim_class=claim_class,
        locally_testable=locally_testable,
        harness_available=harness_available,
    )


def blocker(code, *, authority=BlockerAuthority.INDEPENDENT_ADJUDICATOR):
    independently_validated = authority is not BlockerAuthority.VERIFIER
    return ExecutionBlocker(
        code=code,
        authority=authority,
        evidence_digest="a" * 64,
        evidence_refs=("scratchpad/environment_probe.json",),
        independently_validated=independently_validated,
        validated_by=(BlockerAuthority.DRIVER if independently_validated else None),
    )


def test_mode_policy_matrix_cannot_be_silently_capped_by_backend_or_projection():
    all_severities = set(Severity)
    medium_plus = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
    projections = tuple((Pipeline.SC, e) for e in SC_ECOSYSTEMS) + tuple(
        (Pipeline.L1, e) for e in L1_ECOSYSTEMS
    )

    for mode in AuditMode:
        expected = all_severities if mode is AuditMode.THOROUGH else medium_plus
        observed = set()
        for backend in Backend:
            for pipeline, ecosystem in projections:
                for platform in Platform:
                    resolved = policy(mode, backend, pipeline, ecosystem, platform)
                    required = {s for s in Severity if resolved.requires_attempt(s)}
                    assert required == expected
                    observed.add(tuple(sorted(s.value for s in required)))
        assert len(observed) == 1


@pytest.mark.parametrize("severity", (Severity.LOW, Severity.INFORMATIONAL))
@pytest.mark.parametrize("claim_class", (ClaimClass.UNIT, ClaimClass.PROPERTY))
def test_thorough_low_and_info_locally_testable_rows_require_attempt(severity, claim_class):
    obligation = evaluate_obligation(
        policy(), item(severity=severity, claim_class=claim_class)
    )
    assert obligation.decision is Decision.ATTEMPT_REQUIRED
    assert obligation.debts == ()


@pytest.mark.parametrize("mode", (AuditMode.LIGHT, AuditMode.CORE))
def test_light_and_core_documented_reduced_policy(mode):
    resolved = policy(mode)
    assert resolved.requires_attempt(Severity.MEDIUM)
    assert not resolved.requires_attempt(Severity.LOW)
    assert not resolved.requires_attempt(Severity.INFORMATIONAL)


def test_fuzz_policy_is_separate_and_thorough_medium_plus_only():
    for mode in AuditMode:
        resolved = policy(mode)
        for severity in Severity:
            expected = mode is AuditMode.THOROUGH and severity in {
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
            }
            assert resolved.requires_fuzz(severity) is expected


@pytest.mark.parametrize(
    ("claim_class", "code"),
    (
        (ClaimClass.STRUCTURAL, BlockerCode.STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION),
        (ClaimClass.SPEC, BlockerCode.PURE_SPEC_OR_DOCS_ONLY),
        (ClaimClass.DOCS, BlockerCode.PURE_SPEC_OR_DOCS_ONLY),
    ),
)
def test_typed_evidence_bound_nonexecution_stays_unproven(claim_class, code):
    work = item(
        claim_class=claim_class, locally_testable=False, harness_available=False
    )
    obligation = evaluate_obligation(policy(), work, blocker(code))
    assert obligation.decision is Decision.BLOCKED_UNPROVEN
    assert obligation.proof_scope is ProofScope.UNPROVEN
    receipt = make_nonexecution_receipt(policy(), work, obligation)
    assert not receipt.attempted
    assert receipt.proof_scope is ProofScope.UNPROVEN


def test_verifier_self_reclassification_cannot_waive_execution():
    work = item(
        claim_class=ClaimClass.STRUCTURAL,
        locally_testable=False,
        harness_available=False,
    )
    proposed = blocker(
        BlockerCode.STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION,
        authority=BlockerAuthority.VERIFIER,
    )
    obligation = evaluate_obligation(policy(), work, proposed)
    assert obligation.decision is Decision.ATTEMPT_REQUIRED
    assert "INVALID_BLOCKER" in obligation.debts


def test_verifier_proposal_requires_a_distinct_adjudicator_before_nonexecution():
    work = item(
        claim_class=ClaimClass.STRUCTURAL,
        locally_testable=False,
        harness_available=False,
    )
    adjudicated = ExecutionBlocker(
        code=BlockerCode.STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION,
        authority=BlockerAuthority.VERIFIER,
        evidence_digest="9" * 64,
        evidence_refs=("scratchpad/adjudication.json",),
        independently_validated=True,
        validated_by=BlockerAuthority.INDEPENDENT_ADJUDICATOR,
    )
    obligation = evaluate_obligation(policy(), work, adjudicated)
    assert obligation.decision is Decision.BLOCKED_UNPROVEN
    assert obligation.proof_scope is ProofScope.UNPROVEN


def test_blocker_taxonomy_is_bound_to_claim_shape():
    work = item(claim_class=ClaimClass.UNIT)
    invalid = blocker(BlockerCode.STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION)
    obligation = evaluate_obligation(policy(), work, invalid)
    assert obligation.decision is Decision.ATTEMPT_REQUIRED
    assert "INVALID_BLOCKER" in obligation.debts


@pytest.mark.parametrize(
    "failure", (AttemptResult.COMPILE_FAILED, AttemptResult.RUN_FAILED)
)
def test_compile_or_run_failure_is_attempt_evidence_not_global_refutation(failure):
    resolved = policy()
    work = item()
    obligation = evaluate_obligation(resolved, work)
    receipt = make_execution_receipt(
        resolved,
        work,
        obligation,
        attempt_number=1,
        command_argv=("forge", "test"),
        runner_id="evm-forge",
        result=failure,
        proof_scope=ProofScope.UNPROVEN,
        output_digest="b" * 64,
    )
    assert receipt.attempted
    assert receipt.proof_scope is ProofScope.UNPROVEN
    with pytest.raises(ValueError, match="compile/run failure"):
        make_execution_receipt(
            resolved,
            work,
            obligation,
            attempt_number=1,
            command_argv=("forge", "test"),
            runner_id="evm-forge",
            result=failure,
            proof_scope=ProofScope.HARM,
            output_digest="b" * 64,
        )


def test_assertion_failure_can_only_prove_the_declared_mechanism_oracle():
    resolved = policy()
    work = item()
    obligation = evaluate_obligation(resolved, work)
    receipt = make_execution_receipt(
        resolved,
        work,
        obligation,
        attempt_number=1,
        command_argv=("forge", "test"),
        runner_id="evm-forge",
        result=AttemptResult.ASSERTION_FAILED,
        proof_scope=ProofScope.MECHANISM,
        output_digest="c" * 64,
    )
    assert receipt.proof_scope is ProofScope.MECHANISM


def test_harm_scoped_success_requires_an_executed_harm_oracle():
    resolved = policy()
    work = item()
    obligation = evaluate_obligation(resolved, work)
    receipt = make_execution_receipt(
        resolved,
        work,
        obligation,
        attempt_number=1,
        command_argv=("forge", "test"),
        runner_id="evm-forge",
        result=AttemptResult.HARM_CONFIRMED,
        proof_scope=ProofScope.HARM,
        output_digest="d" * 64,
    )
    assert receipt.proof_scope is ProofScope.HARM
    with pytest.raises(ValueError, match="harm proof"):
        make_execution_receipt(
            resolved,
            work,
            obligation,
            attempt_number=1,
            command_argv=("forge", "test"),
            runner_id="evm-forge",
            result=AttemptResult.MECHANISM_CONFIRMED,
            proof_scope=ProofScope.HARM,
            output_digest="d" * 64,
        )


def test_grouped_rows_preserve_mixed_constituent_testability_and_exact_parity():
    resolved = policy()
    executable = item(constituent_id="unit")
    structural = item(
        constituent_id="structural",
        claim_class=ClaimClass.STRUCTURAL,
        locally_testable=False,
        harness_available=False,
    )
    executable_obligation = evaluate_obligation(resolved, executable)
    structural_obligation = evaluate_obligation(
        resolved,
        structural,
        blocker(BlockerCode.STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION),
    )
    receipts = (
        make_execution_receipt(
            resolved,
            executable,
            executable_obligation,
            attempt_number=1,
            command_argv=("forge", "test"),
            runner_id="evm-forge",
            result=AttemptResult.MECHANISM_CONFIRMED,
            proof_scope=ProofScope.MECHANISM,
            output_digest="e" * 64,
        ),
        make_nonexecution_receipt(resolved, structural, structural_obligation),
    )
    reconciliation = reconcile_receipts(
        resolved, (executable, structural), receipts
    )
    assert reconciliation.coverage_complete
    assert reconciliation.missing_keys == ()
    assert reconciliation.extra_keys == ()


def test_external_integration_without_environment_needs_typed_blocker():
    resolved = policy(ecosystem=Ecosystem.SOLANA)
    work = item(
        claim_class=ClaimClass.INTEGRATION,
        locally_testable=False,
        harness_available=False,
    )
    obligation = evaluate_obligation(
        resolved,
        work,
        blocker(BlockerCode.EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS),
    )
    assert obligation.decision is Decision.BLOCKED_UNPROVEN
    assert obligation.proof_scope is ProofScope.UNPROVEN


def test_retry_reuses_prior_success_instead_of_duplicate_execution():
    resolved = policy()
    work = item()
    obligation = evaluate_obligation(resolved, work)
    successful = make_execution_receipt(
        resolved,
        work,
        obligation,
        attempt_number=1,
        command_argv=("forge", "test"),
        runner_id="evm-forge",
        result=AttemptResult.HARM_CONFIRMED,
        proof_scope=ProofScope.HARM,
        output_digest="f" * 64,
    )
    retry = plan_retry(resolved, work, (successful,))
    assert not retry.should_attempt
    assert retry.reuse_receipt_digest == successful.receipt_digest
    assert retry.next_attempt_number is None


@pytest.mark.parametrize("ecosystem", tuple(Ecosystem))
@pytest.mark.parametrize("platform", tuple(Platform))
def test_runner_specs_are_argv_based_and_cross_platform(ecosystem, platform):
    spec = runner_spec(
        ecosystem, platform, "tests/p0_ah/poc_case.test", selector="poc_case"
    )
    assert spec.command_argv
    assert all(isinstance(part, str) and part for part in spec.command_argv)
    assert not any("&&" in part or ";" in part for part in spec.command_argv)
    if ecosystem is not Ecosystem.GO:
        joined = " ".join(spec.command_argv)
        separator = "\\" if platform is Platform.WINDOWS else "/"
        assert separator in joined


def test_queue_to_receipt_parity_detects_missing_extra_and_duplicates():
    resolved = policy()
    first = item(finding_id="H-01")
    second = item(finding_id="H-02")
    obligation = evaluate_obligation(resolved, first)
    first_receipt = make_execution_receipt(
        resolved,
        first,
        obligation,
        attempt_number=1,
        command_argv=("forge", "test"),
        runner_id="evm-forge",
        result=AttemptResult.MECHANISM_CONFIRMED,
        proof_scope=ProofScope.MECHANISM,
        output_digest="1" * 64,
    )
    extra_work = item(finding_id="H-99")
    extra_obligation = evaluate_obligation(resolved, extra_work)
    extra = make_execution_receipt(
        resolved,
        extra_work,
        extra_obligation,
        attempt_number=1,
        command_argv=("forge", "test"),
        runner_id="evm-forge",
        result=AttemptResult.MECHANISM_CONFIRMED,
        proof_scope=ProofScope.MECHANISM,
        output_digest="2" * 64,
    )
    reconciliation = reconcile_receipts(
        resolved,
        (first, second),
        (first_receipt, first_receipt, extra),
    )
    assert not reconciliation.coverage_complete
    assert second.key in reconciliation.missing_keys
    assert extra.key in reconciliation.extra_keys
    assert first.key in reconciliation.duplicate_keys


def test_resume_reconciliation_is_idempotent():
    resolved = policy()
    work = item()
    obligation = evaluate_obligation(resolved, work)
    receipt = make_execution_receipt(
        resolved,
        work,
        obligation,
        attempt_number=1,
        command_argv=("forge", "test"),
        runner_id="evm-forge",
        result=AttemptResult.MECHANISM_CONFIRMED,
        proof_scope=ProofScope.MECHANISM,
        output_digest="3" * 64,
    )
    first = reconcile_receipts(resolved, (work,), (receipt,))
    resumed = reconcile_receipts(resolved, (work,), (receipt,))
    assert resumed == first
    assert resumed.reconciliation_digest == first.reconciliation_digest


def test_budget_exhaustion_is_visible_debt_not_false_completion():
    resolved = policy()
    work = item()
    obligation = evaluate_obligation(resolved, work)
    receipt = make_budget_exhausted_receipt(
        resolved, work, obligation, attempts_consumed=resolved.max_attempts_per_row
    )
    reconciliation = reconcile_receipts(resolved, (work,), (receipt,))
    assert not reconciliation.coverage_complete
    assert "BUDGET_EXHAUSTED" in receipt.debts
    assert "BUDGET_EXHAUSTED" in reconciliation.debts


def test_policy_and_receipts_are_immutable_records():
    resolved = policy()
    with pytest.raises(FrozenInstanceError):
        resolved.mode = AuditMode.CORE

    work = item()
    obligation = evaluate_obligation(resolved, work)
    receipt = make_budget_exhausted_receipt(
        resolved, work, obligation, attempts_consumed=resolved.max_attempts_per_row
    )
    with pytest.raises(FrozenInstanceError):
        receipt.proof_scope = ProofScope.HARM


def test_policy_and_receipt_digests_reject_silent_record_tampering():
    resolved = policy()
    with pytest.raises(ValueError, match="execution severities"):
        replace(resolved, attempt_severities=(Severity.CRITICAL,))

    work = item()
    obligation = evaluate_obligation(resolved, work)
    receipt = make_execution_receipt(
        resolved,
        work,
        obligation,
        attempt_number=1,
        command_argv=("forge", "test"),
        runner_id="evm-forge",
        result=AttemptResult.MECHANISM_CONFIRMED,
        proof_scope=ProofScope.MECHANISM,
        output_digest="4" * 64,
    )
    with pytest.raises(ValueError, match="receipt digest"):
        replace(receipt, finding_id="H-99")
