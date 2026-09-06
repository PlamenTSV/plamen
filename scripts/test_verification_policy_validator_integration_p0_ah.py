"""Red integration contract for P0-AH shared execution policy wiring.

The policy substrate is already covered independently.  These fixtures lock the
live-validator cutover that is still missing:

* legacy positional callers keep their current behaviour;
* live callers pass one explicit, keyword-only ``execution_policy``;
* that policy, not verifier-authored prose, owns severity coverage;
* hard and soft gates cannot carry independent Light/Core/Thorough filters;
* execution coverage stays separate from fuzz policy and proof scope.

This file intentionally contains no protocol-specific fixtures and performs no
compiler, model, network, or shell execution.
"""

from __future__ import annotations

import ast
import inspect
import re
import sys
from pathlib import Path

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(REPO_ROOT))

import plamen_validators as V  # noqa: E402
from verification_policy import (  # noqa: E402
    AttemptResult,
    AuditMode,
    Backend,
    BlockerAuthority,
    BlockerCode,
    ClaimClass,
    Decision,
    Ecosystem,
    ExecutionBlocker,
    Pipeline,
    Platform,
    ProofScope,
    Severity,
    VerificationWorkItem,
    evaluate_obligation,
    make_execution_receipt,
    resolve_execution_policy,
)


SC_ECOSYSTEMS = (
    Ecosystem.EVM,
    Ecosystem.SOLANA,
    Ecosystem.APTOS,
    Ecosystem.SUI,
    Ecosystem.SOROBAN,
)
L1_ECOSYSTEMS = (Ecosystem.GO, Ecosystem.RUST)
MEDIUM_PLUS = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


def _policy(
    mode: AuditMode = AuditMode.THOROUGH,
    *,
    backend: Backend = Backend.CLAUDE,
    pipeline: Pipeline = Pipeline.SC,
    ecosystem: Ecosystem = Ecosystem.EVM,
    platform: Platform = Platform.POSIX,
):
    return resolve_execution_policy(mode, backend, pipeline, ecosystem, platform)


def _row(
    fid: str,
    severity: Severity,
    claim_class: ClaimClass = ClaimClass.PROPERTY,
) -> dict[str, str]:
    return {
        "finding id": fid,
        "severity": severity.value.title(),
        "poc class": claim_class.value,
    }


def _function_source(module, function_name: str) -> str:
    return inspect.getsource(getattr(module, function_name))


def _assert_keyword_only_policy_parameter(function) -> None:
    parameters = inspect.signature(function).parameters
    assert "execution_policy" in parameters, (
        f"{function.__name__} must expose the shared execution_policy adapter"
    )
    assert parameters["execution_policy"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["execution_policy"].default is None


def _call_required(row, mode, content, policy, scratchpad=None) -> bool:
    """Use only the future adapter seam; fail with a useful red message."""

    _assert_keyword_only_policy_parameter(V._poc_contract_required)
    return V._poc_contract_required(
        row,
        mode.value,
        content,
        scratchpad,
        execution_policy=policy,
    )


def _write_verify(
    scratchpad: Path,
    fid: str,
    *,
    ledger_class: str = "property",
    attempted: str = "NO",
    skip_code: str = "STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION",
    compiled: str = "N/A",
    result: str = "NOT_EXECUTED",
) -> None:
    (scratchpad / f"verify_{fid}.md").write_text(
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Medium\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "### PoC Attempt\n"
        f"- PoC Class: {ledger_class}\n"
        f"- Attempted: {attempted}\n"
        f"- PoC Not Attempted Because: {skip_code}\n"
        "- Test File: tests/generic_verification_test.ext\n"
        "- Command: test-runner --case generic_verification\n"
        "### Execution Result\n"
        f"- Compiled: {compiled}\n"
        f"- Result: {result}\n"
        "- Evidence Tag: [CODE-TRACE]\n",
        encoding="utf-8",
    )


def _all_named_calls(path: Path, call_name: str) -> list[ast.Call]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == call_name:
            calls.append(node)
        elif isinstance(node.func, ast.Attribute) and node.func.attr == call_name:
            calls.append(node)
    return calls


def _keyword_names(call: ast.Call) -> set[str]:
    return {kw.arg for kw in call.keywords if kw.arg is not None}


def test_live_validator_adapter_is_keyword_only_and_legacy_default_is_preserved():
    """The cutover must not silently change isolated legacy helper callers."""

    for function in (
        V._poc_contract_required,
        V._validate_poc_contract_for_rows,
        V._validate_poc_attempt_coverage,
        V._validate_verify_completion,
    ):
        _assert_keyword_only_policy_parameter(function)

    # Compatibility control: a caller that does not provide the new policy
    # remains on the legacy projection until every production path is wired.
    legacy_low = _row("L-LEGACY", Severity.LOW)
    assert V._poc_contract_required(legacy_low, "thorough") is False


def test_shared_policy_owns_attempt_threshold_for_every_backend_and_pipeline():
    """Backend/ecosystem/platform projections are metadata, never severity caps."""

    projections = tuple((Pipeline.SC, e) for e in SC_ECOSYSTEMS) + tuple(
        (Pipeline.L1, e) for e in L1_ECOSYSTEMS
    )
    mismatches: list[str] = []
    content = (
        "**Verdict**: CONFIRMED\n"
        "### PoC Attempt\n"
        "- PoC Class: property\n"
        "- Attempted: NO\n"
    )

    for mode in AuditMode:
        expected = set(Severity) if mode is AuditMode.THOROUGH else MEDIUM_PLUS
        for backend in Backend:
            for pipeline, ecosystem in projections:
                for platform in Platform:
                    policy = _policy(
                        mode,
                        backend=backend,
                        pipeline=pipeline,
                        ecosystem=ecosystem,
                        platform=platform,
                    )
                    for severity in Severity:
                        observed = _call_required(
                            _row(f"ROW-{severity.value}", severity),
                            mode,
                            content,
                            policy,
                        )
                        if observed is not (severity in expected):
                            mismatches.append(
                                "/".join(
                                    (
                                        mode.value,
                                        backend.value,
                                        pipeline.value,
                                        ecosystem.value,
                                        platform.value,
                                        severity.value,
                                        str(observed),
                                    )
                                )
                            )
    assert mismatches == []


@pytest.mark.parametrize("severity", (Severity.LOW, Severity.INFORMATIONAL))
def test_thorough_hard_shard_gate_opens_low_and_info_verify_files(
    tmp_path: Path, severity: Severity
):
    """Direct helper coverage is insufficient: lock the old cheap-filter bypass."""

    _assert_keyword_only_policy_parameter(V._validate_poc_contract_for_rows)
    fid = f"ROW-{severity.value.upper()}"
    row = _row(fid, severity)
    _write_verify(tmp_path, fid)

    issues = V._validate_poc_contract_for_rows(
        tmp_path,
        [row],
        AuditMode.THOROUGH.value,
        execution_policy=_policy(AuditMode.THOROUGH),
    )
    assert any(fid in issue and "not attempted" in issue.lower() for issue in issues)


def test_verifier_prose_reclassification_cannot_excuse_a_policy_obligation(
    tmp_path: Path,
):
    """The same worker cannot author both the waiver and its terminal authority."""

    policy = _policy(AuditMode.THOROUGH)
    fid = "ROW-RECLASS"
    row = _row(fid, Severity.MEDIUM, ClaimClass.PROPERTY)
    _write_verify(tmp_path, fid, ledger_class="structural")
    content = (tmp_path / f"verify_{fid}.md").read_text(encoding="utf-8")

    assert _call_required(row, AuditMode.THOROUGH, content, policy, tmp_path)
    issues = V._validate_poc_contract_for_rows(
        tmp_path,
        [row],
        AuditMode.THOROUGH.value,
        execution_policy=policy,
    )
    assert any(fid in issue for issue in issues)


def test_only_independently_validated_typed_blocker_can_waive_execution():
    """Positive and negative authority controls for the delegated policy call."""

    policy = _policy(AuditMode.THOROUGH)
    work = VerificationWorkItem(
        finding_id="ROW-STRUCTURAL",
        constituent_id="root",
        severity=Severity.LOW,
        claim_class=ClaimClass.STRUCTURAL,
        locally_testable=False,
        harness_available=False,
    )
    verifier_proposal = ExecutionBlocker(
        code=BlockerCode.STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION,
        authority=BlockerAuthority.VERIFIER,
        evidence_digest="a" * 64,
        evidence_refs=("scratchpad/verifier_claim.json",),
        independently_validated=False,
    )
    proposed = evaluate_obligation(policy, work, verifier_proposal)
    assert proposed.decision is Decision.ATTEMPT_REQUIRED
    assert "INVALID_BLOCKER" in proposed.debts

    adjudicated = ExecutionBlocker(
        code=BlockerCode.STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION,
        authority=BlockerAuthority.VERIFIER,
        evidence_digest="b" * 64,
        evidence_refs=("scratchpad/blocker_adjudication.json",),
        independently_validated=True,
        validated_by=BlockerAuthority.INDEPENDENT_ADJUDICATOR,
    )
    blocked = evaluate_obligation(policy, work, adjudicated)
    assert blocked.decision is Decision.BLOCKED_UNPROVEN
    assert blocked.proof_scope is ProofScope.UNPROVEN


@pytest.mark.parametrize(
    "result", (AttemptResult.COMPILE_FAILED, AttemptResult.RUN_FAILED)
)
def test_compile_and_run_failures_are_attempts_but_never_proof(result):
    """Coverage of an attempt must not be confused with mechanism/harm proof."""

    policy = _policy(AuditMode.THOROUGH)
    work = VerificationWorkItem(
        finding_id="ROW-FAILURE",
        constituent_id="root",
        severity=Severity.HIGH,
        claim_class=ClaimClass.PROPERTY,
        locally_testable=True,
        harness_available=True,
    )
    obligation = evaluate_obligation(policy, work)
    receipt = make_execution_receipt(
        policy,
        work,
        obligation,
        attempt_number=1,
        command_argv=("generic-runner", "test"),
        runner_id="generic-runner",
        result=result,
        proof_scope=ProofScope.UNPROVEN,
        output_digest="c" * 64,
    )
    assert receipt.attempted
    assert receipt.proof_scope is ProofScope.UNPROVEN

    with pytest.raises(ValueError, match="compile/run failure"):
        make_execution_receipt(
            policy,
            work,
            obligation,
            attempt_number=1,
            command_argv=("generic-runner", "test"),
            runner_id="generic-runner",
            result=result,
            proof_scope=ProofScope.HARM,
            output_digest="d" * 64,
        )


def test_fuzz_policy_remains_independent_and_thorough_medium_plus_only():
    """P0-AH broadens attempts, not the distinct fuzz-neighbourhood mandate."""

    for mode in AuditMode:
        policy = _policy(mode)
        for severity in Severity:
            assert policy.requires_fuzz(severity) is (
                mode is AuditMode.THOROUGH and severity in MEDIUM_PLUS
            )

    for function_name in (
        "_poc_contract_required",
        "_validate_poc_contract_for_rows",
        "_validate_poc_attempt_coverage",
    ):
        source = _function_source(V, function_name)
        assert "requires_fuzz" not in source
        assert "fuzz_severities" not in source


def test_hard_and_soft_validators_delegate_to_one_policy_authority():
    """Source guard against reintroducing three drifting severity filters."""

    required = _function_source(V, "_poc_contract_required")
    hard = _function_source(V, "_validate_poc_contract_for_rows")
    soft = _function_source(V, "_validate_poc_attempt_coverage")

    assert "execution_policy" in required
    assert "evaluate_obligation" in required

    assert "execution_policy" in hard
    assert re.search(
        r"_poc_contract_required\s*\([^)]*execution_policy\s*=\s*execution_policy",
        hard,
        re.DOTALL,
    )
    assert not re.search(r'if\s+mode_l\s*==\s*["\']light["\']\s*:', hard)
    assert not re.search(
        r'normalize_severity\([^\n]+\)\s+not\s+in\s+\{["\']Critical["\']',
        hard,
    )

    assert "execution_policy" in soft
    assert (
        "_poc_contract_required" in soft
        or "evaluate_obligation" in soft
        or ".requires_attempt(" in soft
    )
    assert not re.search(r'if\s+mode\s*==\s*["\']light["\']\s*:', soft)
    assert not re.search(
        r'if\s+mode\s*==\s*["\']core["\']\s+and\s+severity\s+not\s+in',
        soft,
    )

    # The compatibility branch may call a legacy helper, but the live policy
    # branch itself cannot retain the old all-mode Medium+ terminal return.
    assert not re.search(
        r'return\s+sev\s+in\s+\{["\']Critical["\']\s*,\s*["\']High["\']\s*,\s*["\']Medium["\']\s*\}',
        required,
    )


def test_every_production_validation_call_passes_the_shared_policy():
    """No resume, rc-parity, aggregate, or existing-artifact path may regress."""

    driver_path = SCRIPTS_DIR / "plamen_driver.py"
    validators_path = SCRIPTS_DIR / "plamen_validators.py"

    driver_verify_calls = _all_named_calls(driver_path, "_validate_verify_completion")
    assert driver_verify_calls
    assert all(
        "execution_policy" in _keyword_names(call) for call in driver_verify_calls
    ), "every live driver verify-completion call must pass execution_policy"

    soft_calls = _all_named_calls(driver_path, "_validate_poc_attempt_coverage")
    assert soft_calls
    assert all("execution_policy" in _keyword_names(call) for call in soft_calls)

    internal_verify_calls = _all_named_calls(
        validators_path, "_validate_verify_completion"
    )
    assert internal_verify_calls
    assert all(
        "execution_policy" in _keyword_names(call) for call in internal_verify_calls
    ), "rc-parity and other validator-internal production paths must pass policy"

    hard_calls = _all_named_calls(validators_path, "_validate_poc_contract_for_rows")
    assert hard_calls
    assert all("execution_policy" in _keyword_names(call) for call in hard_calls)

    driver_source = driver_path.read_text(encoding="utf-8")
    assert "resolve_execution_policy(" in driver_source
