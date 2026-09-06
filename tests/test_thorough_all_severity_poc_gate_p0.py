"""Focused regression for the Thorough all-severity PoC contract.

These tests use generic finding identities and never inspect audit findings.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(REPO_ROOT))

import plamen_validators as validators  # noqa: E402
from verification_policy import (  # noqa: E402
    AuditMode,
    Backend,
    BlockerAuthority,
    BlockerCode,
    ClaimClass,
    Ecosystem,
    ExecutionBlocker,
    Pipeline,
    Platform,
    Severity,
    resolve_execution_policy,
)


def _policy(mode: AuditMode):
    return resolve_execution_policy(
        mode,
        Backend.CLAUDE,
        Pipeline.SC,
        Ecosystem.EVM,
        Platform.WINDOWS,
    )


def _row(fid: str, severity: Severity, claim_class: ClaimClass) -> dict[str, str]:
    return {
        "finding id": fid,
        "severity": severity.value.title(),
        "poc class": claim_class.value,
    }


def _write_build_status(scratchpad: Path, succeeded: bool) -> None:
    status = "SUCCESS" if succeeded else "FAILED"
    (scratchpad / "build_status.md").write_text(
        f"# Build Status\n\nStatus: {status}\n",
        encoding="utf-8",
    )


def _write_verify(
    scratchpad: Path,
    fid: str,
    claim_class: ClaimClass,
    *,
    attempted: str | None,
    blocker_code: str = "N/A",
    concrete_execution: bool = False,
) -> None:
    attempted_line = "" if attempted is None else f"- Attempted: {attempted}\n"
    test_file = "tests/generic_poc.ext" if concrete_execution else "N/A"
    command = "generic-test-runner generic_poc" if concrete_execution else "N/A"
    compiled = "YES" if concrete_execution else "N/A"
    result = "PASS" if concrete_execution else "NOT_EXECUTED"
    (scratchpad / f"verify_{fid}.md").write_text(
        "**Verdict**: CONTESTED\n"
        "**Severity**: Low\n"
        "**Preferred Tag**: [CODE-TRACE]\n"
        "### PoC Attempt\n"
        f"- PoC Class: {claim_class.value}\n"
        f"{attempted_line}"
        f"- PoC Not Attempted Because: {blocker_code}\n"
        f"- Test File: {test_file}\n"
        f"- Command: {command}\n"
        "### Execution Result\n"
        f"- Compiled: {compiled}\n"
        f"- Result: {result}\n"
        "- Evidence Tag: [CODE-TRACE]\n",
        encoding="utf-8",
    )


def _typed_blocker(
    code: BlockerCode,
    *,
    independently_validated: bool,
) -> ExecutionBlocker:
    return ExecutionBlocker(
        code=code,
        authority=BlockerAuthority.VERIFIER,
        evidence_digest="a" * 64,
        evidence_refs=("evidence/build_failure.receipt.json",),
        independently_validated=independently_validated,
        validated_by=(
            BlockerAuthority.INDEPENDENT_ADJUDICATOR
            if independently_validated
            else None
        ),
    )


@pytest.mark.parametrize("severity", (Severity.LOW, Severity.INFORMATIONAL))
@pytest.mark.parametrize("claim_class", (ClaimClass.UNIT, ClaimClass.PROPERTY))
@pytest.mark.parametrize("attempted", (None, "", "NO"))
def test_thorough_low_info_blank_or_no_attempt_requires_bounded_repair(
    tmp_path: Path,
    severity: Severity,
    claim_class: ClaimClass,
    attempted: str | None,
) -> None:
    fid = f"GEN-{severity.value}-{claim_class.value}-{attempted!s}"
    row = _row(fid, severity, claim_class)
    _write_build_status(tmp_path, succeeded=True)
    _write_verify(tmp_path, fid, claim_class, attempted=attempted)

    issues = validators._validate_poc_contract_for_rows(
        tmp_path,
        [row],
        AuditMode.THOROUGH.value,
        execution_policy=_policy(AuditMode.THOROUGH),
    )

    assert issues == [
        f"{fid} mandatory {claim_class.value} PoC not attempted with valid blocker"
    ]
    assert validators.verify_poc_contract_only_failed_ids(
        ["verify PoC contract: " + issues[0]]
    ) == [fid]


@pytest.mark.parametrize("severity", (Severity.LOW, Severity.INFORMATIONAL))
def test_available_harness_rejects_even_independently_validated_environment_blocker(
    tmp_path: Path,
    severity: Severity,
) -> None:
    fid = f"GEN-HARNESS-{severity.value}"
    row = _row(fid, severity, ClaimClass.PROPERTY)
    _write_build_status(tmp_path, succeeded=True)
    _write_verify(
        tmp_path,
        fid,
        ClaimClass.PROPERTY,
        attempted="NO",
        blocker_code=BlockerCode.NO_BUILD_ENVIRONMENT.value,
    )

    issues = validators._validate_poc_contract_for_rows(
        tmp_path,
        [row],
        AuditMode.THOROUGH.value,
        execution_policy=_policy(AuditMode.THOROUGH),
        execution_blockers={
            fid: _typed_blocker(
                BlockerCode.NO_BUILD_ENVIRONMENT,
                independently_validated=True,
            )
        },
    )

    assert len(issues) == 1
    assert "not attempted" in issues[0]


@pytest.mark.parametrize("severity", (Severity.LOW, Severity.INFORMATIONAL))
def test_thorough_low_info_concrete_attempt_satisfies_gate(
    tmp_path: Path,
    severity: Severity,
) -> None:
    fid = f"GEN-EXECUTED-{severity.value}"
    row = _row(fid, severity, ClaimClass.UNIT)
    _write_build_status(tmp_path, succeeded=True)
    _write_verify(
        tmp_path,
        fid,
        ClaimClass.UNIT,
        attempted="YES",
        concrete_execution=True,
    )

    assert validators._validate_poc_contract_for_rows(
        tmp_path,
        [row],
        AuditMode.THOROUGH.value,
        execution_policy=_policy(AuditMode.THOROUGH),
    ) == []


def test_self_authored_blocker_cannot_waive_thorough_low_attempt() -> None:
    fid = "GEN-INVALID-BLOCKER"
    row = _row(fid, Severity.LOW, ClaimClass.STRUCTURAL)
    blocker = _typed_blocker(
        BlockerCode.STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION,
        independently_validated=False,
    )

    assert validators._poc_contract_required(
        row,
        AuditMode.THOROUGH.value,
        execution_policy=_policy(AuditMode.THOROUGH),
        execution_blocker=blocker,
    )


def test_true_no_harness_with_independent_typed_blocker_remains_unproven_but_valid(
    tmp_path: Path,
) -> None:
    fid = "GEN-NO-HARNESS"
    row = _row(fid, Severity.INFORMATIONAL, ClaimClass.PROPERTY)
    _write_build_status(tmp_path, succeeded=False)
    _write_verify(
        tmp_path,
        fid,
        ClaimClass.PROPERTY,
        attempted="NO",
        blocker_code=BlockerCode.NO_BUILD_ENVIRONMENT.value,
    )

    issues = validators._validate_poc_contract_for_rows(
        tmp_path,
        [row],
        AuditMode.THOROUGH.value,
        execution_policy=_policy(AuditMode.THOROUGH),
        execution_blockers={
            fid: _typed_blocker(
                BlockerCode.NO_BUILD_ENVIRONMENT,
                independently_validated=True,
            )
        },
    )

    assert issues == []
    (tmp_path / "verification_queue.md").write_text(
        "| Finding ID | Severity | PoC Class |\n"
        "|---|---|---|\n"
        f"| {fid} | Informational | property |\n",
        encoding="utf-8",
    )
    assert validators.parse_verification_queue_rows(tmp_path) == [row]
    assert validators._validate_poc_attempt_coverage(
        tmp_path,
        AuditMode.THOROUGH.value,
        execution_policy=_policy(AuditMode.THOROUGH),
        execution_blockers={
            fid: _typed_blocker(
                BlockerCode.NO_BUILD_ENVIRONMENT,
                independently_validated=True,
            )
        },
    ) == []


@pytest.mark.parametrize("mode", (AuditMode.LIGHT, AuditMode.CORE))
def test_low_attempt_remains_optional_in_light_and_core(
    tmp_path: Path,
    mode: AuditMode,
) -> None:
    fid = f"GEN-{mode.value}-LOW"
    row = _row(fid, Severity.LOW, ClaimClass.PROPERTY)
    _write_build_status(tmp_path, succeeded=True)
    _write_verify(tmp_path, fid, ClaimClass.PROPERTY, attempted=None)

    assert validators._validate_poc_contract_for_rows(
        tmp_path,
        [row],
        mode.value,
        execution_policy=_policy(mode),
    ) == []
