"""RED fixtures for mutable-stage authority and safe canonical retry.

The canonical report-index successor must derive only from the exact PhaseIO
input receipt.  Its staging directory is an execution cache, never an
authority source: changing a copied input, adding an undeclared semantic file,
or changing an intermediate output outside the deterministic transform must
not become an ACTIVE DRIVER commit.

If the final expected-output comparison quarantines an attempt while its
registered predecessor and independently sealed target remain available, the
transaction must also be safely and autonomously retryable.  The arbitrary
third state itself is never retained as authority.

Production code is intentionally not patched by this module.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

# Initialize the known lazy-import cycle in its supported standalone order.
import plamen_mechanical as _mechanical  # noqa: F401
import plamen_driver as D
from artifact_ledger import read_artifact_ledger
import test_report_index_canonical_staging_adversarial_red as RED
import test_report_index_canonical_successor_a0_blocking as A0


def _staged_target(root: Path, contract) -> Path:
    return (
        D._report_index_canonical_recovery_dir(root, contract)
        / "staged_target"
    )


def test_staged_config_mutation_after_arm_cannot_change_policy(
    tmp_path: Path,
) -> None:
    """A copied policy file must remain bound through every staged read."""

    config = A0._config(tmp_path)
    root = Path(config["scratchpad"])
    phase = A0._phase()
    live_policy = {
        "cli_backend": "codex",
        "proven_only": True,
        "severity_authority_cutover": False,
    }
    (root / "config.json").write_text(
        json.dumps(live_policy, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    A0._prepare_model_attempt(
        config,
        A0._report_index_bytes(medium_summary=1, medium_master=2),
    )
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    mutated = False

    def mutate_staged_policy(point: str) -> None:
        nonlocal mutated
        if point != "after_canonical_arm" or mutated:
            return
        mutated = True
        staged_policy = _staged_target(root, contract) / "config.json"
        staged_policy.write_text(
            json.dumps(
                {
                    **live_policy,
                    "proven_only": False,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    issues = D._run_report_index_canonicalization_transaction(
        phase,
        root,
        config,
        fault_inject=mutate_staged_policy,
    )

    assert mutated
    assert issues, (
        "a staged config differing from its armed input binding changed the "
        "canonical severity policy"
    )
    RED._assert_not_active_canonical(root, contract)
    assert json.loads((root / "config.json").read_text(encoding="utf-8")) == (
        live_policy
    )


def test_staged_owned_verifier_mutation_after_arm_is_rejected(
    tmp_path: Path,
) -> None:
    """Producer authority binds exact verifier bytes, not only the live path."""

    config = A0._config(tmp_path)
    root = Path(config["scratchpad"])
    phase = A0._phase()
    RED._prepare_typed_verifier_attempt(config)
    RED._commit_owned_verifier(root, config)
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    verifier_identity = "scratchpad:verify_H-1.md"
    assert verifier_identity in contract.immutable_inputs
    mutated = False

    def mutate_staged_verifier(point: str) -> None:
        nonlocal mutated
        if point != "after_canonical_arm" or mutated:
            return
        mutated = True
        verifier = _staged_target(root, contract) / "verify_H-1.md"
        verifier.write_text(
            "# Verification H-1\n\n"
            "**Verdict**: CONFIRMED\n\n"
            "**Severity**: Medium\n\n"
            "**Evidence Tag**: [CODE-TRACE]\n\n"
            + ("semantically-equivalent-staged-verifier-byte-substitution " * 12)
            + "\n",
            encoding="utf-8",
        )

    issues = D._run_report_index_canonicalization_transaction(
        phase,
        root,
        config,
        fault_inject=mutate_staged_verifier,
    )

    assert mutated
    assert issues, (
        "producer-owned verifier bytes were mutable after the staged binding "
        "comparison"
    )
    RED._assert_not_active_canonical(root, contract)


@pytest.mark.parametrize(
    "fault_point",
    (
        "after_optional_reset",
        "after_dropout_projection",
        "after_status_projection",
        "after_severity_projection",
    ),
)
def test_inter_transform_report_mutation_cannot_enter_output_seal(
    tmp_path: Path,
    fault_point: str,
) -> None:
    """Every inter-transform boundary rejects non-derivation report bytes."""

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
    marker = f"UNAUTHORIZED STAGED MUTATION AT {fault_point}"
    mutated = False

    def mutate_intermediate_report(point: str) -> None:
        nonlocal mutated
        if point != fault_point or mutated:
            return
        mutated = True
        report = _staged_target(root, contract) / "report_index.md"
        report.write_bytes(
            report.read_bytes() + f"\n{marker}\n".encode("utf-8")
        )

    issues = D._run_report_index_canonicalization_transaction(
        phase,
        root,
        config,
        fault_inject=mutate_intermediate_report,
    )

    assert mutated
    assert issues, (
        f"arbitrary report bytes injected at {fault_point} became part of the "
        "sealed canonical target"
    )
    RED._assert_not_active_canonical(root, contract)
    assert marker not in (root / "report_index.md").read_text(
        encoding="utf-8"
    )


def test_undeclared_staged_semantic_file_injection_is_rejected(
    tmp_path: Path,
) -> None:
    """A stage directory scan cannot expand the armed input denominator."""

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
    injected_name = "verify_H-999.md"
    assert f"scratchpad:{injected_name}" not in contract.immutable_inputs
    injected = False

    def inject_undeclared_verifier(point: str) -> None:
        nonlocal injected
        if point != "after_canonical_arm" or injected:
            return
        injected = True
        (_staged_target(root, contract) / injected_name).write_text(
            "# Verification H-999\n\n"
            "**Verdict**: CONFIRMED\n\n"
            "**Severity**: Critical\n\n"
            "**Evidence Tag**: [EXECUTED-POC]\n\n"
            + ("undeclared-staged-semantic-authority " * 12)
            + "\n",
            encoding="utf-8",
        )

    issues = D._run_report_index_canonicalization_transaction(
        phase,
        root,
        config,
        fault_inject=inject_undeclared_verifier,
    )

    assert injected
    assert issues, (
        "an undeclared staged verifier expanded the armed semantic input "
        "denominator"
    )
    RED._assert_not_active_canonical(root, contract)


def test_expected_output_quarantine_retries_from_valid_bound_predecessor(
    tmp_path: Path,
) -> None:
    """A rejected final third state must not permanently poison exact replay."""

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
    marker = b"\nUNAUTHORIZED FINAL COMMIT DRIFT\n"
    mutated = False

    def mutate_before_commit(point: str) -> None:
        nonlocal mutated
        if point != "before_canonical_commit" or mutated:
            return
        mutated = True
        report = root / "report_index.md"
        report.write_bytes(report.read_bytes() + marker)

    first_issues = D._run_report_index_canonicalization_transaction(
        phase,
        root,
        config,
        fault_inject=mutate_before_commit,
    )

    assert mutated
    assert first_issues
    first_unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert first_unit["semantic_status"] == "QUARANTINED"
    assert first_unit["execution_state"] == "OUTPUT_QUARANTINED"
    for identity in (
        "scratchpad:report_index.md",
        "scratchpad:report_coverage.md",
    ):
        assert first_unit["output_prestates"][identity]["status"] == (
            "ACTIVE_REGISTERED_PREDECESSOR"
        )

    staged = _staged_target(root, contract)
    sealed_target = {
        item.path: (staged / item.path).read_bytes()
        for item in contract.outputs
    }

    retry_issues = D._run_report_index_canonicalization_transaction(
        phase,
        root,
        config,
    )

    assert retry_issues == [], (
        "a safely rejected expected-output mismatch could not autonomously "
        f"resume from its still-valid bound predecessor: {retry_issues}"
    )
    final_unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert final_unit["semantic_status"] == "ACTIVE"
    assert final_unit["execution_state"] == "OUTPUT_COMMITTED"
    assert {
        item.path: (root / item.path).read_bytes()
        for item in contract.outputs
    } == sealed_target
    assert marker not in (root / "report_index.md").read_bytes()
