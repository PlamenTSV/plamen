"""Fixture-first live wiring contract for the typed severity authority.

AG-1 remains shadow-only until these producer and commit-order boundaries hold
for both pipelines and both supported orchestration backends.
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import plamen_driver as D
import plamen_validators as V
from plamen_prompt import build_phase_prompt
from plamen_types import L1_PHASES, SC_PHASES, plamen_home
from severity_decision_ledger import compile_severity_prompt_contract


@pytest.mark.parametrize(
    ("pipeline", "language", "phase_name", "command_name"),
    (
        ("sc", "evm", "sc_verify_crithigh", "plamen.md"),
        ("l1", "rust", "verify_crithigh", "plamen-l1.md"),
    ),
)
@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_verify_shard_compiles_exact_severity_schema(
    tmp_path: Path,
    pipeline: str,
    language: str,
    phase_name: str,
    command_name: str,
    backend: str,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phases = SC_PHASES if pipeline == "sc" else L1_PHASES
    phase = next(item for item in phases if item.name == phase_name)
    prompt = build_phase_prompt(
        plamen_home() / "commands" / command_name,
        phase,
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
    contract = compile_severity_prompt_contract()
    assert contract["markdown"] in prompt
    assert "SEVERITY PROPOSAL SIDECAR (MANDATORY)" in prompt
    assert "verify_<finding_id>.severity_proposal.json" in prompt
    assert "driver-owned authority fields" in prompt


def test_live_verifier_commit_validates_content_before_receipt_persistence() -> None:
    prevalidator = getattr(V, "_validate_verifier_outputs_before_receipt", None)
    assert callable(prevalidator), (
        "AG-1 needs a receipt-independent content gate before immutable output "
        "bytes are granted a verifier output receipt"
    )
    source = inspect.getsource(D._run_phase_validators)
    prevalidate_at = source.index("_validate_verifier_outputs_before_receipt(")
    persist_at = source.index("_persist_verifier_output_receipts(")
    completion_at = source.index("_validate_verify_completion(", persist_at)
    assert prevalidate_at < persist_at < completion_at


def test_receipt_prevalidation_is_wired_for_every_sc_and_l1_verify_phase() -> None:
    source = inspect.getsource(D._run_phase_validators)
    assert "phase.name in L1_VERIFY_PHASE_NAMES" in source
    assert "phase.name in SC_VERIFY_PHASE_NAMES" in source
    assert source.count("_validate_verifier_outputs_before_receipt(") == 1
