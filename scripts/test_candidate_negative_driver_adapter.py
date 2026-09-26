"""Driver transaction coverage for the typed attention-negative adapter."""
from __future__ import annotations

from pathlib import Path

from artifact_ledger import read_artifact_ledger
import candidate_negative_authority
from candidate_negative_driver_adapter import (
    ATTENTION_INPUTS,
    ATTENTION_OUTPUT,
    bind_exact_prepublication_candidate_negative_gate,
    compile_prepublication_candidate_negative_gate,
    run_attention_candidate_negative_adapter,
    staged_exact_prepublication_candidate_negative_validator,
    staged_prepublication_candidate_negative_validator,
)
from test_candidate_negative_attention_adapter_p1_f import _typed_authorities


def test_attention_adapter_binds_only_final_typed_authorities_and_replays(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    for name, raw in zip(ATTENTION_INPUTS, _typed_authorities(), strict=True):
        (scratch / name).write_bytes(raw)
    (scratch / "attention_repair_summary.md").write_text(
        "untrusted summary prose\n", encoding="utf-8"
    )
    dimensions = {
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": "claude",
    }
    kwargs = {
        "run_id": "run-attention-adapter",
        "dimensions": dimensions,
    }
    assert run_attention_candidate_negative_adapter(
        scratch, tmp_path, **kwargs
    ) == []
    first = (scratch / ATTENTION_OUTPUT).read_bytes()
    assert run_attention_candidate_negative_adapter(
        scratch, tmp_path, **kwargs
    ) == []
    assert (scratch / ATTENTION_OUTPUT).read_bytes() == first

    key = (
        "sc/thorough/evm/claude/candidate_negative_authority/"
        "harvest.attention_repair"
    )
    unit = read_artifact_ledger(scratch)["work_units"][key]
    assert (unit["semantic_status"], unit["execution_state"]) == (
        "ACTIVE",
        "OUTPUT_COMMITTED",
    )
    assert set(unit["input_bindings"]) == {
        f"scratchpad:{name}" for name in ATTENTION_INPUTS
    }
    assert "scratchpad:attention_repair_summary.md" not in unit["input_bindings"]


def test_attention_adapter_replay_rejects_typed_input_drift(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    for name, raw in zip(ATTENTION_INPUTS, _typed_authorities(), strict=True):
        (scratch / name).write_bytes(raw)
    kwargs = {
        "run_id": "run-attention-adapter",
        "dimensions": {
            "pipeline": "sc",
            "mode": "thorough",
            "ecosystem": "evm",
            "backend": "claude",
        },
    }
    assert run_attention_candidate_negative_adapter(
        scratch, tmp_path, **kwargs
    ) == []
    target = scratch / ATTENTION_INPUTS[-1]
    target.write_bytes(target.read_bytes() + b"foreign\n")
    issues = run_attention_candidate_negative_adapter(
        scratch, tmp_path, **kwargs
    )
    assert issues
    assert any(
        token in issues[0].lower()
        for token in ("projection mismatch", "input", "authority json is invalid")
    )


def _prepublication_context(*, phase: str, output: str) -> dict[str, object]:
    return compile_prepublication_candidate_negative_gate(
        b"# Exact finding-output methodology\n",
        f"scratchpad:{output}",
        f"{phase.upper()}_PRODUCER",
        phase=phase,
        invocation_id=f"{phase}-attempt-1",
    )


def test_rescan_prepublication_accepts_exact_id_not_applicable_proposal_without_mutation(
    tmp_path: Path,
) -> None:
    output = "analysis_percontract_factory.md"
    canonical = tmp_path / output
    canonical.write_bytes(b"canonical prior bytes\n")
    staged = (
        "### Finding [PC5-1]: interface-only administration\n"
        "**Verdict**: NOT_APPLICABLE_PROPOSAL\n"
        "**Evidence**: contracts/interfaces/IFactory.sol:L16\n"
    ).encode()

    issues = staged_prepublication_candidate_negative_validator(
        {f"scratchpad:{output}": staged},
        _prepublication_context(phase="rescan", output=output),
    )

    assert issues == ()
    assert canonical.read_bytes() == b"canonical prior bytes\n"


def test_breadth_prepublication_publishes_derived_id_as_visible_debt(
    tmp_path: Path,
) -> None:
    """A derived identity is transport debt, not a staged rejection.

    Property `format.explicit_candidate_id_binding` (DEBT).  The candidate
    stays visible: the ledger records DERIVED_SOURCE_ITEM_ID and INPUT_DEBT so
    an independent consumer must reopen it.  Denying the artifact instead
    deleted EVERY other candidate the same worker found -- which is the exact
    removal-from-attention the closed identity family exists to prevent.
    """

    output = "analysis_access_control.md"
    canonical = tmp_path / output
    canonical.write_bytes(b"canonical prior bytes\n")
    staged = (
        "### Candidate without a stable identifier\n"
        "**Verdict**: REFUTATION_PROPOSAL\n"
        "**Evidence**: contracts/Vault.sol:L20\n"
    ).encode()

    issues = staged_prepublication_candidate_negative_validator(
        {f"scratchpad:{output}": staged},
        _prepublication_context(phase="breadth", output=output),
    )

    assert issues == ()
    ledger = candidate_negative_authority._build_candidate_negative_ledger_from_bytes(
        phase="breadth",
        artifacts=(
            candidate_negative_authority.ArtifactInput(
                relative_path=f"scratchpad:{output}",
                content=staged,
                producer_identity="WORKER",
                producer_invocation_id="i" * 32,
            ),
        ),
        methodology_bytes=b"# Exact finding-output methodology\n",
        methodology_identity=candidate_negative_authority._STAGED_METHODOLOGY_IDENTITY,
    )
    assert ledger["status"] == "INPUT_DEBT"
    assert ledger["events"][0]["identity_state"] == "DERIVED"
    assert canonical.read_bytes() == b"canonical prior bytes\n"


def test_breadth_rescan_gate_accepts_explicit_reviewable_proposal() -> None:
    output = "analysis_rescan_1.md"
    staged = (
        "### Finding [RS-1]: bounded candidate\n"
        "**Verdict**: REFUTATION_PROPOSAL\n"
        "**Evidence**: contracts/Vault.sol:L20\n"
    ).encode()
    identity = f"scratchpad:{output}"

    assert staged_prepublication_candidate_negative_validator(
        {identity: staged},
        _prepublication_context(phase="rescan", output=output),
    ) == ()


def test_prepublication_gate_rejects_depth_or_resigned_phase() -> None:
    import pytest

    with pytest.raises(ValueError, match="breadth or rescan"):
        _prepublication_context(phase="depth", output="depth_findings.md")

    context = _prepublication_context(
        phase="breadth", output="analysis_access_control.md"
    )
    context["phase"] = "depth"
    assert staged_prepublication_candidate_negative_validator(
        {"scratchpad:analysis_access_control.md": b"# No candidates\n"},
        context,
    ) == (
        "prepublication candidate-negative context is not breadth/rescan",
    )


def test_exact_prepublication_gate_runs_exact_and_semantic_checks(
    monkeypatch,
) -> None:
    output = "analysis_rescan_1.md"
    identity = f"scratchpad:{output}"
    semantic = _prepublication_context(phase="rescan", output=output)
    combined = bind_exact_prepublication_candidate_negative_gate(
        semantic, {"sealed": "exact-write-context"}
    )
    monkeypatch.setattr(
        "candidate_negative_driver_adapter."
        "claude_phase_tool_policy.staged_exact_output_receipt_validator",
        lambda outputs, context: (
            ()
            if set(outputs) == {identity}
            and context == {"sealed": "exact-write-context"}
            else ("exact gate failed",)
        ),
    )
    # A legacy terminal `N/A` on a real candidate is visible debt, not a
    # rejection (property `format.nonterminal_enum_spelling`).  The EXACT gate
    # it is bound to is the part that still denies.
    lenient = (
        "### Finding [RS-2]: live candidate\n"
        "**Verdict**: N/A\n"
    ).encode()

    assert staged_exact_prepublication_candidate_negative_validator(
        {identity: lenient}, combined
    ) == ()
    assert staged_exact_prepublication_candidate_negative_validator(
        {"scratchpad:other.md": lenient}, combined
    ) != ()


def test_bounded_rescan_repair_uses_same_gate_and_publishes_both() -> None:
    output = "analysis_methodology_repair_rescan.md"
    identity = f"scratchpad:{output}"
    context = compile_prepublication_candidate_negative_gate(
        b"# Exact finding-output methodology\n",
        identity,
        "METHODOLOGY_REPAIR",
        phase="rescan",
        invocation_id="rescan-repair-attempt-1",
    )
    invalid = (
        "### Candidate without a stable identifier\n"
        "**Verdict**: REFUTATION_PROPOSAL\n"
    ).encode()
    corrected = (
        "### Finding [RSR-1]: repaired candidate disposition\n"
        "**Verdict**: REFUTATION_PROPOSAL\n"
    ).encode()

    # Both publish; the difference is visible ledger debt, not a discarded
    # repair attempt.
    assert staged_prepublication_candidate_negative_validator(
        {identity: invalid}, context
    ) == ()
    assert staged_prepublication_candidate_negative_validator(
        {identity: corrected}, context
    ) == ()
