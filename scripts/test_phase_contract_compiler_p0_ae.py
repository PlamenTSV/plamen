from __future__ import annotations

import json

import pytest

from phase_contract_compiler import (
    PromptContractError,
    compile_phase_io_prompt,
    extract_compiled_phase_io,
    validate_compiled_phase_io,
)
from phase_io_contracts import resolve_phase_io_contract


def _contract(phase="chain_iter2", unit="model", **kwargs):
    return resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase=phase,
        work_unit_id=unit,
        **kwargs,
    )


def test_compiler_emits_one_compact_digest_bound_authority_block():
    contract = _contract()
    compiled = compile_phase_io_prompt(
        "Read `chain_hypotheses.md`.\nWrite `chain_iteration2.md`.",
        contract,
        actor="MODEL",
    )
    payload = extract_compiled_phase_io(compiled)

    assert compiled.count("PLAMEN_PHASE_IO_CONTRACT_BEGIN") == 1
    assert payload["contract_digest"] == contract.digest
    assert payload["work_unit_key"] == contract.key
    assert payload["allowed_outputs"] == ["scratchpad:chain_iteration2.md"]
    assert "scratchpad:chain_hypotheses.md" in payload["immutable_inputs"]
    assert validate_compiled_phase_io(compiled, contract, actor="MODEL") == []


@pytest.mark.parametrize("verb", ["Write", "update", "append to", "modify"])
def test_compiler_rejects_positive_mutation_of_immutable_input(verb: str):
    contract = _contract()
    with pytest.raises(PromptContractError, match="immutable input"):
        compile_phase_io_prompt(
            f"{verb} `chain_hypotheses.md` with the new chain.",
            contract,
            actor="MODEL",
        )


def test_negative_and_read_only_instructions_do_not_false_fire():
    contract = _contract()
    prompt = (
        "Read `chain_hypotheses.md` as an immutable input.\n"
        "Do not modify `composition_coverage.md`.\n"
        "Write only `chain_iteration2.md`."
    )
    compiled = compile_phase_io_prompt(prompt, contract, actor="MODEL")
    assert validate_compiled_phase_io(compiled, contract, actor="MODEL") == []


def test_relation_lookup_does_not_misclassify_writer_language_as_map_mutation():
    """Agent 2 consumes the map; ``write`` describes a finding relation."""
    contract = _contract(phase="chain_agent2", unit="model")
    prompt = (
        "Use `variable_finding_map.md` to find ALL findings that write to "
        "the SAME variable."
    )

    compiled = compile_phase_io_prompt(prompt, contract, actor="MODEL")

    assert validate_compiled_phase_io(compiled, contract, actor="MODEL") == []
    assert "scratchpad:variable_finding_map.md" in extract_compiled_phase_io(
        compiled
    )["immutable_inputs"]


def test_compiler_rejects_path_led_passive_mutation_of_immutable_input():
    contract = _contract()
    with pytest.raises(PromptContractError, match="immutable input"):
        compile_phase_io_prompt(
            "`chain_hypotheses.md` must be updated with the new chain.",
            contract,
            actor="MODEL",
        )


@pytest.mark.parametrize(
    "prompt",
    [
        "Write `confidence_scores.md` with the final scores.",
        "`confidence_scores.md` must be updated with the final scores.",
        "Create {SCRATCHPAD}/confidence_scores.md and stop.",
        "If `confidence_scores.md` is missing, write it before returning.",
        "`confidence_scores.md` is a stub; replace it with final scores.",
    ],
)
def test_compiler_rejects_mutation_of_foreign_actor_output(prompt: str):
    contract = _contract(
        phase="depth",
        unit="confidence_consensus",
        exact_inputs=("depth_token_flow_findings.md",),
    )

    with pytest.raises(PromptContractError, match="DRIVER-owned output"):
        compile_phase_io_prompt(prompt, contract, actor="MODEL")


def test_foreign_output_read_and_explicit_nonmutation_do_not_false_fire():
    contract = _contract(
        phase="depth",
        unit="confidence_consensus",
        exact_inputs=("depth_token_flow_findings.md",),
    )
    prompt = (
        "Read `confidence_scores.md` only after the driver publishes it.\n"
        "Do not modify `confidence_scores.md`."
    )

    compiled = compile_phase_io_prompt(prompt, contract, actor="MODEL")

    assert validate_compiled_phase_io(compiled, contract, actor="MODEL") == []


def test_mixed_scope_line_keeps_output_permission_and_input_prohibition_distinct():
    contract = _contract()
    prompt = (
        "Write ONLY to `chain_iteration2.md`. MUST NOT modify "
        "`chain_hypotheses.md` or `composition_coverage.md`."
    )
    compiled = compile_phase_io_prompt(prompt, contract, actor="MODEL")
    assert validate_compiled_phase_io(compiled, contract, actor="MODEL") == []


def test_tampered_output_or_digest_is_detected():
    contract = _contract()
    compiled = compile_phase_io_prompt("Analyze the bounded packet.", contract, actor="MODEL")
    tampered = compiled.replace(
        "scratchpad:chain_iteration2.md", "scratchpad:chain_hypotheses.md"
    )
    issues = validate_compiled_phase_io(tampered, contract, actor="MODEL")
    assert "compiled allowed_outputs mismatch" in issues


def test_dynamic_worker_exact_output_not_a_glob():
    contract = _contract(
        phase="depth",
        unit="worker.token_flow",
        exact_outputs=("depth_token_flow_findings.md",),
    )
    compiled = compile_phase_io_prompt("Write the assigned output.", contract, actor="MODEL")
    payload = extract_compiled_phase_io(compiled)
    assert payload["allowed_outputs"] == [
        "scratchpad:depth_token_flow_findings.md"
    ]
    assert not any("*" in path for path in payload["allowed_outputs"])


def test_compiled_json_round_trips_without_markdown_regex_parsing():
    contract = _contract()
    compiled = compile_phase_io_prompt("Perform analysis.", contract, actor="MODEL")
    payload = extract_compiled_phase_io(compiled)
    assert json.loads(json.dumps(payload, sort_keys=True)) == payload
