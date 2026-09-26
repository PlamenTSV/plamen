from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import plamen_driver as D  # noqa: E402


CONSTRAINTS = b"""# Constraint Variables

## Constraint Variables

| Variable | Source Location | Bound / Enforcement | Setter | Status |
|---|---|---|---|---|
| fee | src/Gateway.sol:L10 | none | setFee | UNENFORCED |
| limit | src/Gateway.sol:L11 | checked | setLimit | ENFORCED |
"""

STATE_WRITES = b"""# State Write Map

> **Status**: UNAVAILABLE: mechanical provider emitted no write facts

| State Variable | Written By | Declaration | Confidence |
|---|---|---|---|
| Gateway.fee | UNKNOWN | src/Gateway.sol:L10 | LEXICAL_APPROXIMATE |
"""


def _gate_context(profiles: list[dict[str, object]]) -> dict[str, object]:
    consumption: dict[str, object] = {
        "schema_version": D._DEPTH_BOUND_INPUT_CONSUMPTION_SCHEMA,
        "profiles": profiles,
    }
    consumption["context_digest"] = D._depth_gate_canonical_digest(consumption)
    context: dict[str, object] = {
        "schema_version": D._DEPTH_STAGED_GATE_CONTEXT_SCHEMA,
        "output_identity": "scratchpad:depth_state_trace_findings.md",
        "exact_gate": None,
        "security_obligation_gate": None,
        "candidate_negative_gate": None,
        "bound_input_consumption_gate": consumption,
    }
    context["context_digest"] = D._depth_gate_canonical_digest(context)
    return context


def _receipt(profile: dict[str, object]) -> str:
    return "<!-- PLAMEN_BOUND_INPUT_CONSUMPTION: " + json.dumps(
        profile, sort_keys=False, separators=(",", ":")
    ) + " -->"


def test_profiles_are_content_derived_and_staged_validation_is_fail_closed() -> None:
    profiles = [
        D._depth_bound_input_consumption_profile(
            CONSTRAINTS, "scratchpad:constraint_variables.md"
        ),
        D._depth_bound_input_consumption_profile(
            STATE_WRITES, "scratchpad:state_write_map.md"
        ),
    ]
    assert profiles[0]["table_row_count"] == 2
    assert profiles[0]["table_rows_sha256"] != profiles[0]["sha256"]
    assert profiles[0]["status_profile"] == "ROW_STATUS:ENFORCED,UNENFORCED"
    assert profiles[1]["table_row_count"] == 1
    assert profiles[1]["status_profile"] == "UNAVAILABLE"

    context = _gate_context(profiles)
    identity = "scratchpad:depth_state_trace_findings.md"
    valid = ("\n".join(_receipt(profile) for profile in profiles) + "\n").encode()
    assert D._staged_depth_composite_receipt_validator(
        {identity: valid}, context
    ) == ()

    bad = [dict(profile) for profile in profiles]
    bad[1]["status_profile"] = "POPULATED"
    issues = D._staged_depth_composite_receipt_validator(
        {identity: ("\n".join(_receipt(row) for row in bad) + "\n").encode()},
        context,
    )
    assert any("content-inaccurate" in issue for issue in issues)

    missing = D._staged_depth_composite_receipt_validator(
        {identity: (_receipt(profiles[0]) + "\n").encode()}, context
    )
    assert any("absent" in issue for issue in missing)


def test_compile_binds_both_required_inputs_to_validator_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "constraint_variables.md").write_bytes(CONSTRAINTS)
    (tmp_path / "state_write_map.md").write_bytes(STATE_WRITES)
    monkeypatch.setattr(D, "_depth_candidate_negative_gate_required", lambda _job: False)

    context, identities = D._compile_depth_worker_staged_gate_context(
        job={
            "output": "depth_state_trace_findings.md",
            "agent_id": "depth-state-trace",
            "role": "state_trace",
            "category": "standard",
        },
        scratchpad=tmp_path,
        config={"pipeline": "sc", "_run_id": "run18-test"},
        registered_inputs=("constraint_variables.md", "state_write_map.md"),
        attempt=1,
    )

    assert identities == (
        "scratchpad:constraint_variables.md",
        "scratchpad:state_write_map.md",
    )
    assert context["bound_input_consumption_gate"]["profiles"][0][
        "status_profile"
    ] == "ROW_STATUS:ENFORCED,UNENFORCED"


def test_compile_rejects_missing_required_state_trace_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "constraint_variables.md").write_bytes(CONSTRAINTS)
    monkeypatch.setattr(D, "_depth_candidate_negative_gate_required", lambda _job: False)

    with pytest.raises(ValueError, match="state_write_map.md"):
        D._compile_depth_worker_staged_gate_context(
            job={
                "output": "depth_state_trace_findings.md",
                "agent_id": "depth-state-trace",
                "role": "state_trace",
                "category": "standard",
            },
            scratchpad=tmp_path,
            config={"pipeline": "sc", "_run_id": "run18-test"},
            registered_inputs=("constraint_variables.md",),
            attempt=1,
        )


def test_state_trace_prompt_requires_content_accurate_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plamen = tmp_path / "plamen"
    (plamen / "rules").mkdir(parents=True)
    (plamen / "agents").mkdir()
    (plamen / "prompts" / "evm").mkdir(parents=True)
    for path in (
        plamen / "rules" / "finding-output-format.md",
        plamen / "rules" / "phase4-confidence-scoring.md",
        plamen / "agents" / "depth-state-trace.md",
        plamen / "prompts" / "evm" / "phase4b-depth-templates.md",
    ):
        path.write_text("# Fixture\n", encoding="utf-8")
    monkeypatch.setattr(D, "plamen_home", lambda: plamen)
    monkeypatch.setattr(
        D,
        "_typed_worker_registered_input_paths",
        lambda **_kwargs: ["constraint_variables.md", "state_write_map.md"],
    )
    monkeypatch.setattr(D, "_standard_depth_template_projection", lambda *_a, **_k: "fixture")
    monkeypatch.setattr(D, "_compile_typed_worker_prompt", lambda prompt, **_k: prompt)
    (tmp_path / "constraint_variables.md").write_bytes(CONSTRAINTS)
    (tmp_path / "state_write_map.md").write_bytes(STATE_WRITES)

    prompt = D._build_depth_worker_prompt(
        job={
            "output": "depth_state_trace_findings.md",
            "agent_id": "depth-state-trace",
            "role": "state_trace",
            "category": "standard",
            "focus": "state mutation",
        },
        scratchpad=tmp_path,
        project_root=str(tmp_path / "project"),
        config={"pipeline": "sc", "language": "evm", "mode": "thorough"},
        attempt=1,
        methodology_descriptors=[],
    )

    assert "Bound State-Input Consumption Receipts (MANDATORY)" in prompt
    assert "PLAMEN_BOUND_INPUT_CONSUMPTION" in prompt
    assert "table_row_count" in prompt
    assert "table_rows_sha256" in prompt
    assert "driver-precomputed lines byte-for-byte" in prompt
    assert "rejects copied route metadata" in prompt
