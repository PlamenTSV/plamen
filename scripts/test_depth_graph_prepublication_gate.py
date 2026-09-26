from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import plamen_driver as D  # noqa: E402


def _write_graph_inputs(root: Path) -> None:
    for name in D._DEPTH_GRAPH_CONSUMPTION_INPUTS:
        (root / name).write_text(
            f"# {name}\n\n| Symbol | Evidence |\n|---|---|\n"
            f"| fixture | src/Vault.sol:L10 |\n",
            encoding="utf-8",
        )


def _consumed_markers() -> bytes:
    return ("\n".join(
        f"[GRAPH-ARTIFACT: CONSUMED:{name}]"
        for name in D._DEPTH_GRAPH_CONSUMPTION_INPUTS
    ) + "\n").encode("utf-8")


def test_thorough_standard_leaf_binds_fixed_graph_denominator_and_rejects_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_graph_inputs(tmp_path)
    monkeypatch.setattr(
        D, "_depth_candidate_negative_gate_required", lambda _job: False
    )
    context, staged_inputs = D._compile_depth_worker_staged_gate_context(
        job={
            "output": "depth_external_findings.md",
            "agent_id": "depth-external",
            "role": "external",
            "category": "standard",
        },
        scratchpad=tmp_path,
        config={
            "pipeline": "sc",
            "mode": "thorough",
            "_run_id": "graph-gate-test",
        },
        registered_inputs=D._DEPTH_GRAPH_CONSUMPTION_INPUTS,
        attempt=1,
    )

    expected_inputs = tuple(
        f"scratchpad:{name}" for name in D._DEPTH_GRAPH_CONSUMPTION_INPUTS
    )
    assert staged_inputs == expected_inputs
    assert context["schema_version"] == D._DEPTH_STAGED_GRAPH_GATE_CONTEXT_SCHEMA
    profiles = context["graph_consumption_gate"]["profiles"]
    assert [profile["identity"] for profile in profiles] == list(expected_inputs)
    assert [profile["sha256"] for profile in profiles] == [
        hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        for name in D._DEPTH_GRAPH_CONSUMPTION_INPUTS
    ]

    identity = "scratchpad:depth_external_findings.md"
    assert D._staged_depth_composite_receipt_validator(
        {identity: _consumed_markers()}, context
    ) == ()

    missing = _consumed_markers().replace(
        b"[GRAPH-ARTIFACT: CONSUMED:callee_map.md]\n", b""
    )
    issues = D._staged_depth_composite_receipt_validator(
        {identity: missing}, context
    )
    assert len(issues) == 1
    assert "does not acknowledge graph projection(s): callee_map.md" in issues[0]

    # Restating a marker (e.g. quoting the receipt in a trace row) does not
    # falsify consumption: the property is "acknowledged", not "counted".
    duplicate = _consumed_markers() + (
        b"[GRAPH-ARTIFACT: CONSUMED:caller_map.md]\n"
    )
    assert D._staged_depth_composite_receipt_validator(
        {identity: duplicate}, context
    ) == ()

    # A marker that exists only inside a code fence proves nothing.
    fenced = b"```\n" + _consumed_markers() + b"```\n"
    issues = D._staged_depth_composite_receipt_validator(
        {identity: fenced}, context
    )
    assert len(issues) == 1
    assert "does not acknowledge graph projection(s)" in issues[0]

    # Claiming UNAVAILABLE for a POPULATED projection is a false claim.
    false_claim = _consumed_markers().replace(
        b"[GRAPH-ARTIFACT: CONSUMED:callee_map.md]",
        b"[GRAPH-ARTIFACT: UNAVAILABLE:callee_map.md]",
    )
    issues = D._staged_depth_composite_receipt_validator(
        {identity: false_claim}, context
    )
    assert len(issues) == 1
    assert "claims UNAVAILABLE for populated" in issues[0]


def test_unavailable_projection_may_be_acknowledged_as_unavailable() -> None:
    """The driver publishes an empty projection with `> **Status**: UNAVAILABLE`
    and the depth prompt tells the worker to say so; the gate must accept it."""

    unavailable = b"# state_write_map\n\n> **Status**: UNAVAILABLE\n"
    populated = b"# caller_map\n\n| from | to |\n|---|---|\n| a | b |\n"
    assert D._depth_graph_projection_is_populated(unavailable) is False
    assert D._depth_graph_projection_is_populated(populated) is True
    # an empty table is not content either
    assert D._depth_graph_projection_is_populated(
        b"# caller_map\n\n| from | to |\n|---|---|\n"
    ) is False


def test_fenced_and_commented_markers_are_stripped_before_matching() -> None:
    text = (
        "prose [GRAPH-ARTIFACT: CONSUMED:caller_map.md]\n"
        "```\n[GRAPH-ARTIFACT: CONSUMED:callee_map.md]\n```\n"
        "<!-- [GRAPH-ARTIFACT: CONSUMED:state_write_map.md] -->\n"
    )
    prose = D._depth_graph_acknowledgement_text(text)
    assert "CONSUMED:caller_map.md" in prose
    assert "CONSUMED:callee_map.md" not in prose
    assert "CONSUMED:state_write_map.md" not in prose


def test_non_thorough_or_nonstandard_leaf_has_no_graph_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_graph_inputs(tmp_path)
    monkeypatch.setattr(
        D, "_depth_candidate_negative_gate_required", lambda _job: False
    )
    for mode, category in (("core", "standard"), ("thorough", "scanner")):
        context, staged_inputs = D._compile_depth_worker_staged_gate_context(
            job={
                "output": f"depth_{category}_findings.md",
                "agent_id": f"depth-{category}",
                "role": "external",
                "category": category,
            },
            scratchpad=tmp_path,
            config={"pipeline": "sc", "mode": mode, "_run_id": "test"},
            registered_inputs=D._DEPTH_GRAPH_CONSUMPTION_INPUTS,
            attempt=1,
        )
        assert context["schema_version"] == D._DEPTH_STAGED_GATE_CONTEXT_SCHEMA
        assert "graph_consumption_gate" not in context
        assert staged_inputs == ()


def test_standard_sc_prompt_contains_literal_exact_markers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plamen = tmp_path / "plamen"
    (plamen / "rules").mkdir(parents=True)
    (plamen / "agents").mkdir()
    (plamen / "prompts" / "evm").mkdir(parents=True)
    for path in (
        plamen / "rules" / "finding-output-format.md",
        plamen / "rules" / "phase4-confidence-scoring.md",
        plamen / "agents" / "depth-external.md",
        plamen / "prompts" / "evm" / "phase4b-depth-templates.md",
    ):
        path.write_text("# Fixture\n", encoding="utf-8")
    monkeypatch.setattr(D, "plamen_home", lambda: plamen)
    monkeypatch.setattr(
        D,
        "_typed_worker_registered_input_paths",
        lambda **_kwargs: D._DEPTH_GRAPH_CONSUMPTION_INPUTS,
    )
    monkeypatch.setattr(
        D, "_standard_depth_template_projection", lambda *_a, **_k: "fixture"
    )
    monkeypatch.setattr(
        D, "_compile_typed_worker_prompt", lambda prompt, **_k: prompt
    )

    prompt = D._build_depth_worker_prompt(
        job={
            "output": "depth_external_findings.md",
            "agent_id": "depth-external",
            "role": "external",
            "category": "standard",
            "focus": "external interactions",
        },
        scratchpad=tmp_path,
        project_root=str(tmp_path / "project"),
        config={"pipeline": "sc", "language": "evm", "mode": "thorough"},
        attempt=1,
        methodology_descriptors=[],
    )

    assert "## Exact Graph Artifact Consumption (MANDATORY)" in prompt
    for name in D._DEPTH_GRAPH_CONSUMPTION_INPUTS:
        assert prompt.count(f"[GRAPH-ARTIFACT: CONSUMED:{name}]") == 1
        assert f"{tmp_path.as_posix()}/{name}" in prompt
