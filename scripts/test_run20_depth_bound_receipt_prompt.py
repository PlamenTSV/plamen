from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import plamen_driver as D  # noqa: E402


CONSTRAINTS = b"""# Constraint Variables

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


def _receipt(profile: dict[str, object]) -> str:
    return "<!-- PLAMEN_BOUND_INPUT_CONSUMPTION: " + json.dumps(
        profile,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ) + " -->"


def _profiles() -> list[dict[str, object]]:
    return [
        D._depth_bound_input_consumption_profile(
            CONSTRAINTS, "scratchpad:constraint_variables.md"
        ),
        D._depth_bound_input_consumption_profile(
            STATE_WRITES, "scratchpad:state_write_map.md"
        ),
    ]


def _render_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    attempt: int,
    retry_reasons: list[str] | None = None,
) -> str:
    plamen = tmp_path / "plamen"
    (plamen / "rules").mkdir(parents=True, exist_ok=True)
    (plamen / "agents").mkdir(exist_ok=True)
    (plamen / "prompts" / "evm").mkdir(parents=True, exist_ok=True)
    for path in (
        plamen / "rules" / "finding-output-format.md",
        plamen / "rules" / "phase4-confidence-scoring.md",
        plamen / "agents" / "depth-state-trace.md",
        plamen / "prompts" / "evm" / "phase4b-depth-templates.md",
    ):
        path.write_text("# Fixture\n", encoding="utf-8")

    (tmp_path / "constraint_variables.md").write_bytes(CONSTRAINTS)
    (tmp_path / "state_write_map.md").write_bytes(STATE_WRITES)
    monkeypatch.setattr(D, "plamen_home", lambda: plamen)
    monkeypatch.setattr(
        D,
        "_typed_worker_registered_input_paths",
        lambda **_kwargs: ("constraint_variables.md", "state_write_map.md"),
    )
    monkeypatch.setattr(
        D, "_standard_depth_template_projection", lambda *_args, **_kwargs: "fixture"
    )
    monkeypatch.setattr(
        D, "_compile_typed_worker_prompt", lambda prompt, **_kwargs: prompt
    )

    return D._build_depth_worker_prompt(
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
        attempt=attempt,
        retry_reasons=retry_reasons,
        methodology_descriptors=[],
    )


def test_run20_status_prose_allows_punctuation_mismatch() -> None:
    """Run20's natural `first word` parse retained punctuation the gate strips."""

    status_line = next(
        line for line in STATE_WRITES.decode("utf-8").splitlines()
        if line.startswith("> **Status**:")
    )
    prose_interpretation = re.match(
        r"^> \*\*Status\*\*:\s*(\S+)", status_line
    )
    assert prose_interpretation is not None
    assert prose_interpretation.group(1).upper() == "UNAVAILABLE:"
    assert _profiles()[1]["status_profile"] == "UNAVAILABLE"
    assert prose_interpretation.group(1).upper() != _profiles()[1]["status_profile"]


def test_state_trace_prompt_embeds_exact_consecutive_driver_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompt = _render_prompt(tmp_path, monkeypatch, attempt=1)
    profiles = _profiles()
    exact_block = "\n".join(_receipt(profile) for profile in profiles)
    expected_payloads = [
        json.dumps(
            profile,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
        for profile in profiles
    ]

    assert exact_block in prompt
    observed_payloads = D._BOUND_INPUT_CONSUMPTION_RE.findall(prompt)
    assert observed_payloads == expected_payloads
    assert [json.loads(encoded) for encoded in observed_payloads] == profiles
    assert profiles[1]["status_profile"] == "UNAVAILABLE"
    assert '"status_profile":"UNAVAILABLE:"' not in exact_block
    assert "<lowercase SHA-256 of exact file bytes>" not in prompt
    assert "<all Markdown data rows across the file>" not in prompt


def test_state_trace_exact_receipts_are_stable_across_retry_prompt_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _render_prompt(tmp_path, monkeypatch, attempt=1)
    second = _render_prompt(
        tmp_path,
        monkeypatch,
        attempt=2,
        retry_reasons=[
            "staged depth required bound-input consumption receipts are "
            "absent, reordered, or content-inaccurate"
        ],
    )

    first_receipts = D._BOUND_INPUT_CONSUMPTION_RE.findall(first)
    second_receipts = D._BOUND_INPUT_CONSUMPTION_RE.findall(second)
    assert first_receipts == second_receipts
    assert first_receipts == [
        json.dumps(
            profile,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
        for profile in _profiles()
    ]
