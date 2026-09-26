"""A phase's write directive must name only the artifacts the MODEL writes.

`Phase.expected_artifacts` is the DISK-GATE denominator: for several phases it
includes files the DRIVER derives from the model's output (for example the
deduped inventory).  Rendering that list into "Write exactly these expected
artifacts: `a.md, b.md`" told the worker to write outside its own output
authority, and the pre-launch consistency checker denied the launch for it --
so the phase never ran at all.

Two independent defects had to hold for that to happen, and both are pinned
here: the directive named a driver-written artifact, and the checker read the
whole backticked list as ONE path token that could never resolve.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import claude_worker_prompt_consistency as C  # noqa: E402
import plamen_prompt as P  # noqa: E402
from phase_io_contracts import resolve_phase_io_contract  # noqa: E402
from plamen_types import Phase  # noqa: E402

_CONFIG = {
    "pipeline": "sc",
    "mode": "thorough",
    "language": "evm",
    "cli_backend": "claude",
}


def _phase(name: str, artifacts: list[str]) -> Phase:
    return Phase(name, ["Section"], artifacts, base_timeout_s=60, min_artifact_bytes=1)


def _contract_outputs(phase: str, unit: str) -> tuple[list[str], list[str]]:
    contract = resolve_phase_io_contract(
        pipeline="sc", mode="thorough", ecosystem="evm", backend="claude",
        phase=phase, work_unit_id=unit, exact_inputs=(),
    )
    model, driver = [], []
    for spec in contract.outputs:
        name = str(spec.path).rsplit("/", 1)[-1]
        (model if str(spec.writer).upper() == "MODEL" else driver).append(name)
    return model, driver


@pytest.mark.parametrize("phase_name", sorted(P._TYPED_MODEL_WRITE_UNITS))
def test_write_directive_names_only_model_written_outputs(phase_name: str) -> None:
    unit = P._TYPED_MODEL_WRITE_UNITS[phase_name]
    try:
        model, driver = _contract_outputs(phase_name, unit)
    except Exception as exc:  # pragma: no cover - contract absent in this build
        pytest.skip(f"no resolvable contract for {phase_name}: {exc}")
    if not model:
        pytest.skip(f"{phase_name} has no MODEL-written output")
    phase = _phase(phase_name, sorted(set(model) | set(driver)))

    named, not_to_write = P._model_and_driver_expected_artifacts(phase, dict(_CONFIG))

    assert set(named) == set(model)
    assert set(not_to_write) == set(driver)
    # never widen beyond the phase's own gate denominator
    assert set(named) <= set(phase.expected_artifacts)


def test_untyped_phase_keeps_its_historical_directive() -> None:
    phase = _phase("breadth", ["analysis_a.md"])
    assert P._model_and_driver_expected_artifacts(phase, dict(_CONFIG)) == ((), ())


def test_backticked_artifact_list_tokenizes_per_element() -> None:
    line = (
        "Write exactly these expected artifacts: "
        "`hypotheses.md, finding_mapping.md, enabler_results.md`."
    )
    assert C._path_tokens(line) == (
        "hypotheses.md", "finding_mapping.md", "enabler_results.md",
    )


@pytest.mark.parametrize(
    "span",
    [
        "a b.md, c.md",          # a filename containing a space is not a list
        "see notes.md, then go", # prose residue between the tokens
        "only_one.md",           # a single token is not a list
    ],
)
def test_non_list_spans_stay_one_token(span: str) -> None:
    assert C._list_span_members(span) == ()


def test_every_element_of_a_write_list_must_be_registered() -> None:
    """Control: splitting the list does not weaken write authority."""
    prompt = "Write exactly these expected artifacts: `assigned_findings.md, bogus.md`.\n"
    issues = C.validate_claude_worker_prompt_consistency(
        prompt,
        phase_io_inputs=("scratchpad:recon_summary.md",),
        phase_io_outputs=("scratchpad:assigned_findings.md",),
        policy_tools=("Edit", "Glob", "Grep", "Read", "Write"),
        safe_search_roots=(),
        project_root="/audit/p",
        scratchpad_root="/audit/p/.scratchpad",
    )
    subjects = {issue.subject for issue in issues if issue.code == "UNREGISTERED_OUTPUT_WRITE"}
    assert subjects == {"bogus.md"}
