"""The invariants prompt templates must read only what their PhaseIO contract registers.

DODO run46 (2026-09-20 04:04): the restricted Claude prompt/PhaseIO consistency
check denied BOTH semantic-invariant passes before the model ran --
`UNREGISTERED_ARTIFACT_READ` for `function_list.md` (Pass 1: mandated by the
template, not registered by the contract) and for `semantic_invariants.md`
(Pass 2: the template said to read the live file while the contract registers
the driver's byte snapshot and keeps the live file as the append target).  Both
passes degraded to fallbacks, so Thorough's semantic-invariant analysis silently
never ran on this backend.  This test renders each template and validates it
against its own contract, so the two owners cannot drift apart again.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import claude_worker_prompt_consistency as C  # noqa: E402
from phase_io_contracts import resolve_phase_io_contract  # noqa: E402

_ROOT = _SCRIPTS.parent
PROJECT = "/audit/protocol"
SCRATCHPAD = PROJECT + "/.scratchpad"
BASE = {"pipeline": "sc", "mode": "thorough", "ecosystem": "evm", "backend": "claude-pty"}


def _render(template: Path) -> str:
    text = template.read_text("utf-8")
    text = text.replace("{SCRATCHPAD}", SCRATCHPAD).replace("{PROJECT_ROOT}", PROJECT)
    # Any other placeholder is prose-level; neutralise the braces so the checker
    # sees a token, not a format field.
    return re.sub(r"\{([A-Z_]+)\}", r"\1", text)


def _unregistered_reads(template: Path, phase: str, work_unit_id: str) -> list[tuple[str, str]]:
    contract = resolve_phase_io_contract(**BASE, phase=phase, work_unit_id=work_unit_id)
    inputs = tuple(contract.immutable_inputs) + tuple(contract.bounded_lookup_inputs)
    outputs = tuple(row.identity for row in contract.outputs)
    issues = C.validate_claude_worker_prompt_consistency(
        _render(template),
        phase_io_inputs=inputs,
        phase_io_outputs=outputs,
        policy_tools=("Edit", "Glob", "Grep", "Read", "Write"),
        safe_search_roots=(PROJECT + "/contracts", PROJECT + "/src"),
        project_root=PROJECT,
        scratchpad_root=SCRATCHPAD,
    )
    return [(i.code, i.subject) for i in issues if i.code == "UNREGISTERED_ARTIFACT_READ"]


@pytest.mark.parametrize("template,phase,work_unit_id", [
    ("prompts/shared/v2/phase4a5-invariants.md", "invariants", "worker.semantic_invariants"),
    ("prompts/shared/v2/phase4a5-invariants-p2.md", "invariants_p2", "worker.semantic_invariants_pass2"),
])
def test_invariants_templates_read_only_registered_inputs(template, phase, work_unit_id) -> None:
    assert _unregistered_reads(_ROOT / template, phase, work_unit_id) == []


def test_pass1_contract_registers_function_list() -> None:
    contract = resolve_phase_io_contract(**BASE, phase="invariants", work_unit_id="worker.semantic_invariants")
    assert "scratchpad:function_list.md" in set(contract.immutable_inputs)
