from __future__ import annotations

from pathlib import Path
import sys


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import plamen_driver as D  # noqa: E402
import plamen_parsers as P  # noqa: E402
from verification_method_compiler import _render_compiled_prompt  # noqa: E402


def test_queue_primary_artifact_uses_source_action_not_source_ids(
    tmp_path: Path,
) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        """# Finding Inventory

### Finding [INV-001]: Bound evidence
**Severity**: High
**Location**: contracts/Gateway.sol:10
**Preferred Tag**: CODE-TRACE
**Source IDs**: RS2-1, CC-02
**Source Actions**: analysis_rescan_2.md:RS2-1@sha256:"""
        + "a" * 64
        + """
**Root Cause**: distinct state domains
**Description**: a concrete state transition is not bound
**Impact**: protected assets may be spent
""",
        encoding="utf-8",
    )
    rows = P._queue_rows_from_inventory(tmp_path)
    assert len(rows) == 1
    assert rows[0]["primary artifact"] == "analysis_rescan_2.md"
    assert "RS2-1" not in rows[0]["primary artifact"]


def test_queue_explicit_primary_artifact_precedes_source_action(
    tmp_path: Path,
) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        """# Finding Inventory

### Finding [INV-002]: Promoted evidence
**Severity**: Medium
**Location**: contracts/Gateway.sol:20
**Source IDs**: [DA2-DT-1, DT-1]
**Source Actions**: analysis_old.md:DT-1@sha256:"""
        + "b" * 64
        + """
**Primary Artifact**: depth_da_iter2_findings.md
**Root Cause**: promoted state mismatch
**Description**: promoted evidence remains exact
**Impact**: state accounting may drift
""",
        encoding="utf-8",
    )
    rows = P._queue_rows_from_inventory(tmp_path)
    assert rows[0]["primary artifact"] == "depth_da_iter2_findings.md"


def test_dynamic_staged_gate_rejects_model_transaction_as_poc_blocker() -> None:
    work_id = "INV-001"
    markdown = (
        "# Verification\n\n"
        "Severity: High\nEvidence Tag: [CODE-TRACE]\nVerdict: CONTESTED\n"
        "### PoC Attempt\n"
        "- Attempted: NO\n"
        "- PoC Not Attempted Because: NO_BUILD_ENVIRONMENT\n"
        "- Test File: N/A\n- Test Function: N/A\n- Command: N/A\n"
        "### Execution Result\n"
        "- Compiled: NO\n- Result: NOT_EXECUTED\n"
        "- Output: PHASEIO_EXECUTION_NOT_AUTHORIZED\n"
    ).encode()
    outputs = {
        f"scratchpad:verify_{work_id}.md": markdown,
        f"scratchpad:verify_{work_id}.severity_proposal.json": b"{}",
        f"scratchpad:verify_{work_id}.operator_application.json": b"{}",
    }
    issues = D._staged_dynamic_verifier_output_validator(
        outputs,
        {
            "schema": D._DYNAMIC_VERIFIER_STAGED_GATE_SCHEMA,
            "language": "evm",
            "assignments": [{
                "work_item_id": work_id,
                "constituent_ids": [work_id],
                "poc_required": True,
            }],
            "method_dispatch": {},
        },
    )
    joined = "\n".join(issues)
    assert "driver-owned executor is not a blocker" in joined
    assert "lacks concrete Test File/Test Function/Command" in joined


def test_zero_attempt_ledger_annotation_is_semantically_pre_execution() -> None:
    work_id = "INV-001"
    base = (
        "# Verification\n\nSeverity: High\nEvidence Tag: [CODE-TRACE]\n"
        "Verdict: CONTESTED\n### PoC Attempt\n- Attempted: YES\n"
        "- Test File: test/Candidate.t.sol\n"
        "- Test Function: test_candidate\n"
        "- Command: forge test --match-test test_candidate\n"
        "### Execution Result\n- Compiled: {compiled}\n"
        "- Result: NOT_EXECUTED\n"
        "- Output: DRIVER_MECHANICAL_EXECUTION_PENDING\n"
        "### Mechanical PoC Source\n\n```solidity\n"
        "contract Candidate {{ function test_candidate() public {{}} }}\n```\n"
    )
    context = {
        "schema": D._DYNAMIC_VERIFIER_STAGED_GATE_SCHEMA,
        "language": "evm",
        "assignments": [{
            "work_item_id": work_id,
            "constituent_ids": [work_id],
            "poc_required": True,
        }],
        "method_dispatch": {},
    }
    def issues(compiled: str) -> list[str]:
        return D._staged_dynamic_verifier_output_validator(
            {
                f"scratchpad:verify_{work_id}.md": base.format(compiled=compiled).encode(),
                f"scratchpad:verify_{work_id}.severity_proposal.json": b"{}",
                f"scratchpad:verify_{work_id}.operator_application.json": b"{}",
            },
            context,
        )
    ledger_issue = "pre-driver execution ledger must be"
    assert not any(ledger_issue in issue for issue in issues("NO (attempts: 0)"))
    assert any(ledger_issue in issue for issue in issues("NO (attempts: 1)"))


def test_compiled_verifier_prompt_declares_driver_execution_handoff() -> None:
    prompt = _render_compiled_prompt(
        dispatch_id="VMD-" + "A" * 64,
        pipeline="sc",
        ecosystem="evm",
        backend="codex",
        manifest_path="manifest.md",
        scratchpad_path="/tmp/scratch",
        modules=(),
        operators={},
        debt_codes=("CONTEXT_UNRESOLVED",),
        rows=(),
        output_contract={
            "verifier_markdown_fields": ["Severity", "Evidence Tag", "Verdict"]
        },
    )
    assert "Transactional PoC handoff" in prompt
    assert "PHASEIO_EXECUTION_NOT_AUTHORIZED" in prompt
    assert "DRIVER_MECHANICAL_EXECUTION_PENDING" in prompt
    assert '"work_item_id"' in prompt
    assert '"selected_module_hashes"' in prompt
    assert '"operators"' in prompt
    assert "module_bindings" in prompt


def test_dynamic_poc_suffix_names_exact_required_rows() -> None:
    suffix = D._dynamic_verifier_poc_prompt_suffix({
        "assignments": [
            {"work_item_id": "INV-001", "poc_required": True},
            {"work_item_id": "INV-002", "poc_required": False},
            {"work_item_id": "INV-003", "poc_required": True},
        ]
    })
    assert "`INV-001`" in suffix
    assert "`INV-003`" in suffix
    assert "`INV-002`" not in suffix
    assert "integration, or structural" in suffix
