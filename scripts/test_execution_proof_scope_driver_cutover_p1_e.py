"""Expected-red P1-E live-consumer cutover specifications.

The pure evidence provider is implemented in ``evidence_capabilities.py``.
These nodes remain red until the occupied driver/validator integration slice
loads a candidate-bound ``verify_<ID>.execution_scope_assessment.json`` and
uses it for positive proof labels and negative severity/disposition authority.
"""

from __future__ import annotations

from pathlib import Path

import plamen_validators as V


def _queue(sp: Path, finding_id: str) -> None:
    (sp / "verification_queue.md").write_text(
        "| Finding ID | Severity | Title | Location | PoC Class |\n"
        "|---|---|---|---|---|\n"
        f"| {finding_id} | High | Candidate | Module.sol:10 | unit |\n",
        encoding="utf-8",
    )


def test_p1e_live_proof_label_rejects_unscoped_bare_fuzzer_tag():
    assert V._effective_tag_is_proof_grade("[FUZZ-PASS]") is False, (
        "execution-tag prose authenticates neither oracle provenance nor harm "
        "scope without a candidate-bound P1-E assessment"
    )


def test_p1e_standalone_generated_poc_fail_without_scope_cannot_demote(
    tmp_path: Path,
):
    finding_id = "H-71"
    _queue(tmp_path, finding_id)
    (tmp_path / f"verify_{finding_id}.md").write_text(
        "**Verdict**: REFUTED\n"
        "**Material Harm**: The claimed state loss did not occur.\n"
        "### PoC Attempt\n"
        "- Attempted: YES\n"
        "### Execution Result\n"
        "- Result: FAIL (generated assertion did not reproduce)\n"
        "- Evidence Tag: [POC-FAIL]\n",
        encoding="utf-8",
    )

    assert not (
        tmp_path / f"verify_{finding_id}.execution_scope_assessment.json"
    ).exists()
    assert V._apply_poc_fail_demotions(tmp_path, "thorough") == [], (
        "a generated assertion's negative execution proves only that encoded "
        "attempt until oracle provenance, environment/preconditions, negative "
        "exhaustiveness, and proof scope are independently bound"
    )
    assert not (tmp_path / "poc_demotions.md").exists()
