from __future__ import annotations

import json
from pathlib import Path

import pytest
import plamen_driver as D
from exploration_clear_lifecycle import compile_initial_receipt, write_lifecycle_artifacts
from plamen_types import Phase


def _phase() -> Phase:
    return Phase(
        "enumgap_exploration",
        ["Phase 4b.7"],
        ["enumgap_exploration_findings.md"],
        base_timeout_s=120,
        modes={"core", "thorough"},
        critical=False,
        model="sonnet",
    )


def _config(project: Path, backend: str = "claude") -> dict:
    return {
        "project_root": str(project),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": backend,
        "_run_id": "22345678-1234-4567-8abc-1234567890ab",
    }


def _seed(project: Path) -> tuple[Path, str]:
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    (project / "src").mkdir()
    (project / "src" / "Unit.sol").write_text("one\ntwo\n", encoding="utf-8")
    (scratch / "_enumeration_obligations.json").write_text(
        json.dumps(
            {
                "source": "graph",
                "obligations": [
                    {
                        "finding_id": "INV-1",
                        "function": "entry",
                        "symbol": "state",
                        "required_corefs": ["paired"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    exploration = scratch / "exploration_skeptic_findings.md"
    exploration.write_text(
        "# Exploration\n\n## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| INV-2 | sibling | alternate | NO-GAP | unsupported wording |\n",
        encoding="utf-8",
    )
    receipt = compile_initial_receipt(
        exploration, production_root=project, canonical_prior_ids={}
    )
    write_lifecycle_artifacts(scratch, receipt)
    return scratch, receipt.obligations[0].obligation_id


def test_planning_union_reconcile_and_resume_bind_exact_artifacts(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, clear_id = _seed(project)
    phase = _phase()
    config = _config(project)
    worklist, prep_issues = D._prepare_enumgap_disposition_worklist(
        phase, config, scratch
    )
    assert prep_issues == []
    assert worklist["count"] == 2
    enum_id = next(
        item["work_item_id"]
        for item in worklist["items"]
        if item["kind"] == "ENUMERATION_COREFERENCE"
    )
    assert D._bind_typed_model_phase_inputs(phase, scratch, config) == []
    (scratch / "enumgap_exploration_findings.md").write_text(
        "# Enumgap\n\n"
        "## Finding [NEXP-1]: candidate\n\n"
        "**Severity**: Low\n\n**Location**: src/Unit.sol:L1\n\n"
        "## Coverage Record\n\n"
        "| Obligation | Relationship | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        f"| {enum_id} | co-reference | FINDING | NEXP-1 |\n"
        f"| {clear_id} | invalid clear | CLEAR | src/Unit.sol:L2 |\n",
        encoding="utf-8",
    )
    assert D._record_typed_model_phase_artifacts(
        phase, scratch, config
    ) == []
    receipt, issues = D._reconcile_enumgap_dispositions(
        phase, config, scratch
    )
    assert issues == []
    assert receipt["status"] == "CLEAN"
    assert D._enumgap_disposition_resume_issues(
        scratch, project, mode="thorough"
    ) == []

    before = {
        name: (scratch / name).read_bytes()
        for name in (
            "enumgap_worklist.json",
            "enumgap_disposition_receipt.json",
            "enumgap_residual_obligations.json",
        )
    }
    _, second_issues = D._reconcile_enumgap_dispositions(
        phase, config, scratch
    )
    assert second_issues == []
    assert all((scratch / name).read_bytes() == value for name, value in before.items())


def test_missing_independent_disposition_is_phase_debt_not_clean(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, _ = _seed(project)
    phase = _phase()
    config = _config(project)
    D._prepare_enumgap_disposition_worklist(phase, config, scratch)
    assert D._bind_typed_model_phase_inputs(phase, scratch, config) == []
    (scratch / "enumgap_exploration_findings.md").write_text(
        "# Enumgap\n\n## Coverage Record\n\n"
        "| Obligation | Relationship | Disposition | Evidence |\n"
        "|---|---|---|---|\n",
        encoding="utf-8",
    )
    assert D._record_typed_model_phase_artifacts(
        phase, scratch, config
    ) == []
    receipt, issues = D._reconcile_enumgap_dispositions(
        phase, config, scratch
    )
    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert receipt["unresolved_work_item_ids"]
    assert any("unresolved enumgap work item" in issue for issue in issues)
    for issue in issues:
        D._append_phase_io_debt(
            scratch, phase.name, "ENUMGAP_RECONCILIATION_DEBT", issue
        )
    checkpoint = D.Checkpoint(run_id=config["_run_id"])
    commit = D._commit_phase_from_disk_debt(
        phase,
        checkpoint,
        scratch,
        config,
        [phase],
        clean_transients=False,
    )
    assert commit.state == "COMPLETED_WITH_DEBT"
    assert "enumgap_exploration" in checkpoint.degraded


def test_valid_empty_union_is_exact_noop(tmp_path: Path) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    (scratch / "_enumeration_obligations.json").write_text(
        json.dumps({"source": "graph", "obligations": []}), encoding="utf-8"
    )
    phase = _phase()
    worklist, issues = D._prepare_enumgap_disposition_worklist(
        phase, _config(project), scratch
    )
    assert issues == []
    assert worklist["requires_execution"] is False
    assert D._enumgap_exploration_has_no_obligations(scratch) is True


def _write_enumgap_output(
    scratch: Path, worklist: dict, *, newline: str = "\n"
) -> None:
    rows = "".join(
        f"| {item['work_item_id']} | {item['relationship']} | CLEAR | "
        "src/Unit.sol:L1 |\n"
        for item in worklist["items"]
    )
    text = (
        "# Enumgap\n\n"
        "## Coverage Record\n\n"
        "| Obligation | Relationship | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        f"{rows}"
    )
    (scratch / "enumgap_exploration_findings.md").write_bytes(
        text.replace("\n", newline).encode("utf-8")
    )


def test_uncommitted_enumgap_model_output_is_proposal_only(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, _ = _seed(project)
    phase = _phase()
    config = _config(project)
    worklist, prep_issues = D._prepare_enumgap_disposition_worklist(
        phase, config, scratch
    )
    assert prep_issues == []
    _write_enumgap_output(scratch, worklist)

    receipt, issues = D._reconcile_enumgap_dispositions(
        phase, config, scratch
    )

    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert any("MODEL producer" in issue for issue in issues)
    state = json.loads(
        (scratch / "_artifact_state.json").read_text(encoding="utf-8")
    )
    key = "sc/thorough/evm/claude/enumgap_disposition/reconcile"
    assert state["work_units"].get(key, {}).get(
        "execution_state"
    ) != "OUTPUT_COMMITTED"


@pytest.mark.parametrize("backend", ("claude", "codex"))
@pytest.mark.parametrize("newline", ("\n", "\r\n"), ids=("lf", "crlf"))
def test_exact_enumgap_model_producer_reconciles_for_both_backends_and_bytes(
    tmp_path: Path, backend: str, newline: str,
) -> None:
    project = tmp_path / backend / newline.encode().hex()
    scratch, _ = _seed(project)
    phase = _phase()
    config = _config(project, backend=backend)
    worklist, prep_issues = D._prepare_enumgap_disposition_worklist(
        phase, config, scratch
    )
    assert prep_issues == []
    assert D._bind_typed_model_phase_inputs(phase, scratch, config) == []
    _write_enumgap_output(scratch, worklist, newline=newline)
    assert D._record_typed_model_phase_artifacts(
        phase, scratch, config
    ) == []

    receipt, issues = D._reconcile_enumgap_dispositions(
        phase, config, scratch
    )
    assert issues == []
    assert receipt["status"] == "CLEAN"
    assert D._enumgap_disposition_resume_issues(
        scratch, project, mode="thorough"
    ) == []

    source = scratch / "enumgap_exploration_findings.md"
    source.write_bytes(source.read_bytes().replace(b"\r\n", b"\n"))
    if newline == "\r\n":
        assert any(
            "digest" in issue.lower() or "producer" in issue.lower()
            for issue in D._enumgap_disposition_resume_issues(
                scratch, project, mode="thorough"
            )
        )


def test_enumgap_planning_derives_only_after_exact_input_prebind(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch, _ = _seed(project)
    source = scratch / "_enumeration_obligations.json"
    original = D.compile_enumgap_worklist

    def derive_then_mutate(root):
        result = original(root)
        payload = json.loads(source.read_text(encoding="utf-8"))
        payload["obligations"].append({
            "finding_id": "INV-99",
            "function": "late",
            "symbol": "late",
            "required_corefs": ["late-peer"],
        })
        source.write_text(json.dumps(payload), encoding="utf-8")
        return result

    monkeypatch.setattr(D, "compile_enumgap_worklist", derive_then_mutate)
    _worklist, issues = D._prepare_enumgap_disposition_worklist(
        _phase(), _config(project), scratch
    )
    assert any("changed after prebind" in issue.lower() for issue in issues)
    state = json.loads(
        (scratch / "_artifact_state.json").read_text(encoding="utf-8")
    )
    key = "sc/thorough/evm/claude/enumgap_disposition/planning"
    assert state["work_units"].get(key, {}).get(
        "execution_state"
    ) != "OUTPUT_COMMITTED"


def test_enumgap_reconcile_rejects_output_mutation_between_derive_and_arm(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch, _ = _seed(project)
    phase = _phase()
    config = _config(project)
    worklist, _ = D._prepare_enumgap_disposition_worklist(
        phase, config, scratch
    )
    assert D._bind_typed_model_phase_inputs(phase, scratch, config) == []
    _write_enumgap_output(scratch, worklist)
    assert D._record_typed_model_phase_artifacts(
        phase, scratch, config
    ) == []
    original = D.reconcile_enumgap_output

    def derive_then_mutate(*args, **kwargs):
        result = original(*args, **kwargs)
        path = scratch / "enumgap_exploration_findings.md"
        path.write_bytes(path.read_bytes() + b"\nlate drift\n")
        return result

    monkeypatch.setattr(D, "reconcile_enumgap_output", derive_then_mutate)
    _receipt, issues = D._reconcile_enumgap_dispositions(
        phase, config, scratch
    )
    assert any("changed after prebind" in issue.lower() for issue in issues)
    state = json.loads(
        (scratch / "_artifact_state.json").read_text(encoding="utf-8")
    )
    key = "sc/thorough/evm/claude/enumgap_disposition/reconcile"
    assert state["work_units"].get(key, {}).get(
        "execution_state"
    ) != "OUTPUT_COMMITTED"


def test_empty_enumgap_stub_is_prebound_driver_output(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    (scratch / "_enumeration_obligations.json").write_text(
        json.dumps({"source": "graph", "obligations": []}), encoding="utf-8"
    )
    phase = _phase()
    config = _config(project)
    worklist, issues = D._prepare_enumgap_disposition_worklist(
        phase, config, scratch
    )
    assert issues == [] and worklist["requires_execution"] is False
    receipt, stub_issues = D._run_enumgap_empty_stub_transaction(
        phase, config, scratch
    )
    assert stub_issues == []
    assert receipt["status"] == "EMPTY"
    state = json.loads(
        (scratch / "_artifact_state.json").read_text(encoding="utf-8")
    )
    key = "sc/thorough/evm/claude/enumgap_exploration/empty_stub"
    assert state["work_units"][key]["execution_state"] == "OUTPUT_COMMITTED"
