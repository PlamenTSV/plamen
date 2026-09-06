"""RED fixtures for P0-I resume recovery and canonical-prior immutability.

These tests start from a genuinely committed, non-empty axis MODEL proposal.
They do not launch Claude, Codex, a subprocess, or an audit.  They pin three
transaction properties that presence-only resume checks cannot establish:

* CLEAR and FINDING proposals finalize and replay identically on both backends;
* a crash after MODEL commit is incomplete, but recovery requires only the
  deterministic finalizer rather than another model execution; and
* the canonical identity authority used as PRE_AXIS evidence is frozen.  A
  post-promotion refresh must not rewrite or reinterpret that preimage.

The production implementation is intentionally not changed by this file.
"""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

import axis_disposition as AXIS
import axis_canonical_prior as AXIS_PRIOR
import plamen_driver as DRIVER
from artifact_ledger import read_artifact_ledger
from plamen_types import SC_PHASES, Phase
from test_axis_population_provider_p0_i import _project, _write_graph


RUN_ID = "4fa571e9-1a2f-471d-8ced-7f2f8dff4583"
_MODEL_OUTPUTS = (
    "axis_coverage_findings.md",
    "axis_coverage_dispositions.json",
)
_TERMINAL_OUTPUTS = (
    "axis_disposition_initial_receipt.json",
    "axis_repair_plan.json",
    "axis_repair_execution_receipt.json",
    "axis_disposition_receipt.json",
    "axis_coverage_promotion_receipt.json",
)
_FROZEN_PRIOR_FILES = (
    AXIS_PRIOR.SNAPSHOT_NAME,
    AXIS_PRIOR.AUTHORITY_NAME,
)
_AXIS_SNAPSHOT_FILES = (
    AXIS_PRIOR.SNAPSHOT_NAME,
    AXIS_PRIOR.AUTHORITY_NAME,
)


def _axis_phase() -> Phase:
    return next(phase for phase in SC_PHASES if phase.name == "axis_coverage")


def _config(project: Path, backend: str) -> dict[str, Any]:
    return {
        "project_root": str(project),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": backend,
        "_run_id": RUN_ID,
    }


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sidecar(
    worklist: Mapping[str, Any],
    rows: list[dict[str, Any]],
) -> bytes:
    unsigned = {
        "schema_version": AXIS.MODEL_DISPOSITIONS_SCHEMA,
        "run_id": RUN_ID,
        "worklist_hash": worklist["worklist_hash"],
        "producer": "MODEL",
        "items": rows,
    }
    return _canonical(
        {
            **unsigned,
            "sidecar_digest": _sha(_canonical(unsigned)),
        }
    )


def _source_clear(item: Mapping[str, Any]) -> dict[str, str]:
    return {
        "kind": "SOURCE_LOCUS",
        "source_relpath": str(item["source_relpath"]),
        "source_locus": str(item["source_locus"]),
        "source_hash": str(item["source_hash"]),
    }


def _finding_block(item: Mapping[str, Any]) -> str:
    return (
        f"### Finding [{item['required_action_id']}]: axis fixture candidate\n"
        f"**Work Item ID**: {item['work_item_id']}\n"
        "**Severity**: Low\n"
        f"**Location**: {item['source_locus']}\n"
        "**Description**: exact typed candidate requiring verification\n"
        "**Impact**: independent verification determines material harm\n"
    )


def _snapshot_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _resume_issues(
    *,
    project: Path,
    scratchpad: Path,
    backend: str,
) -> list[str]:
    return DRIVER._axis_disposition_resume_issues(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        language="evm",
        backend=backend,
        run_id=RUN_ID,
    )


def _harvest_negative(
    *,
    phase: Phase,
    config: dict[str, Any],
    scratchpad: Path,
) -> None:
    issues = DRIVER._harvest_axis_clear_candidate_negative(
        phase, config, scratchpad
    )
    assert issues == [], (
        "axis candidate-negative adapter did not complete: "
        + "; ".join(issues)
    )


def _forbid_model_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> list[str]:
    calls: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> int:
        calls.append("model")
        raise AssertionError(
            "a committed axis MODEL proposal must recover without model execution"
        )

    monkeypatch.setattr(DRIVER, "_run_one_codex_exec", forbidden)
    monkeypatch.setattr(
        DRIVER, "_run_one_claude_headless_breadth_worker", forbidden
    )
    return calls


def _committed_model_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    backend: str,
    disposition: str,
) -> tuple[
    Path,
    Path,
    Phase,
    dict[str, Any],
    dict[str, Any],
    dict[str, bytes],
    str,
]:
    """Commit strict MODEL bytes while retaining a frozen PRE_AXIS authority."""

    project, scratchpad = _project(tmp_path / backend / disposition.lower())
    _write_graph(
        scratchpad,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": ["caller-a", "caller-b"],
            }
        },
    )
    # Give the prior authority a real pre-axis identity and make the model
    # contract's inventory input explicit.
    (scratchpad / "findings_inventory.md").write_bytes(
        (
            "### Finding [INV-001]: pre-axis fixture finding\n"
            "**Severity**: Low\n"
            "**Location**: contracts/Unit.sol:L2\n"
            "**Description**: pre-existing candidate\n"
            "**Impact**: bounded fixture impact\n"
        ).encode("utf-8")
    )
    phase = _axis_phase()
    config = _config(project, backend)
    worklist, planning_issues = DRIVER._prepare_axis_disposition_worklist(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert planning_issues == [], (
        "fixture planning must be green before testing recovery: "
        + "; ".join(planning_issues)
    )
    assert worklist["count"] > 0
    assert worklist["requires_execution"] is True

    frozen = AXIS_PRIOR.load_axis_canonical_prior_authority(
        scratchpad,
        expected_run_id=RUN_ID,
        expected_worklist_hash=str(worklist["worklist_hash"]),
        expected_pipeline="sc",
        expected_mode="thorough",
        expected_ecosystem="evm",
    )
    frozen_files = {
        name: (scratchpad / name).read_bytes()
        for name in _FROZEN_PRIOR_FILES
    }
    frozen_digest = str(frozen.authority_digest)
    assert frozen_digest == AXIS_PRIOR.load_axis_canonical_prior_authority(
        scratchpad,
        expected_run_id=RUN_ID,
        expected_worklist_hash=str(worklist["worklist_hash"]),
        expected_pipeline="sc",
        expected_mode="thorough",
        expected_ecosystem="evm",
    ).authority_digest

    bind_issues = DRIVER._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    )
    assert bind_issues == [], (
        "fixture MODEL denominator must bind before outputs: "
        + "; ".join(bind_issues)
    )

    rows: list[dict[str, Any]] = []
    blocks: list[str] = []
    for item in worklist["items"]:
        if disposition == "CLEAR":
            rows.append(
                {
                    "work_item_id": item["work_item_id"],
                    "disposition": "CLEAR",
                    "action_id": "",
                    "evidence": [_source_clear(item)],
                    "rationale": "the exact bound source locus closes this cell",
                }
            )
        elif disposition == "FINDING":
            rows.append(
                {
                    "work_item_id": item["work_item_id"],
                    "disposition": "FINDING",
                    "action_id": item["required_action_id"],
                    "evidence": [],
                    "rationale": "candidate requires independent verification",
                }
            )
            blocks.append(_finding_block(item))
        else:
            raise AssertionError(f"unsupported fixture disposition: {disposition}")

    (scratchpad / "axis_coverage_findings.md").write_bytes(
        ("\n\n".join(blocks) + ("\n" if blocks else "")).encode("utf-8")
    )
    (scratchpad / "axis_coverage_dispositions.json").write_bytes(
        _sidecar(worklist, rows)
    )
    # Tool-policy coverage is orthogonal to this crash/recovery fixture.  The
    # exact MODEL PhaseIO prebind and artifact commit remain real.
    monkeypatch.setattr(
        DRIVER,
        "_validate_claude_phase_tool_boundary_outputs",
        lambda *_args, **_kwargs: [],
    )
    commit_issues = DRIVER._record_typed_model_phase_artifacts(
        phase, scratchpad, config
    )
    assert commit_issues == [], (
        "fixture MODEL commit must be green before simulating a crash: "
        + "; ".join(commit_issues)
    )
    model_contract, _launch = DRIVER._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )
    assert model_contract is not None
    ledger = read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][model_contract.key]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert all((scratchpad / name).is_file() for name in _MODEL_OUTPUTS)
    assert not any(
        (scratchpad / name).exists() for name in _TERMINAL_OUTPUTS
    )
    return (
        project,
        scratchpad,
        phase,
        config,
        dict(worklist),
        frozen_files,
        frozen_digest,
    )


@pytest.mark.parametrize("backend", ("claude", "codex"))
@pytest.mark.parametrize("disposition", ("CLEAR", "FINDING"))
def test_nonempty_finalize_and_resume_preserve_exact_authority_on_both_backends(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    disposition: str,
) -> None:
    (
        project,
        scratchpad,
        phase,
        config,
        _worklist,
        _frozen_files,
        frozen_digest,
    ) = _committed_model_fixture(
        tmp_path,
        monkeypatch,
        backend=backend,
        disposition=disposition,
    )
    model_calls = _forbid_model_execution(monkeypatch)

    application, finalization_issues = (
        DRIVER._finalize_axis_coverage_boundary(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
        )
    )

    assert finalization_issues == [], (
        f"{backend} {disposition} deterministic finalization failed: "
        + "; ".join(finalization_issues)
    )
    assert application["application_record_complete"] is True
    assert model_calls == []
    _harvest_negative(
        phase=phase, config=config, scratchpad=scratchpad
    )
    resume = _resume_issues(
        project=project,
        scratchpad=scratchpad,
        backend=backend,
    )
    assert resume == [], (
        f"{backend} {disposition} finalized authority is not resumable: "
        + "; ".join(resume)
    )
    assert application["canonical_prior_authority_digest"] == frozen_digest


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_crash_after_model_commit_requires_finalizer_not_model_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    (
        project,
        scratchpad,
        phase,
        config,
        _worklist,
        _frozen_files,
        _frozen_digest,
    ) = _committed_model_fixture(
        tmp_path,
        monkeypatch,
        backend=backend,
        disposition="CLEAR",
    )
    model_calls = _forbid_model_execution(monkeypatch)
    before_probe = _snapshot_files(scratchpad)

    resume = DRIVER._phase_content_gate_issues(
        phase, config, scratchpad, str(project)
    )

    assert resume, (
        "MODEL commit without deterministic descendants must never be a clean "
        "resume skip"
    )
    assert any(
        "axis finalizer required" in issue.casefold() for issue in resume
    ), (
        "resume debt must identify deterministic finalizer recovery, not "
        "silently rewind or ambiguously classify the committed MODEL output: "
        + "; ".join(resume)
    )
    assert _snapshot_files(scratchpad) == before_probe, (
        "the resume probe must be side-effect-free"
    )
    assert model_calls == []

    application, recovery_issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert recovery_issues == []
    assert application["application_record_complete"] is True
    assert model_calls == []
    _harvest_negative(
        phase=phase, config=config, scratchpad=scratchpad
    )
    assert _resume_issues(
        project=project,
        scratchpad=scratchpad,
        backend=backend,
    ) == []


def test_checkpoint_resume_uses_semantic_dispatch_not_base_artifact_gate() -> None:
    """The live startup reconciler must reach the P0-I successor authority."""

    source = inspect.getsource(
        DRIVER._reconcile_completed_checkpoint_artifacts
    )
    assert "_resume_semantic_issues(" in source
    assert "_resume_phase_contract_issues(" not in source


def test_pre_axis_canonical_authority_is_immutable_after_finding_promotion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        _project_root,
        scratchpad,
        phase,
        config,
        worklist,
        frozen_files,
        frozen_digest,
    ) = _committed_model_fixture(
        tmp_path,
        monkeypatch,
        backend="claude",
        disposition="FINDING",
    )
    _forbid_model_execution(monkeypatch)
    original_promote = DRIVER._promote_axis_disposition_actions
    observed_before_promotion: dict[str, bytes] = {}

    def capture_then_promote(*args: object, **kwargs: object) -> object:
        observed_before_promotion.update(
            {
                name: (scratchpad / name).read_bytes()
                for name in _FROZEN_PRIOR_FILES
            }
        )
        return original_promote(*args, **kwargs)

    monkeypatch.setattr(
        DRIVER, "_promote_axis_disposition_actions", capture_then_promote
    )
    application, issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )

    assert issues == []
    _harvest_negative(
        phase=phase, config=config, scratchpad=scratchpad
    )
    assert observed_before_promotion == frozen_files, (
        "base reconciliation changed the frozen PRE_AXIS canonical authority"
    )
    assert {
        name: (scratchpad / name).read_bytes()
        for name in _FROZEN_PRIOR_FILES
    } == frozen_files, (
        "post-promotion refresh rewrote the PRE_AXIS evidence preimage; any "
        "current/post-axis projection must use a distinct authority artifact"
    )
    assert application["canonical_prior_authority_digest"] == frozen_digest
    frozen_text = frozen_files[AXIS_PRIOR.SNAPSHOT_NAME].decode(
        "utf-8", errors="strict"
    )
    assert all(
        str(item["required_action_id"]) not in frozen_text
        for item in worklist["items"]
    ), "an axis proposal must not become its own canonical-prior evidence"
    inventory = (scratchpad / "findings_inventory.md").read_text(
        encoding="utf-8", errors="strict"
    )
    assert all(
        f"AXISGAP:{item['required_action_id']}" in inventory
        for item in worklist["items"]
    ), "the immutability fixture did not actually exercise promotion"


def test_later_global_identity_refresh_cannot_reinterpret_axis_prior(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Axis replay consumes its immutable snapshot, not the global live map."""

    (
        project,
        scratchpad,
        phase,
        config,
        _worklist,
        _frozen_files,
        _frozen_digest,
    ) = _committed_model_fixture(
        tmp_path,
        monkeypatch,
        backend="claude",
        disposition="FINDING",
    )
    _forbid_model_execution(monkeypatch)
    application, issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert issues == []
    assert application["application_record_complete"] is True
    _harvest_negative(
        phase=phase, config=config, scratchpad=scratchpad
    )
    assert all(
        (scratchpad / name).is_file() for name in _AXIS_SNAPSHOT_FILES
    ), "P0-I did not materialize a distinct immutable prior snapshot"
    snapshot_before = {
        name: (scratchpad / name).read_bytes()
        for name in _AXIS_SNAPSHOT_FILES
    }

    # Simulate an accepted later phase refreshing the shared current-state
    # canonical projection after axis promotion.
    DRIVER._write_canonical_finding_identity_map(
        scratchpad,
        phase_name="rag_sweep",
        pipeline="sc",
        mode="thorough",
    )
    DRIVER._atomic_driver_json(
        scratchpad / "exploration_clear_prior_aliases.json",
        DRIVER._exploration_clear_prior_alias_payload(scratchpad),
    )
    assert {
        name: (scratchpad / name).read_bytes()
        for name in _AXIS_SNAPSHOT_FILES
    } == snapshot_before
    assert _resume_issues(
        project=project,
        scratchpad=scratchpad,
        backend="claude",
    ) == []
