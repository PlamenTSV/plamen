"""Red P0-AC fixtures for verification transaction completion.

Scope is deliberately limited to verification queue, verifier shard, and
mechanical-verification completion.  Report-index already has a centralized
typed commit and is not tested here.

The required transaction is::

    materialize outputs
      -> validate artifact ledger + queue work plan + receipts
      -> persist any typed debt
      -> delegate to _commit_phase_from_disk_debt / PhaseCommitController
      -> atomically persist typed commit and legacy completion projection

No fast path may call ``Checkpoint.mark_completed`` or clear a debt sentinel
directly.  These fixtures are generic, backend-neutral, and protocol-neutral.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
import re
import sys
import uuid

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(REPO_ROOT))

import plamen_driver as D  # noqa: E402
from plamen_types import Checkpoint, GateFailure, Phase, PhaseCommit  # noqa: E402


PIPELINE_BACKEND_CASES = (
    ("sc", "claude"),
    ("sc", "codex"),
    ("l1", "claude"),
    ("l1", "codex"),
)


def _config(tmp_path: Path, pipeline: str, backend: str) -> dict:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir(parents=True, exist_ok=True)
    return {
        "pipeline": pipeline,
        "mode": "thorough",
        "language": "rust" if pipeline == "l1" else "evm",
        "cli_backend": backend,
        "scratchpad": str(scratchpad),
        "project_root": str(tmp_path),
        "_run_id": str(uuid.uuid4()),
    }


def _phase(pipeline: str, *, kind: str = "shard") -> Phase:
    if kind == "queue":
        name = "verify_queue" if pipeline == "l1" else "sc_verify_queue"
        artifact = "verification_queue.md"
    elif kind == "mechanical":
        name = "mechanical_verify" if pipeline == "l1" else "sc_mechanical_verify"
        artifact = "mechanical_verify_manifest.md"
    else:
        name = "verify_medium_a" if pipeline == "l1" else "sc_verify_medium_a"
        artifact = "verify_ROW-1.md"
    return Phase(
        name,
        ["Verification transaction fixture"],
        [artifact],
        3000,
        min_artifact_bytes=1,
    )


def _seed_phase_artifact(scratchpad: Path, phase: Phase) -> None:
    artifact = phase.expected_artifacts[0]
    assert "*" not in artifact
    (scratchpad / artifact).write_text(
        "# Verification transaction output\n", encoding="utf-8"
    )


def _main_branch(start_marker: str, end_marker: str) -> str:
    source = inspect.getsource(D.main)
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]


def _require_transaction_helper():
    assert hasattr(D, "_commit_verification_transaction"), (
        "live verification paths require one verification-specific precommit "
        "seam that delegates the final state transition"
    )
    helper = D._commit_verification_transaction
    parameters = inspect.signature(helper).parameters
    for name in ("phase", "checkpoint", "scratchpad", "config", "phases"):
        assert name in parameters
    assert "clean_transients" in parameters
    assert parameters["clean_transients"].kind is inspect.Parameter.KEYWORD_ONLY
    return helper


def _require_precommit_validator():
    assert hasattr(D, "_validate_verification_precommit"), (
        "verification completion requires one typed artifact/work-plan/receipt "
        "validator before the centralized phase commit"
    )
    return D._validate_verification_precommit


def _call_transaction(
    helper,
    phase: Phase,
    checkpoint: Checkpoint,
    scratchpad: Path,
    config: dict,
) -> PhaseCommit:
    return helper(
        phase,
        checkpoint,
        scratchpad,
        config,
        [phase],
        clean_transients=True,
    )


def test_verification_helper_validates_then_delegates_without_second_state_machine():
    helper = _require_transaction_helper()
    _require_precommit_validator()
    source = inspect.getsource(helper)

    validate_at = source.index("_validate_verification_precommit(")
    commit_at = source.index("_commit_phase_from_disk_debt(")
    assert validate_at < commit_at
    assert "PhaseCommitController(" not in source, (
        "the verification seam must delegate, not create a second state machine"
    )
    assert "checkpoint.mark_completed(" not in source
    assert "checkpoint.clear_degraded_sentinel(" not in source
    assert "checkpoint.save(" not in source


def test_precommit_denominator_includes_ledger_work_plan_and_receipts():
    validator = _require_precommit_validator()
    source = inspect.getsource(validator)

    assert "read_queue_work_plan" in source
    assert (
        "validate_work_unit_artifacts" in source
        or "_record_typed_verify_queue_routing_artifacts" in source
        or "read_artifact_ledger" in source
    )
    assert re.search(
        r"(?:reconcile_receipts|validate_[A-Za-z0-9_]*receipts|receipt_reconciliation)",
        source,
    ), "execution/non-execution receipt coverage must be validated before commit"

    # Empty partitions are evidence, not absence.  The validator must have an
    # explicit empty-work disposition path rather than skipping validation.
    assert re.search(r"EMPTY(?:_PARTITION|_WORK|_QUEUE|_SHARD)", source)


def test_mechanical_precommit_accepts_explicit_zero_denominator_manifest(
    tmp_path: Path,
):
    config = _config(tmp_path, "sc", "claude")
    scratchpad = Path(config["scratchpad"])
    phase = _phase("sc", kind="mechanical")
    (scratchpad / "mechanical_verify_manifest.md").write_text(
        "# Mechanical Verify Manifest\n\n"
        "**Total verify files**: 0\n\n"
        "| Status | Count |\n|---|---:|\n"
        "| TOOLCHAIN_UNAVAILABLE | 0 |\n| SKIPPED | 0 |\n",
        encoding="utf-8",
    )

    assert D._validate_verification_precommit(
        phase, scratchpad, config, [phase]
    ) == []


def test_mechanical_precommit_retains_nonzero_unavailable_work_as_debt(
    tmp_path: Path,
):
    config = _config(tmp_path, "l1", "codex")
    scratchpad = Path(config["scratchpad"])
    phase = _phase("l1", kind="mechanical")
    (scratchpad / "mechanical_verify_manifest.md").write_text(
        "# Mechanical Verify Manifest\n\n"
        "**Total verify files**: 2\n\n"
        "| Status | Count |\n|---|---:|\n"
        "| TOOLCHAIN_UNAVAILABLE | 2 |\n| SKIPPED | 0 |\n",
        encoding="utf-8",
    )

    issues = D._validate_verification_precommit(
        phase, scratchpad, config, [phase]
    )
    assert any("did not establish execution coverage" in issue for issue in issues)


@pytest.mark.parametrize(
    "start_marker,end_marker,typed_call",
    (
        (
            'if config["pipeline"] == "l1" and phase.name == "verify_queue":',
            "# v2.4.1: SC verify queue",
            "_record_typed_verify_queue_routing_artifacts(",
        ),
        (
            'if config.get("pipeline") != "l1" and phase.name == "sc_verify_queue":',
            "# v2.4.1",
            "_record_typed_verify_queue_routing_artifacts(",
        ),
    ),
)
def test_l1_and_sc_queue_branches_commit_only_after_typed_routing_validation(
    start_marker: str,
    end_marker: str,
    typed_call: str,
):
    branch = _main_branch(start_marker, end_marker)
    typed_at = branch.index(typed_call)
    commit_at = branch.find("_commit_verification_transaction(", typed_at)

    assert commit_at >= 0
    assert typed_at < commit_at
    assert "checkpoint.mark_completed(" not in branch
    assert "checkpoint.clear_degraded_sentinel(" not in branch


def test_mechanical_success_disabled_unavailable_and_failure_share_typed_commit():
    branch = _main_branch(
        'if phase.name in ("sc_mechanical_verify", "mechanical_verify"):',
        "# v2.3.11: report_assemble is Python-native",
    )

    assert "run_phase5b_mechanical_verify(" in branch
    assert "_commit_verification_transaction(" in branch
    assert branch.count("_commit_verification_transaction(") >= 2, (
        "disabled and executed/error terminal paths must both type their commit"
    )
    assert "checkpoint.mark_completed(" not in branch
    assert "checkpoint.clear_degraded_sentinel(" not in branch
    assert "checkpoint.save(" not in branch

    unavailable_at = branch.index('"toolchain_unavailable"')
    commit_after_unavailable = branch.find(
        "_commit_verification_transaction(", unavailable_at
    )
    assert commit_after_unavailable >= 0, (
        "toolchain unavailability must reach a debt-capable typed commit"
    )


@pytest.mark.parametrize(
    "start_marker,end_marker,manifest_call",
    (
        (
            "if phase.name in L1_VERIFY_PHASE_NAMES:",
            "if phase.name in SC_VERIFY_PHASE_NAMES:",
            "ensure_verify_shard_manifests(scratchpad)",
        ),
        (
            "if phase.name in SC_VERIFY_PHASE_NAMES:",
            "if phase.name in _all_verify_aggregate_names:",
            "ensure_sc_verify_shard_manifests(",
        ),
    ),
)
def test_empty_and_existing_verify_shard_fast_paths_use_typed_transaction(
    start_marker: str,
    end_marker: str,
    manifest_call: str,
):
    # Select the occurrences inside the empty-queue/fast-path section, not the
    # earlier validator or queue-construction branches.
    source = inspect.getsource(D.main)
    section_start = source.index("# Empty-queue short-circuit for verification phases")
    start = source.index(start_marker, section_start)
    end = source.index(end_marker, start)
    branch = source[start:end]

    manifest_at = branch.index(manifest_call)
    empty_at = branch.index("if not verify_shards.get(phase.name):", manifest_at)
    validation_at = branch.index("_validate_verify_completion(", empty_at)
    empty_commit_at = branch.find("_commit_verification_transaction(", empty_at)
    existing_commit_at = branch.find(
        "_commit_verification_transaction(", validation_at
    )

    assert empty_commit_at >= 0 and empty_commit_at < validation_at
    assert existing_commit_at >= 0 and validation_at < existing_commit_at
    assert "checkpoint.mark_completed(" not in branch
    assert "checkpoint.clear_degraded_sentinel(" not in branch


def test_empty_queue_fast_path_materializes_before_typed_commit():
    source = inspect.getsource(D.main)
    section_start = source.index("# Empty-queue short-circuit for verification phases")
    queue_start = source.index(
        "if phase.name in _all_verify_queue_names:", section_start
    )
    queue_end = source.index("continue", queue_start) + len("continue")
    branch = source[queue_start:queue_end]

    write_at = branch.index("_write_empty_verification_queue(")
    commit_at = branch.find("_commit_verification_transaction(", write_at)
    assert commit_at >= 0
    assert write_at < commit_at
    assert "checkpoint.mark_completed(" not in branch
    assert "checkpoint.clear_degraded_sentinel(" not in branch


def test_post_execution_verify_success_uses_verification_precommit_after_artifact_recording():
    source = inspect.getsource(D.main)
    start = source.index(
        "for _model_io_issue in _record_typed_model_phase_artifacts("
    )
    end = source.index("# SC report_index: build body-writer manifests", start)
    completion = source[start:end]

    record_at = completion.index("_record_typed_model_phase_artifacts(")
    commit_at = completion.find("_commit_verification_transaction(", record_at)
    assert commit_at >= 0
    assert record_at < commit_at
    assert re.search(
        r"phase\.name\s+in\s+[^\n]*(?:VERIFY|verify)", completion
    ), "only verification phases should select the verification precommit seam"


@pytest.mark.parametrize("pipeline,backend", PIPELINE_BACKEND_CASES)
def test_clean_verification_transaction_is_resume_visible_and_backend_neutral(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    backend: str,
):
    helper = _require_transaction_helper()
    _require_precommit_validator()
    config = _config(tmp_path, pipeline, backend)
    scratchpad = Path(config["scratchpad"])
    phase = _phase(pipeline)
    _seed_phase_artifact(scratchpad, phase)
    checkpoint = Checkpoint(run_id=config["_run_id"])
    monkeypatch.setattr(D, "_validate_verification_precommit", lambda *_a, **_k: [])

    commit = _call_transaction(helper, phase, checkpoint, scratchpad, config)

    assert commit.state == "CLEAN"
    assert checkpoint.phase_commits[phase.name] == commit
    assert phase.name in checkpoint.completed
    assert phase.name not in checkpoint.degraded
    loaded = Checkpoint.load(scratchpad)
    assert loaded.phase_commits[phase.name] == commit
    assert loaded.completed == [phase.name]


@pytest.mark.parametrize("pipeline,backend", PIPELINE_BACKEND_CASES)
def test_precommit_failure_becomes_resume_visible_debt_and_sentinel_survives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    backend: str,
):
    helper = _require_transaction_helper()
    _require_precommit_validator()
    config = _config(tmp_path, pipeline, backend)
    scratchpad = Path(config["scratchpad"])
    phase = _phase(pipeline)
    _seed_phase_artifact(scratchpad, phase)
    checkpoint = Checkpoint(run_id=config["_run_id"])
    monkeypatch.setattr(
        D,
        "_validate_verification_precommit",
        lambda *_a, **_k: [
            "verification receipt reconciliation missing ROW-1"
        ],
    )

    commit = _call_transaction(helper, phase, checkpoint, scratchpad, config)

    assert commit.state == "COMPLETED_WITH_DEBT"
    assert commit.unresolved_failures
    assert phase.name in checkpoint.completed
    assert phase.name in checkpoint.degraded
    sentinel = scratchpad / f"{phase.name}.degraded"
    assert sentinel.exists()
    loaded = Checkpoint.load(scratchpad)
    assert loaded.phase_commits[phase.name].state == "COMPLETED_WITH_DEBT"
    assert phase.name in loaded.degraded
    assert sentinel.exists()


def test_precommit_validator_exception_degrades_instead_of_false_clean_or_halt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    helper = _require_transaction_helper()
    _require_precommit_validator()
    config = _config(tmp_path, "sc", "claude")
    scratchpad = Path(config["scratchpad"])
    phase = _phase("sc")
    _seed_phase_artifact(scratchpad, phase)
    checkpoint = Checkpoint(run_id=config["_run_id"])

    def validation_crash(*_args, **_kwargs):
        raise OSError("synthetic receipt-read interruption")

    monkeypatch.setattr(D, "_validate_verification_precommit", validation_crash)
    commit = _call_transaction(helper, phase, checkpoint, scratchpad, config)

    assert commit.state == "COMPLETED_WITH_DEBT"
    assert any(
        "receipt-read interruption" in failure.message
        for failure in commit.unresolved_failures
    )
    assert phase.name in Checkpoint.load(scratchpad).degraded


def test_fault_between_precommit_and_central_commit_cannot_project_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    helper = _require_transaction_helper()
    _require_precommit_validator()
    config = _config(tmp_path, "l1", "codex")
    scratchpad = Path(config["scratchpad"])
    phase = _phase("l1")
    _seed_phase_artifact(scratchpad, phase)
    checkpoint = Checkpoint(run_id=config["_run_id"])
    checkpoint.save(scratchpad)
    before = (scratchpad / "_v2_checkpoint.json").read_bytes()
    monkeypatch.setattr(D, "_validate_verification_precommit", lambda *_a, **_k: [])

    def commit_crash(*_args, **_kwargs):
        raise OSError("synthetic crash before typed commit")

    monkeypatch.setattr(D, "_commit_phase_from_disk_debt", commit_crash)
    with pytest.raises(OSError, match="before typed commit"):
        _call_transaction(helper, phase, checkpoint, scratchpad, config)

    assert (scratchpad / "_v2_checkpoint.json").read_bytes() == before
    loaded = Checkpoint.load(scratchpad)
    assert phase.name not in loaded.completed
    assert phase.name not in loaded.phase_commits


def test_legacy_mark_completed_cannot_erase_authoritative_typed_debt(
    tmp_path: Path,
):
    config = _config(tmp_path, "sc", "claude")
    scratchpad = Path(config["scratchpad"])
    phase = _phase("sc")
    _seed_phase_artifact(scratchpad, phase)
    checkpoint = Checkpoint(run_id=config["_run_id"])
    failure = GateFailure(
        gate_id=f"{phase.name}.execution_receipts.coverage",
        gate_class="EVIDENCE_INTEGRITY",
        message="execution receipt coverage incomplete",
    )
    D.PhaseCommitController(
        checkpoint, scratchpad, config["project_root"], config
    ).commit(phase, "COMPLETED_WITH_DEBT", (failure,))
    sentinel = scratchpad / f"{phase.name}.degraded"
    assert sentinel.exists()

    # Compatibility code may still call the legacy method.  Once a typed debt
    # commit exists, that call must raise or be a no-op; it cannot clear debt.
    try:
        checkpoint.mark_completed(phase.name)
    except RuntimeError:
        pass
    assert checkpoint.phase_commits[phase.name].state == "COMPLETED_WITH_DEBT"
    assert phase.name in checkpoint.degraded
    assert sentinel.exists()


def test_checkpoint_replace_failure_preserves_prior_resume_state_on_windows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Same-directory Path.replace is the required Windows-safe commit point."""

    config = _config(tmp_path, "l1", "claude")
    scratchpad = Path(config["scratchpad"])
    phase = _phase("l1")
    _seed_phase_artifact(scratchpad, phase)
    checkpoint = Checkpoint(run_id=config["_run_id"])
    checkpoint.save(scratchpad)
    checkpoint_path = scratchpad / "_v2_checkpoint.json"
    prior = checkpoint_path.read_bytes()
    original_replace = Path.replace

    def fail_checkpoint_replace(self: Path, target: Path):
        if self.name == "_v2_checkpoint.json.tmp":
            raise PermissionError("synthetic Windows sharing violation")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_checkpoint_replace)
    with pytest.raises(PermissionError, match="sharing violation"):
        D.PhaseCommitController(
            checkpoint, scratchpad, config["project_root"], config
        ).commit(phase, "CLEAN")

    assert checkpoint_path.read_bytes() == prior
    assert not (scratchpad / "_v2_checkpoint.json.tmp").exists()
    loaded = Checkpoint.load(scratchpad)
    assert loaded.completed == []
    assert loaded.phase_commits == {}


def test_phase_commit_persists_typed_authority_with_legacy_projection_atomically():
    source = inspect.getsource(D.PhaseCommitController.commit)
    typed_at = source.index("self.checkpoint.phase_commits[commit_key] = commit")
    legacy_at = source.index("self.checkpoint.completed.append(phase.name)")
    save_at = source.index("self.checkpoint.save(self.scratchpad)")

    assert typed_at < legacy_at < save_at
    assert "checkpoint.mark_completed(" not in source
