"""Focused component tests for the isolated report-capture transactions.

These tests use a genuinely committed registered report-index producer.  They
do not exercise report rendering or the later seven-output publication.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import pytest


from artifact_ledger import (
    ArtifactLedgerError,
    LEDGER_NAME,
    read_artifact_ledger,
    write_artifact_ledger,
)
import report_capture_phaseio_authority as RCA
from report_capture_transactions import (
    FINAL_CAPTURE_NAME,
    SOURCE_CAPTURE_NAME,
    run_report_final_capture_transaction,
    run_report_source_capture_transaction,
    validate_committed_report_final_capture_transaction,
    validate_committed_report_source_capture_transaction,
)
from test_report_source_capture_cutover_p2 import (
    RUN_ID,
    _commit_sources,
    _config,
    _metadata,
    _roots,
)


OUTPUTS = {
    "project:AUDIT_REPORT.md": ("CLIENT_REPORT", b"# Audited report\n"),
    "scratchpad:report_quality.md": ("REPORT_QUALITY", b"# Quality\n"),
}


def _source_args(tmp_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    project, scratch = _roots(tmp_path)
    _commit_sources(project, scratch, {"report_index.md": b"# Index\n"})
    args: dict[str, Any] = {
        "scratchpad": scratch,
        "project_root": project,
        "run_id": RUN_ID,
        "expected_config": _config(scratch),
        "metadata": _metadata(scratch),
        "fixed_source_roles": {"report_index.md": "REPORT_INDEX"},
        "namespace_roles": {},
    }
    return project, scratch, args


def _final_args(source_args: dict[str, Any]) -> dict[str, Any]:
    return {
        "scratchpad": source_args["scratchpad"],
        "project_root": source_args["project_root"],
        "run_id": source_args["run_id"],
        "expected_config": source_args["expected_config"],
        "derived_outputs": OUTPUTS,
        "location_decisions": (),
    }


def _physical(path: Path) -> tuple[bytes, int, int, int, int]:
    row = path.stat()
    return (
        path.read_bytes(),
        row.st_dev,
        row.st_ino,
        row.st_size,
        row.st_mtime_ns,
    )


def _committed(root: Path, suffix: str) -> bool:
    units = read_artifact_ledger(root)["work_units"]
    rows = [row for key, row in units.items() if key.endswith(suffix)]
    assert len(rows) <= 1
    return bool(
        rows
        and rows[0]["semantic_status"] == "ACTIVE"
        and rows[0]["execution_state"] == "OUTPUT_COMMITTED"
    )


def _replace_directory_object(path: Path) -> tuple[int, int]:
    """Replace only a directory inode while preserving every child inode."""

    before = path.stat()
    old = path.with_name(path.name + ".replaced-root")
    path.rename(old)
    path.mkdir()
    os.chmod(path, before.st_mode & 0o777)
    for child in tuple(old.iterdir()):
        child.rename(path / child.name)
    old.rmdir()
    after = path.stat()
    assert before.st_dev == after.st_dev
    assert before.st_ino != after.st_ino
    return before.st_ino, after.st_ino


def test_source_capture_fresh_commit_and_read_only_replay(tmp_path: Path) -> None:
    _project, scratch, args = _source_args(tmp_path)
    raw = run_report_source_capture_transaction(**args)
    output = scratch / SOURCE_CAPTURE_NAME
    ledger = scratch / LEDGER_NAME
    frozen = (_physical(output), _physical(ledger))

    assert raw == output.read_bytes()
    assert validate_committed_report_source_capture_transaction(**args) == raw
    assert run_report_source_capture_transaction(**args) == raw
    assert (_physical(output), _physical(ledger)) == frozen


@pytest.mark.parametrize(
    "point", ["after_output", "before_commit", "after_commit"]
)
def test_source_capture_fault_rejoins_without_rewrite(
    tmp_path: Path, point: str
) -> None:
    _project, scratch, args = _source_args(tmp_path)

    def fault(label: str) -> None:
        if label == point:
            raise RuntimeError(point)

    with pytest.raises(RuntimeError, match=point):
        run_report_source_capture_transaction(**args, fault_hook=fault)
    output = scratch / SOURCE_CAPTURE_NAME
    frozen_output = _physical(output)
    raw = run_report_source_capture_transaction(**args)

    assert _physical(output) == frozen_output
    assert raw == output.read_bytes()
    assert _committed(scratch, "/report_assemble/source_capture")


def test_source_capture_after_arm_fault_resumes_same_sealed_create(
    tmp_path: Path,
) -> None:
    _project, scratch, args = _source_args(tmp_path)

    def fault(label: str) -> None:
        if label == "after_arm":
            raise RuntimeError(label)

    with pytest.raises(RuntimeError, match="after_arm"):
        run_report_source_capture_transaction(**args, fault_hook=fault)
    ledger_before = (scratch / LEDGER_NAME).read_bytes()
    assert not (scratch / SOURCE_CAPTURE_NAME).exists()
    assert not _committed(scratch, "/report_assemble/source_capture")

    raw = run_report_source_capture_transaction(**args)
    assert raw == (scratch / SOURCE_CAPTURE_NAME).read_bytes()
    assert (scratch / LEDGER_NAME).read_bytes() != ledger_before
    assert _committed(scratch, "/report_assemble/source_capture")


def test_source_capture_persists_exact_create_preexecution_authority(
    tmp_path: Path,
) -> None:
    project, scratch, args = _source_args(tmp_path)
    raw = run_report_source_capture_transaction(**args)
    prepared = RCA.prepare_report_source_capture(**args)
    identity = f"scratchpad:{SOURCE_CAPTURE_NAME}"
    records = {
        identity: {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    }
    expected = RCA.build_report_capture_preexecution_authority(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        contract=prepared.contract,
        launch=prepared.launch,
        expected_output_records=records,
    )
    unit = read_artifact_ledger(scratch)["work_units"][prepared.contract.key]

    assert unit["preexecution_authority"] == expected
    assert unit["preexecution_authority_digest"] == expected["authority_sha256"]
    assert expected["expected_output_records"] == records
    assert expected["root_authority"] == RCA.build_report_capture_root_authority(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        contract=prepared.contract,
        launch=prepared.launch,
    )
    assert "successor_consumption_authority" not in unit
    assert "successor_progress_authority" not in unit
    assert validate_committed_report_source_capture_transaction(**args) == raw


def test_source_capture_armed_resume_requires_same_candidate(
    tmp_path: Path,
) -> None:
    _project, scratch, args = _source_args(tmp_path)

    def fault(label: str) -> None:
        if label == "after_output":
            raise RuntimeError(label)

    with pytest.raises(RuntimeError, match="after_output"):
        run_report_source_capture_transaction(**args, fault_hook=fault)
    output = scratch / SOURCE_CAPTURE_NAME
    frozen = _physical(output)
    changed = {**args, "metadata": {**args["metadata"], "project_name": "other"}}

    with pytest.raises(ArtifactLedgerError, match="plan|candidate|differ"):
        run_report_source_capture_transaction(**changed)
    assert _physical(output) == frozen
    assert not _committed(scratch, "/report_assemble/source_capture")

    assert run_report_source_capture_transaction(**args) == output.read_bytes()


def test_source_capture_refuses_unarmed_exact_prewrite(tmp_path: Path) -> None:
    project, scratch, args = _source_args(tmp_path)
    prepared = RCA.prepare_report_source_capture(**args)
    output = scratch / SOURCE_CAPTURE_NAME
    output.write_bytes(prepared.capture_bytes)
    ledger_before = (scratch / LEDGER_NAME).read_bytes()

    with pytest.raises(ArtifactLedgerError, match="unarmed pre-existing"):
        run_report_source_capture_transaction(**args)

    assert output.read_bytes() == prepared.capture_bytes
    assert (scratch / LEDGER_NAME).read_bytes() == ledger_before
    assert not _committed(scratch, "/report_assemble/source_capture")
    assert project.is_dir()


def test_source_capture_rejects_registered_source_drift_after_arm(
    tmp_path: Path,
) -> None:
    _project, scratch, args = _source_args(tmp_path)

    def fault(label: str) -> None:
        if label == "after_arm":
            (scratch / "report_index.md").write_bytes(b"# Drift\n")

    with pytest.raises((ArtifactLedgerError, ValueError), match="(?i)drift|authority|changed"):
        run_report_source_capture_transaction(**args, fault_hook=fault)

    assert not (scratch / SOURCE_CAPTURE_NAME).exists()
    assert not _committed(scratch, "/report_assemble/source_capture")


def test_source_capture_rejects_config_or_root_drift_after_arm(
    tmp_path: Path,
) -> None:
    project, scratch, args = _source_args(tmp_path)
    config = args["expected_config"]

    def config_fault(label: str) -> None:
        if label == "after_arm":
            config["mode"] = "core"

    with pytest.raises((ArtifactLedgerError, ValueError), match="config|differ|drift"):
        run_report_source_capture_transaction(**args, fault_hook=config_fault)
    assert not (scratch / SOURCE_CAPTURE_NAME).exists()

    # A separate fixture gives the root-identity case an unarmed transaction.
    project2, scratch2, args2 = _source_args(tmp_path / "root-drift")
    original_mode = project2.stat().st_mode & 0o777
    changed_mode = 0o711 if original_mode != 0o711 else 0o755

    def root_fault(label: str) -> None:
        if label == "after_arm":
            os.chmod(project2, changed_mode)

    try:
        with pytest.raises(ArtifactLedgerError, match="root|authority|changed"):
            run_report_source_capture_transaction(**args2, fault_hook=root_fault)
    finally:
        os.chmod(project2, original_mode)
    assert not (scratch2 / SOURCE_CAPTURE_NAME).exists()


def test_source_capture_rechecks_root_after_before_commit(
    tmp_path: Path,
) -> None:
    project, scratch, args = _source_args(tmp_path)
    original_mode = project.stat().st_mode & 0o777
    changed_mode = 0o711 if original_mode != 0o711 else 0o755

    def fault(label: str) -> None:
        if label == "before_commit":
            os.chmod(project, changed_mode)

    try:
        with pytest.raises(ArtifactLedgerError, match="root|authority|changed"):
            run_report_source_capture_transaction(**args, fault_hook=fault)
    finally:
        os.chmod(project, original_mode)

    output = scratch / SOURCE_CAPTURE_NAME
    partial = _physical(output)
    assert not _committed(scratch, "/report_assemble/source_capture")
    assert run_report_source_capture_transaction(**args) == output.read_bytes()
    assert _physical(output) == partial


def test_source_capture_after_commit_mutation_is_not_reblessed(
    tmp_path: Path,
) -> None:
    _project, scratch, args = _source_args(tmp_path)
    output = scratch / SOURCE_CAPTURE_NAME

    def fault(label: str) -> None:
        if label == "after_commit":
            output.write_bytes(b"{}")

    with pytest.raises(
        (ArtifactLedgerError, ValueError),
        match="candidate|output|successor|artifact|replay|differ",
    ):
        run_report_source_capture_transaction(**args, fault_hook=fault)

    ledger = read_artifact_ledger(scratch)
    units = ledger["work_units"]
    unit = next(
        row
        for key, row in units.items()
        if key.endswith("/report_assemble/source_capture")
    )
    identity = f"scratchpad:{SOURCE_CAPTURE_NAME}"
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["artifacts"][identity]["sha256"] != hashlib.sha256(
        output.read_bytes()
    ).hexdigest()
    with pytest.raises((ArtifactLedgerError, ValueError)):
        validate_committed_report_source_capture_transaction(**args)


def test_final_capture_fault_resume_and_committed_read_only_replay(
    tmp_path: Path,
) -> None:
    _project, scratch, source_args = _source_args(tmp_path)
    run_report_source_capture_transaction(**source_args)
    args = _final_args(source_args)

    def fault(label: str) -> None:
        if label == "after_output":
            raise RuntimeError(label)

    with pytest.raises(RuntimeError, match="after_output"):
        run_report_final_capture_transaction(**args, fault_hook=fault)
    output = scratch / FINAL_CAPTURE_NAME
    partial = _physical(output)
    raw = run_report_final_capture_transaction(**args)
    ledger = scratch / LEDGER_NAME
    frozen = (_physical(output), _physical(ledger))

    assert _physical(output) == partial
    assert validate_committed_report_final_capture_transaction(**args) == raw
    assert run_report_final_capture_transaction(**args) == raw
    assert (_physical(output), _physical(ledger)) == frozen


def test_final_capture_after_commit_mutation_is_not_reblessed(
    tmp_path: Path,
) -> None:
    _project, scratch, source_args = _source_args(tmp_path)
    run_report_source_capture_transaction(**source_args)
    args = _final_args(source_args)
    output = scratch / FINAL_CAPTURE_NAME

    def fault(label: str) -> None:
        if label == "after_commit":
            output.write_bytes(b"{}")

    with pytest.raises(
        (ArtifactLedgerError, ValueError),
        match="candidate|output|successor|artifact|replay|differ",
    ):
        run_report_final_capture_transaction(**args, fault_hook=fault)

    ledger = read_artifact_ledger(scratch)
    unit = next(
        row
        for key, row in ledger["work_units"].items()
        if key.endswith("/report_assemble/final_capture")
    )
    identity = f"scratchpad:{FINAL_CAPTURE_NAME}"
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["artifacts"][identity]["sha256"] != hashlib.sha256(
        output.read_bytes()
    ).hexdigest()
    with pytest.raises((ArtifactLedgerError, ValueError)):
        validate_committed_report_final_capture_transaction(**args)


def test_final_capture_armed_resume_requires_same_candidate(
    tmp_path: Path,
) -> None:
    _project, scratch, source_args = _source_args(tmp_path)
    run_report_source_capture_transaction(**source_args)
    args = _final_args(source_args)

    def fault(label: str) -> None:
        if label == "after_output":
            raise RuntimeError(label)

    with pytest.raises(RuntimeError, match="after_output"):
        run_report_final_capture_transaction(**args, fault_hook=fault)
    output = scratch / FINAL_CAPTURE_NAME
    frozen = _physical(output)
    changed_outputs = dict(OUTPUTS)
    changed_outputs["scratchpad:report_quality.md"] = (
        "REPORT_QUALITY",
        b"# Changed quality\n",
    )

    with pytest.raises(ArtifactLedgerError, match="plan|candidate|differ"):
        run_report_final_capture_transaction(
            **{**args, "derived_outputs": changed_outputs}
        )
    assert _physical(output) == frozen
    assert not _committed(scratch, "/report_assemble/final_capture")

    assert run_report_final_capture_transaction(**args) == output.read_bytes()


def test_final_capture_refuses_unarmed_prewrite_and_source_drift(
    tmp_path: Path,
) -> None:
    _project, scratch, source_args = _source_args(tmp_path)
    run_report_source_capture_transaction(**source_args)
    args = _final_args(source_args)
    candidate = RCA.build_report_final_capture_bytes(**args)
    output = scratch / FINAL_CAPTURE_NAME
    output.write_bytes(candidate)
    ledger_before = (scratch / LEDGER_NAME).read_bytes()

    with pytest.raises(ArtifactLedgerError, match="unarmed pre-existing"):
        run_report_final_capture_transaction(**args)
    assert output.read_bytes() == candidate
    assert (scratch / LEDGER_NAME).read_bytes() == ledger_before

    # Use a new authoritative source pair for the after-arm predecessor drift.
    _project2, scratch2, source_args2 = _source_args(tmp_path / "source-drift")
    run_report_source_capture_transaction(**source_args2)
    args2 = _final_args(source_args2)

    def fault(label: str) -> None:
        if label == "after_arm":
            (scratch2 / SOURCE_CAPTURE_NAME).write_bytes(b"{}")

    with pytest.raises((ArtifactLedgerError, ValueError), match="source|capture|authority|drift"):
        run_report_final_capture_transaction(**args2, fault_hook=fault)
    assert not (scratch2 / FINAL_CAPTURE_NAME).exists()
    assert not _committed(scratch2, "/report_assemble/final_capture")


def test_read_only_entrypoints_never_adopt_absent_transactions(
    tmp_path: Path,
) -> None:
    _project, scratch, source_args = _source_args(tmp_path)
    with pytest.raises(ArtifactLedgerError, match="not committed"):
        validate_committed_report_source_capture_transaction(**source_args)
    assert not (scratch / SOURCE_CAPTURE_NAME).exists()
    assert not _committed(scratch, "/report_assemble/source_capture")

    run_report_source_capture_transaction(**source_args)
    final_args = _final_args(source_args)
    with pytest.raises(ArtifactLedgerError, match="not committed"):
        validate_committed_report_final_capture_transaction(**final_args)
    assert not (scratch / FINAL_CAPTURE_NAME).exists()
    assert not _committed(scratch, "/report_assemble/final_capture")


@pytest.mark.posix_only
def test_armed_source_resume_rejects_replaced_scratchpad_root_across_calls(
    tmp_path: Path,
) -> None:
    _project, scratch, args = _source_args(tmp_path)

    def fault(label: str) -> None:
        if label == "after_output":
            raise RuntimeError(label)

    with pytest.raises(RuntimeError, match="after_output"):
        run_report_source_capture_transaction(**args, fault_hook=fault)
    output = scratch / SOURCE_CAPTURE_NAME
    ledger_path = scratch / LEDGER_NAME
    preserved_children = (_physical(output), _physical(ledger_path))

    _replace_directory_object(scratch)
    assert (_physical(output), _physical(ledger_path)) == preserved_children
    with pytest.raises(ArtifactLedgerError, match="root|preexecution|authority|identity"):
        run_report_source_capture_transaction(**args)

    assert (_physical(output), _physical(ledger_path)) == preserved_children
    assert not _committed(scratch, "/report_assemble/source_capture")


@pytest.mark.posix_only
def test_committed_final_loader_rejects_replaced_project_root_across_calls(
    tmp_path: Path,
) -> None:
    project, scratch, source_args = _source_args(tmp_path)
    run_report_source_capture_transaction(**source_args)
    final_args = _final_args(source_args)
    run_report_final_capture_transaction(**final_args)
    source = scratch / SOURCE_CAPTURE_NAME
    final = scratch / FINAL_CAPTURE_NAME
    ledger_path = scratch / LEDGER_NAME
    preserved_children = (
        _physical(source),
        _physical(final),
        _physical(ledger_path),
    )

    _replace_directory_object(project)
    assert (
        _physical(source),
        _physical(final),
        _physical(ledger_path),
    ) == preserved_children
    with pytest.raises(ValueError, match="root authority|preexecution|differs"):
        RCA.load_committed_report_final_capture_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
        )

    assert (
        _physical(source),
        _physical(final),
        _physical(ledger_path),
    ) == preserved_children


def test_registered_capture_rejects_stripped_create_preexecution_authority(
    tmp_path: Path,
) -> None:
    project, scratch, args = _source_args(tmp_path)
    run_report_source_capture_transaction(**args)
    ledger = read_artifact_ledger(scratch)
    keys = [
        key
        for key in ledger["work_units"]
        if key.endswith("/report_assemble/source_capture")
    ]
    assert len(keys) == 1
    unit = ledger["work_units"][keys[0]]
    assert unit.pop("preexecution_authority")["schema"] == (
        "plamen.report-capture-preexecution-authority.v1"
    )
    unit.pop("preexecution_authority_digest")
    assert "successor_consumption_authority" not in unit
    assert "successor_progress_authority" not in unit
    write_artifact_ledger(scratch, ledger)

    with pytest.raises(ValueError, match="preexecution authority differs"):
        RCA.load_committed_report_source_capture_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
        )


def test_committed_capture_rejects_self_consistent_foreign_candidate_seal(
    tmp_path: Path,
) -> None:
    project, scratch, args = _source_args(tmp_path)
    raw = run_report_source_capture_transaction(**args)
    prepared = RCA.prepare_report_source_capture(**args)
    ledger = read_artifact_ledger(scratch)
    unit = ledger["work_units"][prepared.contract.key]
    wrong = b"{}"
    assert wrong != raw
    forged = RCA.build_report_capture_preexecution_authority(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        contract=prepared.contract,
        launch=prepared.launch,
        expected_output_records={
            f"scratchpad:{SOURCE_CAPTURE_NAME}": {
                "sha256": hashlib.sha256(wrong).hexdigest(),
                "size": len(wrong),
            },
        },
    )
    unit["preexecution_authority"] = forged
    unit["preexecution_authority_digest"] = forged["authority_sha256"]
    write_artifact_ledger(scratch, ledger)

    with pytest.raises(ValueError, match="preexecution authority differs"):
        RCA.load_committed_report_source_capture_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
        )
    assert (scratch / SOURCE_CAPTURE_NAME).read_bytes() == raw
