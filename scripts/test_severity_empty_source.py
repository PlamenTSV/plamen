"""Focused authority tests for the authenticated empty severity source."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
from queue_work_items import (
    build_queue_work_plan,
    queue_records_to_json,
)
from plamen_parsers import render_verification_queue_work_item_markdown
from severity_decision_ledger import (
    build_severity_decision_ledger,
    write_severity_decision_ledger,
)
from severity_empty_source import (
    FAULT_POINTS,
    INITIAL_SNAPSHOT_NAME,
    INPUT_NAMES,
    OUTPUT_NAME,
    OUTPUT_NAMES,
    run_empty_severity_source,
)


RUN_ID = "12345678-1234-4234-9234-123456789abc"


def _config(
    project: Path, root: Path, *, pipeline: str = "sc"
) -> dict[str, object]:
    return {
        "pipeline": pipeline,
        "mode": "core",
        "language": "rust" if pipeline == "l1" else "evm",
        "cli_backend": "codex",
        "project_root": str(project),
        "scratchpad": str(root),
        "_run_id": RUN_ID,
    }


def _queue_bytes(items=()) -> dict[str, bytes]:
    items = tuple(items)
    plan = build_queue_work_plan(
        items,
        {"verify-fixture": tuple(item.work_item_id for item in items)} if items else {},
        planner_version="plamen.empty-severity-source-test.v1",
    )
    return {
        "verification_queue.md": (
            render_verification_queue_work_item_markdown(items).encode("utf-8")
        ),
        "verification_queue.work_items.json": (
            queue_records_to_json(items) + "\n"
        ).encode("utf-8"),
        "verification_queue.work_plan.json": (plan.to_json() + "\n").encode(
            "utf-8"
        ),
    }


def _empty_queue_bytes() -> dict[str, bytes]:
    return _queue_bytes()


def _publish_queue(
    project: Path,
    root: Path,
    *,
    work_unit_id: str = "t9.live_receipt_last_cas",
    raw: dict[str, bytes] | None = None,
    pipeline: str = "sc",
    run_id: str = RUN_ID,
) -> None:
    """Publish a typed component producer at the exact T9 output contract.

    This focused fixture proves consumer ownership checks.  It is not a full
    T0--T9 queue-transaction fixture and does not claim that ancestry.
    """
    rows = _empty_queue_bytes() if raw is None else raw
    queue_phase = "verify_queue" if pipeline == "l1" else "sc_verify_queue"
    ecosystem = "rust" if pipeline == "l1" else "evm"
    owner = canonical_work_unit_key(
        pipeline, "core", ecosystem, "codex", queue_phase, work_unit_id
    )
    contract = PhaseIOContract(
        pipeline=pipeline,
        mode="core",
        ecosystem=ecosystem,
        backend="codex",
        phase=queue_phase,
        work_unit_id=work_unit_id,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=(
                    "unstructured.v1"
                    if name.endswith(".md")
                    else "plamen.queue-authority.v1"
                ),
                minimum_gate="FIXTURE_CANONICAL_EMPTY_QUEUE",
                consumers=("severity_adjudication_shadow/source_empty",),
            )
            for name in INPUT_NAMES
        ),
        immutable_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=(),
    )
    record_work_unit_inputs(root, project, contract, launch, run_id=run_id)
    for name, content in rows.items():
        (root / name).write_bytes(content)
    record_work_unit_artifacts(
        root, project, contract, launch, run_id=run_id, actor="DRIVER"
    )


def _fixture(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    root = project / ".scratchpad"
    root.mkdir()
    _publish_queue(project, root)
    return project, root, _config(project, root), _empty_queue_bytes()


def _run(project: Path, root: Path, config: dict[str, object], *, fault_hook=None):
    return run_empty_severity_source(
        scratchpad=root,
        project_root=project,
        config=config,
        fault_hook=fault_hook,
    )


def _source_unit(root: Path):
    matches = [
        row
        for key, row in read_artifact_ledger(root)["work_units"].items()
        if key.endswith("/severity_adjudication_shadow/source_empty")
    ]
    assert len(matches) == 1
    return matches[0]


def test_owned_zero_queue_publishes_exact_unattested_driver_ledger_and_replays(
    tmp_path: Path,
) -> None:
    project, root, config, queue_before = _fixture(tmp_path)
    output = root / OUTPUT_NAME
    snapshot = root / INITIAL_SNAPSHOT_NAME

    assert _run(project, root, config) is True
    expected = build_severity_decision_ledger(RUN_ID, ())
    assert json.loads(output.read_text(encoding="utf-8")) == expected
    assert snapshot.read_bytes() == output.read_bytes()
    assert expected["authority_status"] == "UNATTESTED_COMPATIBILITY"
    assert expected["decision_count"] == 0
    assert expected["decisions"] == []

    writer_projection = tmp_path / "writer-projection.json"
    assert write_severity_decision_ledger(
        writer_projection, RUN_ID, ()
    ) == expected
    assert output.read_bytes() == writer_projection.read_bytes()

    unit = _source_unit(root)
    assert unit["run_id"] == RUN_ID
    assert unit["model_invoked"] is False
    assert unit["launch_digest"]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["semantic_status"] == "ACTIVE"
    assert not unit.get("execution_authority")
    assert set(unit["artifacts"]) == {
        f"scratchpad:{name}" for name in OUTPUT_NAMES
    }
    assert unit["artifacts"][f"scratchpad:{OUTPUT_NAME}"]["writer"] == "DRIVER"

    frozen_output = output.read_bytes()
    frozen_snapshot = snapshot.read_bytes()
    frozen_mtime = output.stat().st_mtime_ns
    frozen_snapshot_mtime = snapshot.stat().st_mtime_ns
    assert _run(project, root, config) is True
    assert output.read_bytes() == frozen_output
    assert output.stat().st_mtime_ns == frozen_mtime
    assert snapshot.read_bytes() == frozen_snapshot
    assert snapshot.stat().st_mtime_ns == frozen_snapshot_mtime
    assert {
        name: (root / name).read_bytes() for name in INPUT_NAMES
    } == queue_before


@pytest.mark.parametrize("fault_point", FAULT_POINTS)
def test_each_fault_prefix_recovers_the_exact_sealed_output(
    tmp_path: Path, fault_point: str,
) -> None:
    project, root, config, queue_before = _fixture(tmp_path)
    fired = False

    def crash(point: str) -> None:
        nonlocal fired
        if point == fault_point and not fired:
            fired = True
            raise RuntimeError(f"fault:{point}")

    with pytest.raises(RuntimeError, match=f"fault:{fault_point}"):
        _run(project, root, config, fault_hook=crash)
    assert fired is True
    assert _run(project, root, config) is True
    assert json.loads((root / OUTPUT_NAME).read_text(encoding="utf-8")) == (
        build_severity_decision_ledger(RUN_ID, ())
    )
    assert (root / INITIAL_SNAPSHOT_NAME).read_bytes() == (
        root / OUTPUT_NAME
    ).read_bytes()
    assert {
        name: (root / name).read_bytes() for name in INPUT_NAMES
    } == queue_before
    unit = _source_unit(root)
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["semantic_status"] == "ACTIVE"


@pytest.mark.parametrize("name", OUTPUT_NAMES)
@pytest.mark.parametrize("damage", ("missing", "tampered"))
def test_committed_output_drift_is_rejected(
    tmp_path: Path, name: str, damage: str,
) -> None:
    project, root, config, _queue_before = _fixture(tmp_path)
    assert _run(project, root, config) is True
    output = root / name
    if damage == "missing":
        output.unlink()
    else:
        output.write_bytes(b"{}\n")
    with pytest.raises(ArtifactLedgerError, match="output replay failed"):
        _run(project, root, config)


def test_input_drift_after_arm_and_cross_run_replay_are_rejected(
    tmp_path: Path,
) -> None:
    project, root, config, _queue_before = _fixture(tmp_path)

    def crash(point: str) -> None:
        if point == "after_arm":
            raise RuntimeError("armed")

    with pytest.raises(RuntimeError, match="armed"):
        _run(project, root, config, fault_hook=crash)
    typed = root / "verification_queue.work_items.json"
    typed.write_bytes(typed.read_bytes() + b"\n")
    with pytest.raises(ArtifactLedgerError, match="queue prebind authority is invalid"):
        _run(project, root, config)

    # Use a separate exact fixture for run identity so the prior input damage
    # cannot mask the transaction-identity check.
    second = project.parent / "second"
    second.mkdir()
    second_root = second / ".scratchpad"
    second_root.mkdir()
    _publish_queue(second, second_root)
    second_config = _config(second, second_root)
    assert _run(second, second_root, second_config) is True
    foreign = dict(second_config)
    foreign["_run_id"] = "87654321-4321-4321-8321-cba987654321"
    with pytest.raises(ArtifactLedgerError, match="queue prebind authority is invalid"):
        _run(second, second_root, foreign)


@pytest.mark.parametrize("run_id", (7, " padded ", ""))
def test_noncanonical_run_identity_is_rejected(
    tmp_path: Path, run_id: object,
) -> None:
    project, root, config, _queue_before = _fixture(tmp_path)
    config["_run_id"] = run_id
    with pytest.raises(ArtifactLedgerError, match="requires an exact"):
        _run(project, root, config)
    assert not any((root / name).exists() for name in OUTPUT_NAMES)


@pytest.mark.parametrize("name", OUTPUT_NAMES)
def test_armed_arbitrary_partial_member_is_rejected(
    tmp_path: Path, name: str,
) -> None:
    project, root, config, _queue_before = _fixture(tmp_path)

    def stop_after_arm(point: str) -> None:
        if point == "after_arm":
            raise RuntimeError("armed")

    with pytest.raises(RuntimeError, match="armed"):
        _run(project, root, config, fault_hook=stop_after_arm)
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"arbitrary\n")
    with pytest.raises(ArtifactLedgerError, match="arbitrary partial"):
        _run(project, root, config)


@pytest.mark.parametrize("state", ("unowned", "wrong_owner"))
def test_zero_queue_requires_exact_current_t9_driver_producer(
    tmp_path: Path, state: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    root = project / ".scratchpad"
    root.mkdir()
    rows = _empty_queue_bytes()
    if state == "unowned":
        for name, raw in rows.items():
            (root / name).write_bytes(raw)
    else:
        _publish_queue(
            project, root, work_unit_id="t8.not_live_receipt", raw=rows
        )

    with pytest.raises(ArtifactLedgerError, match="producer|required input"):
        _run(project, root, _config(project, root))
    assert not (root / OUTPUT_NAME).exists()


@pytest.mark.parametrize("state", ("missing", "empty"))
@pytest.mark.parametrize("name", INPUT_NAMES)
def test_missing_or_empty_queue_input_is_rejected(
    tmp_path: Path, name: str, state: str,
) -> None:
    project, root, config, _queue_before = _fixture(tmp_path)
    path = root / name
    if state == "missing":
        path.unlink()
    else:
        path.write_bytes(b"")
    with pytest.raises((ArtifactLedgerError, ValueError)):
        _run(project, root, config)
    assert not (root / OUTPUT_NAME).exists()


@pytest.mark.parametrize(
    "name",
    (
        "verify_H-STALE.severity_decision.json",
        "Verify_X-CASEFOLD.severity_decision.json",
    ),
)
def test_stale_per_candidate_decision_is_not_reclassified_as_empty(
    tmp_path: Path, name: str,
) -> None:
    project, root, config, _queue_before = _fixture(tmp_path)
    stale = root / name
    stale.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ArtifactLedgerError, match="refuses stale per-candidate"):
        _run(project, root, config)
    assert stale.read_bytes() == b"{}\n"
    assert not (root / OUTPUT_NAME).exists()


@pytest.mark.parametrize("inject_point", ("after_arm", "after_output_1"))
def test_stale_decision_appearing_after_arm_prevents_commit(
    tmp_path: Path, inject_point: str,
) -> None:
    project, root, config, _queue_before = _fixture(tmp_path)
    stale = root / "Verify_X-RACE.severity_decision.json"

    def inject(point: str) -> None:
        if point == inject_point:
            stale.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ArtifactLedgerError, match="stale per-candidate"):
        _run(project, root, config, fault_hook=inject)
    assert stale.is_file()
    assert (root / OUTPUT_NAME).is_file() is (inject_point == "after_output_1")
    assert not (root / INITIAL_SNAPSHOT_NAME).exists()
    unit = _source_unit(root)
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert unit["semantic_status"] == "INPUTS_BOUND"


@pytest.mark.parametrize("name", OUTPUT_NAMES)
@pytest.mark.parametrize("collision", ("file", "symlink"))
def test_foreign_output_file_or_symlink_is_never_adopted(
    tmp_path: Path, name: str, collision: str,
) -> None:
    project, root, config, _queue_before = _fixture(tmp_path)
    output = root / name
    output.parent.mkdir(parents=True, exist_ok=True)
    if collision == "file":
        output.write_bytes(b"foreign\n")
    else:
        try:
            output.symlink_to(root / "absent-foreign-target")
        except OSError:
            pytest.skip("symlink creation is unavailable")
    with pytest.raises(ArtifactLedgerError, match="pre-existing output authority"):
        _run(project, root, config)
    assert not _source_unit_or_none(root)


def _source_unit_or_none(root: Path):
    rows = [
        row
        for key, row in read_artifact_ledger(root)["work_units"].items()
        if key.endswith("/severity_adjudication_shadow/source_empty")
    ]
    assert len(rows) <= 1
    return rows[0] if rows else None


def test_valid_nonempty_queue_is_not_replaced_with_empty_source(tmp_path: Path):
    from test_queue_work_item_p0_aj import _item

    project = tmp_path / "project"
    project.mkdir()
    root = project / ".scratchpad"
    root.mkdir()
    rows = _queue_bytes((_item(),))
    _publish_queue(project, root, raw=rows)
    before = read_artifact_ledger(root)
    assert _run(project, root, _config(project, root)) is False
    assert not (root / OUTPUT_NAME).exists()
    assert read_artifact_ledger(root) == before
    assert {name: (root / name).read_bytes() for name in INPUT_NAMES} == rows


@pytest.mark.parametrize(
    "mutation",
    ("heading", "changed_total", "extra_row"),
)
def test_owned_full_queue_document_drift_is_rejected_before_empty_source_arm(
    tmp_path: Path,
    mutation: str,
) -> None:
    """The typed component producer does not bless a noncanonical document."""

    project = tmp_path / "project"
    project.mkdir()
    root = project / ".scratchpad"
    root.mkdir()
    rows = _empty_queue_bytes()
    original_markdown = rows["verification_queue.md"].decode("utf-8")
    markdown = original_markdown
    if mutation == "heading":
        markdown = markdown.replace(
            "# Verification Queue Manifest",
            "# Verification Queue",
            1,
        )
    elif mutation == "changed_total":
        markdown = markdown.replace(
            "Total: 0 findings | Expected verify_<ID>.md files: 0",
            "Total: 1 findings | Expected verify_<ID>.md files: 1",
            1,
        )
    else:
        separator = (
            "|---------|------------|----------------------|----------|-------|"
            "-----------|---------------|----------|------------------|-----------|"
        )
        extra = (
            "| 1 | H-FOREIGN | verify_H-FOREIGN.md | High | foreign | x | x |"
            " x | x | structural |"
        )
        markdown = markdown.replace(separator, separator + "\n" + extra, 1)
    assert markdown != original_markdown
    rows["verification_queue.md"] = markdown.encode("utf-8")
    _publish_queue(project, root, raw=rows)

    with pytest.raises(ArtifactLedgerError, match="Markdown|queue denominator"):
        _run(project, root, _config(project, root))

    assert _source_unit_or_none(root) is None
    assert not any((root / name).exists() for name in OUTPUT_NAMES)


@pytest.mark.parametrize(
    "nonempty_member",
    ("typed_and_markdown", "work_plan"),
)
def test_owned_typed_and_plan_denominator_disagreement_cannot_adopt_empty_source(
    tmp_path: Path,
    nonempty_member: str,
) -> None:
    """An owned but internally inconsistent component queue is still debt."""

    from test_queue_work_item_p0_aj import _item

    project = tmp_path / "project"
    project.mkdir()
    root = project / ".scratchpad"
    root.mkdir()
    empty = _empty_queue_bytes()
    nonempty = _queue_bytes((_item(),))
    rows = dict(empty)
    if nonempty_member == "typed_and_markdown":
        rows["verification_queue.md"] = nonempty["verification_queue.md"]
        rows["verification_queue.work_items.json"] = nonempty[
            "verification_queue.work_items.json"
        ]
    else:
        rows["verification_queue.work_plan.json"] = nonempty[
            "verification_queue.work_plan.json"
        ]
    _publish_queue(project, root, raw=rows)

    with pytest.raises(ArtifactLedgerError, match="queue denominator"):
        _run(project, root, _config(project, root))

    assert _source_unit_or_none(root) is None
    assert not any((root / name).exists() for name in OUTPUT_NAMES)
