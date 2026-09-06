"""Native-Windows long-path contract for ArtifactLedger transactions.

The persisted authority must not depend on legacy MAX_PATH spelling.  These
tests intentionally cross the distinct publication boundaries in the main
ledger, authority ledgers, authority CAS, successor progress, and the driver's
same-directory atomic output publication.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest

import artifact_ledger as AL
import plamen_driver as D
import rooted_path_io as rooted_io
from phase_io_contracts import (
    ArtifactSpec,
    DriverMergeEvent,
    LaunchSpec,
    PhaseIOContract,
)


pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="native Windows long-path regression contract",
)

BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}
RUN_ID = "run-windows-long-path-successor"


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _long_root(tmp_path: Path, length: int) -> Path:
    """Create one pre-existing safe directory with an exact lexical length."""

    prefix = tmp_path / "long-root"
    prefix.mkdir()
    leaf_size = length - len(os.fspath(prefix)) - 1
    assert 1 <= leaf_size <= 240
    root = prefix / ("r" * leaf_size)
    os.mkdir(rooted_io.native_path(root))
    assert len(os.fspath(root)) == length
    return root


def _artifact(
    *,
    owner: str,
    path: str,
    write_mode: str = "REPLACE",
    consumers: tuple[str, ...] = (),
) -> ArtifactSpec:
    return ArtifactSpec(
        root="scratchpad",
        path=path,
        owner_key=owner,
        artifact_class="DRIVER_GENERATED",
        writer="DRIVER",
        write_mode=write_mode,
        consumers=consumers,
    )


def _launch(contract: PhaseIOContract) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
    )


def _full_one_output_successor(
    scratch: Path,
    project: Path,
    *,
    interrupt_apply_once: bool = False,
) -> None:
    output_name = "findings_inventory.md"
    producer_key = "sc/thorough/evm/claude/inventory/canonical_aggregate"
    consumer_key = "sc/thorough/evm/claude/inventory/additive_reemit"
    relative_consumer = "inventory/additive_reemit"
    producer = PhaseIOContract(
        **BASE,
        phase="inventory",
        work_unit_id="canonical_aggregate",
        outputs=(
            _artifact(
                owner=producer_key,
                path="inventory_id_allocation_delta.json",
                consumers=(relative_consumer,),
            ),
            _artifact(
                owner=producer_key,
                path=output_name,
                consumers=(relative_consumer,),
            ),
        ),
        model_invoked=False,
    )
    producer_launch = _launch(producer)
    source = b'{"ids":["A"]}\n'
    before = b'{"ids":["A"]}\n'
    AL.record_work_unit_inputs(
        scratch,
        project,
        producer,
        producer_launch,
        run_id=RUN_ID,
    )
    D._atomic_driver_bytes(
        scratch / "inventory_id_allocation_delta.json",
        source,
    )
    D._atomic_driver_bytes(scratch / output_name, before)
    AL.record_work_unit_artifacts(
        scratch,
        project,
        producer,
        producer_launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )

    consumer = PhaseIOContract(
        **BASE,
        phase="inventory",
        work_unit_id="additive_reemit",
        outputs=(
            _artifact(
                owner=consumer_key,
                path=output_name,
                write_mode="MERGE",
            ),
        ),
        immutable_inputs=(
            "scratchpad:inventory_id_allocation_delta.json",
        ),
        model_invoked=False,
    )
    consumer_launch = _launch(consumer)
    after = b'{"ids":["A","B"]}\n'
    identity = f"scratchpad:{output_name}"
    event = DriverMergeEvent(
        work_unit_key=consumer.key,
        contract_digest=consumer.digest,
        artifact_identity=identity,
        before_sha256=_digest(before),
        after_sha256=_digest(after),
        source_identities=(
            "scratchpad:inventory_id_allocation_delta.json",
        ),
        identities_before=("A",),
        identities_after=("A", "B"),
    )
    events = {identity: event}
    plan = AL.plan_driver_successor_transaction(
        scratch,
        project,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        planned_output_bytes={identity: after},
        merge_events=events,
    )
    armed = AL.record_work_unit_inputs(
        scratch,
        project,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        successor_plan=plan,
    )
    assert armed["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    AL.begin_driver_successor_step(
        scratch,
        project,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        ordinal=1,
    )
    if interrupt_apply_once:
        def _interrupt(_source: Path, _destination: Path) -> None:
            raise OSError("simulated long-path publication interruption")

        with pytest.MonkeyPatch.context() as patcher:
            patcher.setattr(D, "_durable_driver_replace", _interrupt)
            with pytest.raises(
                OSError,
                match="long-path publication interruption",
            ):
                D._atomic_driver_bytes(scratch / output_name, after)
        assert not any(
            entry.name.startswith(".p.") and entry.name.endswith(".tmp")
            for entry in rooted_io.scandir(scratch)
        )
        resumed = AL.record_work_unit_inputs(
            scratch,
            project,
            consumer,
            consumer_launch,
            run_id=RUN_ID,
            successor_plan=plan,
        )
        assert resumed["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    D._atomic_driver_bytes(scratch / output_name, after)
    AL.complete_driver_successor_step(
        scratch,
        project,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        ordinal=1,
    )
    committed = AL.record_work_unit_artifacts(
        scratch,
        project,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        actor="DRIVER",
        merge_events=events,
    )
    assert committed["semantic_status"] == "ACTIVE"
    assert AL.validate_work_unit_artifacts(
        scratch,
        project,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        actor="DRIVER",
    ) == []


@pytest.mark.parametrize(
    "root_length",
    (205, 210, 215, 220, 225, 230, 235, 240),
)
def test_full_successor_crosses_each_control_publication_boundary(
    tmp_path: Path,
    root_length: int,
) -> None:
    scratch = _long_root(tmp_path, root_length)
    _full_one_output_successor(scratch, tmp_path)


@pytest.mark.parametrize("descendant_length", (259, 260, 261))
def test_full_successor_publishes_exact_max_path_boundary_descendants(
    tmp_path: Path,
    descendant_length: int,
) -> None:
    output_name = "findings_inventory.md"
    scratch = _long_root(
        tmp_path,
        descendant_length - len(output_name) - 1,
    )
    assert len(os.fspath(scratch / output_name)) == descendant_length
    _full_one_output_successor(scratch, tmp_path)


def test_long_path_lock_identity_is_stable_and_reentrant(
    tmp_path: Path,
) -> None:
    scratch = _long_root(tmp_path, 240)
    alias = scratch / "." / "nested" / ".."
    with AL._ledger_transaction_lock(scratch, timeout_s=0.2):
        with AL._ledger_transaction_lock(alias, timeout_s=0.2):
            pass
    assert rooted_io.lexists(scratch / AL._LEDGER_LOCK_FILE)


def test_long_path_lock_contention_times_out_in_another_process(
    tmp_path: Path,
) -> None:
    scratch = _long_root(tmp_path, 240)
    scripts = Path(__file__).resolve().parent
    program = (
        "import pathlib,sys;"
        "sys.path.insert(0,sys.argv[2]);"
        "import artifact_ledger as a;"
        "\ntry:\n"
        "  with a._ledger_transaction_lock("
        "pathlib.Path(sys.argv[1]),timeout_s=0.15): pass\n"
        "except a.ArtifactLedgerError as exc:\n"
        "  sys.exit(0 if 'contention timed out' in str(exc) else 3)\n"
        "sys.exit(4)\n"
    )
    with AL._ledger_transaction_lock(scratch):
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                program,
                os.fspath(scratch),
                os.fspath(scripts),
            ],
            check=False,
            timeout=10,
        )
    assert completed.returncode == 0
    with AL._ledger_transaction_lock(scratch, timeout_s=0.2):
        pass


def test_long_path_interruption_cleans_temp_and_successor_resumes(
    tmp_path: Path,
) -> None:
    scratch = _long_root(tmp_path, 240)
    _full_one_output_successor(
        scratch,
        tmp_path,
        interrupt_apply_once=True,
    )


def test_long_path_control_replace_interruption_cleans_and_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = _long_root(tmp_path, 240)
    ledger = AL.read_artifact_ledger(scratch)

    def _interrupt(_source: Path, _destination: Path) -> None:
        raise OSError("simulated control publication interruption")

    with monkeypatch.context() as patcher:
        patcher.setattr(AL, "_durable_replace", _interrupt)
        with pytest.raises(
            OSError,
            match="control publication interruption",
        ):
            AL.write_artifact_ledger(scratch, ledger)
    assert not any(
        entry.name.startswith(".p.") and entry.name.endswith(".tmp")
        for entry in rooted_io.scandir(scratch)
    )
    AL.write_artifact_ledger(scratch, ledger)
    assert AL.read_artifact_ledger(scratch) == ledger


def test_long_path_lock_rejects_multiply_linked_file(
    tmp_path: Path,
) -> None:
    scratch = _long_root(tmp_path, 240)
    source = scratch / "lock-source"
    descriptor = os.open(
        rooted_io.native_path(source),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY,
        0o600,
    )
    os.write(descriptor, b"\0")
    os.close(descriptor)
    os.link(
        rooted_io.native_path(source),
        rooted_io.native_path(scratch / AL._LEDGER_LOCK_FILE),
    )
    with pytest.raises(
        AL.ArtifactLedgerError,
        match="single-link",
    ):
        with AL._ledger_transaction_lock(scratch):
            pass


def test_long_path_lock_rejects_reparse_root(
    tmp_path: Path,
) -> None:
    parent = _long_root(tmp_path, 230)
    real = parent / "real"
    rooted_io.mkdir(real)
    link = parent / "link"
    try:
        os.symlink(
            rooted_io.native_path(real),
            rooted_io.native_path(link),
            target_is_directory=True,
        )
    except OSError as exc:
        pytest.skip(f"directory symlink creation unavailable: {exc}")
    with pytest.raises(
        AL.ArtifactLedgerError,
        match="safe directory",
    ):
        with AL._ledger_transaction_lock(link):
            pass


def test_long_path_lock_rejects_case_aliased_root(
    tmp_path: Path,
) -> None:
    scratch = _long_root(tmp_path, 240)
    aliased = Path(
        os.fspath(scratch).replace("long-root", "LONG-ROOT")
    )
    assert os.path.normcase(os.fspath(aliased)) == os.path.normcase(
        os.fspath(scratch)
    )
    with pytest.raises(
        AL.ArtifactLedgerError,
        match="safe directory",
    ):
        with AL._ledger_transaction_lock(aliased):
            pass
