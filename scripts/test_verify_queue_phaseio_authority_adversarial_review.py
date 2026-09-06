"""Independent red contract for verify-queue PhaseIO commit authority.

The child status JSON files are useful resumability records, but they are not
an authority root.  A self-consistent status digest can be recomputed by the
same code that changes an output.  Consumption therefore requires an exact,
current-run PhaseIO/artifact-ledger commit for every T0..T9 child and for the
read-only parent.

This fixture intentionally requires one public validation seam:

``validate_verify_queue_transaction_authority(...) -> Sequence[str]``

An empty result means every child and the parent is ledger-committed under the
current pipeline/mode/ecosystem/backend/phase/run identity.  Any issue makes
the transaction non-consumable.  The validator must rederive contract, launch,
input, output, and commit authority from PhaseIO/the artifact ledger; status
JSON alone can never satisfy it.

Production is not modified by this review fixture.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any, Mapping, Sequence

import pytest

from artifact_ledger import (
    _commit_receipt_digest,
    _input_set_digest,
    read_artifact_ledger,
    write_artifact_ledger,
)
from phase_io_contracts import canonical_artifact_identity, canonical_work_unit_key
import test_verify_queue_child_transaction_b5_b7 as BASE


PIPELINE = "sc"
MODE = "thorough"
ECOSYSTEM = "evm"
BACKEND = "claude"
PHASE = "sc_verify_queue"
RUN_ID = "phaseio-authority-sc-claude"
FIXTURE_SHARD = "verification_queue_fixture.md"
RECEIPT_PATH = "verify_queue_transaction.receipt.json"


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _stable_digest(value: Mapping[str, Any]) -> str:
    return _digest(_canonical_bytes(value))


def _module():
    return BASE._load_sut()


def _plan(*, backend: str = BACKEND) -> Mapping[str, Any]:
    module = _module()
    return module.resolve_verify_queue_transaction_plan(
        pipeline=PIPELINE,
        mode=MODE,
        ecosystem=ECOSYSTEM,
        backend=backend,
        phase_name=PHASE,
        external_inputs=BASE.EXTERNAL_INPUTS,
        shard_manifests=(FIXTURE_SHARD,),
        context_capture=BASE.CONTEXT_CAPTURE_SPEC,
    )


def _seed(
    root: Path,
    *,
    backend: str = BACKEND,
    run_id: str = RUN_ID,
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    BASE._seed_upstream_group(
        root,
        pipeline=PIPELINE,
        backend=backend,
        phase="inventory",
        work_unit_id="paired_fixture",
        paths=("findings_inventory.md", "finding_records.json"),
        run_id=run_id,
    )
    BASE._seed_upstream_group(
        root,
        pipeline=PIPELINE,
        backend=backend,
        phase="preverify_fixture",
        work_unit_id="stable_successors",
        paths=(
            "preverify_inventory_successor.json",
            "finding_delivery_successor.json",
        ),
        run_id=run_id,
    )
    BASE._seed_upstream_group(
        root,
        pipeline=PIPELINE,
        backend=backend,
        phase="context_fixture",
        work_unit_id="exact_sources",
        paths=BASE.CONTEXT_INPUTS,
        run_id=run_id,
    )


def _execute(
    root: Path,
    *,
    backend: str = BACKEND,
    run_id: str = RUN_ID,
    executor: BASE._DeterministicChildExecutor | None = None,
    failpoint=None,
) -> tuple[Mapping[str, Any], BASE._DeterministicChildExecutor]:
    _seed(root, backend=backend, run_id=run_id)
    selected = executor or BASE._DeterministicChildExecutor()
    result = _module().execute_verify_queue_transaction(
        scratchpad=root,
        project_root=root.parent,
        plan=_plan(backend=backend),
        run_id=run_id,
        child_executor=selected,
        failpoint=failpoint,
    )
    assert isinstance(result, Mapping)
    return result, selected


def _unit_key(
    work_unit_id: str,
    *,
    backend: str = BACKEND,
) -> str:
    return canonical_work_unit_key(
        PIPELINE,
        MODE,
        ECOSYSTEM,
        backend,
        PHASE,
        work_unit_id,
    )


def _identity(relative: str) -> str:
    if relative.startswith("project::"):
        return canonical_artifact_identity(
            "project", relative[len("project::"):]
        )
    return canonical_artifact_identity("scratchpad", relative)


def _unit_by_id(
    plan: Mapping[str, Any],
    work_unit_id: str,
) -> Mapping[str, Any]:
    if work_unit_id == BASE.PARENT_ID:
        parent = plan.get("parent")
        assert isinstance(parent, Mapping)
        return parent
    return BASE._child_map(plan)[work_unit_id]


def _effective_expected_inputs(
    root: Path,
    planned: Mapping[str, Any],
) -> set[str]:
    values = {str(value) for value in planned.get("exact_inputs", ())}
    state_inputs = planned.get("delivery_state_exact_inputs")
    if isinstance(state_inputs, Mapping):
        t4_status = json.loads(
            (root / BASE.STATUS_PATHS[4]).read_text(
                encoding="utf-8", errors="strict"
            )
        )
        selected = state_inputs.get(str(t4_status.get("state") or ""))
        assert isinstance(selected, list)
        values.update(str(value) for value in selected)
    return {_identity(value) for value in values}


def _manifest_digest(manifest: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _assert_exact_committed_unit(
    root: Path,
    plan: Mapping[str, Any],
    work_unit_id: str,
    *,
    backend: str = BACKEND,
    run_id: str = RUN_ID,
) -> None:
    """Independently verify the minimum non-self-certifying ledger shape."""

    ledger = read_artifact_ledger(root)
    key = _unit_key(work_unit_id, backend=backend)
    unit = ledger.get("work_units", {}).get(key)
    assert isinstance(unit, Mapping), (
        f"{work_unit_id} has no current typed PhaseIO work unit; status JSON "
        "cannot replace ledger authority"
    )
    assert unit.get("schema") == "plamen.artifact-work-unit.v2"
    assert unit.get("work_unit_key") == key
    assert unit.get("run_id") == run_id
    assert unit.get("execution_state") == "OUTPUT_COMMITTED"
    assert unit.get("semantic_status") == "ACTIVE"

    manifest = unit.get("contract_manifest")
    assert isinstance(manifest, Mapping)
    assert manifest.get("key") == key
    assert unit.get("contract_digest") == _manifest_digest(manifest)
    assert (
        isinstance(unit.get("launch_digest"), str)
        and len(str(unit["launch_digest"])) == 64
    )

    planned = _unit_by_id(plan, work_unit_id)
    expected_outputs = {
        _identity(str(row["path"]))
        for row in planned.get("outputs", ())
    }
    manifest_outputs = manifest.get("outputs")
    assert isinstance(manifest_outputs, list)
    assert {
        str(row.get("identity") or "")
        for row in manifest_outputs
        if isinstance(row, Mapping)
    } == expected_outputs
    assert all(
        isinstance(row, Mapping) and row.get("owner_key") == key
        for row in manifest_outputs
    )

    expected_inputs = _effective_expected_inputs(root, planned)
    manifest_inputs = set(manifest.get("immutable_inputs") or ())
    assert not set(manifest.get("bounded_lookup_inputs") or ())
    assert manifest_inputs == expected_inputs
    input_bindings = unit.get("input_bindings")
    assert isinstance(input_bindings, Mapping)
    assert set(input_bindings) == expected_inputs
    assert unit.get("input_set_digest") == _input_set_digest(input_bindings)

    artifacts = unit.get("artifacts")
    assert isinstance(artifacts, Mapping)
    assert set(artifacts) == expected_outputs
    for identity, row in artifacts.items():
        assert isinstance(row, Mapping)
        assert row.get("owner_key") == key
        assert row.get("run_id") == run_id
        assert row.get("contract_digest") == unit.get("contract_digest")
        assert row.get("launch_digest") == unit.get("launch_digest")
        if row.get("status") != "ACTIVE":
            assert row.get("artifact_class") == "CONDITIONAL"
            assert row.get("status") == "MISSING"
            conditional = row.get("conditional_receipt")
            assert isinstance(conditional, Mapping)
            assert conditional.get("state") in {
                "NOT_TRIGGERED",
                "TRIGGERED_EMPTY",
            }
            continue
        artifact_root, relative = identity.split(":", 1)
        path = (
            root / relative
            if artifact_root == "scratchpad"
            else root.parent / relative
        )
        raw = path.read_bytes()
        assert row.get("sha256") == _digest(raw)
        assert row.get("size") == len(raw)
        binding = ledger.get("artifact_bindings", {}).get(identity)
        assert isinstance(binding, Mapping)
        assert binding.get("owner_key") == key
        assert binding.get("run_id") == run_id
        assert binding.get("sha256") == row.get("sha256")
        assert binding.get("size") == row.get("size")

    commit = unit.get("commit_authority")
    assert isinstance(commit, Mapping)
    # The shared artifact ledger's registered commit-authority schema is the
    # authoritative contract.  This fixture originally invented
    # ``plamen.artifact-commit-authority.v1``; accepting that nonexistent
    # spelling would make the review test disagree with every production
    # PhaseIO caller.
    assert commit.get("schema") == "plamen.artifact-output-commit.v1"
    assert commit.get("state") == "ACTIVE"
    assert commit.get("run_id") == run_id
    assert commit.get("work_unit_key") == key
    assert commit.get("contract_digest") == unit.get("contract_digest")
    assert commit.get("launch_digest") == unit.get("launch_digest")
    assert commit.get("input_set_digest") == unit.get("input_set_digest")
    assert commit.get("precommit_issue_count") == 0
    assert commit.get("reason_codes") == []
    assert commit.get("receipt_digest") == _commit_receipt_digest(commit)

    if work_unit_id != BASE.PARENT_ID:
        status_identity = _identity(
            BASE.STATUS_PATHS[BASE.CHILD_IDS.index(work_unit_id)]
        )
        assert status_identity in artifacts
        assert artifacts[status_identity].get("status") == "ACTIVE"


def _authority_issues(
    root: Path,
    *,
    plan: Mapping[str, Any] | None = None,
    run_id: str = RUN_ID,
) -> list[str]:
    validator = getattr(
        _module(), "validate_verify_queue_transaction_authority", None
    )
    assert callable(validator), (
        "verify_queue_transaction must expose a ledger-backed "
        "validate_verify_queue_transaction_authority seam; status JSON "
        "cannot be its own downstream proof"
    )
    issues = validator(
        scratchpad=root,
        project_root=root.parent,
        plan=plan or _plan(),
        run_id=run_id,
        require_parent_commit=True,
    )
    assert isinstance(issues, Sequence) and not isinstance(
        issues, (str, bytes)
    )
    return [str(issue) for issue in issues]


def _assert_non_consumable(
    root: Path,
    *,
    plan: Mapping[str, Any] | None = None,
    run_id: str = RUN_ID,
) -> None:
    assert _authority_issues(root, plan=plan, run_id=run_id), (
        "downstream consumption accepted a transaction without exact "
        "current-run child and parent PhaseIO commit authority"
    )
    ledger = read_artifact_ledger(root)
    parent = ledger.get("work_units", {}).get(_unit_key(BASE.PARENT_ID))
    assert not (
        isinstance(parent, Mapping)
        and parent.get("run_id") == run_id
        and parent.get("execution_state") == "OUTPUT_COMMITTED"
        and parent.get("semantic_status") == "ACTIVE"
    )


def _assert_clean_authority(
    root: Path,
    plan: Mapping[str, Any],
) -> None:
    for work_unit_id in (*BASE.CHILD_IDS, BASE.PARENT_ID):
        _assert_exact_committed_unit(root, plan, work_unit_id)
    assert _authority_issues(root, plan=plan) == []


def _resign_status(path: Path, mutate) -> None:
    payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    mutate(payload)
    unsigned = {
        key: value for key, value in payload.items()
        if key != "status_digest"
    }
    payload["status_digest"] = _stable_digest(unsigned)
    path.write_bytes(_canonical_bytes(payload))


def _copy_transaction_state(
    source: Path,
    destination: Path,
    plan: Mapping[str, Any],
) -> None:
    for child in BASE._children(plan):
        for row in BASE._output_rows(child):
            relative = str(row["path"])
            source_path = source / relative
            destination_path = destination / relative
            if not source_path.is_file():
                destination_path.unlink(missing_ok=True)
                continue
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, destination_path)
    write_artifact_ledger(
        destination,
        copy.deepcopy(read_artifact_ledger(source)),
    )


def _transaction_public_destinations() -> tuple[str, ...]:
    plan = _plan()
    t9 = BASE._child_map(plan)[BASE.CHILD_IDS[9]]
    return tuple(sorted(
        path
        for path in BASE._output_paths(t9)
        if path != BASE.STATUS_PATHS[9]
    ))


PUBLIC_DESTINATIONS = _transaction_public_destinations()


def test_clean_statuses_do_not_replace_exact_child_and_parent_commits(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    plan = _plan()
    result, _executor = _execute(root)

    assert result["parent_commit"]["state"] == "OUTPUT_COMMITTED"
    _assert_clean_authority(root, plan)


def test_forged_self_consistent_status_and_output_are_not_authority(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    plan = _plan()
    _execute(root)
    child_id = BASE.CHILD_IDS[2]
    unit = BASE._child_map(plan)[child_id]
    target = next(
        path
        for path in sorted(BASE._output_paths(unit))
        if path != BASE.STATUS_PATHS[2]
    )
    forged = b'{"forged":"self-consistent-status-is-not-authority"}\n'
    (root / target).write_bytes(forged)

    def mutate(payload: dict[str, Any]) -> None:
        payload["output_digests"][target] = _digest(forged)

    _resign_status(root / BASE.STATUS_PATHS[2], mutate)

    assert _authority_issues(root, plan=plan)


@pytest.mark.parametrize(
    ("foreign_backend", "foreign_run"),
    (
        ("codex", RUN_ID),
        (BACKEND, "phaseio-authority-foreign-run"),
    ),
    ids=("cross-backend-owner", "cross-run-owner"),
)
def test_foreign_complete_transaction_owner_is_not_current_authority(
    tmp_path: Path,
    foreign_backend: str,
    foreign_run: str,
) -> None:
    current = tmp_path / "current" / ".scratchpad"
    foreign = tmp_path / "foreign" / ".scratchpad"
    current_plan = _plan()
    foreign_plan = _plan(backend=foreign_backend)
    _execute(current)
    _execute(
        foreign,
        backend=foreign_backend,
        run_id=foreign_run,
    )
    _copy_transaction_state(foreign, current, foreign_plan)

    assert _authority_issues(
        current,
        plan=current_plan,
        run_id=RUN_ID,
    )


@pytest.mark.parametrize(
    "damage",
    ("missing-child", "missing-commit", "missing-output-binding"),
)
def test_partial_or_malformed_ledger_is_not_consumable(
    tmp_path: Path,
    damage: str,
) -> None:
    root = tmp_path / ".scratchpad"
    plan = _plan()
    _execute(root)
    ledger = read_artifact_ledger(root)
    child_id = BASE.CHILD_IDS[5]
    key = _unit_key(child_id)
    unit = ledger["work_units"].get(key)
    assert isinstance(unit, dict), (
        "fixture precondition: clean execution must create the child ledger "
        "unit before the adversarial mutation"
    )
    if damage == "missing-child":
        ledger["work_units"].pop(key)
    elif damage == "missing-commit":
        unit.pop("commit_authority", None)
    else:
        identity = next(iter(unit.get("artifacts") or ()))
        ledger["artifact_bindings"].pop(identity, None)
    write_artifact_ledger(root, ledger)

    assert _authority_issues(root, plan=plan)


def test_post_commit_output_mutation_is_not_consumable(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    plan = _plan()
    _execute(root)
    target = BASE.T6_OUTPUTS[0]
    with (root / target).open("ab") as stream:
        stream.write(b"\npost-commit mutation\n")

    assert _authority_issues(root, plan=plan)


def test_parent_in_memory_mapping_cannot_self_certify_commit(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    plan = _plan()
    result, _executor = _execute(root)
    assert result["parent_commit"] == {
        "work_unit_id": BASE.PARENT_ID,
        "state": "OUTPUT_COMMITTED",
        "outputs": [],
        "read_only": True,
    }

    ledger = read_artifact_ledger(root)
    ledger.get("work_units", {}).pop(_unit_key(BASE.PARENT_ID), None)
    write_artifact_ledger(root, ledger)

    _assert_non_consumable(root, plan=plan)


def test_downstream_refuses_before_t9_and_parent_output_committed(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    plan = _plan()

    def failpoint(label: str) -> None:
        if label == "after_t8_commit":
            raise RuntimeError("fixture stop before T9")

    with pytest.raises(RuntimeError, match="before T9"):
        _execute(root, failpoint=failpoint)

    ledger = read_artifact_ledger(root)
    for work_unit_id in (BASE.CHILD_IDS[9], BASE.PARENT_ID):
        unit = ledger.get("work_units", {}).get(_unit_key(work_unit_id))
        assert not (
            isinstance(unit, Mapping)
            and unit.get("execution_state") == "OUTPUT_COMMITTED"
            and unit.get("semantic_status") == "ACTIVE"
        )
    _assert_non_consumable(root, plan=plan)


@pytest.mark.parametrize("destination", PUBLIC_DESTINATIONS)
def test_each_t9_destination_write_crash_is_nonconsumable_and_resumable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    destination: str,
) -> None:
    root = tmp_path / ".scratchpad"
    plan = _plan()
    module = _module()
    original_atomic = module._atomic_write
    fired = False

    def crash_after_destination(path: Path, raw: bytes) -> None:
        nonlocal fired
        original_atomic(path, raw)
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            relative = ""
        if relative == destination and not fired:
            fired = True
            raise RuntimeError("fixture destination-write crash")

    monkeypatch.setattr(module, "_atomic_write", crash_after_destination)
    with pytest.raises(RuntimeError, match="destination-write crash"):
        _execute(root)
    assert fired is True
    _assert_non_consumable(root, plan=plan)

    monkeypatch.setattr(module, "_atomic_write", original_atomic)
    resumed, _executor = _execute(root)
    assert resumed["parent_commit"]["state"] == "OUTPUT_COMMITTED"
    _assert_clean_authority(root, plan)


@pytest.mark.parametrize("destination", PUBLIC_DESTINATIONS)
def test_each_t9_destination_uses_absence_cas_and_preserves_foreign_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    destination: str,
) -> None:
    root = tmp_path / ".scratchpad"
    plan = _plan()
    module = _module()
    original_atomic = module._atomic_write
    foreign = b"FOREIGN-CONCURRENT-DESTINATION\n"
    injected = False

    def inject_before_destination(path: Path, raw: bytes) -> None:
        nonlocal injected
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            relative = ""
        if relative == destination and not injected:
            injected = True
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(foreign)
        original_atomic(path, raw)

    monkeypatch.setattr(module, "_atomic_write", inject_before_destination)
    try:
        result, _executor = _execute(root)
    except Exception:
        result = {}
    assert injected is True
    assert (root / destination).read_bytes() == foreign, (
        f"T9 overwrote a concurrent foreign destination instead of failing "
        f"its absence compare-and-swap: {destination}"
    )
    assert (
        not isinstance(result, Mapping)
        or result.get("parent_commit", {}).get("state") != "OUTPUT_COMMITTED"
    )
    _assert_non_consumable(root, plan=plan)


def test_t9_receipt_is_last_and_a_receipt_write_crash_is_not_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / ".scratchpad"
    plan = _plan()
    module = _module()
    original_atomic = module._atomic_write
    receipt_written = False
    destinations_before_receipt: set[str] = set()

    def crash_after_receipt(path: Path, raw: bytes) -> None:
        nonlocal receipt_written
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            relative = ""
        if (
            relative in PUBLIC_DESTINATIONS
            and relative != RECEIPT_PATH
        ):
            destinations_before_receipt.add(relative)
        original_atomic(path, raw)
        if relative == RECEIPT_PATH and not receipt_written:
            receipt_written = True
            assert destinations_before_receipt == (
                set(PUBLIC_DESTINATIONS) - {RECEIPT_PATH}
            ), "transaction receipt was written before all destinations"
            raise RuntimeError("fixture receipt-last crash")

    monkeypatch.setattr(module, "_atomic_write", crash_after_receipt)
    with pytest.raises(RuntimeError, match="receipt-last crash"):
        _execute(root)
    assert receipt_written is True
    _assert_non_consumable(root, plan=plan)

    ledger = read_artifact_ledger(root)
    for work_unit_id in (BASE.CHILD_IDS[9], BASE.PARENT_ID):
        unit = ledger.get("work_units", {}).get(_unit_key(work_unit_id))
        assert not (
            isinstance(unit, Mapping)
            and unit.get("execution_state") == "OUTPUT_COMMITTED"
            and unit.get("semantic_status") == "ACTIVE"
        )

    monkeypatch.setattr(module, "_atomic_write", original_atomic)
    resumed, _executor = _execute(root)
    assert resumed["parent_commit"]["state"] == "OUTPUT_COMMITTED"
    _assert_clean_authority(root, plan)
