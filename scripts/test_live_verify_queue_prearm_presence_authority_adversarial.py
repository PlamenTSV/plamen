"""Adversarial contract for explicit pre-T0 presence authority.

The caller supplies an exact static/dynamic roster.  The provider must not
glob or enumerate directories.  Every roster identity is frozen as either:

* PRESENT: exact bytes plus current-run producer owner/writer/contract/launch;
* ABSENT: an explicit state in the same content-addressed denominator.

T0 output/status prose is never authority for this snapshot.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_inputs,
)
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract
from verify_queue_phaseio_authority import (
    arm_transaction_unit,
    commit_transaction_unit,
)


AUTHORITY_PATH = "prearm_presence_authority.json"
PRESENT_PATH = "inputs/present-authority.json"
DYNAMIC_PATH = "inputs/dynamic-authority.json"
ABSENT_PATH = "inputs/optional-absent.json"
T0_STATUS = "_live_verify_queue_transaction/t0/status.json"
T0_ROSTER = "_live_verify_queue_transaction/t0/input_presence_roster.json"
CASES = (
    ("sc", "evm", "sc_verify_queue", "claude"),
    ("sc", "evm", "sc_verify_queue", "codex"),
    ("l1", "rust", "verify_queue", "claude"),
    ("l1", "rust", "verify_queue", "codex"),
)


def _module():
    try:
        module = importlib.import_module("live_verify_queue_prearm_inputs")
    except ImportError as exc:
        pytest.fail(
            "live_verify_queue_prearm_inputs.py is absent; explicit absence "
            "cannot be authority-bound before T0",
            pytrace=False,
        )
    for name in (
        "capture_prearm_presence_authority",
        "validate_prearm_presence_authority",
        "prearm_effective_input_paths",
    ):
        assert callable(getattr(module, name, None)), (
            f"prearm presence provider lacks required seam {name}"
        )
    return module


def _canonical_bytes(value: Any) -> bytes:
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


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _dims(
    pipeline: str,
    ecosystem: str,
    phase_name: str,
    backend: str,
) -> dict[str, str]:
    return {
        "pipeline": pipeline,
        "mode": "thorough",
        "ecosystem": ecosystem,
        "backend": backend,
        "phase_name": phase_name,
        "run_id": f"presence-{pipeline}-{backend}",
    }


def _producer(
    root: Path,
    project: Path,
    *,
    dims: Mapping[str, str],
    paths: Sequence[str],
    work_unit_id: str,
    run_id: str | None = None,
) -> tuple[PhaseIOContract, LaunchSpec]:
    phase = "preverify_fixture"
    contract = PhaseIOContract(
        pipeline=dims["pipeline"],
        mode=dims["mode"],
        ecosystem=dims["ecosystem"],
        backend=dims["backend"],
        phase=phase,
        work_unit_id=work_unit_id,
        outputs=tuple(ArtifactSpec(
            root="scratchpad",
            path=path,
            owner_key=(
                f"{dims['pipeline']}/{dims['mode']}/{dims['ecosystem']}/"
                f"{dims['backend']}/{phase}/{work_unit_id}"
            ),
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="CREATE",
            schema_version="fixture.prearm-presence-source.v1",
            minimum_gate="STRUCTURAL",
            consumers=(
                f"{dims['phase_name']}/t0.live_upstream_authority",
            ),
        ) for path in paths),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=60,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    selected_run = run_id or dims["run_id"]
    record_work_unit_inputs(
        root, project, contract, launch, run_id=selected_run
    )
    for relative in paths:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_canonical_bytes({"source": relative}))
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=selected_run,
        actor="DRIVER",
    )
    return contract, launch


def _capture(
    root: Path,
    project: Path,
    dims: Mapping[str, str],
    *,
    roster: Sequence[str] = (
        PRESENT_PATH,
        DYNAMIC_PATH,
        ABSENT_PATH,
    ),
) -> Mapping[str, Any]:
    return _module().capture_prearm_presence_authority(
        scratchpad=root,
        project_root=project,
        pipeline=dims["pipeline"],
        mode=dims["mode"],
        ecosystem=dims["ecosystem"],
        backend=dims["backend"],
        phase_name=dims["phase_name"],
        run_id=dims["run_id"],
        roster=tuple(roster),
        authority_identity="scratchpad:" + AUTHORITY_PATH,
    )


def _validate(
    root: Path,
    project: Path,
    dims: Mapping[str, str],
    authority: Mapping[str, Any],
) -> list[str]:
    issues = _module().validate_prearm_presence_authority(
        scratchpad=root,
        project_root=project,
        pipeline=dims["pipeline"],
        mode=dims["mode"],
        ecosystem=dims["ecosystem"],
        backend=dims["backend"],
        phase_name=dims["phase_name"],
        run_id=dims["run_id"],
        authority_identity="scratchpad:" + AUTHORITY_PATH,
        authority=authority,
    )
    assert isinstance(issues, Sequence) and not isinstance(
        issues, (str, bytes)
    )
    return [str(issue) for issue in issues]


def _seed_roster(
    root: Path,
    project: Path,
    dims: Mapping[str, str],
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    _producer(
        root,
        project,
        dims=dims,
        paths=(PRESENT_PATH, DYNAMIC_PATH),
        work_unit_id="roster_sources",
    )


def _commit_authority(
    root: Path,
    project: Path,
    dims: Mapping[str, str],
    authority: Mapping[str, Any],
    *,
    run_id: str | None = None,
) -> None:
    phase = "preverify_fixture"
    work = "presence_authority"
    contract = PhaseIOContract(
        pipeline=dims["pipeline"],
        mode=dims["mode"],
        ecosystem=dims["ecosystem"],
        backend=dims["backend"],
        phase=phase,
        work_unit_id=work,
        outputs=(ArtifactSpec(
            root="scratchpad",
            path=AUTHORITY_PATH,
            owner_key=(
                f"{dims['pipeline']}/{dims['mode']}/{dims['ecosystem']}/"
                f"{dims['backend']}/{phase}/{work}"
            ),
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="CREATE",
            schema_version="plamen.prearm_presence_authority.v1",
            minimum_gate="EXACT_ROSTER_PRESENCE_AND_PRODUCER_AUTHORITY",
            consumers=(
                f"{dims['phase_name']}/t0.live_upstream_authority",
            ),
        ),),
        immutable_inputs=tuple(
            row["identity"]
            for row in authority["entries"]
            if row["state"] == "PRESENT"
        ),
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=60,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    selected_run = run_id or dims["run_id"]
    record_work_unit_inputs(
        root, project, contract, launch, run_id=selected_run
    )
    (root / AUTHORITY_PATH).write_bytes(_canonical_bytes(authority))
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=selected_run,
        actor="DRIVER",
    )


@pytest.mark.parametrize(
    "pipeline,ecosystem,phase_name,backend",
    CASES,
)
def test_complete_static_dynamic_roster_has_explicit_presence_authority(
    tmp_path: Path,
    pipeline: str,
    ecosystem: str,
    phase_name: str,
    backend: str,
) -> None:
    dims = _dims(pipeline, ecosystem, phase_name, backend)
    root = tmp_path / ".scratchpad"
    _seed_roster(root, tmp_path, dims)
    authority = _capture(root, tmp_path, dims)
    _commit_authority(root, tmp_path, dims, authority)

    assert authority["schema_version"] == (
        "plamen.prearm_presence_authority.v1"
    )
    assert {
        key: authority[key]
        for key in (
            "pipeline",
            "mode",
            "ecosystem",
            "backend",
            "phase_name",
            "run_id",
        )
    } == dims
    assert authority["content_addressed"] is True
    assert authority["caller_supplied_exact_roster"] is True
    assert authority["live_glob_allowed"] is False
    assert authority["live_directory_enumeration_allowed"] is False
    assert authority["roster_count"] == 3
    assert authority["roster_identities"] == sorted([
        "scratchpad:" + PRESENT_PATH,
        "scratchpad:" + DYNAMIC_PATH,
        "scratchpad:" + ABSENT_PATH,
    ])
    assert authority["roster_identity_digest"] == _sha(_canonical_bytes(
        authority["roster_identities"]
    ))
    directory_rows = authority["directory_roster"]
    assert directory_rows == [{
        "root": "scratchpad",
        "directory": "inputs",
        "member_identities": sorted([
            "scratchpad:" + PRESENT_PATH,
            "scratchpad:" + DYNAMIC_PATH,
            "scratchpad:" + ABSENT_PATH,
        ]),
        "member_identity_digest": _sha(_canonical_bytes(sorted([
            "scratchpad:" + PRESENT_PATH,
            "scratchpad:" + DYNAMIC_PATH,
            "scratchpad:" + ABSENT_PATH,
        ]))),
    }]
    assert authority["directory_roster_digest"] == _sha(
        _canonical_bytes(directory_rows)
    )

    rows = {row["identity"]: row for row in authority["entries"]}
    absent = rows["scratchpad:" + ABSENT_PATH]
    assert absent == {
        "identity": "scratchpad:" + ABSENT_PATH,
        "state": "ABSENT",
    }
    for relative in (PRESENT_PATH, DYNAMIC_PATH):
        row = rows["scratchpad:" + relative]
        binding = read_artifact_ledger(root)["artifact_bindings"][
            "scratchpad:" + relative
        ]
        assert row["state"] == "PRESENT"
        assert row["sha256"] == _sha((root / relative).read_bytes())
        assert row["size"] == (root / relative).stat().st_size
        assert row["producer"] == {
            key: binding[key]
            for key in (
                "owner_key",
                "writer",
                "run_id",
                "contract_digest",
                "launch_digest",
            )
        }
    assert _validate(root, tmp_path, dims, authority) == []
    assert set(_module().prearm_effective_input_paths(authority)) == {
        PRESENT_PATH,
        DYNAMIC_PATH,
        AUTHORITY_PATH,
    }


def test_t0_status_or_roster_output_cannot_self_certify_absence(
    tmp_path: Path,
) -> None:
    dims = _dims("sc", "evm", "sc_verify_queue", "claude")
    root = tmp_path / ".scratchpad"
    _seed_roster(root, tmp_path, dims)
    authority = _capture(root, tmp_path, dims)
    # Materialize the authority and self-consistent T0 prose without the
    # authority artifact's PhaseIO producer commit.
    (root / AUTHORITY_PATH).write_bytes(_canonical_bytes(authority))
    for relative in (T0_STATUS, T0_ROSTER):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_canonical_bytes({
            "state": "OUTPUT_COMMITTED",
            "safe_to_consume": True,
            "absent": ["scratchpad:" + ABSENT_PATH],
            "authority_digest": authority["authority_digest"],
        }))

    issues = _validate(root, tmp_path, dims, authority)
    assert issues
    assert any(
        "producer" in issue.lower()
        or "phaseio" in issue.lower()
        or "commit" in issue.lower()
        for issue in issues
    )


@pytest.mark.parametrize(
    "boundary",
    ("capture-to-arm", "arm-to-semantic", "semantic-to-commit"),
)
@pytest.mark.parametrize(
    "drift",
    ("absent-appears", "present-content", "present-disappears"),
)
def test_revalidation_rejects_roster_drift_at_every_boundary(
    tmp_path: Path,
    boundary: str,
    drift: str,
) -> None:
    dims = _dims("sc", "evm", "sc_verify_queue", "codex")
    root = tmp_path / ".scratchpad"
    _seed_roster(root, tmp_path, dims)
    authority = _capture(root, tmp_path, dims)
    _commit_authority(root, tmp_path, dims, authority)
    assert _validate(root, tmp_path, dims, authority) == []

    if drift == "absent-appears":
        (root / ABSENT_PATH).write_bytes(b"late appearance\n")
    elif drift == "present-content":
        (root / PRESENT_PATH).write_bytes(b"changed after capture\n")
    else:
        (root / PRESENT_PATH).unlink()

    # The same validation seam is required immediately before T0 arm and
    # again after semantic execution immediately before T0 commit.
    boundary_issues = _validate(root, tmp_path, dims, authority)
    assert boundary_issues, (
        f"prearm presence drift was accepted at {boundary}"
    )
    assert any(
        token in issue.lower()
        for issue in boundary_issues
        for token in ("drift", "presence", "absent", "hash", "missing")
    )


@pytest.mark.parametrize(
    "pipeline,ecosystem,phase_name,backend",
    CASES,
)
def test_current_t0_commit_cannot_ignore_late_optional_appearance(
    tmp_path: Path,
    pipeline: str,
    ecosystem: str,
    phase_name: str,
    backend: str,
) -> None:
    """Directly demonstrates the current unbound-absence failure."""

    dims = _dims(pipeline, ecosystem, phase_name, backend)
    root = tmp_path / ".scratchpad"
    _seed_roster(root, tmp_path, dims)
    plan = dict(dims)
    t0 = {
        "work_unit_id": "t0.live_upstream_authority",
        "exact_inputs": [PRESENT_PATH, DYNAMIC_PATH, ABSENT_PATH],
        "declared_input_denominator": [
            PRESENT_PATH, DYNAMIC_PATH, ABSENT_PATH,
        ],
        "required_inputs": [PRESENT_PATH, DYNAMIC_PATH],
        "presence_roster": [ABSENT_PATH],
        "outputs": [
            {
                "path": T0_ROSTER,
                "root": "scratchpad",
                "artifact_class": "DRIVER_GENERATED",
                "writer": "DRIVER",
                "write_mode": "CREATE",
            },
            {
                "path": T0_STATUS,
                "root": "scratchpad",
                "artifact_class": "DRIVER_GENERATED",
                "writer": "DRIVER",
                "write_mode": "CREATE",
            },
        ],
        "producer_binding_policy": {
            "owner": True,
            "writer": True,
            "run_id": True,
            "contract_digest": True,
            "launch_digest": True,
            "sha256": True,
            "size": True,
            "explicit_absence": True,
        },
    }
    execute, issues, contract, launch = arm_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        plan=plan,
        unit=t0,
        run_id=dims["run_id"],
    )
    assert execute is True
    assert issues == []
    # Appearance occurs after PhaseIO arm but before semantic execution.
    (root / ABSENT_PATH).write_bytes(b"late appearance\n")
    for relative in (T0_ROSTER, T0_STATUS):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_canonical_bytes({
            "state": "OUTPUT_COMMITTED",
            "absent": ["scratchpad:" + ABSENT_PATH],
        }))
    commit_issues = commit_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id=dims["run_id"],
    )
    assert commit_issues, (
        "T0 committed a stale explicit-absence claim after the absent file "
        "appeared between arm and commit"
    )


def test_downstream_authority_rejects_optional_appearance_after_commit(
    tmp_path: Path,
) -> None:
    dims = _dims("sc", "evm", "sc_verify_queue", "claude")
    root = tmp_path / ".scratchpad"
    _seed_roster(root, tmp_path, dims)
    plan = dict(dims)
    unit = {
        "work_unit_id": "t0.live_upstream_authority",
        "exact_inputs": [PRESENT_PATH, DYNAMIC_PATH, ABSENT_PATH],
        "declared_input_denominator": [
            PRESENT_PATH, DYNAMIC_PATH, ABSENT_PATH,
        ],
        "required_inputs": [PRESENT_PATH, DYNAMIC_PATH],
        "presence_roster": [ABSENT_PATH],
        "outputs": [
            {
                "path": T0_ROSTER,
                "root": "scratchpad",
                "artifact_class": "DRIVER_GENERATED",
                "writer": "DRIVER",
                "write_mode": "CREATE",
            },
            {
                "path": T0_STATUS,
                "root": "scratchpad",
                "artifact_class": "DRIVER_GENERATED",
                "writer": "DRIVER",
                "write_mode": "CREATE",
            },
        ],
        "producer_binding_policy": {
            "owner": True,
            "writer": True,
            "run_id": True,
            "contract_digest": True,
            "launch_digest": True,
            "sha256": True,
            "size": True,
            "explicit_absence": True,
        },
    }
    execute, issues, contract, launch = arm_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        plan=plan,
        unit=unit,
        run_id=dims["run_id"],
    )
    assert execute and not issues
    for relative in (T0_ROSTER, T0_STATUS):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_canonical_bytes({"state": "OUTPUT_COMMITTED"}))
    assert not commit_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id=dims["run_id"],
    )
    assert not validate_work_unit_inputs(
        root,
        tmp_path,
        contract,
        launch,
        run_id=dims["run_id"],
    )

    (root / ABSENT_PATH).write_bytes(b"appeared after commit\n")
    downstream_issues = validate_work_unit_inputs(
        root,
        tmp_path,
        contract,
        launch,
        run_id=dims["run_id"],
    )
    assert downstream_issues
    assert any(
        "absence" in issue.lower() or "appeared" in issue.lower()
        for issue in downstream_issues
    )


def test_present_input_drift_is_already_rejected_by_phaseio(
    tmp_path: Path,
) -> None:
    dims = _dims("l1", "rust", "verify_queue", "claude")
    root = tmp_path / ".scratchpad"
    _seed_roster(root, tmp_path, dims)
    plan = dict(dims)
    unit = {
        "work_unit_id": "t0.live_upstream_authority",
        "exact_inputs": [PRESENT_PATH],
        "declared_input_denominator": [PRESENT_PATH],
        "required_inputs": [PRESENT_PATH],
        "presence_roster": [],
        "outputs": [{
            "path": T0_STATUS,
            "root": "scratchpad",
            "artifact_class": "DRIVER_GENERATED",
            "writer": "DRIVER",
            "write_mode": "CREATE",
        }],
        "producer_binding_policy": {
            "owner": True,
            "writer": True,
            "run_id": True,
            "contract_digest": True,
            "launch_digest": True,
            "sha256": True,
            "size": True,
            "explicit_absence": True,
        },
    }
    execute, issues, contract, launch = arm_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        plan=plan,
        unit=unit,
        run_id=dims["run_id"],
    )
    assert execute and not issues
    (root / PRESENT_PATH).write_bytes(b"drift\n")
    (root / T0_STATUS).parent.mkdir(parents=True, exist_ok=True)
    (root / T0_STATUS).write_bytes(b"{}\n")
    assert commit_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id=dims["run_id"],
    )


def test_presence_capture_never_globs_or_enumerates_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dims = _dims("sc", "evm", "sc_verify_queue", "claude")
    root = tmp_path / ".scratchpad"
    _seed_roster(root, tmp_path, dims)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("prearm presence capture enumerated live state")

    monkeypatch.setattr(Path, "glob", forbidden)
    monkeypatch.setattr(Path, "rglob", forbidden)
    monkeypatch.setattr(Path, "iterdir", forbidden)
    monkeypatch.setattr(os, "scandir", forbidden)

    authority = _capture(root, tmp_path, dims)
    assert authority["live_glob_allowed"] is False
    assert authority["live_directory_enumeration_allowed"] is False


@pytest.mark.parametrize(
    "unsafe",
    (
        "../escape.json",
        "inputs/*.json",
        "C:/absolute.json",
        "/absolute.json",
        "project::../escape.json",
    ),
)
def test_unsafe_roster_identity_is_rejected(
    tmp_path: Path,
    unsafe: str,
) -> None:
    dims = _dims("l1", "rust", "verify_queue", "codex")
    root = tmp_path / ".scratchpad"
    root.mkdir()
    with pytest.raises((ValueError, OSError), match="unsafe|canonical|path|identity"):
        _capture(root, tmp_path, dims, roster=(unsafe,))


def test_symlink_or_reparse_roster_member_is_rejected(
    tmp_path: Path,
) -> None:
    dims = _dims("sc", "evm", "sc_verify_queue", "codex")
    root = tmp_path / ".scratchpad"
    root.mkdir()
    target = root / "target.json"
    target.write_bytes(b"target\n")
    link = root / "linked.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("host cannot create a symlink/reparse-point fixture")

    with pytest.raises(
        (ValueError, OSError),
        match="symlink|reparse|unsafe|physical",
    ):
        _capture(root, tmp_path, dims, roster=("linked.json",))


def test_byte_exact_resume_reuses_authority_and_drift_never_rebases(
    tmp_path: Path,
) -> None:
    dims = _dims("l1", "rust", "verify_queue", "codex")
    root = tmp_path / ".scratchpad"
    _seed_roster(root, tmp_path, dims)
    first = _capture(root, tmp_path, dims)
    second = _capture(root, tmp_path, dims)
    assert first == second
    assert first["authority_digest"] == second["authority_digest"]
    _commit_authority(root, tmp_path, dims, first)
    assert _validate(root, tmp_path, dims, first) == []

    (root / ABSENT_PATH).write_bytes(b"appeared during resume\n")
    assert _validate(root, tmp_path, dims, first)
    assert _module().prearm_effective_input_paths(first) == (
        PRESENT_PATH,
        DYNAMIC_PATH,
        AUTHORITY_PATH,
    )


def test_foreign_run_presence_manifest_is_not_t0_authority(
    tmp_path: Path,
) -> None:
    dims = _dims("sc", "evm", "sc_verify_queue", "claude")
    root = tmp_path / ".scratchpad"
    _seed_roster(root, tmp_path, dims)
    authority = _capture(root, tmp_path, dims)
    _commit_authority(
        root,
        tmp_path,
        dims,
        authority,
        run_id="foreign-presence-run",
    )

    issues = _validate(root, tmp_path, dims, authority)
    assert issues
    assert any("run" in issue.lower() or "producer" in issue.lower() for issue in issues)
