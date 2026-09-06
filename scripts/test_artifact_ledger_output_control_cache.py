"""Focused regressions for invocation-local output-authority control reuse."""

from __future__ import annotations

import os
from pathlib import Path
import copy
import pytest

import artifact_ledger as A


def _controls(tmp_path: Path) -> tuple[Path, Path, str, dict[str, object]]:
    scratchpad = tmp_path / ".scratchpad"
    project = tmp_path / "project"
    scratchpad.mkdir(parents=True)
    project.mkdir()
    unsigned: dict[str, object] = {
        "schema": "test.output-authority-cas.v1",
        "value": 1,
    }
    digest = A._canonical_json_digest(unsigned)
    A._write_once_output_authority_cas(
        scratchpad,
        authority_digest=digest,
        unsigned_authority=unsigned,
    )
    A._write_output_authority_ledger(
        scratchpad,
        {
            "schema": A._OUTPUT_AUTHORITY_LEDGER_SCHEMA,
            "authorities": {},
        },
    )
    return scratchpad, project, digest, unsigned


def _valid_output_authority(
    run_id: str,
    work_unit_key: str,
    attempt_ordinal: int,
) -> tuple[str, dict[str, object], dict[str, object]]:
    key = A._output_authority_key(
        run_id=run_id,
        work_unit_key=work_unit_key,
        attempt_ordinal=attempt_ordinal,
    )
    identity = f"scratchpad:artifact-{attempt_ordinal}.md"
    record = {
        "sha256": "0" * 64,
        "size": attempt_ordinal,
    }
    unsigned: dict[str, object] = {
        "schema": A._OUTPUT_AUTHORITY_SCHEMA,
        "authority_key": key,
        "state": "ACTIVE",
        "source": "LEGACY_DESCRIPTOR_CAPTURE",
        "run_id": run_id,
        "work_unit_key": work_unit_key,
        "contract_digest": "1" * 64,
        "launch_digest": "2" * 64,
        "input_set_digest": "3" * 64,
        "attempt_ordinal": attempt_ordinal,
        "quarantine_recovery_history_count": 0,
        "quarantine_recovery_history_head_digest": "",
        "actor": "MODEL",
        "physical_policy": A._NO_FOLLOW_PHYSICAL_POLICY,
        "expected_output_records": {identity: record},
        "observed_outputs": {
            identity: {
                "status": "PRESENT",
                "size": attempt_ordinal,
                "sha256": "0" * 64,
                "physical_identity": f"file:1:{attempt_ordinal}",
                "physical_policy": A._NO_FOLLOW_PHYSICAL_POLICY,
            },
        },
        "reason_codes": [],
    }
    authority = {
        **unsigned,
        "authority_digest": A._canonical_json_digest(unsigned),
    }
    return key, authority, unsigned


def _write_authority_set(
    scratchpad: Path,
    authorities: list[dict[str, object]],
) -> None:
    for authority in authorities:
        digest = str(authority["authority_digest"])
        unsigned = {
            key: value
            for key, value in authority.items()
            if key != "authority_digest"
        }
        A._write_once_output_authority_cas(
            scratchpad,
            authority_digest=digest,
            unsigned_authority=unsigned,
        )
    A._write_output_authority_ledger(
        scratchpad,
        {
            "schema": A._OUTPUT_AUTHORITY_LEDGER_SCHEMA,
            "authorities": {
                str(authority["authority_key"]): authority
                for authority in authorities
            },
        },
    )


def test_validation_epoch_reads_each_control_once_and_terminally_rejoins(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratchpad, project, digest, unsigned = _controls(tmp_path)
    cas_reads = 0
    journal_reads = 0
    real_cas = A._read_output_authority_cas
    real_journal = A._read_output_authority_ledger_with_raw

    def counted_cas(root: Path, requested: str):
        nonlocal cas_reads
        cas_reads += 1
        return real_cas(root, requested)

    def counted_journal(root: Path):
        nonlocal journal_reads
        journal_reads += 1
        return real_journal(root)

    monkeypatch.setattr(A, "_read_output_authority_cas", counted_cas)
    monkeypatch.setattr(
        A,
        "_read_output_authority_ledger_with_raw",
        counted_journal,
    )
    context = A._ArtifactValidationContext(scratchpad, project)

    first_cas = context.output_authority_cas(digest)
    first_journal = context.output_authority_journal()
    first_cas["value"] = "caller mutation"
    first_journal["authorities"]["forged"] = {}

    assert context.output_authority_cas(digest) == unsigned
    assert context.output_authority_journal() == {
        "schema": A._OUTPUT_AUTHORITY_LEDGER_SCHEMA,
        "authorities": {},
    }
    assert (cas_reads, journal_reads) == (1, 1)
    assert context.finish() == []


def test_output_authority_projection_reauthenticates_every_final_cas(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    authorities = [
        _valid_output_authority("run-cache", "unit-cache", ordinal)[1]
        for ordinal in range(1, 6)
    ]
    _write_authority_set(scratchpad, authorities)

    stable_reads: list[Path] = []
    real_read = A._read_stable_regular_bytes_in_bound_directory

    def counted_read(path: Path, **kwargs):
        stable_reads.append(Path(path))
        return real_read(path, **kwargs)

    monkeypatch.setattr(
        A,
        "_read_stable_regular_bytes_in_bound_directory",
        counted_read,
    )
    A._plan_output_authority_reconciliation(scratchpad)
    assert len(stable_reads) == 5

    _, appended, _ = _valid_output_authority("run-cache", "unit-cache", 6)
    authorities.append(appended)
    _write_authority_set(scratchpad, authorities)
    stable_reads.clear()

    journal, cas_repairs, journal_repairs, linked_repairs, orphan_staging = (
        A._plan_output_authority_reconciliation(scratchpad)
    )
    assert (
        cas_repairs,
        journal_repairs,
        linked_repairs,
        orphan_staging,
    ) == ([], [], [], [])
    assert len(journal["authorities"]) == 6
    assert stable_reads == sorted(
        [
            scratchpad
            / A._OUTPUT_AUTHORITY_CAS_DIRECTORY
            / f"{authority['authority_digest']}.json"
            for authority in authorities
        ],
        key=lambda path: path.name,
    )


def test_output_authority_projection_rejects_same_metadata_content_tamper(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    authorities = [
        _valid_output_authority("run-cache-drift", "unit-cache", ordinal)[1]
        for ordinal in range(1, 3)
    ]
    _write_authority_set(scratchpad, authorities)
    A._plan_output_authority_reconciliation(scratchpad)

    target = (
        scratchpad
        / A._OUTPUT_AUTHORITY_CAS_DIRECTORY
        / f"{authorities[0]['authority_digest']}.json"
    )
    before = target.stat()
    raw = target.read_bytes()
    replacement = bytearray(raw)
    replacement[-1] = ord(" ") if replacement[-1] != ord(" ") else ord("\n")
    target.write_bytes(replacement)
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = target.stat()
    assert A._metadata_identity(before) == A._metadata_identity(after)

    with pytest.raises(
        A.ArtifactLedgerError,
        match="filename/content digest mismatch|object is not canonical",
    ):
        A._plan_output_authority_reconciliation(scratchpad)


def test_validation_context_caches_one_epoch_but_finish_rejoins_uncached(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    project = tmp_path / "project"
    scratchpad.mkdir()
    project.mkdir()
    _, authority, unsigned = _valid_output_authority(
        "run-context-cache",
        "unit-context-cache",
        1,
    )
    _write_authority_set(scratchpad, [authority])
    uncached_reads = 0
    real_uncached = A._read_output_authority_cas

    def counted_uncached(root: Path, digest: str):
        nonlocal uncached_reads
        uncached_reads += 1
        return real_uncached(root, digest)

    monkeypatch.setattr(A, "_read_output_authority_cas", counted_uncached)
    context = A._ArtifactValidationContext(scratchpad, project)
    assert context.output_authority_cas(str(authority["authority_digest"])) == unsigned
    assert uncached_reads == 1

    assert context.finish() == []
    assert uncached_reads == 2


def test_reconciliation_binds_directory_once_not_every_cas_ancestor(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The secure full reread stays linear in leaves, not path depth.

    On Windows, exact-name/no-follow traversal of the same deep ancestor chain
    for every immutable CAS child dominated Scenario C.  Reconciliation must
    still reread all content, but it can bind the directory once and perform
    descriptor-stable reads below that exact directory.
    """

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    authorities = [
        _valid_output_authority("run-linear", "unit-linear", ordinal)[1]
        for ordinal in range(1, 33)
    ]
    _write_authority_set(scratchpad, authorities)
    cas_directory = scratchpad / A._OUTPUT_AUTHORITY_CAS_DIRECTORY

    lexical_calls: list[Path] = []
    stable_reads: list[Path] = []
    real_lexical = A._lexical_no_follow_chain
    real_read = A._read_stable_regular_bytes_in_bound_directory

    def counted_lexical(path: Path):
        lexical_calls.append(Path(path))
        return real_lexical(path)

    def counted_read(path: Path, **kwargs):
        stable_reads.append(Path(path))
        return real_read(path, **kwargs)

    monkeypatch.setattr(A, "_lexical_no_follow_chain", counted_lexical)
    monkeypatch.setattr(
        A,
        "_read_stable_regular_bytes_in_bound_directory",
        counted_read,
    )
    plan = A._plan_output_authority_reconciliation(scratchpad)

    assert all(not repair for repair in plan[1:])
    assert len(stable_reads) == len(authorities)
    assert not [
        path for path in lexical_calls
        if path.parent == cas_directory
    ]
    assert lexical_calls.count(cas_directory) == 2


def test_cached_controls_reject_content_and_physical_identity_mutation(
    tmp_path: Path,
) -> None:
    scratchpad, project, digest, _unsigned = _controls(tmp_path)
    context = A._ArtifactValidationContext(scratchpad, project)
    context.output_authority_cas(digest)
    context.output_authority_journal()

    journal_path = scratchpad / A._OUTPUT_AUTHORITY_LEDGER_NAME
    journal_path.write_bytes(journal_path.read_bytes() + b" ")
    issues = context.finish()
    assert any("changed during validation epoch" in issue for issue in issues)

    # A byte-identical replacement is still a new physical authority and must
    # invalidate a fresh epoch at its terminal boundary.
    scratchpad, project, digest, _unsigned = _controls(tmp_path / "replacement")
    context = A._ArtifactValidationContext(scratchpad, project)
    context.output_authority_cas(digest)
    cas_path = (
        scratchpad
        / A._OUTPUT_AUTHORITY_CAS_DIRECTORY
        / f"{digest}.json"
    )
    replacement = cas_path.with_suffix(".replacement")
    replacement.write_bytes(cas_path.read_bytes())
    os.replace(replacement, cas_path)
    issues = context.finish()
    assert any("changed during validation epoch" in issue for issue in issues)


def test_cached_journal_terminal_raw_join_rejects_same_metadata_mutation(
    tmp_path: Path,
) -> None:
    scratchpad, project, _digest, _unsigned = _controls(tmp_path)
    context = A._ArtifactValidationContext(scratchpad, project)
    context.output_authority_journal()

    journal_path = scratchpad / A._OUTPUT_AUTHORITY_LEDGER_NAME
    before = journal_path.stat()
    raw = journal_path.read_bytes()
    mutated = raw.replace(b'"authorities"', b'"authoritieS"', 1)
    assert len(mutated) == len(raw) and mutated != raw
    journal_path.write_bytes(mutated)
    os.utime(journal_path, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = journal_path.stat()
    assert A._metadata_identity(before) == A._metadata_identity(after)

    issues = context.finish()
    assert any(
        "immutable authority control changed during validation epoch" in issue
        for issue in issues
    )


def test_identity_path_cache_is_single_read_and_rejects_alias_drift(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    project = tmp_path / "project"
    scratchpad.mkdir()
    project.mkdir()
    artifact = scratchpad / "bound.md"
    artifact.write_bytes(b"bound bytes")
    calls = 0
    real = A._path_for_identity_with_chains

    def counted(root: Path, target: Path, identity: str, **kwargs):
        nonlocal calls
        calls += 1
        return real(root, target, identity, **kwargs)

    monkeypatch.setattr(A, "_path_for_identity_with_chains", counted)
    context = A._ArtifactValidationContext(scratchpad, project)
    identity = "scratchpad:bound.md"
    assert context.path_for_identity(identity) == artifact
    assert context.path_for_identity(identity) == artifact
    assert calls == 1

    replacement = scratchpad / "replacement.tmp"
    replacement.write_bytes(artifact.read_bytes())
    os.replace(replacement, artifact)
    issues = context.finish()
    assert any(
        identity in issue and "path changed during validation epoch" in issue
        for issue in issues
    )


def test_physical_owner_join_is_once_per_identity_and_terminally_rechecked(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    project = tmp_path / "project"
    scratchpad.mkdir()
    project.mkdir()
    artifact = scratchpad / "owner.md"
    artifact.write_bytes(b"owner bytes")
    identity = "scratchpad:owner.md"
    context = A._ArtifactValidationContext(scratchpad, project)

    first = context.physical_owner_identity(identity)
    assert context.physical_owner_identity(identity) == first
    assert len(context._physical_owner_identities) == 1
    assert context._snapshots == {}

    replacement = scratchpad / "replacement.tmp"
    replacement.write_bytes(artifact.read_bytes())
    os.replace(replacement, artifact)
    issues = context.finish()
    assert any(
        identity in issue and "physical identity changed" in issue
        for issue in issues
    )


def test_absent_snapshot_retains_exact_namespace_physical_identity(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    project = tmp_path / "project"
    scratchpad.mkdir()
    project.mkdir()
    missing = scratchpad / "conditional.md"
    context = A._ArtifactValidationContext(scratchpad, project)

    snapshot, error = context.snapshot(missing)
    assert snapshot is None
    assert error == "SNAPSHOT_IO_FILENOTFOUNDERROR"
    assert context.physical_identity(missing) == (
        f"path:{os.path.normcase(os.path.abspath(os.fspath(missing)))}"
    )
    assert context.finish() == []


def test_input_binding_cache_is_ledger_epoch_local_and_terminally_rejoins(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    project = tmp_path / "project"
    scratchpad.mkdir()
    project.mkdir()
    artifact = scratchpad / "input.md"
    artifact.write_bytes(b"bound input")
    context = A._ArtifactValidationContext(scratchpad, project)
    calls = 0

    def replay_once(
        root: Path,
        target: Path,
        identity: str,
        input_class: str,
        ledger,
        *,
        _validation_context=None,
    ):
        nonlocal calls
        calls += 1
        snapshot, error = _validation_context.snapshot(artifact)
        assert not error
        return {
            "identity": identity,
            "input_class": input_class,
            "status": "ACTIVE",
            "size": snapshot["size"],
            "sha256": snapshot["sha256"],
        }

    monkeypatch.setattr(A, "_input_binding_record_uncached", replay_once)
    first = A._input_binding_record(
        scratchpad,
        project,
        "scratchpad:input.md",
        "IMMUTABLE",
        context.ledger,
        _validation_context=context,
    )
    first["status"] = "caller mutation"
    second = A._input_binding_record(
        scratchpad,
        project,
        "scratchpad:input.md",
        "IMMUTABLE",
        context.ledger,
        _validation_context=context,
    )
    assert second["status"] == "ACTIVE"
    assert calls == 1

    # A different ledger object cannot borrow the epoch cache even when its
    # current bytes happen to be equal.
    other_ledger = copy.deepcopy(context.ledger)
    A._input_binding_record(
        scratchpad,
        project,
        "scratchpad:input.md",
        "IMMUTABLE",
        other_ledger,
        _validation_context=context,
    )
    assert calls == 2

    replacement = scratchpad / "replacement.tmp"
    replacement.write_bytes(artifact.read_bytes())
    os.replace(replacement, artifact)
    assert any(
        "artifact changed during validation epoch" in issue
        for issue in context.finish()
    )


def test_context_json_freeze_preserves_exact_types_and_isolates_mutation(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    project = tmp_path / "project"
    scratchpad.mkdir()
    project.mkdir()
    ledger = A.read_artifact_ledger(scratchpad)
    ledger["test_json_domain"] = {
        "boolean": True,
        "integer": 1,
        "list": [None, False, 2, "value"],
    }
    context = A._ArtifactValidationContext(
        scratchpad,
        project,
        ledger=ledger,
    )
    frozen = context.ledger["test_json_domain"]
    assert type(frozen["boolean"]) is bool
    assert type(frozen["integer"]) is int
    assert type(frozen["list"]) is list
    ledger["test_json_domain"]["list"].append("caller mutation")
    assert frozen["list"] == [None, False, 2, "value"]


@pytest.mark.parametrize(
    "invalid",
    [
        ("tuple",),
        object(),
        float("nan"),
        float("inf"),
        1.25,
    ],
)
def test_context_json_freeze_rejects_python_only_normalization(
    tmp_path: Path,
    invalid,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    project = tmp_path / "project"
    scratchpad.mkdir()
    project.mkdir()
    ledger = A.read_artifact_ledger(scratchpad)
    ledger["test_invalid"] = invalid
    with pytest.raises(A.ArtifactLedgerError, match="non-JSON-domain"):
        A._ArtifactValidationContext(scratchpad, project, ledger=ledger)


def test_terminal_path_trie_inspects_shared_ancestors_once(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "shared" / "nested"
    root.mkdir(parents=True)
    paths = []
    for ordinal in range(24):
        path = root / f"artifact-{ordinal}.json"
        path.write_text(str(ordinal), encoding="utf-8")
        paths.append(path)
    unique_components = {
        os.path.abspath(component)
        for path in paths
        for component, _identity in A._lexical_no_follow_chain(path)
    }
    calls: list[str] = []
    real = A.rooted_io.exact_existing_name

    def counted(path: Path) -> str:
        calls.append(os.path.abspath(os.fspath(path)))
        return real(path)

    monkeypatch.setattr(A.rooted_io, "exact_existing_name", counted)
    chains = A._lexical_no_follow_chains(paths)
    assert len(chains) == len(paths)
    assert len(calls) == len(unique_components)
    assert len(calls) < sum(len(row) for row in chains.values())


@pytest.mark.parametrize(
    "attack",
    [
        "sibling_swap",
        "ancestor_file_id",
        "leaf_add",
        "leaf_remove",
        "mixed_root",
    ],
)
def test_terminal_path_trie_rejects_denominator_mutation(
    tmp_path: Path,
    attack: str,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    project = tmp_path / "project"
    sibling_root = scratchpad / "siblings"
    sibling_root.mkdir(parents=True)
    project.mkdir()
    first = sibling_root / "first.md"
    second = sibling_root / "second.md"
    project_leaf = project / "project.md"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    project_leaf.write_bytes(b"project")
    absent = sibling_root / "absent.md"
    context = A._ArtifactValidationContext(scratchpad, project)
    context.snapshot(first)
    context.snapshot(second)
    context.snapshot(project_leaf)
    context.snapshot(absent)

    if attack == "sibling_swap":
        temporary = sibling_root / "swap.tmp"
        os.replace(first, temporary)
        os.replace(second, first)
        os.replace(temporary, second)
    elif attack == "ancestor_file_id":
        moved = scratchpad / "moved-siblings"
        os.replace(sibling_root, moved)
        sibling_root.mkdir()
        for name in ("first.md", "second.md"):
            (sibling_root / name).write_bytes((moved / name).read_bytes())
    elif attack == "leaf_add":
        absent.write_bytes(b"new")
    elif attack == "leaf_remove":
        first.unlink()
    else:
        replacement = project / "replacement.tmp"
        replacement.write_bytes(project_leaf.read_bytes())
        os.replace(replacement, project_leaf)

    issues = context.finish()
    assert issues
    assert any(
        "changed during validation epoch" in issue
        or "changed during terminal rejoin" in issue
        for issue in issues
    )
