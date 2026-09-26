"""Focused durability tests for severity-bind raw postimage storage."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from artifact_ledger import ArtifactLedgerError
from phase_io_contracts import DriverOutputTransition, DriverSuccessorPlan
import severity_bind_postimage_cas as subject


RUN_ID = "00000000-0000-4000-8000-000000000501"
WORK_KEY = "sc/core/evm/codex/severity_adjudication_shadow/bind.0001.hyp-1"
CONTRACT_DIGEST = "1" * 64
LAUNCH_DIGEST = "2" * 64
INVOCATION_DIGEST = "3" * 64


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fixture(
    tmp_path: Path, *, candidate: str = "HYP-1", bind_ordinal: int = 1,
    salt: bytes = b"",
):
    work_key = (
        "sc/core/evm/codex/severity_adjudication_shadow/"
        f"bind.{bind_ordinal:04d}.{candidate.casefold()}"
    )
    raw = {
        f"scratchpad:verify_{candidate}.severity_adjudication_receipt.json": b'{"receipt":1}' + salt,
        f"scratchpad:verify_{candidate}.severity_decision.json": b'{"decision":2}' + salt,
        "scratchpad:severity_decision_ledger.shadow.json": b'{"ledger":3}\n' + salt,
    }
    transitions = []
    for ordinal, (identity, payload) in enumerate(raw.items(), 1):
        missing = ordinal == 1
        before = b"" if missing else f"before-{ordinal}".encode()
        transitions.append(DriverOutputTransition(
            work_unit_key=work_key,
            contract_digest=CONTRACT_DIGEST,
            ordinal=ordinal,
            artifact_identity=identity,
            before_status="MISSING" if missing else "ACTIVE",
            before_sha256="" if missing else _sha(before),
            before_size=0 if missing else len(before),
            after_sha256=_sha(payload),
            after_size=len(payload),
        ))
    plan = DriverSuccessorPlan(
        run_id=RUN_ID,
        work_unit_key=work_key,
        contract_digest=CONTRACT_DIGEST,
        launch_digest=LAUNCH_DIGEST,
        output_prestate_digest="4" * 64,
        transitions=tuple(transitions),
    )
    return tmp_path, plan, raw


def _seal(tmp_path: Path):
    root, plan, raw = _fixture(tmp_path)
    reference = subject.seal_severity_bind_postimages(
        root, run_id=RUN_ID, work_unit_key=plan.work_unit_key, plan=plan,
        invocation_digest=INVOCATION_DIGEST, output_bytes=raw,
    )
    return root, plan, raw, reference


def test_seal_load_and_exact_replay_preserve_objects(tmp_path: Path):
    root, plan, raw, reference = _seal(tmp_path)
    directory = root / subject.CAS_DIRECTORY
    before = {
        path.name: (path.stat().st_ino, path.stat().st_mtime_ns)
        for path in directory.iterdir()
    }

    replay = subject.seal_severity_bind_postimages(
        root, run_id=RUN_ID, work_unit_key=WORK_KEY, plan=plan,
        invocation_digest=INVOCATION_DIGEST, output_bytes=raw,
    )

    assert replay == reference
    assert subject.load_severity_bind_postimages(
        root, reference=reference, plan=plan,
        invocation_digest=INVOCATION_DIGEST,
    ) == raw
    assert {
        path.name: (path.stat().st_ino, path.stat().st_mtime_ns)
        for path in directory.iterdir()
    } == before


def test_exact_orphaned_blob_prefix_is_adopted_on_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    root, plan, raw = _fixture(tmp_path)
    calls = 0
    real_hook = subject.rio._write_once_pre_publish_hook

    def interrupted(stage: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("injected after durable stage")
        real_hook(stage, destination)

    monkeypatch.setattr(subject.rio, "_write_once_pre_publish_hook", interrupted)
    with pytest.raises(RuntimeError, match="injected after durable stage"):
        subject.seal_severity_bind_postimages(
            root, run_id=RUN_ID, work_unit_key=WORK_KEY, plan=plan,
            invocation_digest=INVOCATION_DIGEST, output_bytes=raw,
        )
    stages = list((root / subject.CAS_DIRECTORY).glob("*.stage"))
    assert len(stages) == 1
    staged = stages[0].read_bytes()
    monkeypatch.setattr(
        subject.rio, "_write_once_pre_publish_hook", real_hook,
    )

    reference = subject.seal_severity_bind_postimages(
        root, run_id=RUN_ID, work_unit_key=WORK_KEY, plan=plan,
        invocation_digest=INVOCATION_DIGEST, output_bytes=raw,
    )
    assert subject.load_severity_bind_postimages(
        root, reference=reference, plan=plan,
        invocation_digest=INVOCATION_DIGEST,
    ) == raw
    assert staged in raw.values()
    assert list((root / subject.CAS_DIRECTORY).glob("*.stage")) == []


def test_current_vector_witness_with_wrong_bytes_is_not_admitted(tmp_path: Path):
    root, plan, _raw, reference = _seal(tmp_path)
    manifest = root / subject.CAS_DIRECTORY / reference["manifest_file"]
    witness = root / subject.CAS_DIRECTORY / (
        f"{subject._durable_stage_name(manifest.name, manifest.read_bytes())}.abandoned"
    )
    if witness.exists():
        os.chmod(witness, 0o600)
    witness.write_bytes(b"foreign")
    os.chmod(witness, 0o600)

    with pytest.raises(ArtifactLedgerError, match="differs from current vector"):
        subject.load_severity_bind_postimages(
            root, reference=reference, plan=plan,
            invocation_digest=INVOCATION_DIGEST,
        )


def test_two_vectors_and_retained_witnesses_replay_independently(tmp_path: Path):
    root, first_plan, first_raw, first_reference = _seal(tmp_path)
    _root, second_plan, second_raw = _fixture(
        tmp_path, candidate="HYP-2", bind_ordinal=2, salt=b"-second",
    )
    second_reference = subject.seal_severity_bind_postimages(
        root, run_id=RUN_ID, work_unit_key=second_plan.work_unit_key,
        plan=second_plan, invocation_digest="7" * 64,
        output_bytes=second_raw,
    )

    assert subject.load_severity_bind_postimages(
        root, reference=first_reference, plan=first_plan,
        invocation_digest=INVOCATION_DIGEST,
    ) == first_raw
    assert subject.load_severity_bind_postimages(
        root, reference=second_reference, plan=second_plan,
        invocation_digest="7" * 64,
    ) == second_raw


@pytest.mark.parametrize("target", ("blob", "manifest"))
def test_tampered_object_is_never_accepted(tmp_path: Path, target: str):
    root, plan, _raw, reference = _seal(tmp_path)
    directory = root / subject.CAS_DIRECTORY
    path = (
        next(directory.glob("*.blob"))
        if target == "blob"
        else directory / reference["manifest_file"]
    )
    os.chmod(path, 0o600)
    path.write_bytes(b"tampered")

    with pytest.raises(ArtifactLedgerError, match="digest differs|differs from plan"):
        subject.load_severity_bind_postimages(
            root, reference=reference, plan=plan,
            invocation_digest=INVOCATION_DIGEST,
        )


def test_reference_plan_and_invocation_are_not_interchangeable(tmp_path: Path):
    root, plan, _raw, reference = _seal(tmp_path)
    changed = dict(reference)
    changed["invocation_digest"] = "5" * 64

    with pytest.raises(ArtifactLedgerError, match="reference differs"):
        subject.load_severity_bind_postimages(
            root, reference=changed, plan=plan,
            invocation_digest=INVOCATION_DIGEST,
        )
    with pytest.raises(ArtifactLedgerError, match="reference differs"):
        subject.load_severity_bind_postimages(
            root, reference=reference, plan=plan,
            invocation_digest="6" * 64,
        )


@pytest.mark.parametrize("foreign", ("foreign", "ABCDEF.json"))
def test_foreign_or_case_ambiguous_census_fails_closed(
    tmp_path: Path, foreign: str,
):
    root, plan, _raw, reference = _seal(tmp_path)
    (root / subject.CAS_DIRECTORY / foreign).write_bytes(b"foreign")

    with pytest.raises(ArtifactLedgerError, match="census is malformed"):
        subject.load_severity_bind_postimages(
            root, reference=reference, plan=plan,
            invocation_digest=INVOCATION_DIGEST,
        )


def test_conflicting_preexisting_content_name_is_preserved(tmp_path: Path):
    root, plan, raw = _fixture(tmp_path)
    directory = root / subject.CAS_DIRECTORY
    directory.mkdir(mode=0o700)
    first = next(iter(raw.values()))
    conflict = directory / f"{_sha(first)}.blob"
    conflict.write_bytes(b"foreign")

    with pytest.raises(ArtifactLedgerError):
        subject.seal_severity_bind_postimages(
            root, run_id=RUN_ID, work_unit_key=WORK_KEY, plan=plan,
            invocation_digest=INVOCATION_DIGEST, output_bytes=raw,
        )
    assert conflict.read_bytes() == b"foreign"


def test_capacity_is_checked_before_adding_any_vector_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    root, plan, raw = _fixture(tmp_path)
    directory = root / subject.CAS_DIRECTORY
    directory.mkdir(mode=0o700)
    first = directory / f"{'a' * 64}.blob"
    second = directory / f"{'b' * 64}.blob"
    first.write_bytes(b"a")
    second.write_bytes(b"b")
    first.chmod(0o600)
    second.chmod(0o600)
    monkeypatch.setattr(subject, "MAX_CAS_ENTRIES", 2)

    with pytest.raises(ArtifactLedgerError, match="no capacity"):
        subject.seal_severity_bind_postimages(
            root, run_id=RUN_ID, work_unit_key=WORK_KEY, plan=plan,
            invocation_digest=INVOCATION_DIGEST, output_bytes=raw,
        )
    assert {path.name for path in directory.iterdir()} == {
        f"{'a' * 64}.blob", f"{'b' * 64}.blob",
    }


def test_symlink_cas_root_is_rejected_without_following(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / subject.CAS_DIRECTORY).symlink_to(outside, target_is_directory=True)
    _root, plan, raw = _fixture(tmp_path)

    with pytest.raises(ArtifactLedgerError, match="CAS is unavailable"):
        subject.seal_severity_bind_postimages(
            tmp_path, run_id=RUN_ID, work_unit_key=WORK_KEY, plan=plan,
            invocation_digest=INVOCATION_DIGEST, output_bytes=raw,
        )
    assert list(outside.iterdir()) == []
@pytest.mark.parametrize("kind", ("blob", "manifest", "witness"))
def test_unrelated_canonical_entry_requires_private_single_link_file(
    tmp_path: Path, kind: str,
):
    root, plan, _raw, reference = _seal(tmp_path)
    directory = root / subject.CAS_DIRECTORY
    if kind == "blob":
        foreign = directory / f"{'8' * 64}.blob"
    elif kind == "manifest":
        foreign = directory / f"{'9' * 64}.json"
    else:
        foreign = directory / (
            f".plamen-write-once-{'a' * 64}.stage.abandoned"
        )
    outside = tmp_path / f"outside-{kind}"
    outside.write_bytes(b"foreign")
    foreign.symlink_to(outside)

    with pytest.raises(ArtifactLedgerError, match="lacks private ownership"):
        subject.load_severity_bind_postimages(
            root, reference=reference, plan=plan,
            invocation_digest=INVOCATION_DIGEST,
        )
    assert outside.read_bytes() == b"foreign"


def test_unrelated_canonical_hardlink_is_rejected_without_reading_peer_bytes(
    tmp_path: Path,
):
    root, plan, _raw, reference = _seal(tmp_path)
    directory = root / subject.CAS_DIRECTORY
    outside = tmp_path / "outside-hardlink"
    outside.write_bytes(b"foreign")
    os.link(outside, directory / f"{'8' * 64}.blob")

    with pytest.raises(ArtifactLedgerError, match="lacks private ownership"):
        subject.load_severity_bind_postimages(
            root, reference=reference, plan=plan,
            invocation_digest=INVOCATION_DIGEST,
        )
    assert outside.read_bytes() == b"foreign"
