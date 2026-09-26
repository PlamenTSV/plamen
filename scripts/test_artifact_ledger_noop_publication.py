"""Exact ledger replays preserve physical identity without skipping checks."""
from __future__ import annotations

import json
import os

import pytest

import artifact_ledger as A


def _seed(tmp_path):
    root = tmp_path / "scratch"
    ledger = A.read_artifact_ledger(root)
    A.write_artifact_ledger(root, ledger)
    return root, ledger, root / A.LEDGER_NAME


def _snapshot(path):
    metadata = path.stat()
    return path.read_bytes(), metadata.st_ino, metadata.st_mtime_ns


@pytest.mark.parametrize("operation", ["write", "cas", "empty_invalidation"])
def test_exact_replay_preserves_bytes_inode_and_mtime(tmp_path, monkeypatch, operation):
    root, ledger, path = _seed(tmp_path)
    before = _snapshot(path)

    def forbid_publication(*_args, **_kwargs):
        pytest.fail("an exact ledger replay must not publish a replacement")

    monkeypatch.setattr(A, "_write_rooted_control_bytes", forbid_publication)
    if operation == "write":
        A.write_artifact_ledger(root, A.read_artifact_ledger(root))
    elif operation == "cas":
        called = []
        committed, digest = A.compare_and_swap_artifact_ledger(
            root,
            expected_digest=A.artifact_ledger_digest(ledger),
            mutator=lambda value: called.append(value),
        )
        assert len(called) == 1
        assert committed == ledger
        assert digest == A.artifact_ledger_digest(ledger)
    else:
        plan = A.semantic_dependency_invalidation_plan(
            ledger, ["scratchpad:unconsumed.md"], run_id="same-run",
        )
        assert plan["invalidated_work_unit_keys"] == []
        assert A.apply_semantic_invalidation(root, plan, run_id="same-run") == plan
    assert _snapshot(path) == before


@pytest.mark.parametrize("operation", ["write", "cas"])
def test_real_change_retains_durable_publication(tmp_path, monkeypatch, operation):
    root, ledger, path = _seed(tmp_path)
    ledger["replay_test"] = "initial"
    A.write_artifact_ledger(root, ledger)
    before = _snapshot(path)
    publications = []
    real_write = A._write_rooted_control_bytes

    def record_write(destination, payload):
        publications.append((destination, payload))
        return real_write(destination, payload)

    monkeypatch.setattr(A, "_write_rooted_control_bytes", record_write)
    if operation == "write":
        ledger["replay_test"] = "changed"
        A.write_artifact_ledger(root, ledger)
    else:
        A.compare_and_swap_artifact_ledger(
            root,
            expected_digest=A.artifact_ledger_digest(ledger),
            mutator=lambda value: value.update(replay_test="changed"),
        )
    assert len(publications) == 1
    assert _snapshot(path)[0] != before[0]
    assert A.read_artifact_ledger(root)["replay_test"] == "changed"


def test_semantically_equal_but_different_bytes_are_not_a_noop(tmp_path):
    root, ledger, path = _seed(tmp_path)
    path.write_text(json.dumps(ledger), encoding="utf-8")
    before = _snapshot(path)
    A.write_artifact_ledger(root, ledger)
    assert _snapshot(path)[0] != before[0]
    assert path.read_bytes() == (
        json.dumps(ledger, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def test_noop_stable_read_failure_is_not_ignored(tmp_path, monkeypatch):
    root, ledger, path = _seed(tmp_path)
    before = _snapshot(path)

    def drift(*_args, **_kwargs):
        raise A.ArtifactLedgerError("synthetic descriptor drift")

    monkeypatch.setattr(A, "_read_stable_regular_bytes", drift)
    with pytest.raises(A.ArtifactLedgerError, match="descriptor drift"):
        A.write_artifact_ledger(root, ledger)
    assert _snapshot(path) == before


@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink", "directory"])
def test_noop_does_not_bypass_destination_checks(tmp_path, unsafe_kind):
    root, ledger, path = _seed(tmp_path)
    original = root / "original.json"
    path.rename(original)
    before = _snapshot(original)
    if unsafe_kind == "symlink":
        path.symlink_to(original)
    elif unsafe_kind == "hardlink":
        os.link(original, path)
    else:
        path.mkdir()
    with pytest.raises(A.ArtifactLedgerError):
        A.write_artifact_ledger(root, ledger)
    assert _snapshot(original) == before


@pytest.mark.parametrize("invalid_kind", ["stale", "malformed_candidate"])
def test_cas_noop_still_rejects_invalid_authority(tmp_path, invalid_kind):
    root, ledger, path = _seed(tmp_path)
    before = _snapshot(path)
    called = []

    def mutate(value):
        called.append(True)
        if invalid_kind == "malformed_candidate":
            value["version"] = True

    with pytest.raises(A.ArtifactLedgerError):
        A.compare_and_swap_artifact_ledger(
            root,
            expected_digest=(
                "0" * 64 if invalid_kind == "stale"
                else A.artifact_ledger_digest(ledger)
            ),
            mutator=mutate,
        )
    assert called == ([] if invalid_kind == "stale" else [True])
    assert _snapshot(path) == before
