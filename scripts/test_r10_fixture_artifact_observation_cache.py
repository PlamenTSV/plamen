"""Fixture-first controls for the R10 strict-fixture observation cache."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path


def _r10_fixture_module():
    path = Path(__file__).with_name("test_r10_demotion_gate.py")
    spec = importlib.util.spec_from_file_location("r10_fixture_cache_subject", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bounded_artifact_observation_cache_is_fresh_and_copy_isolated(
    tmp_path, monkeypatch
):
    fixture = _r10_fixture_module()
    import artifact_ledger as ledger

    root = tmp_path / "fixture"
    parent = root / "nested"
    parent.mkdir(parents=True)
    leaf = parent / "artifact.json"
    leaf.write_bytes(b'{"state":"zero"}\n')
    outside = tmp_path / "outside.json"
    outside.write_bytes(b'{"outside":true}\n')

    stable_delegate = ledger._stable_artifact_snapshot
    physical_delegate = ledger._physical_file_identity
    calls = {"stable": 0, "physical": 0}

    def counted_stable(path):
        calls["stable"] += 1
        return stable_delegate(path)

    def counted_physical(path):
        calls["physical"] += 1
        return physical_delegate(path)

    monkeypatch.setattr(ledger, "_stable_artifact_snapshot", counted_stable)
    monkeypatch.setattr(ledger, "_physical_file_identity", counted_physical)
    fixture._install_bounded_artifact_observation_cache(
        monkeypatch, root
    )

    first, error = ledger._stable_artifact_snapshot(leaf)
    assert error == "" and first is not None
    first["sha256"] = "mutated-return"
    second, error = ledger._stable_artifact_snapshot(leaf)
    assert error == "" and second is not None
    assert second["sha256"] != "mutated-return"
    assert calls["stable"] == 1

    identity = ledger._physical_file_identity(leaf)
    assert ledger._physical_file_identity(leaf) == identity
    assert calls["physical"] == 1

    # A same-length write with a restored timestamp must not hit either cache.
    before = os.lstat(leaf)
    leaf.write_bytes(b'{"state":"ones"}\n')
    os.utime(leaf, ns=(before.st_atime_ns, before.st_mtime_ns))
    changed, error = ledger._stable_artifact_snapshot(leaf)
    assert error == "" and changed is not None
    assert changed["sha256"] != second["sha256"]
    assert ledger._physical_file_identity(leaf) == identity
    assert calls == {"stable": 2, "physical": 2}

    # Replacing an ancestor while preserving the leaf object also invalidates.
    displaced = root / "displaced"
    parent.rename(displaced)
    parent.mkdir()
    (displaced / leaf.name).replace(leaf)
    ledger._stable_artifact_snapshot(leaf)
    ledger._physical_file_identity(leaf)
    assert calls == {"stable": 3, "physical": 3}

    # Missing/error states and paths outside the bounded fixture always delegate.
    leaf.unlink()
    ledger._stable_artifact_snapshot(leaf)
    ledger._stable_artifact_snapshot(leaf)
    ledger._physical_file_identity(leaf)
    ledger._physical_file_identity(leaf)
    ledger._stable_artifact_snapshot(outside)
    ledger._stable_artifact_snapshot(outside)
    ledger._physical_file_identity(outside)
    ledger._physical_file_identity(outside)
    assert calls == {"stable": 7, "physical": 7}


def test_bounded_artifact_observation_cache_rejects_exact_name_alias(
    tmp_path, monkeypatch
):
    fixture = _r10_fixture_module()
    import artifact_ledger as ledger

    root = tmp_path / "fixture"
    root.mkdir()
    leaf = root / "artifact.json"
    leaf.write_bytes(b"same bytes\n")
    original = ledger._stable_artifact_snapshot
    calls = []

    def counted(path):
        calls.append(Path(path))
        return original(path)

    monkeypatch.setattr(ledger, "_stable_artifact_snapshot", counted)
    fixture._install_bounded_artifact_observation_cache(monkeypatch, root)
    ledger._stable_artifact_snapshot(leaf)
    ledger._stable_artifact_snapshot(leaf)
    assert len(calls) == 1

    intermediate = root / "artifact.case-swap"
    alias = root / "ARTIFACT.json"
    leaf.rename(intermediate)
    intermediate.rename(alias)
    ledger._stable_artifact_snapshot(leaf)
    ledger._stable_artifact_snapshot(leaf)
    assert len(calls) == 3


def test_bounded_artifact_observation_cache_forwards_snapshot_contract(
    tmp_path, monkeypatch
):
    fixture = _r10_fixture_module()
    import artifact_ledger as ledger

    root = tmp_path / "fixture"
    root.mkdir()
    leaf = root / "artifact.json"
    leaf.write_bytes(b"bound bytes\n")
    original = ledger._stable_artifact_snapshot
    calls = []

    def counted(
        path,
        *,
        confirmation_reads=True,
        _known_chain=None,
        _captured_chain=None,
    ):
        calls.append((confirmation_reads, _known_chain, _captured_chain))
        return original(
            path,
            confirmation_reads=confirmation_reads,
            _known_chain=_known_chain,
            _captured_chain=_captured_chain,
        )

    monkeypatch.setattr(ledger, "_stable_artifact_snapshot", counted)
    fixture._install_bounded_artifact_observation_cache(monkeypatch, root)
    captured = []
    snapshot, error = ledger._stable_artifact_snapshot(
        leaf,
        confirmation_reads=False,
        _captured_chain=captured,
    )
    assert error == "" and snapshot is not None
    assert captured
    assert calls == [(False, None, captured)]
