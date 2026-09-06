"""Focused regressions for immutable central-closure replay revisions."""

from __future__ import annotations

import os
from pathlib import Path

import artifact_ledger as AL
import closure_broker_v2 as C
import pytest
from test_negative_closure_broker_live_cutover import (
    _materialize_exhaustive_provider_bundle,
    _work,
)


def test_loaded_authority_reuses_exact_immutable_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Candidate fan-out must not re-parse one unchanged provider graph."""

    AL.write_artifact_ledger(tmp_path, AL.read_artifact_ledger(tmp_path))
    _materialize_exhaustive_provider_bundle(tmp_path)
    authority = C.write_central_negative_closure_authority(tmp_path)

    def unexpected_revalidation(_root: Path, _path: Path) -> dict[str, object]:
        raise AssertionError("unchanged replay revision was rebuilt")

    monkeypatch.setattr(C, "_validate_central_bundle", unexpected_revalidation)
    for _ in range(4):
        resolution = authority.resolve(
            work_item=_work(), requested_effect=C.REFUTED_FULL
        )
        assert resolution["status"] == C.AUTHORIZED


def test_artifact_ledger_revision_change_invalidates_replay_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    AL.write_artifact_ledger(tmp_path, AL.read_artifact_ledger(tmp_path))
    _materialize_exhaustive_provider_bundle(tmp_path)
    authority = C.write_central_negative_closure_authority(tmp_path)

    ledger = AL.read_artifact_ledger(tmp_path)
    ledger["central_cache_test_revision"] = 1
    AL.write_artifact_ledger(tmp_path, ledger)

    original = C._validate_central_bundle
    calls = 0

    def counted(root: Path, path: Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return original(root, path)

    monkeypatch.setattr(C, "_validate_central_bundle", counted)
    resolution = authority.resolve(
        work_item=_work(), requested_effect=C.REFUTED_FULL
    )
    assert resolution["status"] == C.AUTHORIZED
    assert calls >= 2


def test_byte_identical_input_replacement_invalidates_replay_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _materialize_exhaustive_provider_bundle(tmp_path)
    authority = C.write_central_negative_closure_authority(tmp_path)
    target = tmp_path / "closure-inputs/candidate.bin"
    replacement = target.with_suffix(".replacement")
    replacement.write_bytes(target.read_bytes())
    os.replace(replacement, target)

    original = C._validate_central_bundle
    calls = 0

    def counted(root: Path, path: Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return original(root, path)

    monkeypatch.setattr(C, "_validate_central_bundle", counted)
    resolution = authority.resolve(
        work_item=_work(), requested_effect=C.REFUTED_FULL
    )
    assert resolution["status"] == C.AUTHORIZED
    assert calls >= 2
