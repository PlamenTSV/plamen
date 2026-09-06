from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
from typing import Any

import pytest

import artifact_ledger
from artifact_ledger import ArtifactLedgerError, LEDGER_NAME, read_artifact_ledger
from program_facts_v2_contracts import ProgramFactsTypeError
from review_fixtures.program_facts_r2_1_b0_red_support import (
    PUBLIC_IDENTITIES,
    require_accepts,
)
from test_program_facts_r21_3_test_composer_b0_red import (
    _candidate_validation_kwargs,
)
from test_program_facts_r21_shared_seams_r7 import (
    _commit_kwargs,
    _committer,
    _ledger_bytes,
    _phaseio_validator,
    _publication_vector,
)
from test_program_facts_r21_shared_seams_r7_r2 import (
    _path_key,
    _phaseio_core_vector,
)


def _file_identity(path: Path) -> tuple[int, int]:
    stat = path.stat(follow_symlinks=False)
    return stat.st_dev, stat.st_ino


def test_shared_r3_phaseio_rejection_preserves_rejected_carrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    law = "PF-SHARED-R7-R3/phaseio-rejected-carrier-immutable"
    candidate, inputs, permit, authority = _phaseio_core_vector(law)
    kwargs = _candidate_validation_kwargs(inputs, permit, authority)
    rejected = deepcopy(candidate)
    rejected["candidate_digest"] = "f" * 64
    rejected_before = deepcopy(rejected)
    caller_before = deepcopy(
        {
            "candidate": candidate,
            "inputs": inputs,
            "permit": permit,
            "authority": authority,
            "kwargs": kwargs,
        }
    )
    owned_root = tmp_path / "phaseio-rejection-owned-root"
    owned_root.mkdir()
    monkeypatch.chdir(owned_root)
    target = _phaseio_validator(law)
    with pytest.raises(ProgramFactsTypeError):
        target(rejected, **kwargs)
    assert rejected == rejected_before
    assert {
        "candidate": candidate,
        "inputs": inputs,
        "permit": permit,
        "authority": authority,
        "kwargs": kwargs,
    } == caller_before


@pytest.mark.parametrize("target_name", ("arm", PUBLIC_IDENTITIES[0]))
def test_shared_r3_byte_identical_replacement_during_stable_read_rejects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_name: str,
) -> None:
    law = f"PF-SHARED-R7-R3/stable-read-identity-race-{target_name}"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    target = (
        vector["arm_path"]
        if target_name == "arm"
        else vector["output_paths"][target_name]
    )
    committer = _committer(law)
    original_read = artifact_ledger._read_stable_regular_bytes
    target_key = _path_key(target)
    original_bytes = target.read_bytes()
    original_stat = target.stat(follow_symlinks=False)
    original_identity = _file_identity(target)
    target_reads = 0
    replacement_identity: tuple[int, int] | None = None

    def racing_read(
        path: Path,
        *,
        limit: int,
        allowed_link_counts: tuple[int, ...] = (1,),
    ) -> bytes:
        nonlocal target_reads, replacement_identity
        observed = original_read(
            path,
            limit=limit,
            allowed_link_counts=allowed_link_counts,
        )
        if (
            _path_key(path) == target_key
            and replacement_identity is None
        ):
            target_reads += 1
            replacement = target.with_name(f"{target.name}.identity-raced")
            replacement.write_bytes(original_bytes)
            os.chmod(replacement, original_stat.st_mode)
            os.utime(
                replacement,
                ns=(
                    original_stat.st_atime_ns,
                    original_stat.st_mtime_ns,
                ),
            )
            replacement_identity = _file_identity(replacement)
            assert replacement_identity != original_identity
            assert replacement.read_bytes() == original_bytes
            assert (
                replacement.stat(follow_symlinks=False).st_mtime_ns
                == original_stat.st_mtime_ns
            )
            os.replace(replacement, target)
            assert _file_identity(target) == replacement_identity
        return observed

    monkeypatch.setattr(
        artifact_ledger,
        "_read_stable_regular_bytes",
        racing_read,
    )
    before_ledger = _ledger_bytes(root)
    with pytest.raises(ArtifactLedgerError):
        committer(**_commit_kwargs(vector))
    assert target_reads == 1
    assert replacement_identity is not None
    assert _file_identity(target) == replacement_identity
    assert _file_identity(target) != original_identity
    assert target.read_bytes() == original_bytes
    assert _ledger_bytes(root) == before_ledger


def test_shared_r3_absent_reader_does_not_materialize_ledger(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7-R3/absent-read-does-not-materialize-ledger"
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _committer(law)
    ledger_path = root / LEDGER_NAME
    assert not ledger_path.exists()
    assert _ledger_bytes(root) is None
    observed = require_accepts(read_artifact_ledger, law, root)
    assert observed["program_facts_v2_generation_selections"] == {}
    assert observed["program_facts_v2_active_selection"] == {
        "state": "ABSENT"
    }
    assert not ledger_path.exists()
    assert _ledger_bytes(root) is None
