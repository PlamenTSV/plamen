"""Durable PhaseIO replay is content/provenance addressed across epochs."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import artifact_ledger as AL
import test_phase_io_commit_authority_p0_ae as fixtures


RUN_ID = "run-commit"


def _active_driver_output(tmp_path: Path, unit: str):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    output = scratchpad / "result.md"
    output.write_bytes(b"stable producer bytes\n")
    contract = fixtures._contract(unit, model=False)
    committed = fixtures._commit(scratchpad, tmp_path, contract)
    assert committed["semantic_status"] == "ACTIVE"
    return scratchpad, output, contract


def test_byte_identical_rematerialization_keeps_producer_authority(
    tmp_path: Path,
) -> None:
    scratchpad, output, contract = _active_driver_output(
        tmp_path, "driver.content_addressed",
    )
    prior_inode = output.stat().st_ino
    replacement = scratchpad / "replacement.tmp"
    replacement.write_bytes(output.read_bytes())
    os.replace(replacement, output)

    assert output.stat().st_ino != prior_inode
    assert AL.validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        fixtures._launch(contract),
        run_id=RUN_ID,
        actor="DRIVER",
    ) == []
    assert AL.semantic_input_prebind_producer_authority_issues(
        scratchpad,
        tmp_path,
        ("scratchpad:result.md",),
        run_id=RUN_ID,
    ) == []


def test_content_change_still_invalidates_producer_authority(
    tmp_path: Path,
) -> None:
    scratchpad, output, contract = _active_driver_output(
        tmp_path, "driver.changed_content",
    )
    output.write_bytes(b"different producer bytes\n")

    issues = AL.validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        fixtures._launch(contract),
        run_id=RUN_ID,
        actor="DRIVER",
    )
    assert any(
        "live bytes differ from issued output authority" in issue
        for issue in issues
    )


@pytest.mark.parametrize("alias_kind", ("hardlink", "symlink"))
def test_content_addressed_replay_still_rejects_link_aliases(
    tmp_path: Path, alias_kind: str,
) -> None:
    scratchpad, output, contract = _active_driver_output(
        tmp_path, f"driver.{alias_kind}",
    )
    peer = scratchpad / "peer.md"
    peer.write_bytes(output.read_bytes())
    output.unlink()
    if alias_kind == "hardlink":
        os.link(peer, output)
    else:
        output.symlink_to(peer)

    assert AL.validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        fixtures._launch(contract),
        run_id=RUN_ID,
        actor="DRIVER",
    )
