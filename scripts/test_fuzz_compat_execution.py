from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform

import pytest

import fuzz_compat_execution as C
import fuzz_workspace_authority as F
import posix_v2_compat_runtime as R


pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="POSIX v2 compatibility campaign execution uses macOS Seatbelt",
)


def _bundle() -> bytes:
    return b"""# Invariant Fuzz Results

## Result Status: EXECUTION_REQUESTED

## No Findings

Campaign execution is delegated to the driver.

## Driver Fuzz Harness Bundle

### Generated File: `test/invariant/InvariantFuzz.t.sol`
```solidity
contract InvariantFuzz { function invariant_fixture() external pure {} }
```

## Driver Fuzz Campaign

**Tool**: forge
**CWD**: .
**Arguments JSON**: ["forge","test","--match-contract","InvariantFuzz","-vv"]
**Assertions JSON**: ["INV-FIXTURE"]
**Expected Cases**: 6400

<!-- PLAMEN_STATUS: COMPLETE -->
"""


def test_driver_materializes_and_executes_compat_campaign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    tools = tmp_path / "tools"
    (project / "src").mkdir(parents=True)
    scratch.mkdir()
    tools.mkdir()
    (project / "foundry.toml").write_text("[profile.default]\nsrc='src'\n")
    (project / "src/Fixture.sol").write_text("contract Fixture {}\n")
    forge = tools / "forge"
    forge.write_text("#!/bin/sh\nprintf 'fixture campaign ran\\n'\n")
    forge.chmod(0o755)
    monkeypatch.setenv("PATH", os.fspath(tools) + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(C, "gate_supply_chain", lambda *_a, **_kw: object())
    monkeypatch.setattr(
        C,
        "project_supply_chain_admission",
        lambda *_a, **_kw: {"admission_sha256": "b" * 64},
    )

    receipt = F.materialize_fuzz_workspace(
        scratchpad=scratch,
        build_root=project,
        project_root=project,
        job_id="invariant-fuzz",
        language="evm",
        role="invariant_fuzz",
        run_id="run-fuzz-compat",
        source_snapshot_digest="a" * 64,
    )
    assert receipt["status"] == "READY"
    model_output = scratch / "invariant_fuzz_results.md"
    model_output.write_bytes(_bundle())
    session = R.issue_posix_v2_compat_session_for_installed_front(
        run_id="run-fuzz-compat",
        project_root=project,
        scratchpad=scratch,
    )
    try:
        command = C.execute_compat_fuzz_campaign(
            session_authority=session,
            authority_path=Path(str(receipt["authority_path"])),
            model_output_path=model_output,
            role="invariant_fuzz",
            timeout_seconds=30,
        )
        assert command["returncode"] == 0
        assert command["process_tree_policy"] == "POSIX_V2_COMPAT_SEATBELT_REDUCED"
        assert command["environment_overrides"]["FOUNDRY_OFFLINE"] == "true"
        assert command["environment_overrides"]["FOUNDRY_INVARIANT_RUNS"] == "256"
        assert command["environment_overrides"]["FOUNDRY_INVARIANT_DEPTH"] == "25"
        assert command["environment_overrides"][
            "FOUNDRY_INVARIANT_FAIL_ON_REVERT"
        ] == "false"
        # Process-local replay returns the same authenticated command identity.
        replay = C.execute_compat_fuzz_campaign(
            session_authority=session,
            authority_path=Path(str(receipt["authority_path"])),
            model_output_path=model_output,
            role="invariant_fuzz",
            timeout_seconds=30,
        )
        assert replay["payload_digest"] == command["payload_digest"]
        result = F.finalize_fuzz_workspace(Path(str(receipt["authority_path"])))
        assert result["status"] == "MEASURED"
        assert result["campaign_execution_status"] == "EXECUTED_SUCCESS"
        assert result["proof_authority"] == "EXECUTION_SCOPE_REQUIRES_CONSUMER"
        assert F.validate_fuzz_workspace_result(
            Path(str(receipt["authority_path"]))
        ) == []
    finally:
        session.close()
