from __future__ import annotations

import json
import hashlib
import os
import sys
from pathlib import Path

import pytest

from tool_coverage_ledger import (
    LEDGER_FILENAME,
    ToolCoverageLedgerError,
    ToolOutcome,
    ToolOutcomeState,
    bind_succeeded_tool_outcome,
    load_tool_coverage_ledger,
    record_tool_outcome,
)


def test_success_requires_schema_validated_count() -> None:
    with pytest.raises(ToolCoverageLedgerError):
        ToolOutcome(
            capability_id="scanner.example",
            tool="example",
            state=ToolOutcomeState.SUCCEEDED,
            reason="looked clean",
            finding_count=0,
            schema_validated=False,
        )


def test_ledger_merges_capabilities_without_erasing_debt(tmp_path: Path) -> None:
    record_tool_outcome(
        tmp_path,
        ToolOutcome.debt(
            "scanner.a",
            "a",
            ToolOutcomeState.UNAVAILABLE,
            "binary absent",
        ),
    )
    for name in ("opengrep_results.sarif", "opengrep_findings.md"):
        (tmp_path / name).write_text(name, encoding="utf-8")
    project_identity = os.path.normcase(
        str(tmp_path.resolve())
    ).replace("\\", "/")
    context = {
        "run_id": "ledger-merge-fixture",
        "phase": "recon-prebreadth",
        "snapshot_sha256": "1" * 64,
        "project_root_sha256": hashlib.sha256(
            project_identity.encode("utf-8")
        ).hexdigest(),
        "ecosystem": "evm",
        "pipeline": "sc",
        "mode": "thorough",
        "platform": (
            "windows"
            if sys.platform == "win32"
            else "macos"
            if sys.platform == "darwin"
            else "linux"
            if sys.platform.startswith("linux")
            else sys.platform
        ),
    }
    success = bind_succeeded_tool_outcome(
        tmp_path,
        ToolOutcome.succeeded(
            "opengrep.static-analysis",
            "opengrep",
            0,
            artifacts=(
                "opengrep_results.sarif",
                "opengrep_findings.md",
            ),
        ),
        context=context,
    )
    record_tool_outcome(tmp_path, success)

    loaded = load_tool_coverage_ledger(tmp_path)
    assert loaded["scanner.a"].state is ToolOutcomeState.UNAVAILABLE
    assert (
        loaded["opengrep.static-analysis"].state
        is ToolOutcomeState.SUCCEEDED
    )
    assert loaded["opengrep.static-analysis"].schema_validated is True
    assert loaded["opengrep.static-analysis"].finding_count == 0


def test_corrupt_existing_ledger_is_not_silently_overwritten(
    tmp_path: Path,
) -> None:
    path = tmp_path / LEDGER_FILENAME
    path.write_text('{"schema_version": 1}', encoding="utf-8")

    with pytest.raises(ToolCoverageLedgerError):
        record_tool_outcome(
            tmp_path,
            ToolOutcome.debt(
                "scanner.a",
                "a",
                ToolOutcomeState.FAILED,
                "tool failed",
            ),
        )
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "schema_version": 1,
    }


def test_outcome_artifacts_must_be_scratch_relative() -> None:
    with pytest.raises(ToolCoverageLedgerError):
        ToolOutcome.succeeded(
            "scanner.a",
            "a",
            1,
            artifacts=("../outside.sarif",),
        )


def test_schema_valid_but_tampered_ledger_fails_digest_check(
    tmp_path: Path,
) -> None:
    record_tool_outcome(
        tmp_path,
        ToolOutcome.debt(
            "scanner.a",
            "a",
            ToolOutcomeState.SKIPPED,
            "not applicable",
        ),
    )
    path = tmp_path / LEDGER_FILENAME
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["capabilities"]["scanner.a"]["reason"] = "silently clean"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        ToolCoverageLedgerError, match="digest mismatch",
    ):
        load_tool_coverage_ledger(tmp_path)
