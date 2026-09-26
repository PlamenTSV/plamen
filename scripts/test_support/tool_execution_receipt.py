"""Deterministic execution-receipt fixtures for ledger unit tests."""

from __future__ import annotations

import hashlib
import json
from typing import Sequence

from tool_coverage_ledger import build_external_tool_execution_receipt


def fixture_execution_receipt(
    tool: str = "opengrep",
    *,
    executable_path: str = "/opt/plamen/bin/opengrep",
    returncode: int = 0,
    accepted_returncodes: Sequence[int] = (0,),
    cwd: str = "/audit/project",
) -> dict:
    authority = {
        "schema": "plamen.runtime-tool-identity.v2",
        "tool_id": tool,
        "identity_kind": "command",
        "command": [tool, "--version"],
        "resolved_executable": executable_path,
        "version": f"{tool} fixture-1.0.0",
        "executable_sha256": "a" * 64,
        "executable_bytes": 4096,
        "identity_status": "MATCH",
        "authority_status": "MATCH",
        "deterministic_provider_authority": True,
        "reason": "",
    }
    authority["authority_digest"] = hashlib.sha256(
        json.dumps(
            authority,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    return build_external_tool_execution_receipt(
        execution_tool=tool,
        provider_authority_before=authority,
        provider_authority_after=authority,
        argv=(executable_path, "scan"),
        cwd=cwd,
        workspace_root=cwd,
        environment_bindings={"PATH": "b" * 64},
        excluded_secret_key_count=2,
        started_at="2026-09-15T09:00:00Z",
        finished_at="2026-09-15T09:00:01Z",
        duration_ms=1000,
        returncode=returncode,
        accepted_returncodes=accepted_returncodes,
        timed_out=False,
        stdout="fixture stdout",
        stderr="",
        stdout_observed_bytes=len(b"fixture stdout"),
        stderr_observed_bytes=0,
        stdout_retained_bytes=len(b"fixture stdout"),
        stderr_retained_bytes=0,
        stdout_sha256=hashlib.sha256(b"fixture stdout").hexdigest(),
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
        stdout_truncated=False,
        stderr_truncated=False,
        process_tree_terminated=True,
        containment_capability={
            "platform": "TEST",
            "write_confinement": "FIXTURE",
        },
        runner_implementation="fixture.owned_runner",
        runner_sha256="c" * 64,
        executable_binding_sha256="e" * 64,
    )
