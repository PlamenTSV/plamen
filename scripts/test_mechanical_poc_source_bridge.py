"""Executable-source bridge regressions for compatibility PoC verification."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import audit_snapshot as S
import mechanical_poc_source as B
import mechanical_prewarm as P
import posix_v2_compat_runtime as C
import spike_mechanical_poc as SP
from queue_work_items import VerifierOutputIdentity, VerifierOutputReceipt
from supply_chain_gate import gate_supply_chain


DRIVER = "sha256:" + "d" * 64


def _verify(path: Path, *, duplicate: bool = False, fence: str = "solidity") -> bytes:
    section = (
        "### Mechanical PoC Source\n\n"
        f"```{fence}\n"
        "contract Candidate { function test_candidate() public {} }\n"
        "```\n"
    )
    raw = (
        "# Verification: H-01\n\n"
        "**Test File**: `test/Candidate.t.sol`\n"
        "**Test Function**: `test_candidate`\n\n"
        + section
        + ("\n" + section if duplicate else "")
    ).encode("utf-8")
    path.write_bytes(raw)
    return raw


def _receipt(path: Path, raw: bytes) -> None:
    identity = VerifierOutputIdentity(
        work_item_id="H-01",
        queue_record_digest="a" * 64,
        work_plan_digest="b" * 64,
        shard_id="sc_verify_shard_a",
        expected_output_file="verify_H-01.md",
        expected_output_identity="scratchpad:verify_H-01.md",
    )
    receipt = VerifierOutputReceipt.bind(
        identity,
        raw,
        severity_proposal=b"{}",
        launch_digest="c" * 64,
        verifier_backend="codex",
    )
    path.with_name("verify_H-01.receipt.json").write_text(
        receipt.to_json(), encoding="utf-8"
    )


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _prewarm_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    project = tmp_path / "project"
    source = project / "source"
    scratch = project / ".scratchpad"
    tools = tmp_path / "tools"
    source.mkdir(parents=True)
    scratch.mkdir()
    tools.mkdir()
    _write(source / "foundry.toml", "[profile.default]\n")
    _write(source / "src/Example.sol", "contract Example {}\n")
    forge = _write(
        tools / "forge",
        "#!/bin/sh\n"
        "mkdir -p \"$XDG_CACHE_HOME/compiler\"\n"
        "printf '[PASS] test_candidate()\\n'\n",
    )
    forge.chmod(0o755)
    monkeypatch.setenv(
        "PATH", os.pathsep.join((os.fspath(tools), "/usr/bin", "/bin"))
    )
    monkeypatch.setattr(
        S, "_runtime_tool_entries", lambda **_kwargs: [("@runtime/test", b"fixed")]
    )
    implementation = tmp_path / "implementation"
    for name in ("scripts", "prompts", "rules", "agents"):
        (implementation / name).mkdir(parents=True)
    _write(implementation / "scripts/plamen_driver.py", "VERSION=1\n")
    _write(implementation / "prompts/p.md", "method\n")
    _write(implementation / "rules/r.md", "rule\n")
    config = {
        "project_root": os.fspath(source),
        "scratchpad": os.fspath(scratch),
        "mode": "light",
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "codex",
    }
    snapshot = S.build_audit_snapshot(config, implementation)

    def guard() -> None:
        assert S.build_audit_snapshot(config, implementation) == snapshot

    session = C.issue_posix_v2_compat_session_for_installed_front(
        run_id="source-bridge-test", project_root=project, scratchpad=scratch
    )
    admission = gate_supply_chain(source, posix_compat_session=session)
    prewarm = P.run_compat_prewarm(
        session_authority=session,
        source_build_root=source.resolve(),
        language="evm",
        registry={},
        driver_identity=DRIVER,
        audit_snapshot=snapshot,
        assert_snapshot_current=guard,
        supply_chain_admission=admission,
        timeout_seconds=10,
    )
    return project, source, scratch, forge, session, prewarm


def test_extract_and_replay_safe_materialization(tmp_path: Path) -> None:
    verify = tmp_path / "verify_H-01.md"
    _verify(verify)
    source = B.extract_mechanical_poc_source(
        verify,
        language="evm",
        test_path="test/Candidate.t.sol",
        test_function="test_candidate",
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    first = B.materialize_mechanical_poc_source(workspace, source)
    second = B.materialize_mechanical_poc_source(workspace, source)
    assert first == second
    assert first.read_bytes() == source.source
    assert source.source_sha256 == hashlib.sha256(source.source).hexdigest()


def test_solidity_fuzz_signature_label_resolves_to_declared_function(
    tmp_path: Path,
) -> None:
    verify = tmp_path / "verify_H-01.md"
    verify.write_text(
        "# Verification: H-01\n\n"
        "- Test File: test/Candidate.t.sol\n"
        "- Test Function: test_candidate and testFuzz_candidate\n\n"
        "### Mechanical PoC Source\n\n```solidity\n"
        "contract Candidate { function testFuzz_candidate(uint96 amount) public {} }\n"
        "```\n",
        encoding="utf-8",
    )
    source = B.extract_mechanical_poc_source(
        verify, language="evm", test_path="test/Candidate.t.sol",
        test_function="testFuzz_candidate(uint96)",
    )
    assert b"function testFuzz_candidate(" in source.source


def test_harm_and_fuzz_labels_are_both_authenticated(tmp_path: Path) -> None:
    verify = tmp_path / "verify_H-01.md"
    verify.write_text(
        "### Mechanical PoC Source\n\n```solidity\n"
        "contract Candidate {"
        " function test_candidate() public {}"
        " function testFuzz_candidate(uint96 amount) public {}"
        " }\n```\n",
        encoding="utf-8",
    )
    source = B.extract_mechanical_poc_source(
        verify, language="evm", test_path="test/Candidate.t.sol",
        test_function="test_candidate and testFuzz_candidate",
    )
    assert b"function test_candidate(" in source.source
    assert SP.parse_verify_file(verify, language="evm").test_function == "test_candidate"
    with pytest.raises(B.MechanicalPoCSourceError, match="POC_SOURCE_FUNCTION"):
        B.extract_mechanical_poc_source(
            verify, language="evm", test_path="test/Candidate.t.sol",
            test_function="test_candidate and testFuzz_missing",
        )


def test_shared_id_harm_and_fuzz_shorthand_selects_real_primary(
    tmp_path: Path,
) -> None:
    verify = tmp_path / "verify_H-12.md"
    verify.write_text(
        "# Verification: H-12\n\n"
        "- Test File: test/H12.t.sol\n"
        "- Test Function: test_H12_and_fuzz_H12\n\n"
        "### Mechanical PoC Source\n\n```solidity\n"
        "contract Candidate {"
        " function test_H12() public {}"
        " function testFuzz_H12(uint96 amount) public {}"
        " }\n```\n",
        encoding="utf-8",
    )
    B.extract_mechanical_poc_source(
        verify, language="evm", test_path="test/H12.t.sol",
        test_function="test_H12_and_fuzz_H12",
    )
    assert SP.parse_verify_file(verify, language="evm").test_function == "test_H12"
    verify.write_text(
        verify.read_text(encoding="utf-8").replace(
            "function testFuzz_H12(", "function testFuzz_other("
        ),
        encoding="utf-8",
    )
    with pytest.raises(B.MechanicalPoCSourceError, match="POC_SOURCE_FUNCTION"):
        B.extract_mechanical_poc_source(
            verify, language="evm", test_path="test/H12.t.sol",
            test_function="test_H12_and_fuzz_H12",
        )


def test_proof_scope_prose_after_fence_is_not_executable_source(
    tmp_path: Path,
) -> None:
    verify = tmp_path / "verify_H-01.md"
    verify.write_text(
        "### Mechanical PoC Source\n\n```solidity\n"
        "contract Candidate { function test_candidate() public {} }\n"
        "```\n\nProof scope: this harness checks only the local branch.\n",
        encoding="utf-8",
    )
    source = B.extract_mechanical_poc_source(
        verify, language="evm", test_path="test/Candidate.t.sol",
        test_function="test_candidate",
    )
    assert source.source == (
        b"contract Candidate { function test_candidate() public {} }\n"
    )


def test_second_fence_in_source_section_remains_ambiguous(
    tmp_path: Path,
) -> None:
    verify = tmp_path / "verify_H-01.md"
    verify.write_text(
        "### Mechanical PoC Source\n\n```solidity\n"
        "contract Candidate { function test_candidate() public {} }\n"
        "```\n\n```solidity\ncontract Other {}\n```\n",
        encoding="utf-8",
    )
    with pytest.raises(B.MechanicalPoCSourceError, match="POC_SOURCE_SECTION"):
        B.extract_mechanical_poc_source(
            verify, language="evm", test_path="test/Candidate.t.sol",
            test_function="test_candidate",
        )


@pytest.mark.parametrize(
    "function",
    ["testFuzz_candidate(uint96);evil", "testFuzz_candidate((uint96))", "testFuzz_other(uint96)"],
)
def test_signature_label_does_not_bypass_function_identity(
    tmp_path: Path, function: str,
) -> None:
    verify = tmp_path / "verify_H-01.md"
    verify.write_text(
        "### Mechanical PoC Source\n\n```solidity\n"
        "contract Candidate { function testFuzz_candidate(uint96 amount) public {} }\n"
        "```\n",
        encoding="utf-8",
    )
    with pytest.raises(B.MechanicalPoCSourceError, match="POC_SOURCE_FUNCTION"):
        B.extract_mechanical_poc_source(
            verify, language="evm", test_path="test/Candidate.t.sol",
            test_function=function,
        )


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("duplicate", "POC_SOURCE_SECTION"),
        ("wrong-language", "POC_SOURCE_LANGUAGE"),
        ("traversal", "POC_SOURCE_PATH"),
        ("missing-function", "POC_SOURCE_FUNCTION"),
    ],
)
def test_ambiguous_or_unsafe_source_is_rejected(
    tmp_path: Path, case: str, code: str
) -> None:
    verify = tmp_path / "verify_H-01.md"
    _verify(
        verify,
        duplicate=case == "duplicate",
        fence="rust" if case == "wrong-language" else "solidity",
    )
    test_path = "../Candidate.t.sol" if case == "traversal" else "test/Candidate.t.sol"
    function = "test_absent" if case == "missing-function" else "test_candidate"
    with pytest.raises(B.MechanicalPoCSourceError, match=code):
        B.extract_mechanical_poc_source(
            verify,
            language="evm",
            test_path=test_path,
            test_function=function,
        )


def test_conflicting_replay_and_symlink_parent_are_rejected(tmp_path: Path) -> None:
    verify = tmp_path / "verify_H-01.md"
    _verify(verify)
    source = B.extract_mechanical_poc_source(
        verify,
        language="evm",
        test_path="test/Candidate.t.sol",
        test_function="test_candidate",
    )
    workspace = tmp_path / "workspace"
    (workspace / "test").mkdir(parents=True)
    (workspace / "test/Candidate.t.sol").write_text("different", encoding="utf-8")
    with pytest.raises(B.MechanicalPoCSourceError, match="POC_SOURCE_REPLAY"):
        B.materialize_mechanical_poc_source(workspace, source)

    aliased = tmp_path / "aliased"
    aliased.mkdir()
    (aliased / "test").symlink_to(tmp_path)
    with pytest.raises(B.MechanicalPoCSourceError, match="POC_SOURCE_WORKSPACE"):
        B.materialize_mechanical_poc_source(aliased, source)


def test_real_candidate_uses_typed_executor_and_never_writes_source_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, source_root, scratch, forge, session, prewarm = _prewarm_fixture(
        tmp_path, monkeypatch
    )
    try:
        verify = scratch / "verify_H-01.md"
        raw = _verify(verify)
        _receipt(verify, raw)
        source = B.extract_mechanical_poc_source(
            verify,
            language="evm",
            test_path="test/Candidate.t.sol",
            test_function="test_candidate",
        )
        B.materialize_mechanical_poc_source(prewarm.workspace_root, source)
        result = P.run_compat_candidate(
            session_authority=session,
            prewarm=prewarm,
            verify_path=verify,
            finding_id="H-01",
            constituent_id="H-01.primary",
            test_relative_path=source.relative_path,
            test_function="test_candidate",
            argv=[os.fspath(forge), "test", "--match-test", "test_candidate"],
            environment_overrides={"FOUNDRY_PROFILE": "default"},
            timeout_seconds=10,
        )
        assert result.returncode == 0
        assert result.terminal_status == "COMPLETED"
        assert "[PASS]" in result.stdout
        assert result.request_sha256
        terminal = json.loads((scratch / result.receipt_relative_path).read_text())
        assert terminal["purpose"] == "CANDIDATE_POC"
        assert terminal["actual_tool_started"] is True
        assert terminal["actual_tool_completion_observed"] is True
        assert terminal["subject_pre"]["sha256"] == source.source_sha256
        assert not (source_root / source.relative_path).exists()
        assert not (project / source.relative_path).exists()
    finally:
        session.close()
