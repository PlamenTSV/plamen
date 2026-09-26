from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import pickle
import stat
import subprocess
import sys
import textwrap
import types
from typing import Any, Mapping, Sequence

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
import claude_phase_tool_policy as claude_policy
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import posix_v2_compat_runtime as compat
import posix_v2_compat_claude as claude_adapter


def _accept_staged_validator(
    staged: Mapping[str, bytes], context: Mapping[str, Any]
) -> Sequence[str]:
    if context.get("token") != "frozen-context":
        return ["context binding changed"]
    if list(staged.values()) != [b"replacement finding\n"]:
        return ["unexpected staged bytes"]
    return []


def _reject_staged_validator(
    _staged: Mapping[str, bytes], _context: Mapping[str, Any]
) -> Sequence[str]:
    return ["zeta semantic rejection", "alpha semantic rejection", "alpha semantic rejection"]


def _accept_last_message_staged_validator(
    staged: Mapping[str, bytes], _context: Mapping[str, Any]
) -> Sequence[str]:
    return (
        []
        if list(staged.values()) == [b"fake final message\n"]
        else ["unexpected recovery bytes"]
    )


def _roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    output = scratchpad / "output"
    output.mkdir(parents=True)
    return project, scratchpad, output


def _fake_codex(
    path: Path,
    *,
    sleep_seconds: float = 0.0,
    write_expected_output: bool = True,
    observed_model: str | None = "gpt-5.4",
) -> Path:
    output_write = (
        "blocks = re.findall(r'```json\\n(.*?)\\n```', "
        "prompt.decode('utf-8'), re.S); "
        "route = json.loads(blocks[-1])['output_routes'][0]; "
        "destination = Path(route['path']); "
        "destination.parent.mkdir(parents=True, exist_ok=True); "
        "destination.write_text('model finding\\n')"
        if write_expected_output
        else "pass"
    )
    startup_write = (
        "pass"
        if observed_model is None
        else (
            "sys.stderr.write("
            + repr(
                "OpenAI Codex v0.test\n"
                "--------\n"
                "workdir: /test\n"
                f"model: {observed_model}\n"
                "provider: openai\n"
                "--------\n"
                "user\n"
            )
            + ")"
        )
    )
    path.write_text(
        "#!" + sys.executable + "\n" + textwrap.dedent(
            f"""
            import json
            from pathlib import Path
            import re
            import sys
            import time

            if sys.argv[1:] == ["--version"]:
                print("codex-cli 0.test")
                raise SystemExit(0)
            {startup_write}
            prompt = sys.stdin.buffer.read()
            time.sleep({sleep_seconds!r})
            {output_write}
            output = Path(sys.argv[sys.argv.index("-o") + 1])
            output.write_bytes(b"fake final message\\n")
            print(json.dumps({{"type": "turn.completed", "prompt_sha256": __import__("hashlib").sha256(prompt).hexdigest()}}))
            """
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _fake_append_codex(path: Path, fragment: bytes) -> Path:
    path.write_text(
        "#!" + sys.executable + "\n" + textwrap.dedent(
            f"""
            import json
            from pathlib import Path
            import re
            import sys

            if sys.argv[1:] == ["--version"]:
                print("codex-cli 0.test")
                raise SystemExit(0)
            sys.stderr.write("OpenAI Codex v0.test\\n--------\\nworkdir: /test\\nmodel: gpt-5.4\\nprovider: openai\\n--------\\nuser\\n")
            prompt = sys.stdin.buffer.read().decode("utf-8")
            blocks = re.findall(r"```json\\n(.*?)\\n```", prompt, re.S)
            routing = json.loads(blocks[-1])
            route = routing["output_routes"][0]
            destination = Path(route["path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes({fragment!r})
            Path(sys.argv[sys.argv.index("-o") + 1]).write_bytes(b"done\\n")
            print(json.dumps({{"type": "turn.completed"}}))
            """
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _fake_claude(
    path: Path,
    *,
    permission_prompts_none: bool = True,
) -> Path:
    required_flags = (
        "--add-dir", "--disable-slash-commands", "--input-format",
        "--mcp-config", "--model", "--no-chrome", "--no-session-persistence",
        "--output-format", "--permission-mode", "--permission-prompts",
        "--print", "--prompt-suggestions", "--restricted", "--safe-mode",
        "--session-id", "--setting-sources", "--settings",
        "--strict-mcp-config", "--tools", "--verbose",
    )
    choice_flags = {
        "--input-format",
        "--output-format",
        "--permission-mode",
        "--permission-prompts",
    }
    help_text = "Usage: claude [options]\n" + "".join(
        f"  {flag} <value>\n"
        for flag in required_flags
        if flag not in choice_flags
    ) + (
        '  --input-format <format>  Input format: "text" (default), or\n'
        '                           "stream-json"\n'
        '  --output-format <format> Output format: "text" (default), "json",\n'
        '                           or "stream-json"\n'
        '  --permission-mode <mode> Permission mode (choices: "manual",\n'
        '                           "dontAsk")\n'
        '  --permission-prompts <target> Prompt target: "host" or\n'
        f'                                "{"none" if permission_prompts_none else "interactive"}"\n'
    )
    path.write_text(
        "#!" + sys.executable + "\n" + textwrap.dedent(
            f"""
            import json
            from pathlib import Path
            import re
            import sys

            if sys.argv[1:] == ["--version"]:
                print("2.1.263 (Claude Code)")
                raise SystemExit(0)
            if sys.argv[1:] == ["--help"]:
                sys.stdout.write({help_text!r})
                raise SystemExit(0)
            prompt = sys.stdin.buffer.read().decode("utf-8")
            route = json.loads(re.findall(r"```json\\n(.*?)\\n```", prompt, re.S)[-1])["output_routes"][0]
            destination = Path(route["path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text("model finding\\n", encoding="utf-8")
            print(json.dumps({{"type": "result", "session_id": "provider-session"}}))
            """
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _fake_claude_valid_stream(path: Path) -> Path:
    path = _fake_claude(path)
    marker = 'print(json.dumps({"type": "result", "session_id": "provider-session"}))'
    replacement = "\n".join((
        "session = sys.argv[sys.argv.index('--session-id') + 1]",
        "model = sys.argv[sys.argv.index('--model') + 1]",
        "events = [",
        "  {'type':'system','subtype':'init','uuid':'init','session_id':session,"
        "'claude_code_version':'2.1.263','cwd':str(Path.cwd()),'model':model,"
        "'permissionMode':'dontAsk','apiKeySource':'none',"
        "'tools':['Edit','Glob','Grep','Read','Write'],'mcp_servers':[],"
        "'plugins':[],'skills':[],'slash_commands':[],'plugin_errors':[],"
        "'agents':['claude','Explore','general-purpose','Plan'],"
        "'capabilities':['interrupt_receipt_v1','msg_lifecycle_v1'],"
        "'output_style':'default'},",
        "  {'type':'assistant','uuid':'assistant','session_id':session,"
        "'parent_tool_use_id':None,'message':{'id':'msg','type':'message',"
        "'role':'assistant','content':[{'type':'text','text':'done'}],"
        "'model':model,'stop_reason':'end_turn',"
        "'usage':{'input_tokens':1,'output_tokens':1}}},",
        "  {'type':'result','subtype':'success','uuid':'result',"
        "'session_id':session,'duration_ms':1,'duration_api_ms':1,"
        "'is_error':False,'num_turns':1,'result':'done','total_cost_usd':0.0,"
        "'usage':{'input_tokens':1,'output_tokens':1},"
        "'modelUsage':{model:{'inputTokens':1,'outputTokens':1,"
        "'cacheReadInputTokens':0,'cacheCreationInputTokens':0,"
        "'webSearchRequests':0,'costUSD':0.0,'provider':'firstParty',"
        "'canonicalModel':model}},'subagent_stats':{'spawned':0},"
        "'permission_denials':[],"
        "'stop_reason':'end_turn','origin':{'kind':'human'}},",
        "]",
        "for event in events: print(json.dumps(event))",
    ))
    source = path.read_text(encoding="utf-8")
    assert source.count(marker) == 1
    path.write_text(source.replace(marker, replacement), encoding="utf-8")
    path.chmod(0o755)
    return path


def _fake_claude_adapter(
    *,
    refusal: bool = False,
    reject_plan: bool = False,
) -> types.SimpleNamespace:
    class CompletionError(ValueError):
        def __init__(self, code: str) -> None:
            super().__init__(code)
            self.code = code

    def compile_plan(**kwargs: Any) -> Mapping[str, Any]:
        if reject_plan:
            raise CompletionError("FIXTURE_PLAN_REJECTED")
        assert kwargs["session_binding"]["backend"] == "claude"
        assert kwargs["phase_io_contract"].backend == "claude"
        assert kwargs["phase_io_launch"].backend == "claude"
        assert kwargs["executable_observation"]["version"] == "2.1.263"
        assert kwargs["phase_tool_boundary"] == {"tools": ["Read", "Grep"]}
        return {
            "provider_session_id": kwargs["provider_session_id"],
            "phase_io_contract_digest": kwargs["phase_io_contract"].digest,
            "phase_io_launch_digest": kwargs["phase_io_launch"].digest,
            "session_binding_sha256": kwargs["session_binding"][
                "session_binding_sha256"
            ],
            "model": kwargs["phase_io_launch"].model,
            "executable_observation_sha256": kwargs[
                "executable_observation"
            ]["observation_sha256"],
            "executable_version": kwargs["executable_observation"]["version"],
            "cwd": str(kwargs["cwd"]),
            "stdin_sha256": hashlib.sha256(kwargs["prompt_bytes"]).hexdigest(),
            "stdin_byte_count": len(kwargs["prompt_bytes"]),
            "output_routes_sha256": hashlib.sha256(json.dumps(
                list(kwargs["output_routes"]),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")).hexdigest(),
        }

    def project_plan(plan: Mapping[str, Any]) -> Mapping[str, Any]:
        core = {
            "schema": "plamen.posix-v2-compat-claude-plan.v1",
            "backend": "claude",
            "compatibility_mode": compat.COMPATIBILITY_MODE,
            "argv": ["-p", "--output-format", "stream-json"],
            "environment": {"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            "auth_mode": "CLAUDE_NATIVE_STORED_SUBSCRIPTION",
            "auth_binding_sha256": "a" * 64,
            "provider_session_id": plan["provider_session_id"],
            "executable_observation_sha256": plan[
                "executable_observation_sha256"
            ],
            "profile_sha256": "d" * 64,
            "expected_init_contract_sha256": "e" * 64,
            "expected_version": None,
            "phase_io_contract_digest": plan["phase_io_contract_digest"],
            "phase_io_launch_digest": plan["phase_io_launch_digest"],
            "session_binding_sha256": plan["session_binding_sha256"],
            "model": plan["model"],
            "executable_version": plan["executable_version"],
            "cwd": plan["cwd"],
            "stdin_sha256": plan["stdin_sha256"],
            "stdin_byte_count": plan["stdin_byte_count"],
            "output_routes_sha256": plan["output_routes_sha256"],
        }
        core["plan_sha256"] = compat._mapping_sha(core)
        return core

    def validate_completion(
        _plan: Mapping[str, Any],
        *,
        stdout: bytes,
        stderr: bytes,
        returncode: int,
    ) -> Mapping[str, Any]:
        assert b'"type": "result"' in stdout
        assert stderr == b""
        assert returncode == 0
        if refusal:
            raise CompletionError("RESULT_CYBER_REFUSAL")
        return {
            "status": "COMPLETED",
            "observed_model": "claude-sonnet-5",
            "session_id": "provider-session",
            "stream_sha256": hashlib.sha256(stdout).hexdigest(),
        }

    def replay_completion(
        _plan: Mapping[str, Any], completion: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        return completion

    return types.SimpleNamespace(
        compile_posix_v2_compat_claude_plan=compile_plan,
        project_posix_v2_compat_claude_plan=project_plan,
        replay_posix_v2_compat_claude_completion=replay_completion,
        validate_posix_v2_compat_claude_completion=validate_completion,
    )


def _fake_routed_codex(
    path: Path,
    raw: bytes,
    *,
    mutate_canonical: bytes | None = None,
    mutate_input: bytes | None = None,
    exit_code: int = 0,
) -> Path:
    canonical_write = (
        "pass"
        if mutate_canonical is None
        else f"Path(route['canonical_path']).write_bytes({mutate_canonical!r})"
    )
    input_write = (
        "pass"
        if mutate_input is None
        else f"Path('input.md').write_bytes({mutate_input!r})"
    )
    path.write_text(
        "#!" + sys.executable + "\n" + textwrap.dedent(
            f"""
            import json
            from pathlib import Path
            import re
            import sys

            if sys.argv[1:] == ["--version"]:
                print("codex-cli 0.test")
                raise SystemExit(0)
            sys.stderr.write("OpenAI Codex v0.test\\n--------\\nworkdir: /test\\nmodel: gpt-5.4\\nprovider: openai\\n--------\\nuser\\n")
            prompt = sys.stdin.buffer.read().decode("utf-8")
            blocks = re.findall(r"```json\\n(.*?)\\n```", prompt, re.S)
            route = json.loads(blocks[-1])["output_routes"][0]
            destination = Path(route["path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes({raw!r})
            {canonical_write}
            {input_write}
            Path(sys.argv[sys.argv.index("-o") + 1]).write_bytes(b"done\\n")
            print(json.dumps({{"type": "turn.completed"}}))
            raise SystemExit({exit_code!r})
            """
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _session(
    tmp_path: Path,
    *,
    backend: str = "codex",
) -> tuple[compat.PosixV2CompatSessionAuthority, Path, Path, Path]:
    project, scratchpad, output = _roots(tmp_path)
    (scratchpad / "input.md").write_text("bound input\n", encoding="utf-8")
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id="run-1",
        project_root=project,
        scratchpad=scratchpad,
        backend=backend,
    )
    return session, project, scratchpad, output


def _phase_io_authority(
    project: Path,
    scratchpad: Path,
    *,
    timeout: float = 10,
    backend: str = "codex",
    model: str = "gpt-5.4",
) -> tuple[PhaseIOContract, LaunchSpec]:
    key = canonical_work_unit_key(
        "sc", "thorough", "evm", backend, "recon", "worker.r1"
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend=backend,
        phase="recon",
        work_unit_id="worker.r1",
        outputs=(ArtifactSpec(
            root="scratchpad",
            path="output/finding.md",
            owner_key=key,
            artifact_class="REQUIRED",
            writer="MODEL",
            write_mode="CREATE",
        ),),
        immutable_inputs=("scratchpad:input.md",),
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend=backend,
        model=model,
        timeout_s=max(1, int(timeout)),
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad, project, contract, launch, run_id="run-1"
    )
    return contract, launch


def _real_claude_boundary(
    scratchpad: Path,
    project: Path,
    contract: PhaseIOContract,
    staged_output: Path,
) -> dict[str, Any]:
    root = scratchpad / "_real_claude_boundary"
    policy_path = root / "policy.json"
    settings_path = root / "settings.json"
    mcp_path = root / "mcp.json"
    receipts = root / "receipts"
    manifest, _settings = claude_policy.write_policy_bundle(
        policy_path=policy_path,
        settings_path=settings_path,
        hook_script=Path(claude_policy.__file__),
        run_id="run-1",
        phase=contract.phase,
        attempt=1,
        expected_cwd=scratchpad,
        project_root=project,
        scratchpad_root=scratchpad,
        methodology_read_roots=(),
        exact_read_files=(scratchpad / "input.md",),
        exact_write_files=(staged_output,),
        forbidden_read_files=(),
        receipt_directory=receipts,
    )
    mcp_path.write_bytes(
        claude_policy.canonical_json_bytes({"mcpServers": {}})
    )
    ledger = read_artifact_ledger(scratchpad)
    return {
        "phase": contract.phase,
        "attempt": 1,
        "contract_key": contract.key,
        "contract_digest": contract.digest,
        "input_set_digest": ledger["work_units"][contract.key][
            "input_set_digest"
        ],
        "manifest_digest": manifest["manifest_digest"],
        "policy_path": str(policy_path),
        "settings_path": str(settings_path),
        "mcp_config_path": str(mcp_path),
        "receipt_directory": str(receipts),
        "write_namespace": str(staged_output.parent),
    }


def _replace_phase_io_authority(
    project: Path,
    scratchpad: Path,
    *,
    base: bytes,
) -> tuple[PhaseIOContract, LaunchSpec]:
    output_path = scratchpad / "findings_inventory.md"
    key = canonical_work_unit_key(
        "sc", "thorough", "evm", "codex", "inventory", "additive_reemit"
    )
    producer_key = canonical_work_unit_key(
        "sc", "thorough", "evm", "codex", "inventory", "canonical_aggregate"
    )
    producer = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="inventory",
        work_unit_id="canonical_aggregate",
        outputs=(ArtifactSpec(
            root="scratchpad",
            path="findings_inventory.md",
            owner_key=producer_key,
            artifact_class="REQUIRED",
            writer="MODEL",
            write_mode="CREATE",
            consumers=(key,),
        ),),
    )
    producer_launch = LaunchSpec(
        work_unit_key=producer_key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        model="gpt-5.4",
        timeout_s=10,
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad, project, producer, producer_launch, run_id="run-1"
    )
    output_path.write_bytes(base)
    record_work_unit_artifacts(
        scratchpad,
        project,
        producer,
        producer_launch,
        run_id="run-1",
        actor="MODEL",
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="inventory",
        work_unit_id="additive_reemit",
        outputs=(ArtifactSpec(
            root="scratchpad",
            path="findings_inventory.md",
            owner_key=key,
            artifact_class="REQUIRED",
            writer="MODEL",
            write_mode="REPLACE",
        ),),
        immutable_inputs=("scratchpad:input.md",),
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        model="gpt-5.4",
        timeout_s=10,
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad, project, contract, launch, run_id="run-1"
    )
    return contract, launch


def _execute(
    monkeypatch: pytest.MonkeyPatch,
    session: compat.PosixV2CompatSessionAuthority,
    project: Path,
    scratchpad: Path,
    output: Path,
    binary: Path,
    *,
    timeout: float = 10.0,
    attempt: int = 1,
    label: str = "recon-worker",
    phase_io_authority: tuple[PhaseIOContract, LaunchSpec] | None = None,
    staged_output_validator: Any = None,
    staged_output_context: Mapping[str, Any] | None = None,
    staged_output_input_identities: Sequence[str] = (),
) -> int:
    monkeypatch.setattr(compat.shutil, "which", lambda _name: str(binary))
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "a" * 64),
    )
    contract, launch = (
        phase_io_authority
        if phase_io_authority is not None
        else _phase_io_authority(project, scratchpad, timeout=timeout)
    )
    return compat.run_codex_exec(
        session_authority=session,
        prompt="Return the sentinel.",
        phase_name=contract.phase,
        needs_mcp=True,
        config={"_run_id": "run-1", "project_root": str(project)},
        scratchpad=scratchpad,
        attempt=attempt,
        label=label,
        expected_outputs=tuple(spec.path for spec in contract.outputs),
        timeout=timeout,
        effective_model="gpt-5.4",
        working_directory=scratchpad,
        writable_directories=(output,),
        phase_io_contract=contract,
        phase_io_launch=launch,
        staged_output_validator=staged_output_validator,
        staged_output_context=staged_output_context,
        staged_output_input_identities=staged_output_input_identities,
    )


def test_auth_admission_reads_and_hashes_exact_fd_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    codex_home = home / ".codex"
    codex_home.mkdir(parents=True)
    auth_path = codex_home / "auth.json"
    raw = b'{"tokens":{"access_token":"original"}}\n'
    auth_path.write_bytes(raw)
    auth_path.chmod(0o600)
    monkeypatch.setattr(compat, "_account_home", lambda: home)
    mode, admitted, digest = compat._load_ambient_codex_auth()
    assert mode == "PRIVATE_AUTH_JSON_COPY"
    assert admitted == raw
    assert digest == hashlib.sha256(raw).hexdigest()


def test_auth_admission_rejects_path_replacement_during_fd_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    codex_home = home / ".codex"
    codex_home.mkdir(parents=True)
    auth_path = codex_home / "auth.json"
    original = b'{"tokens":{"access_token":"original"}}\n'
    replacement = b'{"tokens":{"access_token":"replacement"}}\n'
    auth_path.write_bytes(original)
    auth_path.chmod(0o600)
    replacement_path = codex_home / "replacement.json"
    replacement_path.write_bytes(replacement)
    replacement_path.chmod(0o600)
    monkeypatch.setattr(compat, "_account_home", lambda: home)
    monkeypatch.delenv("CODEX_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    original_read = os.read
    replaced = False

    def replace_path_then_read(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        if not replaced:
            replaced = True
            os.replace(replacement_path, auth_path)
        return original_read(descriptor, size)

    monkeypatch.setattr(compat.os, "read", replace_path_then_read)
    with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
        compat._load_ambient_codex_auth()
    assert replaced is True
    assert caught.value.code == "FILE_ADMISSION"
    assert auth_path.read_bytes() == replacement


def test_codex_binary_hash_rejects_in_place_growth_during_fd_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = _fake_codex(tmp_path / "codex")
    monkeypatch.setattr(compat.shutil, "which", lambda _name: str(binary))
    original_read = os.read
    mutated = False

    def mutate_binary_then_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        if not mutated:
            mutated = True
            with binary.open("ab") as handle:
                handle.write(b"# raced\n")
        return original_read(descriptor, size)

    monkeypatch.setattr(compat.os, "read", mutate_binary_then_read)
    with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
        compat._resolve_codex_binary()
    assert mutated is True
    assert caught.value.code == "FILE_ADMISSION"


def test_authority_is_process_local_opaque_and_not_ambient(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, _project, _scratchpad, _output = _session(tmp_path)
    assert session.binding["mode"] == compat.COMPATIBILITY_MODE
    assert session.binding["native_broker_authority"] is False
    assert session.binding["wer_authority"] is False
    with pytest.raises(TypeError):
        compat.PosixV2CompatSessionAuthority()
    with pytest.raises(TypeError):
        copy.copy(session)
    with pytest.raises(TypeError):
        pickle.dumps(session)
    shell = object.__new__(compat.PosixV2CompatSessionAuthority)
    monkeypatch.setenv("PLAMEN_POSIX_COMPAT_V2", "1")
    with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
        compat.require_posix_v2_compat_session(shell)
    assert caught.value.code == "SESSION_AUTHORITY"
    session.close()


def test_session_binds_exact_backend_before_provider_or_auth_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(
        tmp_path, backend="claude"
    )
    contract, launch = _phase_io_authority(
        project,
        scratchpad,
        backend="claude",
        model="claude-sonnet-5",
    )
    monkeypatch.setattr(
        compat,
        "_resolve_codex_binary",
        lambda: (_ for _ in ()).throw(AssertionError("provider touched")),
    )
    try:
        with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
            compat.run_codex_exec(
                session_authority=session,
                prompt="Return the sentinel.",
                phase_name=contract.phase,
                needs_mcp=False,
                config={"_run_id": "run-1", "project_root": str(project)},
                scratchpad=scratchpad,
                attempt=1,
                label="recon-worker",
                expected_outputs=tuple(spec.path for spec in contract.outputs),
                timeout=10,
                effective_model="claude-sonnet-5",
                working_directory=scratchpad,
                writable_directories=(output,),
                phase_io_contract=contract,
                phase_io_launch=launch,
            )
        assert caught.value.code == "SESSION_AUTHORITY"
        assert not (scratchpad / ".posix_v2_compat_receipts").exists()
    finally:
        session.close()


def test_session_rejects_unknown_backend_before_path_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, _output = _roots(tmp_path)
    monkeypatch.setattr(
        compat,
        "_recover_stale_private_runtime",
        lambda _path: (_ for _ in ()).throw(AssertionError("recovery touched")),
    )
    with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
        compat.issue_posix_v2_compat_session_for_installed_front(
            run_id="run-1",
            project_root=project,
            scratchpad=scratchpad,
            backend="other",
        )
    assert caught.value.code == "SESSION_AUTHORITY"


def test_child_environment_binds_passwd_user_not_ambient_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("USER", "ambient-substitution")
    monkeypatch.setattr(
        compat.pwd,
        "getpwuid",
        lambda _uid: types.SimpleNamespace(
            pw_dir=str(tmp_path),
            pw_name="trusted-account",
        ),
    )
    environment = compat._base_child_environment()
    assert environment["HOME"] == str(tmp_path)
    assert environment["USER"] == "trusted-account"
    assert "ambient-substitution" not in environment.values()


def test_claude_capability_probe_requires_noninteractive_prompt_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = _fake_claude(
        tmp_path / "claude",
        permission_prompts_none=False,
    )
    monkeypatch.setattr(compat.shutil, "which", lambda name: str(binary))
    with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
        compat._resolve_claude_binary()
    assert caught.value.code == "CLAUDE_BINARY"


@pytest.mark.parametrize(
    ("refusal", "expected_return", "expected_status"),
    (
        (False, 0, "COMPLETED"),
        (True, compat.COMPAT_POLICY_REFUSAL, "PROVIDER_REFUSED"),
    ),
)
def test_claude_uses_shared_lifecycle_and_gates_publication_on_stream_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    refusal: bool,
    expected_return: int,
    expected_status: str,
) -> None:
    session, project, scratchpad, output = _session(
        tmp_path, backend="claude"
    )
    contract, launch = _phase_io_authority(
        project,
        scratchpad,
        backend="claude",
        model="claude-sonnet-5",
    )
    binary = _fake_claude(tmp_path / "claude")
    account_home = tmp_path / "account"
    (account_home / ".claude").mkdir(parents=True)
    staging = scratchpad / "_claude_staging"
    staging.mkdir()
    monkeypatch.setattr(compat.shutil, "which", lambda name: str(binary))
    monkeypatch.setattr(compat, "_account_home", lambda: account_home)
    monkeypatch.setitem(
        sys.modules,
        "posix_v2_compat_claude",
        _fake_claude_adapter(refusal=refusal),
    )
    try:
        result = compat.run_claude_exec(
            session_authority=session,
            prompt="Return the sentinel.",
            phase_name=contract.phase,
            needs_mcp=False,
            config={"_run_id": "run-1", "project_root": str(project)},
            scratchpad=scratchpad,
            attempt=1,
            label="recon-worker",
            expected_outputs=tuple(spec.path for spec in contract.outputs),
            timeout=10,
            effective_model="claude-sonnet-5",
            working_directory=scratchpad,
            writable_directories=(output,),
            phase_io_contract=contract,
            phase_io_launch=launch,
            phase_tool_boundary={"tools": ["Read", "Grep"]},
            output_staging_directory=staging,
        )
        assert result == expected_return
        canonical = scratchpad / "output" / "finding.md"
        assert canonical.exists() is (not refusal)
        receipt = json.loads(next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        ).read_text(encoding="ascii"))
        assert receipt["backend"] == "claude"
        assert receipt["status"] == expected_status
        assert receipt["codex_binary"] is None
        assert receipt["provider_execution"]["provider_session_id"] == (
            receipt["provider_execution"]["provider_plan"][
                "provider_session_id"
            ]
        )
        assert receipt["provider_execution"]["native_broker_authority"] is False
        assert receipt["isolation"]["population_zero_proven"] is False
        assert receipt["isolation"][
            "escaped_descendants_excluded_from_observation"
        ] is True
        if refusal:
            assert receipt["failure_code"] == "RESULT_CYBER_REFUSAL"
            assert receipt["completed_output_evidence"] == []
        else:
            assert receipt["observed_model"] == "claude-sonnet-5"
            assert canonical.read_bytes() == b"model finding\n"
            replayed = compat.replay_posix_v2_compat_execution_receipt(
                receipt,
                expected_backend="claude",
            )
            assert replayed["receipt_sha256"] == receipt["receipt_sha256"]
    finally:
        session.close()


def test_claude_preplan_failure_records_diagnostic_and_releases_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(
        tmp_path, backend="claude"
    )
    contract, launch = _phase_io_authority(
        project,
        scratchpad,
        backend="claude",
        model="claude-sonnet-5",
    )
    binary = _fake_claude(tmp_path / "claude")
    account_home = tmp_path / "account"
    (account_home / ".claude").mkdir(parents=True)
    staging = scratchpad / "_claude_staging"
    staging.mkdir()
    monkeypatch.setattr(compat.shutil, "which", lambda name: str(binary))
    monkeypatch.setattr(compat, "_account_home", lambda: account_home)
    monkeypatch.setitem(
        sys.modules,
        "posix_v2_compat_claude",
        _fake_claude_adapter(reject_plan=True),
    )
    result = compat.run_claude_exec(
        session_authority=session,
        prompt="Return the sentinel.",
        phase_name=contract.phase,
        needs_mcp=False,
        config={"_run_id": "run-1", "project_root": str(project)},
        scratchpad=scratchpad,
        attempt=1,
        label="recon-worker",
        expected_outputs=tuple(spec.path for spec in contract.outputs),
        timeout=10,
        effective_model="claude-sonnet-5",
        working_directory=scratchpad,
        writable_directories=(output,),
        phase_io_contract=contract,
        phase_io_launch=launch,
        phase_tool_boundary={"tools": ["Read", "Grep"]},
        output_staging_directory=staging,
    )
    assert result == compat.COMPAT_EXIT_ERROR
    assert not (scratchpad / "output" / "finding.md").exists()
    receipt = json.loads(next(
        (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
    ).read_text(encoding="ascii"))
    assert receipt["status"] == "PRELAUNCH_FAILED"
    assert receipt["failure_code"] == "FIXTURE_PLAN_REJECTED"
    assert "provider_execution" not in receipt
    replayed = compat.replay_posix_v2_compat_execution_receipt(
        receipt,
        expected_backend="claude",
        require_completed=False,
    )
    assert replayed["receipt_sha256"] == receipt["receipt_sha256"]
    session.close()


def test_claude_shared_runtime_uses_real_plan_and_completion_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(
        tmp_path, backend="claude"
    )
    contract, launch = _phase_io_authority(
        project,
        scratchpad,
        backend="claude",
        model="claude-sonnet-5",
    )
    binary = _fake_claude_valid_stream(tmp_path / "claude")
    account_home = tmp_path / "account"
    (account_home / ".claude").mkdir(parents=True)
    staging = scratchpad / "_claude_staging"
    staging.mkdir()
    boundary = _real_claude_boundary(
        scratchpad,
        project,
        contract,
        staging / "output" / "finding.md",
    )
    monkeypatch.setattr(compat.shutil, "which", lambda name: str(binary))
    monkeypatch.setattr(compat, "_account_home", lambda: account_home)

    def admitted_native_auth(**kwargs: Any) -> Any:
        assert kwargs["source_environment"]["USER"] == (
            compat.pwd.getpwuid(os.getuid()).pw_name
        )
        assert "CLAUDE_CONFIG_DIR" not in kwargs["source_environment"]
        return claude_adapter.PosixV2CompatClaudeAuth(
            True,
            claude_adapter.AUTH_MODE,
            "firstParty",
            "NATIVE_DEFAULT_CONFIG_AND_KEYCHAIN",
            "8" * 64,
        )

    monkeypatch.setattr(
        claude_adapter,
        "check_claude_native_auth",
        admitted_native_auth,
    )
    try:
        result = compat.run_claude_exec(
            session_authority=session,
            prompt="Return the sentinel.",
            phase_name=contract.phase,
            needs_mcp=False,
            config={"_run_id": "run-1", "project_root": str(project)},
            scratchpad=scratchpad,
            attempt=1,
            label="recon-worker",
            expected_outputs=tuple(spec.path for spec in contract.outputs),
            timeout=10,
            effective_model="claude-sonnet-5",
            working_directory=scratchpad,
            writable_directories=(output,),
            phase_io_contract=contract,
            phase_io_launch=launch,
            phase_tool_boundary=boundary,
            output_staging_directory=staging,
        )
        assert result == 0
        receipt = json.loads(next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        ).read_text(encoding="ascii"))
        provider = receipt["provider_execution"]
        assert provider["provider_plan"]["schema"] == (
            claude_adapter.PLAN_SCHEMA
        )
        assert provider["completion_evidence"]["schema"] == (
            claude_adapter.COMPLETION_SCHEMA
        )
        provider_prompt = (
            scratchpad / "_provider_prompt_recon-worker.attempt1.md"
        ).read_text(encoding="utf-8")
        staged_path = receipt["phase_io_output_routes"][0]["path"]
        assert provider_prompt.startswith(
            "Return the sentinel.\n\n"
            "# PROVIDER-EFFECTIVE LOCAL PHASEIO ROUTING\n"
        )
        assert "Required deliverable destinations:" in provider_prompt
        assert (
            "at this exact absolute path: " + json.dumps(staged_path)
            in provider_prompt
        )
        assert "supervisor authority" not in provider_prompt
        assert "supersedes" not in provider_prompt
        assert "overrides" not in provider_prompt
        assert "inert routing data" not in provider_prompt
        replayed = compat.replay_posix_v2_compat_execution_receipt(
            receipt,
            expected_backend="claude",
        )
        assert replayed["status"] == "COMPLETED"
    finally:
        session.close()


def test_codex_compat_execution_uses_safe_flags_and_reduced_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_codex(tmp_path / "codex")
    authority = _phase_io_authority(project, scratchpad)
    assert _execute(
        monkeypatch,
        session,
        project,
        scratchpad,
        output,
        binary,
        phase_io_authority=authority,
    ) == 0

    log = (scratchpad / "_stdio_recon-worker.attempt1.log").read_text(
        encoding="utf-8"
    )
    assert '"type": "turn.completed"' in log
    assert (scratchpad / "_codex_output_recon-worker.attempt1.md").read_bytes() == (
        b"fake final message\n"
    )
    receipts = list((scratchpad / ".posix_v2_compat_receipts").glob("*.json"))
    assert len(receipts) == 1
    receipt = json.loads(receipts[0].read_text(encoding="ascii"))
    assert receipt["schema"] == compat.RECEIPT_SCHEMA
    assert receipt["status"] == "COMPLETED"
    assert receipt["codex_version"] == "codex-cli 0.test"
    assert receipt["requested_model"] == "gpt-5.4"
    assert receipt["model_binding"] == "EXPLICIT_CLI_ARGUMENT"
    assert receipt["observed_model"] == "gpt-5.4"
    assert receipt["model_observation"] == "MATCH"
    assert receipt["codex_workspace_directory"] == str(scratchpad)
    assert receipt["requested_read_working_directory"] == str(scratchpad)
    assert str(project) not in receipt["actual_write_roots"]
    assert receipt["actual_write_roots"] == [str(scratchpad), str(output)]
    assert receipt["ambient_mcp_config_loaded"] is False
    assert receipt["methodology_prompt_sha256"] == hashlib.sha256(
        b"Return the sentinel."
    ).hexdigest()
    assert receipt["provider_effective_prompt_sha256"] != receipt[
        "methodology_prompt_sha256"
    ]
    assert receipt["phase_io_contract_digest"] == authority[0].digest
    assert receipt["phase_io_launch_digest"] == authority[1].digest
    assert receipt["phase_io_input_routes"][0]["identity"] == (
        "scratchpad:input.md"
    )
    assert receipt["phase_io_output_routes"][0]["identity"] == (
        "scratchpad:output/finding.md"
    )
    provider_prompt = (
        scratchpad / "_provider_prompt_recon-worker.attempt1.md"
    ).read_text(encoding="utf-8")
    assert "No Plamen MCP server or PhaseIO tool is required" in provider_prompt
    staged_path = receipt["phase_io_output_routes"][0]["path"]
    assert "Required deliverable destinations:" in provider_prompt
    assert (
        "at this exact absolute path: " + json.dumps(staged_path)
        in provider_prompt
    )
    assert "supervisor authority" not in provider_prompt
    assert "supersedes" not in provider_prompt
    assert "overrides" not in provider_prompt
    assert "inert routing data" not in provider_prompt
    assert str(project) in provider_prompt
    assert str(scratchpad / "input.md") in provider_prompt
    assert str(scratchpad / "output/finding.md") in provider_prompt
    assert (
        scratchpad / "_prompt_recon-worker.attempt1.md"
    ).read_text(encoding="utf-8") == "Return the sentinel."
    assert receipt["isolation"] == {
        "approval_policy_requested": "never",
        "codex_sandbox_requested": "workspace-write",
        "dangerous_bypass_requested": False,
        "ephemeral": True,
        "escaped_descendants_excluded_from_observation": True,
        "exhaustive_descendant_termination_authority": False,
        "ignore_rules": True,
        "ignore_user_config": True,
        "native_broker_authority": False,
        "project_read_confinement_os_enforced": False,
        "exact_input_read_confinement_os_enforced": False,
        "exact_output_write_confinement_os_enforced": False,
        "foreign_write_detection_exhaustive": False,
        "compatibility_write_containment": (
            "WORKSPACE_WRITE_PLUS_PROMPT_ENFORCEMENT_REDUCED_ASSURANCE"
        ),
        "population_zero_proven": False,
        "process_group_created_before_exec": True,
        "process_group_empty_observed": True,
        "wer_authority": False,
    }
    assert "--dangerously-bypass-approvals-and-sandbox" not in receipt["argv"]
    assert receipt["argv"].count("--model") == 1
    model_index = receipt["argv"].index("--model")
    assert receipt["argv"][model_index + 1] == "gpt-5.4"
    sandbox_index = receipt["argv"].index("--sandbox")
    assert receipt["argv"][sandbox_index + 1] == "workspace-write"
    assert receipt["receipt_sha256"] == compat._mapping_sha({
        key: value for key, value in receipt.items() if key != "receipt_sha256"
    })
    private_auth = list(
        (scratchpad / ".posix_v2_compat_private").glob("*/codex-home/auth.json")
    )
    assert private_auth == []
    assert list((scratchpad / ".posix_v2_compat_private").iterdir()) == []
    with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
        _execute(
            monkeypatch,
            session,
            project,
            scratchpad,
            output,
            binary,
            phase_io_authority=authority,
        )
    assert caught.value.code == "INVOCATION_REPLAY"
    session.close()


def test_observed_model_mismatch_never_claims_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_codex(
        tmp_path / "codex",
        observed_model="gpt-6-astra",
    )
    try:
        assert _execute(
            monkeypatch,
            session,
            project,
            scratchpad,
            output,
            binary,
        ) == compat.COMPAT_EXIT_ERROR
        receipt_path = next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        )
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        assert receipt["status"] == "MODEL_BINDING_FAILED"
        assert receipt["failure_code"] == "MODEL_BINDING_MISMATCH"
        assert receipt["requested_model"] == "gpt-5.4"
        assert receipt["observed_model"] == "gpt-6-astra"
        assert receipt["model_binding"] == "EXPLICIT_CLI_ARGUMENT"
        assert receipt["model_observation"] == "MISMATCH"
        assert receipt["returncode"] == 0
        assert receipt["compatibility_return_value"] == (
            compat.COMPAT_EXIT_ERROR
        )
        assert receipt["completed_output_evidence"] == []
    finally:
        session.close()


def test_project_root_cannot_be_promoted_to_write_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_codex(tmp_path / "codex")
    contract, launch = _phase_io_authority(project, scratchpad)
    monkeypatch.setattr(compat.shutil, "which", lambda _name: str(binary))
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "a" * 64),
    )
    with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
        compat.run_codex_exec(
            session_authority=session,
            prompt="Read the project without changing it.",
            phase_name="recon",
            needs_mcp=False,
            config={"_run_id": "run-1", "project_root": str(project)},
            scratchpad=scratchpad,
            attempt=1,
            label="recon-worker",
            expected_outputs=("output/finding.md",),
            timeout=10,
            effective_model="gpt-5.4",
            working_directory=scratchpad,
            writable_directories=(output, project),
            phase_io_contract=contract,
            phase_io_launch=launch,
        )
    assert caught.value.code == "WRITABLE_DIRECTORIES"
    assert not (scratchpad / ".posix_v2_compat_receipts").exists()
    session.close()


def test_zero_exit_without_expected_output_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_codex(
        tmp_path / "codex", write_expected_output=False
    )
    assert _execute(
        monkeypatch, session, project, scratchpad, output, binary
    ) == compat.COMPAT_EXIT_ERROR
    receipt_path = next(
        (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
    )
    receipt = json.loads(receipt_path.read_text(encoding="ascii"))
    assert receipt["status"] == "RUNTIME_FAILED"
    assert receipt["failure_code"] == "EXPECTED_OUTPUT_MISSING"
    assert receipt["returncode"] == 0
    session.close()


def test_single_missing_output_recovers_exact_codex_last_message_through_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_codex(tmp_path / "codex", write_expected_output=False)

    try:
        assert _execute(
            monkeypatch,
            session,
            project,
            scratchpad,
            output,
            binary,
            staged_output_validator=_accept_last_message_staged_validator,
            staged_output_context={"purpose": "last-message-recovery"},
        ) == 0
        assert (output / "finding.md").read_bytes() == b"fake final message\n"
        receipt = json.loads(next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        ).read_text(encoding="ascii"))
        assert receipt["status"] == "COMPLETED"
        assert receipt["provider_last_message_evidence"]["status"] == "ADMITTED"
        recovery = receipt["staged_output_recovery"]
        assert recovery["status"] == "RECOVERED_PENDING_SEMANTIC_VALIDATION"
        assert recovery["projection"] == "EXACT_PROVIDER_LAST_MESSAGE_BYTES"
        assert recovery["sha256"] == hashlib.sha256(
            b"fake final message\n"
        ).hexdigest()
    finally:
        session.close()


def test_last_message_recovery_rejected_by_same_frozen_semantic_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_codex(tmp_path / "codex", write_expected_output=False)
    try:
        assert _execute(
            monkeypatch,
            session,
            project,
            scratchpad,
            output,
            binary,
            staged_output_validator=_reject_staged_validator,
            staged_output_context={"purpose": "last-message-recovery"},
        ) == compat.COMPAT_TIMEOUT
        assert not (output / "finding.md").exists()
        receipt = json.loads(next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        ).read_text(encoding="ascii"))
        assert receipt["status"] == "STAGED_SEMANTIC_REJECTED"
        assert receipt["staged_output_recovery"]["status"] == (
            "RECOVERED_PENDING_SEMANTIC_VALIDATION"
        )
        assert receipt["staged_output_rejection_reasons"] == [
            "alpha semantic rejection",
            "zeta semantic rejection",
        ]
    finally:
        session.close()


def test_nonzero_provider_exit_retains_only_semantically_accepted_staged_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_routed_codex(
        tmp_path / "codex",
        b"replacement finding\n",
        exit_code=1,
    )
    try:
        assert _execute(
            monkeypatch,
            session,
            project,
            scratchpad,
            output,
            binary,
            staged_output_validator=_accept_staged_validator,
            staged_output_context={"token": "frozen-context"},
            staged_output_input_identities=("scratchpad:input.md",),
        ) == 0
        assert (output / "finding.md").read_bytes() == (
            b"replacement finding\n"
        )
        receipt = json.loads(next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        ).read_text(encoding="ascii"))
        assert receipt["status"] == "COMPLETED"
        assert receipt["returncode"] == 1
        assert receipt["compatibility_return_value"] == 0
        assert compat.provider_transport_completion_is_admitted(receipt)
        recovery = receipt["provider_nonzero_semantic_completion"]
        assert recovery["status"] == "SEMANTIC_GATE_ACCEPTED"
        assert recovery["provider_returncode"] == 1
        assert dict(compat.replay_posix_v2_compat_execution_receipt(
            receipt, expected_backend="codex"
        )) == receipt
    finally:
        session.close()


def test_nonzero_provider_exit_without_semantic_gate_never_publishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_routed_codex(
        tmp_path / "codex",
        b"replacement finding\n",
        exit_code=1,
    )
    try:
        assert _execute(
            monkeypatch, session, project, scratchpad, output, binary
        ) == 1
        assert not (output / "finding.md").exists()
        receipt = json.loads(next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        ).read_text(encoding="ascii"))
        assert receipt["status"] == "NONZERO_EXIT"
        assert receipt["provider_nonzero_semantic_completion"] is None
        assert not compat.provider_transport_completion_is_admitted(receipt)
    finally:
        session.close()


def test_replace_output_is_private_staged_validated_and_atomically_published(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    base = b"frozen canonical prestate\n"
    replacement = b"replacement finding\n"
    authority = _replace_phase_io_authority(project, scratchpad, base=base)
    binary = _fake_routed_codex(tmp_path / "codex-replace", replacement)
    context = {"token": "frozen-context", "ordinal": 1}
    try:
        result = _execute(
            monkeypatch,
            session,
            project,
            scratchpad,
            output,
            binary,
            phase_io_authority=authority,
            staged_output_validator=_accept_staged_validator,
            staged_output_context=context,
            staged_output_input_identities=("scratchpad:input.md",),
        )
        assert result == 0
        canonical = scratchpad / "findings_inventory.md"
        assert canonical.read_bytes() == replacement
        receipt = json.loads(next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        ).read_text(encoding="ascii"))
        route = receipt["phase_io_output_routes"][0]
        assert route["write_mode"] == "REPLACE"
        assert route["path"] != route["canonical_path"]
        assert "/.posix_v2_compat_private/" in route["path"]
        assert receipt["staged_output_validator_binding"]["input_identities"] == [
            "scratchpad:input.md"
        ]
        assert receipt["staged_output_context"] == context
        assert receipt["completed_output_evidence"][0]["sha256"] == hashlib.sha256(
            replacement
        ).hexdigest()
        assert list((scratchpad / ".posix_v2_compat_private").iterdir()) == []
    finally:
        session.close()


def test_staged_semantic_rejection_preserves_exact_replace_prestate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    base = b"frozen canonical prestate\r\n"
    authority = _replace_phase_io_authority(project, scratchpad, base=base)
    binary = _fake_routed_codex(
        tmp_path / "codex-rejected", b"replacement finding\n"
    )
    try:
        result = _execute(
            monkeypatch,
            session,
            project,
            scratchpad,
            output,
            binary,
            phase_io_authority=authority,
            staged_output_validator=_reject_staged_validator,
            staged_output_context={"token": "frozen-context"},
            staged_output_input_identities=("scratchpad:input.md",),
        )
        assert result == -2
        assert (scratchpad / "findings_inventory.md").read_bytes() == base
        receipt = json.loads(next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        ).read_text(encoding="ascii"))
        assert receipt["status"] == "STAGED_SEMANTIC_REJECTED"
        assert receipt["failure_code"] == "STAGED_SEMANTIC_REJECTED"
        assert receipt["completed_output_evidence"] == []
        assert receipt["staged_output_rejection_reasons"] == [
            "alpha semantic rejection",
            "zeta semantic rejection",
        ]
        assert list((scratchpad / ".posix_v2_compat_private").iterdir()) == []
    finally:
        session.close()


def test_direct_replace_canonical_mutation_is_restored_and_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    base = b"canonical owner bytes\n"
    authority = _replace_phase_io_authority(project, scratchpad, base=base)
    binary = _fake_routed_codex(
        tmp_path / "codex-malicious",
        b"replacement finding\n",
        mutate_canonical=b"malicious direct write\n",
    )
    try:
        assert _execute(
            monkeypatch,
            session,
            project,
            scratchpad,
            output,
            binary,
            phase_io_authority=authority,
        ) == compat.COMPAT_EXIT_ERROR
        assert (scratchpad / "findings_inventory.md").read_bytes() == base
        receipt = json.loads(next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        ).read_text(encoding="ascii"))
        assert receipt["failure_code"] == "CANONICAL_OUTPUT_MUTATION"
        assert receipt["status"] == "RUNTIME_FAILED"
        assert list((scratchpad / ".posix_v2_compat_private").iterdir()) == []
    finally:
        session.close()


def test_staged_input_tamper_rejects_before_validator_and_preserves_prestate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    base = b"canonical owner bytes\n"
    authority = _replace_phase_io_authority(project, scratchpad, base=base)
    binary = _fake_routed_codex(
        tmp_path / "codex-input-tamper",
        b"replacement finding\n",
        mutate_input=b"tampered input\n",
    )
    try:
        assert _execute(
            monkeypatch,
            session,
            project,
            scratchpad,
            output,
            binary,
            phase_io_authority=authority,
            staged_output_validator=_accept_staged_validator,
            staged_output_context={"token": "frozen-context"},
            staged_output_input_identities=("scratchpad:input.md",),
        ) == -2
        assert (scratchpad / "findings_inventory.md").read_bytes() == base
        receipt = json.loads(next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        ).read_text(encoding="ascii"))
        assert receipt["failure_code"] == "STAGED_SEMANTIC_REJECTED"
        assert any(
            "semantic input hash changed" in reason
            for reason in receipt["staged_output_rejection_reasons"]
        )
    finally:
        session.close()


def test_staged_context_is_frozen_before_provider_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    authority = _replace_phase_io_authority(
        project, scratchpad, base=b"canonical owner bytes\n"
    )
    binary = _fake_routed_codex(
        tmp_path / "codex-context-freeze", b"replacement finding\n"
    )
    context = {"token": "frozen-context", "nested": {"ordinal": 1}}
    real_popen = compat.subprocess.Popen

    def mutate_context_then_spawn(*args: Any, **kwargs: Any) -> Any:
        context["token"] = "caller-mutated"
        context["nested"]["ordinal"] = 2
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(compat.subprocess, "Popen", mutate_context_then_spawn)
    try:
        assert _execute(
            monkeypatch,
            session,
            project,
            scratchpad,
            output,
            binary,
            phase_io_authority=authority,
            staged_output_validator=_accept_staged_validator,
            staged_output_context=context,
        ) == 0
        receipt = json.loads(next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        ).read_text(encoding="ascii"))
        assert receipt["staged_output_context"] == {
            "nested": {"ordinal": 1},
            "token": "frozen-context",
        }
    finally:
        session.close()


def test_receipt_persistence_failure_rolls_back_published_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_codex(tmp_path / "codex")
    original_persist = compat._persist_receipt

    def persist_then_fail(*args: Any, **kwargs: Any) -> Path:
        original_persist(*args, **kwargs)
        raise OSError("injected receipt directory fsync failure")

    monkeypatch.setattr(compat, "_persist_receipt", persist_then_fail)
    try:
        assert _execute(
            monkeypatch, session, project, scratchpad, output, binary
        ) == compat.COMPAT_EXIT_ERROR
        assert not (output / "finding.md").exists()
        receipt = json.loads(next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        ).read_text(encoding="ascii"))
        assert receipt["status"] == "RECEIPT_FAILED"
        assert receipt["failure_code"] == "RECEIPT_PERSISTENCE"
        assert receipt["completed_output_evidence"] == []
        assert list((scratchpad / ".posix_v2_compat_private").iterdir()) == []
    finally:
        session.close()


def _recover_in_fresh_process(project: Path, scratchpad: Path) -> None:
    source_root = Path(compat.__file__).resolve().parent
    script = textwrap.dedent(
        """
        import sys
        from pathlib import Path
        sys.path.insert(0, sys.argv[1])
        import posix_v2_compat_runtime as compat
        session = compat.issue_posix_v2_compat_session_for_installed_front(
            run_id="fresh-recovery",
            project_root=Path(sys.argv[2]),
            scratchpad=Path(sys.argv[3]),
        )
        session.close()
        """
    )
    subprocess.run(
        [sys.executable, "-c", script, str(source_root), str(project), str(scratchpad)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


@pytest.mark.parametrize("published_count", [1, 2, 3])
def test_stale_multi_output_publication_rolls_back_after_each_replacement(
    tmp_path: Path,
    published_count: int,
) -> None:
    project, scratchpad, _output = _roots(tmp_path)
    private_root = scratchpad / ".posix_v2_compat_private"
    private_root.mkdir(mode=0o700)
    invocation_id = (f"{published_count:x}" * 32)[:32]
    invocation = private_root / invocation_id
    invocation.mkdir(mode=0o700)
    canonical_paths = [scratchpad / f"multi-{index}.md" for index in range(3)]
    bases = [b"base zero\n", b"base one\n", None]
    original_stats: list[os.stat_result | None] = []
    routes: list[dict[str, Any]] = []
    staged: dict[str, bytes] = {}
    staged_root = invocation / "staged"
    staged_root.mkdir(mode=0o700)
    for index, (canonical, base) in enumerate(zip(canonical_paths, bases)):
        if base is not None:
            canonical.write_bytes(base)
            if index == 1:
                canonical.chmod(0o640)
            original_stats.append(canonical.stat())
        else:
            original_stats.append(None)
        identity = f"scratchpad:{canonical.name}"
        proposal = f"successor {index}\n".encode()
        staged_path = staged_root / f"{index}.md"
        staged_path.write_bytes(proposal)
        staged[identity] = proposal
        routes.append({
            "identity": identity,
            "path": str(staged_path),
            "canonical_path": str(canonical),
            "write_mode": "REPLACE" if base is not None else "CREATE",
            "prestate_existed": base is not None,
            "prestate_size": 0 if base is None else len(base),
            "prestate_sha256": "" if base is None else hashlib.sha256(base).hexdigest(),
        })
    prestates = compat._capture_canonical_output_prestates(scratchpad, routes)
    journal_path, journal = compat._prepare_publication_transaction(
        scratchpad,
        invocation,
        invocation_id,
        ".posix_v2_compat_receipts/missing.json",
        routes,
        prestates,
        staged,
    )
    journal = compat._update_publication_journal(
        journal_path, journal, state="PUBLISHING", published_count=0
    )
    for index, row in enumerate(journal["outputs"][:published_count]):
        prestate = prestates[row["identity"]]
        if prestate.existed:
            os.rename(prestate.path, scratchpad / row["backup_relative"])
        successor = (scratchpad / row["successor_relative"]).read_bytes()
        compat._replace_bytes(prestate.path, successor, prestate.mode)
        journal = compat._update_publication_journal(
            journal_path,
            journal,
            state="PUBLISHING",
            published_count=index + 1,
        )

    _recover_in_fresh_process(project, scratchpad)

    for canonical, base, original in zip(canonical_paths, bases, original_stats):
        if base is None:
            assert not canonical.exists()
            continue
        assert canonical.read_bytes() == base
        recovered = canonical.stat()
        assert (recovered.st_dev, recovered.st_ino) == (
            original.st_dev,
            original.st_ino,
        )
        assert stat.S_IMODE(recovered.st_mode) == stat.S_IMODE(original.st_mode)
    assert list(private_root.iterdir()) == []


@pytest.mark.parametrize("journal_committed", [False, True])
def test_fresh_recovery_finishes_receipted_publication_and_cleans_wal(
    tmp_path: Path,
    journal_committed: bool,
) -> None:
    project, scratchpad, _output = _roots(tmp_path)
    private_root = scratchpad / ".posix_v2_compat_private"
    private_root.mkdir(mode=0o700)
    invocation_id = ("d" if journal_committed else "e") * 32
    invocation = private_root / invocation_id
    invocation.mkdir(mode=0o700)
    canonical_paths = [scratchpad / "commit-a.md", scratchpad / "commit-b.md"]
    canonical_paths[0].write_bytes(b"old a\n")
    routes: list[dict[str, Any]] = []
    staged: dict[str, bytes] = {}
    staged_root = invocation / "staged"
    staged_root.mkdir(mode=0o700)
    for index, canonical in enumerate(canonical_paths):
        identity = f"scratchpad:{canonical.name}"
        proposal = f"committed {index}\n".encode()
        staged_path = staged_root / f"{index}.md"
        staged_path.write_bytes(proposal)
        staged[identity] = proposal
        existed = canonical.exists()
        prior = canonical.read_bytes() if existed else b""
        routes.append({
            "identity": identity,
            "path": str(staged_path),
            "canonical_path": str(canonical),
            "write_mode": "REPLACE" if existed else "CREATE",
            "prestate_existed": existed,
            "prestate_size": len(prior),
            "prestate_sha256": hashlib.sha256(prior).hexdigest() if existed else "",
        })
    prestates = compat._capture_canonical_output_prestates(scratchpad, routes)
    receipt_relative = ".posix_v2_compat_receipts/crash.json"
    journal_path, journal = compat._prepare_publication_transaction(
        scratchpad,
        invocation,
        invocation_id,
        receipt_relative,
        routes,
        prestates,
        staged,
    )
    journal, evidence = compat._publish_prepared_transaction(
        scratchpad, journal_path, journal, prestates
    )
    compat._persist_receipt(
        scratchpad / ".posix_v2_compat_receipts",
        "crash",
        {
            "schema": compat.RECEIPT_SCHEMA,
            "status": "COMPLETED",
            "failure_code": None,
            "invocation_id": invocation_id,
            "completed_output_evidence": evidence,
            "publication_transaction_binding_sha256": (
                compat._publication_transaction_binding(journal)
            ),
        },
    )
    if journal_committed:
        journal = compat._update_publication_journal(
            journal_path,
            journal,
            state="COMMITTED",
            published_count=2,
        )

    _recover_in_fresh_process(project, scratchpad)

    assert canonical_paths[0].read_bytes() == b"committed 0\n"
    assert canonical_paths[1].read_bytes() == b"committed 1\n"
    assert list(private_root.iterdir()) == []
    assert not list(scratchpad.glob(".*.posix-v2-prestate-*"))


def test_canonical_cas_rejects_identical_bytes_inode_and_mode_replacement(
    tmp_path: Path,
) -> None:
    _project, scratchpad, _output = _roots(tmp_path)
    canonical = scratchpad / "cas.md"
    raw = b"identical bytes\n"
    canonical.write_bytes(raw)
    route = {
        "identity": "scratchpad:cas.md",
        "canonical_path": str(canonical),
        "prestate_existed": True,
        "prestate_size": len(raw),
        "prestate_sha256": hashlib.sha256(raw).hexdigest(),
    }
    prestate = compat._capture_canonical_output_prestates(scratchpad, [route])
    replacement = scratchpad / ".cas-replacement"
    replacement.write_bytes(raw)
    os.replace(replacement, canonical)
    assert not compat._canonical_output_matches_prestate(
        scratchpad, "scratchpad:cas.md", prestate["scratchpad:cas.md"]
    )
    compat._restore_changed_canonical_prestates(scratchpad, prestate)
    recaptured = compat._capture_canonical_output_prestates(scratchpad, [route])
    canonical.chmod(0o640)
    assert not compat._canonical_output_matches_prestate(
        scratchpad, "scratchpad:cas.md", recaptured["scratchpad:cas.md"]
    )


@pytest.mark.parametrize(
    ("base", "fragment"),
    [
        (b"pass-one-without-terminal-newline", b"\n## Pass 2\nnew gap\n"),
        (b"pass-one\r\nwithout-terminal-newline", b"\r\n## Pass 2\r\nnew gap\r\n"),
    ],
)
def test_append_publication_preserves_exact_frozen_prefix(
    tmp_path: Path,
    base: bytes,
    fragment: bytes,
) -> None:
    """Publication is raw byte concatenation on Unix and CRLF inputs."""
    _project, scratchpad, _output = _roots(tmp_path)
    canonical = scratchpad / "semantic_invariants.md"
    staged = scratchpad / ".private" / "append" / canonical.name
    staged.parent.mkdir(parents=True)
    canonical.write_bytes(base)
    route = {
        "identity": "scratchpad:semantic_invariants.md",
        "path": str(staged),
        "canonical_path": str(canonical),
        "write_mode": "APPEND",
        "prestate_size": len(base),
        "prestate_sha256": hashlib.sha256(base).hexdigest(),
    }

    frozen = compat._capture_append_bases(scratchpad, [route])
    staged.write_bytes(fragment)
    evidence = compat._publish_append_fragments(scratchpad, [route], frozen)

    assert canonical.read_bytes() == base + fragment
    assert canonical.read_bytes()[: len(base)] == base
    assert len(evidence) == 1
    assert evidence[0]["path"] == str(canonical)
    assert evidence[0]["sha256"] == hashlib.sha256(base + fragment).hexdigest()
    assert evidence[0]["size"] == len(base + fragment)


def test_append_provider_canonical_mutation_is_restored_and_rejected(
    tmp_path: Path,
) -> None:
    _project, scratchpad, _output = _roots(tmp_path)
    canonical = scratchpad / "semantic_invariants.md"
    staged = scratchpad / ".private" / "append" / canonical.name
    staged.parent.mkdir(parents=True)
    base = b"pass-one-without-terminal-newline"
    canonical.write_bytes(base)
    route = {
        "identity": "scratchpad:semantic_invariants.md",
        "path": str(staged),
        "canonical_path": str(canonical),
        "write_mode": "APPEND",
        "prestate_size": len(base),
        "prestate_sha256": hashlib.sha256(base).hexdigest(),
    }
    frozen = compat._capture_append_bases(scratchpad, [route])

    canonical.write_bytes(base + b"\n")
    staged.write_bytes(b"## Pass 2\n")

    assert compat._restore_changed_append_bases(scratchpad, [route], frozen) is True
    assert canonical.read_bytes() == base


def test_codex_compat_append_is_staged_then_byte_exactly_published(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    base = b"pass-one-without-terminal-newline"
    fragment = b"\n## Pass 2\nnew gap\n"
    canonical = scratchpad / "semantic_invariants.md"
    producer_key = canonical_work_unit_key(
        "sc", "thorough", "evm", "codex", "invariants", "worker.pass1"
    )
    producer = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="invariants",
        work_unit_id="worker.pass1",
        outputs=(ArtifactSpec(
            root="scratchpad",
            path="semantic_invariants.md",
            owner_key=producer_key,
            artifact_class="REQUIRED",
            writer="MODEL",
            write_mode="CREATE",
        ),),
    )
    producer_launch = LaunchSpec(
        work_unit_key=producer_key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        model="gpt-5.4",
        timeout_s=10,
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad, project, producer, producer_launch, run_id="run-1"
    )
    canonical.write_bytes(base)
    record_work_unit_artifacts(
        scratchpad,
        project,
        producer,
        producer_launch,
        run_id="run-1",
        actor="MODEL",
    )
    key = canonical_work_unit_key(
        "sc", "thorough", "evm", "codex", "invariants_p2", "worker.pass2"
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="invariants_p2",
        work_unit_id="worker.pass2",
        outputs=(ArtifactSpec(
            root="scratchpad",
            path="semantic_invariants.md",
            owner_key=key,
            artifact_class="REQUIRED",
            writer="MODEL",
            write_mode="APPEND",
        ),),
        immutable_inputs=("scratchpad:input.md",),
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        model="gpt-5.4",
        timeout_s=10,
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(scratchpad, project, contract, launch, run_id="run-1")
    binary = _fake_append_codex(tmp_path / "codex-append", fragment)
    monkeypatch.setattr(compat.shutil, "which", lambda _name: str(binary))
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "a" * 64),
    )
    try:
        result = compat.run_codex_exec(
            session_authority=session,
            prompt="Write only the append fragment.",
            phase_name="invariants_p2",
            needs_mcp=False,
            config={"_run_id": "run-1", "project_root": str(project)},
            scratchpad=scratchpad,
            attempt=1,
            label="pass2",
            expected_outputs=("semantic_invariants.md",),
            timeout=10,
            effective_model="gpt-5.4",
            working_directory=scratchpad,
            writable_directories=(output,),
            phase_io_contract=contract,
            phase_io_launch=launch,
        )
        assert result == 0
        assert canonical.read_bytes() == base + fragment
        receipt_path = next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        )
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        route = receipt["phase_io_output_routes"][0]
        assert route["path"] != route["canonical_path"]
        assert route["canonical_path"] == str(canonical)
    finally:
        session.close()


def test_timeout_kills_group_but_never_claims_population_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_codex(tmp_path / "codex", sleep_seconds=5.0)
    assert _execute(
        monkeypatch,
        session,
        project,
        scratchpad,
        output,
        binary,
        timeout=0.1,
    ) == compat.COMPAT_TIMEOUT
    receipt_path = next(
        (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
    )
    receipt = json.loads(receipt_path.read_text(encoding="ascii"))
    assert receipt["status"] == "TIMED_OUT"
    assert receipt["timed_out"] is True
    assert receipt["isolation"]["process_group_empty_observed"] is True
    assert receipt["isolation"]["population_zero_proven"] is False
    assert list((scratchpad / ".posix_v2_compat_private").iterdir()) == []
    session.close()


def test_private_cleanup_never_follows_external_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_codex(tmp_path / "codex")
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "sentinel.txt"
    sentinel.write_bytes(b"must survive\n")
    original_write = compat._write_absent_bytes

    def write_and_inject_symlink(path: Path, raw: bytes, mode: int) -> None:
        original_write(path, raw, mode)
        if path.name == "auth.json":
            os.symlink(external, path.parent / "external-link")

    monkeypatch.setattr(compat, "_write_absent_bytes", write_and_inject_symlink)
    try:
        assert _execute(
            monkeypatch,
            session,
            project,
            scratchpad,
            output,
            binary,
        ) == 0
        assert sentinel.read_bytes() == b"must survive\n"
        assert list((scratchpad / ".posix_v2_compat_private").iterdir()) == []
    finally:
        session.close()


def test_cleanup_failure_cannot_claim_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_codex(tmp_path / "codex")

    def fail_cleanup(*_args: object, **_kwargs: object) -> None:
        raise compat.PosixV2CompatRuntimeError(
            "PRIVATE_RUNTIME_CLEANUP", "injected cleanup failure"
        )

    monkeypatch.setattr(
        compat, "_cleanup_private_invocation_payload", fail_cleanup
    )
    try:
        assert _execute(
            monkeypatch,
            session,
            project,
            scratchpad,
            output,
            binary,
        ) == compat.COMPAT_EXIT_ERROR
        receipt_path = next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        )
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        assert receipt["status"] == "CLEANUP_FAILED"
        assert receipt["failure_code"] == "PRIVATE_RUNTIME_CLEANUP"
        assert receipt["compatibility_return_value"] == compat.COMPAT_EXIT_ERROR
        assert receipt["completed_output_evidence"] == []
        assert not (output / "finding.md").exists()
        assert "PRIVATE_RUNTIME_CLEANUP" in (
            scratchpad / "_stdio_recon-worker.attempt1.log"
        ).read_text(encoding="utf-8")
    finally:
        session.close()


def test_cleanup_removes_only_exact_invocation_and_recovery_removes_sibling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_codex(tmp_path / "codex")
    sibling_name = "f" * 32
    original_write = compat._write_absent_bytes

    def write_and_inject_sibling(path: Path, raw: bytes, mode: int) -> None:
        original_write(path, raw, mode)
        if path.name == "auth.json":
            sibling = scratchpad / ".posix_v2_compat_private" / sibling_name
            sibling.mkdir(mode=0o700)
            (sibling / "retained.txt").write_text("sibling\n", encoding="utf-8")

    monkeypatch.setattr(compat, "_write_absent_bytes", write_and_inject_sibling)
    try:
        assert _execute(
            monkeypatch,
            session,
            project,
            scratchpad,
            output,
            binary,
        ) == 0
        sibling = scratchpad / ".posix_v2_compat_private" / sibling_name
        assert (sibling / "retained.txt").read_text(encoding="utf-8") == "sibling\n"
    finally:
        session.close()
    monkeypatch.setattr(compat, "_write_absent_bytes", original_write)
    recovered = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id="run-1",
        project_root=project,
        scratchpad=scratchpad,
    )
    try:
        assert list((scratchpad / ".posix_v2_compat_private").iterdir()) == []
    finally:
        recovered.close()


def test_repeated_invocations_leave_private_root_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, output = _session(tmp_path)
    binary = _fake_codex(tmp_path / "codex")
    try:
        for attempt in range(1, 7):
            authority = _phase_io_authority(project, scratchpad)
            assert _execute(
                monkeypatch,
                session,
                project,
                scratchpad,
                output,
                binary,
                attempt=attempt,
                label=f"recon-worker-{attempt}",
                phase_io_authority=authority,
            ) == 0
            assert list((scratchpad / ".posix_v2_compat_private").iterdir()) == []
            (output / "finding.md").unlink()
    finally:
        session.close()


def test_cleanup_rejects_nested_device_crossing_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, _output = _roots(tmp_path)
    del project
    opened = compat._open_private_runtime_root(scratchpad, create=True)
    assert opened is not None
    private_root, descriptor, identity = opened
    invocation_name = "a" * 32
    invocation = private_root / invocation_name
    nested = invocation / "nested"
    nested.mkdir(mode=0o700, parents=True)
    invocation.chmod(0o700)
    (nested / "sentinel.txt").write_bytes(b"retained\n")
    original_stat = compat.os.stat
    original_open = compat.os.open
    nested_opened = False

    def cross_device_stat(
        path: object,
        *args: object,
        **kwargs: object,
    ) -> os.stat_result:
        observed = original_stat(path, *args, **kwargs)
        if path == "nested" and kwargs.get("dir_fd") is not None:
            fields = list(observed)
            fields[2] = int(observed.st_dev) + 1
            return os.stat_result(fields)
        return observed

    def observe_open(
        path: object,
        *args: object,
        **kwargs: object,
    ) -> int:
        nonlocal nested_opened
        if path == "nested" and kwargs.get("dir_fd") is not None:
            nested_opened = True
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(compat.os, "stat", cross_device_stat)
    monkeypatch.setattr(compat.os, "open", observe_open)
    try:
        with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
            compat._cleanup_private_entry(
                descriptor,
                invocation_name,
                budget=compat._PrivateCleanupBudget(
                    root_device=int(identity[0])
                ),
            )
        assert caught.value.code == "PRIVATE_RUNTIME_CLEANUP"
        assert nested_opened is False
        quarantined = private_root / (".cleanup-" + invocation_name)
        assert (quarantined / "nested" / "sentinel.txt").read_bytes() == (
            b"retained\n"
        )
    finally:
        os.close(descriptor)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork required")
def test_session_is_rejected_in_forked_child(tmp_path: Path) -> None:
    session, _project, _scratchpad, _output = _session(tmp_path)
    read_fd, write_fd = os.pipe()
    process_id = os.fork()
    if process_id == 0:
        os.close(read_fd)
        try:
            compat.require_posix_v2_compat_session(session)
        except compat.PosixV2CompatRuntimeError as exc:
            os.write(write_fd, exc.code.encode("ascii"))
        else:
            os.write(write_fd, b"ACCEPTED")
        finally:
            os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    observed = os.read(read_fd, 128)
    os.close(read_fd)
    _, status_value = os.waitpid(process_id, 0)
    assert os.waitstatus_to_exitcode(status_value) == 0
    assert observed == b"SESSION_AUTHORITY"
    session.close()
