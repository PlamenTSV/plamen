from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

import claude_provider_preparation as provider
import claude_runtime_materialization as materialization
import headless_worker_runtime as headless
import test_claude_provider_preparation as provider_fixtures
import test_headless_worker_runtime_p0_am as headless_fixtures
import test_mcp_runtime_generation as mcp_fixtures
import test_worker_execution_receipts as wer_fixtures
import worker_execution_receipts as wer


# The failed r39 recon prompt was 9,059 bytes, already enough to exceed the
# 8,191-character cmd.exe/batch-file boundary once it crossed plamen.cmd.  Use
# a larger payload so this remains a transport test on every supported host.
LONG_PROMPT = (
    "# r39 stdin-only transport\n"
    + ("audit this exact byte sequence: λ\n" * 2_048)
).encode("utf-8")


def test_claude_command_is_prompt_independent_and_short(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    package = provider_fixtures._prepare(monkeypatch, tmp_path)
    prompt = LONG_PROMPT.decode("utf-8")

    argv = package.command_for_bound_stdin()
    alternate = package.command_for_bound_stdin()

    assert len(LONG_PROMPT) > 32 * 1024
    assert argv == alternate
    assert argv[1:3] == ("-p", "--model")
    assert prompt not in argv
    assert provider.PROMPT_PLACEHOLDER not in argv
    assert len(subprocess.list2cmdline(argv)) < 8_191
    with pytest.raises(provider.ClaudeProviderPreparationError, match="retired"):
        package.command_for_prompt(prompt)


def test_long_prompt_bytes_are_delivered_once_through_bound_stdin(
    tmp_path: Path,
) -> None:
    bindings = wer_fixtures._bindings(tmp_path)
    prompt_path = tmp_path / bindings.prompt.relative_path
    prompt_path.write_bytes(LONG_PROMPT)
    expected_sha256 = hashlib.sha256(LONG_PROMPT).hexdigest()
    script = (
        "from pathlib import Path; import hashlib,json,sys; "
        "raw=sys.stdin.buffer.read(); "
        "p=Path('worker-out/result.json'); "
        "p.parent.mkdir(parents=True,exist_ok=True); "
        "p.write_text(json.dumps({'finding_id':hashlib.sha256(raw).hexdigest()}),"
        "encoding='utf-8')"
    )
    physical_argv = [sys.executable, "-I", "-c", script]

    completed = wer.run_observed_worker(
        scratchpad=tmp_path,
        bindings=bindings,
        argv=physical_argv,
        cwd=tmp_path,
        output_scope_relative="worker-out",
        expected_outputs=(
            wer.ExpectedOutput(
                "finding-r39",
                "result.json",
                "canonical/result.json",
            ),
        ),
        parser_digest=wer_fixtures.strict_json_digest,
        environment={},
        environment_allowlist=(),
        stdin_input=bindings.prompt,
        timeout_seconds=10,
    )

    result = json.loads(
        completed.published_paths[0].read_text(encoding="utf-8")
    )
    arm = json.loads(completed.arm_path.read_text(encoding="utf-8"))
    process_intent = arm["process_intent"]

    assert result == {"finding_id": expected_sha256}
    assert process_intent["argv"] == physical_argv
    assert LONG_PROMPT.decode("utf-8") not in process_intent["argv"]
    assert process_intent["stdin"] == {
        "state": "BOUND_INPUT",
        "input_name": "prompt",
        "relative_path": bindings.prompt.relative_path,
        "sha256": expected_sha256,
        "size": len(LONG_PROMPT),
    }
    wer.validate_completed_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        publish_receipt_path=completed.publish_receipt_path,
        parser_digest=wer_fixtures.strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
        expected_publish_sha256=completed.publish_sha256,
    )


@pytest.mark.parametrize(
    "positional",
    (provider.PROMPT_PLACEHOLDER, "legacy positional prompt"),
)
def test_runtime_rejects_reintroduced_positional_prompt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    positional: str,
) -> None:
    package = provider_fixtures._prepare(monkeypatch, tmp_path)
    profile_flags = tuple(package.record["headless_profile"]["cli_flags"])
    base_argv = list(
        package.command_for_bound_stdin()
    )
    del base_argv[-len(profile_flags) :]
    print_index = base_argv.index("-p")
    base_argv.insert(print_index + 1, positional)

    with pytest.raises(
        materialization.ClaudeRuntimeMaterializationError,
        match="prompt only via stdin",
    ):
        materialization._compile_final_argv(
            base_argv,
            request=package.record["launch_security_request"],
            policy=package.record["launch_security_request"]["policy"],
        )


def test_claude_prompt_over_ten_mib_is_refused_before_attempt_arm(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    contract, launch = headless_fixtures._arm(tmp_path, backend="claude")
    # Isolate the transport-order invariant from provider credential/profile
    # fixtures: the limit must fire after typed normalization but before argv
    # construction, ledger replay, attempt creation, or provider execution.
    monkeypatch.setattr(
        headless,
        "_normalize_startup_authority_binding",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        headless,
        "_normalize_claude_launch_contract",
        lambda **_kwargs: ({}, {}, {}),
    )
    monkeypatch.setattr(
        headless,
        "_compile_claude_provider_parent_authority",
        lambda **_kwargs: (None, None, ()),
    )
    builder_called = False

    def forbidden_builder(_output_directory: Path) -> tuple[str, ...]:
        nonlocal builder_called
        builder_called = True
        raise AssertionError("over-limit Claude prompt reached command building")

    # The routing suffix is non-empty, so an exactly 10 MiB source prompt must
    # exceed Claude Code's documented 10 MiB piped-stdin ceiling.
    over_limit_prompt = "x" * (10 * 1024 * 1024)
    with pytest.raises(
        headless.HeadlessWorkerRuntimeError,
        match="exceeds the 10 MiB stdin transport limit",
    ):
        headless.prepare_headless_worker(
            scratchpad=tmp_path,
            project_root=tmp_path,
            run_id=headless_fixtures.RUN_ID,
            phase_io_contract=contract,
            phase_io_launch=launch,
            prompt=over_limit_prompt,
            command_builder=forbidden_builder,
            cwd=tmp_path,
            environment={},
            environment_allowlist=(),
            source_snapshot_digest="a" * 64,
            methodology_digests=("b" * 64,),
            startup_authority_binding={},
        )

    assert builder_called is False
    assert not (tmp_path / ".worker_transactions").exists()
    assert not (tmp_path / ".worker_execution_receipts").exists()


def test_nested_backend_member_launch_preserves_exact_large_stdin(
    tmp_path: Path,
) -> None:
    runtime = mcp_fixtures.RUNTIME
    relative = "node_modules/fixture-mcp/dist/index.js"

    def materialize(payload: Path) -> None:
        mcp_fixtures._materialize(payload)
        payload.joinpath(*relative.split("/")).write_text(
            "import hashlib,sys\n"
            "sys.stdout.write(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())\n",
            encoding="utf-8",
        )

    authority_inputs = mcp_fixtures._install_authority()
    request = authority_inputs["generation_request"]
    store = tmp_path / "nested-backend-runtime"
    published = runtime.stage_npm_generation(
        store,
        request.generation_id,
        materialize,
        **authority_inputs,
        signer=mcp_fixtures._sign,
        verifier=mcp_fixtures._verify,
    )
    validated = runtime.validate_generation(
        store,
        request.generation_id,
        verifier=mcp_fixtures._verify,
    )
    row = {item["path"]: item for item in validated.entries}[relative]
    prompt_path = tmp_path / "nested-prompt.bin"
    prompt_path.write_bytes(LONG_PROMPT)

    with prompt_path.open("rb") as prompt_handle:
        process = runtime.launch_generation_member(
            store,
            request.generation_id,
            relative,
            execution_kind="node",
            expected_size=row["size"],
            expected_sha256=row["sha256"],
            node_executable=sys.executable,
            verifier=mcp_fixtures._verify,
            **mcp_fixtures._member_launch_authority(published, request),
            stdin=prompt_handle,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate(timeout=10)

    assert process.returncode == 0
    assert stderr == b""
    assert stdout.decode("ascii") == hashlib.sha256(LONG_PROMPT).hexdigest()


def test_nested_backend_front_process_inherits_exact_large_stdin(
    tmp_path: Path,
) -> None:
    """Model plamen backend-launch -> signed member without rebinding stdin."""

    runtime = mcp_fixtures.RUNTIME
    relative = "node_modules/fixture-mcp/dist/index.js"

    def materialize(payload: Path) -> None:
        mcp_fixtures._materialize(payload)
        payload.joinpath(*relative.split("/")).write_text(
            "import hashlib,sys\n"
            "sys.stdout.write(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())\n",
            encoding="utf-8",
        )

    authority_inputs = mcp_fixtures._install_authority()
    request = authority_inputs["generation_request"]
    store = tmp_path / "nested-front-runtime"
    published = runtime.stage_npm_generation(
        store,
        request.generation_id,
        materialize,
        **authority_inputs,
        signer=mcp_fixtures._sign,
        verifier=mcp_fixtures._verify,
    )
    validated = runtime.validate_generation(
        store,
        request.generation_id,
        verifier=mcp_fixtures._verify,
    )
    row = {item["path"]: item for item in validated.entries}[relative]
    launch_authority = mcp_fixtures._member_launch_authority(
        published,
        request,
    )
    helper = tmp_path / "backend_front.py"
    helper.write_text(
        "import hashlib,hmac,importlib.util,sys\n"
        f"spec=importlib.util.spec_from_file_location('nested_runtime',{str(Path(runtime.__file__).resolve())!r})\n"
        "runtime=importlib.util.module_from_spec(spec)\n"
        "sys.modules[spec.name]=runtime\n"
        "spec.loader.exec_module(runtime)\n"
        f"key={mcp_fixtures.KEY!r}\n"
        "def verify(raw,auth):\n"
        " return auth.get('scheme')=='test-hmac-sha256' and auth.get('key_id')=='fixture-key-v1' and hmac.compare_digest(auth.get('signature',''),hmac.new(key,raw,hashlib.sha256).hexdigest())\n"
        "child=runtime.launch_generation_member(\n"
        f" {str(store)!r},{request.generation_id!r},{relative!r},\n"
        " execution_kind='node',\n"
        f" expected_size={row['size']!r},expected_sha256={row['sha256']!r},\n"
        " node_executable=sys.executable,verifier=verify,\n"
        f" expected_receipt_sha256={launch_authority['expected_receipt_sha256']!r},\n"
        f" expected_census_sha256={launch_authority['expected_census_sha256']!r},\n"
        f" expected_request_sha256={launch_authority['expected_request_sha256']!r},\n"
        f" expected_generation_policy_sha256={launch_authority['expected_generation_policy_sha256']!r})\n"
        "raise SystemExit(child.wait())\n",
        encoding="utf-8",
    )
    front_argv = [sys.executable, "-I", str(helper)]

    completed = subprocess.run(
        front_argv,
        input=LONG_PROMPT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
    )

    assert LONG_PROMPT.decode("utf-8") not in front_argv
    assert completed.returncode == 0
    assert completed.stderr == b""
    assert completed.stdout.decode("ascii") == hashlib.sha256(
        LONG_PROMPT
    ).hexdigest()
