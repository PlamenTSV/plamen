from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import inspect
import shutil
import sys
import threading
import uuid

import pytest

import bb_wrapper_provider_adapter as adapter
import bb_path_authority
import claude_executable_observation as claude_executable
import claude_provider_preparation as claude_preparation
import claude_runtime_materialization as claude_runtime
import worker_execution_receipts as worker_receipts
import test_claude_launch_authority_fixtures as claude_fixtures
from test_claude_launch_authority_fixtures import (
    OFFLINE_OAUTH_TOKEN,
    claude_test_postprocess_state_update_source,
    install_test_only_launch_authority_adapter,
)
from test_claude_mcp_generation_authority import (
    authenticated_mcp_selection_fixture,
)

TOKENIZED_RPC = "https://rpc.example.invalid/v1/fixture-secret-token"


def _private_single_link_python(tmp_path: Path) -> Path:
    """Copy the test interpreter so production alias checks remain enabled."""

    source = Path(sys.executable).resolve(strict=True)
    destination = tmp_path / "private-python" / source.name
    destination.parent.mkdir()
    shutil.copyfile(sys.executable, destination)
    if os.name == "nt":
        for name in (
            "python3.dll", "python312.dll", "vcruntime140.dll",
            "vcruntime140_1.dll",
        ):
            dependency = source.parent / name
            if dependency.is_file():
                shutil.copyfile(dependency, destination.parent / name)
    destination.chmod(0o700)
    assert destination.stat().st_nlink == 1
    return destination.resolve(strict=True)


def _mcp_selection() -> dict[str, object]:
    return authenticated_mcp_selection_fixture()


def _canonical(value) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _request(tmp_path: Path, *, backend: str = "codex"):
    scratchpad = tmp_path / "project" / ".scratchpad"
    project = scratchpad.parent
    scratchpad.mkdir(parents=True)
    prompt = b"Return an exact short verdict.\n"
    environment = (
        {}
        if backend == "codex"
        else {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONIOENCODING": "utf-8",
            "RPC_URL": TOKENIZED_RPC,
        }
    )
    names = sorted(environment)
    environment_record = adapter.compile_bb_provider_environment_record(
        backend=backend,
        environment_names=names,
    )
    request = {
        "schema": "plamen.bb.provider-request.v4",
        "request_id": "",
        "backend": backend,
        "capability": "read_write",
        "label": "vsc",
        "model": "fixture-model",
        "timeout_seconds": 30,
        "run_id": str(uuid.uuid4()),
        "runtime_closure_sha256": "1" * 64,
        "adapter_sha256": hashlib.sha256(
            Path(adapter.__file__).read_bytes()
        ).hexdigest(),
        "scratchpad": str(scratchpad.resolve()),
        "project_root": str(project.resolve()),
        "cwd": str(project.resolve()),
        "extra_add_dirs": [],
        "prompt_authority": {
            "relative_path": "placeholder/prompt.md",
            "sha256": hashlib.sha256(prompt).hexdigest(),
            "size": len(prompt),
        },
        "environment_allowlist": names,
        "environment_allowlist_sha256": adapter._digest(names),
        "environment_semantic_authority_id": str(uuid.uuid4()),
        "environment_authority": environment_record,
        "provider_policy": adapter.compile_bb_provider_policy(
            backend=backend,
            model="fixture-model",
            capability="read_write",
            mcp_runtime_selection=(
                _mcp_selection() if backend == "claude" else None
            ),
        ),
    }
    semantic_sha = adapter._digest(adapter._semantic_payload(request))
    attempt = 0
    request_id = str(
        uuid.uuid5(
            adapter._SEMANTIC_REQUEST_NAMESPACE,
            f"{semantic_sha}:{attempt}",
        )
    )
    root = (
        scratchpad
        / ".bb_provider_requests"
        / semantic_sha
        / str(attempt)
    )
    root.mkdir(parents=True)
    prompt_path = root / "prompt.md"
    prompt_path.write_bytes(prompt)
    request["request_id"] = request_id
    request["prompt_authority"]["relative_path"] = (
        prompt_path.relative_to(scratchpad).as_posix()
    )
    raw = _canonical(request)
    request_path = root / "request.json"
    request_path.write_bytes(raw)
    authority = {
        "scratchpad": str(scratchpad.resolve()),
        "relative_path": request_path.relative_to(scratchpad).as_posix(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    environment_authority = adapter.prepare_bb_provider_environment(
        record=environment_record,
        environment=environment,
        request_binding={
            "request_authority": authority,
            "request_id": request_id,
            "run_id": request["run_id"],
        },
    )
    return scratchpad, authority, environment, environment_authority


def test_codex_adapter_executes_through_public_wer_and_replays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_python = _private_single_link_python(tmp_path)
    scratchpad, authority, environment, environment_authority = _request(
        tmp_path
    )
    request = json.loads(
        (
            scratchpad / authority["relative_path"]
        ).read_text(encoding="utf-8")
    )
    _contract, _launch, output_relative = adapter._contract_launch(request)

    def command_builder(_request, _environment):
        def build(output_directory):
            return [
                str(private_python),
                "-c",
                (
                    "from pathlib import Path; import sys; "
                    "p=Path(sys.argv[1]); p.parent.mkdir(parents=True, "
                    "exist_ok=True); p.write_bytes("
                    "b'fixture provider output\\n')"
                ),
                str(Path(output_directory) / output_relative),
            ]

        return build

    monkeypatch.setattr(adapter, "_command_builder", command_builder)
    result = adapter.invoke_bb_provider(
        authority,
        environment_authority=environment_authority,
    )
    assert result["schema"] == adapter.BB_PROVIDER_INVOCATION_SCHEMA
    replay = adapter.replay_bb_provider_invocation(
        result["invocation_authority"],
        scratchpad=scratchpad,
    )
    assert replay["output"] == "fixture provider output\n"
    assert replay["backend"] == "codex"
    assert replay["output_authority"]["relative_path"].startswith(
        ".bb_provider_outputs/"
    )
    receipt = json.loads(
        (
            scratchpad
            / result["invocation_authority"]["relative_path"]
        ).read_text(encoding="utf-8")
    )
    for name in (
        "wer_completion_authority",
        "attempt_authority",
        "output_authority",
        "incorporation_authority",
    ):
        path = scratchpad / receipt[name]["relative_path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == receipt[name][
            "sha256"
        ]


def test_adapter_preflight_advertises_both_prepared_provider_paths() -> None:
    assert adapter.SUPPORTED_BACKENDS == ("claude", "codex")


def test_claude_contract_launch_identity_is_not_relabelled_codex(
    tmp_path: Path,
) -> None:
    scratchpad, authority, _environment, _environment_authority = _request(
        tmp_path,
        backend="claude",
    )
    request = json.loads(
        (
            scratchpad / authority["relative_path"]
        ).read_text(encoding="utf-8")
    )
    contract, launch, _output_relative = adapter._contract_launch(request)
    assert contract.backend == "claude"
    assert launch.backend == "claude"
    assert "/claude/" in contract.key


def test_claude_path_uses_public_provider_compilers_not_driver_defaults() -> None:
    source = inspect.getsource(adapter)
    assert "from plamen_driver import" not in source
    assert "import plamen_driver" not in source
    assert "compile_claude_headless_provider_authority" in source
    assert "compile_standard_claude_headless_provider_policy" in source
    assert "compile_test_claude_provider_preparation" not in source


def test_provider_policy_is_backend_typed_and_replayed_exactly(
    tmp_path: Path,
) -> None:
    codex = adapter.compile_bb_provider_policy(
        backend="codex",
        model="fixture-model",
        capability="read_write",
    )
    claude = adapter.compile_bb_provider_policy(
        backend="claude",
        model="fixture-model",
        capability="read_write",
        mcp_runtime_selection=_mcp_selection(),
    )
    assert codex["reasoning_effort"] == "xhigh"
    assert codex["claude_policy"] is None
    assert claude["reasoning_effort"] is None
    assert claude["claude_policy"]["launch_model"] == "fixture-model"
    assert claude["claude_policy"]["mcp_policy"][
        "runtime_selection"
    ] == _mcp_selection()
    with pytest.raises(ValueError, match="immutable MCP runtime selection"):
        adapter.compile_bb_provider_policy(
            backend="claude",
            model="fixture-model",
            capability="read_write",
        )

    scratchpad, authority, environment, environment_authority = _request(
        tmp_path,
        backend="claude",
    )
    request_path = scratchpad / authority["relative_path"]
    request = json.loads(request_path.read_text(encoding="utf-8"))
    environment_authority.revoke()
    environment_record = adapter.compile_bb_provider_environment_record(
        backend="claude",
        environment_names=sorted(environment),
    )
    request["environment_authority"] = environment_record
    request["provider_policy"]["claude_policy"]["max_stream_bytes"] += 1
    raw = _canonical(request)
    request_path.write_bytes(raw)
    mutated = {
        **authority,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    with pytest.raises(
        ValueError,
        match="provider policy authority does not replay",
    ):
        adapter.invoke_bb_provider(
            mutated,
            environment_authority=environment_authority,
        )


def test_environment_records_are_unlinkable_and_secret_free() -> None:
    names = ["PATH", "RPC_URL"]
    first = adapter.compile_bb_provider_environment_record(
        backend="claude",
        environment_names=names,
    )
    second = adapter.compile_bb_provider_environment_record(
        backend="claude",
        environment_names=names,
    )
    assert first["authority_id"] != second["authority_id"]
    assert first["authority_sha256"] != second["authority_sha256"]
    encoded = _canonical([first, second])
    assert TOKENIZED_RPC.encode("utf-8") not in encoded
    assert hashlib.sha256(TOKENIZED_RPC.encode("utf-8")).hexdigest().encode(
        "ascii"
    ) not in encoded


def test_wrong_or_reconstructed_environment_authority_fails_closed(
    tmp_path: Path,
) -> None:
    scratchpad, request_authority, environment, original = _request(
        tmp_path,
        backend="claude",
    )
    original.revoke()
    request = json.loads(
        (scratchpad / request_authority["relative_path"]).read_text(
            encoding="utf-8"
        )
    )
    wrong_record = adapter.compile_bb_provider_environment_record(
        backend="claude",
        environment_names=sorted(environment),
    )
    wrong = adapter.prepare_bb_provider_environment(
        record=wrong_record,
        environment=environment,
        request_binding={
            "request_authority": request_authority,
            "request_id": request["request_id"],
            "run_id": request["run_id"],
        },
    )
    with pytest.raises(
        ValueError,
        match="wrong or already used",
    ):
        adapter.invoke_bb_provider(
            request_authority,
            environment_authority=wrong,
        )
    with pytest.raises(
        ValueError,
        match="exact process-local environment authority",
    ):
        adapter.invoke_bb_provider(  # type: ignore[arg-type]
            request_authority,
            environment_authority=request["environment_authority"],
        )


def test_same_environment_record_cannot_prepare_two_value_authorities() -> None:
    record = adapter.compile_bb_provider_environment_record(
        backend="claude",
        environment_names=["RPC_URL"],
    )
    binding = {
        "request_authority": {"sha256": "1" * 64},
        "request_id": str(uuid.uuid4()),
        "run_id": str(uuid.uuid4()),
    }
    first = adapter.prepare_bb_provider_environment(
        record=record,
        environment={"RPC_URL": "https://one.invalid"},
        request_binding=binding,
    )
    with pytest.raises(ValueError, match="already prepared"):
        adapter.prepare_bb_provider_environment(
            record=record,
            environment={"RPC_URL": "https://two.invalid"},
            request_binding=binding,
        )
    assert first.claim(
        expected_record=record,
        request_binding=binding,
    ) == {"RPC_URL": "https://one.invalid"}
    first.revoke()
    with pytest.raises(ValueError, match="already prepared"):
        adapter.prepare_bb_provider_environment(
            record=record,
            environment={"RPC_URL": "https://one.invalid"},
            request_binding=binding,
        )


def test_concurrent_duplicate_environment_preparation_has_one_winner() -> None:
    record = adapter.compile_bb_provider_environment_record(
        backend="claude",
        environment_names=["RPC_URL"],
    )
    binding = {
        "request_authority": {"sha256": "2" * 64},
        "request_id": str(uuid.uuid4()),
        "run_id": str(uuid.uuid4()),
    }
    barrier = threading.Barrier(2)

    def prepare(value: str):
        barrier.wait()
        try:
            return adapter.prepare_bb_provider_environment(
                record=record,
                environment={"RPC_URL": value},
                request_binding=binding,
            )
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        authorities = list(
            pool.map(
                prepare,
                ("https://one.invalid", "https://two.invalid"),
            )
        )
    winners = [item for item in authorities if item is not None]
    assert len(winners) == 1
    winners[0].revoke()


def test_foreign_process_environment_record_cannot_be_prepared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = adapter.compile_bb_provider_environment_record(
        backend="claude",
        environment_names=["RPC_URL"],
    )
    monkeypatch.setattr(adapter, "_ENVIRONMENT_ISSUANCE", {})
    with pytest.raises(ValueError, match="foreign"):
        adapter.prepare_bb_provider_environment(
            record=record,
            environment={"RPC_URL": "https://one.invalid"},
            request_binding={
                "request_authority": {"sha256": "3" * 64},
                "request_id": str(uuid.uuid4()),
                "run_id": str(uuid.uuid4()),
            },
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "unexpected_field",
        "wrong_schema",
        "noncanonical_json",
    ),
)
def test_exported_replay_rejects_nonexact_invocation_receipt_before_references(
    tmp_path: Path,
    mutation: str,
) -> None:
    scratchpad = tmp_path / "project" / ".scratchpad"
    receipt_root = scratchpad / ".bb_provider_receipts" / mutation
    receipt_root.mkdir(parents=True)
    receipt = {
        "schema": adapter.BB_PROVIDER_INVOCATION_SCHEMA,
        "request_authority": {
            "relative_path": ".bb_provider_requests/missing/request.json",
            "sha256": "1" * 64,
        },
        "request_id": str(uuid.uuid4()),
        "backend": "claude",
        "model": "fixture-model",
        "capability": "read_write",
        "prompt_sha256": "2" * 64,
        "cwd": str(scratchpad.parent.resolve()),
        "extra_add_dirs": [],
        "environment_allowlist_sha256": "3" * 64,
        "environment_authority": {},
        "runtime_closure_sha256": "4" * 64,
        "adapter_sha256": "5" * 64,
        "provider_executable_sha256": "6" * 64,
        "provider_argv_sha256": "7" * 64,
        "wer_completion_authority": {},
        "attempt_authority": {},
        "output_authority": {},
        "incorporation_authority": {},
    }
    if mutation == "unexpected_field":
        receipt["unexpected"] = True
        raw = _canonical(receipt)
    elif mutation == "wrong_schema":
        receipt["schema"] = "plamen.bb.provider-invocation.invalid"
        raw = _canonical(receipt)
    else:
        raw = json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8")
    receipt_path = receipt_root / "invocation.json"
    receipt_path.write_bytes(raw)
    authority = {
        "relative_path": receipt_path.relative_to(scratchpad).as_posix(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    with pytest.raises(ValueError, match="exact canonical schema"):
        adapter.replay_bb_provider_invocation(
            authority,
            scratchpad=scratchpad,
        )


def test_claude_adapter_executes_real_wtx_phaseio_and_replay_is_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_python = _private_single_link_python(tmp_path)
    install_test_only_launch_authority_adapter(monkeypatch.setattr)
    monkeypatch.setattr(
        adapter,
        "_assert_bb_claude_mcp_selection_current",
        lambda expected: dict(expected),
    )
    monkeypatch.setattr(adapter, "CLAUDE_DEFAULT_AUTH_ROUTE", "OAUTH_TOKEN")
    scratchpad, authority, environment, environment_authority = _request(
        tmp_path,
        backend="claude",
    )
    def offline_backend_prefix(value):
        selected = dict(value)
        return (
            str(private_python),
            "backend-launch",
            "--backend",
            "claude",
            "--generation",
            selected["generation_id"],
            "--receipt-sha256",
            selected["receipt_sha256"],
            "--census-sha256",
            selected["census_sha256"],
            "--request-sha256",
            selected["request_sha256"],
            "--policy-sha256",
            selected["generation_policy_sha256"],
            "--",
        )

    monkeypatch.setattr(
        claude_preparation,
        "_backend_argv_prefix_from_selection",
        offline_backend_prefix,
    )
    monkeypatch.setattr(
        claude_runtime,
        "_installed_backend_front",
        lambda: str(private_python),
    )
    monkeypatch.setattr(
        worker_receipts,
        "_installed_claude_backend_front",
        lambda: str(private_python),
    )
    monkeypatch.setattr(
        claude_executable,
        "run_owned_process",
        lambda *_args, **_kwargs: type(
            "OwnedVersionProbe",
            (),
            {
                "returncode": 0,
                "stdout": "2.1.252 (Claude Code)\n",
                "stderr": "",
                "process_tree_terminated": True,
            },
        )(),
    )
    (scratchpad / "backend-launch").write_text(
        "import sys\n"
        "separator=sys.argv.index('--')\n"
        "suffix=sys.argv[separator+1:]\n"
        "if suffix == ['--version']:\n"
        "    sys.stdout.write('2.1.252 (Claude Code)\\n')\n"
        "else:\n"
        "    sys.argv=suffix\n"
        "    script=suffix[0]\n"
        "    namespace={'__name__':'__main__','__file__':script}\n"
        "    exec(compile(open(script,'rb').read(),script,'exec'),namespace)\n",
        encoding="utf-8",
    )
    environment_authority.revoke()
    request_path = scratchpad / authority["relative_path"]
    request = json.loads(request_path.read_text(encoding="utf-8"))
    source_config = tmp_path / "offline-claude-source"
    source_config.mkdir()
    environment.update(
        {
            "CLAUDE_BIN": str(private_python),
            "CLAUDE_CODE_OAUTH_TOKEN": OFFLINE_OAUTH_TOKEN,
            "CLAUDE_CONFIG_DIR": str(source_config.resolve()),
        }
    )
    environment_record = adapter.compile_bb_provider_environment_record(
        backend="claude",
        environment_names=sorted(environment),
    )
    request["environment_allowlist"] = sorted(environment)
    request["environment_allowlist_sha256"] = adapter._digest(
        sorted(environment)
    )
    request["environment_semantic_authority_id"] = str(uuid.uuid4())
    request["environment_authority"] = environment_record
    # The reusable offline provider fixture validates its startup receipt at
    # its cwd.  Keeping cwd at the canonical scratchpad exercises the same
    # rooted PhaseIO/WTx lifecycle without depending on a host Claude install.
    request["cwd"] = str(scratchpad.resolve())
    semantic_sha = adapter._digest(adapter._semantic_payload(request))
    request_id = str(
        uuid.uuid5(
            adapter._SEMANTIC_REQUEST_NAMESPACE,
            f"{semantic_sha}:0",
        )
    )
    replacement_root = (
        scratchpad
        / ".bb_provider_requests"
        / semantic_sha
        / "0"
    )
    replacement_root.mkdir(parents=True)
    prompt_source = scratchpad / request["prompt_authority"]["relative_path"]
    prompt_raw = prompt_source.read_bytes()
    prompt_path = replacement_root / "prompt.md"
    prompt_path.write_bytes(prompt_raw)
    request["request_id"] = request_id
    request["prompt_authority"]["relative_path"] = (
        prompt_path.relative_to(scratchpad).as_posix()
    )
    raw = _canonical(request)
    request_path = replacement_root / "request.json"
    request_path.write_bytes(raw)
    authority = {
        "scratchpad": str(scratchpad.resolve()),
        "relative_path": request_path.relative_to(scratchpad).as_posix(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    launch_count = 0
    provider_script = scratchpad / "offline-bb-claude-provider.py"

    def offline_command_template(*, executable, intent, profile):
        assert Path(executable).resolve(strict=True) == private_python
        stream_bytes = claude_fixtures._stream_bytes(
            expected_init=profile["expected_init_contract"],
            session_id=intent["session_id"],
            observed_model=request["model"],
        )
        provider_script.write_text(
            "from pathlib import Path\n"
            "import re\n"
            "import sys\n"
            "prompt=sys.stdin.buffer.read().decode('utf-8')\n"
            "targets=re.findall(r'-> `([^`]+)`', prompt)\n"
            "if len(targets) != 1:\n"
            "    raise SystemExit(8)\n"
            "output=Path(targets[0])\n"
            "output.parent.mkdir(parents=True, exist_ok=True)\n"
            "output.write_bytes(b'fixture Claude provider output\\n')\n"
            + claude_test_postprocess_state_update_source()
            + "sys.stdout.buffer.write("
            + repr(stream_bytes)
            + ")\n",
            encoding="utf-8",
        )
        return [
            str(private_python),
            str(provider_script),
            "-p",
            "--model",
            intent["launch_model"],
            "--output-format",
            "stream-json",
            "--verbose",
            "--session-id",
            intent["session_id"],
            "--no-session-persistence",
            *tuple(profile["cli_flags"]),
        ]

    # Only the provider executable is replaced by an offline stand-in.  The
    # adapter's production compiler, preparation, WorkPlan, WER, and PhaseIO
    # code paths remain unmocked and consume the real ephemeral environment.
    monkeypatch.setattr(
        claude_preparation,
        "_command_template",
        offline_command_template,
    )
    real_compile = adapter._compile_claude_provider_authority

    def observed_production_compile(*args, **kwargs):
        nonlocal launch_count
        compiled = real_compile(*args, **kwargs)
        launch_count += 1
        assert (
            compiled["runtime_local_inputs"]["ambient_environment"][
                "RPC_URL"
            ]
            == TOKENIZED_RPC
        )
        return compiled

    monkeypatch.setattr(
        adapter,
        "_compile_claude_provider_authority",
        observed_production_compile,
    )
    # Rebind after changing the request identity/cwd in this fixture.
    environment_authority = adapter.prepare_bb_provider_environment(
        record=environment_record,
        environment=environment,
        request_binding={
            "request_authority": authority,
            "request_id": request_id,
            "run_id": request["run_id"],
        },
    )
    result = adapter.invoke_bb_provider(
        authority,
        environment_authority=environment_authority,
    )
    assert launch_count == 1
    replay = adapter.replay_bb_provider_invocation(
        result["invocation_authority"],
        scratchpad=scratchpad,
    )
    assert replay["backend"] == "claude"
    assert replay["output"] == "fixture Claude provider output\n"
    assert launch_count == 1
    units = adapter.read_artifact_ledger(scratchpad)["work_units"]
    assert len(units) == 1
    assert next(iter(units.values()))["execution_state"] == "OUTPUT_COMMITTED"
    forbidden = set()
    for secret in (
        TOKENIZED_RPC,
        OFFLINE_OAUTH_TOKEN,
    ):
        forbidden.add(secret.encode("utf-8"))
        forbidden.add(
            hashlib.sha256(secret.encode("utf-8")).hexdigest().encode(
                "ascii"
            )
        )
    for path in scratchpad.rglob("*"):
        if path.is_file():
            raw = path.read_bytes()
            assert all(secret not in raw for secret in forbidden)


def test_public_adapter_rooted_publication_rejects_parent_symlink(
    tmp_path: Path,
) -> None:
    root = tmp_path / "scratchpad"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    parent = root / ".bb_provider_receipts"
    try:
        parent.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"host cannot create a directory symlink fixture: {exc}")
    with pytest.raises(bb_path_authority.BBPathAuthorityError):
        bb_path_authority.publish_rooted_bytes(
            root,
            ".bb_provider_receipts/unit/invocation.json",
            b"{}",
            label="public BB fixture",
            replay_exact=False,
            max_bytes=1024,
        )
    assert list(outside.rglob("*")) == []


@pytest.mark.parametrize(
    "relative",
    (
        "../escape",
        "nested\\escape",
        "file:stream",
        "AUX.json",
        "non-nfc-e\u0301",
        "trailing.",
        "trailing ",
    ),
)
def test_public_adapter_rejects_nonportable_artifact_names(
    tmp_path: Path,
    relative: str,
) -> None:
    root = tmp_path / "scratchpad"
    root.mkdir()
    with pytest.raises(bb_path_authority.BBPathAuthorityError):
        bb_path_authority.publish_rooted_bytes(
            root,
            relative,
            b"x",
            label="public BB fixture",
            replay_exact=True,
            max_bytes=1024,
        )
