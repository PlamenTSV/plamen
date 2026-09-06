"""Fixture-first selected-MCP driver/provider privacy integration.

No fixture launches Claude or contacts an MCP server.  The source manifest is
an offline file whose environment value is intentionally high entropy so the
tests can prove that neither the value nor its stable SHA-256 becomes public
authority.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

import claude_provider_preparation as P
import claude_runtime_materialization as M
import plamen_driver as D
import test_worker_execution_receipts as wer_fixtures
import worker_execution_receipts as W
from test_claude_provider_preparation import (
    RUN_ID,
    _attach,
    _inputs,
    _install_observers,
    _public_inputs,
)
from test_headless_driver_cutover_p0_am import (
    _armed_inventory_model,
    _install_offline_driver_provider,
)
from test_wer_claude_command_and_runtime_fingerprint_p0_am import (
    _v2_configuration,
    _write_empty_bound_settings,
)
from test_support_startup_permit import durable_startup_permit


SERVER = "unified-vuln-db"
SECRET = "offline-solodit-secret-r1-7f393ab17e"


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _source_manifest(
    tmp_path: Path,
    *,
    secret: str = SECRET,
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "installed-mcp.json"
    source.write_bytes(
        _canonical(
            {
                "mcpServers": {
                    SERVER: {
                        "command": sys.executable,
                        "args": ["-I", "-c", "raise SystemExit(0)"],
                        "cwd": str(tmp_path.resolve()),
                        "env": {"SOLODIT_API_KEY": secret},
                    }
                }
            }
        )
    )
    return source


def _assert_no_secret_or_oracle(value: object) -> None:
    def encode(item: object) -> bytes:
        if isinstance(item, bytes):
            return item
        if isinstance(item, dict):
            return b"".join(
                encode(key) + encode(child)
                for key, child in item.items()
            )
        if isinstance(item, (tuple, list)):
            return b"".join(encode(child) for child in item)
        return str(item).encode("utf-8")

    rendered = encode(value)
    assert SECRET.encode("utf-8") not in rendered
    assert hashlib.sha256(SECRET.encode("utf-8")).hexdigest().encode(
        "ascii"
    ) not in rendered


def test_selected_mcp_observation_is_structural_and_secret_free(
    tmp_path: Path,
) -> None:
    source = _source_manifest(tmp_path)

    observation = M.observe_claude_mcp_source_manifest(
        source_path=source,
        run_id=RUN_ID,
        server_names=(SERVER,),
    )

    assert observation["server_names"] == (SERVER,)
    assert observation["source_store_class"] == "CLAUDE_MCP_JSON"
    assert observation["source_file_size"] == source.stat().st_size
    assert len(observation["source_file_identity_sha256"]) == 64
    assert len(observation["materialization_id"]) == 32
    template = observation["selected_config_template_bytes"]
    payload = json.loads(template)
    entry = payload["mcpServers"][SERVER]
    assert entry["plamenRuntimeEnvironmentNames"] == [
        "SOLODIT_API_KEY"
    ]
    assert "env" not in entry
    assert entry["command"] == str(Path(sys.executable).resolve())
    _assert_no_secret_or_oracle(observation)


def test_driver_selected_mcp_propagates_only_template_and_private_source_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_offline_driver_provider(monkeypatch)
    phase, config, contract, original_launch = _armed_inventory_model(
        tmp_path,
        backend="claude",
    )
    phase = D.Phase(
        name="rag_sweep",
        section_markers=["## RAG"],
        expected_artifacts=["rag_validation.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )
    launch = type(original_launch)(
        work_unit_key=original_launch.work_unit_key,
        pipeline=original_launch.pipeline,
        mode=original_launch.mode,
        ecosystem=original_launch.ecosystem,
        backend=original_launch.backend,
        model=original_launch.model,
        timeout_s=original_launch.timeout_s,
        exec_mode=original_launch.exec_mode,
        tool_policy=("filesystem", "mcp"),
    )
    source = _source_manifest(tmp_path)
    config["claude_auth_route"] = "OAUTH_TOKEN"
    config["_claude_mcp_source_manifest_path"] = str(source)
    calls: list[dict[str, object]] = []

    def capture(**kwargs):
        calls.append(dict(kwargs))
        output = tmp_path / "transaction-output"
        output.mkdir(exist_ok=True)
        base = tuple(kwargs["command_builder"](output))
        assert "--settings" not in base
        assert "--mcp-config" not in base
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(D, "execute_headless_worker", capture)
    monkeypatch.setattr(D, "_record_phase_cost", lambda *_a, **_k: None)
    monkeypatch.setattr(
        D,
        "detect_background_orphan",
        lambda *_a, **_k: None,
    )

    assert D._run_transactional_headless_leaf(
        backend="claude",
        prompt="offline RAG prompt",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        label="rag-sweep",
        expected_outputs=["rag_validation.md"],
        timeout=30,
        effective_model=launch.model,
        contract=contract,
        launch=launch,
        working_directory=str(tmp_path),
        analysis_directories=(str(tmp_path),),
    ) == 0

    assert len(calls) == 1
    call = calls[0]
    package = call["claude_provider_preparation"]
    assert isinstance(package, P.ClaudeProviderPreparation)
    assert call["environment"] == {}
    assert call["claude_bound_settings_bytes"] is not None
    template = call["claude_selected_mcp_config_bytes"]
    assert isinstance(template, bytes)
    assert package.record["mcp_policy"]["server_names"] == [SERVER]
    assert package.record["settings_policy"]["mode"] == "BOUND_SETTINGS"
    assert (
        call["claude_runtime_local_inputs"]["ambient_environment"][
            M.CLAUDE_PRIVATE_MCP_SOURCE_MANIFEST_ENV
        ]
        == str(source.resolve())
    )
    for public in (
        package.to_bytes(),
        package.record,
        call["claude_launch_security"],
        call["claude_launch_security_request"],
        template,
    ):
        _assert_no_secret_or_oracle(public)


@pytest.mark.parametrize(
    "manifest",
    [
        {"mcpServers": {}},
        {
            "mcpServers": {
                SERVER: {
                    "command": sys.executable,
                    "args": [],
                    "cwd": ".",
                    "env": {"SOLODIT_API_KEY": SECRET},
                }
            }
        },
        {
            "mcpServers": {
                SERVER: {
                    "command": sys.executable,
                    "args": [],
                    "cwd": None,
                    "env": {"SOLODIT_API_KEY": ""},
                }
            }
        },
    ],
)
def test_selected_mcp_unavailable_or_malformed_is_prelaunch_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    manifest: object,
) -> None:
    _install_offline_driver_provider(monkeypatch)
    phase, config, contract, original_launch = _armed_inventory_model(
        tmp_path,
        backend="claude",
    )
    phase = D.Phase(
        name="rag_sweep",
        section_markers=["## RAG"],
        expected_artifacts=["rag_validation.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )
    launch = type(original_launch)(
        work_unit_key=original_launch.work_unit_key,
        pipeline=original_launch.pipeline,
        mode=original_launch.mode,
        ecosystem=original_launch.ecosystem,
        backend=original_launch.backend,
        model=original_launch.model,
        timeout_s=original_launch.timeout_s,
        exec_mode=original_launch.exec_mode,
        tool_policy=("filesystem", "mcp"),
    )
    source = tmp_path / "mcp.json"
    source.write_bytes(_canonical(manifest))
    config["claude_auth_route"] = "OAUTH_TOKEN"
    config["_claude_mcp_source_manifest_path"] = str(source)
    called = False

    def forbidden(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("MCP debt reached provider execution")

    monkeypatch.setattr(D, "execute_headless_worker", forbidden)
    monkeypatch.setattr(D, "_record_phase_cost", lambda *_a, **_k: None)
    monkeypatch.setattr(
        D,
        "detect_background_orphan",
        lambda *_a, **_k: None,
    )

    assert D._run_transactional_headless_leaf(
        backend="claude",
        prompt="offline RAG prompt",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        label="rag-sweep-debt",
        expected_outputs=["rag_validation.md"],
        timeout=30,
        effective_model=launch.model,
        contract=contract,
        launch=launch,
        working_directory=str(tmp_path),
        analysis_directories=(str(tmp_path),),
    ) == D.EXIT_ERROR
    assert called is False


def test_runtime_resolves_secret_only_inside_attempt_private_mcp_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source_manifest(tmp_path)
    observation = M.observe_claude_mcp_source_manifest(
        source_path=source,
        run_id=RUN_ID,
        server_names=(SERVER,),
    )
    values = _inputs(
        tmp_path / "provider",
        route="OAUTH_TOKEN",
        settings_mode="BOUND_SETTINGS",
        mcp_servers=(SERVER,),
    )
    settings = values["_bound_settings_bytes"]
    template = observation["selected_config_template_bytes"]
    assert isinstance(settings, bytes)
    assert isinstance(template, bytes)
    values["_selected_mcp_config_bytes"] = template
    values["mcp_policy"] = P.compile_claude_mcp_policy(
        settings_mode="BOUND_SETTINGS",
        server_names=(SERVER,),
        source_manifest_sha256=observation[
            "source_manifest_sha256"
        ],
        selected_config_sha256=hashlib.sha256(template).hexdigest(),
    )
    ambient = dict(values["ambient_environment"])
    ambient[M.CLAUDE_PRIVATE_MCP_SOURCE_MANIFEST_ENV] = str(
        source.resolve()
    )
    values["ambient_environment"] = ambient
    scratchpad = Path(values["startup_scratchpad"])
    values["startup_authority_binding"] = durable_startup_permit(
        scratchpad,
        run_id=RUN_ID,
    )
    executable = Path(str(values["configured_claude_bin"]))
    _install_observers(
        monkeypatch,
        executable,
        stored_available=False,
    )
    package = P.prepare_claude_provider(**_public_inputs(values))
    attachment = _attach(package, values)
    claimed = P.claim_bound_claude_provider_runtime(
        attachment,
        provider_preparation=package,
        expected_preparation_sha256=package.preparation_sha256,
        expected_runtime_host_policy_sha256=package.record[
            "runtime_host_policy"
        ]["policy_sha256"],
        expected_attachment_sha256=attachment.attachment_sha256,
    )
    flags = tuple(package.record["headless_profile"]["cli_flags"])
    base = package.command_for_bound_stdin()[:-len(flags)]
    request = M.compile_claude_runtime_materialization_request(
        launch_security_request=package.record[
            "launch_security_request"
        ],
        provider_runtime=claimed,
        base_argv=base,
        scratchpad=scratchpad,
        startup_permit_binding=values["startup_authority_binding"],
        run_id=RUN_ID,
        outer_attempt_arm_sha256="a" * 64,
        work_plan_sha256="b" * 64,
        attempt_id="attempt-private-mcp",
        process_scope_identity="scope-private-mcp",
    )
    runtime = M.materialize_claude_runtime(request)
    mcp_path = Path(
        runtime.final_argv[
            runtime.final_argv.index("--mcp-config") + 1
        ]
    )
    authority_bytes = runtime._selected_mcp_config_file.exact_bytes
    try:
        assert runtime.process_writable_root in mcp_path.parents
        private_payload = json.loads(mcp_path.read_bytes())
        assert private_payload["mcpServers"][SERVER]["env"] == {
            "SOLODIT_API_KEY": SECRET
        }
        assert "plamenRuntimeEnvironmentNames" not in (
            private_payload["mcpServers"][SERVER]
        )
        for public in (
            package.to_bytes(),
            package.record,
            runtime.receipt,
            runtime.redacted_receipts,
            repr(runtime),
        ):
            _assert_no_secret_or_oracle(public)
    finally:
        runtime.abort_before_process_scope("TEST_PRIVATE_MCP_ABORT")
    assert not mcp_path.exists()
    assert authority_bytes
    assert set(authority_bytes) == {0}


def test_wer_receipt_binding_omits_secret_derived_mcp_digest_and_replays_revoked_files(
    tmp_path: Path,
) -> None:
    mcp_config = _source_manifest(tmp_path)
    mcp_raw_sha256 = hashlib.sha256(mcp_config.read_bytes()).hexdigest()
    settings = _write_empty_bound_settings(tmp_path)
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    configuration, profile_flags = _v2_configuration(
        tmp_path,
        permission_mode="dontAsk",
        mcp_server_names=(SERVER,),
    )
    argv = [
        *wer_fixtures._claude_stream_argv(script),
        *profile_flags,
        "--settings",
        str(settings),
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
    ]

    binding = W._claude_stream_stdout_binding(
        configuration,
        argv=argv,
        stdout_limit_bytes=W.DEFAULT_STDOUT_LIMIT_BYTES,
        cwd=tmp_path.resolve(),
        effective_model="claude-opus",
    )
    profile = binding["command_contract"]["headless_profile"]
    mcp_binding = profile["mcp_config"]
    assert "sha256" not in mcp_binding
    assert mcp_binding["privacy_mode"] == (
        "EPHEMERAL_ENVIRONMENT_VALUES"
    )
    assert mcp_binding["environment_names"] == {
        SERVER: ["SOLODIT_API_KEY"]
    }
    assert mcp_binding["credential_values_recorded"] is False
    assert mcp_binding["credential_content_hashes_recorded"] is False
    assert mcp_raw_sha256 not in json.dumps(
        binding,
        sort_keys=True,
    )
    _assert_no_secret_or_oracle(binding)

    settings.unlink()
    mcp_config.unlink()
    replayed = W._claude_stream_stdout_binding(
        configuration,
        argv=argv,
        stdout_limit_bytes=W.DEFAULT_STDOUT_LIMIT_BYTES,
        cwd=tmp_path.resolve(),
        effective_model="claude-opus",
        bound_headless_profile_authority=profile,
    )
    assert replayed == binding


def test_source_drift_after_observation_rolls_back_attempt_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source_manifest(tmp_path)
    observation = M.observe_claude_mcp_source_manifest(
        source_path=source,
        run_id=RUN_ID,
        server_names=(SERVER,),
    )
    values = _inputs(
        tmp_path / "provider",
        route="OAUTH_TOKEN",
        settings_mode="BOUND_SETTINGS",
        mcp_servers=(SERVER,),
    )
    template = observation["selected_config_template_bytes"]
    values["_selected_mcp_config_bytes"] = template
    values["mcp_policy"] = P.compile_claude_mcp_policy(
        settings_mode="BOUND_SETTINGS",
        server_names=(SERVER,),
        source_manifest_sha256=observation[
            "source_manifest_sha256"
        ],
        selected_config_sha256=hashlib.sha256(template).hexdigest(),
    )
    values["ambient_environment"] = {
        **values["ambient_environment"],
        M.CLAUDE_PRIVATE_MCP_SOURCE_MANIFEST_ENV: str(source.resolve()),
    }
    scratchpad = Path(values["startup_scratchpad"])
    values["startup_authority_binding"] = durable_startup_permit(
        scratchpad,
        run_id=RUN_ID,
    )
    executable = Path(str(values["configured_claude_bin"]))
    _install_observers(
        monkeypatch,
        executable,
        stored_available=False,
    )
    package = P.prepare_claude_provider(**_public_inputs(values))
    attachment = _attach(package, values)
    claimed = P.claim_bound_claude_provider_runtime(
        attachment,
        provider_preparation=package,
        expected_preparation_sha256=package.preparation_sha256,
        expected_runtime_host_policy_sha256=package.record[
            "runtime_host_policy"
        ]["policy_sha256"],
        expected_attachment_sha256=attachment.attachment_sha256,
    )
    flags = tuple(package.record["headless_profile"]["cli_flags"])
    request = M.compile_claude_runtime_materialization_request(
        launch_security_request=package.record[
            "launch_security_request"
        ],
        provider_runtime=claimed,
        base_argv=package.command_for_bound_stdin()[:-len(flags)],
        scratchpad=scratchpad,
        startup_permit_binding=values["startup_authority_binding"],
        run_id=RUN_ID,
        outer_attempt_arm_sha256="c" * 64,
        work_plan_sha256="d" * 64,
        attempt_id="attempt-mcp-drift",
        process_scope_identity="scope-mcp-drift",
    )
    source.write_bytes(
        _source_manifest(
            tmp_path / "changed",
            secret="different-offline-solodit-secret",
        ).read_bytes()
    )

    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="source manifest",
    ):
        M.materialize_claude_runtime(request)
    roots = list(
        (scratchpad / "_auxiliary_writable_roots").glob("**/*")
    )
    assert not [path for path in roots if path.is_file()]
