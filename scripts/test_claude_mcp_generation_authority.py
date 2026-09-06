"""Authenticated immutable MCP generation binding across Claude consumers."""

from __future__ import annotations

import ast
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import claude_headless_profile as H
import claude_executable_observation as E
import claude_launch_security as L
import claude_provider_preparation as P
import claude_runtime_materialization as M
import plamen_driver as D


def _member_authority(
    selection: dict[str, object],
    row: dict[str, object],
    private: Ed25519PrivateKey,
) -> dict[str, object]:
    root, roster = L._native_backend_roster(row["relative_path"])
    closure = []
    for path in sorted(roster, key=lambda item: (item.casefold(), item)):
        is_primary = path == row["relative_path"]
        is_file = is_primary or not any(
            other != path and other.startswith(path + "/") for other in roster
        )
        closure.append({
            "path": path,
            "kind": "file" if is_file else "directory",
            "size": row["size"] if is_primary else (1 if is_file else 0),
            "sha256": row["sha256"] if is_primary else "e" * 64,
            "mode": 0o755,
            "link_count": 1,
            "reparse": False,
        })
    root_parts = root.split("/")[:-1]
    ancestors = [{
        "path": ".", "mode": 0o755, "link_count": 1, "reparse": False,
    }]
    ancestors.extend({
        "path": "/".join(root_parts[:index]),
        "mode": 0o755,
        "link_count": 1,
        "reparse": False,
    } for index in range(1, len(root_parts) + 1))
    authority = {
        "schema": "plamen.mcp_native_resource_closure.v2",
        "generation_id": selection["generation_id"],
        "receipt_sha256": selection["receipt_sha256"],
        "census_sha256": selection["census_sha256"],
        "request_sha256": selection["request_sha256"],
        "generation_policy_sha256": selection["generation_policy_sha256"],
        "execution_kind": row["execution_kind"],
        "receipt_file_sha256": "f" * 64,
        "relative_path": row["relative_path"],
        "size": row["size"],
        "sha256": row["sha256"],
        "mode": 0o755,
        "link_count": 1,
        "closure_root": root,
        "closure_count": len(closure),
        "closure_sha256": hashlib.sha256(L._canonical_json(closure)).hexdigest(),
        "closure": closure,
        "ancestors": ancestors,
    }
    return {
        "authority": authority,
        "authentication": {
            "scheme": "ed25519",
            "key_id": selection["receipt_key_id"],
            "signature": private.sign(L._canonical_json(authority)).hex(),
        },
    }


def authenticated_mcp_selection_fixture() -> dict[str, object]:
    private = Ed25519PrivateKey.from_private_bytes(b"\x17" * 32)
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    selection = {
        "schema": "plamen.mcp_current_selection.v1",
        "store_root": os.fspath(D._installed_mcp_public_front_path().parent),
        "generation_id": "generation-1",
        "receipt_sha256": "1" * 64,
        "census_sha256": "2" * 64,
        "request_sha256": "3" * 64,
        "generation_policy_sha256": "4" * 64,
        "receipt_key_id": hashlib.sha256(bytes.fromhex(public)).hexdigest(),
        "receipt_public_key": public,
        "install_transaction_id": "install-1",
        "install_receipt_sha256": "7" * 64,
        "install_source_manifest_sha256": "8" * 64,
        "install_runtime_manifest_sha256": "9" * 64,
        "install_adapter_manifest_sha256": "a" * 64,
        "server_launches": {
            "unified-vuln-db": {
                "entrypoint": "finalizers/schema-sanitizer.js",
                "node_args": ["payload/server.js"],
                "cwd": None,
                "environment_names": [],
            }
        },
        "backend_launches": {
            "claude": {
                "execution_kind": "native",
                "relative_path": "node_modules/@anthropic-ai/claude-code/bin/claude.exe",
                "version": "2.1.252",
                "size": 217400000,
                "sha256": "c" * 64,
            },
            "codex": {
                "execution_kind": "native",
                "relative_path": (
                    "node_modules/@openai/codex-win32-x64/vendor/"
                    "x86_64-pc-windows-msvc/bin/codex.exe"
                ),
                "version": "0.152.0",
                "size": 1000,
                "sha256": "d" * 64,
            },
        },
        "signature": "b" * 128,
    }
    for row in selection["backend_launches"].values():
        row["member_authority"] = _member_authority(selection, row, private)
    return selection


def _selection() -> dict[str, object]:
    return authenticated_mcp_selection_fixture()


def _canonical_line(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"


def _selected_config(selection: dict[str, object]) -> bytes:
    old = D._DIRECT_CLAUDE_MCP_SELECTION
    try:
        D._DIRECT_CLAUDE_MCP_SELECTION = selection
        return D._selected_claude_mcp_config_bytes(
            server_names=("unified-vuln-db",)
        )
    finally:
        D._DIRECT_CLAUDE_MCP_SELECTION = old


def test_signed_selection_replays_and_any_tuple_drift_changes_identity() -> None:
    selection = _selection()
    replayed = L.replay_mcp_current_selection(selection)
    digest = L.mcp_current_selection_sha256(replayed)

    assert replayed == selection
    assert len(digest) == 64
    changed = copy.deepcopy(selection)
    changed["generation_policy_sha256"] = "c" * 64
    with pytest.raises(L.ClaudeLaunchSecurityError):
        L.mcp_current_selection_sha256(changed)

    malformed = json.loads(json.dumps(selection))
    malformed["server_launches"]["unified-vuln-db"]["cwd"] = 7
    with pytest.raises(L.ClaudeLaunchSecurityError):
        L.replay_mcp_current_selection(malformed)


@pytest.mark.parametrize(
    "package,target,executable",
    [
        ("darwin-arm64", "aarch64-apple-darwin", "codex"),
        ("darwin-x64", "x86_64-apple-darwin", "codex"),
        ("linux-arm64", "aarch64-unknown-linux-musl", "codex"),
        ("linux-x64", "x86_64-unknown-linux-musl", "codex"),
        ("win32-arm64", "aarch64-pc-windows-msvc", "codex.exe"),
        ("win32-x64", "x86_64-pc-windows-msvc", "codex.exe"),
    ],
)
def test_signed_selection_accepts_only_governed_native_codex_layouts(
    package: str, target: str, executable: str,
) -> None:
    selection = _selection()
    row = selection["backend_launches"]["codex"]
    row["relative_path"] = (
        f"node_modules/@openai/codex-{package}/vendor/{target}/bin/{executable}"
    )
    private = Ed25519PrivateKey.from_private_bytes(b"\x17" * 32)
    row["member_authority"] = _member_authority(selection, row, private)

    assert L.replay_mcp_current_selection(selection) == selection


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["backend_launches"]["codex"].update({
            "execution_kind": "node",
            "relative_path": "node_modules/@openai/codex/bin/codex.js",
        }),
        lambda value: value["backend_launches"]["codex"].update({
            "relative_path": (
                "node_modules/@openai/codex-win32-x64/vendor/"
                "aarch64-pc-windows-msvc/bin/codex.exe"
            ),
        }),
        lambda value: value["backend_launches"]["claude"].pop(
            "member_authority"
        ),
        lambda value: value["backend_launches"]["claude"]
        ["member_authority"]["authority"].update({"sha256": "0" * 64}),
        lambda value: value["backend_launches"]["claude"]
        ["member_authority"]["authentication"].update({
            "signature": "0" * 128,
        }),
        lambda value: value["backend_launches"]["claude"]
        ["member_authority"]["authority"]["closure"][0].update({
            "reparse": True,
        }),
    ],
)
def test_signed_selection_rejects_backend_authority_drift(mutation) -> None:
    malformed = copy.deepcopy(_selection())
    mutation(malformed)
    with pytest.raises(L.ClaudeLaunchSecurityError):
        L.replay_mcp_current_selection(malformed)


def test_provider_policy_launch_and_headless_authority_bind_full_selection() -> None:
    selection = _selection()
    config = _selected_config(selection)
    config_sha256 = hashlib.sha256(config).hexdigest()
    policy = P.compile_claude_mcp_policy(
        settings_mode="BOUND_SETTINGS",
        server_names=("unified-vuln-db",),
        source_manifest_sha256=selection["receipt_sha256"],
        selected_config_sha256=config_sha256,
        runtime_selection=selection,
    )
    authority = L.compile_claude_mcp_authority(
        settings_mode="BOUND_SETTINGS",
        server_names=("unified-vuln-db",),
        source_manifest_sha256=selection["receipt_sha256"],
        selected_config_sha256=config_sha256,
        runtime_selection=policy["runtime_selection"],
    )

    assert policy["runtime_selection_sha256"] == (
        authority["runtime_selection_sha256"]
    )
    assert authority["schema"] == L.CLAUDE_MCP_AUTHORITY_SELECTION_SCHEMA
    assert H._replay_mcp_authority(
        authority, settings_mode="BOUND_SETTINGS"
    ) == authority

    tampered = json.loads(json.dumps(authority))
    tampered["runtime_selection"]["request_sha256"] = "d" * 64
    with pytest.raises(H.ClaudeHeadlessProfileError):
        H._replay_mcp_authority(
            tampered, settings_mode="BOUND_SETTINGS"
        )


def test_materialization_replays_exact_generation_launcher_before_lease() -> None:
    selection = _selection()
    config = _selected_config(selection)
    settings = (
        b'{"enabledPlugins":{},"hooks":{},"mcpServers":{},'
        b'"permissions":{"deny":["Agent","Task"]}}\n'
    )
    authority = L.compile_claude_mcp_authority(
        settings_mode="BOUND_SETTINGS",
        server_names=("unified-vuln-db",),
        source_manifest_sha256=selection["receipt_sha256"],
        selected_config_sha256=hashlib.sha256(config).hexdigest(),
        runtime_selection=selection,
    )
    policy = {
        "settings_authority": L.compile_claude_settings_authority(
            mode="BOUND_SETTINGS",
            settings_sha256=hashlib.sha256(settings).hexdigest(),
            external_policy_sha256=hashlib.sha256(config).hexdigest(),
        ),
        "mcp_authority": authority,
    }

    assert M._validated_bound_runtime_sources(
        policy=policy,
        bound_settings_bytes=settings,
        selected_mcp_config_bytes=config,
    ) == (settings, config, ("unified-vuln-db",))

    payload = json.loads(config)
    payload["mcpServers"]["unified-vuln-db"]["args"][-1] = "e" * 64
    tampered = _canonical_line(payload)
    tampered_authority = L.compile_claude_mcp_authority(
        settings_mode="BOUND_SETTINGS",
        server_names=("unified-vuln-db",),
        source_manifest_sha256=selection["receipt_sha256"],
        selected_config_sha256=hashlib.sha256(tampered).hexdigest(),
        runtime_selection=selection,
    )
    tampered_policy = {**policy, "mcp_authority": tampered_authority}
    with pytest.raises(M.ClaudeRuntimeMaterializationError) as denied:
        M._validated_bound_runtime_sources(
            policy=tampered_policy,
            bound_settings_bytes=settings,
            selected_mcp_config_bytes=tampered,
        )
    assert denied.value.reason_code == "RUNTIME_MCP_SELECTION_DRIFT"


def test_driver_admission_requires_canonical_authenticated_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection = _selection()
    calls: list[list[str]] = []
    monkeypatch.setattr(
        D, "_assert_direct_claude_projection_current", lambda: None
    )

    def completed(command, **_kwargs):
        calls.append(list(command))
        return type("Completed", (), {
            "returncode": 0,
            "stdout": _canonical_line(selection),
            "stderr": b"",
        })()

    monkeypatch.setattr(D.subprocess, "run", completed)
    D._admit_direct_driver_projection({"cli_backend": "claude"})

    assert D._DIRECT_CLAUDE_MCP_SELECTION == selection
    assert calls == [[
        os.fspath(D._installed_mcp_public_front_path()),
        "mcp-selection",
        "--json",
        "--backend",
        "claude",
    ]]

    monkeypatch.setattr(
        D.subprocess,
        "run",
        lambda *_args, **_kwargs: type("Completed", (), {
            "returncode": 0,
            "stdout": _canonical_line(selection) + b"\n",
            "stderr": b"",
        })(),
    )
    with pytest.raises(D.DirectDriverProjectionAdmissionError):
        D._assert_claude_mcp_selection_current()


def test_codex_only_clears_selection_without_front_or_mcp_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(D, "_DIRECT_CLAUDE_MCP_SELECTION", _selection())
    monkeypatch.setattr(
        D.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("Codex-only invoked Claude front"),
    )

    D._admit_direct_driver_projection({"cli_backend": "codex"})

    assert D._DIRECT_CLAUDE_MCP_SELECTION is None


def test_generation_backend_observation_probes_only_public_front(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    front = tmp_path / ("plamen.cmd" if os.name == "nt" else "plamen")
    front.write_bytes(b"authenticated installed front\n")
    selection = _selection()
    old = D._DIRECT_CLAUDE_MCP_SELECTION
    D._DIRECT_CLAUDE_MCP_SELECTION = selection
    try:
        prefix = D._selected_claude_backend_argv_prefix()
    finally:
        D._DIRECT_CLAUDE_MCP_SELECTION = old
    prefix = (str(front.resolve()), *prefix[1:])
    calls: list[list[str]] = []

    observed_kwargs = {}

    def run_owned(argv, **kwargs):
        calls.append(list(argv))
        observed_kwargs.update(kwargs)
        return type(
            "Owned",
            (),
            {
                "returncode": 0,
                "stdout": "2.1.252 (Claude Code)\n",
                "stderr": "",
                "process_tree_terminated": True,
            },
        )()

    monkeypatch.setattr(E, "run_owned_process", run_owned)
    observed = E.observe_claude_generation_backend(
        installed_front=str(front.resolve()),
        backend_argv_prefix=prefix,
        selection_sha256=L.mcp_current_selection_sha256(selection),
        selected_backend=selection["backend_launches"]["claude"],
        environment={},
    )
    replayed = E.replay_claude_executable_observation(observed)

    assert calls == [[*prefix, "--version"]]
    assert E.GENERATION_VERSION_PROBE_TIMEOUT_SECONDS == 120.0
    assert observed_kwargs["timeout"] == (
        E.GENERATION_VERSION_PROBE_TIMEOUT_SECONDS
    )
    assert replayed["resolved_executable"] == str(front.resolve())
    assert replayed["backend_launch_authority"]["argv_prefix"] == list(prefix)
    assert replayed["backend_launch_authority"]["selected_backend"] == (
        selection["backend_launches"]["claude"]
    )
    assert "schema-sanitizer" not in "\0".join(calls[0])
    assert selection["backend_launches"]["claude"]["relative_path"] not in calls[0]

    tampered = copy.deepcopy(replayed)
    tampered["backend_launch_authority"]["selected_backend"][
        "member_authority"
    ]["authority"]["closure"][0]["reparse"] = True
    with pytest.raises(E.ClaudeExecutableObservationError):
        E.replay_claude_executable_observation(tampered)


def test_generation_backend_observation_reuses_only_exact_current_authority(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    front = tmp_path / ("plamen.cmd" if os.name == "nt" else "plamen")
    front.write_bytes(b"authenticated installed front\n")
    selection = _selection()
    old = D._DIRECT_CLAUDE_MCP_SELECTION
    D._DIRECT_CLAUDE_MCP_SELECTION = selection
    try:
        generated = D._selected_claude_backend_argv_prefix()
    finally:
        D._DIRECT_CLAUDE_MCP_SELECTION = old
    prefix = (str(front.resolve()), *generated[1:])
    calls: list[list[str]] = []

    def run_owned(argv, **_kwargs):
        calls.append(list(argv))
        return type(
            "Owned",
            (),
            {
                "returncode": 0,
                "stdout": "2.1.252 (Claude Code)\n",
                "stderr": "",
                "process_tree_terminated": True,
            },
        )()

    monkeypatch.setattr(E, "_GENERATION_OBSERVATION_CACHE", None)
    monkeypatch.setattr(E, "run_owned_process", run_owned)
    common = {
        "installed_front": str(front.resolve()),
        "backend_argv_prefix": prefix,
        "selection_sha256": L.mcp_current_selection_sha256(selection),
        "selected_backend": selection["backend_launches"]["claude"],
        "environment": {},
    }

    first = E.observe_claude_generation_backend(**common)
    second = E.observe_claude_generation_backend(**common)
    assert second == first
    assert second is not first
    assert calls == [[*prefix, "--version"]]

    # Caller mutation cannot poison the immutable cached bytes.
    first["version_probe"]["stdout_utf8"] = "attacker-controlled\n"
    assert E.observe_claude_generation_backend(**common) == second
    assert len(calls) == 1

    # A front byte change, selection change, or environment change is a new
    # authority and must execute a fresh authenticated probe.
    front.write_bytes(b"replacement authenticated installed front\n")
    E.observe_claude_generation_backend(**common)
    assert len(calls) == 2

    changed_selection = dict(common)
    changed_selection["selection_sha256"] = "f" * 64
    E.observe_claude_generation_backend(**changed_selection)
    assert len(calls) == 3

    changed_environment = dict(changed_selection)
    changed_environment["environment"] = {"PLAMEN_RUN_ID": "different"}
    E.observe_claude_generation_backend(**changed_environment)
    assert len(calls) == 4

    required_capability = dict(common)
    required_capability["required_capabilities"] = ("-p",)
    E.observe_claude_generation_backend(**required_capability)
    assert len(calls) == 5
    E.observe_claude_generation_backend(**required_capability)
    assert len(calls) == 5

    changed_timeout = dict(required_capability)
    changed_timeout["timeout_seconds"] = 119.0
    E.observe_claude_generation_backend(**changed_timeout)
    assert len(calls) == 6

    changed_member = dict(common)
    changed_member["selected_backend"] = copy.deepcopy(
        common["selected_backend"]
    )
    authentication = changed_member["selected_backend"][
        "member_authority"
    ]["authentication"]
    authentication["signature"] = (
        ("0" if authentication["signature"][0] != "0" else "1")
        + authentication["signature"][1:]
    )
    E.observe_claude_generation_backend(**changed_member)
    assert len(calls) == 7


def test_generation_backend_observation_single_flights_concurrent_preparations(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    front = tmp_path / ("plamen.cmd" if os.name == "nt" else "plamen")
    front.write_bytes(b"authenticated installed front\n")
    selection = _selection()
    old = D._DIRECT_CLAUDE_MCP_SELECTION
    D._DIRECT_CLAUDE_MCP_SELECTION = selection
    try:
        generated = D._selected_claude_backend_argv_prefix()
    finally:
        D._DIRECT_CLAUDE_MCP_SELECTION = old
    prefix = (str(front.resolve()), *generated[1:])
    calls: list[list[str]] = []
    barrier = threading.Barrier(8)

    def run_owned(argv, **_kwargs):
        calls.append(list(argv))
        time.sleep(0.05)
        return type(
            "Owned",
            (),
            {
                "returncode": 0,
                "stdout": "2.1.252 (Claude Code)\n",
                "stderr": "",
                "process_tree_terminated": True,
            },
        )()

    monkeypatch.setattr(E, "_GENERATION_OBSERVATION_CACHE", None)
    monkeypatch.setattr(E, "run_owned_process", run_owned)
    kwargs = {
        "installed_front": str(front.resolve()),
        "backend_argv_prefix": prefix,
        "selection_sha256": L.mcp_current_selection_sha256(selection),
        "selected_backend": selection["backend_launches"]["claude"],
        "environment": {},
    }

    def observe(_number: int):
        barrier.wait(timeout=5)
        return E.observe_claude_generation_backend(**kwargs)

    with ThreadPoolExecutor(max_workers=8) as pool:
        observations = list(pool.map(observe, range(8)))

    assert len(calls) == 1
    assert calls[0] == [*prefix, "--version"]
    assert all(value == observations[0] for value in observations)
    assert len({id(value) for value in observations}) == 8


def test_cached_observation_cannot_bypass_public_front_selection_revalidation(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real public route rejects stale selection before member creation."""

    front = tmp_path / ("plamen.cmd" if os.name == "nt" else "plamen")
    front.write_bytes(b"authenticated installed front\n")
    selection = _selection()
    old = D._DIRECT_CLAUDE_MCP_SELECTION
    D._DIRECT_CLAUDE_MCP_SELECTION = selection
    try:
        generated = D._selected_claude_backend_argv_prefix()
    finally:
        D._DIRECT_CLAUDE_MCP_SELECTION = old
    prefix = (str(front.resolve()), *generated[1:])
    probe_calls: list[list[str]] = []

    def run_owned(argv, **_kwargs):
        probe_calls.append(list(argv))
        return type(
            "Owned",
            (),
            {
                "returncode": 0,
                "stdout": "2.1.252 (Claude Code)\n",
                "stderr": "",
                "process_tree_terminated": True,
            },
        )()

    monkeypatch.setattr(E, "_GENERATION_OBSERVATION_CACHE", None)
    monkeypatch.setattr(E, "run_owned_process", run_owned)
    kwargs = {
        "installed_front": str(front.resolve()),
        "backend_argv_prefix": prefix,
        "selection_sha256": L.mcp_current_selection_sha256(selection),
        "selected_backend": selection["backend_launches"]["claude"],
        "environment": {},
    }
    E.observe_claude_generation_backend(**kwargs)
    E.observe_claude_generation_backend(**kwargs)
    assert len(probe_calls) == 1, "precondition: second observation is cached"

    # Execute the real source function in a dependency-injected namespace. A
    # stale-current-selection failure must occur before committed-install
    # replay, runtime loading, or generation-member Popen can be reached.
    source_path = Path(D.__file__).resolve().parent.parent / "plamen.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))
    route_node = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_backend_public_route"
    )
    ast.fix_missing_locations(route_node)
    reached: list[str] = []

    def stale_selection(**_kwargs):
        raise RuntimeError("stale current selection")

    namespace = {
        "_validated_mcp_current_selection": stale_selection,
        "_backend_launcher_args": lambda *_args, **_kwargs: reached.append(
            "launcher-args"
        ),
        "_validated_committed_install_receipt": lambda: reached.append(
            "committed-install"
        ),
        "_mcp_runtime_module": lambda *_args: reached.append("runtime"),
        "_mcp_receipt_callbacks": lambda *_args: reached.append("callbacks"),
        "os": os,
    }
    exec(
        compile(
            ast.Module(body=[route_node], type_ignores=[]),
            str(source_path),
            "exec",
        ),
        namespace,
    )
    with pytest.raises(RuntimeError, match="stale current selection"):
        namespace["_backend_public_route"]([*prefix[1:], "--version"])
    assert reached == []

    backend_branch = source[
        source.index('        if arg == "backend-launch":'):
        source.index('        if arg == "--codex-install-census-child":')
    ]
    assert "raise SystemExit(_backend_public_route(sys.argv[1:]))" in backend_branch
    assert "raise SystemExit(75)" in backend_branch


def test_generation_backend_probe_timeout_bounds_fail_closed(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    front = tmp_path / ("plamen.cmd" if os.name == "nt" else "plamen")
    front.write_bytes(b"authenticated installed front\n")
    selection = _selection()
    old = D._DIRECT_CLAUDE_MCP_SELECTION
    D._DIRECT_CLAUDE_MCP_SELECTION = selection
    try:
        generated = D._selected_claude_backend_argv_prefix()
    finally:
        D._DIRECT_CLAUDE_MCP_SELECTION = old
    prefix = (str(front.resolve()), *generated[1:])
    calls = []
    monkeypatch.setattr(
        E,
        "run_owned_process",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    for invalid in (float("nan"), float("inf"), -float("inf"), 0, -1, 120.001):
        with pytest.raises(E.ClaudeExecutableObservationError):
            E.observe_claude_generation_backend(
                installed_front=str(front.resolve()),
                backend_argv_prefix=prefix,
                selection_sha256=L.mcp_current_selection_sha256(selection),
                selected_backend=selection["backend_launches"]["claude"],
                environment={},
                timeout_seconds=invalid,
            )
    assert calls == []

    def timed_out(argv, **kwargs):
        calls.append((list(argv), kwargs))
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(E, "run_owned_process", timed_out)
    with pytest.raises(E.ClaudeExecutableObservationError, match="TimeoutExpired"):
        E.observe_claude_generation_backend(
            installed_front=str(front.resolve()),
            backend_argv_prefix=prefix,
            selection_sha256=L.mcp_current_selection_sha256(selection),
            selected_backend=selection["backend_launches"]["claude"],
            environment={},
            timeout_seconds=120.0,
        )
    assert len(calls) == 1
    assert calls[0][0] == [*prefix, "--version"]
    assert calls[0][1]["timeout"] == 120.0


def test_materialization_accepts_only_exact_backend_launch_prefix() -> None:
    selection = _selection()
    old = D._DIRECT_CLAUDE_MCP_SELECTION
    D._DIRECT_CLAUDE_MCP_SELECTION = selection
    try:
        prefix = list(D._selected_claude_backend_argv_prefix())
    finally:
        D._DIRECT_CLAUDE_MCP_SELECTION = old
    observation = {
        "resolved_executable": prefix[0],
        "backend_launch_authority": {
            "argv_prefix": prefix,
            "selection_sha256": L.mcp_current_selection_sha256(selection),
            "selected_backend": selection["backend_launches"]["claude"],
        },
    }
    session = "00000000-0000-4000-8000-000000000001"
    suffix = [
        "-p",
        "--model",
        "claude-sonnet-5",
        "--output-format",
        "stream-json",
        "--verbose",
        "--session-id",
        session,
        "--no-session-persistence",
    ]
    policy = {
        "mcp_authority": {"runtime_selection": selection},
        "headless_profile": {
            "expected_init_contract": {
                "accepted_models": ["claude-sonnet-5"]
            },
            "cli_flags": ["--safe-mode"],
        },
    }
    compiled = M._compile_final_argv(
        [*prefix, *suffix],
        request={"executable_observation": observation},
        policy=policy,
    )
    assert compiled == tuple([*prefix, *suffix, "--safe-mode"])

    direct_native = selection["backend_launches"]["claude"]["relative_path"]
    with pytest.raises(M.ClaudeRuntimeMaterializationError) as denied:
        M._compile_final_argv(
            [direct_native, *suffix],
            request={"executable_observation": observation},
            policy=policy,
        )
    assert denied.value.reason_code == "BASE_ARGV_BACKEND_AUTHORITY_MISMATCH"
