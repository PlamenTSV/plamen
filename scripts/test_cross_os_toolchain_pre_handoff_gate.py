"""Pre-handoff red fixtures for cross-OS and external-tool integrity.

These tests intentionally specify unresolved portability and tool-result
authority requirements.  They are isolated from production code so the
implementation owner can make each fixture red -> green independently.
"""

from __future__ import annotations

import ast
import inspect
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

import audit_snapshot as SNAP
import mechanical_verify as MV
import plamen as INSTALLER
import pty_exec as PTY
import recon_prepass as RECON
import worker_execution_receipts as WER

_TEST_SEC3_IMAGE = (
    "ghcr.io/sec3-product/x-ray@sha256:" + ("1" * 64)
)


def _synthetic_advisory_provider(source_id: str) -> str:
    return json.dumps({
        "schema_version": "plamen.advisory_source.v1",
        "source_id": source_id,
        "provider": "synthetic-fixture",
        "content_sha256": "a" * 64,
        "as_of": "2026-07-25T00:00:00Z",
        "expires_at": "2026-07-26T00:00:00Z",
    }, sort_keys=True, separators=(",", ":"))


def test_macos_typed_worker_has_native_identity_and_containment_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """macOS must be a supported execution target, not generic unsupported POSIX."""

    monkeypatch.setattr(WER.os, "name", "posix")
    monkeypatch.setattr(WER.sys, "platform", "darwin")
    capability = WER.process_tree_termination_capability()
    assert capability["platform"] == "MACOS"
    assert capability["pre_execution_assignment"] is True

    source = inspect.getsource(WER._process_creation_identity)
    assert "darwin" in source.lower(), (
        "process identity falls through to Linux /proc on macOS"
    )


def test_posix_pty_spawn_does_not_use_preexec_fn_from_threaded_workers() -> None:
    """Python documents preexec_fn as unsafe in applications with threads."""

    source = inspect.getsource(PTY.ClaudePtySession.spawn)
    assert "preexec_fn" not in source


@pytest.mark.parametrize(
    "runner",
    [
        MV._run_test_for_finding,
        MV._prewarm_build,
        MV._prewarm_cargo_test_targets,
    ],
)
def test_mechanical_verification_uses_owned_tree_hardened_runner(runner) -> None:
    """Timeouts must terminate descendants and never drain inherited pipes."""

    source = inspect.getsource(runner)
    assert not (
        "subprocess.run" in source and "capture_output=True" in source
    ), f"{runner.__name__} still has the inherited-pipe timeout hang pattern"


@pytest.mark.parametrize("payload", [None, "{not valid sarif"])
def test_opengrep_absent_or_malformed_sarif_is_failure_not_clean_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: str | None,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    rules = tmp_path / "rules"
    source = project / "sources" / "m.move"
    (rules / "rules").mkdir(parents=True)
    source.parent.mkdir(parents=True)
    scratch.mkdir()
    source.write_text("module 0x1::m {}", encoding="utf-8")

    monkeypatch.setattr(RECON.shutil, "which", lambda name: f"/tool/{name}")
    monkeypatch.setattr(
        RECON,
        "_ensure_opengrep_rules",
        lambda: {"aptos-move-rules": rules},
    )
    monkeypatch.setattr(
        RECON,
        "_production_source_files",
        lambda _project, _exts: [source],
    )

    def fake_run(_cmd, _cwd, _timeout, **_kwargs):
        if payload is not None:
            (scratch / "opengrep_results.sarif").write_text(
                payload, encoding="utf-8"
            )
        return 0, ""

    monkeypatch.setattr(RECON, "_run_hardened", fake_run)
    status = RECON._run_opengrep_scan(scratch, project, "aptos")
    assert status.startswith("FAILED:"), status


@pytest.mark.parametrize("payload", [None, "{not valid sarif"])
def test_sec3_absent_or_malformed_sarif_is_failure_not_clean_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: str | None,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    source = project / "src" / "lib.rs"
    source.parent.mkdir(parents=True)
    scratch.mkdir()
    source.write_text("pub fn f() {}", encoding="utf-8")

    monkeypatch.setattr(RECON.shutil, "which", lambda name: f"/tool/{name}")
    monkeypatch.setattr(RECON, "_iter_files", lambda _project, _exts: [source])

    def fake_run(cmd, _cwd, _timeout):
        if cmd[:2] == ["docker", "run"] and payload is not None:
            output = scratch / ".sec3-output"
            output.mkdir(parents=True, exist_ok=True)
            (output / RECON._SEC3_SARIF_FILENAME).write_text(
                payload, encoding="utf-8"
            )
        return 0, ""

    monkeypatch.setattr(RECON, "_run_hardened", fake_run)
    status = RECON._run_sec3_xray(
        scratch, project, image_ref=_TEST_SEC3_IMAGE,
    )
    assert status.startswith("FAILED:"), status


def test_cargo_audit_unparseable_rc_zero_is_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n", encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text(
        "# synthetic\nversion = 3\n", encoding="utf-8"
    )
    monkeypatch.setattr(RECON.shutil, "which", lambda name: f"/tool/{name}")
    monkeypatch.setattr(
        RECON,
        "_resolve_advisory_source",
        lambda source_id: (
            tmp_path.parent / f"{tmp_path.name}-advisory",
            _synthetic_advisory_provider(source_id),
            "",
        ),
    )
    outcomes = iter([(0, "cargo-audit 0.test"), (0, "not-json")])
    monkeypatch.setattr(RECON, "_run_hardened", lambda *_args: next(outcomes))

    status, findings = RECON._cargo_audit_scan(tmp_path)
    assert status.startswith("FAILED:"), status
    assert findings == []


def test_govulncheck_unparseable_rc_zero_is_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "go.mod").write_text("module example.invalid/x\n", encoding="utf-8")
    monkeypatch.setattr(RECON.shutil, "which", lambda name: f"/tool/{name}")
    monkeypatch.setattr(
        RECON,
        "_resolve_advisory_source",
        lambda source_id: (
            tmp_path.parent / f"{tmp_path.name}-advisory",
            _synthetic_advisory_provider(source_id),
            "",
        ),
    )
    monkeypatch.setattr(
        RECON, "_run_hardened", lambda *_args: (0, "not-json")
    )

    status, findings = RECON._govulncheck_scan(tmp_path)
    assert status.startswith("FAILED:"), status
    assert findings == []


def test_sec3_image_is_immutable_digest_and_source_mount_is_read_only() -> None:
    # No mutable default is allowed. The governed capability config must
    # provide a digest, and only an immutable digest is accepted.
    assert RECON._resolve_sec3_image() is None
    assert RECON._resolve_sec3_image(_TEST_SEC3_IMAGE) == _TEST_SEC3_IMAGE
    assert RECON._resolve_sec3_image("ghcr.io/sec3-product/x-ray:latest") is None
    source = inspect.getsource(RECON._run_sec3_xray)
    assert ":/workspace:ro" in source
    assert ":/output:rw" in source


def test_opengrep_rules_are_prebound_not_cloned_during_audit() -> None:
    source = inspect.getsource(RECON._ensure_opengrep_rules)
    assert '"clone"' not in source
    assert "shutil.rmtree" not in source


def test_windows_scanner_installer_and_runtime_accept_the_same_binary() -> None:
    """Windows currently installs Semgrep while the runner resolves only OpenGrep."""

    installer_source = inspect.getsource(INSTALLER._opengrep_cmds)
    runner_source = inspect.getsource(RECON._run_opengrep_scan)
    if "semgrep" in installer_source:
        assert "semgrep" in runner_source


def _minimum_node_engine_from_lock(lock: dict) -> tuple[int, int, int]:
    minimum = (0, 0, 0)
    for package in lock.get("packages", {}).values():
        expression = str((package.get("engines") or {}).get("node") or "")
        for match in re.finditer(r">=\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", expression):
            version = tuple(int(part or 0) for part in match.groups())
            minimum = max(minimum, version)
    return minimum


def test_node_runtime_contract_covers_locked_dependency_floor() -> None:
    package = json.loads(
        (Path(INSTALLER.__file__).parent / "mcp-packages" / "package.json").read_text(
            encoding="utf-8"
        )
    )
    lock = json.loads(
        (Path(INSTALLER.__file__).parent / "mcp-packages" / "package-lock.json").read_text(
            encoding="utf-8"
        )
    )
    declared = str((package.get("engines") or {}).get("node") or "")
    match = re.search(r">=\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", declared)
    assert match is not None, "package.json has no machine-readable Node floor"
    declared_floor = tuple(int(part or 0) for part in match.groups())
    assert declared_floor >= _minimum_node_engine_from_lock(lock)


def _runtime_required_npm_flags() -> tuple[str, ...]:
    runtime_path = (
        Path(INSTALLER.__file__).resolve().parent
        / "scripts" / "plamen_mcp_runtime.py"
    )
    tree = ast.parse(runtime_path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name)
            and target.id == "REQUIRED_NPM_INSTALL_FLAGS"
            for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            assert isinstance(value, tuple)
            return value
    raise AssertionError("immutable MCP runtime omits required npm flags")


def test_mcp_packages_use_lockfile_exact_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    required = (
        "ci", "--ignore-scripts", "--no-audit", "--no-fund",
        "--no-bin-links",
    )
    assert _runtime_required_npm_flags() == required

    wrapper_source = inspect.getsource(INSTALLER._setup_mcp_packages)
    immutable_source = inspect.getsource(INSTALLER._setup_mcp_immutable_generation)
    runtime = INSTALLER._mcp_runtime_module(
        Path(INSTALLER.__file__).resolve().parent
    )
    assert runtime.MANAGED_NODE_VERSION == "24.20.0"
    assert runtime.MANAGED_NPM_VERSION == "11.19.0"
    npm_source = inspect.getsource(runtime.run_managed_npm_ci)
    node_source = inspect.getsource(runtime.run_managed_node)
    assert "_setup_mcp_immutable_generation" in wrapper_source
    assert "_setup_mcp_packages_legacy" not in wrapper_source
    assert "subprocess" not in wrapper_source
    assert "runtime.ensure_managed_node_runtime" in immutable_source
    assert "managed_node.node_path" in immutable_source
    assert "managed_node.npm_cli_path" in immutable_source
    assert "runtime.run_managed_npm_ci" in immutable_source
    assert "shutil.which" not in immutable_source
    assert "subprocess.run" not in immutable_source
    assert "runtime.REQUIRED_NPM_INSTALL_FLAGS" in immutable_source
    assert "npm_install_flags=runtime.REQUIRED_NPM_INSTALL_FLAGS" in immutable_source
    assert "runtime.validate_generation" in immutable_source
    assert "runtime.stage_npm_generation" in immutable_source
    assert "managed.npm_cli_path" in npm_source
    assert "*REQUIRED_NPM_INSTALL_FLAGS" in npm_source
    assert "run_managed_node(" in npm_source
    assert "command = [str(_display_path(current.node_path)), *arguments]" in node_source

    managed = SimpleNamespace(
        node_path=Path("/managed/node"),
        npm_cli_path=Path("/managed/lib/node_modules/npm/bin/npm-cli.js"),
    )
    direct_calls: list[dict[str, object]] = []

    def direct_node(selected, arguments, **kwargs):
        direct_calls.append({
            "selected": selected, "arguments": list(arguments), **kwargs,
        })
        return SimpleNamespace(returncode=0)

    verifier = lambda *_a: True
    environment = {"PATH": "/managed-only"}
    monkeypatch.setattr(runtime, "run_managed_node", direct_node)
    result = runtime.run_managed_npm_ci(
        managed, Path("/private/payload"), verifier=verifier,
        environment=environment, timeout=321,
    )
    assert result.returncode == 0
    assert len(direct_calls) == 1
    assert direct_calls[0]["selected"] is managed
    assert direct_calls[0]["arguments"] == [
        str(managed.npm_cli_path), *required,
    ]
    assert direct_calls[0]["verifier"] is verifier
    assert direct_calls[0]["cwd"] == Path("/private/payload")
    assert direct_calls[0]["environment"] is environment
    assert direct_calls[0]["timeout"] == 321
    assert direct_calls[0]["capture_output"] is True
    assert direct_calls[0]["text"] is True

    delegated: list[tuple[object, dict[str, object]]] = []

    def refuse_generation(writer, **kwargs):
        delegated.append((writer, kwargs))
        return False

    writer = lambda _message: None
    monkeypatch.setattr(
        INSTALLER, "_setup_mcp_immutable_generation", refuse_generation,
    )
    assert INSTALLER._setup_mcp_packages(
        writer, mcp_root="/committed/root", update_claude=True,
        allow_materialization=False,
    ) is False
    assert delegated == [(writer, {
        "mcp_root": "/committed/root", "allow_materialization": False,
    })]


def test_mcp_package_materialization_executes_npm_ci(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "plamen"
    mcp_dir = home / "mcp-packages"
    mcp_dir.mkdir(parents=True)
    dependency = "tavily-mcp"
    version = "1.0.0"
    (mcp_dir / "package.json").write_text(json.dumps({
        "private": True, "dependencies": {dependency: version}
    }), encoding="utf-8")
    (mcp_dir / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {dependency: version}},
            "node_modules/tavily-mcp": {
                "version": version,
                "resolved": "https://registry.npmjs.org/tavily-mcp/-/tavily-mcp-1.0.0.tgz",
                "integrity": "sha512-" + ("A" * 88),
            },
        },
    }), encoding="utf-8")
    (mcp_dir / "schema-sanitizer.js").write_text(
        "// reviewed fixture\n", encoding="utf-8"
    )
    store = tmp_path / "immutable-store"
    managed_root = tmp_path / "managed-node-runtime"
    node = managed_root / "bin" / "node"
    npm = managed_root / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"
    node.parent.mkdir(parents=True)
    npm.parent.mkdir(parents=True)
    node.write_bytes(b"fixture node")
    npm.write_bytes(b"fixture bundled npm cli")
    required = _runtime_required_npm_flags()
    generation_id = "npm-" + ("a" * 64)
    staged: list[dict[str, object]] = []
    managed_runtime = SimpleNamespace(
        node_path=node.absolute(), npm_cli_path=npm.absolute(),
        npm_version="11.19.0", generation_id="node-" + ("b" * 64),
    )
    managed_requests: list[dict[str, object]] = []
    npm_ci_calls: list[dict[str, object]] = []

    class Runtime:
        REQUIRED_NPM_INSTALL_FLAGS = required

        @staticmethod
        def ensure_managed_node_runtime(
            selected_store, *, signer, verifier, allow_download,
        ):
            managed_requests.append({
                "store": Path(selected_store), "signer": signer,
                "verifier": verifier, "allow_download": allow_download,
            })
            return managed_runtime

        @staticmethod
        def materialization_environment(
            node_path, npm_path, materialization_root, *, source_env,
        ):
            assert node_path == str(node.absolute())
            assert npm_path == str(npm.absolute())
            assert Path(materialization_root).is_absolute()
            assert source_env is INSTALLER.os.environ
            return {"PATH": str(tmp_path), "PLAMEN_MATERIALIZATION": "1"}

        @staticmethod
        def _canonical_json(value):
            return json.dumps(
                value, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")

        @staticmethod
        def derive_generation_request(**kwargs):
            assert kwargs["npm_install_flags"] == required
            assert kwargs["finalizer_policy"] == {
                "schema": "plamen.mcp_finalizer_policy.v1",
                "output_entrypoint": "schema-sanitizer.js",
                "require_ordinary_file": True,
                "require_single_link": True,
                "post_npm_actions": [{
                    "schema": "plamen.claude_native_finalizer.v1",
                    "package": "@anthropic-ai/claude-code",
                    "version": "2.1.252",
                    "script": "node_modules/@anthropic-ai/claude-code/install.cjs",
                    "output": "node_modules/@anthropic-ai/claude-code/bin/claude.exe",
                    "probe_args": ["--version"],
                }],
            }
            return SimpleNamespace(generation_id=generation_id)

        @staticmethod
        def validate_generation(*_args, **_kwargs):
            raise FileNotFoundError("generation is not yet materialized")

        @staticmethod
        def run_managed_npm_ci(
            selected, payload, *, verifier, environment, timeout,
        ):
            assert selected is managed_runtime
            npm_ci_calls.append({
                "selected": selected, "payload": Path(payload),
                "verifier": verifier, "environment": dict(environment),
                "timeout": timeout,
                "command": [str(selected.node_path), str(selected.npm_cli_path), *required],
            })
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        @staticmethod
        def stage_npm_generation(
            selected_store, selected_generation, materializer, **kwargs,
        ):
            assert Path(selected_store) == store
            assert selected_generation == generation_id
            assert kwargs["npm_install_flags"] == required
            assert kwargs["generation_request"].generation_id == generation_id
            payload = tmp_path / "private-staging-payload"
            payload.mkdir()
            materializer(payload)
            staged.append({"payload": payload, "kwargs": kwargs})
            # Never pretend that a partial fixture is a published generation.
            # The installer must fail closed when the signed staging primitive
            # does not return a fully validated immutable generation.
            raise RuntimeError("synthetic signed staging refusal")

    monkeypatch.setattr(INSTALLER, "_validate_mcp_lock", lambda *_a: (True, "ok"))
    monkeypatch.setattr(
        INSTALLER, "_validated_committed_install_receipt",
        lambda: {"plamen_root": str(home.absolute())},
    )
    monkeypatch.setattr(INSTALLER, "_mcp_runtime_module", lambda *_a: Runtime)
    monkeypatch.setattr(
        INSTALLER, "_mcp_receipt_callbacks",
        lambda *_a: (lambda _raw: {}, lambda *_a: True, "1" * 64, "2" * 64),
    )
    monkeypatch.setattr(INSTALLER, "_mcp_generation_store_root", lambda: store)
    monkeypatch.setattr(
        INSTALLER, "_managed_node_store_root", lambda: managed_root,
    )
    monkeypatch.setattr(
        INSTALLER.shutil, "which",
        lambda name: (_ for _ in ()).throw(
            AssertionError("ambient/PATH executable lookup is forbidden: " + name)
        ),
    )
    monkeypatch.setattr(
        INSTALLER, "_publish_mcp_selection",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("unvalidated generation reached selection publication")
        ),
    )
    monkeypatch.setattr(
        INSTALLER.subprocess, "run",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("managed npm must not use ambient subprocess.run")
        ),
    )
    messages: list[str] = []
    assert INSTALLER._setup_mcp_packages(
        messages.append, mcp_root=str(home), update_claude=False,
        allow_materialization=True,
    ) is False
    assert len(managed_requests) == 1
    assert managed_requests[0]["store"] == managed_root
    assert managed_requests[0]["allow_download"] is True
    assert len(npm_ci_calls) == 1, messages
    assert npm_ci_calls[0]["command"] == [str(node), str(npm), *required]
    assert npm_ci_calls[0]["payload"] == tmp_path / "private-staging-payload"
    assert npm_ci_calls[0]["environment"] == {
        "PATH": str(tmp_path), "PLAMEN_MATERIALIZATION": "1",
    }
    assert npm_ci_calls[0]["timeout"] == 600
    assert len(staged) == 1
    assert any("immutable MCP setup failed" in message for message in messages)

    before = (len(staged), len(npm_ci_calls))

    def unavailable_managed_runtime(*_args, **_kwargs):
        raise RuntimeError("managed Node authority unavailable")

    monkeypatch.setattr(
        Runtime, "ensure_managed_node_runtime", unavailable_managed_runtime,
    )
    denied_messages: list[str] = []
    assert INSTALLER._setup_mcp_packages(
        denied_messages.append, mcp_root=str(home), update_claude=False,
        allow_materialization=False,
    ) is False
    assert (len(staged), len(npm_ci_calls)) == before
    assert any(
        "managed Node authority unavailable" in message
        for message in denied_messages
    )


def test_snapshot_does_not_casefold_distinct_posix_scope_paths() -> None:
    source = inspect.getsource(SNAP._scope_file_targets)
    assert ".casefold()" not in source or 'os.name == "nt"' in source


def test_scope_target_identity_is_case_sensitive_only_on_posix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upper = Path("/repo/Token.sol")
    lower = Path("/repo/token.sol")
    monkeypatch.setattr(SNAP.os, "name", "posix")
    assert SNAP._scope_target_identity(upper) != SNAP._scope_target_identity(lower)
    monkeypatch.setattr(SNAP.os, "name", "nt")
    assert SNAP._scope_target_identity(upper) == SNAP._scope_target_identity(lower)


def test_runtime_snapshot_binds_mechanically_invoked_tools() -> None:
    required = {
        "node",
        "npm",
        "medusa",
        "solana",
        "anchor",
        "cargo-build-sbf",
        "trident",
        "cargo-scout-audit",
        "cargo-fuzz",
        "rust-analyzer",
        "scip-go",
        "opengrep",
        "docker",
        "govulncheck",
        "cargo-audit",
        "ast-grep",
    }
    missing = sorted(
        tool for tool in required
        if tool not in SNAP.RUNTIME_TOOL_COMMANDS
    )
    assert not missing, f"runtime snapshot omits audit-semantic tools: {missing}"


def test_runtime_snapshot_emits_one_fingerprint_per_mechanical_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        SNAP,
        "_runtime_tool_fingerprint",
        lambda command, **_kwargs: json.dumps({
            "command": list(command),
            "resolved_executable": "UNAVAILABLE",
            "version": "UNAVAILABLE",
        }).encode("utf-8"),
    )
    monkeypatch.setattr(
        SNAP,
        "_runtime_python_distribution_fingerprint",
        lambda name, **_kwargs: json.dumps({
            "distribution": name,
            "version": "UNAVAILABLE",
        }).encode("utf-8"),
    )
    monkeypatch.setattr(SNAP, "_installed_python_packages", lambda: b"[]")
    names = {
        name.removeprefix("@runtime/tool/")
        for name, _payload in SNAP._fixed_runtime_tool_entries()
        if name.startswith("@runtime/tool/")
    }
    assert {
        "node",
        "npm",
        "medusa",
        "solana",
        "anchor",
        "cargo-build-sbf",
        "trident",
        "cargo-scout-audit",
        "cargo-fuzz",
        "rust-analyzer",
        "scip-go",
        "opengrep",
        "semgrep",
        "docker",
        "govulncheck",
        "cargo-audit",
        "ast-grep",
    } <= names


def test_recon_build_status_does_not_retry_dependency_materialization_after_snapshot() -> None:
    """All dependency writes belong to the explicit pre-snapshot preparation step."""

    source = inspect.getsource(RECON._write_build_status)
    assert "_prepare_evm_build(" not in source
