"""Supply-chain and production-launch regressions for npm MCP servers."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tomllib

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    old_argv = sys.argv
    sys.argv = [str(path)]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = old_argv
    return module


INSTALLER = _load(ROOT / "plamen.py", "plamen_mcp_locked_test")
ADAPTER = _load(ROOT / "scripts" / "codex_adapter.py", "codex_adapter_mcp_test")
UPDATE_CONFIG = _load(ROOT / "mcp-packages" / "update_config.py", "mcp_update_config_test")


def test_checked_in_mcp_lock_is_complete_exact_and_integrity_bound() -> None:
    valid, result = INSTALLER._validate_mcp_lock(
        str(ROOT / "mcp-packages" / "package.json"),
        str(ROOT / "mcp-packages" / "package-lock.json"),
    )
    assert valid, result
    assert len(result) == 64
    package = json.loads(
        (ROOT / "mcp-packages" / "package.json").read_text(encoding="utf-8")
    )
    lock = json.loads(
        (ROOT / "mcp-packages" / "package-lock.json").read_text(encoding="utf-8")
    )
    assert package["dependencies"]["@anthropic-ai/claude-code"] == "2.1.252"
    assert package["dependencies"]["@openai/codex"] == "0.152.0"
    assert lock["packages"]["node_modules/@anthropic-ai/claude-code"]["integrity"] == (
        "sha512-ftoO0eLOZyEDrA3KDd7QZH5qdvToiTcoip3YdGGx8wzH4R9YUwHO+5V"
        "G01JDRn8u7MrRcXkf7FvbMYezEt0VyQ=="
    )
    assert lock["packages"]["node_modules/@openai/codex"]["integrity"] == (
        "sha512-Vx0tg/J5SbxYYGJazTtL/XySK9Dlqc5KW1MZM71NMwVci/4F1ap+FfSKPFTl"
        "rICEtOTuq3KNcWSdv9oMGdPuRw=="
    )


def test_backend_public_route_uses_exact_native_fast_admission(monkeypatch) -> None:
    digest = "a" * 64
    selection = {
        "store_root": "C:/isolated-store",
        "generation_id": "npm-" + "b" * 64,
        "receipt_sha256": "c" * 64,
        "census_sha256": "d" * 64,
        "request_sha256": "e" * 64,
        "generation_policy_sha256": "f" * 64,
        "backend_launches": {
            "claude": {
                "execution_kind": "native",
                "relative_path": "node_modules/@anthropic-ai/claude-code/bin/claude.exe",
                "version": "2.1.252", "size": 7, "sha256": digest,
                "member_authority": {"signed": "claude"},
            },
            "codex": {
                "execution_kind": "native",
                "relative_path": (
                    "node_modules/@openai/codex-win32-x64/vendor/"
                    "x86_64-pc-windows-msvc/bin/codex.exe"
                ),
                "version": "0.152.0", "size": 11, "sha256": "1" * 64,
                "member_authority": {"signed": "codex"},
            },
        },
    }
    calls = []

    class Process:
        def wait(self):
            return 0

    runtime = SimpleNamespace(
        launch_generation_member=lambda *args, **kwargs: calls.append(
            (args, kwargs)
        ) or Process(),
    )
    selected = []
    monkeypatch.setattr(
        INSTALLER, "_validated_mcp_current_selection",
        lambda **kwargs: selected.append(kwargs) or selection,
    )
    monkeypatch.setattr(INSTALLER, "_validated_committed_install_receipt", lambda: {
        "plamen_root": str(ROOT),
    })
    monkeypatch.setattr(INSTALLER, "_mcp_runtime_module", lambda _root: runtime)
    monkeypatch.setattr(
        INSTALLER, "_mcp_receipt_callbacks",
        lambda _receipt: (None, lambda *_args: True, "", ""),
    )
    argv = [*INSTALLER._backend_launcher_args(selection, backend="claude"), "--version"]
    assert INSTALLER._backend_public_route(argv) == 0
    assert selected == [{
        "backend": "claude", "full_generation": False,
        "verify_generation_receipt": False,
    }]
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[2] == selection["backend_launches"]["claude"]["relative_path"]
    assert kwargs["execution_kind"] == "native"
    assert kwargs["node_executable"] is None
    assert kwargs["full_census"] is False
    assert kwargs["expected_generation_policy_sha256"] == (
        selection["generation_policy_sha256"]
    )
    assert kwargs["member_args"] == ["--version"]
    assert kwargs["authenticated_member_authority"] == {"signed": "claude"}


@pytest.mark.parametrize(
    "codex_mutation",
    (None, "missing_resource", "case_alias", "extra", "hardlink"),
)
@pytest.mark.parametrize(
    "platform_name,architecture,target",
    (
        ("darwin", "arm64", "aarch64-apple-darwin"),
        ("darwin", "x64", "x86_64-apple-darwin"),
        ("linux", "arm64", "aarch64-unknown-linux-musl"),
        ("linux", "x64", "x86_64-unknown-linux-musl"),
        ("win32", "arm64", "aarch64-pc-windows-msvc"),
        ("win32", "x64", "x86_64-pc-windows-msvc"),
    ),
)
def test_backend_selection_requires_exact_codex_native_resource_closure(
    tmp_path: Path, codex_mutation: str | None, platform_name: str,
    architecture: str, target: str,
) -> None:
    claude = "node_modules/@anthropic-ai/claude-code/bin/claude.exe"
    claude_package = "node_modules/@anthropic-ai/claude-code/package.json"
    codex_root = (
        f"node_modules/@openai/codex-{platform_name}-{architecture}/vendor/{target}"
    )
    suffix = ".exe" if platform_name == "win32" else ""
    codex = codex_root + "/bin/codex" + suffix
    codex_package = "node_modules/@openai/codex/package.json"
    for relative, version in (
        (claude_package, "2.1.252"), (codex_package, "0.152.0"),
    ):
        package_path = tmp_path.joinpath(*relative.split("/"))
        package_path.parent.mkdir(parents=True, exist_ok=True)
        package_path.write_text(json.dumps({"version": version}), encoding="utf-8")

    manifest_path = tmp_path.joinpath(*(codex_root + "/codex-package.json").split("/"))
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps({
        "layoutVersion": 1, "version": "0.152.0",
        "target": target, "variant": "codex",
        "entrypoint": "bin/codex" + suffix, "resourcesDir": "codex-resources",
        "pathDir": "codex-path",
    }), encoding="utf-8")

    claude_roster = {claude.rsplit("/", 1)[0], claude}
    codex_roster = {
        codex_root, codex_root + "/bin", codex_root + "/codex-path",
        codex_root + "/codex-resources", codex_root + "/codex-package.json",
        codex, codex_root + "/bin/codex-code-mode-host" + suffix,
        codex_root + "/codex-path/rg" + suffix,
    }
    if platform_name == "win32":
        codex_roster.update({
            codex_root + "/codex-resources/codex-command-runner.exe",
            codex_root + "/codex-resources/codex-windows-sandbox-setup.exe",
        })
        resource = codex_root + "/codex-resources/codex-command-runner.exe"
    else:
        codex_roster.update({
            codex_root + "/codex-resources/zsh",
            codex_root + "/codex-resources/zsh/bin",
            codex_root + "/codex-resources/zsh/bin/zsh",
        })
        if platform_name == "linux":
            codex_roster.add(codex_root + "/codex-resources/bwrap")
            resource = codex_root + "/codex-resources/bwrap"
        else:
            resource = codex_root + "/codex-resources/zsh/bin/zsh"
    directories = {
        relative for relative in claude_roster | codex_roster
        if any(other.startswith(relative + "/") for other in claude_roster | codex_roster)
    }

    def row(
        relative: str, *, links: int = 1, kind: str | None = None,
    ) -> dict[str, object]:
        kind = kind or ("directory" if relative in directories else "file")
        return {
            "path": relative, "kind": kind, "reparse": False,
            "link_count": links, "size": 1, "sha256": "a" * 64,
            "mode": 0o644,
        }

    entries = [
        *(row(relative) for relative in sorted(claude_roster | codex_roster)),
        row(claude_package), row(codex_package),
    ]
    if codex_mutation == "missing_resource":
        entries = [item for item in entries if item["path"] != resource]
    elif codex_mutation == "case_alias":
        next(item for item in entries if item["path"] == resource)["path"] = (
            resource.rsplit("/", 1)[0] + "/" + resource.rsplit("/", 1)[1].upper()
        )
    elif codex_mutation == "extra":
        entries.append(row(codex_root + "/codex-resources/unselected-helper.exe"))
    elif codex_mutation == "hardlink":
        next(item for item in entries if item["path"] == resource)["link_count"] = 2

    calls = []
    runtime = SimpleNamespace(
        native_resource_roster=lambda relative: tuple(sorted(
            claude_roster if relative == claude else codex_roster
        )),
        sign_generation_member_authority=lambda validated, relative, **kwargs: (
            calls.append((validated, relative, kwargs)) or {"signed": relative}
        ),
    )
    validated = SimpleNamespace(entries=tuple(entries), payload_path=tmp_path)
    if codex_mutation is not None:
        with pytest.raises(RuntimeError, match="native-resource denominator"):
            INSTALLER._mcp_backend_launches(
                validated, runtime=runtime, signer=lambda _raw: {},
                generation_policy_sha256="b" * 64,
            )
        return
    launches = INSTALLER._mcp_backend_launches(
        validated, runtime=runtime, signer=lambda _raw: {},
        generation_policy_sha256="b" * 64,
    )
    assert set(launches) == {"claude", "codex"}
    assert [relative for _validated, relative, _kwargs in calls] == [claude, codex]
    assert launches["claude"]["member_authority"] == {"signed": claude}
    assert launches["codex"]["member_authority"] == {"signed": codex}


def test_lock_validator_rejects_ranges_and_missing_integrity(tmp_path: Path) -> None:
    package = {"dependencies": {"safe-package": "^1.0.0"}}
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": package["dependencies"]},
            "node_modules/safe-package": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/safe-package/-/safe-package-1.0.0.tgz",
            },
        },
    }
    package_path = tmp_path / "package.json"
    lock_path = tmp_path / "package-lock.json"
    package_path.write_text(json.dumps(package), encoding="utf-8")
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    valid, result = INSTALLER._validate_mcp_lock(str(package_path), str(lock_path))
    assert not valid and "exactly version-pinned" in result

    package["dependencies"]["safe-package"] = "1.0.0"
    lock["packages"][""]["dependencies"] = package["dependencies"]
    package_path.write_text(json.dumps(package), encoding="utf-8")
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    valid, result = INSTALLER._validate_mcp_lock(str(package_path), str(lock_path))
    assert not valid and "sha512 integrity" in result


@pytest.mark.parametrize(
    "relative",
    (
        Path("@anthropic-ai/claude-code/bin/claude.exe.old.1"),
        Path("@anthropic-ai/claude-code-win32-x64/claude.exe.old.2"),
    ),
)
def test_claude_updater_debris_is_never_admitted(
    tmp_path: Path,
    relative: Path,
) -> None:
    node_modules = tmp_path / "node_modules"
    debris = node_modules / relative
    debris.parent.mkdir(parents=True)
    debris.write_bytes(b"old executable must not be trusted")
    assert INSTALLER._mcp_runtime_has_updater_debris(str(node_modules))


def test_locked_claude_entrypoint_is_detached_from_optional_package(
    tmp_path: Path,
) -> None:
    optional = tmp_path / "optional" / "claude.exe"
    entrypoint = tmp_path / "package" / "bin" / "claude.exe"
    optional.parent.mkdir(parents=True)
    entrypoint.parent.mkdir(parents=True)
    payload = b"MZ" + (b"reviewed-claude" * 4096)
    optional.write_bytes(payload)
    try:
        entrypoint.hardlink_to(optional)
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")
    before_optional = optional.stat(follow_symlinks=False)
    assert before_optional.st_nlink == 2

    assert INSTALLER._detach_locked_claude_cli(str(entrypoint))

    assert entrypoint.read_bytes() == payload
    assert optional.read_bytes() == payload
    assert entrypoint.stat(follow_symlinks=False).st_nlink == 1
    assert optional.stat(follow_symlinks=False).st_nlink == 1
    assert (
        entrypoint.stat(follow_symlinks=False).st_ino
        != optional.stat(follow_symlinks=False).st_ino
    )


def test_public_launcher_refuses_hardlinked_locked_claude(
    tmp_path: Path,
) -> None:
    plamen_root = tmp_path / ".plamen"
    entrypoint = (
        plamen_root / "mcp-packages" / "node_modules" / "@anthropic-ai"
        / "claude-code" / "bin" / "claude.exe"
    )
    sibling = entrypoint.with_name("claude-source.exe")
    sibling.parent.mkdir(parents=True)
    sibling.write_bytes(b"MZ" + (b"locked" * 1024))
    try:
        entrypoint.hardlink_to(sibling)
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")

    assert INSTALLER._locked_claude_cli(plamen_root) is None
    assert INSTALLER._detach_locked_claude_cli(str(entrypoint))
    # Fixed mutable node_modules is legacy diagnostic input only; backend
    # execution is admitted solely through the signed generation shim.
    assert INSTALLER._locked_claude_cli(plamen_root) is None


def _fake_manifests(root: Path) -> tuple[Path, dict[str, str]]:
    mcp_dir = root / "mcp-packages"
    mcp_dir.mkdir(parents=True)
    deps = {
        name: f"1.0.{index}"
        for index, name in enumerate(INSTALLER._MCP_NPM_ENTRYPOINTS)
    }
    deps["@anthropic-ai/claude-code"] = "2.1.252"
    deps["@openai/codex"] = "0.152.0"
    package = {"private": True, "dependencies": deps}
    packages = {"": {"dependencies": deps}}
    for name, version in deps.items():
        packages[f"node_modules/{name}"] = {
            "version": version,
            "resolved": f"https://registry.npmjs.org/fake/-/fake-{version}.tgz",
            "integrity": "sha512-" + ("A" * 88),
        }
    lock = {"lockfileVersion": 3, "packages": packages}
    (mcp_dir / "package.json").write_text(json.dumps(package), encoding="utf-8")
    (mcp_dir / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    (mcp_dir / "schema-sanitizer.js").write_text(
        "// reviewed fixture\n", encoding="utf-8"
    )
    return mcp_dir, deps


def _fake_selection() -> dict:
    names = json.loads((ROOT / "mcp.json.example").read_text(encoding="utf-8"))["mcpServers"]
    return {
        "generation_id": "npm-" + "1" * 64,
        "receipt_sha256": "2" * 64,
        "census_sha256": "3" * 64,
        "request_sha256": "4" * 64,
        "generation_policy_sha256": "5" * 64,
        "server_launches": {name: {} for name in names},
    }


@pytest.mark.parametrize("target", ["package", "lock"])
def test_duplicate_manifest_keys_fail_before_store_or_npm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str,
) -> None:
    mcp_dir, _dependencies = _fake_manifests(tmp_path)
    if target == "package":
        (mcp_dir / "package.json").write_text(
            '{"dependencies":{"x":"1.0.0","x":"1.0.0"}}', encoding="utf-8",
        )
    else:
        (mcp_dir / "package-lock.json").write_text(
            '{"lockfileVersion":3,"packages":{"":{"dependencies":{}},'
            '"node_modules/x":{"version":"1.0.0","version":"1.0.0"}}}',
            encoding="utf-8",
        )
    store = tmp_path / "external-store"
    monkeypatch.setattr(INSTALLER, "_mcp_generation_store_root", lambda: store)
    calls = []
    monkeypatch.setattr(INSTALLER.subprocess, "run", lambda *args, **kwargs: calls.append(args))
    assert not INSTALLER._setup_mcp_packages(
        lambda _message: None, mcp_root=tmp_path,
    )
    assert calls == [] and not store.exists()


def test_legacy_finalizer_refuses_ambient_node_and_npm_wrappers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mcp_dir, dependencies = _fake_manifests(tmp_path)
    (mcp_dir / "node_modules" / "@anthropic-ai" / "claude-code").mkdir(
        parents=True,
    )
    calls: list[tuple[list[str], Path]] = []
    monkeypatch.setattr(INSTALLER.shutil, "which", lambda name: "/tool/npm")

    def fake_run(command, *, cwd=None, **_kwargs):
        cwd = Path(cwd) if cwd else mcp_dir
        calls.append((list(command), cwd))
        if str(command[-1]).endswith("install.cjs"):
            binary = cwd / "bin" / "claude.exe"
            binary.write_bytes(b"MZ" + (b"\0" * 5000))
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        if command[-1] == "--version":
            return SimpleNamespace(
                returncode=0, stderr="", stdout="2.1.252 (Claude Code)\n"
            )
        node_modules = cwd / "node_modules"
        (node_modules / ".package-lock.json").parent.mkdir(parents=True, exist_ok=True)
        (node_modules / ".package-lock.json").write_text(
            json.dumps({"lockfileVersion": 3}), encoding="utf-8"
        )
        for name, version in dependencies.items():
            package_dir = node_modules.joinpath(*name.split("/"))
            package_dir.mkdir(parents=True)
            (package_dir / "package.json").write_text(
                json.dumps({"name": name, "version": version}), encoding="utf-8"
            )
            entry = package_dir / INSTALLER._MCP_NPM_ENTRYPOINTS[name]
            entry.parent.mkdir(parents=True, exist_ok=True)
            entry.write_text("// reviewed fixture\n", encoding="utf-8")
            if name == "@anthropic-ai/claude-code":
                (package_dir / "install.cjs").write_text(
                    "// reviewed allowlist fixture\n", encoding="utf-8"
                )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(INSTALLER.subprocess, "run", fake_run)
    clean_env = {"PATH": "/tool"}
    assert not INSTALLER._finalize_locked_claude_cli(
        str(mcp_dir / "node_modules"), "2.1.252", lambda _message: None,
        node_executable="/tool/node", env=clean_env,
    )
    assert calls == []
    with pytest.raises(RuntimeError, match="ambient npm materialization"):
        INSTALLER._setup_mcp_packages_legacy(
            lambda _message: None, mcp_root=tmp_path,
        )


def test_claude_merge_migrates_existing_npx_and_preserves_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claude = tmp_path / ".claude"
    claude.mkdir()
    target = claude / "mcp.json"
    target.write_text(json.dumps({"mcpServers": {
        "helius": {
            "command": "npx",
            "args": ["-y", "helius-mcp@1.3.0"],
            "env": {"HELIUS_API_KEY": "secret"},
        },
        "slither-analyzer": {
            "command": "C:/Users/old/AppData/Python/python.exe",
            "args": ["-m", "slither_mcp.server"],
            "env": {"KEEP": "yes"},
        },
    }}), encoding="utf-8")
    monkeypatch.setattr(INSTALLER, "PLAMEN_HOME", str(ROOT))
    monkeypatch.setattr(INSTALLER, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(INSTALLER, "_validated_mcp_current_selection", lambda **_kwargs: _fake_selection())
    monkeypatch.setattr(INSTALLER, "_mcp_public_command_path", lambda: Path("C:/Plamen/plamen.cmd"))
    INSTALLER._merge_mcp_json(lambda _message: None)
    helius = json.loads(target.read_text(encoding="utf-8"))["mcpServers"]["helius"]
    assert helius["command"] == "C:\\Plamen\\plamen.cmd"
    assert helius["args"][0:5] == ["mcp-launch", "--backend", "claude", "--server", "helius"]
    assert helius["env"] == {"HELIUS_API_KEY": "secret"}
    slither = json.loads(target.read_text(encoding="utf-8"))["mcpServers"][
        "slither-analyzer"
    ]
    assert slither["command"] == "C:\\Plamen\\plamen.cmd"
    assert slither["args"][0:5] == ["mcp-launch", "--backend", "claude", "--server", "slither-analyzer"]
    assert "cwd" not in slither
    assert slither["env"] == {"KEEP": "yes"}


def test_all_production_mcp_entries_require_authenticated_front_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    template = json.loads((ROOT / "mcp.json.example").read_text(encoding="utf-8"))
    npm_names = {"evm-chain-data", "foundry-suite", "tavily-search", "memory", "helius"}
    for name in npm_names:
        server = template["mcpServers"][name]
        assert server["command"] == "PLAMEN_AUTHENTICATED_FRONT"
        assert server["args"] == ["MATERIALIZED_DURING_INSTALL", name]
    assert "node_modules" not in json.dumps(template)


def test_checked_in_codex_config_template_is_valid_and_network_free() -> None:
    raw = (ROOT / "codex-adapter" / "config.toml.example").read_text(
        encoding="utf-8"
    )
    parsed = tomllib.loads(raw)
    assert parsed["agents"]["max_threads"] == 6
    assert "npx" not in raw.lower()
    assert "mcp_servers" not in parsed
    assert "YOUR_" not in raw


def test_codex_mcp_merge_is_transactional_owned_and_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "plamen"
    root.mkdir()
    (root / "mcp.json.example").write_text(
        (ROOT / "mcp.json.example").read_text(encoding="utf-8"), encoding="utf-8"
    )
    codex_home = tmp_path / ".codex"
    codex_home.mkdir()
    target = codex_home / "config.toml"
    target.write_text(
        'model = "user-model"\ncustom_key = "keep-me"\n\n'
        '[mcp_servers.user-owned]\ncommand = "C:/custom/server.exe"\nargs = []\n\n'
        '[mcp_servers.helius]\ncommand = "npx"\nargs = ["-y", "helius-mcp"]\n'
        '[mcp_servers.helius.env]\nHELIUS_API_KEY = "secret"\n\n'
        '# [mcp_servers.memory]\n# command = "npx"\n# args = ["-y", "memory"]\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(INSTALLER.shutil, "which", lambda name: "C:/Node/node.exe")
    monkeypatch.setattr(INSTALLER, "_validated_mcp_current_selection", lambda **_kwargs: _fake_selection())
    monkeypatch.setattr(INSTALLER, "_mcp_public_command_path", lambda: Path("C:/Plamen/plamen.cmd"))
    messages = []
    assert INSTALLER._merge_codex_mcp_toml(
        messages.append, codex_home=codex_home, plamen_root=root
    )
    first = target.read_text(encoding="utf-8")
    parsed = tomllib.loads(first)
    assert parsed["model"] == "user-model"
    assert parsed["custom_key"] == "keep-me"
    assert parsed["mcp_servers"]["user-owned"]["command"] == "C:/custom/server.exe"
    assert parsed["mcp_servers"]["helius"]["env"]["HELIUS_API_KEY"] == "secret"
    assert parsed["mcp_servers"]["helius"]["command"] == "C:/Plamen/plamen.cmd"
    assert "mcp-launch" in first and "node_modules" not in first
    assert "npx" not in first.lower()
    assert "@mcp-dockmaster" not in first
    assert first.count(INSTALLER._CODEX_MCP_START) == 1
    assert INSTALLER._merge_codex_mcp_toml(
        messages.append, codex_home=codex_home, plamen_root=root
    )
    assert target.read_text(encoding="utf-8") == first


def test_codex_mcp_merge_bootstraps_missing_config_from_public_template(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "plamen"
    adapter = root / "codex-adapter"
    adapter.mkdir(parents=True)
    (root / "mcp.json.example").write_text(
        (ROOT / "mcp.json.example").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (adapter / "config.toml.example").write_text(
        (ROOT / "codex-adapter" / "config.toml.example").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    codex_home = tmp_path / ".codex"
    codex_home.mkdir()
    monkeypatch.setattr(
        INSTALLER,
        "_validated_mcp_current_selection",
        lambda **_kwargs: _fake_selection(),
    )
    monkeypatch.setattr(
        INSTALLER,
        "_mcp_public_command_path",
        lambda: Path("C:/Plamen/plamen.cmd"),
    )

    assert INSTALLER._merge_codex_mcp_toml(
        lambda _message: None,
        codex_home=codex_home,
        plamen_root=root,
    )
    installed = tomllib.loads(
        (codex_home / "config.toml").read_text(encoding="utf-8")
    )
    assert installed["model"] == "gpt-5.6-terra"
    assert installed["agents"]["max_threads"] == 6
    assert installed["mcp_servers"]


def test_codex_mcp_merge_refuses_invalid_existing_config_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "plamen"
    root.mkdir()
    (root / "mcp.json.example").write_text(
        (ROOT / "mcp.json.example").read_text(encoding="utf-8"), encoding="utf-8"
    )
    codex_home = tmp_path / ".codex"
    codex_home.mkdir()
    target = codex_home / "config.toml"
    original = 'broken = "C:\\Users\\unterminated"\n'
    target.write_text(original, encoding="utf-8")
    monkeypatch.setattr(INSTALLER.shutil, "which", lambda name: "C:/Node/node.exe")
    assert not INSTALLER._merge_codex_mcp_toml(
        lambda _message: None, codex_home=codex_home, plamen_root=root
    )
    assert target.read_text(encoding="utf-8") == original


def test_receipt_includes_both_mcp_config_authorities() -> None:
    assert {"mcp.json.example", "codex-adapter/config.toml.example"}.issubset(
        INSTALLER._CODEX_INSTALL_MCP_FILES
    )
    assert INSTALLER._CODEX_INSTALL_SOURCE_COUNT == 764
    assert INSTALLER._CODEX_INSTALL_RUNTIME_COUNT == 733
    assert "scripts/plamen_mcp_runtime.py" in INSTALLER._CODEX_INSTALL_MCP_FILES


def test_claude_update_converges_owned_python_servers_on_managed_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claude = tmp_path / ".claude"
    claude.mkdir()
    target = claude / "mcp.json"
    target.write_text(json.dumps({"mcpServers": {
        "slither-analyzer": {
            "command": "C:/Users/old/AppData/Python/python.exe",
            "args": ["-m", "slither_mcp.server"],
            "env": {"KEEP": "yes"},
        },
        "user-owned": {"command": "custom", "args": []},
    }}), encoding="utf-8")
    front = tmp_path / "bin" / "plamen.cmd"
    front.parent.mkdir(); front.write_bytes(b"front")
    selection = _fake_selection()
    raw = (json.dumps(selection, sort_keys=True, separators=(",", ":")) + "\n").encode()
    monkeypatch.setattr(UPDATE_CONFIG, "MCP_JSON", target)
    monkeypatch.setattr(UPDATE_CONFIG, "PUBLIC_FRONT", front)
    monkeypatch.setattr(
        UPDATE_CONFIG.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=raw, stderr=b""),
    )
    assert UPDATE_CONFIG.main() == 0
    servers = json.loads(target.read_text(encoding="utf-8"))["mcpServers"]
    slither = servers["slither-analyzer"]
    assert slither["command"] == str(front)
    assert slither["args"][:5] == [
        "mcp-launch", "--backend", "claude", "--server", "slither-analyzer",
    ]
    assert slither["env"] == {"KEEP": "yes"}
    assert servers["user-owned"] == {"command": "custom", "args": []}
