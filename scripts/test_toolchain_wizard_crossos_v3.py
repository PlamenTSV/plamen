"""Cross-OS, fail-closed contracts for the V3 toolchain wizard."""

from __future__ import annotations

import io
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import plamen


@pytest.mark.parametrize("host", ("darwin", "linux", "win32"))
@pytest.mark.parametrize(
    "command, executable",
    (
        ("cargo install cargo-audit --version 0.22.2 --locked", "cargo"),
        ("go install example.invalid/tool@v1.2.3", "go"),
        ("rustup toolchain install nightly-2026-08-01", "rustup"),
    ),
)
def test_go_cargo_and_rustup_are_direct_one_shot_argv(
    monkeypatch, host, command, executable
):
    monkeypatch.setattr(plamen.sys, "platform", host)
    monkeypatch.setattr(
        plamen, "_find_bin", lambda name, _paths=None: f"/managed/{name}"
    )
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=9)

    monkeypatch.setattr(plamen.subprocess, "run", run)
    monkeypatch.setattr(plamen.sys, "stdout", io.StringIO())

    assert plamen._run_install_cmd(command, retries=7) is False
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert isinstance(argv, list)
    assert argv[0] == f"/managed/{executable}"
    assert kwargs["shell"] is False


def test_dependency_check_does_not_require_node_or_ambient_python(monkeypatch):
    monkeypatch.setattr(plamen, "_dependency_backend_paths", lambda: {"codex": "/managed/codex"})
    monkeypatch.setattr(plamen.sys, "executable", __file__)
    monkeypatch.setattr(plamen, "_go_medusa_paths", lambda: [])
    monkeypatch.setattr(plamen, "_probe_rag_db", lambda: 0)
    monkeypatch.setattr(
        plamen,
        "_probe_mcp_servers",
        lambda: (_ for _ in ()).throw(AssertionError("ambient MCP probe")),
    )
    seen = []

    def find(name, _paths=None):
        seen.append(name)
        assert name not in {"npm", "npx", "python", "python3"}
        return f"/fixture/{name}"

    monkeypatch.setattr(plamen, "_find_bin", find)
    monkeypatch.setattr(plamen.sys, "stdout", io.StringIO())

    assert plamen.check_dependencies() is True
    assert "git" in seen


def test_installed_backend_authority_failure_never_falls_back_to_ambient(monkeypatch):
    monkeypatch.setattr(plamen, "_installed_runtime_root", lambda: Path("/installed"))
    monkeypatch.setattr(
        plamen,
        "_early_admitted_install_authority",
        lambda: (_ for _ in ()).throw(RuntimeError("receipt rejected")),
    )
    monkeypatch.setattr(
        plamen,
        "_find_claude_bin",
        lambda: (_ for _ in ()).throw(AssertionError("ambient fallback")),
    )
    monkeypatch.setattr(
        plamen,
        "_find_codex_bin",
        lambda: (_ for _ in ()).throw(AssertionError("ambient fallback")),
    )
    assert plamen._dependency_backend_paths() == {}


def test_installed_audit_menu_uses_current_managed_generation_only(monkeypatch):
    monkeypatch.setattr(plamen, "_installed_runtime_root", lambda: Path("/installed"))
    monkeypatch.setattr(
        plamen, "_dependency_backend_paths",
        lambda: {"claude": "/managed/current/claude", "codex": "/managed/current/codex"},
    )
    monkeypatch.setattr(
        plamen, "_detect_cli_backends",
        lambda: pytest.fail("installed audit menu must not inspect ambient CLIs"),
    )
    assert plamen._audit_cli_backends() == ["claude", "codex"]


def test_quick_check_does_not_require_node_tooling(monkeypatch):
    monkeypatch.setattr(plamen, "_dependency_backend_paths", lambda: {"codex": "/managed/codex"})
    monkeypatch.setattr(plamen.sys, "executable", __file__)
    seen = []

    def find(name, _paths=None):
        seen.append(name)
        assert name not in {"npm", "npx"}
        return "/fixture/git"

    monkeypatch.setattr(plamen, "_find_bin", find)
    assert plamen._quick_check_required() is True
    assert seen == ["git"]


def test_selectable_recipes_never_include_manual_or_medusa_actions(monkeypatch):
    monkeypatch.setattr(
        plamen,
        "_locked_toolchain_identity",
        lambda _identity: {
            "install_spec": "github.com/scip-code/scip-go/cmd/scip-go@v0.2.7"
        },
    )
    rows = [row for recipes in plamen._INSTALL_RECIPES.values() for row in recipes]
    assert rows
    assert all(row[2]() for row in rows)
    assert not any("medusa" in row[0].lower() for row in rows)
    assert not any(
        "medusa" in label.lower()
        for entries in plamen._UNSUPPORTED_TOOLCHAIN_RECIPES.values()
        for label, _reason in entries
    )
    assert any(
        "medusa v1.5.1" == label.lower()
        and "receipt-verified" in status.lower()
        and "ambient go installation is disabled" in status.lower()
        for label, status in plamen._BUNDLED_TOOLCHAIN_STATUS["EVM"]
    )


def test_ai_backends_are_not_setup_tool_version_pins():
    assert "claude" not in plamen._SETUP_PINNED_TOOL_VERSIONS
    assert "codex" not in plamen._SETUP_PINNED_TOOL_VERSIONS


def test_host_search_paths_do_not_publish_foreign_os_locations():
    paths = plamen._GO_PATHS + plamen._DAML_PATHS + plamen._STELLAR_PATHS
    if plamen.sys.platform == "win32":
        assert not any(path.startswith("/usr/") for path in paths)
        assert not any(path.startswith("/opt/") for path in paths)
    else:
        assert not any("AppData" in path for path in paths)
        assert not any(path.startswith("C:") for path in paths)
        assert not any(path.startswith("/c/Program Files") for path in paths)
    if plamen.sys.platform != "darwin":
        assert "/opt/homebrew/bin" not in plamen._AST_GREP_PATHS


def test_stellar_has_rust_prerequisite_on_every_host():
    stellar = next(
        row for row in plamen._INSTALL_RECIPES["Soroban"]
        if row[0] == "Stellar CLI"
    )
    assert stellar[6] == "rust"


def test_cargo_fuzz_requires_rustup_and_exact_nightly():
    rows = [
        row for recipes in plamen._INSTALL_RECIPES.values() for row in recipes
        if "cargo-fuzz" in row[0].lower()
    ]
    assert rows
    assert all(row[6] == ["rust", "rustup"] for row in rows)
    assert all(
        row[2]()[:1] == ["rustup toolchain install nightly-2026-08-01"]
        for row in rows
    )


def test_cargo_fuzz_nightly_probe_is_exact(monkeypatch):
    monkeypatch.setattr(plamen, "_find_bin", lambda *_args: "/fixture/rustup")
    monkeypatch.setattr(
        plamen.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="stable-aarch64-apple-darwin\nnightly-2026-08-01-aarch64-apple-darwin (default)\n",
        ),
    )
    assert plamen._cargo_fuzz_nightly_is_current() is True


@pytest.mark.parametrize(
    "output, expected, ok",
    (
        ("cargo-audit 0.22.2", "0.22.2", True),
        ("cargo-audit 0.22.20", "0.22.2", False),
        ("cargo-audit 0.22.1", "0.22.2", False),
    ),
)
def test_exact_version_probe_uses_token_boundaries(
    monkeypatch, output, expected, ok
):
    monkeypatch.setattr(plamen, "_find_bin", lambda *_args: "/fixture/tool")
    monkeypatch.setattr(
        plamen.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=output, stderr=""
        ),
    )
    observed, _message = plamen._probe_tool_runtime(
        "cargo-audit", [], expected_version=expected,
    )
    assert observed is ok


@pytest.mark.parametrize(
    "binary, output, expected",
    (
        ("ast-grep", "ast-grep 0.45.2", "0.45.2"),
        ("cargo-fuzz", "cargo-fuzz 0.13.2", "0.13.2"),
        ("govulncheck", "Go: go1.25.0\nScanner: govulncheck@v1.7.0", "1.7.0"),
        ("osv-scanner", "osv-scanner version: 2.5.1\nosv-scalibr version: 0.5.2", "2.5.1"),
        ("scip-go", "0.2.7", "0.2.7"),
        ("solana_fender", "solana_fender 0.5.4", "0.5.4"),
        ("stellar", "stellar 28.0.0 (build-id)", "28.0.0"),
    ),
)
def test_each_pinned_tool_uses_its_own_version_field(
    monkeypatch, binary, output, expected
):
    monkeypatch.setattr(plamen, "_find_bin", lambda *_args: "/fixture/tool")
    monkeypatch.setattr(
        plamen.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=output, stderr=""
        ),
    )
    assert plamen._probe_tool_runtime(
        binary, [], expected_version=expected
    ) == (True, "ok")


def test_expected_version_in_dependency_line_is_not_tool_authority(monkeypatch):
    monkeypatch.setattr(plamen, "_find_bin", lambda *_args: "/fixture/tool")
    monkeypatch.setattr(
        plamen.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=(
                "osv-scanner version: 9.9.9\n"
                "osv-scalibr version: 2.5.1\n"
            ),
            stderr="",
        ),
    )
    ok, message = plamen._probe_tool_runtime(
        "osv-scanner", [], expected_version="2.5.1"
    )
    assert ok is False
    assert "expected 2.5.1" in message
    assert "observed 9.9.9, 2.5.1" in message


def test_unrecognized_version_output_fails_with_clear_diagnostic(monkeypatch):
    monkeypatch.setattr(plamen, "_find_bin", lambda *_args: "/fixture/tool")
    monkeypatch.setattr(
        plamen.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout="healthy, trust me", stderr=""
        ),
    )
    assert plamen._probe_tool_runtime(
        "cargo-audit", [], expected_version="0.22.2"
    ) == (False, "version output is unrecognized (expected 0.22.2)")


def test_scout_version_comes_from_cargo_install_ledger(monkeypatch):
    monkeypatch.setattr(
        plamen,
        "_find_bin",
        lambda name, _paths=None: f"/fixture/{name}",
    )
    calls = []

    def run(argv, **_kwargs):
        calls.append(argv)
        return SimpleNamespace(
            returncode=0,
            stdout="cargo-scout-audit v0.3.16:\n    cargo-scout-audit\n",
            stderr="",
        )

    monkeypatch.setattr(plamen.subprocess, "run", run)
    assert plamen._probe_tool_runtime(
        "cargo-scout-audit", [], expected_version="0.3.16"
    ) == (True, "ok")
    assert calls == [["/fixture/cargo", "install", "--list"]]


def test_pinned_executable_receipt_detects_byte_tamper(tmp_path, monkeypatch):
    executable = tmp_path / "cargo-audit"
    executable.write_bytes(b"reviewed executable bytes")
    receipt_root = tmp_path / "receipts"
    monkeypatch.setattr(plamen, "_setup_tool_receipt_root", lambda: receipt_root)
    monkeypatch.setattr(plamen, "_find_bin", lambda *_args: str(executable))
    monkeypatch.setattr(
        plamen,
        "_probe_tool_runtime",
        lambda *_args, **_kwargs: (True, "ok"),
    )

    assert plamen._publish_setup_tool_receipt("cargo-audit", "0.22.2", [str(tmp_path)]) == (
        True,
        "receipt verified",
    )
    executable.write_bytes(b"tampered executable bytes")
    ok, message = plamen._validate_setup_tool_receipt(
        "cargo-audit", "0.22.2", [str(tmp_path)]
    )
    assert ok is False
    assert "identity differs" in message


def test_path_update_preserves_install_destination_precedence(
    tmp_path, monkeypatch
):
    go_bin = tmp_path / "custom-go-bin"
    fallback = tmp_path / "fallback-go-bin"
    unrelated = tmp_path / "custom-go-binary"
    for directory in (go_bin, fallback, unrelated):
        directory.mkdir()
    monkeypatch.setenv(
        "PATH", os.pathsep.join((str(unrelated), str(go_bin), str(fallback)))
    )

    plamen._update_path_env([str(go_bin), str(fallback)])

    entries = os.environ["PATH"].split(os.pathsep)
    assert entries[:2] == [str(go_bin), str(fallback)]
    assert entries.count(str(go_bin)) == 1
    assert entries.count(str(fallback)) == 1
    assert str(unrelated) in entries


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell configuration")
def test_posix_persist_quotes_shell_metacharacters(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    injected = tmp_path / "tools $(touch SHOULD_NOT_EXIST) ' quoted"

    plamen._persist_path_posix(str(injected))

    config = tmp_path / ".zshrc"
    rendered = config.read_text(encoding="utf-8")
    assert "# plamen-path-json:" in rendered
    assert subprocess.run(
        ["/bin/sh", "-n", str(config)], capture_output=True, text=True
    ).returncode == 0
    environment = dict(os.environ)
    environment["PATH"] = "/usr/bin:/bin"
    assert subprocess.run(
        ["/bin/sh", "-c", f'. "{config}"'],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
    ).returncode == 0
    assert not (tmp_path / "SHOULD_NOT_EXIST").exists()
