"""Release-facing CLI safety and truthfulness regressions."""

import importlib.util
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_release_front", ROOT / "plamen.py"
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def test_public_parser_rejects_unknown_and_conflicting_options():
    front = _load_front()
    with pytest.raises(SystemExit) as unknown:
        front._parse_cli_opts(["project", "--typo"])
    assert unknown.value.code == 2
    with pytest.raises(SystemExit) as conflict:
        front._parse_cli_opts(["project", "--codex", "--claude"])
    assert conflict.value.code == 2


def test_public_parser_requires_explicit_fallback_authorization():
    front = _load_front()
    ordinary = front._parse_cli_opts(["project", "--codex"])
    authorized = front._parse_cli_opts(
        ["project", "--codex", "--allow-model-fallback"]
    )
    assert ordinary["allow_model_fallback"] is False
    assert authorized["allow_model_fallback"] is True


@pytest.mark.parametrize(
    "argv",
    (
        ["plamen.py", "install", "--help"],
        ["plamen.py", "install", "--codex", "-h"],
        ["plamen.py", "core", "--help"],
    ),
)
def test_nested_help_exits_before_mutating_command_dispatch(
    argv, monkeypatch, capsys
):
    front = _load_front()
    monkeypatch.setattr(front.sys, "argv", argv)
    with pytest.raises(SystemExit) as stopped:
        front._early_cli_discovery()
    assert stopped.value.code == 0
    assert "Usage:" in capsys.readouterr().out


def test_driver_display_survives_closed_output_pipes_and_commits_marker(
    tmp_path,
):
    """A vanished Codex/CI attachment must not kill the live audit."""
    marker = tmp_path / "phase_checkpoint_committed.txt"
    script = textwrap.dedent(
        """
        import sys
        import time
        from pathlib import Path
        import plamen_display as display

        display.install_detached_output_guards()
        print("READY", flush=True)
        time.sleep(0.4)
        display.print_phase_heartbeat("breadth", 1, status="worker complete")
        print("stdout after detach", flush=True)
        Path(sys.argv[1]).write_text("COMMITTED\\n", encoding="utf-8")
        """
    )
    env = dict(os.environ)
    env["PLAMEN_PLAIN_OUTPUT"] = "1"
    proc = subprocess.Popen(
        [sys.executable, "-c", script, str(marker)],
        cwd=ROOT / "scripts",
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None
    assert proc.stdout.readline().strip() == "READY"
    proc.stdout.close()
    proc.stderr.close()

    assert proc.wait(timeout=10) == 0
    assert marker.read_text(encoding="utf-8") == "COMMITTED\n"


def test_setup_refuses_non_tty_before_install_mutation(monkeypatch):
    front = _load_front()
    called = []

    class Stream:
        def isatty(self):
            return False

        def write(self, value):
            return len(value)

        def flush(self):
            pass

    monkeypatch.setattr(front.sys, "stdin", Stream())
    monkeypatch.setattr(front.sys, "stdout", Stream())
    monkeypatch.setattr(front, "run_install", lambda: called.append(True))
    assert front.run_setup() == 2
    assert called == []


def test_driver_result_never_calls_missing_report_success(tmp_path, capsys):
    front = _load_front()
    config = tmp_path / ".scratchpad" / "config.json"
    config.parent.mkdir()
    assert front._render_driver_result(0, str(config), str(tmp_path)) == 3
    assert "NO DELIVERABLE" in capsys.readouterr().out


def test_codex_model_alias_typo_fails_closed():
    sys.path.insert(0, str(ROOT / "scripts"))
    import plamen_types

    with pytest.raises(ValueError, match="unknown Codex model alias"):
        plamen_types._resolve_codex_model_alias("snonet")


def test_managed_backend_postcondition_censuses_once_and_binds_claude_projection(
    tmp_path, monkeypatch,
):
    front = _load_front()
    observed = []
    monkeypatch.setattr(
        front,
        "_validated_mcp_current_selection",
        lambda **policy: observed.append(policy) or {
            "backend_launches": {"claude": {}, "codex": {}},
        },
    )
    projection_checks = []
    monkeypatch.setattr(
        front, "_assert_claude_projection_current",
        lambda: projection_checks.append(True),
    )
    monkeypatch.setattr(
        front,
        "_locked_backend_cli",
        lambda backend, _root, *, selection: tmp_path / f"plamen-{backend}",
    )

    paths = front._validated_managed_backend_paths(tmp_path)
    assert observed == [{
        "backend": "codex", "full_generation": False,
        "verify_generation_receipt": True,
    }]
    assert projection_checks == [True]
    assert paths == {
        "claude": tmp_path / "plamen-claude",
        "codex": tmp_path / "plamen-codex",
    }


def test_managed_backend_postcondition_rejects_missing_exact_shim(
    tmp_path, monkeypatch,
):
    front = _load_front()
    monkeypatch.setattr(
        front,
        "_validated_mcp_current_selection",
        lambda *, backend, **_policy: {
            "backend_launches": {"claude": {}, "codex": {}},
        },
    )
    monkeypatch.setattr(front, "_assert_claude_projection_current", lambda: None)
    monkeypatch.setattr(front, "_locked_backend_cli", lambda *_a, **_k: None)
    with pytest.raises(RuntimeError, match="managed claude backend shim"):
        front._validated_managed_backend_paths(tmp_path)


def _write_version_shim(path: Path, output: str, *, returncode: int = 0) -> None:
    if os.name == "nt":
        path.write_bytes(
            (
                "@echo off\r\n"
                f"echo {output}\r\n"
                f"exit /b {returncode}\r\n"
            ).encode("ascii")
        )
    else:
        path.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' {output!r}\n"
            f"exit {returncode}\n",
            encoding="utf-8",
        )
        path.chmod(0o700)


def test_managed_backend_version_postcondition_executes_both_selected_members(
    tmp_path, monkeypatch,
):
    front = _load_front()
    authority = {"plamen_root": str(tmp_path), "paths": {}, "selection": {}}
    observed = []

    def direct(managed, backend, member_args, *, timeout):
        observed.append((managed, backend, member_args, timeout))
        return subprocess.CompletedProcess(
            ["selected-member"], 0,
            front._MANAGED_BACKEND_VERSION_OUTPUTS[backend], b"",
        )

    monkeypatch.setattr(front, "_run_authenticated_backend_member", direct)
    front._assert_managed_backend_version_postcondition(authority)
    assert [row[1:3] for row in observed] == [
        ("claude", ("--version",)), ("codex", ("--version",)),
    ]


@pytest.mark.parametrize(
    ("backend", "output", "returncode"),
    (
        ("claude", "2.1.251 (Claude Code)", 0),
        ("codex", "codex-cli 0.152.0", 7),
    ),
)
def test_managed_backend_version_postcondition_rejects_wrong_or_failed_shim(
    tmp_path, monkeypatch, backend, output, returncode,
):
    front = _load_front()
    authority = {"plamen_root": str(tmp_path), "paths": {}, "selection": {}}

    def direct(_managed, name, _member_args, *, timeout):
        del timeout
        observed = output.encode() + b"\n" if name == backend else (
            front._MANAGED_BACKEND_VERSION_OUTPUTS[name]
        )
        code = returncode if name == backend else 0
        return subprocess.CompletedProcess(["selected-member"], code, observed, b"")

    monkeypatch.setattr(front, "_run_authenticated_backend_member", direct)

    with pytest.raises(RuntimeError, match=f"managed {backend} backend"):
        front._assert_managed_backend_version_postcondition(authority)


def test_internal_launcher_bootstrap_rejects_absent_or_fabricated_reader(
    monkeypatch,
):
    front = _load_front()
    monkeypatch.setattr(front, "_CODEX_INSTALL_READER", None)
    monkeypatch.setattr(front, "_CODEX_INSTALL_ADMISSION", None)
    with pytest.raises(RuntimeError, match="capability is absent"):
        front._early_internal_launcher_receipt()

    monkeypatch.setattr(
        front, "_CODEX_INSTALL_READER", (object(), lambda: None, b"{}\n"),
    )
    monkeypatch.setattr(front, "_CODEX_INSTALL_READER_COMMAND_KIND", "FRONT_VERSION")
    monkeypatch.setattr(front, "_CODEX_INSTALL_ADMISSION", object())
    with pytest.raises(RuntimeError, match="capability is absent"):
        front._early_internal_launcher_receipt()

    # A caller can instantiate a separate manager, but its object is not in
    # the production replay closure and therefore cannot authorize anything.
    issue_fake, _replay_fake = front._codex_install_admission_capability_manager()
    fake_reader = (7, lambda: None, b"{}\n")
    fake_capability = issue_fake(
        reader=fake_reader,
        command_kind="FRONT_DOCTOR",
        installed_root=Path(front.__file__).parent,
        codex_home=Path(front.__file__).parent,
    )
    monkeypatch.setattr(front, "_CODEX_INSTALL_READER", fake_reader)
    monkeypatch.setattr(front, "_CODEX_INSTALL_READER_COMMAND_KIND", "FRONT_DOCTOR")
    monkeypatch.setattr(front, "_CODEX_INSTALL_ADMISSION", fake_capability)
    with pytest.raises(RuntimeError, match="capability is absent"):
        front._early_internal_launcher_receipt()


def test_internal_launcher_bootstrap_is_dependency_closed_before_callsite():
    source = (ROOT / "plamen.py").read_text(encoding="utf-8")
    helper = source.index("\ndef _early_internal_launcher_receipt(")
    bootstrap = source.index("\ndef _bootstrap(")
    call = source.index("\nif not _bootstrap():")
    late_receipt = source.index("\ndef _validated_committed_install_receipt(")
    plamen_home = source.index("\nPLAMEN_HOME = ")
    assert helper < bootstrap < call < plamen_home < late_receipt
    bootstrap_region = source[bootstrap:call]
    assert "_validated_committed_install_receipt" not in bootstrap_region
    assert "Path(PLAMEN_HOME)" not in bootstrap_region


def test_backend_shim_plan_uses_one_signed_fast_selection(tmp_path, monkeypatch):
    front = _load_front()
    selection = {
        "backend_launches": {"claude": {}, "codex": {}},
    }
    validations = []
    monkeypatch.setattr(
        front, "_validated_mcp_current_selection",
        lambda **kwargs: validations.append(kwargs) or selection,
    )
    monkeypatch.setattr(
        front, "_backend_shim_path",
        lambda backend: tmp_path / f"plamen-{backend}.cmd",
    )
    rendered = []

    def render(
        backend, _root, _interpreter=None, *, selection,
        suppress_bytecode=True,
    ):
        if suppress_bytecode:
            rendered.append((backend, selection))
        return (backend + "\n").encode()

    monkeypatch.setattr(front, "_backend_shim_bytes", render)
    plan = front._backend_cli_shim_plan(tmp_path)

    assert validations == [{"backend": "codex", "full_generation": False}]
    assert rendered == [("claude", selection), ("codex", selection)]
    assert set(plan) == {"claude", "codex"}


def test_doctor_source_has_no_ambient_node_npm_or_npx_requirement():
    front = _load_front()
    source = inspect.getsource(front.run_doctor)
    assert 'for tool in ("python", "git")' in source
    assert 'for tool in ("python", "git", "npx")' not in source
    assert "_validated_managed_backend_authority" in source


def test_failure_diagnosis_default_makes_no_provider_call(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / "scripts"))
    import plamen_display

    (tmp_path / "_stdio_recon.log").write_text("gate failed\n", encoding="utf-8")
    called = []
    monkeypatch.setattr(
        plamen_display.subprocess,
        "Popen",
        lambda *args, **kwargs: called.append(True),
    )
    plamen_display.print_failure_diagnosis(
        "recon",
        str(tmp_path),
        ["recon_summary.md"],
        {"pipeline": "sc", "mode": "core", "language": "evm"},
    )
    assert called == []
    assert (tmp_path / "_diagnosis_recon.md").is_file()


def test_installer_refuses_checkout_destination_overlap(tmp_path, monkeypatch):
    front = _load_front()
    source = tmp_path / "checkout"
    source.mkdir()
    monkeypatch.setattr(
        front, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(front, "_codex_install_source_rows", lambda *_a: [])
    with pytest.raises(RuntimeError, match="overlap"):
        front._install_codex_package_transaction(
            source_root=source,
            plamen_root=source / "runtime",
            codex_home=tmp_path / "codex",
        )


def test_linked_worktree_git_file_is_a_checkout(tmp_path):
    front = _load_front()
    (tmp_path / ".git").write_text(
        "gitdir: C:/repo/.git/worktrees/example\n", encoding="utf-8"
    )
    assert front._is_git_checkout(str(tmp_path)) is True


def test_manifest_writer_does_not_rewrite_source_checkout(tmp_path, monkeypatch):
    front = _load_front()
    source = tmp_path / "source"
    claude = tmp_path / "claude"
    codex = tmp_path / "codex"
    source.mkdir()
    claude.mkdir()
    codex.mkdir()
    original_expanduser = front.os.path.expanduser

    monkeypatch.setattr(front, "PLAMEN_HOME", str(source))
    monkeypatch.setattr(front, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        front.os.path,
        "expanduser",
        lambda value: str(codex)
        if value == "~/.codex"
        else original_expanduser(value),
    )
    monkeypatch.setattr(
        front, "_toolchain_runtime_bundle_sha256", lambda _root: "a" * 64
    )

    front._write_install_manifest()

    assert not (source / front._PLAMEN_MANIFEST).exists()
    assert (claude / front._PLAMEN_MANIFEST).is_file()
    assert (codex / front._PLAMEN_MANIFEST).is_file()


def test_empty_critical_editable_dependency_fails_install_postcondition(
    tmp_path, monkeypatch
):
    front = _load_front()
    (tmp_path / "custom-mcp" / "slither-mcp").mkdir(parents=True)
    monkeypatch.setattr(front, "PLAMEN_HOME", str(tmp_path))
    monkeypatch.setattr(front, "_installed_version", lambda: front.VERSION)
    monkeypatch.setattr(front, "_installed_runtime_bundle_sha256", lambda: "x")
    monkeypatch.setattr(front, "_toolchain_runtime_bundle_sha256", lambda _root: "x")
    monkeypatch.setattr(front, "_protobuf_runtime_is_current", lambda: True)

    assert front._setup_python_deps(lambda _text: None, force_refresh=True) is False


def test_codex_adapter_source_cache_is_backed_up_and_refreshed(tmp_path):
    front = _load_front()
    source = tmp_path / "source"
    runtime = tmp_path / "runtime"
    codex = tmp_path / "codex"
    relative = Path("codex-adapter/skills/plamen/plamen-wizard.md")
    source_file = source / relative
    runtime_file = runtime / relative
    source_file.parent.mkdir(parents=True)
    runtime_file.parent.mkdir(parents=True)
    source_file.write_bytes(b"new adapter\n")
    runtime_file.write_bytes(b"old adapter\n")
    digest = hashlib.sha256(source_file.read_bytes()).hexdigest()
    transaction_id = "1" * 32
    receipt = {
        "source_root": str(source),
        "plamen_root": str(runtime),
        "codex_root": str(codex),
        "transaction_id": transaction_id,
        "adapter_count": 1,
        "rows": [
            {
                "source_path": relative.as_posix(),
                "destination_root": "codex",
                "sha256": digest,
            }
        ],
    }

    assert front._sync_codex_adapter_source_cache(receipt) == 1
    assert runtime_file.read_bytes() == b"new adapter\n"
    transaction = codex / ".plamen-install-transactions" / transaction_id
    assert (transaction / "source-cache-backup" / relative).read_bytes() == b"old adapter\n"
    assert (transaction / "source-cache.json").is_file()
