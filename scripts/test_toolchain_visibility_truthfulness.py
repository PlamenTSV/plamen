"""A binary census cannot certify installation or end-to-end readiness."""
import pytest

from test_cli_release_readiness import _load_front


def _report(monkeypatch, *, available, compatibility):
    front = _load_front()
    monkeypatch.setattr(front, "_go_medusa_paths", lambda: [])
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: compatibility)
    monkeypatch.setattr(
        front, "_find_bin",
        lambda name, paths: f"/fixture/{name}" if available(name) else None,
    )
    captured = []
    front._report_toolchain_visibility(captured.append)
    return "".join(captured)


def test_visible_binaries_do_not_claim_a_working_audit(monkeypatch):
    output = _report(monkeypatch, available=lambda name: True, compatibility=False)
    assert "All chain-tool binaries listed here are visible" in output
    assert "Presence check only" in output
    assert "readiness are not verified" in output
    assert "Every audit mode will run end-to-end" not in output


def test_foundry_requires_all_advertised_binaries(monkeypatch):
    output = _report(
        monkeypatch,
        available=lambda name: name not in {"cast", "cast.exe", "anvil", "anvil.exe"},
        compatibility=False,
    )
    assert "Foundry (forge/cast/anvil) — missing: cast, anvil" in output
    assert "All chain-tool binaries" not in output


def test_compatibility_report_does_not_direct_users_to_disabled_setup(monkeypatch):
    output = _report(monkeypatch, available=lambda name: False, compatibility=True)
    assert "Automated toolchain setup is unavailable" in output
    assert "plamen setup" not in output
    assert "plamen doctor" in output
    assert "Audits will run" not in output


def test_supported_setup_report_distinguishes_manual_prerequisites(monkeypatch):
    output = _report(monkeypatch, available=lambda name: False, compatibility=False)
    assert "plamen setup" in output
    assert "manual prerequisites still require separate installation" in output


@pytest.mark.parametrize("interpreter_exists", [False, True])
def test_full_dependency_check_uses_launcher_not_ambient_python(
    tmp_path, monkeypatch, interpreter_exists,
):
    front = _load_front()
    interpreter = tmp_path / "managed-python"
    if interpreter_exists:
        interpreter.write_text("fixture only", encoding="utf-8")
    monkeypatch.setattr(front.sys, "executable", str(interpreter))
    monkeypatch.setattr(
        front,
        "_dependency_backend_paths",
        lambda: {"fixture-backend": "/fixture/backend"},
    )
    monkeypatch.setattr(front, "_go_medusa_paths", lambda: [])
    monkeypatch.setattr(front, "_probe_rag_db", lambda: 0)
    monkeypatch.setattr(
        front,
        "_probe_mcp_servers",
        lambda: (_ for _ in ()).throw(AssertionError("ambient MCP probe")),
    )

    def find(name, paths=None):
        assert name not in {"python", "python3"}, "ambient Python must not be probed"
        return f"/fixture/{name}"

    monkeypatch.setattr(front, "_find_bin", find)
    assert front.check_dependencies() is interpreter_exists
