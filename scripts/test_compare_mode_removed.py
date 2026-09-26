"""Compare was never an implemented audit mode; keep its dead flow removed."""

import ast
from pathlib import Path

import pytest

from test_claude_transport_wizard import _load_front


@pytest.mark.parametrize("compatibility", [False, True])
def test_help_and_pipeline_menu_do_not_offer_compare(monkeypatch, compatibility):
    front = _load_front()
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: compatibility)
    monkeypatch.setattr(front, "_find_claude_bin", lambda: "/installed/claude")
    monkeypatch.setattr(front, "_drain_stdin", lambda: None)
    menus = []

    class Prompt:
        def execute(self):
            return "sc"

    def select(**kwargs):
        menus.extend(kwargs["choices"])
        return Prompt()

    monkeypatch.setattr(front.inquirer, "select", select)
    assert front.select_pipeline() == "sc"
    assert "compare" not in front._public_help_text("3.0.0").casefold()
    assert "compare" not in front.MODES
    assert not any(isinstance(choice, dict) and choice.get("value") == "compare"
                   for choice in menus)


@pytest.mark.parametrize("arguments", [
    ["compare"], ["compare", "report.md"],
    ["compare", "report.md", "--docs", "reference.md", "--claude"],
])
def test_removed_command_is_usage_error_without_provider(monkeypatch, capsys, arguments):
    front = _load_front()
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: True)
    monkeypatch.setattr(front.sys, "argv", ["plamen", *arguments])

    def forbidden(*args, **kwargs):
        pytest.fail("removed Compare command reached an effect")

    monkeypatch.setattr(front.subprocess, "run", forbidden)
    monkeypatch.setattr(front, "launch_v2", forbidden)
    monkeypatch.setattr(front, "show_banner", forbidden)
    with pytest.raises(SystemExit) as stopped:
        front.main()
    assert stopped.value.code == 2
    assert "unknown command: compare" in capsys.readouterr().err


def test_compare_only_helpers_and_state_machine_are_deleted():
    tree = ast.parse((Path(__file__).resolve().parents[1] / "plamen.py").read_text())
    names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    assert not names.intersection({"launch_claude", "select_report", "_cmp_crumbs_to"})
    # Ordinary identity/file comparison helpers must remain intact.
    assert "compare" in names
    assert not any(isinstance(node, ast.Constant) and node.value == "compare"
                   for node in ast.walk(tree))


@pytest.mark.parametrize("relative", ["scripts/banner.py", "scripts/banner_rich.py"])
def test_standalone_banners_present_only_current_audit_modes(relative):
    source = (Path(__file__).resolve().parents[1] / relative).read_text(
        encoding="utf-8"
    )
    assert "Compare" not in source
    assert "ground truth" not in source
    assert "mode 3 only" not in source
    assert all(label in source for label in ("Light", "Core", "Thorough"))
