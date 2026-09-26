"""Policy stops have a local, actionable explanation, not gate-repair advice."""
from io import StringIO
from pathlib import Path

import pytest

import plamen_display as display


@pytest.mark.parametrize("rich", [False, True])
def test_policy_stop_without_logs_is_literal_and_offline(
    tmp_path, monkeypatch, capsys, rich
):
    if rich:
        console_module = pytest.importorskip("rich.console")
        output = StringIO()
        monkeypatch.setattr(
            display, "console",
            console_module.Console(file=output, width=200, color_system=None),
        )
    monkeypatch.setattr(display, "RICH_AVAILABLE", rich)

    def forbidden(*args, **kwargs):
        raise AssertionError("A policy diagnostic must not launch a process")

    monkeypatch.setattr(display.subprocess, "Popen", forbidden)
    receipt = tmp_path / "[literal]receipt.json"
    receipt.write_text('{"preserve":true}', encoding="utf-8")
    display.print_provider_policy_stop("depth", str(tmp_path), str(receipt))
    shown = output.getvalue() if rich else capsys.readouterr().err
    saved = (tmp_path / "_diagnosis_depth.md").read_text(encoding="utf-8")
    for text in (shown, saved):
        assert "PROVIDER_POLICY_REFUSAL" in text
        assert "[literal]receipt.json" in text
        assert "Resolve the provider access issue before explicitly resuming" in text
        assert "https://learn.chatgpt.com/docs/cyber-safety" in text
        assert "GATE_MISMATCH" not in text
        assert "after retry exhaustion" not in text
        assert "account is approved" in text
    assert receipt.read_text(encoding="utf-8") == '{"preserve":true}'


def test_policy_stop_is_visible_even_if_diagnosis_cannot_be_saved(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(display, "RICH_AVAILABLE", False)

    def unwritable(*args, **kwargs):
        raise PermissionError("read-only fixture")

    monkeypatch.setattr(Path, "write_text", unwritable)
    display.print_provider_policy_stop("depth", str(tmp_path), "receipt.json")
    assert "PROVIDER_POLICY_REFUSAL" in capsys.readouterr().err
