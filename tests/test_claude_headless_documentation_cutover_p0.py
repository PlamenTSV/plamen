"""Documentation contract for retiring public Claude compatibility launches."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SC_WIZARD = ROOT / "commands" / "plamen-wizard.md"
L1_WIZARD = ROOT / "commands" / "plamen-l1-wizard.md"
TERMINAL_GUIDE = ROOT / "docs" / "terminal-legacy-claude-audits.md"
CODEX_SC = ROOT / "codex-adapter" / "commands" / "plamen-wizard.md"
CODEX_L1 = ROOT / "codex-adapter" / "commands" / "plamen-l1-wizard.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def test_public_templates_never_generate_or_recommend_claude_pty() -> None:
    for path in (SC_WIZARD, L1_WIZARD, TERMINAL_GUIDE):
        body = _read(path).lower()
        assert "pty" not in body, path
        assert (
            '"claude_exec_mode": "headless"' in body
            or 'config["claude_exec_mode"] = "headless"' in body
            or path == L1_WIZARD
        )


def test_sc_wizard_routes_only_thorough_to_explicit_contained_headless() -> None:
    body = _read(SC_WIZARD)
    assert 'if MODE == "thorough"' in body
    assert 'config["cli_backend"] = "claude-headless"' in body
    assert 'config["claude_exec_mode"] = "headless"' in body
    assert 'config["cli_backend"] = "codex"' in body
    assert "authenticated contained headless" in body
    assert "SC Light/Core use Codex" in body


def test_l1_wizard_is_codex_only_and_does_not_emit_claude_transport() -> None:
    body = _read(L1_WIZARD)
    assert '"cli_backend": "codex"' in body
    assert '"cli_backend": "claude"' not in body
    assert "claude_exec_mode" not in body
    assert "Claude is not a supported contained backend for L1 audits" in body
    assert "MISSING:codex" in body


def test_terminal_guide_uses_explicit_sc_thorough_headless_flags() -> None:
    body = _read(TERMINAL_GUIDE)
    for marker in (
        "Smart Contract Thorough",
        "--mode thorough",
        "--pipeline sc",
        "--cli-backend claude-headless",
        "--claude-exec-mode headless",
        '"cli_backend": "claude-headless"',
        '"claude_exec_mode": "headless"',
        "contained-worker capability check fails must use Codex",
    ):
        assert marker in body
    assert "Do not adapt this Claude command to L1, Light, or Core" in body


def test_existing_evidence_is_never_migrated_in_place() -> None:
    for path in (SC_WIZARD, L1_WIZARD, TERMINAL_GUIDE):
        normalized = " ".join(_read(path).split()).lower()
        assert "distinct clean" in normalized
        assert "existing" in normalized
        assert "auto-migrate" in normalized
        assert "in place" in normalized


def test_codex_command_adapters_are_thin_nonmirror_wrappers() -> None:
    pairs = ((SC_WIZARD, CODEX_SC), (L1_WIZARD, CODEX_L1))
    for source, adapter in pairs:
        adapter_body = _read(adapter)
        assert source.read_bytes() != adapter.read_bytes()
        assert "~/.codex/skills/plamen/" in adapter_body
        assert "config.json" not in adapter_body
