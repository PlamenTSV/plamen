"""Launcher-level P0-AO regression contracts.

The interactive wrapper must not reintroduce the destructive lifecycle that
the driver now refuses. These source-level assertions protect the small launcher
surface whose behavior is otherwise hidden behind an interactive UI.
"""
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def test_wizard_never_deletes_or_fresh_restarts_existing_run_in_place():
    source = (ROOT / "plamen.py").read_text(encoding="utf-8", errors="replace")
    assert "shutil.rmtree(old_sp" not in source
    assert "resume_v2(existing[\"config_path\"], fresh=True)" not in source
    assert '_driver_cmd.append("--fresh")' not in source


def test_driver_interrupt_path_never_offers_to_delete_run_evidence():
    source = (ROOT / "scripts" / "plamen_driver.py").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "display.wait_purge_choice()" not in source
    assert "_purge_scratchpad(scratchpad, config)" not in source


def test_generated_codex_guidance_requires_a_distinct_clean_destination():
    source = (ROOT / "scripts" / "codex_adapter.py").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "distinct clean destination" in source
    assert 'plamen_driver.py --fresh "{{CONFIG_PATH}}"' not in source


def test_codex_skill_packages_every_referenced_wizard_resource(tmp_path, monkeypatch):
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    import codex_adapter

    monkeypatch.setattr(codex_adapter, "PLAMEN_HOME", tmp_path)
    codex_adapter.generate_skill_md(tmp_path)
    skill_root = tmp_path / "skills" / "plamen"
    base = (skill_root / "SKILL.md").read_text(encoding="utf-8")
    for name in ("plamen-wizard.md", "plamen-l1-wizard.md"):
        resource = skill_root / name
        assert name in base
        assert resource.is_file()
        text = resource.read_text(encoding="utf-8")
        assert "distinct clean destination" in text
        assert "plamen_driver.py" in text
        assert "--fresh" not in text
        checked_in = ROOT / "codex-adapter" / "skills" / "plamen" / name
        checked_text = checked_in.read_text(encoding="utf-8")
        for marker in (
            "distinct clean destination",
            "--startup-intent START_NEW_RUN",
            'cli_backend: "codex"',
        ):
            assert marker in checked_text
        assert "--fresh" not in checked_text


def test_claude_wizard_guidance_never_advertises_in_place_fresh_restart():
    for relative in (
        "commands/plamen-wizard.md",
        "commands/plamen-l1-wizard.md",
        "docs/usage.md",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8", errors="replace")
        assert "distinct clean destination" in text, relative
        assert "plamen_driver.py --fresh" not in text, relative
