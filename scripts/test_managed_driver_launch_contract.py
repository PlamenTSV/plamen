"""Regression coverage for the public managed-runtime driver launch contract."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import plamen_driver as driver


ROOT = Path(__file__).resolve().parents[1]


def test_installed_driver_rejects_ambient_python_before_path_pinning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    managed = tmp_path / "managed"
    ambient = tmp_path / "ambient"
    (managed / ("Scripts" if driver.os.name == "nt" else "bin")).mkdir(
        parents=True
    )
    ambient.mkdir()
    monkeypatch.setattr(driver, "_installed_package_runtime_root", lambda: tmp_path)
    original_expanduser = driver.os.path.expanduser
    monkeypatch.setattr(
        driver.os.path,
        "expanduser",
        lambda value: str(managed)
        if value == "~/.local/share/plamen/runtime/py312"
        else original_expanduser(value),
    )
    monkeypatch.setattr(driver.sys, "prefix", str(ambient))

    with pytest.raises(RuntimeError, match="ambient Python"):
        driver._pin_installed_runtime_scripts_path()


def test_installed_driver_pins_the_exact_managed_scripts_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    managed = tmp_path / "managed"
    scripts = managed / ("Scripts" if driver.os.name == "nt" else "bin")
    scripts.mkdir(parents=True)
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setattr(driver, "_installed_package_runtime_root", lambda: tmp_path)
    original_expanduser = driver.os.path.expanduser
    monkeypatch.setattr(
        driver.os.path,
        "expanduser",
        lambda value: str(managed)
        if value == "~/.local/share/plamen/runtime/py312"
        else original_expanduser(value),
    )
    monkeypatch.setattr(driver.sys, "prefix", str(managed))
    monkeypatch.setenv("PATH", driver.os.pathsep.join((str(other), str(scripts))))

    driver._pin_installed_runtime_scripts_path()

    assert driver.os.environ["PATH"].split(driver.os.pathsep) == [
        str(scripts),
        str(other),
    ]


def test_codex_wizard_assets_never_launch_installed_driver_with_ambient_python() -> None:
    assets = (
        ROOT / "codex-adapter" / "skills" / "plamen" / "SKILL.md",
        ROOT / "codex-adapter" / "skills" / "plamen" / "plamen-wizard.md",
        ROOT / "codex-adapter" / "skills" / "plamen" / "plamen-l1-wizard.md",
        ROOT / "codex-adapter" / "commands" / "plamen.md",
        ROOT / "codex-adapter" / "commands" / "plamen-l1.md",
        ROOT / "codex-adapter" / "commands" / "plamen-wizard.md",
        ROOT / "codex-adapter" / "commands" / "plamen-l1-wizard.md",
    )
    for asset in assets:
        text = asset.read_text(encoding="utf-8")
        assert not any(
            "python " in line.lower() and "plamen_driver.py" in line.lower()
            for line in text.splitlines()
        )
        assert 'plamen resume "{CONFIG_PATH}"' in text
        assert 'plamen start-config "' in text


def test_start_config_uses_current_managed_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import plamen

    project = tmp_path / "project"
    scratchpad = project / ".scratchpad-r17"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text(
        json.dumps({
            "project_root": str(project),
            "scratchpad": str(scratchpad),
            "pipeline": "sc",
            "mode": "thorough",
        }),
        encoding="utf-8",
    )
    runtime = tmp_path / "runtime"
    (runtime / "scripts").mkdir(parents=True)
    (runtime / "scripts" / "plamen_driver.py").write_text(
        "# fixture\n", encoding="utf-8"
    )
    calls: list[list[str]] = []
    child_envs: list[dict[str, str]] = []
    receipt_path = tmp_path / "private-state" / "decision.json"
    receipt_path.parent.mkdir()

    def fake_run(argv, *, env):
        calls.append(list(argv))
        child_envs.append(env)
        assert len(env["PLAMEN_STARTUP_DECISION_MAC_KEY"]) == 64
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(plamen, "PLAMEN_HOME", str(runtime))
    monkeypatch.setattr(plamen.sys, "executable", "managed-python")
    monkeypatch.setattr(plamen.subprocess, "run", fake_run)
    monkeypatch.setattr(
        plamen, "_resume_startup_decision_destination",
        lambda *_args: receipt_path,
    )
    monkeypatch.setattr(
        plamen, "_render_driver_result", lambda *_args, **_kwargs: 0,
    )

    with pytest.raises(SystemExit, match="0"):
        plamen.start_config_v2(str(config_path))

    assert calls == [[
        "managed-python",
        str(runtime / "scripts" / "plamen_driver.py"),
        "--startup-intent",
        "START_NEW_RUN",
        "--startup-decision-receipt",
        str(receipt_path),
        str(config_path),
    ]]
    assert "PLAMEN_STARTUP_DECISION_MAC_KEY" not in child_envs[0]
