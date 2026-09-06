from __future__ import annotations

import inspect

import plamen_driver as driver


def test_every_driver_claude_launch_builder_uses_exact_update_controls() -> None:
    assert driver._CLAUDE_UPDATE_DISABLE_ENV == {
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_UPDATES": "1",
    }
    builders = (
        driver._execute_dynamic_verifier_launch,
        driver._skeptic_provider_environment,
        driver._severity_adjudication_environment,
        driver._run_transactional_headless_leaf,
        driver._run_one_codex_exec,
        driver.run_phase,
    )
    for builder in builders:
        source = inspect.getsource(builder)
        assert "_CLAUDE_UPDATE_DISABLE_ENV" in source, builder.__name__


def test_unrecognized_legacy_update_alias_is_absent_from_driver() -> None:
    source = inspect.getsource(driver)
    assert "ANTHROPIC_DISABLE_AUTOUPDATE" not in source
