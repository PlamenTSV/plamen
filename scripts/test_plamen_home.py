"""Unit tests for plamen_home() portability function.

Covers:
  - PLAMEN_HOME env var override
  - Script-relative detection (follows symlinks)
  - Fallback to ~/.claude
  - lru_cache behavior
  - resolve_v1_prompt() uses plamen_home()
  - _STANDALONE_V2_DIR uses plamen_home()
  - {PLAMEN_BASE} runtime placeholder

Run: python -m pytest test_plamen_home.py -v
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_types as T  # noqa: E402
from plamen_types import plamen_home  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_cache():
    """Clear plamen_home lru_cache before each test."""
    plamen_home.cache_clear()
    yield
    plamen_home.cache_clear()


class TestPlamenHomeEnvVar:
    def test_env_var_override(self, tmp_path):
        (tmp_path / "scripts").mkdir()
        (tmp_path / "rules").mkdir()
        (tmp_path / "prompts").mkdir()
        with mock.patch.dict(os.environ, {"PLAMEN_HOME": str(tmp_path)}):
            assert plamen_home() == tmp_path

    def test_env_var_nonexistent_dir_ignored(self):
        fake = str(Path.home() / "nonexistent_plamen_test_dir_xyz")
        with mock.patch.dict(os.environ, {"PLAMEN_HOME": fake}):
            result = plamen_home()
            assert result != Path(fake)

    def test_env_var_empty_string_ignored(self):
        with mock.patch.dict(os.environ, {"PLAMEN_HOME": "   "}):
            result = plamen_home()
            assert result != Path("   ")

    def test_env_var_takes_priority_over_script_relative(self, tmp_path):
        env_dir = tmp_path / "env_root"
        env_dir.mkdir()
        (env_dir / "scripts").mkdir()
        (env_dir / "rules").mkdir()
        (env_dir / "prompts").mkdir()
        with mock.patch.dict(os.environ, {"PLAMEN_HOME": str(env_dir)}):
            assert plamen_home() == env_dir


class TestPlamenHomeScriptRelative:
    def test_script_relative_detection(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PLAMEN_HOME", None)
            result = plamen_home()
            # plamen_types.py is at ~/.claude/scripts/plamen_types.py
            # parent.parent = ~/.claude/ which has scripts/, rules/, prompts/
            expected = Path(T.__file__).resolve().parent.parent
            assert result == expected

    def test_result_is_absolute(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PLAMEN_HOME", None)
            result = plamen_home()
            assert result.is_absolute()


class TestPlamenHomeFallback:
    def test_fallback_to_dot_claude(self, tmp_path):
        fake_script = tmp_path / "isolated" / "plamen_types.py"
        fake_script.parent.mkdir(parents=True)
        fake_script.write_text("# fake")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PLAMEN_HOME", None)
            with mock.patch.object(T, "__file__", str(fake_script)):
                result = plamen_home()
                assert result == Path.home() / ".claude"


class TestPlamenHomeCaching:
    def test_lru_cache_returns_same_object(self, tmp_path):
        (tmp_path / "scripts").mkdir()
        (tmp_path / "rules").mkdir()
        (tmp_path / "prompts").mkdir()
        with mock.patch.dict(os.environ, {"PLAMEN_HOME": str(tmp_path)}):
            a = plamen_home()
            b = plamen_home()
            assert a is b


class TestPlamenHomeIntegration:
    def test_resolve_v1_prompt_uses_plamen_home(self):
        import plamen_prompt as PP
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PLAMEN_HOME", None)
            plamen_home.cache_clear()
            result = PP.resolve_v1_prompt("sc")
            assert str(plamen_home()) in str(result)

    def test_standalone_v2_dir_under_plamen_home(self):
        import plamen_prompt as PP
        v2_dir = PP._STANDALONE_V2_DIR
        assert str(plamen_home()) in str(v2_dir)

    def test_plamen_base_placeholder(self):
        import plamen_prompt as PP
        test_text = "Read {PLAMEN_BASE}/rules/test.md"
        config = {"language": "evm", "scratchpad": "/tmp/test", "project_root": "/tmp"}
        rendered = PP._render_runtime_placeholders(test_text, config)
        assert plamen_home().as_posix() in rendered
        assert "{PLAMEN_BASE}" not in rendered

    def test_legacy_claude_methodology_paths_render_to_canonical_home(self):
        import plamen_prompt as PP
        test_text = (
            "Read `~/.claude/rules/test.md` and "
            "`$HOME/.claude/agents/example.md`."
        )
        config = {
            "language": "evm",
            "scratchpad": "/tmp/test",
            "project_root": "/tmp",
        }

        rendered = PP._render_runtime_placeholders(test_text, config)

        assert "~/.claude" not in rendered
        assert "$HOME/.claude" not in rendered
        assert f"{plamen_home().as_posix()}/rules/test.md" in rendered
        assert f"{plamen_home().as_posix()}/agents/example.md" in rendered


class TestPlamenHomeInAllField:
    def test_exported_in_all(self):
        assert "plamen_home" in T.__all__
