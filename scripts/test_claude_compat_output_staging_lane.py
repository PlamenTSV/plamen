"""The Claude compatibility leaf must materialize its staging lane.

DODO run27 died in recon with every worker reporting::

    [plamen-compat-stderr]
    BOUND_PATH: Claude output staging directory is unavailable

Cause: ``_run_transactional_headless_leaf`` computed the restricted staging
root with ``attempt_output_directory``, which deliberately RESOLVES without
creating (several callers depend on the path not existing yet), and handed it
straight to the compatibility runtime -- which binds it with
``resolve(strict=True)`` and fails closed when it is absent.  The native
transaction path materializes its own lane inside
``execute_worker_transaction``; the compatibility path had no equivalent step,
so every Claude compat leaf died before launching.

This was invisible until the supply-chain gate stopped rejecting Claude
sessions outright, because no Claude-backend audit could previously start.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from worker_transaction import (  # noqa: E402
    attempt_output_directory,
    compile_attempt_write_scope,
    materialize_attempt_output_directory,
)


@pytest.fixture
def scope():
    return compile_attempt_write_scope(
        run_id="staging-lane-test",
        phase="recon",
        work_unit_id="phase",
        attempt_id=f"attempt-{uuid.uuid4().hex[:24]}",
    )


def _scratchpad(tmp_path: Path) -> Path:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    return scratchpad


def test_resolver_still_does_not_create(tmp_path: Path, scope) -> None:
    """The resolve-only contract must be preserved for its other callers."""
    scratchpad = _scratchpad(tmp_path)
    assert not attempt_output_directory(scratchpad, scope).exists()


def test_materializer_creates_a_bindable_lane(tmp_path: Path, scope) -> None:
    """Exactly the properties the compat runtime binds with."""
    scratchpad = _scratchpad(tmp_path)
    lane = materialize_attempt_output_directory(scratchpad, scope)

    # `resolve(strict=True)` must succeed -- this is the failing assertion.
    assert lane.resolve(strict=True) == lane.resolve()
    assert lane.is_dir()
    # The runtime refuses a symlink or a non-directory.
    assert not lane.is_symlink()
    # The runtime requires a STRICT scratchpad descendant.
    assert lane != scratchpad
    assert scratchpad.resolve() in lane.resolve().parents


def test_materializer_agrees_with_the_resolver(tmp_path: Path, scope) -> None:
    """The created lane must be the same path the rest of the code computes."""
    scratchpad = _scratchpad(tmp_path)
    assert (
        materialize_attempt_output_directory(scratchpad, scope)
        == attempt_output_directory(scratchpad, scope)
    )


def test_materializing_is_idempotent(tmp_path: Path, scope) -> None:
    """A retry or a sibling worker sharing ancestors must not explode."""
    scratchpad = _scratchpad(tmp_path)
    first = materialize_attempt_output_directory(scratchpad, scope)
    assert materialize_attempt_output_directory(scratchpad, scope) == first


def test_lane_is_not_satisfied_by_a_symlink(tmp_path: Path, scope) -> None:
    """An aliased lane must be refused, not silently accepted."""
    scratchpad = _scratchpad(tmp_path)
    target = attempt_output_directory(scratchpad, scope)
    target.parent.mkdir(parents=True, exist_ok=True)
    elsewhere = tmp_path / "outside"
    elsewhere.mkdir()
    target.symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(Exception):
        materialize_attempt_output_directory(scratchpad, scope)


def test_cli_directory_grants_cover_every_policy_authorized_root() -> None:
    """The CLI boundary must be a superset of what the hook may ALLOW.

    Under `--restricted --permission-mode dontAsk` the CLI refuses a read
    outside its own directory grants BEFORE the PreToolUse hook is consulted,
    so any root the hook can authorize must also be granted via `--add-dir`.
    Two live failures came from exactly this gap:
      * run28 -- workers denied Read on the audited contracts
        (hook: ALLOW/SOURCE_READ);
      * run30 -- instantiate denied Read on
        `~/.plamen/agents/skills/evm/*/SKILL.md`
        (hook: ALLOW/METHODOLOGY_READ).
    This pins the source-level invariant so a third read-root class cannot be
    added to the policy without also being granted to the CLI.
    """
    source = (_SCRIPTS / "posix_v2_compat_claude.py").read_text(encoding="utf-8")
    assert "policy[\"source_read_root\"]" in source, (
        "the audited source root is no longer granted to the CLI"
    )
    assert "methodology_read_roots" in source, (
        "policy methodology read roots are no longer granted to the CLI; "
        "workers will be denied their own SKILL.md methodology files"
    )
    assert "--add-dir" in source
