"""Serial Git-backed ratchets for runtime Python packaging."""
from __future__ import annotations

from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"


def _run_git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _is_ignored(path: Path) -> bool:
    relative = path.relative_to(REPO_ROOT).as_posix()
    result = _run_git("check-ignore", "--no-index", "--quiet", "--", relative)
    assert result.returncode in {0, 1}, (
        f"git check-ignore failed for {relative}: {result.stderr.strip()}"
    )
    return result.returncode == 0


def test_every_literal_python_unignore_exception_exists() -> None:
    rules = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    missing: list[str] = []
    for rule in rules:
        if not rule.startswith("!scripts/") or not rule.endswith(".py"):
            continue
        # Wildcard exceptions (currently test_*.py) describe a set, not a path.
        if any(token in rule for token in "*?["):
            continue
        relative = rule[1:]
        if not (REPO_ROOT / relative).is_file():
            missing.append(relative)
    assert not missing, f"stale literal Python .gitignore exceptions: {missing}"


def test_changed_or_new_runtime_python_modules_are_not_ignored() -> None:
    """Dirty/new production modules must be package-visible before tests pass.

    ``git check-ignore`` normally suppresses answers for tracked paths, hence
    ``--no-index``.  Enumerating disk files also catches an ignored *untracked*
    module that ``git status`` would otherwise hide.
    """

    changed = _run_git(
        "diff", "--name-only", "--diff-filter=ACMR", "HEAD", "--", "scripts"
    )
    assert changed.returncode == 0, changed.stderr
    changed_paths = {
        REPO_ROOT / row.strip()
        for row in changed.stdout.splitlines()
        if row.strip().endswith(".py")
    }

    tracked = _run_git("ls-files", "--", "scripts/*.py")
    assert tracked.returncode == 0, tracked.stderr
    tracked_paths = {REPO_ROOT / row.strip() for row in tracked.stdout.splitlines()}
    untracked_paths = set(SCRIPTS_DIR.glob("*.py")) - tracked_paths

    candidates = changed_paths | untracked_paths
    runtime_candidates = {
        path
        for path in candidates
        if path.is_file()
        and not path.name.startswith("test_")
        and path.name != "conftest.py"
    }
    ignored = sorted(
        path.relative_to(REPO_ROOT).as_posix()
        for path in runtime_candidates
        if _is_ignored(path)
    )
    assert not ignored, (
        "changed/new runtime Python modules would be absent from a fresh "
        f"checkout: {ignored}"
    )
