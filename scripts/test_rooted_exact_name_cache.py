"""`exact_existing_name` on POSIX must not re-list the parent on every call.

Measured before the fix: `_snapshot_file_state` calls it once per entry, and
each call ran a full `scandir` of the parent -> O(n^2). At 32,769 entries that
was a >59-minute 100%-CPU spin in
`test_containment_control_authority_survives_32769_prior_entries`.

These tests pin the property (one listing per unchanged directory) and every
semantic the check must keep: exact hit passes, case-distinct spelling raises,
absent name is not this function's concern, and a CHANGE to the directory is
seen on the very next call.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import rooted_path_io as R  # noqa: E402

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX listing path only")


@pytest.fixture
def counted_scandir(monkeypatch):
    calls = {"n": 0}
    real = R.scandir

    def counting(path):
        calls["n"] += 1
        return real(path)

    monkeypatch.setattr(R, "scandir", counting)
    R._parent_name_cache.clear()
    return calls


def _populate(root: Path, n: int) -> list[str]:
    names = [f"entry-{i:05d}.md" for i in range(n)]
    for name in names:
        (root / name).write_bytes(b"x")
    return names


def test_unchanged_directory_is_listed_once(tmp_path, counted_scandir) -> None:
    names = _populate(tmp_path, 2000)
    for name in names:
        R.exact_existing_name(tmp_path / name)
    assert counted_scandir["n"] == 1, (
        f"parent listed {counted_scandir['n']} times for 2000 calls; "
        "the O(n^2) behaviour is back"
    )


def test_case_distinct_spelling_still_raises(tmp_path, counted_scandir) -> None:
    (tmp_path / "Report.md").write_bytes(b"x")
    R.exact_existing_name(tmp_path / "Report.md")  # exact: fine
    with pytest.raises(R.RootedPathIOError, match="casing mismatch"):
        R.exact_existing_name(tmp_path / "report.md")
    with pytest.raises(R.RootedPathIOError, match="casing mismatch"):
        R.exact_existing_name(tmp_path / "REPORT.MD")
    assert counted_scandir["n"] == 1


def test_absent_name_is_not_an_error(tmp_path, counted_scandir) -> None:
    _populate(tmp_path, 3)
    R.exact_existing_name(tmp_path / "does-not-exist.md")  # no raise


def test_directory_change_is_seen_on_the_next_call(tmp_path, counted_scandir) -> None:
    """A hit must be exactly as fresh as the directory's own change signal."""
    _populate(tmp_path, 5)
    R.exact_existing_name(tmp_path / "entry-00000.md")
    assert counted_scandir["n"] == 1
    # Directory mtime granularity: make sure the write lands in a later tick.
    time.sleep(0.02)
    (tmp_path / "Newcomer.md").write_bytes(b"x")
    with pytest.raises(R.RootedPathIOError, match="casing mismatch"):
        R.exact_existing_name(tmp_path / "newcomer.md")
    assert counted_scandir["n"] == 2, "a changed directory was served from cache"


def test_rename_invalidates(tmp_path, counted_scandir) -> None:
    _populate(tmp_path, 5)
    R.exact_existing_name(tmp_path / "entry-00001.md")
    time.sleep(0.02)
    os.rename(tmp_path / "entry-00001.md", tmp_path / "Entry-00001.md")
    with pytest.raises(R.RootedPathIOError, match="casing mismatch"):
        R.exact_existing_name(tmp_path / "entry-00001.md")
    R.exact_existing_name(tmp_path / "Entry-00001.md")
    assert counted_scandir["n"] == 2


def test_cache_is_bounded(tmp_path, counted_scandir) -> None:
    for i in range(R._PARENT_NAME_CACHE_LIMIT + 5):
        d = tmp_path / f"d{i}"
        d.mkdir()
        (d / "a").write_bytes(b"x")
        R.exact_existing_name(d / "a")
    assert len(R._parent_name_cache) <= R._PARENT_NAME_CACHE_LIMIT


def test_nonexistent_parent_returns_silently(tmp_path, counted_scandir) -> None:
    R.exact_existing_name(tmp_path / "nope" / "child")  # is_dir(parent) is False
    assert counted_scandir["n"] == 0


def test_ancestor_walk_working_set_fits_the_cache(tmp_path, counted_scandir) -> None:
    """`checked_file` verifies every ancestor per call: depth+1 parents.

    With a bound of 8 and FIFO eviction a 10-deep path thrashed on EVERY
    call (measured: 0 hits in 8,222 calls). The bound must exceed any
    realistic depth and eviction must be least-recently-used.
    """
    deep = tmp_path
    for i in range(12):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    names = _populate(deep, 300)
    for name in names:
        R.checked_file(deep / name, require_single_link=False)
    depth = len((deep / names[0]).parents)
    # One listing per distinct parent on the walk, plus the target dir: the
    # count must be bounded by the DEPTH, not by the number of files.
    assert counted_scandir["n"] <= depth + 2, (
        f"{counted_scandir['n']} listings for 300 files over depth {depth}: "
        "the ancestor working set is thrashing the cache again"
    )
