"""Independent adversarial review of snapshot hashing and walk caching.

The snapshot is an authority boundary, so an optimization may avoid a read
only when it can prove that the same bytes are still present.  These fixtures
exercise metadata spoofing, file replacement, opened-file/path races, symlink
referents, path-set drift, traversal determinism, and cache lifetime.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(REPO_ROOT))

import audit_snapshot as A  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_file_hash_cache():
    A._FILE_HASH_CACHE.clear()
    yield
    A._FILE_HASH_CACHE.clear()


def _actual_digest(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def test_same_size_edit_with_restored_mtime_never_hits_stale_digest(
    tmp_path: Path,
) -> None:
    path = tmp_path / "State.sol"
    original = b"contract State { uint256 a; }\n"
    changed = b"contract State { uint256 b; }\n"
    assert len(original) == len(changed)
    path.write_bytes(original)
    before = path.stat()
    first, first_size = A._hash_path(path)
    assert first == _actual_digest(original)

    path.write_bytes(changed)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    second, second_size = A._hash_path(path)

    assert first_size == second_size == len(changed)
    assert second == _actual_digest(changed)
    assert second != first


def test_symlink_retarget_changes_digest_even_when_target_bytes_match(
    tmp_path: Path,
) -> None:
    first_target = tmp_path / "first.sol"
    second_target = tmp_path / "second.sol"
    first_target.write_bytes(b"same bytes\n")
    second_target.write_bytes(b"same bytes\n")
    link = tmp_path / "selected.sol"
    try:
        link.symlink_to(first_target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"file symlink unavailable: {exc}")
    first = A._hash_path(link)
    link.unlink()
    link.symlink_to(second_target)
    second = A._hash_path(link)
    assert second != first


def test_symlink_target_same_size_restored_mtime_edit_is_not_stale(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.sol"
    link = tmp_path / "selected.sol"
    original = b"contract Target { uint256 a; }\n"
    changed = b"contract Target { uint256 b; }\n"
    assert len(original) == len(changed)
    target.write_bytes(original)
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"file symlink unavailable: {exc}")
    before = target.stat()
    first = A._hash_path(link)
    target.write_bytes(changed)
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    second = A._hash_path(link)
    assert second != first
    expected_prefix = b"SYMLINK\0" + os.fsencode(os.readlink(link)) + b"\0"
    assert second[0] == _actual_digest(expected_prefix + changed)


def test_atomic_file_replacement_cannot_reuse_prior_digest(
    tmp_path: Path,
) -> None:
    path = tmp_path / "Module.move"
    replacement = tmp_path / "replacement.tmp"
    original = b"module 0x1::A {}\n"
    changed = b"module 0x1::B {}\n"
    assert len(original) == len(changed)
    path.write_bytes(original)
    before = path.stat()
    first = A._hash_path(path)
    replacement.write_bytes(changed)
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    os.replace(replacement, path)
    second = A._hash_path(path)
    assert second[0] == _actual_digest(changed)
    assert second != first


def test_opened_file_identity_must_match_the_pre_and_post_path_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Models an A->B->A rename race around the path-based pre/post stats."""

    victim = tmp_path / "victim.rs"
    alternate = tmp_path / "alternate.rs"
    victim.write_bytes(b"pub fn trusted() {}\n")
    alternate.write_bytes(b"pub fn replaced() {}\n")
    real_open = Path.open

    def _open_other(self: Path, *args, **kwargs):
        if self == victim:
            return real_open(alternate, *args, **kwargs)
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _open_other)
    with pytest.raises(A.SnapshotInputError, match="changed|identity|stable"):
        A._hash_path(victim)


def test_tree_walk_rejects_nested_directory_symlink_instead_of_hiding_it(
    tmp_path: Path,
) -> None:
    methodology = tmp_path / "agents"
    methodology.mkdir()
    external = tmp_path / "external-methodology"
    external.mkdir()
    (external / "rule.md").write_text("material rule\n", encoding="utf-8")
    link = methodology / "linked-rules"
    try:
        link.symlink_to(external, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")
    with pytest.raises(A.SnapshotInputError, match="symlink|junction|link"):
        A._tree_entries(tmp_path, ("agents",))


def test_deletion_and_addition_change_path_set_even_with_identical_bytes(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "agents"
    tree.mkdir()
    first_path = tree / "first.md"
    first_path.write_bytes(b"same\n")
    first = A._digest_entries(A._tree_entries(tmp_path, ("agents",)))
    first_path.unlink()
    (tree / "second.md").write_bytes(b"same\n")
    second = A._digest_entries(A._tree_entries(tmp_path, ("agents",)))
    assert second["path_set_digest"] != first["path_set_digest"]
    assert second["digest"] != first["digest"]
    assert second["file_count"] == first["file_count"] == 1


def test_walk_and_digest_are_deterministic_with_case_distinct_paths(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "agents"
    (tree / "zeta").mkdir(parents=True)
    (tree / "alpha").mkdir()
    (tree / "root.md").write_text("root\n", encoding="utf-8")
    (tree / "zeta" / "B.md").write_text("B\n", encoding="utf-8")
    (tree / "alpha" / "a.md").write_text("a\n", encoding="utf-8")
    first_entries = A._tree_entries(tmp_path, ("agents",))
    second_entries = A._tree_entries(tmp_path, ("agents",))
    assert [name for name, _ in first_entries] == [
        name for name, _ in second_entries
    ]
    assert A._digest_entries(first_entries) == A._digest_entries(
        reversed(second_entries)
    )
    synthetic = (("A.sol", b"x"), ("a.sol", b"x"))
    assert A._digest_entries(synthetic)["file_count"] == 2
    assert A._digest_entries(synthetic) == A._digest_entries(reversed(synthetic))


def test_cache_does_not_retain_unbounded_old_identities_for_one_path(
    tmp_path: Path,
) -> None:
    path = tmp_path / "changing.go"
    normalized = os.path.normcase(str(path.resolve(strict=False)))
    for size in range(1, 65):
        path.write_bytes(b"x" * size)
        A._hash_path(path)
    assert set(A._FILE_HASH_CACHE) == {normalized}, (
        "same-process cache must replace the one entry for this path rather "
        "than retaining every historical metadata identity"
    )
    cached_identity, cached_result = A._FILE_HASH_CACHE[normalized]
    assert cached_identity[0] == normalized
    assert cached_result == (_actual_digest(b"x" * 64), 64)
