"""Independent hostile contract for retained hardlink-alias approvals.

The fast path may avoid repeated FindFirstFileNameW/FindNextFileNameW walks
only while an exact native write/delete-denial handle remains open and every
stored approval fact still authenticates.  This suite uses tiny synthetic
distributions; the live Slither timing diagnostic is explicit opt-in only.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import time
import types
from typing import Any, Iterator
from unittest import mock

import pytest

import audit_snapshot as A


pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="retained native denial handles are a Windows authority",
)


def _norm(path: Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


class _StatDriftView:
    """Override identity/link fields while retaining the complete stat API."""

    def __init__(
        self,
        base: os.stat_result,
        *,
        st_ino: int | None = None,
        st_nlink: int | None = None,
    ) -> None:
        self._base = base
        self.st_ino = int(base.st_ino if st_ino is None else st_ino)
        self.st_nlink = int(base.st_nlink if st_nlink is None else st_nlink)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._base, name)


def _record_hash(path: Path) -> str:
    encoded = base64.urlsafe_b64encode(
        hashlib.sha256(path.read_bytes()).digest()
    ).decode("ascii").rstrip("=")
    return "sha256=" + encoded


@pytest.fixture(autouse=True)
def _clean_retained_process_state() -> Iterator[None]:
    A._release_retained_hardlink_denials()
    A._FILE_HASH_CACHE.clear()
    yield
    A._release_retained_hardlink_denials()
    A._FILE_HASH_CACHE.clear()


@pytest.fixture
def external_alias(tmp_path: Path) -> dict[str, Path]:
    project = tmp_path / "audit-target"
    first = tmp_path / "runtime-a" / "provider.py"
    alias = tmp_path / "runtime-b" / "provider.py"
    other = tmp_path / "other" / "unrelated.py"
    for directory in (project, first.parent, alias.parent, other.parent):
        directory.mkdir(parents=True, exist_ok=True)
    first.write_bytes(b"reviewed provider bytes\n")
    os.link(first, alias)
    other.write_bytes(b"unrelated native identity\n")
    return {
        "root": tmp_path,
        "project": project,
        "first": first,
        "alias": alias,
        "other": other,
    }


def _approve(paths: dict[str, Path]) -> tuple[int, int]:
    A._reject_unexpected_hardlinks(
        paths["first"],
        "retained alias fixture",
        project_root=paths["project"],
        retain_fully_enumerated_external_aliases=True,
        retained_authority_root=paths["root"],
    )
    row = paths["first"].stat(follow_symlinks=False)
    identity = (int(row.st_dev), int(row.st_ino))
    assert identity in A._RETAINED_HARDLINK_APPROVALS
    assert identity in A._RETAINED_HARDLINK_DENIAL_FDS
    return identity


def _reuse(paths: dict[str, Path]) -> None:
    A._reject_unexpected_hardlinks(
        paths["first"],
        "retained alias fixture",
        project_root=paths["project"],
        retain_fully_enumerated_external_aliases=True,
        retained_authority_root=paths["root"],
    )


def test_first_approval_enumerates_twice_then_exact_reuse_enumerates_zero(
    external_alias: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bounded acceptance metric is native enumeration count, not time."""

    real_enumerator = A._windows_hardlink_aliases
    enumerated: list[Path] = []

    def counted(path: Path) -> tuple[Path, ...]:
        enumerated.append(Path(path))
        return real_enumerator(path)

    monkeypatch.setattr(A, "_windows_hardlink_aliases", counted)
    _approve(external_alias)
    # One complete enumeration precedes denial acquisition and another exact
    # enumeration follows it.  No approval may arise from a partial first pass.
    assert enumerated == [external_alias["first"], external_alias["first"]]

    enumerated.clear()
    monkeypatch.setattr(
        A,
        "_windows_hardlink_aliases",
        lambda _path: (_ for _ in ()).throw(
            AssertionError("retained fast path re-enumerated aliases")
        ),
    )
    _reuse(external_alias)
    assert enumerated == []


def test_corrupted_cached_alias_set_cannot_substitute_a_nonexistent_name(
    external_alias: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-cardinality cache corruption must not survive the fast path."""

    identity = _approve(external_alias)
    locked_count, locked_aliases, locked_root = (
        A._RETAINED_HARDLINK_APPROVALS[identity]
    )
    assert len(locked_aliases) == locked_count == 2
    current = _norm(external_alias["first"])
    ghost = _norm(external_alias["root"] / "runtime-c" / "ghost.py")
    # Preserve every currently checked scalar: cardinality, current path,
    # authority root, externality, identity and link count.  Only an
    # authenticated cache payload can distinguish this forged alias roster.
    A._RETAINED_HARDLINK_APPROVALS[identity] = (
        locked_count,
        tuple(sorted((current, ghost))),
        locked_root,
    )
    monkeypatch.setattr(
        A,
        "_windows_hardlink_aliases",
        lambda _path: (_ for _ in ()).throw(
            AssertionError("corrupt approval must fail before enumeration")
        ),
    )
    with pytest.raises(A.SnapshotInputError, match="approval|cache|drift"):
        _reuse(external_alias)


@pytest.mark.parametrize("drift", ("identity", "link_count"))
def test_live_native_identity_or_link_count_drift_fails_closed(
    external_alias: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    _approve(external_alias)
    first = external_alias["first"]
    real_stat = Path.stat

    def drifted_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        row = real_stat(self, *args, **kwargs)
        if self != first:
            return row
        return _StatDriftView(
            row,
            st_ino=(int(row.st_ino) + 1 if drift == "identity" else int(row.st_ino)),
            st_nlink=(
                int(row.st_nlink) + 1
                if drift == "link_count"
                else int(row.st_nlink)
            ),
        )

    monkeypatch.setattr(Path, "stat", drifted_stat)
    with pytest.raises(A.SnapshotInputError, match="approval|hardlink|drift"):
        _reuse(external_alias)


def test_closed_retained_descriptor_invalidates_approval(
    external_alias: dict[str, Path],
) -> None:
    identity = _approve(external_alias)
    descriptor = A._RETAINED_HARDLINK_DENIAL_FDS[identity]
    os.close(descriptor)
    with pytest.raises(A.SnapshotInputError, match="approval|hardlink|missing|drift"):
        _reuse(external_alias)


def test_known_approval_cannot_bypass_validation_via_singleton_downshift(
    external_alias: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A known retained identity is checked before the nlink==1 shortcut."""

    identity = _approve(external_alias)
    descriptor = A._RETAINED_HARDLINK_DENIAL_FDS[identity]
    os.close(descriptor)
    first = external_alias["first"]
    real_stat = Path.stat

    def singleton_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        row = real_stat(self, *args, **kwargs)
        if self != first:
            return row
        return _StatDriftView(row, st_nlink=1)

    monkeypatch.setattr(Path, "stat", singleton_stat)
    with pytest.raises(A.SnapshotInputError, match="approval|hardlink|missing|drift"):
        _reuse(external_alias)


def test_replaced_retained_descriptor_invalidates_approval(
    external_alias: dict[str, Path],
) -> None:
    identity = _approve(external_alias)
    original = A._RETAINED_HARDLINK_DENIAL_FDS[identity]
    os.close(original)
    replacement = os.open(external_alias["other"], os.O_RDONLY)
    A._RETAINED_HARDLINK_DENIAL_FDS[identity] = replacement
    with pytest.raises(A.SnapshotInputError, match="approval|hardlink|drift"):
        _reuse(external_alias)


def test_project_root_exclusion_is_rechecked_on_every_reuse(
    external_alias: dict[str, Path],
) -> None:
    _approve(external_alias)
    with pytest.raises(A.SnapshotInputError, match="approval|hardlink|drift"):
        A._reject_unexpected_hardlinks(
            external_alias["first"],
            "retained alias fixture",
            # The original approval used a disjoint audit target.  A later
            # target containing either approved name must invalidate reuse.
            project_root=external_alias["alias"].parent,
            retain_fully_enumerated_external_aliases=True,
            retained_authority_root=external_alias["root"],
        )


def test_replay_uses_cross_volume_safe_project_containment(
    external_alias: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Approval replay must not call ``commonpath`` across Windows drives."""

    _approve(external_alias)
    inspected: list[tuple[Path, Path | None]] = []

    def outside(path: Path, root: Path | None) -> bool:
        inspected.append((Path(path), root))
        return False

    monkeypatch.setattr(A, "_path_is_within", outside)
    _reuse(external_alias)
    assert len(inspected) == 2
    assert all(root == external_alias["project"] for _path, root in inspected)


def _small_distribution(tmp_path: Path) -> tuple[Any, dict[str, Path]]:
    project = tmp_path / "audit-target"
    runtime = tmp_path / "runtime-a"
    install = runtime / "Lib" / "site-packages"
    package = install / "fixture_pkg"
    cache = package / "__pycache__"
    dist_info = install / "fixture_dist-1.0.dist-info"
    alias_root = tmp_path / "runtime-b"
    for directory in (project, cache, dist_info, alias_root):
        directory.mkdir(parents=True, exist_ok=True)

    module = package / "__init__.py"
    pyc = cache / "fixture.cpython-test.pyc"
    record = dist_info / "RECORD"
    module.write_bytes(b"VALUE = 'SAFE'\n")
    pyc.write_bytes(b"synthetic safe bytecode payload\n")

    module_name = "fixture_pkg/__init__.py"
    pyc_name = "fixture_pkg/__pycache__/fixture.cpython-test.pyc"
    record_name = "fixture_dist-1.0.dist-info/RECORD"
    record.write_text(
        f"{module_name},{_record_hash(module)},{module.stat().st_size}\n"
        f"{pyc_name},,\n"
        f"{record_name},,\n",
        encoding="utf-8",
    )
    aliases = {
        "module_alias": alias_root / "module-alias.py",
        "pyc_alias": alias_root / "module-alias.pyc",
        "record_alias": alias_root / "RECORD-alias",
    }
    os.link(module, aliases["module_alias"])
    os.link(pyc, aliases["pyc_alias"])
    os.link(record, aliases["record_alias"])

    class FixtureDistribution:
        metadata = {"Name": "fixture-dist"}
        files = (Path(module_name), Path(pyc_name), Path(record_name))

        @staticmethod
        def locate_file(relative: object) -> Path:
            return install / Path(str(relative))

    paths = {
        "project": project,
        "module": module,
        "pyc": pyc,
        "record": record,
        **aliases,
    }
    return FixtureDistribution(), paths


def test_small_closure_reuses_alias_approval_but_rehashes_content_and_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    distribution, paths = _small_distribution(tmp_path)
    real_enumerator = A._windows_hardlink_aliases
    first_enumerations: list[Path] = []

    def counted(path: Path) -> tuple[Path, ...]:
        first_enumerations.append(Path(path))
        return real_enumerator(path)

    monkeypatch.setattr(A, "_windows_hardlink_aliases", counted)
    with mock.patch(
        "importlib.metadata.distributions", return_value=[distribution]
    ), mock.patch(
        "importlib.util.find_spec",
        return_value=types.SimpleNamespace(origin=str(paths["module"])),
    ):
        first = A._python_distribution_closure(
            "fixture-dist",
            "fixture_pkg",
            project_root=paths["project"],
        )
    # Three cross-directory identities each require pre/post-denial complete
    # enumeration.  Repeated occurrences inside the same closure use the
    # retained approval.
    assert len(first_enumerations) == 6
    assert first["record_member_file_count"] == 3
    assert first["record_member_native_identity_count"] == 3

    A._FILE_HASH_CACHE.clear()
    hashed: list[Path] = []
    record_reads: list[Path] = []
    real_hash = A._hash_path
    real_read_bytes = Path.read_bytes

    def counted_hash(path: Path) -> tuple[bytes, int]:
        hashed.append(Path(path))
        return real_hash(path)

    def counted_read_bytes(self: Path) -> bytes:
        if self == paths["record"]:
            record_reads.append(self)
        return real_read_bytes(self)

    monkeypatch.setattr(A, "_hash_path", counted_hash)
    monkeypatch.setattr(Path, "read_bytes", counted_read_bytes)
    monkeypatch.setattr(
        A,
        "_windows_hardlink_aliases",
        lambda _path: (_ for _ in ()).throw(
            AssertionError("unchanged retained closure re-enumerated aliases")
        ),
    )
    with mock.patch(
        "importlib.metadata.distributions", return_value=[distribution]
    ), mock.patch(
        "importlib.util.find_spec",
        return_value=types.SimpleNamespace(origin=str(paths["module"])),
    ):
        second = A._python_distribution_closure(
            "fixture-dist",
            "fixture_pkg",
            project_root=paths["project"],
        )

    assert second == first
    assert hashed == [paths["record"], paths["module"], paths["pyc"]]
    assert record_reads == [paths["record"]]
    # Both ordinary module and pyc aliases remain physically denied after the
    # cached validation; the optimization creates no mutation window.
    with pytest.raises(OSError):
        paths["module_alias"].write_bytes(b"attacker module bytes")
    with pytest.raises(OSError):
        paths["pyc_alias"].write_bytes(b"attacker pyc bytes")


def test_retained_observation_cannot_promote_slither_authority() -> None:
    controls = A._load_toolchain_identity_controls()
    locked = controls[0]["slither"]
    _expected, status, authority, _lock_digest, _governance_digest = (
        A._runtime_identity_policy(
            "slither",
            resolved_identity=str(locked["package_name"]),
            version=str(locked["expected_version"]),
            identity_kind="python_distribution",
            controls=controls,
        )
    )
    assert status == "OBSERVED_NONAUTHORITATIVE"
    assert authority is False


@pytest.mark.skipif(
    os.environ.get("PLAMEN_RUN_FULL_SLITHER_ALIAS_TIMING") != "1",
    reason=(
        "diagnostic only: set PLAMEN_RUN_FULL_SLITHER_ALIAS_TIMING=1 to time "
        "the exact live full closure"
    ),
)
def test_diagnostic_live_slither_full_closure_second_call_timing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Diagnostic timing only; security acceptance has no wall-clock bound."""

    started = time.perf_counter()
    first = A._python_distribution_closure(
        "slither-analyzer", "slither", project_root=tmp_path
    )
    first_seconds = time.perf_counter() - started
    monkeypatch.setattr(
        A,
        "_windows_hardlink_aliases",
        lambda _path: (_ for _ in ()).throw(
            AssertionError("live retained closure re-enumerated aliases")
        ),
    )
    started = time.perf_counter()
    second = A._python_distribution_closure(
        "slither-analyzer", "slither", project_root=tmp_path
    )
    second_seconds = time.perf_counter() - started
    assert second == first
    print(
        "FULL_SLITHER_ALIAS_TIMING "
        f"first_seconds={first_seconds:.6f} "
        f"second_seconds={second_seconds:.6f} "
        f"members={first['record_member_file_count']}"
    )
