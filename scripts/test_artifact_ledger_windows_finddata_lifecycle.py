"""Windows FFI lifecycle regressions for artifact-ledger path replay."""

from __future__ import annotations

import ast
import ctypes
from concurrent.futures import ThreadPoolExecutor
import gc
import inspect
import os
from pathlib import Path
import tracemalloc

import pytest

import artifact_ledger as A


def test_lexical_replay_declares_no_dynamic_ffi_types() -> None:
    """The cross-OS source contract forbids per-call ctypes type creation."""

    tree = ast.parse(inspect.getsource(A._lexical_no_follow_chain))
    dynamic_classes = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
    ]
    assert dynamic_classes == []


@pytest.mark.skipif(os.name != "nt", reason="Windows native FFI contract")
def test_windows_finddata_abi_matches_win32_find_dataw() -> None:
    """Pin the exact SDK ABI consumed by FindFirstFileW."""

    expected_fields = [
        "dwFileAttributes",
        "ftCreationTime",
        "ftLastAccessTime",
        "ftLastWriteTime",
        "nFileSizeHigh",
        "nFileSizeLow",
        "dwReserved0",
        "dwReserved1",
        "cFileName",
        "cAlternateFileName",
    ]
    assert [
        name for name, _field_type in A._WindowsFindData._fields_
    ] == expected_fields
    assert ctypes.sizeof(A._WindowsFindData) == 592
    assert ctypes.alignment(A._WindowsFindData) == 4
    assert A._WindowsFindData.cFileName.offset == 44
    assert A._WindowsFindData.cAlternateFileName.offset == 564

    argument_types = A._WINDOWS_FIND_FIRST_FILE_W.argtypes
    assert argument_types[0] is ctypes.wintypes.LPCWSTR
    assert argument_types[1]._type_ is A._WindowsFindData


@pytest.mark.skipif(os.name != "nt", reason="Windows native FFI contract")
def test_windows_lexical_replay_has_bounded_type_and_memory_growth(
    tmp_path: Path,
) -> None:
    target = tmp_path / "nested" / "artifact.json"
    target.parent.mkdir()
    target.write_text("fixture\n", encoding="utf-8")
    A._lexical_no_follow_chain(target)
    gc.collect()
    before_types = set(ctypes.Structure.__subclasses__())

    already_tracing = tracemalloc.is_tracing()
    if not already_tracing:
        tracemalloc.start(5)
    gc.collect()
    before_bytes = tracemalloc.get_traced_memory()[0]
    try:
        for _ in range(128):
            A._lexical_no_follow_chain(target)
        gc.collect()
        after_bytes = tracemalloc.get_traced_memory()[0]
    finally:
        if not already_tracing:
            tracemalloc.stop()

    new_types = set(ctypes.Structure.__subclasses__()) - before_types
    assert not {
        value
        for value in new_types
        if value.__module__ == A.__name__
    }
    assert after_bytes - before_bytes < 1024 * 1024


@pytest.mark.skipif(os.name != "nt", reason="Windows native FFI contract")
def test_windows_lexical_replay_preserves_path_semantics(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "CaseSensitiveDirectory"
    directory.mkdir()
    regular = directory / "Artifact.json"
    regular.write_text("fixture\n", encoding="utf-8")

    directory_rows = A._lexical_no_follow_chain(directory)
    file_rows = A._lexical_no_follow_chain(regular)
    missing_rows = A._lexical_no_follow_chain(
        directory / "missing" / "descendant.json"
    )
    assert directory_rows
    assert file_rows[-1][0] == str(regular)
    assert missing_rows == directory_rows

    with pytest.raises(ValueError, match="traversal-free"):
        A.canonical_artifact_identity(
            "scratchpad",
            "../outside.json",
        )
    with pytest.raises(
        A.ArtifactLedgerError,
        match="case/NFC alias",
    ):
        A._lexical_no_follow_chain(
            tmp_path / "casesensitivedirectory" / "Artifact.json"
        )

    link = tmp_path / "artifact-link.json"
    try:
        link.symlink_to(regular)
    except OSError as exc:
        pytest.skip(f"Windows symlink creation unavailable: {exc}")
    with pytest.raises(
        A.ArtifactLedgerError,
        match="symlink/reparse",
    ):
        A._lexical_no_follow_chain(link)


@pytest.mark.skipif(os.name != "nt", reason="Windows native FFI contract")
def test_windows_lexical_replay_is_concurrent_and_type_stable(
    tmp_path: Path,
) -> None:
    target = tmp_path / "parallel" / "artifact.json"
    target.parent.mkdir()
    target.write_text("fixture\n", encoding="utf-8")
    expected = A._lexical_no_follow_chain(target)
    gc.collect()
    before_types = set(ctypes.Structure.__subclasses__())

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                A._lexical_no_follow_chain,
                [target] * 256,
            )
        )

    assert results == [expected] * 256
    gc.collect()
    assert not (
        set(ctypes.Structure.__subclasses__()) - before_types
    )
