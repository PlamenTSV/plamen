"""Windows private execution-root long-path restoration regression."""

from __future__ import annotations

import os
from pathlib import Path
import shutil

import pytest

import windows_private_execution_root as private_root


@pytest.mark.skipif(os.name != "nt", reason="Windows integrity labels only")
def test_restore_medium_integrity_enumerates_extended_length_members(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "private-parent"
    parent.mkdir()
    root = parent / "runtime-home"
    authority = private_root.create_windows_private_execution_root(root)
    closed = False
    try:
        authority.lower_to_low_integrity()
        deep = root
        while len(str(deep / "payload.bin")) <= 300:
            deep /= "codex-plugin-cache-segment-0123456789"
        os.makedirs(private_root._native_path(deep))
        payload = deep / "payload.bin"
        with open(private_root._native_path(payload), "wb") as stream:
            stream.write(b"fixture")

        authority.restore_medium_integrity_tree()
        authority.close_after_medium_restore()
        closed = True
        assert os.path.isfile(private_root._native_path(payload))
    finally:
        if not closed:
            try:
                authority.restore_medium_integrity_tree()
                authority.close_after_medium_restore()
            except Exception:
                pass
        if os.path.lexists(private_root._native_path(root)):
            shutil.rmtree(private_root._native_path(root))
