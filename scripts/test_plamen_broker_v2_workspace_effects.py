"""Darwin/POSIX native workspace-effect integration tests."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "native" / "darwin" / "plamen_broker_v2_workspace_effects.c"
HEADER = ROOT / "native" / "darwin" / "plamen_broker_v2_workspace_effects.h"
TEST = ROOT / "native" / "tests" / "plamen_broker_v2_workspace_effects_test.c"
PROTOCOL = ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"


def _compiler() -> str:
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if compiler is None:
        pytest.skip("a C11 compiler is required")
    return compiler


@pytest.fixture(scope="module")
def workspace_peer(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("workspace-effects") / "workspace-effects-test"
    command = [
        _compiler(), "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
        "-Wno-deprecated-declarations",
        "-I", os.fspath(ROOT / "native" / "include"),
        "-I", os.fspath(ROOT / "native" / "posix"),
        "-I", os.fspath(ROOT / "native" / "darwin"),
        os.fspath(TEST), os.fspath(SOURCE), os.fspath(PROTOCOL),
        "-o", os.fspath(output),
    ]
    if sys.platform.startswith("linux"):
        command.append("-lcrypto")
    subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return output


def test_workspace_effects_real_descriptor_relative_lifecycle(
    workspace_peer: Path, tmp_path: Path,
) -> None:
    completed = subprocess.run(
        [os.fspath(workspace_peer), os.fspath(tmp_path)],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    workspaces = list((tmp_path / "state").glob("workspace-*"))
    assert len(workspaces) == 1
    workspace = workspaces[0]
    assert (workspace / "merged" / "Main.sol").read_text() == "contract Main {}\n"
    assert (workspace / "control" / "config.json").is_file()
    assert (workspace / "layout.receipt").is_file()
    assert (workspace / "precreate-recensus.receipt").is_file()
    assert (workspace / "postcreate-recensus.receipt").is_file()
    assert (workspace / "control" / "config.receipt").is_file()
    assert not (tmp_path / "project" / "code" / ".scratchpad").exists()


def test_workspace_effects_source_is_closed_and_bounded() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    assert "openat(" in source and "O_NOFOLLOW" in source
    assert "TREE_MAX_DEPTH" in source and "TREE_MAX_TOTAL_SIZE" in source
    assert "fsync(" in source and "renameat(" in source
    assert "getenv(" not in source and "system(" not in source
    assert "authority_fds is" not in header  # stale aggregate ownership wording
    assert "never consumes, closes, or changes the caller's entries" in header


def test_workspace_effects_strict_c11_and_analyzer() -> None:
    base = [
        _compiler(), "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
        "-I", os.fspath(ROOT / "native" / "include"),
        "-I", os.fspath(ROOT / "native" / "darwin"),
    ]
    subprocess.run(base + ["-fsyntax-only", os.fspath(SOURCE)], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if sys.platform == "darwin" and "clang" in Path(_compiler()).name:
        subprocess.run(
            base + ["--analyze", "-Xanalyzer", "-analyzer-output=text",
                    os.fspath(SOURCE)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
