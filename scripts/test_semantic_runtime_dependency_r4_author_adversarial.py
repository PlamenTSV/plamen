"""Author reds for semantic runtime import-root provenance."""

from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import sys
from typing import Any

import pytest


SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import isolated_execution_host as H  # noqa: E402
import program_facts_types  # noqa: E402,F401
import worker_execution_receipts as W  # noqa: E402


def _resign(candidate: dict[str, Any]) -> dict[str, Any]:
    candidate["runtime_dependency_sha256"] = H._sha(
        {
            key: copy.deepcopy(value)
            for key, value in candidate.items()
            if key != "runtime_dependency_sha256"
        }
    )
    return candidate


def _unrelated_file_record() -> dict[str, Any]:
    path = Path(__file__).resolve(strict=True)
    raw = path.read_bytes()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }


def test_distribution_identity_must_descend_from_its_claimed_root() -> None:
    """A jointly resealed root set cannot detach identity from its owner."""

    binding, _paths = W._semantic_runtime_dependency_binding()
    candidate = copy.deepcopy(binding)
    unrelated_root = str(Path(__file__).resolve().parents[1])
    candidate["distributions"][0]["import_root"] = unrelated_root
    candidate["import_roots"] = sorted(
        {row["import_root"] for row in candidate["distributions"]},
        key=os.path.normcase,
    )

    with pytest.raises(
        H.IsolatedExecutionProtocolError,
        match="distribution.*identity|identity.*import root",
    ):
        H._validate_runtime_dependency_binding(_resign(candidate))


def test_external_module_file_must_descend_from_governed_import_root() -> None:
    """A self-consistent file record cannot move a dependency into the repo."""

    binding, _paths = W._semantic_runtime_dependency_binding()
    candidate = copy.deepcopy(binding)
    external = next(
        row
        for row in candidate["modules"]
        if row["module_name"].split(".", 1)[0]
        in {"attr", "attrs", "jsonschema", "referencing", "rpds"}
        and row["kind"] != "NAMESPACE_PACKAGE"
    )
    external.update(_unrelated_file_record())

    with pytest.raises(
        H.IsolatedExecutionProtocolError,
        match="external.*import root|module.*import root",
    ):
        H._validate_runtime_dependency_binding(_resign(candidate))
