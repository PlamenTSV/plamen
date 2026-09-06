"""Author red fixtures for semantic runtime distribution provenance."""

from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import sys
from typing import Any, Callable

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


def _must_reject(mutate: Callable[[dict[str, Any]], None]) -> None:
    binding, _paths = W._semantic_runtime_dependency_binding()
    candidate = copy.deepcopy(binding)
    mutate(candidate)
    with pytest.raises(
        H.IsolatedExecutionProtocolError,
        match=(
            "distribution|metadata|record|module|origin|identity|"
            "version|kind|prefix|root"
        ),
    ):
        H._validate_runtime_dependency_binding(_resign(candidate))


def _file_record(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    raw = resolved.read_bytes()
    return {
        "path": str(resolved),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }


def test_distribution_name_must_replay_from_metadata() -> None:
    def forge_name(binding: dict[str, Any]) -> None:
        row = next(
            item
            for item in binding["distributions"]
            if item["distribution_name"] == "attrs"
        )
        row["distribution_name"] = "attrs-forged"
        binding["distributions"].sort(
            key=lambda item: item["distribution_name"]
        )

    _must_reject(forge_name)


def test_record_owned_stub_cannot_replace_exact_module_origin() -> None:
    """A RECORD-owned .pyi is not the import origin of ``attr``."""

    def substitute_stub(binding: dict[str, Any]) -> None:
        row = next(
            item
            for item in binding["modules"]
            if item["module_name"] == "attr"
        )
        stub = Path(row["path"]).with_suffix(".pyi")
        row.update(_file_record(stub))

    _must_reject(substitute_stub)


def test_extension_binary_cannot_be_relabelled_as_python_source() -> None:
    def relabel_kind(binding: dict[str, Any]) -> None:
        row = next(
            item
            for item in binding["modules"]
            if item["kind"] == "EXTENSION_BINARY"
        )
        row["kind"] = "PYTHON_SOURCE"

    _must_reject(relabel_kind)


def test_external_top_level_prefix_case_alias_is_not_a_new_module() -> None:
    def case_alias(binding: dict[str, Any]) -> None:
        row = next(
            item
            for item in binding["modules"]
            if item["module_name"] == "attr"
        )
        row["module_name"] = "Attr"
        binding["modules"].sort(key=lambda item: item["module_name"])

    _must_reject(case_alias)


def test_distribution_root_cannot_move_to_a_nested_prefix_alias() -> None:
    def nested_root(binding: dict[str, Any]) -> None:
        row = binding["distributions"][0]
        current = Path(row["import_root"]).resolve(strict=True)
        nested = next(
            path.parent
            for path in (
                Path(item["path"]).resolve(strict=True)
                for item in row["identity_files"]
            )
            if current in path.parents
        )
        row["import_root"] = str(nested)
        binding["import_roots"] = sorted(
            {item["import_root"] for item in binding["distributions"]},
            key=os.path.normcase,
        )

    _must_reject(nested_root)
