"""Fixture-first REDs for the frozen PhaseIO all-I/O ratchet (Cut 5).

The ratchet is evidence, never publication authority.  The fixtures require a
source-roster-pinned AST inventory, a reviewer-owned classification join, and
a runtime observer/tree-diff that fails unknown authoritative mutations.
They intentionally exclude the independent review's later hardening backlog.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parent

SEMANTIC_CLASSES = {
    "READ_VALIDATED_AUTHORITY",
    "READ_DECISION_UNVALIDATED",
    "WRITE_AUTHORITATIVE",
    "WRITE_COMPATIBILITY",
    "WRITE_DERIVED_CACHE",
    "WRITE_ADDITIVE_TELEMETRY",
    "WRITE_TRANSIENT_OPERATIONAL",
    "WRITE_EXTERNAL_PROJECT",
    "DEAD_UNREACHABLE",
}


def _load_required_module(filename: str, module_name: str):
    path = SCRIPTS / filename
    assert path.is_file(), f"missing frozen all-I/O ratchet module: {filename}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_static_inventory_pins_exact_source_roster_and_aggregate_digest(
    tmp_path: Path,
) -> None:
    module = _load_required_module(
        "phaseio_boundary_inventory.py",
        "_phaseio_boundary_inventory_red_roster",
    )
    build = getattr(module, "build_phaseio_boundary_inventory", None)
    assert callable(build)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    first = scripts / "first.py"
    second = scripts / "second.py"
    first.write_text(
        "from pathlib import Path as P\n"
        "def write(root):\n"
        "    (P(root) / 'semantic.json').write_text('{}')\n",
        encoding="utf-8",
    )
    second.write_text(
        "def read(path):\n"
        "    return path.read_bytes()\n",
        encoding="utf-8",
    )

    payload = build(scripts)
    roster = payload["source_roster"]
    assert [row["path"] for row in roster] == ["first.py", "second.py"]
    assert [row["sha256"] for row in roster] == [_sha(first), _sha(second)]
    expected_aggregate = hashlib.sha256(
        json.dumps(
            roster,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert payload["source_roster_sha256"] == expected_aggregate


def test_static_inventory_detects_aliases_and_rejects_unclassified_io(
    tmp_path: Path,
) -> None:
    module = _load_required_module(
        "phaseio_boundary_inventory.py",
        "_phaseio_boundary_inventory_red_alias",
    )
    build = getattr(module, "build_phaseio_boundary_inventory", None)
    validate = getattr(module, "validate_phaseio_boundary_inventory", None)
    assert callable(build) and callable(validate)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "aliased.py").write_text(
        "from pathlib import Path as P\n"
        "def publish(root):\n"
        "    out = P(root) / 'findings_inventory.md'\n"
        "    out.write_text('changed')\n",
        encoding="utf-8",
    )

    payload = build(scripts)
    rows = payload["rows"]
    assert any(
        row["operation"] == "write_text"
        and row["module"] == "aliased.py"
        and row["owner"] == "publish"
        for row in rows
    )
    issues = validate(payload, expected_classifications={})
    assert any("unclassified" in issue.lower() for issue in issues)


def test_static_rows_have_closed_schema_and_stable_ast_fingerprint(
    tmp_path: Path,
) -> None:
    module = _load_required_module(
        "phaseio_boundary_inventory.py",
        "_phaseio_boundary_inventory_red_schema",
    )
    build = getattr(module, "build_phaseio_boundary_inventory", None)
    assert callable(build)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    source = scripts / "sample.py"
    source.write_text(
        "def consume(path):\n"
        "    return path.read_text()\n",
        encoding="utf-8",
    )
    first = build(scripts)
    source.write_text(
        "\n\n"
        "def consume(path):\n"
        "    return path.read_text()\n",
        encoding="utf-8",
    )
    second = build(scripts)
    first_row = first["rows"][0]
    second_row = second["rows"][0]

    required = {
        "module",
        "owner",
        "operation",
        "target_root",
        "target_pattern",
        "reachability",
        "required_authority",
        "semantic_class",
        "ast_fingerprint",
        "source_sha256",
    }
    assert required.issubset(first_row)
    assert first_row["ast_fingerprint"] == second_row["ast_fingerprint"]
    assert first_row["source_sha256"] != second_row["source_sha256"]
    assert first_row["semantic_class"] in SEMANTIC_CLASSES | {"UNCLASSIFIED"}


def test_runtime_observer_tree_diff_rejects_unknown_authoritative_mutation(
    tmp_path: Path,
) -> None:
    module = _load_required_module(
        "phaseio_runtime_io_observer.py",
        "_phaseio_runtime_io_observer_red_unknown",
    )
    snapshot = getattr(module, "snapshot_io_tree", None)
    reconcile = getattr(module, "reconcile_observed_io", None)
    assert callable(snapshot) and callable(reconcile)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    before = snapshot(scratch)
    (scratch / "findings_inventory.md").write_text(
        "# changed outside authority\n", encoding="utf-8"
    )
    after = snapshot(scratch)

    issues = reconcile(
        before=before,
        after=after,
        observations=(),
        active_artifact_outputs=(),
        active_semantic_mutations=(),
        active_custom_transactions=(),
        explicit_nonsemantic_allowlist=(),
    )
    assert any(
        "findings_inventory.md" in issue
        and any(token in issue.lower() for token in ("unknown", "authority"))
        for issue in issues
    )


def test_runtime_observer_is_process_scoped_evidence_not_authority() -> None:
    module = _load_required_module(
        "phaseio_runtime_io_observer.py",
        "_phaseio_runtime_io_observer_red_boundary",
    )
    source = inspect_source = (SCRIPTS / "phaseio_runtime_io_observer.py").read_text(
        encoding="utf-8", errors="strict"
    )
    assert "ContextVar" in inspect_source
    assert "addaudithook" in inspect_source
    assert not any(
        name in source
        for name in (
            "record_work_unit_artifacts(",
            "finalize_semantic_mutation(",
            "authorize_exact_committed_output_repair(",
        )
    )
    assert getattr(module, "OBSERVER_IS_AUTHORITY", False) is False
