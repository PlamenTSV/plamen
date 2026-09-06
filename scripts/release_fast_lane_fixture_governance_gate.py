"""Exact denominator governance for quarantined Temp/review fixtures.

This file is deliberately not named ``test_*.py``.  It is an explicit
governance gate and therefore cannot add itself to the production fast-lane
denominator it validates.
"""

from __future__ import annotations

import ast
import hashlib
import os
import tomllib
from collections import Counter
from pathlib import Path

from release_fast_lane_fixture_collector import (
    canonical_roster,
    load_manifest,
    validate_committed_roster,
    validate_sources,
)


REPO = Path(__file__).resolve().parent.parent
MANIFEST = Path(__file__).with_name(
    "release_fast_lane_fixture_governance_manifest.json"
)
PLAMEN_RUNTIME_ASSETS = (
    {
        "kind": "control",
        "mode": "file",
        "path": "scripts/release_fast_lane_fixture_governance_manifest.json",
    },
)
PREEXISTING_EXACT_RED_IGNORE = (
    "review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/"
    "test_crosscheck_schema_contracts_stdlib_v1_transport_totality_"
    "amendment_red.py"
)


def _node_manifest_sha256(nodes: list[str]) -> str:
    return hashlib.sha256(("\n".join(nodes) + "\n").encode()).hexdigest()


def _node_source(node_id: str) -> str:
    return node_id.split("::", 1)[0].replace("\\", "/")


def _contains_pytest_identity(path: Path) -> bool:
    """Conservatively recognize a source that can contribute a test node."""

    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError):
        return True
    return any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
        for node in ast.walk(tree)
    )


def _candidate_fixture_sources(root: Path) -> set[str]:
    rows: set[str] = set()
    for dirname in ("Temp", "review_fixtures"):
        base = root / dirname
        if not base.exists():
            continue
        pending = [base]
        visited_directories = 0
        visited_files = 0
        while pending:
            directory = pending.pop()
            visited_directories += 1
            if visited_directories > 20_000:
                raise AssertionError("fixture source directory bound exceeded")
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        raise AssertionError(f"aliased fixture source path: {entry.path}")
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    visited_files += 1
                    if visited_files > 20_000:
                        raise AssertionError("fixture source file bound exceeded")
                    path = Path(entry.path)
                    if not path.match("test*.py"):
                        continue
                    relative = path.relative_to(root).as_posix()
                    if relative == PREEXISTING_EXACT_RED_IGNORE:
                        continue
                    if _contains_pytest_identity(path):
                        rows.add(relative)
    return rows


def test_fixture_governance_manifest_and_default_quarantine_are_exact():
    payload = load_manifest(REPO, MANIFEST)
    assert payload["schema_version"] == (
        "plamen.release_fast_lane_fixture_governance.v2"
    )
    assert payload["authority"]["classification_audit"] == {
        "disposition": "COMPLETE_READ_ONLY_SOURCE_AND_GOVERNANCE_AUDIT",
        "evidence_policy": "HISTORICAL_HASH_ONLY_NON_DEREFERENCED",
        "sha256": "6b74d92bb9d378047976e8f75ceeba7c9b5063181b6476ac9c5782e818bc78f3",
    }
    assert payload["authority"]["classification_audit_r2"] == {
        "disposition": (
            "AMEND_ACCEPTED_R3_13_HISTORY_TO_CURRENT_ENVIRONMENT_BOUND_QUARANTINE"
        ),
        "evidence_policy": "HISTORICAL_HASH_ONLY_NON_DEREFERENCED",
        "sha256": "bdabe00016bda7920f9e5dff454f611ba11384b698828924881284be7520e9d6",
    }
    assert payload["authority"]["partition_plan"] == {
        "evidence_policy": "HISTORICAL_HASH_ONLY_NON_DEREFERENCED",
        "sha256": "a0e951c3585c73faa4ebf0e037ee34733b3ef2d5e6049bb58efcf25e51ee640e",
    }
    assert payload["authority"]["post_collection_repair"] == {
        "disposition": "REPAIR",
        "evidence_policy": "HISTORICAL_HASH_ONLY_NON_DEREFERENCED",
        "sha256": "73868382f8edfe38b448ea3e2ceac2fb47f7e038d2c77fbd0c0f383a497792d5",
    }

    rows = payload["files"]
    paths = validate_sources(payload, REPO)
    assert len(rows) == len(set(paths)) == 72
    selected_nodes, selected_digest = validate_committed_roster(payload, paths)
    assert len(selected_nodes) == len(set(selected_nodes)) == 1036
    assert selected_digest == (
        "9b746138049fdea6fe73a1a6b3101b407a0302b522997bfdd403c0919effc4ac"
    )
    historical = payload["authority"]["historical_selected_fast_manifest"]
    assert historical == {
        "disposition": "HISTORICAL_HASH_ONLY_NON_DEREFERENCED_ACCOUNTING",
        "node_count": 16337,
        "sha256": "a3e385de5e8106552f898f42b4deb8cf91697292ef3c49864b1d488a9467f172",
    }

    source_counts = Counter(row["class"] for row in rows)
    node_counts = Counter()
    for row in rows:
        node_counts[row["class"]] += row["node_count"]
        control = payload["controls"][row["control_id"]]
        if row["class"] == "UNGOVERNED":
            assert row["control_id"] == "U-NONE"
            assert control["artifact_sha256"] == []
        else:
            assert control["artifact_sha256"]
        assert control["disposition"]
    for classification, expected in payload["classification_totals"].items():
        assert source_counts[classification] == expected["source_count"]
        assert node_counts[classification] == expected["node_count"]
        classified_paths = {
            row["path"] for row in rows if row["class"] == classification
        }
        classified_nodes = [
            node for node in selected_nodes if _node_source(node) in classified_paths
        ]
        assert len(classified_nodes) == expected["node_count"]
        assert _node_manifest_sha256(classified_nodes) == (
            expected["node_manifest_sha256"]
        )
    assert source_counts == {
        "ACCEPT_GREEN": 8,
        "ACCEPTED_HISTORICAL_ENVIRONMENT_BOUND_QUARANTINE": 2,
        "HISTORICAL_RED_EXPECTED_DEBT": 18,
        "REPAIR_NONINSTALLED": 37,
        "UNGOVERNED": 7,
    }
    assert node_counts == {
        "ACCEPT_GREEN": 199,
        "ACCEPTED_HISTORICAL_ENVIRONMENT_BOUND_QUARANTINE": 19,
        "HISTORICAL_RED_EXPECTED_DEBT": 254,
        "REPAIR_NONINSTALLED": 450,
        "UNGOVERNED": 114,
    }
    assert {
        row["path"]
        for row in rows
        if row["class"]
        == "ACCEPTED_HISTORICAL_ENVIRONMENT_BOUND_QUARANTINE"
    } == {
        "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/"
        "r3_13_windows_native_candidate/test_r3_13_launcher_green.py",
        "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/"
        "r3_13_windows_native_candidate/test_r3_13_windows_native_green.py",
    }

    accounting = payload["accounting"]
    assert accounting["original_selected_fast"] == (
        accounting["production_default_fast"]
        + accounting["accepted_fixture_nodes"]
        + accounting["debt_quarantine_nodes"]
    ) == 16337
    assert accounting["accepted_fixture_nodes"] == 199
    assert accounting["debt_quarantine_nodes"] == 837
    assert accounting["integration_nodes"] == 585

    fixture_totals = payload["fixture_totals"]
    fixture_paths = set(paths)
    fixture_nodes = [
        node for node in selected_nodes if _node_source(node) in fixture_paths
    ]
    assert len(fixture_nodes) == fixture_totals["node_count"] == 1036
    assert _node_manifest_sha256(fixture_nodes) == (
        fixture_totals["node_manifest_sha256"]
    )
    quarantined_paths = {
        row["path"] for row in rows if row["class"] != "ACCEPT_GREEN"
    }
    quarantined_nodes = [
        node for node in selected_nodes if _node_source(node) in quarantined_paths
    ]
    assert len(quarantined_nodes) == (
        fixture_totals["current_quarantine_and_debt_node_count"]
    ) == 837
    assert _node_manifest_sha256(quarantined_nodes) == (
        fixture_totals["current_quarantine_and_debt_node_manifest_sha256"]
    )

    config = tomllib.loads((REPO / "pyproject.toml").read_text("utf-8"))
    addopts = config["tool"]["pytest"]["ini_options"]["addopts"]
    assert "--ignore=Temp" in addopts
    assert "--ignore=review_fixtures" in addopts
    assert f"--ignore={PREEXISTING_EXACT_RED_IGNORE}" in addopts

    # Root quarantine is discovery policy, not deletion. All governed paths
    # must remain present and explicit-target invocable.
    assert all((REPO / path).is_file() for path in paths)
    unknown = _candidate_fixture_sources(REPO) - set(paths)
    assert unknown == set(), f"unclassified fixture test sources: {sorted(unknown)}"


def test_unknown_fixture_source_is_rejected_by_the_governance_model(tmp_path):
    unknown = tmp_path / "Temp" / "new_candidate" / "test_unknown.py"
    unknown.parent.mkdir(parents=True)
    unknown.write_text("def test_unclassified():\n    assert True\n", "utf-8")
    discovered = _candidate_fixture_sources(tmp_path)
    assert discovered == {"Temp/new_candidate/test_unknown.py"}
    governed: set[str] = set()
    assert discovered - governed


def test_committed_fixture_roster_is_source_exact_and_canonical():
    payload = load_manifest(REPO, MANIFEST)
    paths = validate_sources(payload, REPO)
    nodes, digest = validate_committed_roster(payload, paths)
    assert hashlib.sha256(canonical_roster(nodes)).hexdigest() == digest
    assert {_node_source(node) for node in nodes} == set(paths)
