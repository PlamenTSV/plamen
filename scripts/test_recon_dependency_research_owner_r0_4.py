"""R0-4: conditional recon research owner plus deterministic row parity."""
from __future__ import annotations

import json
from pathlib import Path

import dependency_obligations as O
import plamen_driver as D


def _base(root: Path) -> Path:
    root.mkdir(parents=True)
    return root


def test_evm_nonlocal_import_becomes_research_obligation(tmp_path):
    root = _base(tmp_path / "evm")
    (root / "src").mkdir()
    (root / "src" / "Entry.sol").write_text(
        'import {Remote} from "@scope/library/Remote.sol";\ncontract Entry {}\n'
    )
    result = O.enumerate_dependency_obligations(root, {"language": "evm"})
    assert any(row["dependency"] == "@scope/library" for row in result["obligations"])
    assert all(row["source_location"].startswith("src/Entry.sol:L") for row in result["obligations"])


def test_rust_and_go_only_enumerate_direct_dependencies_used_by_source(tmp_path):
    root = _base(tmp_path / "l1")
    (root / "src").mkdir()
    (root / "src" / "lib.rs").write_text("use used_crate::Client;\n")
    (root / "Cargo.toml").write_text(
        '[dependencies]\nused-crate = "1"\nunused-crate = "2"\nlocal = { path = "../local" }\n'
    )
    (root / "main.go").write_text(
        'package main\nimport (\n "example.org/used/pkg"\n)\n'
    )
    (root / "go.mod").write_text(
        "module local\nrequire (\n example.org/used v1.2.3\n example.org/unused v1.0.0\n)\n"
    )
    result = O.enumerate_dependency_obligations(
        root, {"pipeline": "l1", "language": "rust"}
    )
    names = {row["dependency"] for row in result["obligations"]}
    assert {"used-crate", "example.org/used"} <= names
    assert "unused-crate" not in names and "example.org/unused" not in names
    assert "local" not in names


def test_move_and_daml_manifests_are_provider_backed(tmp_path):
    root = _base(tmp_path / "mixed")
    (root / "sources").mkdir()
    (root / "sources" / "m.move").write_text("module 0x1::m {}\n")
    (root / "Move.toml").write_text(
        '[package]\nname="m"\n[dependencies]\nRemote = { git = "https://example.invalid/r" }\nLocal = { local = "../local" }\n'
    )
    (root / "Main.daml").write_text("module Main where\n")
    (root / "daml.yaml").write_text(
        "sdk-version: 1\ndependencies:\n  - daml-prim\n"
    )
    result = O.enumerate_dependency_obligations(root, {"language": "daml"})
    names = {row["dependency"] for row in result["obligations"]}
    assert "Remote" in names and "Local" not in names and "daml-prim" in names


def test_fetch_failure_or_missing_worker_never_produces_empty_ledger(tmp_path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    obligations = {
        "schema": O.SCHEMA,
        "obligations": [
            O._row("source-import", "remote-a", "src/A.sol:L1", "import"),
            O._row("cargo-direct", "remote-b", "Cargo.toml:L2", "1.0"),
        ],
        "observed_count": 2,
        "retained_count": 2,
        "truncated": False,
        "overflow_ids": [],
    }
    result = O.reconcile_dependency_research_ledger(
        scratchpad, obligations, worker_text=""
    )
    ledger = (scratchpad / "external_dependency_research.md").read_text()
    assert result["unresolved"] == 2
    assert ledger.count("NEEDS_DEPENDENCY_RESEARCH") >= 2
    ok, issues = O.validate_dependency_ledger_parity(obligations, ledger)
    assert ok and issues == []
    assert (scratchpad / "report_semantic_dependency_research.md").exists()


def test_research_overlay_requires_source_and_preserves_failed_row(tmp_path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    first = O._row("source-import", "remote-a", "src/A.sol:L1", "import")
    second = O._row("cargo-direct", "remote-b", "Cargo.toml:L2", "1.0")
    obligations = {
        "obligations": [first, second],
        "observed_count": 2,
        "retained_count": 2,
        "truncated": False,
    }
    worker = (
        "| Obligation ID | Dependency | Integration Surface | Assumed Behavior | Real Behavior | Source | Conformance | Fetch Status |\n"
        "|---|---|---|---|---|---|---|---|\n"
        f"| {first['obligation_id']} | remote-a | src/A.sol:L1 | stable | documented behavior | https://docs.invalid/a | MATCH | RESEARCHED |\n"
        f"| {second['obligation_id']} | remote-b | Cargo.toml:L2 | stable | - | - | UNKNOWN | FETCH_FAILED |\n"
    )
    result = O.reconcile_dependency_research_ledger(
        scratchpad, obligations, worker_text=worker
    )
    ledger = (scratchpad / "external_dependency_research.md").read_text()
    assert result["researched"] == 1 and result["unresolved"] == 1
    assert "FETCH_FAILED" in ledger


def test_external_research_is_conditional_wave_not_fifth_base_worker(tmp_path):
    assert "external_dependency_research" not in {
        job["role"] for job in D._recon_worker_jobs({"mode": "thorough"})
    }
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    prompt = D._build_recon_worker_prompt(
        job={
            "agent_id": "R-EXT",
            "role": "external_dependency_research",
            "output": "recon_external_dependency_research.md",
            "focus": "research",
        },
        scratchpad=scratchpad,
        project_root=str(tmp_path),
        config={"language": "evm", "mode": "thorough", "pipeline": "sc"},
        attempt=1,
    )
    assert "external_dependency_obligations.json" in prompt
    assert "do not retry" in prompt.lower()
    assert "Preserve each supplied Obligation ID exactly" in prompt


def test_backend_independent_parity_fallback_writes_obligations(tmp_path):
    project = _base(tmp_path / "project")
    (project / "src").mkdir()
    (project / "src" / "A.sol").write_text('import "pkg/A.sol";\ncontract A {}\n')
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    result = D._ensure_recon_dependency_parity(
        scratchpad, str(project), {"language": "evm", "pipeline": "sc"}
    )
    data = json.loads((scratchpad / "external_dependency_obligations.json").read_text())
    assert data["obligations"]
    assert result["unresolved"] >= 1
