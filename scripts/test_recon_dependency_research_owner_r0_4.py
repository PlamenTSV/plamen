"""R0-4: conditional recon research owner plus deterministic row parity."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

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
        config={
            "language": "evm",
            "mode": "thorough",
            "pipeline": "sc",
            "project_root": str(tmp_path),
            "scratchpad": str(scratchpad),
        },
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
    config = {
        "language": "evm",
        "pipeline": "sc",
        "mode": "core",
        "cli_backend": "codex",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": "dependency-parity-fixture",
        "run_id": "dependency-parity-fixture",
    }
    result = D._ensure_recon_dependency_parity(
        scratchpad, str(project), config
    )
    data = json.loads((scratchpad / "external_dependency_obligations.json").read_text())
    assert data["obligations"]
    assert result["unresolved"] >= 1


def test_vendored_trees_are_pruned_before_descent_and_do_not_change_authority(
    tmp_path, monkeypatch
):
    project = _base(tmp_path / "project")
    (project / "src").mkdir()
    (project / "src" / "A.sol").write_text(
        'import "@scope/library/A.sol";\ncontract A {}\n'
    )
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    config = {
        "language": "evm",
        "pipeline": "sc",
        "mode": "core",
        "cli_backend": "codex",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": "dependency-pruning-fixture",
        "run_id": "dependency-pruning-fixture",
    }

    baseline_obligations = O.enumerate_dependency_obligations(project, config)
    baseline_authority = D._dependency_authority_payload(
        config=config,
        kind="OBLIGATIONS",
        obligations=baseline_obligations,
    )

    for excluded in ("node_modules", "vendor", "target"):
        nested = project / excluded / "package" / "nested"
        nested.mkdir(parents=True)
        (nested / "Hidden.sol").write_text('import "hidden/pkg.sol";\n')
        (nested / "Cargo.toml").write_text(
            '[dependencies]\nhidden-crate = "1"\n'
        )
        (nested / "go.mod").write_text(
            "module hidden\nrequire hidden.example/pkg v1.0.0\n"
        )
        (nested / "Move.toml").write_text(
            '[dependencies]\nHidden = { git = "https://example.invalid/hidden" }\n'
        )
        (nested / "daml.yaml").write_text(
            "dependencies:\n  - hidden-daml\n"
        )

    real_scandir = O.os.scandir
    excluded_names = {"node_modules", "vendor", "target"}
    visited: list[str] = []

    def explode_on_vendored_descent(directory):
        relative = Path(directory).relative_to(project)
        if any(part.casefold() in excluded_names for part in relative.parts):
            raise AssertionError(f"walk descended into excluded tree: {relative}")
        visited.append(relative.as_posix())
        return real_scandir(directory)

    monkeypatch.setattr(O.os, "scandir", explode_on_vendored_descent)
    census = O.collect_unvendored_files(project)
    obligations = O.enumerate_dependency_obligations(
        project, config, admitted_files=census
    )
    authority = D._dependency_authority_payload(
        config=config,
        kind="OBLIGATIONS",
        obligations=obligations,
        admitted_files=census,
    )

    assert obligations == baseline_obligations
    assert authority == baseline_authority
    assert visited


def test_dependency_census_prunes_all_plamen_runtime_roots_before_descent(
    tmp_path, monkeypatch
):
    project = _base(tmp_path / "project")
    (project / "src").mkdir()
    source = project / "src" / "Entry.sol"
    source.write_text('import "remote/pkg.sol";\ncontract Entry {}\n')
    runtime_roots = (
        project / ".scratchpad-rerun-codex-20260905",
        project / ".ScratchPad-Interrupted",
        project / ".plamen-stale-snapshots-20260905",
    )
    for runtime_root in runtime_roots:
        receipt = runtime_root / "_auxiliary_writable_root_startup_receipts"
        receipt.mkdir(parents=True)
        (receipt / "runtime.json").write_text("runtime-only")

    real_scandir = O.os.scandir

    def reject_runtime_descent(directory):
        relative = Path(directory).relative_to(project)
        if relative.parts and relative.parts[0].casefold().startswith(
            (".scratchpad", ".plamen-stale-snapshots")
        ):
            raise AssertionError(f"walk descended into runtime tree: {relative}")
        return real_scandir(directory)

    monkeypatch.setattr(O.os, "scandir", reject_runtime_descent)
    census = O.collect_unvendored_files(project)

    assert census.files == (source,)


def test_dependency_census_rejects_file_links_and_directory_reparses(tmp_path):
    project = _base(tmp_path / "project")
    (project / "src").mkdir()
    (project / "src" / "Entry.sol").write_text(
        'import "safe/pkg.sol";\ncontract Entry {}\n'
    )
    outside = _base(tmp_path / "outside")
    (outside / "Escape.sol").write_text(
        "interface IEscape { function read() external returns (uint256); }\n"
        "contract EscapeCaller { function call(address a) external { "
        "IEscape(a).read(); } }\n"
    )
    (outside / "Cargo.toml").write_text(
        '[dependencies]\nescaped-crate = "1"\n'
    )

    file_link = project / "src" / "Escape.sol"
    try:
        file_link.symlink_to(outside / "Escape.sol")
    except OSError as exc:
        pytest.skip(f"file symlink creation is unavailable: {exc}")

    directory_link = project / "linked-outside"
    if os.name == "nt":
        created = subprocess.run(
            ["cmd", "/d", "/c", "mklink", "/J", str(directory_link), str(outside)],
            check=False,
            capture_output=True,
            text=True,
        )
        if created.returncode != 0:
            pytest.skip(f"junction creation is unavailable: {created.stderr}")
    else:
        directory_link.symlink_to(outside, target_is_directory=True)

    config = {
        "language": "evm",
        "pipeline": "sc",
        "mode": "core",
        "cli_backend": "codex",
        "project_root": str(project),
        "scratchpad": str(project / ".scratchpad"),
        "_run_id": "dependency-link-fixture",
    }
    (project / ".scratchpad").mkdir()
    obligations = O.enumerate_dependency_obligations(project, config)
    authority = D._dependency_authority_payload(
        config=config,
        kind="OBLIGATIONS",
        obligations=obligations,
    )

    assert {row["dependency"] for row in obligations["obligations"]} == {"safe"}
    assert [row["path"] for row in authority["source_rows"]] == ["src/Entry.sol"]
    assert file_link not in O.collect_unvendored_files(project)
    assert not any(
        path.is_relative_to(directory_link)
        for path in O.collect_unvendored_files(project)
    )


@pytest.mark.parametrize(
    ("limit_name", "limit", "layout", "expected_code"),
    (
        ("MAX_TRAVERSAL_DIRECTORIES", 1, "directory", "DIRECTORY_LIMIT"),
        ("MAX_TRAVERSAL_FILES", 1, "files", "FILE_LIMIT"),
        ("MAX_TRAVERSAL_BYTES", 3, "bytes", "BYTE_LIMIT"),
    ),
)
def test_dependency_census_bounds_fail_closed_with_typed_debt(
    tmp_path, monkeypatch, limit_name, limit, layout, expected_code
):
    project = _base(tmp_path / "project")
    if layout == "directory":
        (project / "src").mkdir()
    elif layout == "files":
        (project / "A.sol").write_text("a")
        (project / "B.sol").write_text("b")
    else:
        (project / "A.sol").write_text("four")
    monkeypatch.setattr(O, limit_name, limit)
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()

    with pytest.raises(O.DependencyTraversalError) as caught:
        O.write_dependency_obligations(
            scratchpad, project, {"language": "evm"}
        )

    assert caught.value.code == expected_code
    assert caught.value.observed > caught.value.limit
    assert not (scratchpad / "external_dependency_obligations.json").exists()


def test_dependency_census_rejects_non_nfc_path_names(tmp_path):
    project = _base(tmp_path / "project")
    (project / "e\u0301.sol").write_text("contract E {}\n")

    with pytest.raises(O.DependencyTraversalError) as caught:
        O.collect_unvendored_files(project)

    assert caught.value.code == "UNSAFE_NAME"


def test_dependency_census_rejects_case_aliases_where_supported(tmp_path):
    project = _base(tmp_path / "project")
    (project / "Alpha.sol").write_text("contract Alpha {}\n")
    (project / "alpha.sol").write_text("contract alpha {}\n")
    if len({entry.name for entry in os.scandir(project)}) < 2:
        pytest.skip("filesystem does not support case-distinct aliases")

    with pytest.raises(O.DependencyTraversalError) as caught:
        O.collect_unvendored_files(project)

    assert caught.value.code == "NAME_ALIAS"


def test_dependency_enumeration_rejects_project_root_link_or_junction(tmp_path):
    target = _base(tmp_path / "actual-project")
    (target / "src").mkdir()
    (target / "src" / "Entry.sol").write_text(
        'import "outside/pkg.sol";\ncontract Entry {}\n'
    )
    alias = tmp_path / "project-alias"
    if os.name == "nt":
        created = subprocess.run(
            ["cmd", "/d", "/c", "mklink", "/J", str(alias), str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if created.returncode != 0:
            pytest.skip(f"junction creation is unavailable: {created.stderr}")
    else:
        alias.symlink_to(target, target_is_directory=True)

    with pytest.raises(O.DependencyTraversalError) as caught:
        O.enumerate_dependency_obligations(
            alias,
            {"language": "evm", "project_root": str(alias)},
        )

    assert caught.value.code == "UNSAFE_ROOT"


def test_dependency_authority_binds_same_path_root_object_identity(tmp_path):
    project = _base(tmp_path / "project")
    (project / "src").mkdir()
    source_bytes = b'import "remote/pkg.sol";\ncontract Entry {}\n'
    (project / "src" / "Entry.sol").write_bytes(source_bytes)
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    config = {
        "language": "evm",
        "pipeline": "sc",
        "mode": "core",
        "cli_backend": "codex",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": "dependency-root-identity-fixture",
        "run_id": "dependency-root-identity-fixture",
    }
    first_obligations = O.enumerate_dependency_obligations(project, config)
    first = D._dependency_authority_payload(
        config=config,
        kind="OBLIGATIONS",
        obligations=first_obligations,
    )

    retained_original = tmp_path / "retained-original"
    project.rename(retained_original)
    project.mkdir()
    (project / "src").mkdir()
    (project / "src" / "Entry.sol").write_bytes(source_bytes)
    second_obligations = O.enumerate_dependency_obligations(project, config)
    second = D._dependency_authority_payload(
        config=config,
        kind="OBLIGATIONS",
        obligations=second_obligations,
    )

    assert first_obligations == second_obligations
    assert first["source_rows"] == second["source_rows"]
    assert first["project_root"] == second["project_root"]
    assert first["project_root_identity"] != second["project_root_identity"]
    assert first["authority_sha256"] != second["authority_sha256"]
    with pytest.raises(D.ArtifactLedgerError):
        D._validate_current_dependency_authority(
            first,
            config=config,
            kind="OBLIGATIONS",
        )


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    (
        ("partial", "ROSTER_MISMATCH"),
        ("extra", "ROSTER_MISMATCH"),
        ("reordered", "ROSTER_ORDER"),
    ),
)
def test_dependency_admitted_roster_must_equal_complete_census(
    tmp_path,
    mutation,
    expected_code,
):
    project = _base(tmp_path / "project")
    (project / "src").mkdir()
    (project / "src" / "A.sol").write_text(
        'import "remote/a.sol";\ncontract A {}\n'
    )
    (project / "src" / "B.sol").write_text("contract B {}\n")
    (project / "Cargo.toml").write_text(
        '[dependencies]\nremote-crate = "1"\n'
    )
    census = O.collect_unvendored_files(project)
    assert len(census) == 3
    if mutation == "partial":
        injected = census.files[:1]
    elif mutation == "extra":
        outside = tmp_path / "outside.sol"
        outside.write_text("contract Outside {}\n")
        injected = (*census.files, outside)
    else:
        injected = tuple(reversed(census.files))
    config = {
        "language": "evm",
        "pipeline": "sc",
        "mode": "core",
        "cli_backend": "codex",
        "project_root": str(project),
        "scratchpad": str(tmp_path / "scratchpad"),
        "_run_id": "dependency-roster-injection-fixture",
    }

    with pytest.raises(O.DependencyTraversalError) as caught:
        O.enumerate_dependency_obligations(
            project,
            config,
            admitted_files=injected,
        )
    assert caught.value.code == expected_code

    obligations = O.enumerate_dependency_obligations(project, config)
    with pytest.raises(O.DependencyTraversalError) as caught:
        D._dependency_authority_payload(
            config=config,
            kind="OBLIGATIONS",
            obligations=obligations,
            admitted_files=injected,
        )
    assert caught.value.code == expected_code
