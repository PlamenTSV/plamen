from __future__ import annotations

import json
from pathlib import Path

import pytest

import audit_snapshot as snapshot
import plamen_mechanical as mechanical
import plamen_validators as validators
from plamen_parsers import _load_scope_file_paths, _path_in_scope_file
from plamen_types import (
    parse_exact_scope_text,
    validate_exact_scope_authority,
)


def _write(path: Path, text: str = "contract C {}\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _scope(root: Path, rows: list[str]) -> Path:
    path = root / "bb-exact-scope.md"
    path.write_text("\n".join(f"- `{row}`" for row in rows) + "\n", encoding="utf-8")
    return path


def test_exact_parser_accepts_portable_complex_ecosystem_paths() -> None:
    text = "\n".join(
        [
            "- `contracts/My Token.sol`",
            "- `packages/@scope/1Vault.vy`",
        ]
    )
    evm = parse_exact_scope_text(text, pipeline="sc", ecosystem="evm")
    assert evm == (
        "contracts/My Token.sol",
        "packages/@scope/1Vault.vy",
    )
    assert parse_exact_scope_text(
        "`ledger/Café.daml`\n",
        pipeline="sc",
        ecosystem="daml",
    ) == ("ledger/Café.daml",)


@pytest.mark.parametrize(
    "row",
    [
        r"contracts\A.sol",
        "../contracts/A.sol",
        "C:/repo/contracts/A.sol",
        "//server/share/A.sol",
        "contracts/*.sol",
        "contracts/CON.sol",
        "contracts/Dir./A.sol",
        "contracts/Cafe\u0301.sol",
    ],
)
def test_exact_parser_rejects_cross_os_ambiguous_rows(row: str) -> None:
    with pytest.raises(ValueError):
        parse_exact_scope_text(row + "\n", pipeline="sc", ecosystem="evm")


def test_exact_parser_rejects_casefold_collisions() -> None:
    with pytest.raises(ValueError, match="portable collision"):
        parse_exact_scope_text(
            "contracts/Vault.sol\ncontracts/vault.sol\n",
            pipeline="sc",
            ecosystem="evm",
        )


@pytest.mark.parametrize(
    ("pipeline", "ecosystem"),
    [("typo", "evm"), ("sc", "evmm")],
)
def test_exact_parser_rejects_unknown_pipeline_or_ecosystem(
    pipeline: str,
    ecosystem: str,
) -> None:
    with pytest.raises(ValueError, match="unsupported"):
        parse_exact_scope_text(
            "contracts/A.sol\n",
            pipeline=pipeline,
            ecosystem=ecosystem,
        )


def test_exact_authority_requires_disk_spelling_and_rejects_alias(tmp_path: Path) -> None:
    _write(tmp_path / "contracts" / "Vault.sol")
    good = _scope(tmp_path, ["contracts/Vault.sol"])
    assert validate_exact_scope_authority(
        tmp_path, good, pipeline="sc", ecosystem="evm"
    ) == ("contracts/Vault.sol",)

    bad = _scope(tmp_path, ["contracts/vault.sol"])
    with pytest.raises(ValueError):
        validate_exact_scope_authority(
            tmp_path, bad, pipeline="sc", ecosystem="evm"
        )


def test_exact_authority_rejects_symlink_or_reparse_path(tmp_path: Path) -> None:
    outside = _write(tmp_path / "outside" / "Vault.sol")
    link = tmp_path / "linked"
    try:
        link.symlink_to(outside.parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")
    scope = _scope(tmp_path, ["linked/Vault.sol"])
    with pytest.raises(ValueError, match="symbolic link|junction|reparse"):
        validate_exact_scope_authority(
            tmp_path, scope, pipeline="sc", ecosystem="evm"
        )


def test_exact_snapshot_selects_only_full_path_not_same_basename(tmp_path: Path) -> None:
    selected = _write(tmp_path / "repo-a" / "contracts" / "A.sol")
    _write(tmp_path / "repo-b" / "vendor" / "A.sol")
    scope = _scope(tmp_path, ["repo-a/contracts/A.sol"])
    targets = snapshot._scope_file_targets(
        {
            "scope_file": str(scope),
            "scope_match_mode": "exact",
            "pipeline": "sc",
            "language": "evm",
        },
        tmp_path,
    )
    assert targets == [selected.resolve()]


def test_exact_parser_and_matcher_never_accept_basename_or_suffix_alias(
    tmp_path: Path,
) -> None:
    scope = _scope(tmp_path, ["repo-a/contracts/A.sol"])
    names = _load_scope_file_paths(
        str(scope),
        match_mode="exact",
        pipeline="sc",
        language="evm",
    )
    assert _path_in_scope_file(
        "repo-a/contracts/A.sol", names, match_mode="exact"
    )
    assert not _path_in_scope_file("vendor/A.sol", names, match_mode="exact")
    assert not _path_in_scope_file("contracts/A.sol", names, match_mode="exact")
    assert not _path_in_scope_file(
        r"repo-a\contracts\A.sol", names, match_mode="exact"
    )


def test_exact_scope_is_coverage_denominator_without_scip_and_handles_spaces(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    rows = [
        "repo-a/contracts/A.sol",
        "repo-b/contracts/A.sol",
        "contracts/My Token.sol",
        "packages/@scope/1Vault.sol",
        "contracts/Café.sol",
    ]
    for row in rows:
        _write(tmp_path / Path(row))
    scope = _scope(tmp_path, rows)
    (scratchpad / "analysis_one.md").write_text(
        "Reviewed `repo-a/contracts/A.sol` and `contracts/My Token.sol`.\n",
        encoding="utf-8",
    )

    coverage = validators._compute_scip_coverage_sets(
        scratchpad,
        scope_file=str(scope),
        scope_match_mode="exact",
        pipeline="sc",
        language="evm",
    )
    assert coverage["prod_indexed"] == set(rows)
    assert coverage["covered"] == {
        "repo-a/contracts/A.sol",
        "contracts/My Token.sol",
    }
    assert set(coverage["uncited"]) == set(rows) - set(coverage["covered"])
    assert coverage["scope_unindexed"] == set(rows)

    items = mechanical._build_attention_repair_items(
        scratchpad,
        "thorough",
        scope_file=str(scope),
        scope_match_mode="exact",
        pipeline="sc",
        language="evm",
    )
    queued = {
        item["target"]
        for item in items
        if item["kind"] == "uncited-security-file"
    }
    assert queued == set(coverage["uncited"])

    validators._write_final_subsystem_coverage_summary(
        scratchpad,
        scope_file=str(scope),
        scope_match_mode="exact",
        pipeline="sc",
        language="evm",
        run_id="run-bb-1",
        source_snapshot_digest="a" * 64,
    )
    final = (scratchpad / "subsystem_coverage_final.md").read_text(
        encoding="utf-8"
    )
    assert "40.0%" in final
    assert "`repo-b/contracts/A.sol`" in final
    authority = json.loads(
        (
            scratchpad / "exact_scope_coverage_authority.json"
        ).read_text(encoding="utf-8")
    )
    assert authority["status"] == "INCOMPLETE"
    assert authority["claim"] == "EXACT_SCOPE_APPLICATION_INCOMPLETE"
    assert authority["run_id"] == "run-bb-1"
    assert authority["source_snapshot_digest"] == "a" * 64
    assert set(authority["required_paths"]) == set(rows)
    assert set(authority["unresolved_paths"]) == set(rows) - set(
        authority["cited_paths"]
    )
    assert validators._validate_exact_scope_coverage_authority(
        scratchpad,
        scope_file=str(scope),
        expected_run_id="run-bb-1",
        expected_source_snapshot_digest="a" * 64,
    ) == []

    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text("# Audit Report\n\n## Findings\n\nNone.\n", encoding="utf-8")
    assert validators._project_exact_scope_coverage_limitations(
        scratchpad,
        report,
    ) == []
    projected = report.read_text(encoding="utf-8")
    assert "## Audit Scope Coverage Limitations" in projected
    assert "Individually verified findings remain valid" in projected
    assert validators._validate_exact_scope_coverage_delivery(
        scratchpad,
        report,
        scope_file=str(scope),
        expected_run_id="run-bb-1",
        expected_source_snapshot_digest="a" * 64,
    ) == []

    report.write_text(
        projected.replace(
            "<!-- PLAMEN_EXACT_SCOPE_COVERAGE_END -->",
            "",
        ),
        encoding="utf-8",
    )
    assert any(
        "report limitation marker" in issue
        for issue in validators._validate_exact_scope_coverage_delivery(
            scratchpad,
            report,
            scope_file=str(scope),
            expected_run_id="run-bb-1",
            expected_source_snapshot_digest="a" * 64,
        )
    )


def test_complete_exact_authority_forbids_stale_limitation_projection(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write(tmp_path / "contracts" / "A.sol")
    scope = _scope(tmp_path, ["contracts/A.sol"])
    (scratchpad / "analysis_one.md").write_text(
        "`contracts/A.sol:L1` reviewed\n",
        encoding="utf-8",
    )
    validators._write_final_subsystem_coverage_summary(
        scratchpad,
        scope_file=str(scope),
        scope_match_mode="exact",
        pipeline="sc",
        language="evm",
        run_id="run-complete",
        source_snapshot_digest="d" * 64,
    )
    authority = json.loads(
        (
            scratchpad / "exact_scope_coverage_authority.json"
        ).read_text(encoding="utf-8")
    )
    assert authority["status"] == "COMPLETE"
    assert authority["claim"] == "EXACT_SCOPE_APPLICATION_COMPLETE"
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text(
        "# Audit Report\n\n"
        "<!-- PLAMEN_EXACT_SCOPE_COVERAGE_BEGIN -->\n"
        "stale limitation\n"
        "<!-- PLAMEN_EXACT_SCOPE_COVERAGE_END -->\n",
        encoding="utf-8",
    )
    issues = validators._validate_exact_scope_coverage_delivery(
        scratchpad,
        report,
        scope_file=str(scope),
        expected_run_id="run-complete",
        expected_source_snapshot_digest="d" * 64,
    )
    assert any("must not retain" in issue for issue in issues)


def test_exact_final_authority_rejects_tamper_and_binding_mismatch(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write(tmp_path / "contracts" / "A.sol")
    scope = _scope(tmp_path, ["contracts/A.sol"])
    validators._write_final_subsystem_coverage_summary(
        scratchpad,
        scope_file=str(scope),
        scope_match_mode="exact",
        pipeline="sc",
        language="evm",
        run_id="run-a",
        source_snapshot_digest="b" * 64,
    )
    assert any(
        "run_id mismatch" in issue
        for issue in validators._validate_exact_scope_coverage_authority(
            scratchpad,
            scope_file=str(scope),
            expected_run_id="run-b",
            expected_source_snapshot_digest="b" * 64,
        )
    )
    authority_path = scratchpad / "exact_scope_coverage_authority.json"
    payload = json.loads(authority_path.read_text(encoding="utf-8"))
    payload["status"] = "COMPLETE"
    authority_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    issues = validators._validate_exact_scope_coverage_authority(
        scratchpad,
        scope_file=str(scope),
        expected_run_id="run-a",
        expected_source_snapshot_digest="b" * 64,
    )
    assert any("self-hash mismatch" in issue for issue in issues)
    assert any("status mismatch" in issue for issue in issues)


def test_attention_queue_cannot_self_certify_exact_scope_coverage(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    rows = ["contracts/A.sol", "contracts/B.sol"]
    for row in rows:
        _write(tmp_path / Path(row))
    scope = _scope(tmp_path, rows)
    (scratchpad / "analysis_one.md").write_text(
        "Reviewed `contracts/A.sol`.\n",
        encoding="utf-8",
    )

    needed, _reason = mechanical._prepare_attention_repair(
        scratchpad,
        "thorough",
        scope_file=str(scope),
        scope_match_mode="exact",
        pipeline="sc",
        language="evm",
    )
    assert needed
    assert "`contracts/B.sol`" in (
        scratchpad / "attention_repair_queue.md"
    ).read_text(encoding="utf-8")

    coverage = validators._compute_scip_coverage_sets(
        scratchpad,
        scope_file=str(scope),
        scope_match_mode="exact",
        pipeline="sc",
        language="evm",
    )
    assert coverage["covered"] == {"contracts/A.sol"}
    assert coverage["uncited"] == ["contracts/B.sol"]


def test_bound_attention_receipt_can_discharge_only_its_exact_reviewed_row(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    rows = ["contracts/A.sol", "contracts/B.sol"]
    for row in rows:
        _write(tmp_path / Path(row))
    scope = _scope(tmp_path, rows)
    (scratchpad / "analysis_one.md").write_text(
        "Reviewed `contracts/A.sol`.\n",
        encoding="utf-8",
    )
    needed, _ = mechanical._prepare_attention_repair(
        scratchpad,
        "thorough",
        scope_file=str(scope),
        scope_match_mode="exact",
        pipeline="sc",
        language="evm",
    )
    assert needed
    queue = (scratchpad / "attention_repair_queue.md").read_text(
        encoding="utf-8"
    )
    binding = next(
        line for line in queue.splitlines()
        if line.startswith("QUEUE_BINDING_SHA256:")
    )
    (scratchpad / "attention_repair_summary.md").write_text(
        "\n".join(
            [
                "# Attention Repair",
                "",
                binding,
                "",
                "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
                "|---|---|---|---|---|---|",
                "| 1 | security-obligation | `SO-000` | SAFE | "
                "`SO-000` reviewed | no issue |",
                "| 2 | uncited-security-file | `contracts/B.sol` | SAFE | "
                "`contracts/B.sol:L1` reviewed | no issue |",
                "",
            ]
        ),
        encoding="utf-8",
    )
    hard, _soft = validators._validate_attention_repair(
        scratchpad,
        "thorough",
    )
    assert hard == []
    receipt = json.loads(
        (
            scratchpad / "attention_repair_application_receipt.json"
        ).read_text(encoding="utf-8")
    )
    assert receipt["status"] == "COMPLETE"
    assert receipt["accepted_paths"] == ["contracts/B.sol"]

    coverage = validators._compute_scip_coverage_sets(
        scratchpad,
        scope_file=str(scope),
        scope_match_mode="exact",
        pipeline="sc",
        language="evm",
    )
    assert coverage["covered"] == set(rows)
    assert coverage["uncited"] == []


def test_bound_attention_receipt_rejects_semantically_tampered_queue(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    mechanical._write_attention_repair_queue(
        scratchpad,
        [
            {
                "kind": "uncited-security-file",
                "target": "contracts/A.sol",
                "reason": "uncited",
                "source": "scope.md",
                "evidence": "contracts/A.sol",
            }
        ],
    )
    queue_path = scratchpad / "attention_repair_queue.md"
    queue = queue_path.read_text(encoding="utf-8")
    binding = next(
        line for line in queue.splitlines()
        if line.startswith("QUEUE_BINDING_SHA256:")
    )
    queue_path.write_text(
        queue.replace("contracts/A.sol", "contracts/B.sol"),
        encoding="utf-8",
    )
    (scratchpad / "attention_repair_summary.md").write_text(
        "\n".join(
            [
                "# Attention Repair",
                binding,
                "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
                "|---|---|---|---|---|---|",
                "| 1 | uncited-security-file | `contracts/B.sol` | SAFE | "
                "`contracts/B.sol:L1` reviewed | no issue |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    hard, _soft = validators._validate_attention_repair(
        scratchpad,
        "thorough",
    )

    assert any("semantic binding" in issue for issue in hard)
    assert not (
        scratchpad / "attention_repair_application_receipt.json"
    ).exists()


def test_final_exact_authority_ignores_unvalidated_attention_receipt(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write(tmp_path / "contracts" / "A.sol")
    scope = _scope(tmp_path, ["contracts/A.sol"])
    mechanical._write_attention_repair_queue(
        scratchpad,
        [
            {
                "kind": "uncited-security-file",
                "target": "contracts/A.sol",
                "reason": "uncited",
                "source": str(scope),
                "evidence": "contracts/A.sol",
            }
        ],
    )
    queue_path = scratchpad / "attention_repair_queue.md"
    (scratchpad / "attention_repair_application_receipt.json").write_text(
        json.dumps(
            {
                "schema": "attacker-controlled",
                "status": "COMPLETE",
                "queue_file_sha256": "0" * 64,
                "accepted_paths": [],
                "unresolved_paths": ["contracts/A.sol"],
            }
        ),
        encoding="utf-8",
    )

    validators._write_final_subsystem_coverage_summary(
        scratchpad,
        scope_file=str(scope),
        scope_match_mode="exact",
        pipeline="sc",
        language="evm",
        run_id="run-bb-receipt",
        source_snapshot_digest="c" * 64,
    )
    authority = json.loads(
        (
            scratchpad / "exact_scope_coverage_authority.json"
        ).read_text(encoding="utf-8")
    )

    assert authority["applied_needs_human_paths"] == []
    assert authority["queued_unapplied_paths"] == ["contracts/A.sol"]
    assert authority["unqueued_unresolved_paths"] == []
    assert authority["attention_application_receipt_sha256"]
    assert queue_path.is_file()


def test_attention_queue_cannot_self_certify_legacy_coverage(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    (scratchpad / "scip").mkdir(parents=True)
    (scratchpad / "scip" / "repo_map.md").write_text(
        "## contracts/A.sol\n\n## contracts/B.sol\n",
        encoding="utf-8",
    )
    (scratchpad / "analysis_one.md").write_text(
        "Reviewed contracts/A.sol:L1.\n",
        encoding="utf-8",
    )
    needed, _ = mechanical._prepare_attention_repair(
        scratchpad,
        "thorough",
    )
    assert needed
    coverage = validators._compute_scip_coverage_sets(scratchpad)
    assert "contracts/B.sol" in coverage["uncited"]


@pytest.mark.parametrize("file_count", [17, 33])
def test_exact_uncited_scope_rows_are_not_silently_lost_to_legacy_caps(
    tmp_path: Path,
    file_count: int,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    rows = [
        f"contracts/Scope{index:02d}.sol"
        for index in range(file_count)
    ]
    for row in rows:
        _write(tmp_path / Path(row))
    scope = _scope(tmp_path, rows)
    items = mechanical._build_attention_repair_items(
        scratchpad,
        "thorough",
        scope_file=str(scope),
        scope_match_mode="exact",
        pipeline="sc",
        language="evm",
    )
    queued = {
        item["target"]
        for item in items
        if item["kind"] == "uncited-security-file"
    }
    assert queued == set(rows)


@pytest.mark.parametrize(
    ("verdict", "expected_status", "accepted", "unresolved"),
    [
        ("SAFE", "COMPLETE", ["Vault.sol"], []),
        ("NEEDS_HUMAN", "INCOMPLETE", [], ["Vault.sol"]),
    ],
)
def test_bound_attention_receipt_handles_root_level_source_paths(
    tmp_path: Path,
    verdict: str,
    expected_status: str,
    accepted: list[str],
    unresolved: list[str],
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    mechanical._write_attention_repair_queue(
        scratchpad,
        [
            {
                "kind": "uncited-security-file",
                "target": "Vault.sol",
                "reason": "uncited",
                "source": "scope.md",
                "evidence": "Vault.sol",
            }
        ],
    )
    queue = (scratchpad / "attention_repair_queue.md").read_text(
        encoding="utf-8"
    )
    binding = next(
        line for line in queue.splitlines()
        if line.startswith("QUEUE_BINDING_SHA256:")
    )
    evidence = (
        "`Vault.sol` unavailable"
        if verdict == "NEEDS_HUMAN"
        else "`Vault.sol:L1` reviewed"
    )
    (scratchpad / "attention_repair_summary.md").write_text(
        "\n".join(
            [
                "# Attention Repair",
                binding,
                "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
                "|---|---|---|---|---|---|",
                "| 1 | uncited-security-file | `Vault.sol` | "
                f"{verdict} | {evidence} | result |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    hard, _soft = validators._validate_attention_repair(
        scratchpad,
        "thorough",
    )
    assert hard == []
    receipt = json.loads(
        (
            scratchpad / "attention_repair_application_receipt.json"
        ).read_text(encoding="utf-8")
    )
    assert receipt["status"] == expected_status
    assert receipt["accepted_paths"] == accepted
    assert receipt["unresolved_paths"] == unresolved


@pytest.mark.parametrize(
    ("language", "row"),
    [("daml", "ledger/Main.daml"), ("evm", "contracts/Vault.vy")],
)
def test_exact_recon_zero_citations_fails_loudly_for_all_source_types(
    tmp_path: Path,
    language: str,
    row: str,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write(tmp_path / Path(row), "// source\n")
    scope = _scope(tmp_path, [row])
    issues = validators._validate_recon_coverage(
        scratchpad,
        str(tmp_path),
        language,
        scope_file=str(scope),
        scope_match_mode="exact",
        pipeline="sc",
    )
    assert any("zero file-path citations" in issue for issue in issues)


def test_scope_match_mode_is_snapshot_bound(tmp_path: Path) -> None:
    _write(tmp_path / "contracts" / "A.sol")
    scope = _scope(tmp_path, ["contracts/A.sol"])
    base = {
        "project_root": str(tmp_path),
        "scope_file": str(scope),
        "pipeline": "sc",
        "language": "evm",
    }
    legacy = snapshot._config_component(
        {**base, "scope_match_mode": "legacy"}
    )
    exact = snapshot._config_component(
        {**base, "scope_match_mode": "exact"}
    )
    assert legacy["digest"] != exact["digest"]
