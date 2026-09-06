"""Adversarial contract for the immutable niche lifecycle authority.

These tests intentionally exercise the lifecycle authority through the legacy
promotion entry point.  The JSON sidecar and Markdown receipt are projections;
neither may manufacture a clean lifecycle by coordinated rewriting.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import threading
from uuid import uuid4

import pytest

import niche_lifecycle_authority as N
import plamen_markdown as PM
import plamen_mechanical as M
import plamen_parsers as P


@pytest.fixture(autouse=True)
def _reviewed_markdown_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise logic under the exact runtime pinned by requirements-ci.lock."""

    monkeypatch.setattr(PM, "runtime_markdown_it_version", lambda: "4.2.0")


def _checkpoint(root: Path, run_id: str | None = None) -> str:
    run = run_id or str(uuid4())
    (root / "_v2_checkpoint.json").write_text(
        json.dumps({"run_id": run}), encoding="utf-8"
    )
    return run


def _finding(finding_id: str, title: str = "candidate") -> str:
    return (
        f"## Finding [{finding_id}]: {title}\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L1\n"
        f"**Description**: {title} remains actionable.\n"
        "**Impact**: Material harm remains possible.\n"
    )


def _inventory(root: Path) -> None:
    (root / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8"
    )


def _rehash_sidecar(path: Path, mutate) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    value.pop("artifact_sha256", None)
    value["artifact_sha256"] = M._niche_identity_debt_digest(value)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_projection_and_receipt_coordinated_rehash_cannot_erase_tombstone(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(_finding("SC-61"), encoding="utf-8")
    assert M.promote_niche_to_inventory(tmp_path) == (1, 0)
    source.write_text("# Empty\n", encoding="utf-8")
    assert M.promote_niche_to_inventory(tmp_path) == (0, 0)

    sidecar = tmp_path / "niche_identity_debt.json"

    def erase(value: dict) -> None:
        value["source_errors"] = []
        value["source_error_count"] = 0
        value["blocking_debt_count"] = len(value["candidates"])
        value["removed_action_count"] = len(value["lifecycle_records"])
        value["removed_action_set_sha256"] = M._niche_removed_action_set_digest(
            value["source_errors"], value["lifecycle_records"]
        )

    _rehash_sidecar(sidecar, erase)
    (tmp_path / "niche_promotion_receipt.md").write_text(
        "# Niche Promotion Receipt\n\nClean.\n", encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="lifecycle authority|projection"):
        M.read_niche_identity_debt_sidecar(tmp_path)


def test_projection_rehash_cannot_omit_one_current_action(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _inventory(tmp_path)
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(
        _finding("SC-61", "one") + "\n" + _finding("SC-62", "two"),
        encoding="utf-8",
    )
    assert M.promote_niche_to_inventory(tmp_path) == (2, 2)
    sidecar = tmp_path / "niche_identity_debt.json"

    def omit(value: dict) -> None:
        value["actions"] = value["actions"][:1]
        value["action_count"] = 1
        value["action_set_sha256"] = M._niche_action_set_digest(value["actions"])
        value["live_action_denominator_sha256"] = (
            M._niche_live_action_denominator_digest(value["actions"])
        )

    _rehash_sidecar(sidecar, omit)
    with pytest.raises(RuntimeError, match="lifecycle authority|projection"):
        M.read_niche_identity_debt_sidecar(tmp_path)


def test_clean_action_without_exact_inventory_referent_is_blocking(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-61"), encoding="utf-8"
    )
    assert M.promote_niche_to_inventory(tmp_path) == (1, 0)
    authority = N.load_current_niche_lifecycle(tmp_path)
    assert authority["summary"]["blocking_count"] == 1
    assert authority["transitions"][0]["state"] == "UNDELIVERED_CLEAN_ACTION"
    assert authority["transitions"][0]["blocking"] is True


def test_projection_cannot_hide_undelivered_clean_action(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-61"), encoding="utf-8"
    )
    M.promote_niche_to_inventory(tmp_path)
    sidecar = tmp_path / "niche_identity_debt.json"

    def hide(value: dict) -> None:
        value["source_errors"] = []
        value["source_error_count"] = 0
        value["blocking_debt_count"] = len(value["candidates"])

    _rehash_sidecar(sidecar, hide)
    with pytest.raises(
        RuntimeError,
        match="UNDELIVERED_CLEAN_ACTION|lifecycle authority|projection",
    ):
        M.read_niche_identity_debt_sidecar(tmp_path)


def test_cross_run_lifecycle_replay_fails_closed(tmp_path: Path) -> None:
    first = _checkpoint(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-61"), encoding="utf-8"
    )
    M.promote_niche_to_inventory(tmp_path)
    second = _checkpoint(tmp_path)
    assert second != first
    with pytest.raises(RuntimeError, match="CROSS_RUN_REPLAY"):
        M.promote_niche_to_inventory(tmp_path)
    projection = json.loads(
        (tmp_path / "niche_identity_debt.json").read_text(encoding="utf-8")
    )
    assert projection["blocking_debt_count"] >= 1
    assert projection["lifecycle_authority_status"] == "BLOCKED"


def test_inventory_referents_ignore_fences_html_comments_and_other_blocks() -> None:
    identity = "NACT-" + "A" * 24
    text = (
        "### Finding [INV-001]: real\n"
        f"**Source Action Identity**: {identity}\n\n"
        "### Finding [INV-002]: unrelated\n"
        "```md\n"
        f"**Source Action Identity**: {identity}\n"
        "```\n\n"
        "<!--\n"
        f"### Finding [INV-003]: fake\n**Source Action Identity**: {identity}\n"
        "-->\n"
        "<pre>\n"
        f"### Finding [INV-004]: fake\n**Source Action Identity**: {identity}\n"
        "</pre>\n"
    )
    # Operational Markdown remains parseable evidence, but no Markdown field
    # alone is a delivery authority after R6.
    assert M._inventory_niche_action_referents(text) == {}
    records = M._operational_inventory_finding_records(text)
    assert [row["inventory_id"] for row in records] == ["INV-001", "INV-002"]


def test_niche_action_denominator_ignores_non_operational_markdown(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _inventory(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        "```md\n"
        + _finding("SC-91", "fenced example")
        + "```\n\n<!--\n"
        + _finding("SC-92", "comment example")
        + "-->\n\n<pre>\n"
        + _finding("SC-93", "html example")
        + "</pre>\n\n"
        + _finding("SC-61", "real candidate"),
        encoding="utf-8",
    )
    assert M.promote_niche_to_inventory(tmp_path) == (1, 1)
    authority = N.load_current_niche_lifecycle(tmp_path)
    assert [
        row["normalized_local_id"] for row in authority["actions"]
    ] == ["SC-61"]


def test_source_authored_supersession_cannot_resolve_old_history(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(_finding("SC-61", "old"), encoding="utf-8")
    M.promote_niche_to_inventory(tmp_path)
    old = N.load_current_niche_lifecycle(tmp_path)["transitions"][0][
        "source_action_identity"
    ]
    source.write_text(
        _finding("SC-61", "new")
        + f"**Supersedes Source Action Identities**: {old}\n",
        encoding="utf-8",
    )
    M.promote_niche_to_inventory(tmp_path)
    current = N.load_current_niche_lifecycle(tmp_path)
    old_rows = [
        row for row in current["history"]
        if row["source_action_identity"] == old
    ]
    assert any(row["state"] == "SOURCE_ACTION_REMOVED" for row in old_rows)
    assert not any(row["state"] == "SUPERSEDED" for row in old_rows)


def test_post_parse_source_mutation_cannot_commit_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _checkpoint(tmp_path)
    _inventory(tmp_path)
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(_finding("SC-61"), encoding="utf-8")
    original = P._parse_depth_finding_blocks

    def mutate(path: Path, *args, **kwargs):
        rows = original(path, *args, **kwargs)
        source.write_text(_finding("SC-99", "swapped"), encoding="utf-8")
        return rows

    monkeypatch.setattr(P, "_parse_depth_finding_blocks", mutate)
    with pytest.raises(RuntimeError, match="NICHE_SOURCE.*CHANGED|capture.*drift"):
        M.promote_niche_to_inventory(tmp_path)
    payload = json.loads(
        (tmp_path / "niche_identity_debt.json").read_text(encoding="utf-8")
    )
    assert payload["blocking_debt_count"] >= 1
    assert payload["lifecycle_authority_status"] == "BLOCKED"


def test_late_namespace_member_cannot_escape_denominator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _checkpoint(tmp_path)
    _inventory(tmp_path)
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(_finding("SC-61"), encoding="utf-8")
    original = P._parse_depth_finding_blocks

    def add_member(path: Path, *args, **kwargs):
        rows = original(path, *args, **kwargs)
        (tmp_path / "niche_late_findings.md").write_text(
            _finding("SC-62", "late member"), encoding="utf-8"
        )
        return rows

    monkeypatch.setattr(P, "_parse_depth_finding_blocks", add_member)
    with pytest.raises(RuntimeError, match="namespace.*drift|NAMESPACE"):
        M.promote_niche_to_inventory(tmp_path)
    payload = json.loads(
        (tmp_path / "niche_identity_debt.json").read_text(encoding="utf-8")
    )
    assert payload["blocking_debt_count"] >= 1
    assert payload["lifecycle_authority_status"] == "BLOCKED"


def test_phaseio_input_binding_must_equal_retained_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _checkpoint(tmp_path)
    _inventory(tmp_path)
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(_finding("SC-61"), encoding="utf-8")
    original = N.record_work_unit_inputs

    def forge_binding(*args, **kwargs):
        unit = original(*args, **kwargs)
        unit = dict(unit)
        bindings = {
            key: dict(value)
            for key, value in unit["input_bindings"].items()
        }
        bindings[f"scratchpad:{source.name}"]["sha256"] = "0" * 64
        unit["input_bindings"] = bindings
        return unit

    monkeypatch.setattr(N, "record_work_unit_inputs", forge_binding)
    with pytest.raises(RuntimeError, match="PhaseIO input authority"):
        M.promote_niche_to_inventory(tmp_path)
    payload = json.loads(
        (tmp_path / "niche_identity_debt.json").read_text(encoding="utf-8")
    )
    assert payload["blocking_debt_count"] >= 1
    assert payload["lifecycle_authority_status"] == "BLOCKED"


def test_projection_hardlink_is_never_authority(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-61"), encoding="utf-8"
    )
    M.promote_niche_to_inventory(tmp_path)
    projection = tmp_path / "niche_identity_debt.json"
    alias = tmp_path.parent / f"{tmp_path.name}-projection-alias.json"
    try:
        os.link(projection, alias)
    except OSError as exc:
        pytest.skip(f"hardlink unavailable: {exc}")
    try:
        with pytest.raises((RuntimeError, ValueError), match="link|nlink|alias"):
            M.read_niche_identity_debt_sidecar(tmp_path)
    finally:
        alias.unlink(missing_ok=True)


def test_inventory_hardlink_is_rejected_before_promotion_write(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _inventory(tmp_path)
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(_finding("SC-61"), encoding="utf-8")
    inventory = tmp_path / "findings_inventory.md"
    original = inventory.read_bytes()
    alias = tmp_path.parent / f"{tmp_path.name}-inventory-alias.md"
    try:
        os.link(inventory, alias)
    except OSError as exc:
        pytest.skip(f"hardlink unavailable: {exc}")
    try:
        with pytest.raises(RuntimeError, match="INVENTORY_CAPTURE_UNSAFE"):
            M.promote_niche_to_inventory(tmp_path)
        assert inventory.read_bytes() == original
        assert alias.read_bytes() == original
    finally:
        alias.unlink(missing_ok=True)


def test_lifecycle_cas_hardlink_is_rejected(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-61"), encoding="utf-8"
    )
    M.promote_niche_to_inventory(tmp_path)
    generation = next((tmp_path / "_niche_lifecycle_cas").glob("*.json"))
    alias = tmp_path.parent / f"{tmp_path.name}-cas-alias.json"
    try:
        os.link(generation, alias)
    except OSError as exc:
        pytest.skip(f"hardlink unavailable: {exc}")
    try:
        with pytest.raises(
            N.NicheLifecycleAuthorityError,
            match="unsafe|link|nlink|alias|regular",
        ):
            N.load_current_niche_lifecycle(tmp_path)
    finally:
        alias.unlink(missing_ok=True)


def test_lifecycle_validator_rejects_reordered_and_duplicate_keys(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _inventory(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-61") + "\n" + _finding("SC-62"), encoding="utf-8"
    )
    M.promote_niche_to_inventory(tmp_path)
    current = N.load_current_niche_lifecycle(tmp_path)
    reversed_rows = dict(current)
    reversed_rows["transitions"] = list(reversed(current["transitions"]))
    with pytest.raises(N.NicheLifecycleAuthorityError, match="order"):
        N.validate_niche_lifecycle_generation(reversed_rows)
    duplicated = dict(current)
    duplicated["transitions"] = [
        current["transitions"][0], current["transitions"][0]
    ]
    with pytest.raises(N.NicheLifecycleAuthorityError, match="duplicate|denominator"):
        N.validate_niche_lifecycle_generation(duplicated)


def test_generic_literal_id_table_is_not_a_finding(tmp_path: Path) -> None:
    path = tmp_path / "niche_runtime_findings.md"
    path.write_text(
        "| ID | Title | Impact |\n"
        "| --- | --- | --- |\n"
        "| ID | configuration | material impact |\n",
        encoding="utf-8",
    )
    assert P._parse_depth_finding_blocks(path) == []


@pytest.mark.parametrize(
    "table",
    (
        "| ID | Title | Impact |\n|---|---|---|\n"
        "| SC-61 | candidate | material harm |\n",
        "| Severity | Candidate ID | Description |\n|---|---|---|\n"
        "| Medium | SC-61 | material candidate |\n",
        "| Location | Finding ID | Title |\n|---|---|---|\n"
        "| src/X.sol:L1 | SC-61 | candidate |\n",
    ),
)
def test_generic_id_headers_are_position_independent_with_semantics(
    tmp_path: Path, table: str
) -> None:
    path = tmp_path / "niche_runtime_findings.md"
    path.write_text(table, encoding="utf-8")
    rows = P._parse_depth_finding_blocks(path)
    assert [row["id"] for row in rows] == ["SC-61"]
    assert rows[0]["_low_confidence_rowonly"] == "true"


def test_blind_spot_letter_id_schema_remains_isolated(tmp_path: Path) -> None:
    (tmp_path / "blind_spot_a_findings.md").write_text(
        _finding("BLIND-A1", "blind issue"), encoding="utf-8"
    )
    rows = M._parse_blind_spot_findings(tmp_path)
    assert [row["source_id"] for row in rows] == ["BLIND-A1"]


def test_blind_spot_missing_required_field_stays_excluded(tmp_path: Path) -> None:
    (tmp_path / "blind_spot_a_findings.md").write_text(
        "## Finding [BLIND-A1]: incomplete\n**Severity**: Medium\n",
        encoding="utf-8",
    )
    assert M._parse_blind_spot_findings(tmp_path) == []


def test_niche_namespace_does_not_consume_blind_spot_artifacts(tmp_path: Path) -> None:
    (tmp_path / "blind_spot_a_findings.md").write_text(
        _finding("BLIND-A1", "blind issue"), encoding="utf-8"
    )
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-61", "niche issue"), encoding="utf-8"
    )
    assert [row["source_id"] for row in M._parse_niche_findings(tmp_path)] == [
        "SC-61"
    ]


def _context_kwargs(root: Path, *, run_id: str, **overrides) -> dict:
    value = {
        "project_root": root,
        "run_id": run_id,
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": "claude",
    }
    value.update(overrides)
    return value


def test_lifecycle_head_projection_and_sidecar_bind_all_typed_dimensions(
    tmp_path: Path,
) -> None:
    run_id = _checkpoint(tmp_path)
    M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    )
    head = json.loads((tmp_path / N.NICHE_LIFECYCLE_HEAD).read_text())
    sidecar = M.read_niche_identity_debt_sidecar(tmp_path)
    assert sidecar is not None
    for field, expected in {
        "pipeline": "sc", "mode": "thorough", "ecosystem": "evm",
        "backend": "claude", "phase": "depth", "producer": "niche_promotion",
    }.items():
        assert head[field] == expected
        assert sidecar[f"lifecycle_{field}"] == expected
    assert head["context_sha256"] == sidecar["lifecycle_context_sha256"]


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("pipeline", "l1"),
        ("mode", "core"),
        ("ecosystem", "soroban"),
        ("backend", "codex"),
    ],
)
def test_lifecycle_rejects_mixed_generation_dimensions_same_run(
    tmp_path: Path, field: str, replacement: str,
) -> None:
    run_id = _checkpoint(tmp_path)
    first = _context_kwargs(tmp_path, run_id=run_id)
    M.promote_niche_to_inventory(tmp_path, **first)
    (tmp_path / "niche_changed_findings.md").write_text(
        _finding("SC-991", "typed context drift"), encoding="utf-8"
    )
    second = dict(first)
    second[field] = replacement
    with pytest.raises(RuntimeError, match="CONTEXT|context|REPLAY"):
        M.promote_niche_to_inventory(tmp_path, **second)
    expected = N.niche_lifecycle_context(
        project_root=tmp_path,
        run_id=run_id,
        dimensions={
            "pipeline": "sc", "mode": "thorough", "ecosystem": "evm",
            "backend": "claude", "phase": "depth",
            "producer": "niche_promotion",
        },
    )
    current = N.load_current_niche_lifecycle(
        tmp_path, project_root=tmp_path, expected_context=expected
    )
    assert current is not None and current["attempt_ordinal"] == 1


def _source_entry(root: Path) -> dict:
    entries = M._parse_niche_findings(root)
    assert len(entries) == 1
    return entries[0]


def _spoof_inventory_block(
    entry: dict, *, inventory_id: str = "INV-001", **changes,
) -> str:
    fields = {
        "artifact": entry["source_file"],
        "local_id": entry["source_id"],
        "source_sha256": entry["source_sha256"],
        "start": entry["source_byte_start"],
        "end": entry["source_byte_end"],
        "block_sha256": entry["source_block_sha256"],
        "action_identity": entry["source_action_identity"],
    }
    fields.update(changes)
    return (
        f"### Finding [{inventory_id}]: unauthenticated inventory claim\n"
        "**Severity**: Medium\n**Location**: src/Unrelated.sol:L1\n"
        f"**Source IDs**: {fields['local_id']}\n"
        f"**Primary Artifact**: {fields['artifact']}\n"
        f"**Source Artifact Hash**: sha256:{fields['source_sha256']}\n"
        f"**Source Byte Range**: {fields['start']}-{fields['end']}\n"
        f"**Source Block SHA256**: {fields['block_sha256']}\n"
        f"**Source Action Identity**: {fields['action_identity']}\n"
        "**Verdict**: NEEDS_VERIFICATION\n**Description**: unrelated\n"
        "**Impact**: unrelated\n"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"bare": True},
        {"artifact": "niche_wrong_findings.md"},
        {"local_id": "SC-999"},
        {"source_sha256": "0" * 64},
        {"start": 1},
        {"block_sha256": "1" * 64},
    ],
)
def test_inventory_markdown_cannot_self_certify_niche_delivery(
    tmp_path: Path, changes: dict,
) -> None:
    run_id = _checkpoint(tmp_path)
    (tmp_path / "niche_spoof_findings.md").write_text(
        _finding("SC-701", "real source action"), encoding="utf-8"
    )
    entry = _source_entry(tmp_path)
    change = dict(changes)
    if change.pop("bare", False):
        inventory = (
            "# Findings Inventory\n\n### Finding [INV-001]: bare spoof\n"
            f"**Source Action Identity**: {entry['source_action_identity']}\n"
        )
    else:
        inventory = "# Findings Inventory\n\n" + _spoof_inventory_block(
            entry, **change
        )
    (tmp_path / "findings_inventory.md").write_text(inventory, encoding="utf-8")
    assert M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    ) == (1, 1)
    current = N.load_current_niche_lifecycle(
        tmp_path, project_root=tmp_path, expected_run_id=run_id
    )
    assert current is not None
    # The real candidate is appended for recall, but the pre-existing NACT
    # claim makes delivery ambiguous.  Neither row may mint clean authority.
    assert current["summary"]["blocking_count"] == 1
    assert current["delivery_records"] == []


def test_duplicate_inventory_referents_remain_undelivered_debt(
    tmp_path: Path,
) -> None:
    run_id = _checkpoint(tmp_path)
    (tmp_path / "niche_duplicate_findings.md").write_text(
        _finding("SC-702", "duplicate claim"), encoding="utf-8"
    )
    entry = _source_entry(tmp_path)
    (tmp_path / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        + _spoof_inventory_block(entry, inventory_id="INV-001")
        + "\n"
        + _spoof_inventory_block(entry, inventory_id="INV-002"),
        encoding="utf-8",
    )
    assert M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    ) == (1, 1)
    current = N.load_current_niche_lifecycle(
        tmp_path, project_root=tmp_path, expected_run_id=run_id
    )
    assert current is not None
    assert current["summary"]["blocking_count"] == 1
    assert current["delivery_records"] == []


def test_committed_delivery_fails_when_exact_inventory_block_changes(
    tmp_path: Path,
) -> None:
    run_id = _checkpoint(tmp_path)
    _inventory(tmp_path)
    (tmp_path / "niche_bound_findings.md").write_text(
        _finding("SC-705", "bound delivery"), encoding="utf-8"
    )
    assert M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    ) == (1, 1)
    inventory = tmp_path / "findings_inventory.md"
    text = inventory.read_text(encoding="utf-8")
    inventory.write_text(
        text.replace("**Primary Artifact**: niche_bound_findings.md",
                     "**Primary Artifact**: niche_other_findings.md"),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="typed delivery|binding changed"):
        M.read_niche_identity_debt_sidecar(tmp_path)


def test_recovery_reaps_journal_bound_uncommitted_cas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    original = N.record_work_unit_artifacts
    calls = {"count": 0}
    def fail_once(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("injected post-CAS pre-ledger crash")
        return original(*args, **kwargs)
    monkeypatch.setattr(N, "record_work_unit_artifacts", fail_once)
    with pytest.raises(RuntimeError):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )
    assert list((tmp_path / N.NICHE_LIFECYCLE_CAS_DIR).glob("*.json"))
    assert M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    ) == (0, 0)


def test_recovery_rebuilds_missing_head_after_committed_cas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    original = N._write_head_projection
    calls = {"count": 0}
    def fail_once(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("injected post-ledger pre-head crash")
        return original(*args, **kwargs)
    monkeypatch.setattr(N, "_write_head_projection", fail_once)
    with pytest.raises(RuntimeError):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )
    assert not (tmp_path / N.NICHE_LIFECYCLE_HEAD).exists()
    assert M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    ) == (0, 0)


def test_recovery_after_pre_cas_journal_failure_has_no_orphan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    original = N._write_transaction_journal
    calls = {"count": 0}
    def fail_once(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("injected pre-CAS journal failure")
        return original(*args, **kwargs)
    monkeypatch.setattr(N, "_write_transaction_journal", fail_once)
    with pytest.raises(RuntimeError):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )
    cas = tmp_path / N.NICHE_LIFECYCLE_CAS_DIR
    assert not cas.exists() or list(cas.glob("*.json")) == []
    assert M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    ) == (0, 0)


def test_recovery_after_post_head_journal_clear_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    original = N._clear_transaction_journal
    calls = {"count": 0}
    def fail_once(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("injected post-head journal cleanup failure")
        return original(*args, **kwargs)
    monkeypatch.setattr(N, "_clear_transaction_journal", fail_once)
    with pytest.raises(RuntimeError):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )
    assert (tmp_path / N.NICHE_LIFECYCLE_HEAD).is_file()
    assert (tmp_path / N.NICHE_LIFECYCLE_TRANSACTION).is_file()
    assert M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    ) == (0, 0)
    assert not (tmp_path / N.NICHE_LIFECYCLE_TRANSACTION).exists()


def test_unjournaled_uncommitted_cas_is_blocking_not_reaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    monkeypatch.setattr(
        N, "record_work_unit_artifacts",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("crash")),
    )
    with pytest.raises(RuntimeError):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )
    (tmp_path / N.NICHE_LIFECYCLE_TRANSACTION).unlink()
    with pytest.raises(N.NicheLifecycleAuthorityError, match="unjournaled"):
        N.load_current_niche_lifecycle(
            tmp_path, project_root=tmp_path, expected_run_id=run_id
        )


def test_journal_bound_partial_cas_is_safely_reaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    original = N.record_work_unit_artifacts
    calls = {"count": 0}
    def fail_once(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("crash after partial CAS")
        return original(*args, **kwargs)
    monkeypatch.setattr(N, "record_work_unit_artifacts", fail_once)
    with pytest.raises(RuntimeError):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )
    [cas] = list((tmp_path / N.NICHE_LIFECYCLE_CAS_DIR).glob("*.json"))
    cas.write_bytes(b"{")
    assert M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    ) == (0, 0)


def test_tampered_transaction_journal_is_blocking_not_reaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    monkeypatch.setattr(
        N, "record_work_unit_artifacts",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("crash")),
    )
    with pytest.raises(RuntimeError):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )
    journal = tmp_path / N.NICHE_LIFECYCLE_TRANSACTION
    value = json.loads(journal.read_text())
    value["generation_sha256"] = "0" * 64
    journal.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(N.NicheLifecycleAuthorityError, match="transaction digest"):
        N.load_current_niche_lifecycle(
            tmp_path, project_root=tmp_path, expected_run_id=run_id
        )


def test_valid_stale_head_rebuilds_to_unique_committed_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    )
    first_head = json.loads((tmp_path / N.NICHE_LIFECYCLE_HEAD).read_text())
    (tmp_path / "niche_second_findings.md").write_text(
        _finding("SC-704", "second generation"), encoding="utf-8"
    )
    original = N._write_head_projection
    calls = {"count": 0}
    def fail_once(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("leave valid stale head")
        return original(*args, **kwargs)
    monkeypatch.setattr(N, "_write_head_projection", fail_once)
    with pytest.raises(RuntimeError):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )
    assert json.loads((tmp_path / N.NICHE_LIFECYCLE_HEAD).read_text()) == first_head
    current = N.load_current_niche_lifecycle(
        tmp_path, project_root=tmp_path, expected_run_id=run_id
    )
    assert current is not None and current["attempt_ordinal"] == 2
    assert json.loads((tmp_path / N.NICHE_LIFECYCLE_HEAD).read_text())[
        "generation_sha256"
    ] == current["generation_sha256"]


def test_tampered_head_is_blocking_not_reconstructed(tmp_path: Path) -> None:
    run_id = _checkpoint(tmp_path)
    M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    )
    head = tmp_path / N.NICHE_LIFECYCLE_HEAD
    value = json.loads(head.read_text())
    value["generation_sha256"] = "f" * 64
    head.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(N.NicheLifecycleAuthorityError, match="head digest"):
        N.load_current_niche_lifecycle(
            tmp_path, project_root=tmp_path, expected_run_id=run_id
        )


def test_same_byte_physical_source_replacement_is_not_idempotent_authority(
    tmp_path: Path,
) -> None:
    run_id = _checkpoint(tmp_path)
    _inventory(tmp_path)
    source = tmp_path / "niche_runtime_findings.md"
    raw = _finding("SC-703", "physical replay")
    source.write_text(raw, encoding="utf-8")
    assert M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    ) == (1, 1)
    replacement = tmp_path / "replacement.md"
    replacement.write_text(raw, encoding="utf-8")
    os.replace(replacement, source)
    with pytest.raises(RuntimeError, match="PHYSICAL|physical|REPLAY"):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )


def test_same_byte_physical_inventory_replacement_is_not_idempotent_authority(
    tmp_path: Path,
) -> None:
    run_id = _checkpoint(tmp_path)
    _inventory(tmp_path)
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(_finding("SC-704", "inventory physical replay"), encoding="utf-8")
    assert M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    ) == (1, 1)
    inventory = tmp_path / "findings_inventory.md"
    replacement = tmp_path / "replacement_inventory.md"
    replacement.write_bytes(inventory.read_bytes())
    os.replace(replacement, inventory)
    with pytest.raises(RuntimeError, match="PHYSICAL|physical|REPLAY"):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )


def test_forged_inventory_publication_capability_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    _inventory(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-705", "forged publication capability"), encoding="utf-8"
    )

    def forged(scratchpad: Path, **kwargs: object) -> object:
        M._promo_atomic_write_text(
            Path(scratchpad) / "findings_inventory.md",
            bytes(kwargs["expected_post_bytes"]).decode("utf-8"),
        )
        return object()

    monkeypatch.setattr(
        M, "_issue_niche_inventory_publication_capability", forged
    )
    with pytest.raises(RuntimeError, match="CAPABILITY"):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )


def test_reused_inventory_publication_capability_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    _inventory(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-706", "reused publication capability"), encoding="utf-8"
    )
    issued: list[object] = []
    real_finalize = M._finalize_niche_lifecycle_authority

    def capture(*args: object, **kwargs: object) -> object:
        issued.append(kwargs["inventory_publication_capability"])
        return real_finalize(*args, **kwargs)

    monkeypatch.setattr(
        M, "_finalize_niche_lifecycle_authority", capture
    )
    assert M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    ) == (1, 1)
    (tmp_path / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8"
    )

    def replay(scratchpad: Path, **kwargs: object) -> object:
        M._promo_atomic_write_text(
            Path(scratchpad) / "findings_inventory.md",
            bytes(kwargs["expected_post_bytes"]).decode("utf-8"),
        )
        return issued[0]

    monkeypatch.setattr(
        M, "_issue_niche_inventory_publication_capability", replay
    )
    with pytest.raises(RuntimeError, match="CAPABILITY.*REUSED"):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )


def test_inventory_publication_capability_rejects_post_issue_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    _inventory(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-707", "stale publication capability"), encoding="utf-8"
    )
    real_finalize = M._finalize_niche_lifecycle_authority

    def replace_after_issue(*args: object, **kwargs: object) -> object:
        inventory = Path(args[0]) / "findings_inventory.md"
        replacement = Path(args[0]) / "post_issue_inventory.md"
        replacement.write_bytes(inventory.read_bytes())
        os.replace(replacement, inventory)
        return real_finalize(*args, **kwargs)

    monkeypatch.setattr(
        M, "_finalize_niche_lifecycle_authority", replace_after_issue
    )
    with pytest.raises(RuntimeError, match="CAPABILITY_STALE_OR_DRIFTED"):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )


def test_inventory_publication_capability_same_thread_positive_and_cleanup(
    tmp_path: Path,
) -> None:
    run_id = _checkpoint(tmp_path)
    _inventory(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-708", "same-thread publication"), encoding="utf-8"
    )
    assert M.promote_niche_to_inventory(
        tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
    ) == (1, 1)
    with N._INVENTORY_PUBLICATION_CAPABILITY_LOCK:
        assert N._INVENTORY_PUBLICATION_CAPABILITIES == {}


def test_inventory_publication_capability_rejects_cross_thread_transfer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    _inventory(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-709", "cross-thread publication"), encoding="utf-8"
    )
    real_finalize = M._finalize_niche_lifecycle_authority

    def cross_thread(*args: object, **kwargs: object) -> object:
        failures: list[BaseException] = []

        def worker() -> None:
            try:
                real_finalize(*args, **kwargs)
            except BaseException as exc:  # the exception is the test subject
                failures.append(exc)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        assert len(failures) == 1
        raise failures[0]

    monkeypatch.setattr(M, "_finalize_niche_lifecycle_authority", cross_thread)
    with pytest.raises(RuntimeError, match="CAPABILITY_STALE_OR_DRIFTED"):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )
    with N._INVENTORY_PUBLICATION_CAPABILITY_LOCK:
        assert N._INVENTORY_PUBLICATION_CAPABILITIES == {}


def test_invalid_capability_attempt_burns_before_valid_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    _inventory(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-710", "one-shot publication"), encoding="utf-8"
    )
    real_finalize = M._finalize_niche_lifecycle_authority

    def invalid_then_valid(*args: object, **kwargs: object) -> object:
        invalid = dict(kwargs)
        invalid_dimensions = dict(kwargs["dimensions"])
        invalid_dimensions["backend"] = "codex"
        invalid["dimensions"] = invalid_dimensions
        with pytest.raises(
            N.NicheLifecycleAuthorityError,
            match="CAPABILITY_STALE_OR_DRIFTED",
        ):
            real_finalize(*args, **invalid)
        return real_finalize(*args, **kwargs)

    monkeypatch.setattr(
        M, "_finalize_niche_lifecycle_authority", invalid_then_valid
    )
    with pytest.raises(RuntimeError, match="CAPABILITY_INVALID_OR_REUSED"):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )


def test_inventory_publication_capability_exception_path_does_not_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    _inventory(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-711", "exception cleanup"), encoding="utf-8"
    )

    def fail_before_consume(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("synthetic pre-consume failure")

    monkeypatch.setattr(
        M, "_finalize_niche_lifecycle_authority", fail_before_consume
    )
    with pytest.raises(RuntimeError, match="synthetic pre-consume failure"):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )
    with N._INVENTORY_PUBLICATION_CAPABILITY_LOCK:
        assert N._INVENTORY_PUBLICATION_CAPABILITIES == {}


def test_inventory_publication_capability_rejects_wrong_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _checkpoint(tmp_path)
    _inventory(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-712", "wrong-process publication"), encoding="utf-8"
    )
    real_finalize = M._finalize_niche_lifecycle_authority
    real_getpid = os.getpid

    def wrong_process(*args: object, **kwargs: object) -> object:
        monkeypatch.setattr(N.os, "getpid", lambda: real_getpid() + 1)
        return real_finalize(*args, **kwargs)

    monkeypatch.setattr(M, "_finalize_niche_lifecycle_authority", wrong_process)
    with pytest.raises(RuntimeError, match="CAPABILITY_STALE_OR_DRIFTED"):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )


@pytest.mark.parametrize("capture_ordinal", [1, 2])
def test_inventory_publication_capability_rejects_wrong_pre_or_post_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capture_ordinal: int,
) -> None:
    run_id = _checkpoint(tmp_path)
    _inventory(tmp_path)
    (tmp_path / "niche_runtime_findings.md").write_text(
        _finding("SC-713", "wrong publication bytes"), encoding="utf-8"
    )
    real_capture = N._capture_exact_inventory
    count = 0

    def corrupted(path: Path, limit: int) -> dict[str, object]:
        nonlocal count
        count += 1
        row = dict(real_capture(path, limit))
        if count == capture_ordinal:
            row["raw"] = bytes(row["raw"]) + b"corrupt"
        return row

    monkeypatch.setattr(N, "_capture_exact_inventory", corrupted)
    with pytest.raises(RuntimeError, match="inventory .* trusted publication"):
        M.promote_niche_to_inventory(
            tmp_path, **_context_kwargs(tmp_path, run_id=run_id)
        )


def test_inventory_publication_issuer_has_one_private_synchronous_ast_callsite() -> None:
    assert "_publish_niche_inventory_with_capability" not in N.__all__
    tree = ast.parse(Path(M.__file__).read_text(encoding="utf-8"))
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_issue_niche_inventory_publication_capability"
    ]
    assert len(calls) == 1
    ancestors: list[ast.AST] = []
    cursor: ast.AST | None = calls[0]
    while cursor in parents:
        cursor = parents[cursor]
        ancestors.append(cursor)
    assert any(isinstance(node, ast.Try) for node in ancestors)
    functions = [node for node in ancestors if isinstance(node, ast.FunctionDef)]
    assert functions and functions[0].name == "promote_niche_to_inventory"
