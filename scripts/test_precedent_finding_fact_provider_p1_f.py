from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import plamen_mechanical as M
import precedent_finding_fact_provider as F
import precedent_evidence_authority as P


RUN_ID = "run-fact-provider"
SNAPSHOT = "a" * 64


def _inventory(*rows: tuple[str, str, str]) -> str:
    parts = ["# Findings Inventory", ""]
    for finding_id, title, body in rows:
        parts.extend(
            [
                f"### Finding [{finding_id}]: {title}",
                "",
                body,
                "",
            ]
        )
    return "\n".join(parts)


def _record(
    finding_id: str,
    *,
    root_cause: str = "free form root cause words",
    mechanism_class: str | None = None,
    preconditions: list[str] | None = None,
) -> dict:
    row = {
        "inventory_id": finding_id,
        "title": f"Title for {finding_id}",
        "root_cause": root_cause,
        "description": "Generic prose must not become a typed fact.",
        "location": "src/module.rs:17",
    }
    if mechanism_class is not None:
        row["mechanism_class"] = mechanism_class
    if preconditions is not None:
        row["precondition_classes"] = preconditions
    return row


def _write_records(root: Path, *rows: dict) -> None:
    inventory_sha = hashlib.sha256(
        (root / F.INVENTORY_NAME).read_bytes()
    ).hexdigest() if (root / F.INVENTORY_NAME).is_file() else ""
    (root / F.TYPED_RECORDS_NAME).write_text(
        json.dumps(
            {
                "schema_version": "plamen.finding_records.v2",
                "source": F.INVENTORY_NAME,
                "source_sha256": inventory_sha,
                "records": list(rows),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _derive(root: Path) -> dict:
    return F.derive_precedent_finding_facts(
        root, run_id=RUN_ID, snapshot_digest=SNAPSHOT
    )


def _by_id(payload: dict) -> dict[str, dict]:
    return {row["finding_id"]: row for row in payload["findings"]}


def test_explicit_typed_semantics_are_bound_to_the_exact_inventory_block(tmp_path: Path):
    text = _inventory(
        (
            "INV-001",
            "State transition mismatch",
            "**Location**: `src/lib.rs:17`\n\n**Description**: bounded.",
        )
    )
    (tmp_path / F.INVENTORY_NAME).write_text(text, encoding="utf-8")
    _write_records(
        tmp_path,
        _record(
            "INV-001",
            mechanism_class="STATE_TRANSITION_MISMATCH",
            preconditions=["CALLER_CONTROLS_INPUT", "DEPENDENT_STATE_PRESENT"],
        ),
    )

    payload = _derive(tmp_path)
    row = _by_id(payload)["INV-001"]

    assert payload["schema_version"] == P.FINDING_FACTS_SCHEMA
    assert payload["status"] == "COMPLETE"
    assert row["mechanism_class"] == "STATE_TRANSITION_MISMATCH"
    assert row["precondition_classes"] == [
        "CALLER_CONTROLS_INPUT",
        "DEPENDENT_STATE_PRESENT",
    ]
    assert row["mechanism_origin"] == "EXPLICIT_TYPED_FIELDS"
    assert row["source_artifact"] == F.INVENTORY_NAME
    assert row["source_artifact_sha256"] == hashlib.sha256(
        (tmp_path / F.INVENTORY_NAME).read_bytes()
    ).hexdigest()
    assert len(row["source_block_sha256"]) == 64
    assert row["source_binding_sha256"] == F.source_binding_digest(row)


def test_typed_semantics_without_exact_source_owner_degrade_to_opaque(tmp_path: Path):
    (tmp_path / F.INVENTORY_NAME).write_text(
        _inventory(("INV-001", "Generic title", "Generic body.")),
        encoding="utf-8",
    )
    (tmp_path / F.TYPED_RECORDS_NAME).write_text(
        json.dumps(
            {
                "schema_version": "plamen.finding_records.v2",
                "records": [
                    _record(
                        "INV-001",
                        mechanism_class="STATE_TRANSITION_MISMATCH",
                        preconditions=["CALLER_CONTROLS_INPUT"],
                    )
                ],
            }
        ),
        encoding="utf-8",
    )

    payload = _derive(tmp_path)
    row = _by_id(payload)["INV-001"]
    assert payload["status"] == "DEGRADED"
    assert row["mechanism_origin"] == "OPAQUE_SOURCE_IDENTITY"
    assert any(
        debt["code"] == "TYPED_RECORD_ARTIFACT_MALFORMED"
        for debt in payload["debts"]
    )


def test_mechanical_finding_record_sidecar_binds_exact_inventory_bytes(tmp_path: Path):
    inventory = _inventory(
        ("INV-001", "Generic title", "**Location**: `src/module.rs:17`")
    )
    (tmp_path / F.INVENTORY_NAME).write_text(inventory, encoding="utf-8")

    assert M._write_finding_records_from_inventory(tmp_path) == 1
    payload = json.loads(
        (tmp_path / F.TYPED_RECORDS_NAME).read_text(encoding="utf-8")
    )
    assert payload["source"] == F.INVENTORY_NAME
    assert payload["source_sha256"] == hashlib.sha256(
        (tmp_path / F.INVENTORY_NAME).read_bytes()
    ).hexdigest()


def test_missing_semantic_fields_get_stable_opaque_identities_not_prose_inference(
    tmp_path: Path,
):
    (tmp_path / F.INVENTORY_NAME).write_text(
        _inventory(
            (
                "L1-CONSENSUS-7",
                "Access control oracle fee overflow",
                "**Root Cause**: A very semantic-looking phrase.\n"
                "**Description**: CALLER CONTROLS INPUT and dependent state.",
            )
        ),
        encoding="utf-8",
    )
    _write_records(
        tmp_path,
        _record("L1-CONSENSUS-7", root_cause="access control oracle fee overflow"),
    )

    first = _derive(tmp_path)
    second = _derive(tmp_path)
    row = first["findings"][0]

    assert first == second
    assert row["mechanism_origin"] == "OPAQUE_SOURCE_IDENTITY"
    assert row["mechanism_class"].startswith("OPAQUE_MECHANISM_")
    assert row["precondition_classes"][0].startswith("OPAQUE_PRECONDITION_")
    assert "ACCESS_CONTROL" not in row["mechanism_class"]
    assert "ORACLE" not in row["mechanism_class"]
    assert row["fact_issues"] == []


def test_missing_typed_records_is_legacy_compatible_and_exactly_block_bound(tmp_path: Path):
    (tmp_path / F.INVENTORY_NAME).write_text(
        _inventory(("APTOS_MOVE-14", "Legacy Move finding", "**Impact**: bounded.")),
        encoding="utf-8",
    )

    payload = _derive(tmp_path)
    row = payload["findings"][0]

    assert row["finding_id"] == "APTOS_MOVE-14"
    assert row["extraction_status"] == "OPAQUE_BOUND"
    assert row["source_block_start_line"] == 3
    assert row["source_block_end_line"] >= row["source_block_start_line"]
    assert any(debt["code"] == "TYPED_RECORD_ARTIFACT_ABSENT" for debt in payload["debts"])


@pytest.mark.parametrize(
    "finding_id",
    ["INV-001", "SOLANA-CPI-9", "APTOS_MOVE-14", "SUI.PT-2", "SOROBAN:AUTH-3", "GO-RUST-L1-21"],
)
def test_legacy_and_non_evm_identities_are_preserved(finding_id: str, tmp_path: Path):
    (tmp_path / F.INVENTORY_NAME).write_text(
        _inventory((finding_id, "Portable identity", "**Impact**: bounded.")),
        encoding="utf-8",
    )

    assert _derive(tmp_path)["findings"][0]["finding_id"] == finding_id.upper()


def test_duplicate_inventory_ids_preserve_each_occurrence_as_unmeasurable_debt(
    tmp_path: Path,
):
    (tmp_path / F.INVENTORY_NAME).write_text(
        _inventory(
            ("INV-001", "First", "**Description**: first body."),
            ("INV-001", "Second", "**Description**: second body."),
        ),
        encoding="utf-8",
    )
    _write_records(tmp_path, _record("INV-001"))

    payload = _derive(tmp_path)
    rows = payload["findings"]

    assert len(rows) == 2
    assert {row["finding_id"] for row in rows} == {"INV-001"}
    assert len({row["source_block_sha256"] for row in rows}) == 2
    assert all(row["extraction_status"] == "UNMEASURABLE" for row in rows)
    assert all(row["mechanism_class"] == "" for row in rows)
    assert any(debt["code"] == "DUPLICATE_INVENTORY_ID" for debt in payload["debts"])


def test_duplicate_typed_ids_cannot_select_semantics_by_order(tmp_path: Path):
    (tmp_path / F.INVENTORY_NAME).write_text(
        _inventory(("INV-001", "One finding", "**Description**: body.")),
        encoding="utf-8",
    )
    _write_records(
        tmp_path,
        _record(
            "INV-001",
            mechanism_class="FIRST_CLASS",
            preconditions=["FIRST_PRECONDITION"],
        ),
        _record(
            "INV-001",
            mechanism_class="SECOND_CLASS",
            preconditions=["SECOND_PRECONDITION"],
        ),
    )

    payload = _derive(tmp_path)
    row = payload["findings"][0]

    assert row["extraction_status"] == "UNMEASURABLE"
    assert row["mechanism_class"] == ""
    assert any(debt["code"] == "DUPLICATE_TYPED_ID" for debt in payload["debts"])


def test_malformed_typed_inventory_degrades_to_raw_opaque_facts(tmp_path: Path):
    (tmp_path / F.INVENTORY_NAME).write_text(
        _inventory(("INV-001", "Raw survivor", "**Description**: body.")),
        encoding="utf-8",
    )
    (tmp_path / F.TYPED_RECORDS_NAME).write_text(
        '{"schema_version":"plamen.finding_records.v2","records":[],"records":[]}',
        encoding="utf-8",
    )

    payload = _derive(tmp_path)
    row = payload["findings"][0]

    assert row["extraction_status"] == "OPAQUE_BOUND"
    assert row["mechanism_class"].startswith("OPAQUE_MECHANISM_")
    assert any(debt["code"] == "TYPED_RECORD_ARTIFACT_MALFORMED" for debt in payload["debts"])


def test_unreadable_inventory_preserves_typed_ids_as_visible_unmeasurable_rows(
    tmp_path: Path,
):
    (tmp_path / F.INVENTORY_NAME).write_bytes(b"\xff\xfe\x00broken")
    _write_records(tmp_path, _record("INV-001"), _record("L1-NODE-2"))

    payload = _derive(tmp_path)

    assert {row["finding_id"] for row in payload["findings"]} == {
        "INV-001",
        "L1-NODE-2",
    }
    assert all(row["extraction_status"] == "UNMEASURABLE" for row in payload["findings"])
    assert all(row["mechanism_class"] == "" for row in payload["findings"])
    assert any(debt["code"] == "INVENTORY_ARTIFACT_MALFORMED" for debt in payload["debts"])


def test_oversized_inventory_is_bounded_and_typed_ids_remain_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(F, "MAX_INVENTORY_BYTES", 24)
    (tmp_path / F.INVENTORY_NAME).write_text(
        _inventory(("INV-001", "Large", "**Description**: body beyond cap.")),
        encoding="utf-8",
    )
    _write_records(tmp_path, _record("INV-001"))

    payload = _derive(tmp_path)

    assert payload["findings"][0]["finding_id"] == "INV-001"
    assert payload["findings"][0]["extraction_status"] == "UNMEASURABLE"
    assert any(debt["code"] == "INVENTORY_ARTIFACT_OVERSIZED" for debt in payload["debts"])


def test_high_cardinality_threshold_flags_but_never_truncates_known_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(F, "MAX_FINDINGS", 1)
    (tmp_path / F.INVENTORY_NAME).write_text(
        _inventory(
            ("INV-001", "First", "**Description**: first."),
            ("INV-002", "Second", "**Description**: second."),
        ),
        encoding="utf-8",
    )

    payload = _derive(tmp_path)

    assert [row["finding_id"] for row in payload["findings"]] == ["INV-001", "INV-002"]
    assert payload["status"] == "DEGRADED"
    assert any(
        debt["code"] == "FINDING_DENOMINATOR_HIGH_CARDINALITY"
        for debt in payload["debts"]
    )


def test_malformed_heading_id_gets_content_bound_debt_identity_not_dropped(tmp_path: Path):
    (tmp_path / F.INVENTORY_NAME).write_text(
        "# Findings\n\n### Finding [bad id with spaces]: Still content\n\nBody.\n",
        encoding="utf-8",
    )

    payload = _derive(tmp_path)
    row = payload["findings"][0]

    assert row["finding_id"].startswith("UNMEASURABLE-")
    assert row["extraction_status"] == "UNMEASURABLE"
    assert row["mechanism_class"] == ""
    assert any(debt["code"] == "FINDING_ID_MALFORMED" for debt in payload["debts"])


def test_source_drift_invalidates_previous_provider_artifact(tmp_path: Path):
    inventory = tmp_path / F.INVENTORY_NAME
    inventory.write_text(
        _inventory(("INV-001", "Before", "**Description**: first.")),
        encoding="utf-8",
    )
    original = _derive(tmp_path)

    inventory.write_text(
        _inventory(("INV-001", "After", "**Description**: changed.")),
        encoding="utf-8",
    )

    issues = F.validate_precedent_finding_facts(
        original, tmp_path, run_id=RUN_ID, snapshot_digest=SNAPSHOT
    )
    assert any("stale" in issue for issue in issues)
    assert _derive(tmp_path)["findings"][0]["source_binding_sha256"] != original["findings"][0]["source_binding_sha256"]


def test_one_derivation_reads_each_source_once_and_receipt_binds_those_same_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    inventory = tmp_path / F.INVENTORY_NAME
    inventory.write_text(
        _inventory(("INV-001", "Stable", "**Description**: body.")),
        encoding="utf-8",
    )
    original_bounded_read = F.read_bounded_regular_bytes
    calls: dict[Path, int] = {}

    def counted_read_bytes(path: Path, limit: int) -> bytes:
        calls[path] = calls.get(path, 0) + 1
        return original_bounded_read(path, limit)

    monkeypatch.setattr(F, "read_bounded_regular_bytes", counted_read_bytes)
    payload = _derive(tmp_path)

    assert calls[inventory] == 1
    descriptor = next(
        row for row in payload["input_artifacts"] if row["artifact"] == F.INVENTORY_NAME
    )
    assert descriptor["sha256"] == payload["findings"][0]["source_artifact_sha256"]


def test_empty_denominator_is_explicit_debt_not_synthetic_success(tmp_path: Path):
    (tmp_path / F.INVENTORY_NAME).write_text("# Findings Inventory\n\nNone.\n", encoding="utf-8")
    _write_records(tmp_path)

    payload = _derive(tmp_path)

    assert payload["findings"] == []
    assert payload["denominator_count"] == 0
    assert payload["status"] == "DEGRADED"
    assert any(debt["code"] == "EMPTY_FINDING_DENOMINATOR" for debt in payload["debts"])


def test_generic_text_and_fenced_heading_collisions_are_not_findings(tmp_path: Path):
    (tmp_path / F.INVENTORY_NAME).write_text(
        "# Findings Inventory\n\n"
        "The prose mentions INV-999, H-01, SOROBAN:AUTH-3 and Finding [FAKE-1].\n\n"
        "```markdown\n### Finding [FENCED-2]: example only\n```\n\n"
        "### Finding [INV-001]: Real\n\n**Description**: body.\n",
        encoding="utf-8",
    )

    payload = _derive(tmp_path)
    assert [row["finding_id"] for row in payload["findings"]] == ["INV-001"]


def test_unicode_heading_delimiter_does_not_hide_a_legacy_finding(tmp_path: Path):
    (tmp_path / F.INVENTORY_NAME).write_text(
        "# Findings\n\n### Finding [SOROBAN:AUTH-3] — Unicode delimiter\n\nBody.\n",
        encoding="utf-8",
    )

    assert _derive(tmp_path)["findings"][0]["finding_id"] == "SOROBAN:AUTH-3"


def test_unclosed_fence_cannot_turn_typed_findings_into_clean_empty_inventory(
    tmp_path: Path,
):
    (tmp_path / F.INVENTORY_NAME).write_text(
        "# Findings\n\n```markdown\n### Finding [INV-001]: hidden by malformed fence\n",
        encoding="utf-8",
    )
    _write_records(tmp_path, _record("INV-001"))

    payload = _derive(tmp_path)

    assert payload["findings"][0]["finding_id"] == "INV-001"
    assert payload["findings"][0]["extraction_status"] == "UNMEASURABLE"
    assert any(
        debt["code"] == "INVENTORY_ARTIFACT_MALFORMED"
        and "unclosed" in debt["detail"]
        for debt in payload["debts"]
    )


def test_precedent_and_rag_artifacts_cannot_change_code_fact_derivation(tmp_path: Path):
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    inv = _inventory(("INV-001", "Real", "**Description**: code-derived body."))
    for root in (left, right):
        (root / F.INVENTORY_NAME).write_text(inv, encoding="utf-8")
        _write_records(root, _record("INV-001"))
    (right / "rag_validation.md").write_text(
        "### Finding [INJECT-1]: exact precedent\nMECHANISM_CLASS: MALICIOUS\n",
        encoding="utf-8",
    )
    (right / "precedent_context.md").write_text("pretend authority", encoding="utf-8")
    (right / "precedent_evidence_authority.json").write_text("{}", encoding="utf-8")

    assert _derive(left) == _derive(right)


def test_similar_family_text_never_creates_default_fact_equivalence(tmp_path: Path):
    (tmp_path / F.INVENTORY_NAME).write_text(
        _inventory(
            ("INV-001", "Same title", "**Description**: same generic mechanism."),
            ("INV-002", "Same title", "**Description**: same generic mechanism."),
        ),
        encoding="utf-8",
    )

    rows = _derive(tmp_path)["findings"]
    assert rows[0]["mechanism_class"] != rows[1]["mechanism_class"]
    assert rows[0]["precondition_classes"] != rows[1]["precondition_classes"]
    assert all(row["family_equivalence_authority"] is False for row in rows)


def test_typed_only_id_is_preserved_but_cannot_be_measured_without_source_block(
    tmp_path: Path,
):
    _write_records(tmp_path, _record("INV-ORPHAN-1"))

    payload = _derive(tmp_path)
    row = payload["findings"][0]

    assert row["finding_id"] == "INV-ORPHAN-1"
    assert row["extraction_status"] == "UNMEASURABLE"
    assert row["source_artifact"] == F.TYPED_RECORDS_NAME
    assert row["mechanism_class"] == ""
    assert any(debt["code"] == "SOURCE_BLOCK_MISSING" for debt in payload["debts"])


def test_writer_is_idempotent_and_tamper_validation_fails(tmp_path: Path):
    (tmp_path / F.INVENTORY_NAME).write_text(
        _inventory(("INV-001", "One", "**Description**: body.")),
        encoding="utf-8",
    )
    first = F.write_precedent_finding_facts(
        tmp_path, run_id=RUN_ID, snapshot_digest=SNAPSHOT
    )
    first_bytes = (tmp_path / F.FACTS_NAME).read_bytes()
    second = F.write_precedent_finding_facts(
        tmp_path, run_id=RUN_ID, snapshot_digest=SNAPSHOT
    )

    assert first == second
    assert first_bytes == (tmp_path / F.FACTS_NAME).read_bytes()
    assert F.validate_precedent_finding_facts(
        second, tmp_path, run_id=RUN_ID, snapshot_digest=SNAPSHOT
    ) == []

    tampered = copy.deepcopy(second)
    tampered["findings"][0]["family_equivalence_authority"] = True
    assert F.validate_precedent_finding_facts(
        tampered, tmp_path, run_id=RUN_ID, snapshot_digest=SNAPSHOT
    )


def test_provider_rows_feed_existing_reconciler_and_debt_rows_stay_unmeasurable(
    tmp_path: Path,
):
    (tmp_path / F.INVENTORY_NAME).write_text(
        _inventory(
            ("INV-001", "First", "**Description**: first body."),
            ("INV-001", "Second", "**Description**: second body."),
        ),
        encoding="utf-8",
    )
    facts = _derive(tmp_path)
    proposals = {
        "schema_version": P.PROPOSAL_SCHEMA,
        "run_id": RUN_ID,
        "snapshot_digest": SNAPSHOT,
        "proposals": [],
    }

    authority = P.reconcile_precedent_evidence(facts, proposals)

    rows = authority["finding_precedent"]
    assert len(rows) == 2
    assert len({row["finding_id"] for row in rows}) == 2
    assert all(row["finding_id"].startswith("UNMEASURABLE-") for row in rows)
    assert all(row["match_status"] == "UNMEASURABLE" for row in rows)
    assert all(row["mechanism_confidence_delta"] == 0.0 for row in rows)
    assert any(
        debt["code"] == "FINDING_FACT_MALFORMED"
        and "duplicated" in debt["detail"]
        for debt in authority["debts"]
    )


def test_fact_payload_has_no_verdict_severity_proof_or_precedent_authority(tmp_path: Path):
    (tmp_path / F.INVENTORY_NAME).write_text(
        _inventory(("INV-001", "One", "**Severity**: Critical\n**Verdict**: Confirmed.")),
        encoding="utf-8",
    )

    payload = _derive(tmp_path)
    row = payload["findings"][0]

    assert "severity" not in row
    assert "verdict" not in row
    assert "proof" not in row
    assert "precedent" not in row
    assert payload["capabilities"] == {
        "may_change_severity": False,
        "may_clear_or_demote": False,
        "may_force_contested": False,
        "may_grant_proof": False,
        "may_propagate_family_equivalence": False,
    }
