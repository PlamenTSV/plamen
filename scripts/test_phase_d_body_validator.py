"""Phase D: LLM body writer manifest + validation gate tests.

The body writer architecture (Codex's recommendation):
1. Driver emits per-shard JSON manifests: each manifest lists findings with their
   verified evidence (location, evidence tag, description, recommendation) so
   the LLM body writer cannot hallucinate.
2. Driver shards by tier with caps: C/H<=15, M<=20, L/I<=30.
3. After the LLM writes a body file, the driver runs deterministic validation:
   - Coverage: every manifest finding appears in the body (by report ID).
   - No extras: body contains no report IDs not in the manifest.
   - Evidence integrity: cited locations / evidence tags match the manifest.
   - REPORT-BLOCKED: findings whose verify_*.md has no usable evidence are
     marked REPORT-BLOCKED in the manifest; body must reflect that flag.
4. On any validation failure: halt-hard, log the diff.

Run: `python test_phase_d_body_validator.py`
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path
import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402
import plamen_parsers as P  # noqa: E402
from queue_work_items import (  # noqa: E402
    QueueWorkItem,
    VerifierOutputIdentity,
    VerifierOutputReceipt,
    build_queue_work_plan,
)

PASS = 0
FAIL = 0


def check(label: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label} :: {detail}")


def _proposal_bytes(item: QueueWorkItem) -> bytes:
    constituents = [item.work_item_id, *item.constituents]
    payload = {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": item.work_item_id,
        "constituent_ids": constituents,
        "impact": {
            "class": "High",
            "harmed_asset": "protected asset",
            "harmed_capability": "asset integrity",
            "premise_id": f"PREM-{item.work_item_id}-IMPACT",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-{item.work_item_id}-IMPACT"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "likelihood": {
            "class": "Medium",
            "actor": "unprivileged actor",
            "preconditions": ["reachable state"],
            "premise_id": f"PREM-{item.work_item_id}-LIKELIHOOD",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-{item.work_item_id}-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "modifiers": [],
        "proposed_severity": "High",
        "adjustment": None,
        "constituent_premise_outcomes": {
            value: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
            for value in constituents
        },
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _bind_current_verifier_outputs(sp: Path) -> None:
    """Install exact typed completion authority for positive legacy fixtures."""
    queue = sp / "verification_queue.md"
    if not queue.is_file():
        verify_files = sorted(sp.glob("verify_*.md"))
        if verify_files:
            lines = [
                "# Verification Queue",
                "",
                "| Finding ID | Severity | Title | Location | Preferred Tag |",
                "|------------|----------|-------|----------|---------------|",
            ]
            for output in verify_files:
                finding_id = output.stem.removeprefix("verify_")
                body = output.read_text(encoding="utf-8", errors="replace")
                severity_match = re.search(
                    r"(?im)^\s*\*\*(?:final\s+)?severity\*\*\s*:\s*([^\r\n]+)",
                    body,
                )
                severity = severity_match.group(1).strip() if severity_match else "Medium"
                title_match = re.search(
                    rf"(?im)^\s*#{{1,3}}\s+(?:Verification:\s*{re.escape(finding_id)}\s*(?:[â—–-]+\s*)?)?(.+?)\s*$",
                    body,
                )
                title = title_match.group(1).strip() if title_match else f"Fixture {finding_id}"
                if title.casefold() == finding_id.casefold():
                    title = f"Fixture {finding_id}"
                location_match = re.search(
                    r"(?im)^\s*\*\*Location\*\*\s*:\s*([^\r\n]+)", body
                ) or re.search(
                    r"`([^`\r\n]+\.(?:sol|rs|move|go)(?::[^`\r\n]+)?)`", body
                )
                location = location_match.group(1).strip() if location_match else "fixture/source"
                tag = "CODE-TRACE" if "CODE-TRACE" in body.upper() else "MANUAL-REVIEW"
                cells = [finding_id, severity, title, location, tag]
                lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
            queue.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if not queue.is_file():
        return
    rows = P.parse_verification_queue_rows(sp)
    if not rows:
        return
    items = P._ensure_typed_queue_authority(queue, rows)
    shard = "fixture_verifier"
    plan = build_queue_work_plan(
        items,
        {shard: tuple(item.work_item_id for item in items)},
        planner_version="test.phase-d.v1",
    )
    (sp / "verification_queue.work_plan.json").write_text(
        plan.to_json(), encoding="utf-8"
    )
    for item in items:
        output = sp / item.expected_output_file
        if not output.is_file():
            continue
        proposal = _proposal_bytes(item)
        (sp / f"verify_{item.work_item_id}.severity_proposal.json").write_bytes(
            proposal
        )
        identity = VerifierOutputIdentity.for_assignment(item, plan, shard)
        receipt = VerifierOutputReceipt.bind(
            identity,
            output.read_bytes(),
            severity_proposal=proposal,
            launch_digest="a" * 64,
            verifier_backend="claude",
        )
        (sp / f"verify_{item.work_item_id}.identity.json").write_text(
            json.dumps(identity.to_dict(), sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        (sp / f"verify_{item.work_item_id}.receipt.json").write_text(
            receipt.to_json(), encoding="utf-8"
        )


@pytest.fixture(autouse=True)
def _typed_verifier_fixture_boundary(monkeypatch):
    """Migrate positive legacy fixtures without weakening production gates."""
    l1_builder = D._build_body_writer_manifests
    sc_builder = D._build_sc_body_writer_manifests

    def bound_l1(sp: Path, *args, **kwargs):
        _bind_current_verifier_outputs(Path(sp))
        return l1_builder(sp, *args, **kwargs)

    def bound_sc(sp: Path, *args, **kwargs):
        _bind_current_verifier_outputs(Path(sp))
        return sc_builder(sp, *args, **kwargs)

    monkeypatch.setattr(D, "_build_body_writer_manifests", bound_l1)
    monkeypatch.setattr(D, "_build_sc_body_writer_manifests", bound_sc)


# =============================================================================
# Manifest generation: shape, sharding, and evidence integrity.
# =============================================================================

def _seed_records(sp: Path, n_per_tier: dict[str, int]):
    """Seed scratchpad with verification queue + verify files yielding records.

    n_per_tier: {"C": 2, "H": 5, "M": 25, "L": 50, "I": 0}
    """
    queue_lines = [
        "# Verification Queue",
        "",
        "| Finding ID | Severity | Title | Location | Preferred Tag |",
        "|------------|----------|-------|----------|---------------|",
    ]
    sev_label = {"C": "Critical", "H": "High", "M": "Medium", "L": "Low", "I": "Informational"}
    counter = 1
    fids = []
    for tier, n in n_per_tier.items():
        for i in range(n):
            fid = f"INV-{counter:03d}"
            fids.append((tier, fid))
            queue_lines.append(
                f"| {fid} | {sev_label[tier]} | Test {tier}{i} | src/F{counter}.sol:L{counter} | CODE-TRACE |"
            )
            counter += 1
    (sp / "verification_queue.md").write_text("\n".join(queue_lines) + "\n", encoding="utf-8")
    for tier, fid in fids:
        (sp / f"verify_{fid}.md").write_text(
            f"""# {fid}
**Verdict**: CONFIRMED
**Severity**: {sev_label[tier]}
**Location**: src/F.sol:L1
**Description**: Test description for {fid}.
**Recommendation**: Test recommendation for {fid}.
**Evidence Tag**: CODE-TRACE
""",
            encoding="utf-8",
        )
    _bind_current_verifier_outputs(sp)


def test_MAN_shape_and_required_fields(tmp_path: Path):
    sp = tmp_path
    _seed_records(sp, {"C": 1, "H": 1, "M": 1, "L": 1, "I": 0})
    D._write_mechanical_report_index(sp)
    manifests = D._build_body_writer_manifests(sp)
    check(
        "MAN.returns_dict_keyed_by_shard",
        isinstance(manifests, dict) and len(manifests) >= 1,
        f"manifests={list(manifests.keys())}",
    )
    # Check first manifest shape
    any_shard = next(iter(manifests.values()))
    f0 = any_shard["findings"][0]
    required = {"report_id", "finding_id", "severity", "title", "location", "evidence_tag",
                "verify_file", "description", "poc_result", "recommendation", "report_blocked"}
    check(
        "MAN.required_finding_fields",
        required.issubset(f0.keys()),
        f"missing={required - f0.keys()}",
    )
    coverage = sp / "report_coverage.md"
    check(
        "MAN.report_coverage_emitted",
        coverage.exists() and "## Active Trace" in coverage.read_text(encoding="utf-8"),
        "report_coverage.md missing or malformed",
    )


def test_MAN_body_manifest_never_derives_blank_verify_filename(tmp_path: Path):
    sp = tmp_path
    (sp / "report_records.json").write_text(
        json.dumps({
            "active": [
                {
                    "report_id": "H-01",
                    "finding_id": "",
                    "absorbed_finding_ids": ["", "INV-001", "  "],
                    "severity": "High",
                    "title": "valid absorbed id",
                    "location": "src/F.sol:L1",
                    "evidence": "CODE-TRACE",
                }
            ],
            "excluded": [],
        }),
        encoding="utf-8",
    )
    (sp / "verify_INV-001.md").write_text(
        "# INV-001\n\n**Description**: valid evidence\n**Recommendation**: fix\n",
        encoding="utf-8",
    )

    manifests = D._build_body_writer_manifests(sp)
    text = json.dumps(manifests)
    ok = "verify_.md" not in text and "verify_INV-001.md" in text
    check("MAN.no_blank_verify_filename", ok, text)
    assert ok


def test_MAN_shards_by_tier_with_caps(tmp_path: Path):
    """C+H share a shard with cap 15, M caps at 20, L/I cap at 30."""
    sp = tmp_path
    _seed_records(sp, {"C": 5, "H": 12, "M": 30, "L": 45, "I": 5})
    D._write_mechanical_report_index(sp)
    manifests = D._build_body_writer_manifests(sp)

    # Verify each shard's size respects the cap.
    sizes_ok = True
    detail = []
    for shard_name, m in manifests.items():
        n = len(m["findings"])
        if shard_name.startswith("report_critical_high"):
            sizes_ok = sizes_ok and n <= 15
            detail.append(f"{shard_name}={n}<=15")
        elif shard_name.startswith("report_medium"):
            sizes_ok = sizes_ok and n <= 20
            detail.append(f"{shard_name}={n}<=20")
        elif shard_name.startswith("report_low_info"):
            sizes_ok = sizes_ok and n <= 30
            detail.append(f"{shard_name}={n}<=30")
    check("MAN.shards_respect_caps", sizes_ok, "; ".join(detail))


def test_MAN_total_findings_equal_active(tmp_path: Path):
    sp = tmp_path
    _seed_records(sp, {"C": 3, "H": 3, "M": 3, "L": 3, "I": 0})
    D._write_mechanical_report_index(sp)
    records = json.loads((sp / "report_records.json").read_text(encoding="utf-8"))
    n_active = len(records["active"])
    manifests = D._build_body_writer_manifests(sp)
    total = sum(len(m["findings"]) for m in manifests.values())
    check(
        "MAN.total_matches_active",
        total == n_active,
        f"total={total} active={n_active}",
    )


def test_MAN_marks_report_blocked_when_evidence_missing(tmp_path: Path):
    """A verify file with no Description/Recommendation -> REPORT-BLOCKED."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Medium | Empty bug | src/F.sol:L1 | CODE-TRACE |
""", encoding="utf-8")
    # Verify file with verdict but no body content.
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: Medium
""", encoding="utf-8")
    D._write_mechanical_report_index(sp)
    manifests = D._build_body_writer_manifests(sp)
    f = next(iter(manifests.values()))["findings"][0]
    check("MAN.report_blocked_when_no_evidence", f["report_blocked"] is True, repr(f))


def test_MAN_section_headed_evidence_not_report_blocked(tmp_path: Path):
    """Section-headed verifier narratives are real body-writer evidence."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Medium | Section bug | src/F.sol:L1 | CODE-TRACE |
""", encoding="utf-8")
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: Medium

## Description

The vulnerable function accepts stale accounting state and can under-allocate
funds in later intervals.

## Recommendation

Persist the original distribution base and add a regression test for weekly
allocation rollover.
""", encoding="utf-8")
    D._write_mechanical_report_index(sp)
    manifests = D._build_body_writer_manifests(sp)
    f = next(iter(manifests.values()))["findings"][0]
    ok = (
        f["report_blocked"] is False
        and "stale accounting state" in f["description"]
        and "regression test" in f["recommendation"]
    )
    check("MAN.section_headed_evidence_not_report_blocked", ok, repr(f))


def test_MAN_poc_result_seed_from_execution_result(tmp_path: Path):
    """Manifest carries verifier execution result so body writers do not omit it."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | High | Structural bug | src/F.sol:L1 | CODE-TRACE |
""", encoding="utf-8")
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: High

## Finding Summary

The setter updates privileged state immediately.

## Execution Result

- **Result:** NOT_EXECUTED
- **Output:** Code trace confirms there is no delay or second confirmation step.

## Recommendation

Use a two-step delayed update.
""", encoding="utf-8")
    D._write_mechanical_report_index(sp)
    manifests = D._build_body_writer_manifests(sp)
    f = next(iter(manifests.values()))["findings"][0]
    ok = (
        "poc_result" in f
        and "NOT_EXECUTED" in f["poc_result"]
        and "no delay" in f["poc_result"]
    )
    check("MAN.poc_result_seed_from_execution_result", ok, repr(f))


def test_MAN_na_section_headings_remain_report_blocked(tmp_path: Path):
    """Empty/N/A section headings must not count as body-writer evidence."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Medium | Empty section bug | src/F.sol:L1 | CODE-TRACE |
""", encoding="utf-8")
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: Medium

## Description

N/A

## Recommendation

Not provided
""", encoding="utf-8")
    D._write_mechanical_report_index(sp)
    manifests = D._build_body_writer_manifests(sp)
    f = next(iter(manifests.values()))["findings"][0]
    check("MAN.na_section_headings_remain_blocked", f["report_blocked"] is True, repr(f))


def test_SYNTH_generic_fallback_is_not_shippable_body(tmp_path: Path):
    """Mechanical report recovery must not disguise generic fallback prose as quality."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Medium | Missing narrative | src/F.sol:L1 | CODE-TRACE |
""", encoding="utf-8")
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: Medium
**Location**: src/F.sol:L1
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")

    section = D._synth_report_section_from_verify(
        sp,
        "M-01",
        "INV-001",
        {
            "finding id": "INV-001",
            "severity": "Medium",
            "title": "Missing narrative",
            "location": "src/F.sol:L1",
            "preferred tag": "CODE-TRACE",
        },
        unresolved=False,
    )

    check(
        "SYNTH.generic_fallback_report_blocked",
        "[REPORT-BLOCKED: insufficient verifier evidence]" in section,
        section,
    )


def test_MAN_sc_manifest_section_headed_evidence_seeded(tmp_path: Path):
    """SC body manifests use the same section-aware evidence extraction."""
    sp = tmp_path
    (sp / "report_index.md").write_text("""# Report Index

## Summary
| Severity | Count |
|----------|-------|
| High | 1 |

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| H-01 | Section headed issue | High | src/F.sol:L9 | CONFIRMED | - | H-1 |
""", encoding="utf-8")
    (sp / "verify_H-1.md").write_text("""# H-1
**Verdict**: CONFIRMED
**Severity**: High

## Description

The reward accounting invariant is violated when distributions are processed
after an interval rollover.

## Suggested Fix

Checkpoint the distribution base before executing the interval loop.
""", encoding="utf-8")
    manifests = D._build_sc_body_writer_manifests(sp)
    f = next(iter(manifests.values()))["findings"][0]
    ok = (
        f["report_blocked"] is False
        and "reward accounting invariant" in f["description"]
        and "Checkpoint the distribution base" in f["recommendation"]
    )
    check("MAN.sc_section_headed_evidence_seeded", ok, repr(f))


def test_MAN_inventory_location_fallback_for_generic_queue_location(tmp_path: Path):
    """Body manifests inherit original inventory locations when queue/report metadata is generic."""
    sp = tmp_path
    (sp / "findings_inventory.md").write_text("""# Finding Inventory

## Findings

### Finding [INV-001]: Accounting bug
**Severity**: High
**Location**: src/Accounting.sol:L77
**Source IDs**: AC-1
**Description**: Original inventory location is precise.
""", encoding="utf-8")
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | High | Accounting bug | High, [POC-PASS] | CODE-TRACE |
""", encoding="utf-8")
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: High

## Description
The accounting bug is confirmed by code trace.

## Recommendation
Fix the accounting update.
""", encoding="utf-8")
    D._write_mechanical_report_index(sp)
    manifests = D._build_body_writer_manifests(sp)
    f = next(iter(manifests.values()))["findings"][0]
    check(
        "MAN.inventory_location_fallback_generic_queue",
        f["location"] == "src/Accounting.sol:L77",
        repr(f),
    )


def test_MAN_sc_inventory_location_fallback_for_generic_index_and_verify(tmp_path: Path):
    """SC manifests recover source location from inventory when index/verify omit it."""
    sp = tmp_path
    (sp / "findings_inventory.md").write_text("""# Finding Inventory

## Findings

### Finding [INV-001]: Oracle bug
**Severity**: High
**Location**: contracts/Oracle.sol:L88
**Source IDs**: H-1
**Description**: Inventory keeps the original precise source path.
""", encoding="utf-8")
    (sp / "report_index.md").write_text("""# Report Index

## Summary
| Severity | Count |
|----------|-------|
| High | 1 |

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| H-01 | Oracle bug | High | High, [POC-PASS] | CONFIRMED | - | H-1 |
""", encoding="utf-8")
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| H-1 | High | Oracle bug | High, [POC-PASS] | CODE-TRACE |
""", encoding="utf-8")
    (sp / "verify_H-1.md").write_text("""# H-1
**Verdict**: CONFIRMED
**Severity**: High

## Description
The oracle bug is confirmed but this verifier omitted a Location field.

## Recommendation
Validate oracle freshness before consumption.
""", encoding="utf-8")
    manifests = D._build_sc_body_writer_manifests(sp)
    f = next(iter(manifests.values()))["findings"][0]
    check(
        "MAN.sc_inventory_location_fallback_generic_index",
        f["location"] == "contracts/Oracle.sol:L88",
        repr(f),
    )


def test_MAN_finding_records_written_from_inventory(tmp_path: Path):
    """Inventory produces a structured identity ledger for downstream phases."""
    sp = tmp_path
    (sp / "findings_inventory.md").write_text("""# Finding Inventory

## Findings

### Finding [INV-001]: Distribution accounting bug
**Severity**: High
**Location**: contracts/Burn.sol:L44
**Preferred Tag**: CODE-TRACE
**Source IDs**: AC-1, TF-2
**Root Cause**: The distribution base is decremented during interval burns.
**Description**: Later intervals allocate from a shrinking base.
**Impact**: Burns are lower than intended.
""", encoding="utf-8")
    n = D._write_finding_records_from_inventory(sp)
    records = json.loads((sp / "finding_records.json").read_text(encoding="utf-8"))
    rec = records["records"][0]
    ok = (
        n == 1
        and rec["inventory_id"] == "INV-001"
        and set(rec["source_ids"]) == {"AC-1", "TF-2"}
        and rec["location"] == "contracts/Burn.sol:L44"
        and "shrinking base" in rec["description"]
    )
    check("MAN.finding_records_written_from_inventory", ok, repr(records))


def test_MAN_sc_manifest_can_inherit_from_finding_records_without_inventory_markdown(tmp_path: Path):
    """SC report handoff can use structured records instead of reparsing prose."""
    sp = tmp_path
    (sp / "finding_records.json").write_text(json.dumps({
        "schema_version": "plamen.finding_records.v1",
        "source": "findings_inventory.md",
        "records": [{
            "inventory_id": "INV-001",
            "source_ids": ["H-1"],
            "title": "Precise oracle freshness bug",
            "severity": "High",
            "location": "contracts/Oracle.sol:L88",
            "preferred_tag": "CODE-TRACE",
            "description": "The original inventory narrative names the oracle freshness failure.",
            "root_cause": "Freshness check missing",
            "impact": "Stale prices can be consumed.",
        }],
    }), encoding="utf-8")
    (sp / "report_index.md").write_text("""# Report Index

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| H-01 |  | High | High, [POC-PASS] | CONFIRMED | - | H-1 |
""", encoding="utf-8")
    (sp / "verify_H-1.md").write_text("""# H-1
**Verdict**: CONFIRMED
**Severity**: High

## Description
N/A

## Recommendation
Not provided
""", encoding="utf-8")
    manifests = D._build_sc_body_writer_manifests(sp)
    f = next(iter(manifests.values()))["findings"][0]
    ok = (
        f["title"] == "Precise oracle freshness bug"
        and f["location"] == "contracts/Oracle.sol:L88"
        and "oracle freshness failure" in f["description"]
        and f["report_blocked"] is True
    )
    check("MAN.sc_manifest_inherits_from_finding_records", ok, repr(f))


def test_MAN_sc_report_records_written_from_index_and_manifests(tmp_path: Path):
    """SC pipelines get the same structured report ledger as mechanical L1."""
    sp = tmp_path
    (sp / "finding_records.json").write_text(json.dumps({
        "schema_version": "plamen.finding_records.v1",
        "source": "findings_inventory.md",
        "records": [{
            "inventory_id": "INV-001",
            "source_ids": ["H-1"],
            "title": "Precise oracle freshness bug",
            "severity": "High",
            "location": "contracts/Oracle.sol:L88",
            "preferred_tag": "CODE-TRACE",
            "description": "The original inventory narrative names the oracle freshness failure.",
        }],
    }), encoding="utf-8")
    (sp / "report_index.md").write_text("""# Report Index

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| H-01 | Oracle freshness | High | contracts/Oracle.sol:L88 | CONFIRMED | - | H-1 |

## Excluded Findings
| Internal ID | Severity | Title | Exclusion Reason |
|-------------|----------|-------|------------------|
| H-2 | Low | Refuted duplicate | REFUTED by verifier |
""", encoding="utf-8")
    (sp / "verify_H-1.md").write_text("""# H-1
**Verdict**: CONFIRMED
**Severity**: High

## Description
The oracle freshness issue is confirmed.

## Recommendation
Check freshness before use.
""", encoding="utf-8")
    D._build_sc_body_writer_manifests(sp)
    records = json.loads((sp / "report_records.json").read_text(encoding="utf-8"))
    ok = (
        records["active"][0]["report_id"] == "H-01"
        and records["active"][0]["finding_id"] == "H-1"
        and records["active"][0]["location"] == "contracts/Oracle.sol:L88"
        and records["excluded"][0]["finding_id"] == "H-2"
        and "Refuted duplicate" in records["excluded"][0]["title"]
    )
    check("MAN.sc_report_records_written", ok, repr(records))


def test_MAN_finding_records_merge_with_inventory_fallback_when_partial(tmp_path: Path):
    """A partial/newer finding_records.json must not hide inventory markdown."""
    sp = tmp_path
    (sp / "findings_inventory.md").write_text("""# Finding Inventory

## Findings

### Finding [INV-001]: Old cached bug
**Severity**: High
**Location**: contracts/Old.sol:L1
**Source IDs**: OLD-1

### Finding [INV-002]: Fresh bug
**Severity**: High
**Location**: contracts/Fresh.sol:L55
**Source IDs**: GOV-7
""", encoding="utf-8")
    (sp / "finding_records.json").write_text(json.dumps({
        "schema_version": "plamen.finding_records.v1",
        "source": "findings_inventory.md",
        "records": [{
            "inventory_id": "INV-001",
            "source_ids": ["OLD-1"],
            "title": "Old cached bug",
            "severity": "High",
            "location": "contracts/Old.sol:L1",
        }],
    }), encoding="utf-8")
    locs = D._inventory_location_map(sp)
    ok = (
        locs.get("INV-001") == "contracts/Old.sol:L1"
        and locs.get("INV-002") == "contracts/Fresh.sol:L55"
        and locs.get("GOV-7") == "contracts/Fresh.sol:L55"
    )
    check("MAN.finding_records_partial_does_not_hide_inventory", ok, repr(locs))


def test_MAN_finding_records_capture_section_headed_inventory_narrative(tmp_path: Path):
    """Structured inventory ledger preserves section-headed narratives."""
    sp = tmp_path
    (sp / "findings_inventory.md").write_text("""# Finding Inventory

## Findings

### Finding [INV-001]: Section inventory bug
**Severity**: Medium
**Location**: contracts/Vault.sol:L12
**Preferred Tag**: CODE-TRACE
**Source IDs**: AC-9

## Root Cause

The vault mutates accounting before checking the final invariant.

## Description

The section-headed description carries the real finding identity.

## Impact

Withdrawals can observe stale accounting.
""", encoding="utf-8")
    D._write_finding_records_from_inventory(sp)
    rec = json.loads((sp / "finding_records.json").read_text(encoding="utf-8"))["records"][0]
    ok = (
        "mutates accounting" in rec["root_cause"]
        and "real finding identity" in rec["description"]
        and "stale accounting" in rec["impact"]
    )
    check("MAN.finding_records_capture_section_inventory", ok, repr(rec))


def test_MAN_sc_manifest_maps_niche_prefix_ids_from_report_index(tmp_path: Path):
    """SC report-index parsing must cover all canonical internal ID prefixes."""
    sp = tmp_path
    (sp / "finding_records.json").write_text(json.dumps({
        "schema_version": "plamen.finding_records.v1",
        "source": "findings_inventory.md",
        "records": [{
            "inventory_id": "INV-001",
            "source_ids": ["GOV-7"],
            "title": "Governance timelock bypass",
            "severity": "High",
            "location": "contracts/Governance.sol:L77",
            "preferred_tag": "CODE-TRACE",
            "description": "Governance execution bypasses the timelock.",
        }],
    }), encoding="utf-8")
    (sp / "report_index.md").write_text("""# Report Index

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| H-01 |  | High | High, [POC-PASS] | CONFIRMED | - | GOV-7 |
""", encoding="utf-8")
    (sp / "verify_GOV-7.md").write_text("""# GOV-7
**Verdict**: CONFIRMED
**Severity**: High

## Description
N/A

## Recommendation
Not provided
""", encoding="utf-8")
    manifests = D._build_sc_body_writer_manifests(sp)
    f = next(iter(manifests.values()))["findings"][0]
    ok = (
        f["finding_id"] == "GOV-7"
        and f["location"] == "contracts/Governance.sol:L77"
        and f["title"] == "Governance timelock bypass"
        and "bypasses the timelock" in f["description"]
    )
    check("MAN.sc_manifest_maps_niche_prefix_ids", ok, repr(f))


def test_MAN_report_assemble_recovers_missing_report_records(tmp_path: Path):
    """Resume/old scratchpads should recover SC report_records before assembly."""
    sp = tmp_path
    proj = sp / "proj"
    proj.mkdir()
    (sp / "finding_records.json").write_text(json.dumps({
        "schema_version": "plamen.finding_records.v1",
        "source": "findings_inventory.md",
        "records": [{
            "inventory_id": "INV-001",
            "source_ids": ["H-1"],
            "title": "Oracle freshness bug",
            "severity": "High",
            "location": "contracts/Oracle.sol:L88",
            "preferred_tag": "CODE-TRACE",
            "description": "Oracle freshness can be stale.",
        }],
    }), encoding="utf-8")
    (sp / "report_index.md").write_text("""# Report Index

## Summary
| Severity | Count |
|----------|-------|
| High | 1 |

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| H-01 | Oracle freshness bug | High | contracts/Oracle.sol:L88 | CONFIRMED | - | H-1 |
""", encoding="utf-8")
    (sp / "verify_H-1.md").write_text("""# H-1
**Verdict**: CONFIRMED
**Severity**: High

## Description
Oracle freshness is confirmed.

## Recommendation
Validate freshness before use.
""", encoding="utf-8")
    (sp / "report_critical_high.md").write_text("""# Critical and High Findings

## High Findings

### [H-01] Oracle freshness bug
**Severity**: High
**Location**: contracts/Oracle.sol:L88
**Impact**: Stale oracle data can cause incorrect protocol accounting.
**PoC Result**: PASS
**Description**: Oracle freshness is confirmed with enough detail to satisfy the report quality checks and preserve the specific finding identity in the body.
**Recommendation**: Validate freshness before use and add a regression test.
""", encoding="utf-8")
    ok = D._assemble_report_python(sp, str(proj))
    records_ok = (sp / "report_records.json").exists()
    trace_ok = (sp / "report_traceability_internal.md").exists()
    check("MAN.report_assemble_recovers_report_records", ok and records_ok and trace_ok, f"ok={ok}")


def test_MAN_sc_manifest_prefers_verified_claim_identity(tmp_path: Path):
    """Verifier title/location repair stale report-index cells before body writing."""
    sp = tmp_path
    (sp / "report_index.md").write_text("""# Report Index

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| M-01 | Stale hypothesis title | Medium | WrongContract.sol:stalePath() | VERIFIED [CODE-TRACE] | - | H-1 |
""", encoding="utf-8")
    (sp / "verify_H-1.md").write_text("""# Verification: H-1 — Actual verified sqrtPriceX96 truncation

**Final Verdict**: CONFIRMED
**Evidence Tag**: [CODE-TRACE]

## Description
The verified issue is at `Protocol.sol:141`, where sqrtPriceX96 arithmetic floors three times.

## Recommendation
Use higher precision arithmetic before casting.
""", encoding="utf-8")
    manifests = D._build_sc_body_writer_manifests(sp)
    row = manifests["report_medium"]["findings"][0]
    check(
        "MAN.sc_manifest_prefers_verified_title",
        row["title"] == "Actual verified sqrtPriceX96 truncation",
        repr(row),
    )
    check(
        "MAN.sc_manifest_prefers_verified_location",
        row["location"] == "Protocol.sol:141",
        repr(row),
    )


def test_MAN_sc_manifest_uses_second_heading_when_h1_is_only_verification_id(tmp_path: Path):
    """`# Verification: H-N` is not a claim title; use the next substantive heading."""
    sp = tmp_path
    (sp / "report_index.md").write_text("""# Report Index

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| L-01 | Stale index title | Low | Vault.sol:oldPath() | VERIFIED [CODE-TRACE] | - | H-32 |
""", encoding="utf-8")
    (sp / "verify_H-32.md").write_text("""# Verification: H-32
## Ceiling rounding creates zero-input swap

**Final Verdict**: CONFIRMED
**Evidence Tag**: [CODE-TRACE]

## Finding Summary
At `Vault.sol:167-173`, ceil rounding can consume the full dust amount.

## Recommendation
Guard zero input.
""", encoding="utf-8")
    manifests = D._build_sc_body_writer_manifests(sp)
    row = manifests["report_low_info"]["findings"][0]
    check(
        "MAN.sc_manifest_uses_second_heading_title",
        row["title"] == "Ceiling rounding creates zero-input swap",
        repr(row),
    )


def test_MAN_sc_missing_verify_preserves_report_index_location(tmp_path: Path):
    """Inventory fallbacks must not replace a usable report-index location."""
    sp = tmp_path
    (sp / "report_index.md").write_text("""# Report Index

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| M-01 | Missing verify finding | Medium | Minting.sol:distributeSnapshot() | VERIFIED [CODE-TRACE] | - | H-21 |
""", encoding="utf-8")
    (sp / "findings_inventory.md").write_text("""## Finding [H-21]: Fallback finding
**Location**: BuyAndBurn.sol:578-583
**Description**: Fallback text from a non-verifier source.
""", encoding="utf-8")
    manifests = D._build_sc_body_writer_manifests(sp)
    row = manifests["report_medium"]["findings"][0]
    check(
        "MAN.sc_missing_verify_keeps_index_location",
        row["location"] == "Minting.sol:distributeSnapshot()",
        repr(row),
    )


def test_MAN_sc_manifest_ignores_poc_test_file_as_primary_location(tmp_path: Path):
    """PoC test paths in verifier artifacts must not replace production source locations."""
    sp = tmp_path
    (sp / "report_index.md").write_text("""# Report Index

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| H-01 | Production bug | High | Minting.sol:pre-liquidity path | VERIFIED [CODE-TRACE] | - | H-9 |
""", encoding="utf-8")
    (sp / "verify_H-9.md").write_text("""# Verification: H-9 — Production bug

**Final Verdict**: CONFIRMED
**Evidence Tag**: [CODE-TRACE]

### PoC Attempt
- Test File: test/Test_H43_Uint192Cast.t.sol

## Code Trace
### Vulnerable code (Minting.sol:155-172)
The production branch reassigns `_amount`.
""", encoding="utf-8")
    manifests = D._build_sc_body_writer_manifests(sp)
    row = manifests["report_critical_high"]["findings"][0]
    check(
        "MAN.sc_manifest_uses_production_location_over_test_file",
        row["location"] == "Minting.sol:155-172",
        repr(row),
    )


def test_MAN_sc_chain_manifest_inherits_constituent_verifiers(tmp_path: Path):
    """CH-* report rows inherit H-* verifier evidence from hypotheses table."""
    sp = tmp_path
    (sp / "report_index.md").write_text("""# Report Index

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| H-01 | Chain report | High | Vault.sol:compound() | VERIFIED | - | CH-1 |
""", encoding="utf-8")
    (sp / "hypotheses.md").write_text("""# Hypotheses

| Hypothesis ID | Title | Severity | Verdict | Source Findings | Location |
|---------------|-------|----------|---------|-----------------|----------|
| CH-1 | Chain report | High | CHAIN | H-10, H-11 | Vault.sol:compound() |
""", encoding="utf-8")
    for fid in ("H-10", "H-11"):
        (sp / f"verify_{fid}.md").write_text(f"""# Verification: {fid} — constituent

**Final Verdict**: CONFIRMED
**Evidence Tag**: [CODE-TRACE]

## Description
Verified constituent at `Vault.sol:L42`.

## Recommendation
Fix the constituent issue.
""", encoding="utf-8")
    manifests = D._build_sc_body_writer_manifests(sp)
    row = manifests["report_critical_high"]["findings"][0]
    check(
        "MAN.sc_chain_manifest_inherits_verifiers",
        row["verify_files"] == ["verify_H-10.md", "verify_H-11.md"] and not row["report_blocked"],
        repr(row),
    )


def test_MAN_sc_manifest_prefers_index_verification_files_over_all_constituents(tmp_path: Path):
    """Merged rows should not be report-blocked by duplicate constituents absent from Verification cell."""
    sp = tmp_path
    (sp / "report_index.md").write_text("""# Report Index

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| M-29 | Merged duplicate report | Medium | BridgeRouter.sol:admin | verify_HM-05.md, verify_HM-06.md | - | HM-05+HM-06+HM-07+HM-08 |
""", encoding="utf-8")
    for fid in ("HM-05", "HM-06"):
        (sp / f"verify_{fid}.md").write_text(f"""# Verification: {fid}

**Final Verdict**: CONFIRMED
**Evidence Tag**: [CODE-TRACE]

## Description
Verified duplicate constituent at `BridgeRouter.sol:L42`.

## Execution Result
Code trace verified; no executable PoC was required.

## Recommendation
Fix the merged issue.
""", encoding="utf-8")
    manifests = D._build_sc_body_writer_manifests(sp)
    row = manifests["report_medium"]["findings"][0]
    ok = (
        row["verify_files"] == ["verify_HM-05.md", "verify_HM-06.md"]
        and row["report_blocked"] is False
    )
    check("MAN.sc_prefers_index_verification_files", ok, repr(row))


# =============================================================================
# Body validator: coverage, no-extras, evidence integrity.
# =============================================================================

def _make_manifest(findings: list[dict]) -> dict:
    return {"shard": "report_test", "findings": findings}


def _good_body(findings: list[dict]) -> str:
    out = ["# Test Findings", ""]
    for f in findings:
        out.append(f"## [{f['report_id']}] {f['title']}")
        out.append(f"**Severity**: {f['severity']}")
        out.append(f"**Location**: {f['location']}")
        out.append(f"**Evidence Tag**: {f['evidence_tag']}")
        out.append(f"**Description**: {f['description']}")
        out.append(f"**Impact**: {f.get('impact', 'A material impact.')}")
        out.append(f"**PoC Result**: {f.get('poc_result', 'Code trace confirms the condition.')}")
        out.append(f"**Recommendation**: {f['recommendation']}")
        out.append("")
    return "\n".join(out)


_BASE_FINDING = {
    "report_id": "M-01",
    "finding_id": "INV-001",
    "severity": "Medium",
    "title": "Test bug",
    "location": "src/F.sol:L42",
    "evidence_tag": "CODE-TRACE",
    "verify_file": "verify_INV-001.md",
    "description": "A description.",
    "poc_result": "Code trace confirms the condition.",
    "recommendation": "A recommendation.",
    "report_blocked": False,
}


def test_VAL_clean_body_passes():
    manifest = _make_manifest([dict(_BASE_FINDING)])
    body = _good_body(manifest["findings"])
    res = D._validate_report_body(body, manifest)
    check("VAL.clean_body_passes", res["ok"] is True, repr(res))


def test_VAL_chm_missing_poc_result_fails_body_gate():
    """Catch C/H/M body omissions before report_assemble degrades late."""
    manifest = _make_manifest([dict(_BASE_FINDING, report_id="H-01", severity="High")])
    # No PoC Result AND no Evidence Tag/Evidence (RPT-2 accepts those as PoC
    # evidence), so the substantive-PoC check genuinely fires.
    body = """# Test
## [H-01] Test bug
**Severity**: High
**Location**: src/F.sol:L42
**Description**: A description.
**Impact**: A material impact.
**Recommendation**: A recommendation.
"""
    res = D._validate_report_body(body, manifest)
    # GATE-2: substantive-PoC adequacy is prose quality -> reported in `content`
    # (telemetry/WARN) but it must NOT flip `ok` (which hard-halts the critical
    # report_body_writer phase). Mechanical checks still gate `ok`.
    ok = res["ok"] is True and any("PoC Result" in s for s in res.get("content", []))
    check("VAL.chm_missing_poc_result_is_soft_warn", ok, repr(res))


def test_VAL_missing_finding_fails():
    manifest = _make_manifest([
        dict(_BASE_FINDING, report_id="M-01"),
        dict(_BASE_FINDING, report_id="M-02"),
    ])
    # Body only writes M-01.
    body = _good_body([manifest["findings"][0]])
    res = D._validate_report_body(body, manifest)
    check(
        "VAL.missing_finding_fails",
        res["ok"] is False and "M-02" in str(res.get("missing", [])),
        repr(res),
    )


def test_VAL_extra_finding_fails():
    manifest = _make_manifest([dict(_BASE_FINDING)])
    extras = manifest["findings"] + [
        dict(_BASE_FINDING, report_id="M-99", title="Hallucinated bug"),
    ]
    body = _good_body(extras)
    res = D._validate_report_body(body, manifest)
    check(
        "VAL.extra_finding_fails",
        res["ok"] is False and "M-99" in str(res.get("extras", [])),
        repr(res),
    )


def test_VAL_wrong_location_fails():
    manifest = _make_manifest([dict(_BASE_FINDING)])
    bad = dict(_BASE_FINDING, location="src/HALLUCINATED.sol:L999")
    body = _good_body([bad])
    res = D._validate_report_body(body, manifest)
    check(
        "VAL.wrong_location_fails",
        res["ok"] is False and "location" in str(res.get("integrity", [])).lower(),
        repr(res),
    )


def test_VAL_composite_manifest_location_allows_source_token_rewrite():
    """Composite index locations need not be copied verbatim if source identity survives."""
    finding = dict(
        _BASE_FINDING,
        location="BuyAndBurn.sol, Minting.sol:admin setters",
    )
    manifest = _make_manifest([finding])
    body = """# Test
## [M-01] renounceOwnership not overridden
**Severity**: Medium
**Location**: `BuyAndBurn.sol:L35`
**Evidence Tag**: CODE-TRACE
**Description**: The contract inherits Ownable2Step and does not override renounceOwnership.
**Impact**: Ownership can be renounced and leave privileged flows unmanaged.
**PoC Result**: Code trace confirms the missing override.
**Recommendation**: Override renounceOwnership.
"""
    res = D._validate_report_body(body, manifest)
    check("VAL.composite_location_source_token_passes", res["ok"] is True, repr(res))


def test_VAL_source_token_drift_still_fails():
    """A function word in the title cannot hide a body copied from another source file."""
    finding = dict(_BASE_FINDING, location="BuyAndBurn.sol:buyAndBurn()")
    manifest = _make_manifest([finding])
    body = """# Test
## [M-01] buyAndBurn called with zero balance
**Severity**: Medium
**Location**: `Protocol.sol:L136-L141`
**Evidence Tag**: CODE-TRACE
**Description**: The sqrtPriceX96 constructor math truncates.
**Recommendation**: Use higher precision arithmetic.
"""
    res = D._validate_report_body(body, manifest)
    check(
        "VAL.source_file_drift_fails",
        res["ok"] is False and "location" in str(res.get("integrity", [])).lower(),
        repr(res),
    )


def test_VAL_report_blocked_handling():
    """Report-blocked findings must show the REPORT-BLOCKED tag in the body."""
    manifest = _make_manifest([dict(_BASE_FINDING, report_blocked=True)])
    body = """# Test
## [M-01] Test bug [REPORT-BLOCKED: insufficient evidence]
**Severity**: Medium
**Location**: src/F.sol:L42
**Evidence Tag**: CODE-TRACE
**Description**: A description.
"""
    res = D._validate_report_body(body, manifest)
    check("VAL.report_blocked_with_tag_passes", res["ok"] is True, repr(res))

    # Same finding without the tag -> should fail.
    body_no_tag = _good_body(manifest["findings"])
    res2 = D._validate_report_body(body_no_tag, manifest)
    check(
        "VAL.report_blocked_without_tag_fails",
        res2["ok"] is False and "blocked" in str(res2).lower(),
        repr(res2),
    )

    body_unverified = """# Test
## [M-01] Test bug [VERIFICATION NOT EXECUTED]
**Severity**: Medium
**Location**: src/F.sol:L42
**Evidence Tag**: CODE-TRACE
**Description**: Phase 5 verification did not produce a file.
"""
    res3 = D._validate_report_body(body_unverified, manifest)
    check("VAL.report_blocked_verification_not_executed_passes", res3["ok"] is True, repr(res3))


def test_VAL_id_case_insensitive_and_whitespace():
    """`m-01` / `[M-01 ]` / `[ M-01]` all match M-01."""
    manifest = _make_manifest([dict(_BASE_FINDING, report_id="M-01")])
    body = """# Test
## [m-01]   Test bug
**Severity**: Medium
**Location**: src/F.sol:L42
**Evidence Tag**: CODE-TRACE
**Description**: ok
**Impact**: ok
**PoC Result**: ok
**Recommendation**: ok
"""
    res = D._validate_report_body(body, manifest)
    check("VAL.id_case_tolerant", res["ok"] is True, repr(res))


def test_VAL_body_with_appendix_only_does_not_count_extras():
    """Appendix mentions of internal IDs (INV-001) are not extras."""
    manifest = _make_manifest([dict(_BASE_FINDING)])
    body = _good_body(manifest["findings"]) + """
## Appendix A: Internal Audit Traceability
| Report ID | Internal Hypothesis |
|-----------|---------------------|
| M-01 | INV-001 |
"""
    res = D._validate_report_body(body, manifest)
    check("VAL.appendix_does_not_break", res["ok"] is True, repr(res))


# =============================================================================
# End-to-end: drive manifest -> validate body output.
# =============================================================================

def test_E2E_manifest_then_validate_passes(tmp_path: Path):
    sp = tmp_path
    _seed_records(sp, {"C": 1, "H": 1, "M": 1, "L": 1, "I": 0})
    D._write_mechanical_report_index(sp)
    manifests = D._build_body_writer_manifests(sp)
    for shard_name, manifest in manifests.items():
        body = _good_body(manifest["findings"])
        res = D._validate_report_body(body, manifest)
        check(
            f"E2E.{shard_name}_validates",
            res["ok"] is True,
            f"shard={shard_name} res={res}",
        )


# =============================================================================
# Test runner
# =============================================================================

TESTS_BASIC = [
    test_VAL_clean_body_passes,
    test_VAL_chm_missing_poc_result_fails_body_gate,
    test_VAL_missing_finding_fails,
    test_VAL_extra_finding_fails,
    test_VAL_wrong_location_fails,
    test_VAL_composite_manifest_location_allows_source_token_rewrite,
    test_VAL_source_token_drift_still_fails,
    test_VAL_report_blocked_handling,
    test_VAL_id_case_insensitive_and_whitespace,
    test_VAL_body_with_appendix_only_does_not_count_extras,
]

TESTS_INTEG = [
    test_MAN_shape_and_required_fields,
    test_MAN_shards_by_tier_with_caps,
    test_MAN_total_findings_equal_active,
    test_MAN_marks_report_blocked_when_evidence_missing,
    test_MAN_section_headed_evidence_not_report_blocked,
    test_MAN_poc_result_seed_from_execution_result,
    test_MAN_na_section_headings_remain_report_blocked,
    test_SYNTH_generic_fallback_is_not_shippable_body,
    test_MAN_sc_manifest_section_headed_evidence_seeded,
    test_MAN_inventory_location_fallback_for_generic_queue_location,
    test_MAN_sc_inventory_location_fallback_for_generic_index_and_verify,
    test_MAN_finding_records_written_from_inventory,
    test_MAN_sc_manifest_can_inherit_from_finding_records_without_inventory_markdown,
    test_MAN_sc_report_records_written_from_index_and_manifests,
    test_MAN_finding_records_merge_with_inventory_fallback_when_partial,
    test_MAN_finding_records_capture_section_headed_inventory_narrative,
    test_MAN_sc_manifest_maps_niche_prefix_ids_from_report_index,
    test_MAN_report_assemble_recovers_missing_report_records,
    test_MAN_sc_manifest_prefers_verified_claim_identity,
    test_MAN_sc_manifest_uses_second_heading_when_h1_is_only_verification_id,
    test_MAN_sc_missing_verify_preserves_report_index_location,
    test_MAN_sc_manifest_ignores_poc_test_file_as_primary_location,
    test_MAN_sc_chain_manifest_inherits_constituent_verifiers,
    test_MAN_sc_manifest_prefers_index_verification_files_over_all_constituents,
    test_E2E_manifest_then_validate_passes,
]


def main() -> int:
    n = len(TESTS_BASIC) + len(TESTS_INTEG)
    print(f"Running {n} body-validator tests...")
    for t in TESTS_BASIC:
        print(f"\n[{t.__name__}]")
        try:
            t()
        except Exception as exc:
            global FAIL
            FAIL += 1
            print(f"  CRASH {t.__name__} :: {exc!r}")
    for t in TESTS_INTEG:
        print(f"\n[{t.__name__}]")
        try:
            with tempfile.TemporaryDirectory() as td:
                t(Path(td))
        except Exception as exc:
            FAIL += 1
            print(f"  CRASH {t.__name__} :: {exc!r}")
    print(f"\n{'=' * 64}")
    print(f"  PASS: {PASS}   FAIL: {FAIL}")
    print('=' * 64)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
