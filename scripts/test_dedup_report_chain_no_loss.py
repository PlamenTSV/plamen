"""End-to-end ZERO-DATA-LOSS chain test for the dedup -> report pipeline.

Models an INV-013/014 family from a prior L1 audit:

  * INV-013: consensus config-hash mismatch, INBOUND only,
    Source IDs {CI-1, NS-2}, peer_network_service.rs:990-1000, [CODE-TRACE],
    Medium.
  * INV-014: SAME config-hash mismatch PLUS a distinct OUTBOUND path,
    Source IDs {CI-1, NS-2, NS-7}, peer_network_service.rs:990-1048,
    [POC-PASS], High. INV-014 is the source-ID + location SUPERSET, so it MUST
    be the survivor.

A deterministic dedup_decisions.md (simulating the LLM/mechanical merge after
the survivor-superset gate) merges INV-013 INTO INV-014 with the outbound
content coupled. The test then drives the real driver chain:

  1. dedup post-swap propagation (_propagate_dedup_absorbed_to_finding_mapping)
  2. mechanical report_index + report_coverage build
  3. mechanical AUDIT_REPORT assembly

and asserts NO distinct attack path / severity / evidence is lost, INV-013 is
accounted as MERGED (not AUTO_EXCLUDED / not silently dropped), and the
pipeline does not halt.

Negative case: a large-aggregate KEEP-SEPARATE pair (15-source-ID INV-127 vs
INV-118) yields TWO distinct findings — neither absorbed.
"""

from pathlib import Path
import shutil

import plamen_driver as d
import plamen_mechanical as m


# --- survivor finding body (INV-014) carrying BOTH paths after coupling -----
_DEDUPED_INVENTORY = """# Findings Inventory

### Finding [INV-014]: Consensus config-hash mismatch logged but not enforced
**Severity**: High
**Location**: peer_network_service.rs:990-1048
**Source IDs**: CI-1, NS-2, NS-7
**Preferred Tag**: POC-PASS
**Description**: The inbound handshake config-hash check at
peer_network_service.rs:990-1000 logs a mismatch but does not reject the peer.
Additionally, the outbound path at peer_network_service.rs:1041-1048 (absorbed
from INV-013) re-dials mismatched peers; this route must be fixed together with
the inbound check.
**Impact**: A peer with a mismatched consensus config is admitted (inbound) and
re-dialed (outbound), enabling cross-config gossip pollution.

### Finding [INV-127]: Outbound response-size OOM on client dial loop
**Severity**: High
**Location**: gossip_client.rs:150-170
**Source IDs**: NS-1, NS-2, NS-3, NS-4, NS-5, NS-6, NS-7, NS-8, NS-9, CI-1, CI-2, DS-1, DS-2, DS-3, DS-4
**Preferred Tag**: CODE-TRACE
**Description**: Unbounded outbound response buffering.
**Impact**: OOM under crafted oversized responses.

### Finding [INV-118]: Unbounded peers Vec on discovery ingest
**Severity**: Medium
**Location**: server.rs:1071-1108
**Source IDs**: NS-3
**Preferred Tag**: CODE-TRACE
**Description**: Discovery ingest appends to peers Vec without a cap.
**Impact**: Memory exhaustion via flooded discovery.
"""

_DEDUP_DECISIONS = """# Semantic Dedup Decisions

**Status**: COMPLETE

## Decisions

| Finding ID | Status | Coupled-content | Notes |
|------------|--------|-----------------|-------|
| INV-014 | PASS |  | survivor (superset) |
| INV-013 | MERGED into INV-014 | outbound peer_network_service.rs:1041-1048 re-dial path coupled into INV-014; INV-014 keeps [POC-PASS], High | survivor superset confirmed |
| INV-127 | KEEP SEPARATE |  | aggregate (15 source IDs); DIRECTION_FLIP vs INV-118 |
| INV-118 | KEEP SEPARATE |  | distinct unbounded-peers defect |
"""

_VERIFICATION_QUEUE = """# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag | Priority |
|------------|----------|-------|----------|---------------|----------|
| INV-014 | High | Consensus config-hash mismatch not enforced | peer_network_service.rs:990-1048 | POC-PASS | 1 |
| INV-127 | High | Outbound response-size OOM | gossip_client.rs:150-170 | CODE-TRACE | 2 |
| INV-118 | Medium | Unbounded peers Vec | server.rs:1071-1108 | CODE-TRACE | 3 |
"""

_VERIFY_INV014 = """# Verification: INV-014

**Verdict**: CONFIRMED
**Severity**: High
**Preferred Tag**: POC-PASS

### Execution Result
- Compiled: YES
- Result: PASS
- Evidence Tag: [POC-PASS]

The inbound config-hash check AND the outbound re-dial path at
peer_network_service.rs:1041-1048 are both exploitable.
"""

_VERIFY_INV127 = """# Verification: INV-127
**Verdict**: CONFIRMED
**Severity**: High
**Preferred Tag**: CODE-TRACE
### Execution Result
- Evidence Tag: [CODE-TRACE]
"""

_VERIFY_INV118 = """# Verification: INV-118
**Verdict**: CONFIRMED
**Severity**: Medium
**Preferred Tag**: CODE-TRACE
### Execution Result
- Evidence Tag: [CODE-TRACE]
"""


def _setup(tmp_path: Path) -> Path:
    sp = tmp_path / "scratchpad"
    sp.mkdir()
    absorbed = """
### Finding [INV-013]: Consensus config-hash mismatch inbound variant
**Severity**: Medium
**Location**: peer_network_service.rs:990-1000
**Source IDs**: CI-1, NS-2
**Root Cause**: The config hash is logged but not enforced.
**Description**: The inbound path accepts the mismatched peer.
**Impact**: A mismatched peer can enter the gossip set.
**Recommendation**: Reject mismatched peers on every path.
**Evidence Scope**: The inbound handshake path.
[CODE-TRACE]
"""
    (sp / "findings_inventory.md").write_text(
        _DEDUPED_INVENTORY + absorbed, encoding="utf-8"
    )
    (sp / "dedup_decisions.md").write_text(_DEDUP_DECISIONS, encoding="utf-8")
    assert m.apply_llm_dedup_decisions(sp, "sc_semantic_dedup") == 1
    shutil.copy2(sp / "findings_inventory_deduped.md", sp / "findings_inventory.md")
    (sp / "verification_queue.md").write_text(_VERIFICATION_QUEUE, encoding="utf-8")
    (sp / "verify_INV-014.md").write_text(_VERIFY_INV014, encoding="utf-8")
    (sp / "verify_INV-127.md").write_text(_VERIFY_INV127, encoding="utf-8")
    (sp / "verify_INV-118.md").write_text(_VERIFY_INV118, encoding="utf-8")
    return sp


def test_dedup_report_chain_no_data_loss(tmp_path: Path):
    sp = _setup(tmp_path)
    project_root = tmp_path / "proj"
    project_root.mkdir()

    # --- (1) driver dedup post-swap propagation ---
    n_prop = d._propagate_dedup_absorbed_to_finding_mapping(sp)
    assert n_prop == 1, "INV-013 should propagate as absorbed into INV-014"

    # (e) absorbed map sidecar records INV-013 -> INV-014 with coupled content
    sidecar = (sp / "dedup_absorbed_map.md").read_text(encoding="utf-8")
    assert "INV-013" in sidecar and "INV-014" in sidecar
    assert "field-complete-preserved" in sidecar

    # finding_mapping did not exist at dedup time (normal ordering); now build
    # the mechanical chain baseline (which is what the real pipeline does next).
    # The baseline maps surviving inventory findings; then re-run propagation so
    # INV-013 lands as a constituent of INV-014's hypothesis.
    written = m._write_chain_passthrough_outputs(sp, "test chain baseline")
    assert "finding_mapping.md" in written
    d._propagate_dedup_absorbed_to_finding_mapping(sp)
    fm = (sp / "finding_mapping.md").read_text(encoding="utf-8")
    # (e) finding_mapping lists INV-013 as a constituent of the survivor hyp.
    inv013_rows = [ln for ln in fm.splitlines() if ln.strip().startswith("| INV-013")]
    assert inv013_rows, "INV-013 must appear in finding_mapping"
    # survivor INV-014 hypothesis id
    inv014_rows = [ln for ln in fm.splitlines() if ln.strip().startswith("| INV-014")]
    assert inv014_rows
    surv_hyp = inv014_rows[0].split("|")[2].strip()
    assert surv_hyp and surv_hyp in inv013_rows[0]
    assert "INV-014" in inv013_rows[0]  # survivor referenced

    # --- (2) mechanical report_index + report_coverage ---
    n_idx = m._write_mechanical_report_index(sp)
    assert n_idx > 0
    idx = (sp / "report_index.md").read_text(encoding="utf-8")
    cov = (sp / "report_coverage.md").read_text(encoding="utf-8")

    # (a) survivor finding is High (higher severity inherited / preserved)
    surv_idx_rows = [ln for ln in idx.splitlines() if "INV-014" in ln and "|" in ln]
    assert surv_idx_rows, "survivor INV-014 must be in report index"
    assert any("High" in ln for ln in surv_idx_rows), "survivor must be High"

    # (d) INV-013 accounted as MERGED in report_coverage (NOT AUTO_EXCLUDED /
    #     not silently dropped)
    cov_013 = [ln for ln in cov.splitlines() if "INV-013" in ln]
    assert cov_013, "INV-013 must appear in report_coverage ledger"
    assert any("MERGED" in ln for ln in cov_013), (
        "INV-013 must be MERGED, not dropped: " + " | ".join(cov_013)
    )
    assert not any("AUTO_EXCLUDED" in ln for ln in cov_013)

    # --- (3) report assembly: write minimal tier files (stand-in for the LLM
    #     tier writer, which is the only non-Python step) and assemble. ---
    # The tier writer reads the deduped inventory + finding_mapping; we model
    # its faithful output so we can assert (b)/(c)/(f) on the assembled report.
    (sp / "report_critical_high.md").write_text(
        "## Critical Findings\n\n"
        "## High Findings\n\n"
        "### [H-01] Consensus config-hash mismatch not enforced [VERIFIED]\n\n"
        "**Severity**: High\n"
        "**Location**: peer_network_service.rs:990-1048\n\n"
        "**Description**: The inbound config-hash check at "
        "peer_network_service.rs:990-1000 is logged but not enforced. "
        "Additionally, the distinct outbound re-dial path at "
        "peer_network_service.rs:1041-1048 admits mismatched peers.\n\n"
        "**PoC Result**: [POC-PASS] — both paths exploitable.\n\n"
        "**Recommendation**: Enforce config-hash on inbound AND outbound.\n\n"
        "### [H-02] Outbound response-size OOM [VERIFIED]\n\n"
        "**Severity**: High\n"
        "**Location**: gossip_client.rs:150-170\n\n"
        "**Description**: Unbounded outbound response buffering causes OOM.\n\n"
        "**Recommendation**: Bound the response buffer.\n",
        encoding="utf-8",
    )
    (sp / "report_medium.md").write_text(
        "## Medium Findings\n\n"
        "### [M-01] Unbounded peers Vec on discovery ingest [VERIFIED]\n\n"
        "**Severity**: Medium\n"
        "**Location**: server.rs:1071-1108\n\n"
        "**Description**: Discovery ingest appends to peers Vec without a cap, "
        "enabling memory exhaustion. This is a distinct defect from the OOM "
        "finding.\n\n"
        "**Recommendation**: Cap the peers Vec.\n",
        encoding="utf-8",
    )
    (sp / "report_low_info.md").write_text(
        "## Low Findings\n\n## Informational Findings\n", encoding="utf-8"
    )

    ok = m._assemble_report_python(sp, str(project_root))
    assert ok is True, "report assembly must succeed (no halt)"
    report_path = project_root / "AUDIT_REPORT.md"
    assert report_path.exists()
    report = report_path.read_text(encoding="utf-8")

    # (f) AUDIT_REPORT non-stub (well above a minimal byte threshold)
    assert len(report) > 600, f"report too small ({len(report)} bytes) — likely a stub"

    # (b) [POC-PASS] preserved in the survivor's section
    assert "POC-PASS" in report

    # (c) the survivor report text mentions BOTH the inbound config-hash check
    #     AND the distinct outbound peer_network_service.rs:1041-1048 path.
    assert "peer_network_service.rs:990-1000" in report  # inbound
    assert "peer_network_service.rs:1041-1048" in report  # outbound (no drop)

    # Negative case: the KEEP-SEPARATE aggregate pair stays as TWO distinct
    # findings — neither absorbed. INV-127 and INV-118 are both present and
    # NOT in the absorbed map.
    assert "INV-127" not in sidecar  # not absorbed
    assert "INV-118" not in sidecar  # not absorbed
    # Both surface as their own report rows (H-02 and M-01).
    assert "gossip_client.rs:150-170" in report  # INV-127 distinct site
    assert "server.rs:1071-1108" in report        # INV-118 distinct site


def test_keep_separate_aggregate_not_absorbed(tmp_path: Path):
    """INV-127 (15 source IDs) and INV-118 must NOT merge — distinct TPs."""
    sp = _setup(tmp_path)
    mapping = d._dedup_absorbed_survivor_mapping(sp)
    # Only INV-013 absorbed; the aggregate KEEP-SEPARATE pair is untouched.
    assert set(mapping.keys()) == {"INV-013"}
    assert "INV-127" not in mapping
    assert "INV-118" not in mapping


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
