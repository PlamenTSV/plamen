"""Ship A — machine-contract foundation tests.

Covers: section-scoped Markdown AST (plamen_markdown), the contract base I/O +
SpawnManifest/RescanManifest models (plamen_contracts), the fallback ladder
(JSON valid->authoritative / invalid->ContractError / absent->from_markdown),
and the grammar-registry consolidation of DEPTH_EVIDENCE_TAG_RE.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_markdown as M  # noqa: E402
import plamen_contracts as C  # noqa: E402
import plamen_types as T  # noqa: E402

# A manifest that reproduces an observed bleed: a `## Breadth Agents` table (8
# agents) followed by `## Required Template Coverage` whose header ALSO matches
# the old "template+required" heuristic.
MANIFEST_LIKE = """# Spawn Manifest

## Breadth Agents

| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |
|----------|----------|-----------|----------|------------|-----------------|--------|
| AGENT | ECONOMIC + TEMPORAL | YES | B1 | core_state | analysis_core_state.md | QUEUED |
| AGENT | SEMI_TRUSTED | YES | B2 | access_control | analysis_access_control.md | QUEUED |
| AGENT | FLASH_LOAN | YES | B3 | flash_loan | analysis_flash_loan.md | QUEUED |

## Required Template Coverage

| Template (Required=YES) | Agent | Status |
|------------------------|-------|--------|
| FLASH_LOAN_INTERACTION | B3 | COVERED |
| TOKEN_FLOW_TRACING | B4 | COVERED |
"""


# ───────────────────────── AST utility ──────────────────────────

def test_section_scope_no_bleed():
    rows = M.first_section_table(MANIFEST_LIKE, r"\bbreadth\s+agents?\b",
                                 required_columns=["agent_id", "expected_output"])
    assert len(rows) == 3, [r.get("agent_id") for r in rows]
    assert [r["agent_id"] for r in rows] == ["B1", "B2", "B3"]
    # the coverage table must NOT contribute rows
    assert all(r["expected_output"].startswith("analysis_") for r in rows)


def test_section_ends_at_next_equal_level_heading():
    toks = M.section_tokens(MANIFEST_LIKE, r"\bbreadth\s+agents?\b")
    # the breadth section tokens must not contain the coverage table's cells
    txt = " ".join(t.content for t in toks if t.type == "inline")
    assert "Required Template Coverage" not in txt
    assert "FLASH_LOAN_INTERACTION" not in txt  # that's a coverage-table cell


def test_normalize_header_matches_legacy():
    assert M.normalize_header("Expected Output") == "expected_output"
    assert M.normalize_header("Required?") == "required"
    assert M.normalize_header("Template (Required=YES)") == "template_required_yes"


def test_missing_section_returns_empty():
    assert M.first_section_table("# nothing here", r"breadth") == []


def _eight_agent_manifest() -> str:
    lines = [
        "# Spawn Manifest",
        "",
        "## Breadth Agents",
        "",
        "| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |",
        "|----------|----------|-----------|----------|------------|-----------------|--------|",
    ]
    lines.extend(
        f"| AGENT | GENERIC_{i:02d} | YES | B{i} | role_{i:02d} | analysis_role_{i:02d}.md | QUEUED |"
        for i in range(1, 9)
    )
    return "\n".join(lines) + "\n"


def test_hermetic_eight_agent_manifest_regression():
    """An eight-row manifest stays exact without machine-local audit data."""
    md = _eight_agent_manifest()
    sm = C.SpawnManifest.from_markdown(md)
    assert sm.count() == 8
    assert len(sm.outputs()) == 8
    assert len(set(sm.outputs())) == 8  # all unique


# ───────────────────────── SpawnManifest contract ──────────────────────────

def test_spawn_from_markdown_no_bleed():
    sm = C.SpawnManifest.from_markdown(MANIFEST_LIKE)
    assert sm.count() == 3
    assert sm.outputs() == [
        "analysis_core_state.md", "analysis_access_control.md",
        "analysis_flash_loan.md",
    ]


def test_spawn_round_trip_render_reparse():
    sm = C.SpawnManifest.from_markdown(MANIFEST_LIKE)
    rendered = sm.render_markdown()
    sm2 = C.SpawnManifest.from_markdown(rendered)
    assert sm2.outputs() == sm.outputs()
    assert sm2.count() == sm.count()


def test_spawn_invalid_output_rejected():
    import pytest
    with pytest.raises(Exception):
        C.SpawnManifest(agents=[
            C.BreadthAgentRow(agent_id="B1", focus_area="x", output="notanalysis.md"),
        ])


def test_spawn_duplicate_output_rejected():
    import pytest
    with pytest.raises(Exception):
        C.SpawnManifest(agents=[
            C.BreadthAgentRow(agent_id="B1", focus_area="x", output="analysis_x.md"),
            C.BreadthAgentRow(agent_id="B2", focus_area="x", output="analysis_x.md"),
        ])


# ───────────────────────── fallback ladder (load_contract) ─────────────────

def test_load_contract_json_authoritative(tmp_path):
    sm = C.SpawnManifest.from_markdown(MANIFEST_LIKE)
    C.write_contract_sidecar(tmp_path, sm)
    loaded = C.load_contract(tmp_path, C.SpawnManifest)
    assert loaded is not None and loaded.outputs() == sm.outputs()


def test_load_contract_absent_falls_back_to_markdown(tmp_path):
    (tmp_path / "spawn_manifest.md").write_text(MANIFEST_LIKE, encoding="utf-8")
    loaded = C.load_contract(tmp_path, C.SpawnManifest)
    assert loaded is not None and loaded.count() == 3


def test_load_contract_invalid_json_hard_fails(tmp_path):
    import pytest
    (tmp_path / "spawn_manifest.json").write_text(
        '{"schema_version": "plamen.spawn_manifest.v1", "agents": '
        '[{"agent_id": "B1", "focus_area": "x", "output": "BAD.md"}]}',
        encoding="utf-8",
    )
    # invalid output -> ContractError (NOT a silent fallback to markdown)
    with pytest.raises(C.ContractError):
        C.load_contract(tmp_path, C.SpawnManifest)


def test_load_contract_wrong_schema_version_hard_fails(tmp_path):
    import pytest
    (tmp_path / "spawn_manifest.json").write_text(
        '{"schema_version": "plamen.spawn_manifest.v0", "agents": []}',
        encoding="utf-8",
    )
    with pytest.raises(C.ContractError):
        C.load_contract(tmp_path, C.SpawnManifest)


def test_sidecar_idempotent_write(tmp_path):
    sm = C.SpawnManifest.from_markdown(MANIFEST_LIKE)
    p1 = C.write_contract_sidecar(tmp_path, sm)
    mtime1 = p1.stat().st_mtime_ns
    import time
    time.sleep(0.01)
    C.write_contract_sidecar(tmp_path, sm)
    assert p1.stat().st_mtime_ns == mtime1  # no needless rewrite


# ───────────────────────── RescanManifest contract ─────────────────────────

def test_rescan_accepts_hyphen_and_dot_filenames():
    md = ("# Rescan Manifest\n- analysis_rescan_1.md\n"
          "- analysis_percontract_core-vault.md\n"
          "- analysis_percontract_v1.2.md\n")
    rm = C.RescanManifest.from_markdown(md)
    assert "analysis_percontract_core-vault.md" in rm.outputs_declared
    assert "analysis_percontract_v1.2.md" in rm.outputs_declared


def test_rescan_glob_form_not_counted():
    import pytest
    md = "# Rescan Manifest\n- analysis_rescan_*.md\n"
    with pytest.raises(C.ContractError):
        C.RescanManifest.from_markdown(md)


# ───────────────────────── grammar registry consolidation ──────────────────

def test_depth_evidence_tag_registry_is_superset():
    re_ = T.DEPTH_EVIDENCE_TAG_RE
    for tag in ("[BOUNDARY:x]", "[TRACE path]", "[MEDUSA-PASS]",
                "[NON-DET:x]", "[ASSYMMETRIC]".replace("ASSYMMETRIC", "ASYMMETRIC"),
                "[CROSS-DOMAIN-DEP: external]", "[DST-foo]"):
        assert re_.search(tag), f"canonical regex missed {tag!r}"


def test_parsers_and_driver_share_canonical_tag_regex():
    import plamen_parsers as P
    import plamen_driver as D
    assert P._DEPTH_EVIDENCE_TAG_RE is T.DEPTH_EVIDENCE_TAG_RE
    assert D._DEPTH_EVIDENCE_TAG_RE is T.DEPTH_EVIDENCE_TAG_RE
