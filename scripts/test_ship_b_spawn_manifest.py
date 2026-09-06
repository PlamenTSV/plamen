"""Ship B — spawn manifest section-scoping (instantiate unblock).

The breadth-manifest parsers must read ONLY the `## Breadth Agents` section, so
a later table whose header also matches the template+required heuristic (e.g.
`## Required Template Coverage`) cannot bleed into the roster. Legacy manifests
without the heading still parse via full-document fallback.
"""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_parsers as P  # noqa: E402

# Bleed-shaped: `## Breadth Agents` (3 agents) followed by `## Required Template
# Coverage` whose `| Template (Required=YES) | Agent | Status |` header matches
# the old "template+required" heuristic and bled in (count=16/outputs=None).
BLEED = """# Spawn Manifest

## Breadth Agents

| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |
|----------|----------|-----------|----------|------------|-----------------|--------|
| AGENT | A | YES | B1 | core_state | analysis_core_state.md | QUEUED |
| AGENT | B | YES | B2 | access_control | analysis_access_control.md | QUEUED |
| AGENT | C | YES | B3 | token_flow | analysis_token_flow.md | QUEUED |

## Required Template Coverage

| Template (Required=YES) | Agent | Status |
|------------------------|-------|--------|
| FLASH_LOAN_INTERACTION | B3 | COVERED |
| TOKEN_FLOW_TRACING | B4 | COVERED |
| SEMI_TRUSTED_ROLES | B2 | COVERED |
"""

# Legacy manifest: roster table directly under `# Spawn Manifest`, no
# `## Breadth Agents` heading. Must still parse (full-doc fallback).
LEGACY_NO_HEADING = """# Spawn Manifest

| Template | Required? | Agent ID | Focus Area | Expected Output | Status |
|----------|-----------|----------|------------|-----------------|--------|
| Core | YES | B1 | core_state | analysis_core_state.md | PENDING |
| Ext  | YES | B2 | external | analysis_external.md | PENDING |
"""


def _seed(tmp_path: Path, md: str) -> Path:
    sp = tmp_path / ".scratchpad"
    sp.mkdir(exist_ok=True)
    (sp / "spawn_manifest.md").write_text(md, encoding="utf-8")
    return sp


def test_bleed_manifest_count_is_three_not_six(tmp_path):
    sp = _seed(tmp_path, BLEED)
    assert P.parse_breadth_manifest_count(sp) == 3


def test_bleed_manifest_outputs_are_only_breadth(tmp_path):
    sp = _seed(tmp_path, BLEED)
    outs = P.parse_breadth_manifest_outputs(sp)
    assert outs == [
        "analysis_core_state.md", "analysis_access_control.md",
        "analysis_token_flow.md",
    ]
    assert len(outs) == P.parse_breadth_manifest_count(sp)  # no asymmetry


def test_legacy_no_heading_still_parses(tmp_path):
    sp = _seed(tmp_path, LEGACY_NO_HEADING)
    assert P.parse_breadth_manifest_count(sp) == 2
    assert P.parse_breadth_manifest_outputs(sp) == [
        "analysis_core_state.md", "analysis_external.md",
    ]


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


def test_hermetic_eight_agent_manifest_regression(tmp_path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "spawn_manifest.md").write_text(
        _eight_agent_manifest(), encoding="utf-8"
    )
    assert P.parse_breadth_manifest_count(sp) == 8
    assert len(P.parse_breadth_manifest_outputs(sp)) == 8
