"""Worker-visible depth methodology stays inside the restricted lane.

These assets are read by already-launched row workers.  They must not direct a
worker to discover legacy home paths, invoke tools outside the filesystem-only
profile, or create an output that is absent from the driver's exact allowlist.
"""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent
AGENTS = ROOT / "agents"
DEPTH_ROLES = tuple(sorted(AGENTS.glob("depth-*.md")))
INTEGRATION_HAZARD = (
    AGENTS / "skills" / "injectable" / "integration-hazard-research" / "SKILL.md"
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_all_depth_roles_use_only_driver_bound_methodology_paths() -> None:
    assert {path.name for path in DEPTH_ROLES} == {
        "depth-consensus-invariant.md",
        "depth-edge-case.md",
        "depth-external.md",
        "depth-network-surface.md",
        "depth-state-trace.md",
        "depth-token-flow.md",
    }
    for path in DEPTH_ROLES:
        text = _text(path)
        assert "~/.claude" not in text, path
        assert "content-bound" in text, path
        assert "output allowlist" in text, path


def test_depth_role_frontmatter_does_not_advertise_denied_tools() -> None:
    for path in DEPTH_ROLES:
        text = _text(path)
        match = re.search(r"^tools:\s*\[([^\]]*)\]", text, re.MULTILINE)
        assert match is not None, path
        tools = match.group(1)
        for denied in (
            "Bash",
            "PowerShell",
            "Task",
            "Agent",
            "WebSearch",
            "WebFetch",
            "mcp__",
        ):
            assert denied not in tools, (path, denied)


def test_depth_roles_do_not_direct_worker_to_spawn_or_write_sidecars() -> None:
    for path in DEPTH_ROLES:
        text = _text(path)
        assert "Task(" not in text, path
    network = _text(AGENTS / "depth-network-surface.md")
    assert "network_surface.md" not in network
    assert "Embed this enumeration in the assigned findings file" in network


def test_l1_roles_use_real_bound_evidence_or_typed_debt() -> None:
    consensus = _text(AGENTS / "depth-consensus-invariant.md")
    network = _text(AGENTS / "depth-network-surface.md")
    combined = consensus + network

    assert "opengrep_hits_ranked.md" not in combined
    assert "opengrep_findings.md projection" in consensus
    assert "opengrep_findings.md projection" in network

    assert "driver-bound upstream-diff projection" not in consensus
    assert "There is no\n   assumed `upstream-diff` artifact" in consensus
    assert "NEEDS_UPSTREAM_DIFFERENTIAL:" in consensus
    assert "differential-dependent verdict CONTESTED" in consensus


def test_l1_severity_is_embedded_or_driver_bound_not_directly_opened() -> None:
    consensus = _text(AGENTS / "depth-consensus-invariant.md")
    assert "docs/l1-mode/severity-matrix.md" not in consensus
    assert "Use a content-bound L1 severity methodology" in consensus
    assert "Do not discover or open a severity document" in consensus
    for impact in ("Critical impact", "High impact", "Medium impact"):
        assert impact in consensus


def test_state_trace_named_inputs_exist_in_central_depth_selector() -> None:
    state_trace = _text(AGENTS / "depth-state-trace.md")
    selector = _text(ROOT / "scripts" / "phase_io_contracts.py")
    for name in ("findings_inventory.md", "constraint_variables.md"):
        assert f"driver-bound `{name}`" in state_trace
        assert f'"{name}"' in selector
    assert "authenticated projection" in state_trace


def test_integration_hazard_is_projection_only_and_single_output() -> None:
    text = _text(INTEGRATION_HAZARD)
    assert "scratchpad:external_dependency_research.md" in text
    assert "model-visible PhaseIO projection" in text
    assert "NEEDS_DEPENDENCY_RESEARCH: <dependency>:<file:line>:" in text
    assert "## Integration Hazard Catalog" in text
    assert "one driver-assigned findings file" in text
    assert "integration_hazard_catalog.md" not in text
    for forbidden in (
        "WebSearch",
        "WebFetch",
        "mcp__",
        "tavily_search",
        "Task(",
        "~/.claude",
    ):
        assert forbidden not in text, forbidden
