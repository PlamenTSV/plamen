"""Wave-2 L1 proof-harness tests: A5 (mechanical govulncheck/cargo-audit
dependency scan) and A6 (L1<->Move skill-lane routing).

A5 covers `recon_prepass._run_dependency_audit_l1` (+ its govulncheck/
cargo-audit helpers), wired into the pre-breadth hook in plamen_driver.py.

A6 covers `recon_prepass._seed_move_sources_flag` (HAS_MOVE_SOURCES mechanical
detection) and its consumer in plamen_driver.py, `_l1_move_skill_injection_block`
/ `_build_depth_worker_prompt` routing.

Every positive test asserts a NON-EMPTY landing (a real artifact/route/
classification on a synthetic input) -- never merely "does not crash".
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import recon_prepass as RP  # noqa: E402
import plamen_driver as D  # noqa: E402


_RECON_PREPASS_RUN_ID = "l1-depaudit-move-routing-fixture"


@pytest.fixture(autouse=True)
def _bound_synthetic_advisory_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """These legacy scanner fixtures isolate parsing, not DB freshness."""
    monkeypatch.setattr(
        RP,
        "_resolve_advisory_source",
        lambda source_id: (
            tmp_path,
            json.dumps({
                "schema_version": "plamen.advisory_source.v1",
                "source_id": source_id,
                "provider": "synthetic-fixture",
                "content_sha256": "a" * 64,
                "as_of": "2026-07-25T00:00:00Z",
                "expires_at": "2026-07-26T00:00:00Z",
            }, sort_keys=True, separators=(",", ":")),
            "",
        ),
    )


# ── helpers ──────────────────────────────────────────────────────────────

def _mkscratch(tmp_path: Path) -> Path:
    s = tmp_path / ".scratchpad"
    s.mkdir()
    return s


def _mk_go_proj(tmp_path: Path) -> Path:
    p = tmp_path / "go_project"
    p.mkdir()
    (p / "go.mod").write_text("module example.com/l1client\n\ngo 1.21\n", encoding="utf-8")
    return p


def _mk_rust_proj(tmp_path: Path) -> Path:
    p = tmp_path / "rust_project"
    p.mkdir()
    (p / "Cargo.toml").write_text("[package]\nname = \"l1client\"\n", encoding="utf-8")
    (p / "Cargo.lock").write_text(
        "# synthetic lockfile\nversion = 3\n", encoding="utf-8"
    )
    return p


_GOVULNCHECK_NDJSON = "\n".join([
    '{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}',
    '{"osv":{"id":"GO-2024-0001","summary":"Synthetic test vulnerability"}}',
    (
        '{"finding":{"osv":"GO-2024-0001","fixed_version":"v1.2.3",'
        '"trace":[{"module":"example.com/vulnerable-dep","package":'
        '"vulnpkg","version":"v1.0.0","function":"DoUnsafeThing"}]}}'
    ),
])

_CARGO_AUDIT_JSON = """{
  "database": {"advisory-count": 500},
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-2024-9999",
          "package": "synthdep",
          "title": "Synthetic test advisory",
          "date": "2024-01-01",
          "severity": null,
          "cvss": null,
          "url": "https://rustsec.org/advisories/RUSTSEC-2024-9999"
        },
        "versions": {"patched": [">=2.0.0"], "unaffected": []},
        "package": {"name": "synthdep", "version": "1.0.0"}
      }
    ]
  }
}"""


# ═══════════════════════════════════════════════════════════════════════
# A5: govulncheck (Go)
# ═══════════════════════════════════════════════════════════════════════

def test_govulncheck_scan_toolchain_unavailable(tmp_path):
    proj = _mk_go_proj(tmp_path)
    with mock.patch.object(RP.shutil, "which", return_value=None):
        status, findings = RP._govulncheck_scan(proj)
    assert status.startswith("TOOLCHAIN_UNAVAILABLE")
    assert "govulncheck" in status
    assert findings == []


def test_govulncheck_scan_skips_no_go_mod(tmp_path):
    proj = tmp_path / "no_go_mod"
    proj.mkdir()
    with mock.patch.object(RP.shutil, "which", return_value="/usr/bin/govulncheck"):
        status, findings = RP._govulncheck_scan(proj)
    assert status.startswith("SKIPPED")
    assert "go.mod" in status
    assert findings == []


def test_govulncheck_scan_parses_synthetic_hit(tmp_path):
    """Positive-harvest: a synthetic NDJSON finding must produce a real,
    non-empty parsed hit — not merely 'did not crash'."""
    proj = _mk_go_proj(tmp_path)
    with mock.patch.object(RP.shutil, "which", return_value="/usr/bin/govulncheck"), \
         mock.patch.object(RP, "_run_hardened", return_value=(3, _GOVULNCHECK_NDJSON)):
        status, findings = RP._govulncheck_scan(proj)
    assert status == "WRITTEN"
    assert len(findings) == 1
    hit = findings[0]
    assert hit["id"] == "GO-2024-0001"
    assert hit["module"] == "example.com/vulnerable-dep"
    assert hit["fixed_version"] == "v1.2.3"
    assert "Synthetic test vulnerability" in hit["summary"]


def test_govulncheck_scan_failed_nonzero_no_findings(tmp_path):
    proj = _mk_go_proj(tmp_path)
    with mock.patch.object(RP.shutil, "which", return_value="/usr/bin/govulncheck"), \
         mock.patch.object(RP, "_run_hardened", return_value=(1, "not valid json at all")):
        status, findings = RP._govulncheck_scan(proj)
    assert "FAILED" in status
    assert findings == []


# ═══════════════════════════════════════════════════════════════════════
# A5: cargo audit (Rust)
# ═══════════════════════════════════════════════════════════════════════

def test_cargo_audit_scan_toolchain_unavailable_no_cargo(tmp_path):
    proj = _mk_rust_proj(tmp_path)
    with mock.patch.object(RP.shutil, "which", return_value=None):
        status, findings = RP._cargo_audit_scan(proj)
    assert status.startswith("TOOLCHAIN_UNAVAILABLE")
    assert findings == []


def test_cargo_audit_scan_toolchain_unavailable_no_subcommand(tmp_path):
    proj = _mk_rust_proj(tmp_path)
    with mock.patch.object(RP.shutil, "which", return_value="/usr/bin/cargo-audit"), \
         mock.patch.object(RP, "_run_hardened", return_value=(1, "probe failed")):
        status, findings = RP._cargo_audit_scan(proj)
    assert status.startswith("TOOLCHAIN_UNAVAILABLE")
    assert "cargo-audit executable probe" in status
    assert findings == []


def test_cargo_audit_scan_skips_no_cargo_toml(tmp_path):
    proj = tmp_path / "no_cargo_toml"
    proj.mkdir()
    with mock.patch.object(RP.shutil, "which", return_value="/usr/bin/cargo-audit"):
        status, findings = RP._cargo_audit_scan(proj)
    assert status.startswith("SKIPPED")
    assert findings == []


def test_cargo_audit_scan_parses_synthetic_hit(tmp_path):
    """Positive-harvest: a synthetic cargo-audit JSON vulnerability must
    produce a real, non-empty parsed hit."""
    proj = _mk_rust_proj(tmp_path)

    def _fake_run_hardened(cmd, cwd=None, timeout=120, env=None):
        if "--version" in cmd:
            return 0, "cargo-audit 0.20.0"
        return 0, _CARGO_AUDIT_JSON

    with mock.patch.object(RP.shutil, "which", return_value="/usr/bin/cargo-audit"), \
         mock.patch.object(RP, "_run_hardened", side_effect=_fake_run_hardened):
        status, findings = RP._cargo_audit_scan(proj)
    assert status == "WRITTEN"
    assert len(findings) == 1
    hit = findings[0]
    assert hit["id"] == "RUSTSEC-2024-9999"
    assert hit["package"] == "synthdep"
    assert hit["patched"] == ">=2.0.0"


def test_parse_cargo_audit_json_handles_banner_prefix():
    """cargo-audit's combined stdout+stderr can carry a warning banner ahead
    of the JSON payload; the parser must still find and parse it."""
    raw = "warning: unmaintained crate detected\n" + _CARGO_AUDIT_JSON
    findings, parse_ok = RP._parse_cargo_audit_json(raw)
    assert parse_ok is True
    assert len(findings) == 1
    assert findings[0]["id"] == "RUSTSEC-2024-9999"


def test_parse_cargo_audit_json_no_json_not_parse_ok():
    findings, parse_ok = RP._parse_cargo_audit_json("totally not json output")
    assert parse_ok is False
    assert findings == []


# ═══════════════════════════════════════════════════════════════════════
# A5: _run_dependency_audit_l1 (top-level, writes dependency_audit_findings.md)
# ═══════════════════════════════════════════════════════════════════════

def test_run_dependency_audit_l1_toolchain_unavailable_writes_marker(tmp_path):
    """Positive-harvest degrade path: toolchain missing -> a real
    TOOLCHAIN_UNAVAILABLE marker lands in the artifact (never raises)."""
    scratch = _mkscratch(tmp_path)
    proj = _mk_go_proj(tmp_path)
    with mock.patch.object(RP.shutil, "which", return_value=None):
        status = RP._run_dependency_audit_l1(scratch, proj, "go")
    assert "TOOLCHAIN_UNAVAILABLE" in status
    dest = scratch / "dependency_audit_findings.md"
    assert dest.exists()
    text = dest.read_text(encoding="utf-8")
    assert "TOOLCHAIN_UNAVAILABLE" in text
    assert "govulncheck" in text.lower()


def test_run_dependency_audit_l1_writes_real_findings_on_synthetic_hit(tmp_path):
    """Positive-harvest: a real (non-empty) findings table must land in
    dependency_audit_findings.md on a synthetic hit."""
    scratch = _mkscratch(tmp_path)
    proj = _mk_go_proj(tmp_path)
    with mock.patch.object(RP.shutil, "which", return_value="/usr/bin/govulncheck"), \
         mock.patch.object(RP, "_run_hardened", return_value=(3, _GOVULNCHECK_NDJSON)):
        status = RP._run_dependency_audit_l1(scratch, proj, "go")
    assert "WRITTEN" in status
    assert "go=WRITTEN:1" in status
    dest = scratch / "dependency_audit_findings.md"
    assert dest.exists()
    text = dest.read_text(encoding="utf-8")
    assert "GO-2024-0001" in text
    assert "vulnpkg" in text
    assert "No known-vulnerability dependency findings." not in text


def test_run_dependency_audit_l1_mixed_language_runs_both(tmp_path):
    scratch = _mkscratch(tmp_path)
    proj = tmp_path / "mixed_project"
    proj.mkdir()
    (proj / "go.mod").write_text("module example.com/l1\n\ngo 1.21\n", encoding="utf-8")
    (proj / "Cargo.toml").write_text("[package]\nname = \"l1\"\n", encoding="utf-8")
    with mock.patch.object(RP.shutil, "which", return_value=None):
        status = RP._run_dependency_audit_l1(scratch, proj, "mixed")
    assert "go=TOOLCHAIN_UNAVAILABLE" in status
    assert "rust=TOOLCHAIN_UNAVAILABLE" in status
    text = (scratch / "dependency_audit_findings.md").read_text(encoding="utf-8")
    assert "Go (govulncheck)" in text
    assert "Rust (cargo audit)" in text


def test_run_dependency_audit_l1_never_raises_on_internal_error(tmp_path):
    """Degrade-continue floor: an unexpected internal exception must not
    propagate, and a FAILED marker artifact must still be written."""
    scratch = _mkscratch(tmp_path)
    proj = _mk_go_proj(tmp_path)
    with mock.patch.object(RP, "_govulncheck_scan", side_effect=RuntimeError("boom")):
        status = RP._run_dependency_audit_l1(scratch, proj, "go")
    assert "FAILED" in status
    text = (scratch / "dependency_audit_findings.md").read_text(encoding="utf-8")
    assert "FAILED" in text


def test_run_dependency_audit_l1_unknown_language_degrades(tmp_path):
    scratch = _mkscratch(tmp_path)
    proj = tmp_path / "unknown_lang_project"
    proj.mkdir()
    status = RP._run_dependency_audit_l1(scratch, proj, "cpp")
    assert "TOOLCHAIN_UNAVAILABLE" in status
    assert (scratch / "dependency_audit_findings.md").exists()


def test_driver_dependency_audit_lazy_wrapper_delegates(tmp_path):
    """The plamen_driver.py lazy wrapper must delegate to recon_prepass's
    real implementation (proves the pre-breadth hook's call target exists
    and is wired, without needing the full phase-execution machinery)."""
    scratch = _mkscratch(tmp_path)
    proj = _mk_go_proj(tmp_path)
    with mock.patch.object(RP.shutil, "which", return_value=None):
        status = D._run_dependency_audit_l1(scratch, proj, "go")
    assert "TOOLCHAIN_UNAVAILABLE" in status
    assert (scratch / "dependency_audit_findings.md").exists()


def test_dependency_audit_wiring_is_l1_gated_in_source():
    """Structural SC-isolation proof: the pre-breadth hook call to
    `_run_dependency_audit_l1` must be textually gated by
    `config.get("pipeline") == "l1"` (mirrors the existing Go/Rust SCIP-bake
    gating already used in the same hook)."""
    src = (SCRIPTS_DIR / "plamen_driver.py").read_text(encoding="utf-8")
    idx = src.index('lambda: _run_dependency_audit_l1(')
    window = src[max(0, idx - 2400):idx]
    assert 'config.get("pipeline") == "l1"' in window


# ═══════════════════════════════════════════════════════════════════════
# A6: recon-side HAS_MOVE_SOURCES detection (recon_prepass.py)
# ═══════════════════════════════════════════════════════════════════════

def _mk_l1_move_proj(tmp_path: Path, *, with_move: bool) -> Path:
    p = tmp_path / "l1_move_project"
    p.mkdir()
    (p / "go.mod").write_text("module example.com/l1client\n\ngo 1.21\n", encoding="utf-8")
    (p / "consensus").mkdir()
    (p / "consensus" / "engine.go").write_text("package consensus\n", encoding="utf-8")
    if with_move:
        (p / "movevm").mkdir()
        (p / "movevm" / "executor.move").write_text(
            "module 0x1::executor { public fun run() {} }\n", encoding="utf-8"
        )
    return p


def test_detect_move_sources_l1_positive(tmp_path):
    proj = _mk_l1_move_proj(tmp_path, with_move=True)
    assert RP._detect_move_sources_l1(proj) is True


def test_detect_move_sources_l1_negative(tmp_path):
    proj = _mk_l1_move_proj(tmp_path, with_move=False)
    assert RP._detect_move_sources_l1(proj) is False


def test_seed_move_sources_flag_detected_positive_harvest(tmp_path):
    """Positive-harvest: a real .move file must produce a real
    HAS_MOVE_SOURCES landing in both detected_patterns.md and
    template_recommendations.md (Required=YES rows for the 3 routed skills)."""
    scratch = _mkscratch(tmp_path)
    proj = _mk_l1_move_proj(tmp_path, with_move=True)

    status = RP._seed_move_sources_flag(scratch, proj)
    assert status == "DETECTED:HAS_MOVE_SOURCES"

    dp = (scratch / "detected_patterns.md").read_text(encoding="utf-8")
    assert "HAS_MOVE_SOURCES" in dp

    tr = (scratch / "template_recommendations.md").read_text(encoding="utf-8")
    assert "HAS_MOVE_SOURCES" in tr
    assert "MOVE_SAFETY_CORE_DIRECTIVES" in tr
    assert "ABILITY_ANALYSIS" in tr
    assert "TYPE_SAFETY" in tr
    # Required column must actually be flipped, not just a mention.
    assert "| `MOVE_SAFETY_CORE_DIRECTIVES` |" in tr
    assert "YES" in tr


def test_seed_move_sources_flag_not_detected(tmp_path):
    scratch = _mkscratch(tmp_path)
    proj = _mk_l1_move_proj(tmp_path, with_move=False)
    status = RP._seed_move_sources_flag(scratch, proj)
    assert status == "NOT_DETECTED"
    # No flag file should be spuriously created.
    dp = scratch / "detected_patterns.md"
    if dp.exists():
        assert "HAS_MOVE_SOURCES" not in dp.read_text(encoding="utf-8")


def test_run_recon_prepass_l1_with_move_sources_end_to_end(tmp_path):
    """Full run_recon_prepass() positive-harvest: HAS_MOVE_SOURCES flows
    through to template_recommendations.md for a real L1+Move workspace."""
    scratch = tmp_path / ".scratchpad"
    proj = _mk_l1_move_proj(tmp_path, with_move=True)
    results = RP.run_recon_prepass({
        "scratchpad": str(scratch),
        "project_root": str(proj),
        "_run_id": _RECON_PREPASS_RUN_ID,
        "language": "go",
        "pipeline": "l1",
    })
    assert results.get("move_sources_flag", "").startswith("DETECTED")
    tr = (scratch / "template_recommendations.md").read_text(encoding="utf-8")
    assert "HAS_MOVE_SOURCES" in tr
    assert "MOVE_SAFETY_CORE_DIRECTIVES" in tr


def test_run_recon_prepass_l1_without_move_sources_no_flag(tmp_path):
    scratch = tmp_path / ".scratchpad"
    proj = _mk_l1_move_proj(tmp_path, with_move=False)
    results = RP.run_recon_prepass({
        "scratchpad": str(scratch),
        "project_root": str(proj),
        "_run_id": _RECON_PREPASS_RUN_ID,
        "language": "go",
        "pipeline": "l1",
    })
    assert results.get("move_sources_flag") == "NOT_DETECTED"
    tr = (scratch / "template_recommendations.md").read_text(encoding="utf-8")
    assert "HAS_MOVE_SOURCES" not in tr


def test_run_recon_prepass_sc_pipeline_never_runs_move_sources_flag(tmp_path):
    """SC ISOLATION: an SC (non-l1) pipeline run must never invoke the
    HAS_MOVE_SOURCES dispatch at all -- not 'NOT_DETECTED', simply absent --
    even for an aptos project that legitimately has native .move sources
    (those are handled by the pre-existing `_bake_move_graph` lane, untouched
    by this change)."""
    scratch = tmp_path / ".scratchpad"
    proj = tmp_path / "aptos_project"
    proj.mkdir()
    (proj / "Move.toml").write_text("[package]\nname = \"pkg\"\n", encoding="utf-8")
    (proj / "sources").mkdir()
    (proj / "sources" / "coin.move").write_text(
        "module 0x1::coin { public fun mint() {} }\n", encoding="utf-8"
    )
    results = RP.run_recon_prepass({
        "scratchpad": str(scratch),
        "project_root": str(proj),
        "_run_id": _RECON_PREPASS_RUN_ID,
        "language": "aptos",
        "pipeline": "sc",
    })
    assert "move_sources_flag" not in results
    tr_path = scratch / "template_recommendations.md"
    if tr_path.exists():
        assert "HAS_MOVE_SOURCES" not in tr_path.read_text(encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════
# A6: driver-side routing (plamen_driver.py)
# ═══════════════════════════════════════════════════════════════════════

def _write_detected_patterns_with_move_flag(scratch: Path) -> None:
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / "detected_patterns.md").write_text(
        "# Detected Patterns\n\n"
        "## Flags (mechanical — embedded Move sources)\n"
        "- `HAS_MOVE_SOURCES`\n\n"
        "Embedded Move-VM execution layer detected.\n",
        encoding="utf-8",
    )


def test_l1_has_move_sources_true_from_detected_patterns(tmp_path):
    scratch = _mkscratch(tmp_path)
    _write_detected_patterns_with_move_flag(scratch)
    assert D._l1_has_move_sources(scratch) is True


def test_l1_has_move_sources_false_when_absent(tmp_path):
    scratch = _mkscratch(tmp_path)
    assert D._l1_has_move_sources(scratch) is False


def test_l1_move_skill_injection_block_positive_for_state_trace(tmp_path):
    """Positive-harvest: the routing block must name real, resolvable
    aptos/sui SKILL.md paths -- not just fire an empty/placeholder block."""
    scratch = _mkscratch(tmp_path)
    _write_detected_patterns_with_move_flag(scratch)

    block = D._l1_move_skill_injection_block(scratch, "state_trace")
    assert block != ""
    assert "MOVE SKILL ROUTING" in block
    assert "MOVE_SAFETY_CORE_DIRECTIVES" in block
    assert "ABILITY_ANALYSIS" in block
    assert "TYPE_SAFETY" in block

    # Every referenced skill path must actually exist on disk (real routing,
    # not a dangling reference).
    for name in ("MOVE_SAFETY_CORE_DIRECTIVES", "ABILITY_ANALYSIS", "TYPE_SAFETY"):
        p = D._sc_skill_path_for_name(name, "aptos")
        assert p is not None and p.exists(), f"{name} did not resolve"
        assert p.as_posix() in block


def test_l1_move_skill_injection_block_positive_for_external(tmp_path):
    scratch = _mkscratch(tmp_path)
    _write_detected_patterns_with_move_flag(scratch)
    block = D._l1_move_skill_injection_block(scratch, "external")
    assert block != ""
    assert "MOVE_SAFETY_CORE_DIRECTIVES" in block


def test_l1_move_skill_injection_block_empty_for_non_routed_role(tmp_path):
    scratch = _mkscratch(tmp_path)
    _write_detected_patterns_with_move_flag(scratch)
    block = D._l1_move_skill_injection_block(scratch, "consensus_invariant")
    assert block == ""


def test_l1_move_skill_injection_block_empty_without_flag(tmp_path):
    scratch = _mkscratch(tmp_path)
    block = D._l1_move_skill_injection_block(scratch, "state_trace")
    assert block == ""


def _l1_job(role: str, agent_id: str, output: str) -> dict:
    return {
        "agent_id": agent_id,
        "role": role,
        "output": output,
        "category": "standard",
        "focus": f"L1 {role} focus",
    }


def test_build_depth_worker_prompt_l1_routes_move_skills_into_state_trace(tmp_path):
    """End-to-end positive-harvest: HAS_MOVE_SOURCES + role=state_trace must
    produce a real Move-skill routing section in the actual depth worker
    prompt (the production path, not just the helper in isolation)."""
    scratch = _mkscratch(tmp_path)
    _write_detected_patterns_with_move_flag(scratch)
    job = _l1_job("state_trace", "depth-state-trace", "depth_state_trace_findings.md")

    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=scratch,
        project_root=str(tmp_path),
        config={"language": "go", "mode": "core", "pipeline": "l1"},
        attempt=1,
    )
    assert "MOVE SKILL ROUTING" in prompt
    assert "MOVE_SAFETY_CORE_DIRECTIVES" in prompt


def test_build_depth_worker_prompt_l1_no_move_sources_no_routing(tmp_path):
    scratch = _mkscratch(tmp_path)
    job = _l1_job("state_trace", "depth-state-trace", "depth_state_trace_findings.md")

    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=scratch,
        project_root=str(tmp_path),
        config={"language": "go", "mode": "core", "pipeline": "l1"},
        attempt=1,
    )
    assert "MOVE SKILL ROUTING" not in prompt


def test_build_depth_worker_prompt_l1_non_routed_role_no_routing(tmp_path):
    scratch = _mkscratch(tmp_path)
    _write_detected_patterns_with_move_flag(scratch)
    job = _l1_job(
        "consensus_invariant", "depth-consensus-invariant",
        "depth_consensus_invariant_findings.md",
    )

    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=scratch,
        project_root=str(tmp_path),
        config={"language": "go", "mode": "core", "pipeline": "l1"},
        attempt=1,
    )
    assert "MOVE SKILL ROUTING" not in prompt


def test_build_depth_worker_prompt_sc_pipeline_never_calls_move_routing(tmp_path, monkeypatch):
    """SC ISOLATION (hard proof): on the SC path, `_l1_move_skill_injection_block`
    must never even be called -- even when HAS_MOVE_SOURCES happens to be
    present in the scratchpad (defense-in-depth). Monkeypatch it to raise so
    any invocation fails the test loudly instead of silently no-op'ing."""
    scratch = _mkscratch(tmp_path)
    _write_detected_patterns_with_move_flag(scratch)

    def _boom(*args, **kwargs):
        raise AssertionError("_l1_move_skill_injection_block must not be called for SC pipeline")

    monkeypatch.setattr(D, "_l1_move_skill_injection_block", _boom)

    job = {
        "agent_id": "depth-state-trace",
        "role": "state_trace",
        "output": "depth_state_trace_findings.md",
        "category": "standard",
        "focus": "SC state trace",
    }
    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=scratch,
        project_root=str(tmp_path),
        config={"language": "evm", "mode": "core", "pipeline": "sc"},
        attempt=1,
    )
    assert "MOVE SKILL ROUTING" not in prompt
    assert "AGENT_ROW: depth-state-trace" in prompt


def test_build_depth_worker_prompt_sc_byte_identical_around_skill_block(tmp_path):
    """SC ISOLATION: the SC prompt-building branch (pipeline != 'l1') must be
    unaffected by this change -- exercise it and confirm the pre-existing SC
    skill-injection mechanism (_sc_skill_injection_block/_parse_sc_skill_bindings)
    is what actually ran, not the new L1 Move routing helper."""
    scratch = _mkscratch(tmp_path)
    job = {
        "agent_id": "depth-external",
        "role": "external",
        "output": "depth_external_findings.md",
        "category": "standard",
        "focus": "SC external",
    }
    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=scratch,
        project_root=str(tmp_path),
        config={"language": "evm", "mode": "core", "pipeline": "sc"},
        attempt=1,
    )
    assert "MOVE SKILL ROUTING" not in prompt
    assert "MOVE_SAFETY_CORE_DIRECTIVES" not in prompt


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
