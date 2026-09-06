"""Explicit archival moves report answer keys but preserves fuzz workspaces.

Report/RCA files can be explicit answer keys. Preserved `.medusa-tests` data is
not moved: production-source and Slither boundaries exclude it, while fuzz
authority copies it only into quarantine.
"""
from __future__ import annotations

from pathlib import Path

import plamen_driver as PD


def _mk(p: Path, body: str = "x") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _proj(tmp_path: Path) -> Path:
    # project_root = .../omni/contracts ; parent (.../omni) is the Foundry root.
    proj = tmp_path / "omni" / "contracts"
    proj.mkdir(parents=True)
    return proj


def test_archives_reports_and_rca_but_preserves_fuzz_harness(tmp_path):
    proj = _proj(tmp_path)
    # answer-key artifacts
    _mk(proj / "AUDIT_REPORT-20260701-2140.md", "# prior report\nC-01 ...")
    _mk(proj / "AUDIT_REPORT.md", "# latest prior report")
    _mk(proj / "PARTIAL_RCA.md", "root cause ...")
    _mk(proj / "RC_AGENT_FIXTURE_RCA.md", "fixture rca ...")
    _mk(proj / "CONSOLIDATION-FIX-NOTES.md", "notes ...")
    _mk(proj / ".medusa-tests" / "MedusaCampaignV6.sol",
        "// usePreFeeForSwap true = buggy (production)")
    # legitimate in-scope source that must be UNTOUCHED
    _mk(proj / "CrossChainRouter.sol", "pragma solidity ^0.8.0;\ncontract G {}")
    _mk(proj / "interfaces" / "IBridgeRouter.sol", "interface I {}")

    archive = PD._archive_prior_audit_artifacts(proj)

    # returned a real dot-prefixed archive, one level up
    assert archive is not None
    assert archive.parent == proj.parent
    assert archive.name.startswith(".plamen_archive_")
    assert archive.is_dir()

    # answer-key artifacts are GONE from project_root...
    for name in (
        "AUDIT_REPORT-20260701-2140.md", "AUDIT_REPORT.md", "PARTIAL_RCA.md",
        "RC_AGENT_FIXTURE_RCA.md", "CONSOLIDATION-FIX-NOTES.md",
    ):
        assert not (proj / name).exists(), f"{name} should have been moved"
    assert (proj / ".medusa-tests" / "MedusaCampaignV6.sol").is_file()

    # ...and present in the archive (moved, not deleted)
    assert (archive / "AUDIT_REPORT-20260701-2140.md").is_file()
    assert (archive / "PARTIAL_RCA.md").is_file()
    assert not (archive / ".medusa-tests").exists()

    # legitimate source is UNTOUCHED
    assert (proj / "CrossChainRouter.sol").is_file()
    assert (proj / "interfaces" / "IBridgeRouter.sol").is_file()


def test_dot_prefixed_report_archive_is_invisible_to_source_walks(tmp_path):
    # A dot-prefixed archive at the Foundry root must be skipped by the same
    # walks recon/compile use, so it can never be re-ingested.
    import recon_prepass as RP
    proj = _proj(tmp_path)
    _mk(proj / "AUDIT_REPORT.md", "prior")
    _mk(proj / ".medusa-tests" / "Harness.sol", "contract H {}")
    _mk(proj / "Real.sol", "pragma solidity ^0.8.0;\ncontract R {}")

    archive = PD._archive_prior_audit_artifacts(proj)
    assert archive is not None
    # The report archive lives under a dot-dir at the Foundry root (parent).
    foundry_root = proj.parent
    comp = RP._compile_unit_files(foundry_root, (".sol",))
    rels = {p.relative_to(foundry_root).as_posix() for p in comp}
    # Real source still visible; archived harness NOT visible to the walk.
    assert any(r.endswith("Real.sol") for r in rels)
    assert not any("plamen_archive" in r for r in rels)
    assert not any("Harness.sol" in r for r in rels)


def test_noop_when_nothing_to_archive(tmp_path):
    proj = _proj(tmp_path)
    _mk(proj / "CrossChainRouter.sol", "contract G {}")
    assert PD._archive_prior_audit_artifacts(proj) is None
    # no stray archive dir created
    assert not any(p.name.startswith(".plamen_archive_")
                   for p in proj.parent.iterdir())


def test_never_raises_on_bad_root(tmp_path):
    assert PD._archive_prior_audit_artifacts(tmp_path / "does_not_exist") is None
