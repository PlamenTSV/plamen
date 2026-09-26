"""Exact producer authority for deterministic recon-prepass niche findings."""
from __future__ import annotations

import json
import sys
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import artifact_ledger as AL  # noqa: E402
import finding_producer_registry as R  # noqa: E402
import plamen_driver as D  # noqa: E402
import plamen_mechanical as M  # noqa: E402
import recon_prepass as RP  # noqa: E402
from plamen_types import SC_PHASES  # noqa: E402
from test_inventory_canonical_aggregate_phaseio_p0_l import (  # noqa: E402
    _fixture,
    _seed_for_aggregate,
)


def _seed_canonical(tmp_path: Path) -> tuple[Path, Path, dict]:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, "single_shard")
    phase = next(row for row in SC_PHASES if row.name == "inventory")
    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=phase,
        derivation_kind="single_shard",
    )
    assert issues == []
    return project, scratch, config


def _write_prepass_sources(project: Path) -> None:
    (project / "IParity.sol").write_text(
        "interface IParity { function declaredCall() external; }\n",
        encoding="utf-8",
    )
    (project / "Parity.sol").write_text(
        "contract Parity is IParity {\n"
        " function declaredCall() external {}\n"
        " function omittedCall() external {}\n"
        "}\n",
        encoding="utf-8",
    )
    (project / "Setter.sol").write_text(
        "contract Setter {\n"
        " uint256 public fee;\n"
        " function setFee(uint256 value) external { fee = value; }\n"
        "}\n",
        encoding="utf-8",
    )


def test_prepass_niche_producers_are_exact_artifact_scoped() -> None:
    cases = (
        (
            "niche_interface_parity_findings.md",
            "recon_prepass_interface_parity",
            "IFACE-1",
            "PSET-1",
        ),
        (
            "niche_permissionless_setters_findings.md",
            "recon_prepass_permissionless_setters",
            "PSET-1",
            "IFACE-1",
        ),
    )
    for artifact, expected_key, accepted_id, rejected_id in cases:
        producer = R.producer_for_artifact(
            artifact, consumer="canonical_identity"
        )
        assert producer is not None
        assert producer.key == expected_key
        assert R.producer_accepts_current_local_id(producer, accepted_id)
        assert not R.producer_accepts_current_local_id(producer, rejected_id)

        assert R.producer_for_artifact(
            artifact, consumer="pre_dedup_promotion"
        ) is None

    generic = R.producer_for_artifact(
        "niche_runtime_findings.md", consumer="canonical_identity"
    )
    assert generic is not None and generic.key == "niche"
    assert not R.producer_accepts_current_local_id(generic, "PSET-1")
    assert not R.producer_accepts_current_local_id(generic, "IFACE-1")
    assert R.validate_registry_projection_completeness() == []


def test_real_prepass_outputs_authenticate_but_are_not_depth_niche_actions(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_prepass_sources(project)

    assert RP._write_interface_parity_findings(scratch, project) == "WRITTEN"
    assert RP._write_permissionless_setter_findings(scratch, project) == "WRITTEN"

    for artifact, finding_id in (
        ("niche_interface_parity_findings.md", "IFACE-1"),
        ("niche_permissionless_setters_findings.md", "PSET-1"),
    ):
        rows = M._parsers._parse_depth_finding_blocks(
            scratch / artifact, consumer="canonical_identity"
        )
        by_id = {str(row["id"]): row for row in rows}
        assert by_id[finding_id]["_identity_status"] == "REGISTERED"
        assert by_id[finding_id]["_identity_debt"] == ""
        assert by_id[finding_id]["_local_id_valid"] == "true"

    # These recon actions publish through the manifest-bound inventory
    # transaction, never through the post-depth specialized niche writer.
    assert M._parse_niche_findings(scratch) == []


def test_specialized_depth_publisher_cannot_duplicate_prepass_pset(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_prepass_sources(project)
    assert RP._write_permissionless_setter_findings(scratch, project) == "WRITTEN"
    (scratch / "niche_runtime_findings.md").write_text(
        "### Finding [NS-1]: runtime niche action\n"
        "**Severity**: Medium\n"
        "**Location**: Setter.sol:L2\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Description**: runtime-only mechanism\n"
        "**Impact**: runtime-only material harm\n",
        encoding="utf-8",
    )
    rows = M._parse_niche_findings(scratch)
    assert [row["source_id"] for row in rows] == ["NS-1"]
    assert rows[0]["identity_status"] == "REGISTERED"
    assert rows[0]["identity_debt"] == ""
