"""Driver-level regression for typed Program Facts tool unavailability.

This deliberately uses the production workspace and PhaseIO publishers.  The
only fixture seam is the existing immutable-snapshot stabilization used by the
Stage-2 integration suite while unrelated source writers share the checkout.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

from artifact_ledger import read_artifact_ledger
import evm_analysis_workspace_authority as WORKSPACE
import plamen_driver as DRIVER
from program_facts_types import strict_json_loads
import test_program_facts_driver_integration_stage2 as BASE


BAKE_KEY = "sc/thorough/evm/claude/recon/program_facts_bake"
FORBIDDEN_COMPILER_VERSION_KEYS = frozenset(
    {
        "compiler_version",
        "distribution_version",
        "solc_version",
        "toolchain_version",
        "version_output",
    }
)


def _decode_sidecars(scratchpad: Path) -> tuple[dict, dict, dict]:
    decoded = []
    for name in BASE.SIDE_CARS:
        raw = (scratchpad / name).read_bytes()
        decoded.append(
            strict_json_loads(
                raw,
                require_final_lf=True,
                require_canonical=True,
            )
        )
    payload, receipt, debt = decoded
    return payload, receipt, debt


def _keys(value: object):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _keys(child)


def test_driver_unadmitted_solc_commits_typed_unavailable_bundle_without_version(
    tmp_path: Path,
) -> None:
    fixture = BASE._fixture(tmp_path)
    workspace = WORKSPACE.load_evm_analysis_workspace_authority(
        fixture["scratchpad"],
        expected_run_id=fixture["run_id"],
        expected_snapshot_sha256=fixture["snapshot"]["snapshot_digest"],
    )
    solc = next(row for row in workspace["tools"] if row["tool_id"] == "solc")
    assert solc["admission_state"] == "UNADMITTED"
    assert solc["signed_runtime_authority"] is None
    assert workspace["solc_identity"] == {
        "admission_state": "UNADMITTED",
        "snapshot_runtime_identity": solc["snapshot_runtime_identity"],
        "tool_row_sha256": solc["tool_row_sha256"],
    }
    variant, compiler = BASE.INTEGRATION._workspace_build_variant(workspace)
    assert compiler is None
    assert variant["build_root_id"].startswith("PFW-")
    assert "/" not in variant["build_root_id"]
    assert "\\" not in variant["build_root_id"]
    assert ":" not in variant["build_root_id"]

    # BASE._run supplies the production-valid immutable source/snapshot
    # authorities.  Replacing only its selected entry point with the driver's
    # thin integration seam ensures this test traverses the real driver branch.
    with patch.object(
        BASE,
        "ensure_program_facts_stage2_emit_only",
        DRIVER._ensure_program_facts_stage2_emit_only,
    ):
        first = BASE._run(fixture)

    assert first.valid is True
    assert first.state == "UNSUPPORTED"
    assert first.reused is False
    assert first.consumer_activation is False
    assert first.reason_codes == ("WORKSPACE_TOOL_UNADMITTED",)

    scratchpad = fixture["scratchpad"]
    before = {
        name: (scratchpad / name).read_bytes() for name in BASE.SIDE_CARS
    }
    payload, receipt, debt = _decode_sidecars(scratchpad)
    assert payload["schema_version"] == "plamen.mechanical_program_facts.v1"
    assert payload["facts"] == []
    assert payload["nodes"] == []
    assert payload["occurrences"] == []
    assert {row["status"] for row in payload["coverage"]} == {"UNKNOWN"}
    assert "toolchains" not in payload
    assert all("version" not in row for row in payload["build_variants"])
    assert receipt["schema_version"] == (
        "plamen.mechanical_program_facts_receipt.v1"
    )
    assert receipt["status"] == "UNAVAILABLE"
    assert receipt["build_attempts"] == []
    assert receipt["provider_runs"] == []
    assert receipt["worker_transaction_refs"] == []
    assert debt["schema_version"] == (
        "plamen.mechanical_program_facts_debt.v1"
    )
    assert debt["debts"]
    assert {row["reason"] for row in debt["debts"]} == {
        "PROVIDER_UNAVAILABLE"
    }
    assert all(row["terminal_negative_authority"] is False for row in debt["debts"])

    # An unadmitted tool contributes only its content-bound row digest to the
    # build variant.  No placeholder/fabricated compiler version may appear in
    # any committed public sidecar.
    assert not (FORBIDDEN_COMPILER_VERSION_KEYS & set(_keys(payload)))
    assert not (FORBIDDEN_COMPILER_VERSION_KEYS & set(_keys(receipt)))
    assert not (FORBIDDEN_COMPILER_VERSION_KEYS & set(_keys(debt)))

    ledger = read_artifact_ledger(scratchpad)
    assert ledger["work_units"][BAKE_KEY]["semantic_status"] == "ACTIVE"
    artifacts_by_name = {
        BASE.SIDE_CARS[0]: "facts",
        BASE.SIDE_CARS[2]: "debt",
    }
    for name, artifact_name in artifacts_by_name.items():
        assert receipt["artifacts"][artifact_name]["file_sha256"] == (
            hashlib.sha256(before[name]).hexdigest()
        )

    with patch.object(
        BASE,
        "ensure_program_facts_stage2_emit_only",
        DRIVER._ensure_program_facts_stage2_emit_only,
    ):
        replayed = BASE._run(fixture)
    assert replayed.valid is True
    assert replayed.reused is True
    assert {
        name: (scratchpad / name).read_bytes() for name in BASE.SIDE_CARS
    } == before
