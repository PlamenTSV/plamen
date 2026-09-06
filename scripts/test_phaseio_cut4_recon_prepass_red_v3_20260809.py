"""V3 RED denominator for the live Cut-4 recon prepass boundary.

Unlike V1/V2, this module enters through the current production functions.  It
does not import a proposed application module, accept a status string as proof,
or replace any ArtifactLedger/transaction helper.  Provider execution may be
made unavailable, but the real prepass, driver startup, ledger reader, and
resume/degrade branch remain in the path.
"""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
from typing import Any, Mapping

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import artifact_ledger as AL  # noqa: E402
import plamen_driver as D  # noqa: E402
import recon_prepass as RP  # noqa: E402
import test_driver_smoke as DRIVER_SMOKE  # noqa: E402


RUN_ID = "cut4-recon-v3"
V1_HASHES = {
    "test_phaseio_cut4_recon_prepass_red_20260730.py":
        "50be6f719bde3c0910b9766fdf682824d5a3d4d4ec26cec86cedc48c4a224f2a",
    "test_phaseio_cut4_recon_dependency_merge_red_20260730.py":
        "7abf2efb49123bdcf93732a909ccd0f98f9371688c4bee7a69a5675b970e1bb1",
}
V2_HASHES = {
    "test_phaseio_cut4_recon_prepass_red_v2_20260809.py":
        "103f4c38b3d2f293b70dee127ac81e3c1a0d5fb5f36927873ce2033fe3689f4a",
    "test_phaseio_cut4_recon_dependency_merge_red_v2_20260809.py":
        "0de4ff1d7492416035721ac629cd21258feb0d17987f6b6c7a9ebdf62bd3a57a",
}

SC_PREPASS = (
    "contract_inventory.md",
    "state_variables.md",
    "function_list.md",
    "build_status.md",
    "design_context.md",
    "attack_surface.md",
    "detected_patterns.md",
    "template_recommendations.md",
    "recon_summary.md",
    "meta_buffer.md",
    "external_dependency_research.md",
)
L1_PREPASS = (
    "subsystem_map.md",
    "trust_boundaries.md",
    "attack_surface.md",
    "threat_model.md",
    "template_recommendations.md",
    "recon_summary.md",
    "meta_buffer.md",
    "external_dependency_research.md",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _workspace(
    tmp_path: Path,
    *,
    pipeline: str,
    mode: str,
    route: str,
) -> tuple[Path, Path, dict[str, Any]]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    source = project / "src"
    source.mkdir(parents=True)
    scratchpad.mkdir()
    if pipeline == "l1":
        (source / "node.rs").write_text(
            "pub fn process_block(height: u64) -> bool { height > 0 }\n",
            encoding="utf-8",
        )
        language = "rust"
    else:
        (source / "Protocol.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "contract Protocol { uint256 public value; "
            "function set(uint256 x) external { value = x; } }\n",
            encoding="utf-8",
        )
        language = "evm"
    backend = "codex" if route == "codex" else "claude"
    config = {
        "pipeline": pipeline,
        "mode": mode,
        "language": language,
        "cli_backend": backend,
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": RUN_ID,
        "run_id": RUN_ID,
        "prepass_external_scanners": False,
    }
    return project, scratchpad, config


def _assert_nonempty(root: Path, names: tuple[str, ...]) -> None:
    missing = [name for name in names if not (root / name).is_file()]
    empty = [name for name in names if (root / name).is_file() and not (root / name).read_bytes()]
    assert not missing, f"real prepass omitted files: {missing}"
    assert not empty, f"real prepass emitted zero-byte files: {empty}"


def _disable_external_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make only OS/provider execution unavailable; keep prepass logic real."""
    monkeypatch.setattr(RP.shutil, "which", lambda _name: None)
    monkeypatch.setattr(RP, "gate_supply_chain", lambda _root: None)
    monkeypatch.setattr(
        RP,
        "run_owned_process",
        lambda _args, **_kwargs: SimpleNamespace(
            returncode=127, stdout="", stderr="fixture unavailable"
        ),
    )


def _active_unit(root: Path, suffix: str) -> Mapping[str, Any]:
    ledger = AL.read_artifact_ledger(root)
    matches = [
        row for key, row in ledger.get("work_units", {}).items()
        if str(key).endswith(suffix)
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(matches) == 1, f"expected one committed unit *{suffix}, got {len(matches)}"
    return matches[0]


def _assert_committed_outputs(root: Path, unit: Mapping[str, Any], names: tuple[str, ...]) -> None:
    ledger = AL.read_artifact_ledger(root)
    identities = {f"scratchpad:{name}" for name in names}
    assert identities.issubset(set(unit.get("artifacts", {})))
    for identity in identities:
        row = ledger.get("artifact_bindings", {}).get(identity)
        assert isinstance(row, Mapping), f"missing committed binding {identity}"
        assert row.get("status") == "ACTIVE"
        assert row.get("owner_key") == unit.get("work_unit_key")
        record = unit["artifacts"][identity]
        assert int(record.get("size") or 0) > 0


def test_v1_v2_fixture_preimages_remain_byte_frozen() -> None:
    for name, expected in {**V1_HASHES, **V2_HASHES}.items():
        path = SCRIPTS / name
        assert path.is_file(), name
        assert _sha(path) == expected


@pytest.mark.parametrize(
    ("pipeline", "mode", "route"),
    (
        ("sc", "light", "codex"),
        ("sc", "core", "claude-headless"),
        ("sc", "thorough", "pty"),
        ("l1", "light", "pty"),
        ("l1", "core", "codex"),
        ("l1", "thorough", "claude-headless"),
    ),
)
def test_live_prepass_matrix_requires_one_committed_selected_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    mode: str,
    route: str,
) -> None:
    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline=pipeline, mode=mode, route=route
    )

    # This is the current entry point.  Tool discovery/build failure is a real
    # provider outcome; it must not erase the deterministic prepass bytes.
    result = RP.run_recon_prepass(config)
    expected = L1_PREPASS if pipeline == "l1" else SC_PREPASS
    _assert_nonempty(scratchpad, expected)
    assert isinstance(result, dict) and result

    unit = _active_unit(scratchpad, "/recon/prepass")
    assert unit.get("run_id") == RUN_ID
    _assert_committed_outputs(scratchpad, unit, expected)


@pytest.mark.parametrize(
    "failpoint",
    (
        "after_roster_arm",
        "after_first_semantic_publish",
        "before_commit",
    ),
)
def test_live_prepass_exposes_named_transactional_crash_recovery_seam(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failpoint: str,
) -> None:
    _disable_external_providers(monkeypatch)
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="codex"
    )
    RP.run_recon_prepass(config)
    _assert_nonempty(scratchpad, SC_PREPASS)

    signature = inspect.signature(RP.run_recon_prepass)
    assert "failure_injector" in signature.parameters, (
        f"real run_recon_prepass has no named publication seam for {failpoint}"
    )


@pytest.mark.parametrize("mutation", ("source_edit", "config_edit", "unexpected_output"))
def test_live_prepass_drift_never_rebinds_the_armed_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    RP.run_recon_prepass(config)
    _assert_nonempty(scratchpad, SC_PREPASS)
    first = {name: _sha(scratchpad / name) for name in SC_PREPASS}

    if mutation == "source_edit":
        (project / "src" / "Protocol.sol").write_text(
            "pragma solidity ^0.8.20; contract Changed { function x() external {} }\n",
            encoding="utf-8",
        )
    elif mutation == "config_edit":
        config["language"] = "solana"
    else:
        (scratchpad / "recon_unplanned_semantic.md").write_text(
            "# Unplanned\n\nnonempty semantic output\n", encoding="utf-8"
        )

    RP.run_recon_prepass(config)
    _assert_nonempty(scratchpad, SC_PREPASS)
    units = AL.read_artifact_ledger(scratchpad).get("work_units", {})
    committed = [
        row for key, row in units.items()
        if str(key).endswith("/recon/prepass")
        and isinstance(row, Mapping)
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert committed, "drift was executed with zero durable prepass ledger"
    latest = committed[-1]
    if any(first[name] != _sha(scratchpad / name) for name in SC_PREPASS):
        assert latest.get("publication_generation") != committed[0].get("publication_generation")
    assert latest.get("semantic_status") == "ACTIVE"


def test_real_driver_startup_calls_real_prepass_before_phase_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Reuse the stable phase-loop harness, but replace its deliberate prepass
    # module stub with a wrapper around the real production entry point.
    marker = tmp_path / "real_prepass_called.json"
    old = '''_stub_mod = types.ModuleType("recon_prepass")\n_stub_mod.run_recon_prepass = lambda cfg: "stub-prepass"'''
    new = f'''import recon_prepass as _real_recon_prepass\n_real_run_recon_prepass = _real_recon_prepass.run_recon_prepass\ndef _observed_real_prepass(cfg):\n    result = _real_run_recon_prepass(cfg)\n    Path(r"{marker}").write_text(json.dumps(result, sort_keys=True), encoding="utf-8")\n    return result\n_real_recon_prepass.run_recon_prepass = _observed_real_prepass\n_stub_mod = _real_recon_prepass'''
    template = DRIVER_SMOKE.RUNNER_TEMPLATE.replace(old, new)
    template = template.replace('sys.modules["recon_prepass"] = _stub_mod', '')
    monkeypatch.setattr(DRIVER_SMOKE, "RUNNER_TEMPLATE", template)

    run_root, _project, scratchpad, config_path, call_log = DRIVER_SMOKE._make_project(
        "cut4_v3_startup_", mode="light", pipeline="sc",
        extra_config={"cli_backend": "codex"},
    )
    try:
        DRIVER_SMOKE._run_driver(run_root, config_path, call_log, "A")
        assert marker.is_file() and marker.read_bytes()
        _assert_nonempty(scratchpad, SC_PREPASS)
        unit = _active_unit(scratchpad, "/recon/prepass")
        _assert_committed_outputs(scratchpad, unit, SC_PREPASS)
    finally:
        shutil.rmtree(run_root, ignore_errors=True)


def test_actual_marker_degrade_branch_requires_canonical_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_external_providers(monkeypatch)
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="light", route="pty"
    )
    RP.run_recon_prepass(config)
    _assert_nonempty(scratchpad, SC_PREPASS)
    hard, _soft = D._validate_recon_content_structure(scratchpad, backend="claude")
    missing = [f"recon content: {item}" for item in hard]

    degraded, _new_missing = D._try_recon_prepass_marker_degrade(
        scratchpad, config, missing
    )
    # The real branch may legitimately decline when another content defect is
    # present.  Either way it cannot claim a canonical promotion without a
    # committed DRIVER successor over the actual bytes.
    if degraded:
        _assert_nonempty(scratchpad, SC_PREPASS)
    unit = _active_unit(scratchpad, "/recon/prepass_degrade")
    _assert_committed_outputs(scratchpad, unit, SC_PREPASS)


def test_zero_byte_output_cannot_be_clean_prepass_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_external_providers(monkeypatch)
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="claude-headless"
    )
    RP.run_recon_prepass(config)
    _assert_nonempty(scratchpad, SC_PREPASS)
    (scratchpad / "function_list.md").write_bytes(b"")

    unit = _active_unit(scratchpad, "/recon/prepass")
    ledger = AL.read_artifact_ledger(scratchpad)
    binding = ledger.get("artifact_bindings", {}).get("scratchpad:function_list.md")
    assert isinstance(binding, Mapping)
    assert binding.get("status") != "ACTIVE", (
        "zero-byte semantic output retained ACTIVE producer authority"
    )
    assert unit.get("semantic_status") != "ACTIVE"
