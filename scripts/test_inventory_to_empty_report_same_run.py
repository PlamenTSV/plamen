"""Pending inventory-authority regression toward the same-run empty report seam.

Recon is not executed. Breadth source records and accepted depth/chain inputs
remain explicit synthetic fixture authority. A local Codex-compatible process
produces one inventory chunk through registered MODEL execution; real DRIVER
reconciliation, canonical aggregation and additive repair preserve its two
harmless Low candidates before accepted depth adds the third. The existing
same-run continuation then reaches policy-empty report assembly.

This does not claim provider judgment, vulnerability discovery, active
verification, complete phase coverage, or global report publication. There
are no target repositories or external model calls. The deliberately omitted
second chunk candidate tests visible debt and actual recall repair, not a
fabricated successful inventory generation. This regression is not a passed
milestone: inventory MODEL incorporation currently lacks the genuine POSIX
execution authority required below. The test uses the production recorder;
it must fail at that gap until the actual runtime path is corrected.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

import artifact_ledger as AL
from audit_snapshot import build_audit_snapshot
import plamen_driver as D
import test_depth_to_empty_report_same_run as REPORT
import test_depth_to_queue_same_run_semantics as DEPTH
import test_inventory_canonical_aggregate_phaseio_p0_l as INVENTORY
import test_live_verify_queue_main_boundary_a0 as QUEUE
from test_support_startup_permit import durable_startup_permit
from test_verification_report_tail_same_run_integration import _patch_compat_codex_lookup


pytestmark = [pytest.mark.integration, pytest.mark.posix_only]
PREFIX = "sc/core/evm/codex/"
SOURCE = "analysis_a.md"
MANIFEST = "inventory_chunk_a.manifest.md"
CHUNK = "findings_inventory_chunk_a.md"


def _candidate(identity: str, title: str, *, source_ids: tuple[str, ...] = ()) -> str:
    sources = f"**Source IDs**: {', '.join(source_ids)}\n" if source_ids else ""
    return (
        f"### Finding [{identity}]: {title}\n"
        "**Severity**: Low\n"
        "**Location**: src/Unit.sol:L3\n"
        "**Preferred Tag**: CODE-TRACE\n"
        + sources
        + "**Verdict**: NEEDS_VERIFICATION\n"
        "**Description**: Benign synthetic identity-accounting record. "
        "This fixture makes no real security finding or exploit assertion. "
        "The local contract only declares a public integer.\n"
        "**Root Cause**: Synthetic artifact identity retained for a software test.\n"
        "**Impact**: Omitting this record would make the fixture's candidate "
        "accounting incomplete; no harm to a deployed system is asserted.\n\n"
    )


def _workspace(tmp_path: Path):
    project = tmp_path / "synthetic-inventory-to-report"
    (project / "src").mkdir(parents=True)
    (project / "src" / "Unit.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Unit {\nuint256 public value;\n}\n",
        encoding="utf-8",
    )
    (project / "src" / "main.unit").write_bytes(b"// bounded main-boundary context\n")
    root = project / ".scratchpad"
    root.mkdir()
    run_id = QUEUE._canonical_run_id("sc")
    config = QUEUE.ADAPTER_FIXTURE._dimensions(
        pipeline="sc", backend="codex", project=project, root=root, run_id=run_id,
    )
    config["mode"] = "core"
    config["_auxiliary_writable_root_startup_binding"] = durable_startup_permit(
        root, run_id=run_id,
    )
    config["_audit_snapshot"] = build_audit_snapshot(
        config, Path(__file__).resolve().parent.parent,
    )
    (root / "config.json").write_bytes(DEPTH._json_bytes(config))
    (root / SOURCE).write_text(
        "# Synthetic accepted breadth records\n\n"
        + _candidate("A-01", "Synthetic identity one")
        + _candidate("A-02", "Synthetic identity two"),
        encoding="utf-8",
    )
    DEPTH._claim(root, project, config, (SOURCE,),
                 phase="breadth", work_unit_id="synthetic_accepted_breadth", writer="MODEL")
    INVENTORY._manifest(root, "inventory_chunk_a", (SOURCE,))
    DEPTH._claim(root, project, config, (MANIFEST,),
                 phase="inventory_prepare", work_unit_id="synthetic_manifest")
    return project, root, config


def _run_inventory_child(project, root, config, monkeypatch, request):
    """One controlled process; no direct MODEL claim or synthetic receipt."""
    import posix_v2_compat_runtime as compat

    phase = INVENTORY._phase("inventory_chunk_a")
    contract, launch = D._typed_model_phase_contract_and_launch(phase, root, config)
    assert contract is not None and launch is not None and contract.model_invoked
    assert D._bind_typed_model_phase_inputs(phase, root, config) == []
    assert set(contract.immutable_inputs) == {f"scratchpad:{SOURCE}", f"scratchpad:{MANIFEST}"}
    output = (
        "# Synthetic Inventory Chunk\n\n"
        "## Source Summary\n\n"
        "Two harmless source candidates are bound. This deterministic child "
        "emits only the first so the fixture can exercise visible missing-row "
        "debt and DRIVER recall repair for the second. No candidate is refuted.\n\n"
        "## Master Table\n\n| ID | Title |\n|---|---|\n"
        "| CC-01 | Synthetic identity one |\n\n"
        "## Per-Finding Detail\n\n"
        + _candidate("CC-01", "Synthetic identity one", source_ids=(f"{SOURCE}:A-01",))
    )
    binary = project.parent / "fixture-codex-synthetic-inventory"
    binary.write_text(
        f"#!{sys.executable} -B\n"
        "import hashlib,json,re,sys\nfrom pathlib import Path\n"
        "if sys.argv[1:]==['--version']:\n"
        " print('codex-cli synthetic-inventory-fixture'); raise SystemExit(0)\n"
        "prompt=sys.stdin.read()\n"
        f"sys.stderr.write('OpenAI Codex v0.test\\n--------\\nworkdir: /fixture\\nmodel: {launch.model}\\nprovider: openai\\n--------\\nuser\\n')\n"
        "_request,sep,transport=prompt.partition('\\n# PROVIDER-EFFECTIVE LOCAL PHASEIO ROUTING\\n')\n"
        "assert sep\n"
        "blocks=[json.loads(b) for b in re.findall(r'```json\\s*(.*?)\\s*```',transport,re.S)]\n"
        "routing=next(b for b in blocks if b.get('schema')=='plamen.posix_v2_codex_local_phaseio.v1')\n"
        "bound={}\n"
        "for route in routing['input_routes']:\n"
        " raw=Path(route['path']).read_bytes()\n"
        " assert len(raw)==route['size'] and hashlib.sha256(raw).hexdigest()==route['sha256']\n"
        " assert route['identity'] not in bound\n"
        " bound[route['identity']]=raw\n"
        f"assert set(bound)=={{'scratchpad:{SOURCE}','scratchpad:{MANIFEST}'}}\n"
        "routes=routing['output_routes']\n"
        f"assert len(routes)==1 and routes[0]['identity']=='scratchpad:{CHUNK}'\n"
        f"Path(routes[0]['path']).write_text({output!r},encoding='utf-8')\n"
        "Path(sys.argv[sys.argv.index('-o')+1]).write_text('complete\\n')\n"
        "print(json.dumps({'type':'turn.completed'}))\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id=config["_run_id"], project_root=project, scratchpad=root,
    )
    session_closed = False

    def close_inventory_session():
        # The runtime close is intentionally not idempotent. Close before the
        # report child gets its own authority, retaining failure-safe cleanup.
        nonlocal session_closed
        if not session_closed:
            session.close()
            session_closed = True

    request.addfinalizer(close_inventory_session)
    with monkeypatch.context() as child_patch:
        child_patch.setattr(D, "_POSIX_COMPAT_V2_PROCESS_MARKER", D._POSIX_COMPAT_V2_MARKER_TOKEN)
        child_patch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)
        _patch_compat_codex_lookup(child_patch, binary)
        child_patch.setattr(compat, "_load_ambient_codex_auth",
                            lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "c" * 64))
        assert D._run_one_codex_exec(
            prompt="Render only the bound harmless synthetic inventory fixture.\n",
            phase=phase, config=config, scratchpad=root, attempt=1,
            label=phase.name, expected_outputs=[spec.path for spec in contract.outputs],
            timeout=float(launch.timeout_s), effective_model=launch.model,
            phase_io_contract=contract, phase_io_launch=launch,
        ) == 0
    assert (root / CHUNK).read_text(encoding="utf-8") == output
    # Exercise the actual parent-boundary validation and recorder. An omitted
    # source must remain observable debt before any DRIVER restoration; MODEL
    # execution and completeness of its candidate projection are distinct.
    chunk_issues = D._validate_inventory_chunk_structure(root, phase.name)
    assert len(chunk_issues) == 1 and (
        "inventory chunk exact reconciliation:" in chunk_issues[0]
        and "analysis_a.md:A-02 -> UNMATCHED" in chunk_issues[0]
    ), chunk_issues
    chunk_state = D._reconcile_exact_inventory(root, phase_name=phase.name, persist=False)
    assert {row["source_finding_id"]: row["disposition"] for row in chunk_state["candidates"]} == {
        "A-01": "RETAINED", "A-02": "HUMAN_REVIEW_DEBT",
    }
    # Production also records genuinely executed MODEL bytes on this content
    # gate failure. That is not a clean inventory phase completion claim.
    assert D._record_typed_model_phase_artifacts(phase, root, config) == []
    unit = AL.read_artifact_ledger(root)["work_units"][contract.key]
    assert unit["semantic_status"] == "ACTIVE" and unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit.get("execution_authority"), "inventory MODEL commit lacks genuine child execution authority"
    assert unit["execution_authority"] == unit["commit_authority"]["execution_authority"]
    assert AL.validate_work_unit_artifacts(root, project, contract, launch,
                                         run_id=config["_run_id"], actor="MODEL") == []
    close_inventory_session()
    return contract.key, deepcopy(unit)


def test_controlled_inventory_child_reaches_same_run_policy_empty_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request,
):
    if os.name != "posix":
        pytest.skip("controlled local children require POSIX compatibility")
    project, root, config = _workspace(tmp_path)
    run_id = config["_run_id"]
    source_bytes = (root / SOURCE).read_bytes()
    model_key, model_unit = _run_inventory_child(project, root, config, monkeypatch, request)
    chunk_bytes = (root / CHUNK).read_bytes()

    assert D._record_inventory_reconciliation_phase_io_named(
        scratchpad=root, config=config, phase_name="inventory_chunk_a", timeout_s=60,
    ) == []
    reconciliation_key = PREFIX + "inventory_chunk_a/exact_reconciliation"
    reconciliation = AL.read_artifact_ledger(root)["work_units"][reconciliation_key]
    DEPTH._assert_consumes(reconciliation, CHUNK, model_key, model_unit, chunk_bytes, run_id)
    result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=root, config=config, phase=INVENTORY._phase("inventory"),
        derivation_kind="single_shard",
    )
    assert issues == [] and result["finding_count"] == 1
    prestate = D._reconcile_exact_inventory(root, persist=False)
    assert {row["source_finding_id"]: row["disposition"] for row in prestate["candidates"]} == {
        "A-01": "RETAINED", "A-02": "HUMAN_REVIEW_DEBT",
    }
    assert D._record_inventory_reemit_phase_io(
        scratchpad=root, project_root=project, config=config, run_id=run_id,
    ) == []
    assert D._record_inventory_reconciliation_phase_io(
        scratchpad=root, config=config, phase=INVENTORY._phase("inventory"),
    ) == []
    ids = INVENTORY._projected_inventory_ids(root)
    assert all(values == {"INV-001", "INV-002"} for values in ids)
    ledger = AL.read_artifact_ledger(root)
    for name in DEPTH.CANONICAL:
        assert ledger["artifact_bindings"][f"scratchpad:{name}"]["owner_key"] == DEPTH.SEED_KEY
    reemit = ledger["work_units"][DEPTH.SEED_KEY]
    assert reemit["semantic_status"] == "ACTIVE" and reemit["execution_state"] == "OUTPUT_COMMITTED"
    assert ledger["work_units"][model_key] == model_unit

    # Accepted depth is still a named fixture boundary, not an executed worker.
    (root / "niche_runtime_findings.md").write_text(
        DEPTH._candidate("SC-61", "Synthetic accepted depth addition", 3), encoding="utf-8",
    )
    DEPTH._claim(root, project, config, ("niche_runtime_findings.md",),
                 phase="depth", work_unit_id="synthetic_accepted_niche", writer="MODEL")
    frozen_inventory_units = deepcopy(AL.read_artifact_ledger(root)["work_units"])
    invocations = []

    def existing_inventory_only(requested_path):
        assert requested_path == tmp_path
        invocations.append(requested_path)
        assert len(invocations) == 1
        assert AL.read_artifact_ledger(root)["work_units"][DEPTH.SEED_KEY] == reemit
        return project, root, config

    # Reuse the existing continuation by replacing its test-only initial-input
    # factory. No runtime function, authority gate, worker result, or canonical
    # output is substituted. In particular QUEUE._seed is never called.
    with monkeypatch.context() as continuation_patch:
        continuation_patch.setattr(DEPTH, "_seed_initial_inputs", existing_inventory_only)
        REPORT.test_accepted_depth_identity_retains_same_run_authority_through_empty_report(
            tmp_path, continuation_patch, request,
        )
    assert invocations == [tmp_path]
    final = AL.read_artifact_ledger(root)
    assert all(final["work_units"][key] == unit for key, unit in frozen_inventory_units.items())
    assert (root / SOURCE).read_bytes() == source_bytes
    assert (root / CHUNK).read_bytes() == chunk_bytes
    assert final["work_units"][model_key]["artifacts"][f"scratchpad:{CHUNK}"]["sha256"] == hashlib.sha256(chunk_bytes).hexdigest()
    excluded = json.loads((root / "verification_queue_evidence_excluded.json").read_text())["rows"]
    assert sorted(row["finding id"] for row in excluded) == ["INV-001", "INV-002", "INV-003"]
    assert all(row["severity"] == "Low" for row in excluded)
    checkpoint = D.Checkpoint.load(root)
    assert checkpoint.run_id == run_id
    assert "report_assemble" in checkpoint.completed
    assert not {"recon", "breadth", "depth", "report_floor"} & set(checkpoint.completed)
    assert (project / "AUDIT_REPORT.md").is_file()
