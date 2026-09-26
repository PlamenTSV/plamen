"""Accepted synthetic depth additions reach the real same-run queue boundary.

This starts at the accepted-output seam, not provider execution. Initial input
producers are explicit fixtures; additive finalization, prequeue successors,
publication authentication, and missing-source lifecycle debt are production
operations. No audit, provider, exploit, or report worker is executed.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

import artifact_ledger as AL
from audit_snapshot import build_audit_snapshot
from finding_producer_registry import write_application_skeptic_proposal_projection
import plamen_driver as D
import plamen_validators as V
import security_obligation_lifecycle as LIFECYCLE
import test_live_verify_queue_main_boundary_a0 as QUEUE
from test_support_startup_permit import durable_startup_permit
from verify_queue_transaction import validate_live_verify_queue_publication


pytestmark = pytest.mark.integration
PREFIX = "sc/core/evm/codex/"
SEED_KEY = PREFIX + "inventory/additive_reemit"
SOURCE_KEY = PREFIX + "depth/synthetic_accepted_niche"
CAPTURE_KEY = PREFIX + "inventory/additive_depth_finalize.source_capture"
SUCCESSOR_KEY = PREFIX + "inventory/additive_depth_finalize"
CANONICAL = tuple(D._DEPTH_ADDITIVE_CANONICAL)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def _bytes(root: Path, names: tuple[str, ...]) -> dict[str, bytes]:
    return {name: (root / name).read_bytes() for name in names}


def _candidate(identity: str, title: str, line: int) -> str:
    return (
        f"### Finding [{identity}]: {title}\n"
        f"**Source IDs**: [{identity}]\n"
        "**Severity**: Low\n"
        f"**Location**: src/Unit.sol:L{line}\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Primary Artifact**: niche_runtime_findings.md\n"
        "**Description**: Harmless synthetic candidate used only to track "
        "identity preservation across deterministic artifact transitions. "
        "No real vulnerability or executable reproduction is asserted.\n"
        "**Impact**: Losing this fixture identity would make the test's "
        "candidate accounting incomplete.\n\n"
    )


def _claim(root: Path, project: Path, config: dict, paths: tuple[str, ...],
           *, phase: str, work_unit_id: str, writer: str = "DRIVER") -> None:
    # This helper is used only for initial inputs, never a successor postimage.
    QUEUE.ADAPTER_FIXTURE._claim_group(
        root=root, project=project, config=config, run_id=config["_run_id"],
        paths=paths, phase=phase, work_unit_id=work_unit_id, writer=writer,
    )


def _seed_initial_inputs(tmp_path: Path) -> tuple[Path, Path, dict]:
    project = tmp_path / "synthetic-depth-to-queue"
    (project / "src").mkdir(parents=True)
    (project / "src" / "Unit.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Unit {\nuint256 public value;\n}\n",
        encoding="utf-8",
    )
    # All project context exists before the real snapshot is taken.
    (project / "src" / "main.unit").write_bytes(
        b"// bounded main-boundary context\n"
    )
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
    (root / "config.json").write_bytes(_json_bytes(config))

    initial = (("INV-001", "Synthetic seed one"),
               ("INV-002", "Synthetic seed two"))
    raw = ("# Findings Inventory\n\n" + "".join(
        _candidate(identity, title, line)
        for line, (identity, title) in enumerate(initial, 1)
    )).encode()
    (root / "findings_inventory.md").write_bytes(raw)
    (root / "finding_records.json").write_bytes(
        D.derive_preverify_finding_records_bytes(raw)
    )
    (root / "_id_ledger.json").write_bytes(_json_bytes({
        "schema_version": "plamen.id_ledger.v1",
        "allocations": [
            {"id": identity, "prefix": "INV-", "owner_phase": "inventory",
             "owner_attempt": 1, "owning_artifact": "findings_inventory.md",
             "title_hash": D._title_hash(title), "title_preview": title,
             "allocated_at": "1970-01-01T00:00:00+00:00"}
            for identity, title in initial
        ],
    }))
    _claim(root, project, config, CANONICAL,
           phase="inventory", work_unit_id="additive_reemit")
    (root / "niche_runtime_findings.md").write_text(
        _candidate("SC-61", "Synthetic accepted depth addition", 3),
        encoding="utf-8",
    )
    _claim(root, project, config, ("niche_runtime_findings.md",),
           phase="depth", work_unit_id="synthetic_accepted_niche", writer="MODEL")
    return project, root, config


def _seed_queue_context(root: Path, project: Path, config: dict,
                        actual_ids: tuple[str, ...]) -> None:
    """Add initial context only; canonical/depth generations are off limits."""
    roster = set(QUEUE.LIVE._base_upstream_inputs("sc"))
    produced_later = {
        "preverify_inventory_successor.json", "finding_delivery_successor.json",
        "live_verify_queue_methodology_projection.receipt.json",
    }
    absent = ({QUEUE.SECURITY_OBLIGATION_AUTHORITY_FILE}
              | QUEUE.P1M_OPTIONAL_OUTPUTS | QUEUE.CHAIN_GROUPING_OPTIONAL_OUTPUTS)
    context_names = roster - produced_later - absent
    protected = set(CANONICAL) | {
        D._DEPTH_ADDITIVE_SOURCE_MANIFEST, D._DEPTH_ADDITIVE_FINALIZATION,
        D._DEPTH_ADDITIVE_DEBT, "niche_runtime_findings.md",
    }
    assert not context_names & protected
    assert all(not (root / name).exists() for name in context_names)
    write_application_skeptic_proposal_projection(root, [])
    write_application_skeptic_proposal_projection(
        root, [], projection_name="candidate_negative_skeptic_proposals.md",
    )
    for name in sorted(context_names):
        path = root / name
        if not path.exists():
            path.write_bytes(
                b"# Synthetic current-run context\n" if path.suffix == ".md"
                else _json_bytes({"artifact": name})
            )
    _claim(root, project, config, tuple(sorted(context_names)),
           phase="preverify_adapter_fixture", work_unit_id="current_run_upstream")
    (root / "caller_map.md").write_bytes(_json_bytes({"artifact": "caller_map.md"}))
    (root / "inventory_evidence_validation.md").write_bytes(
        b"# Inventory Evidence Validation\n\n"
    )
    _claim(root, project, config, ("inventory_evidence_validation.md",),
           phase="preverify_adapter_fixture", work_unit_id="initial_evidence")

    # Publish the initial MODEL chain trio once, from the actual allocator IDs.
    # Never reuse QUEUE._seed: it replaces/reclaims the canonical inventory.
    assert all(not (root / name).exists() for name in
               ("hypotheses.md", "finding_mapping.md", "enabler_results.md"))
    (root / "hypotheses.md").write_text(
        "# Hypotheses\n\n"
        "| Hypothesis ID | Severity | Title | Constituent Findings |\n"
        "|---|---|---|---|\n"
        f"| H-1 | Low | Synthetic grouping only | {', '.join(actual_ids)} |\n",
        encoding="utf-8",
    )
    (root / "finding_mapping.md").write_text(
        "# Finding Mapping\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|---|---|---|\n" + "".join(
            f"| {identity} | H-1 | GROUPED |\n" for identity in actual_ids
        ), encoding="utf-8",
    )
    (root / "enabler_results.md").write_text("# Enabler Results\n\n", encoding="utf-8")
    QUEUE._claim_chain_model_pair(
        root=root, project=project, config=config, run_id=config["_run_id"],
    )


def _assert_consumes(unit: dict, name: str, producer_key: str,
                     producer: dict, raw: bytes, run_id: str) -> None:
    binding = unit["input_bindings"]["scratchpad:" + name]
    assert binding["producer_work_unit_key"] == producer_key
    assert binding["producer_run_id"] == run_id
    assert binding["producer_contract_digest"] == producer["contract_digest"]
    assert binding["producer_launch_digest"] == producer["launch_digest"]
    assert binding["producer_commit_receipt_digest"] == producer["commit_authority"]["receipt_digest"]
    assert binding["sha256"] == hashlib.sha256(raw).hexdigest()
    assert binding["size"] == len(raw)


def test_accepted_depth_identity_reaches_authenticated_same_run_core_queue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_execution(*_args, **_kwargs):
        pytest.fail("synthetic composition must not execute a provider or audit phase")

    monkeypatch.setattr(D, "_run_one_codex_exec", no_execution)
    monkeypatch.setattr(D, "run_phase", no_execution)
    project, root, config = _seed_initial_inputs(tmp_path)
    run_id = config["_run_id"]
    before = _bytes(root, CANONICAL)
    initial_units = deepcopy(AL.read_artifact_ledger(root)["work_units"])
    result = D._run_accepted_depth_postprocessors(
        "depth", root, accepted=True, recovery_preflight=False, config=config,
    )
    assert result["added_inventory_ids"] == ["INV-003"], result
    assert "transaction" not in result.get("failed_processors", []), result
    after = _bytes(root, CANONICAL)
    ids = D._depth_additive_identity_set("findings_inventory.md", after["findings_inventory.md"])
    assert ids == ("INV-001", "INV-002", "INV-003")
    for name in CANONICAL:
        assert D._depth_additive_identity_set(name, after[name]) == ids
    assert b"SC-61" in after["findings_inventory.md"]

    ledger = AL.read_artifact_ledger(root)
    capture = ledger["work_units"][CAPTURE_KEY]
    successor = ledger["work_units"][SUCCESSOR_KEY]
    assert successor["semantic_status"] == "ACTIVE"
    assert successor["execution_state"] == "OUTPUT_COMMITTED"
    assert successor["commit_authority"]["actor"] == "DRIVER"
    for name in CANONICAL:
        _assert_consumes(capture, name, SEED_KEY, initial_units[SEED_KEY], before[name], run_id)
        binding = ledger["artifact_bindings"]["scratchpad:" + name]
        assert binding["owner_key"] == SUCCESSOR_KEY and binding["status"] == "ACTIVE"
        assert binding["sha256"] == hashlib.sha256(after[name]).hexdigest()
        assert successor["output_prestates"]["scratchpad:" + name]["predecessor_owner_key"] == SEED_KEY
    _assert_consumes(capture, "niche_runtime_findings.md", SOURCE_KEY,
                     initial_units[SOURCE_KEY], (root / "niche_runtime_findings.md").read_bytes(), run_id)
    _assert_consumes(successor, D._DEPTH_ADDITIVE_SOURCE_MANIFEST,
                     CAPTURE_KEY, capture, (root / D._DEPTH_ADDITIVE_SOURCE_MANIFEST).read_bytes(), run_id)
    retained_units = {**initial_units, CAPTURE_KEY: deepcopy(capture),
                      SUCCESSOR_KEY: deepcopy(successor)}
    retained_files = _bytes(root, (*CANONICAL, D._DEPTH_ADDITIVE_SOURCE_MANIFEST,
                                  D._DEPTH_ADDITIVE_FINALIZATION, D._DEPTH_ADDITIVE_DEBT))

    _seed_queue_context(root, project, config, ids)
    assert _bytes(root, tuple(retained_files)) == retained_files
    assert all(AL.read_artifact_ledger(root)["work_units"][key] == unit
               for key, unit in retained_units.items())
    dependency = D._ensure_recon_dependency_parity(root, str(project), config)
    assert dependency["expected_ids"] == []
    assert D._run_sc_semantic_dedup_noop(root, config, "synthetic preserve-all") == [
        "dedup_decisions.md", "findings_inventory_deduped.md",
    ]
    assert (root / "findings_inventory_deduped.md").read_bytes() == after["findings_inventory.md"]
    phase, phases = QUEUE._phase_and_graph("sc")
    checkpoint = QUEUE._checkpoint(root, config, run_id)
    outcome = QUEUE._invoke(boundary=QUEUE._boundary(), phase=phase,
                            checkpoint=checkpoint, root=root, config=config, phases=phases)
    assert outcome["state"] == "COMMITTED" and outcome["safe_to_continue"], outcome
    plan = outcome["cutover_result"]["plan"]
    assert validate_live_verify_queue_publication(
        scratchpad=root, project_root=project, plan=plan, run_id=run_id,
    )["safe_to_consume"] is True
    active = V.parse_verification_queue_rows(root)
    excluded = json.loads((root / "verification_queue_evidence_excluded.json").read_text())["rows"]
    denominator = [row["finding id"] for row in (*active, *excluded)]
    assert sorted(denominator) == list(ids) and len(set(denominator)) == len(ids)
    assert active == []
    assert all(row["severity"] == "Low" and row["exclusion reason"] == "AUTHORIZED_EXCLUDED"
               for row in excluded)

    final = json.loads((root / "preverify_inventory_successor.json").read_text())
    delivery = json.loads((root / "finding_delivery_successor.json").read_text())
    assert final["run_id"] == delivery["run_id"] == run_id
    assert delivery["final_inventory_receipt_digest"] == final["receipt_digest"]
    assert final["inventory_sha256"] == hashlib.sha256(after["findings_inventory.md"]).hexdigest()
    ledger = AL.read_artifact_ledger(root)
    for name in ("preverify_inventory_successor.json", "finding_delivery_successor.json"):
        binding = ledger["artifact_bindings"]["scratchpad:" + name]
        assert binding["owner_key"] == PREFIX + "sc_verify_queue/preverify_successors"
        assert binding["run_id"] == run_id and binding["status"] == "ACTIVE"
    # Exact downstream input receipts must still point to the accepted depth
    # generation, not a fixture re-claim of the same bytes.
    consumers = [unit for key, unit in ledger["work_units"].items()
                 if "/sc_verify_queue/" in key and
                 unit.get("input_bindings", {}).get("scratchpad:findings_inventory.md", {}).get(
                     "producer_work_unit_key") == SUCCESSOR_KEY]
    assert consumers
    for unit in consumers:
        _assert_consumes(unit, "findings_inventory.md", SUCCESSOR_KEY,
                         successor, after["findings_inventory.md"], run_id)
    assert _bytes(root, tuple(retained_files)) == retained_files
    assert all(ledger["work_units"][key] == unit for key, unit in retained_units.items())

    # An accepted additive candidate does not invent security-obligation
    # authority. Keep the actual missing-source lifecycle debt observable.
    assert not (root / QUEUE.SECURITY_OBLIGATION_AUTHORITY_FILE).exists()
    assert D._record_security_obligation_lifecycle_phase_io(root, config) == [
        "security-obligation lifecycle retained unresolved/debt aliases for human review"
    ]
    assert D._validate_security_obligation_lifecycle_phase_io(root, config) == []
    debt = json.loads((root / LIFECYCLE.AUTHORITY_FILE).read_text())
    assert debt["run_id"] == run_id and debt["status"] == "DEGRADED_HUMAN_REVIEW"
    assert debt["denominator_complete"] is False
    assert debt["source_authority_digest"] is None and debt["rows"] == []
    assert debt["issues"] == ["security_authority: missing, malformed, or digest-mismatched"]
    assert not (root / "report_index.md").exists()
    assert not (root / "AUDIT_REPORT.md").exists()
