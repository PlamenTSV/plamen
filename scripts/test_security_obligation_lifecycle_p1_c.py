"""Exact post-depth security-obligation lifecycle authority fixtures."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import security_obligation_authority as SO
import security_obligation_lifecycle as L
from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from mandatory_reverification import (
    ASSIGNMENT_FILE,
    COMPLETION_FILE,
    DENOMINATOR_FILE,
    ROUTING_FILE,
    bind_mandatory_reverification_assignments,
    build_mandatory_reverification_denominator,
    reconcile_mandatory_reverification_completion,
    route_mandatory_reverification,
)
from queue_work_items import (
    LineageLink,
    LocationRecord,
    QueueWorkItem,
    QueueWorkPlan,
    SeverityProposal,
    VerifierOutputIdentity,
    VerifierOutputReceipt,
    build_queue_work_plan,
    queue_records_to_json,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from mechanical_successor_receipts import apply_mechanical_successor
from verifier_work_roster import (
    VerifierLaunchSpec,
    VerifierUnitReceipt,
    VerifierWorkRoster,
    build_verifier_launch_spec,
    build_verifier_runtime_policy,
    build_verifier_work_roster,
)


RUN_ID = "12345678-1234-4234-9234-123456789abc"
SNAPSHOT = "a" * 64


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _proposal(item: QueueWorkItem) -> bytes:
    constituents = [item.work_item_id, *item.constituents]
    value = {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": item.work_item_id,
        "constituent_ids": constituents,
        "impact": {
            "class": "Medium",
            "harmed_asset": "protected asset",
            "harmed_capability": "asset integrity",
            "premise_id": f"PREM-{item.work_item_id}-IMPACT",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-{item.work_item_id}-IMPACT"],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "likelihood": {
            "class": "Medium",
            "actor": "unprivileged actor",
            "preconditions": ["reachable state"],
            "premise_id": f"PREM-{item.work_item_id}-LIKELIHOOD",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-{item.work_item_id}-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "modifiers": [],
        "proposed_severity": "Medium",
        "adjustment": None,
        "constituent_premise_outcomes": {
            value: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
            for value in constituents
        },
    }
    return json.dumps(value, sort_keys=True).encode("utf-8")


def _security_denominator(root: Path, *, count: int = 2) -> list[str]:
    checkpoint = {
        "completed": ["recon"],
        "degraded": [],
        "rate_limited_at": None,
        "run_id": RUN_ID,
        "config": {"pipeline": "sc", "language": "evm", "mode": "thorough"},
        "audit_snapshot": {
            "schema": "plamen.audit-input-snapshot.v1",
            "snapshot_digest": SNAPSHOT,
            "components": {"source_scope": {"digest": "b" * 64}},
        },
    }
    _json(root / "_v2_checkpoint.json", checkpoint)
    functions = {
        f"vault{index}::native_wcoin_approve": {
            "bare": "native_wcoin_approve",
            "loc": f"src/Vault.sol:L{10 + index}",
            "callers": [],
            "callees": [],
        }
        for index in range(1, count + 1)
    }
    _json(
        root / "_mechanical_graph.json",
        {
            "schema_version": "plamen.mechanical-graph.v2",
            "source": "evm-source",
            "functions": functions,
            "var_refs": {},
            "state_symbols": [],
        },
    )
    authority = SO.write_security_obligation_authority(root)
    aliases = sorted(
        str(alias["alias_id"])
        for obligation in authority["obligations"]
        if obligation["rule_id"] == "security.wrapped_asset_classification.v1"
        for alias in obligation["trigger_aliases"]
    )
    assert len(aliases) == count
    assert SO.validate_security_obligation_authority(root) == []
    return aliases


def _item(work_id: str, aliases: tuple[str, ...]) -> QueueWorkItem:
    return QueueWorkItem(
        candidate_identity=work_id,
        work_item_id=work_id,
        lineage=(
            LineageLink(
                identity=work_id,
                relation="ORIGIN",
                source_artifact="security_obligation_authority.json",
            ),
            *(LineageLink(
                identity=alias,
                relation="ALIAS",
                source_artifact="security_obligation_authority.json",
            ) for alias in aliases),
        ),
        aliases=aliases,
        constituents=(),
        severity_proposal=SeverityProposal(
            level="Medium",
            impact="Medium",
            likelihood="Medium",
            rationale="Fixture proposal retained for independent verification.",
        ),
        evidence_class="code-trace",
        bug_class="security-obligation",
        preferred_tag="CODE-TRACE",
        queue_priority=1,
        location_records=(
            LocationRecord(
                artifact="src/Vault.sol", start_line=10, end_line=12, symbol="review"
            ),
        ),
        primary_artifacts=("security_obligation_authority.json",),
        poc_class="unit",
        title="Exact security obligation candidate",
    )


def _write_runtime(root: Path, items: list[QueueWorkItem], *, verdict: str) -> None:
    (root / "verification_queue.md").write_text(
        "# Verification queue\n", encoding="utf-8"
    )
    (root / "verification_queue.work_items.json").write_text(
        queue_records_to_json(items) + "\n", encoding="utf-8"
    )
    plan = build_queue_work_plan(
        items,
        {"verify_medium_a": [item.work_item_id for item in items]},
        planner_version="plamen.lifecycle-fixture.v1",
    )
    (root / "verification_queue.work_plan.json").write_text(
        plan.to_json() + "\n", encoding="utf-8"
    )
    policy = build_verifier_runtime_policy(
        backend="claude",
        model="claude-opus-4-8",
        transport="pty",
        timeout_seconds=300,
        max_concurrency=2,
        source_root=str(root.parent.resolve()),
    )
    roster = build_verifier_work_roster(
        plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=policy,
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    (root / "verification_runtime_roster.json").write_text(
        roster.to_json() + "\n", encoding="utf-8"
    )
    for unit in roster.work_units:
        unit_dir = root / "_verifier_runtime_units" / unit.work_unit_id
        unit_dir.mkdir(parents=True, exist_ok=True)
        prompt = f"fixture prompt for {unit.work_unit_id}\n".encode()
        spec = build_verifier_launch_spec(roster, unit.work_unit_id, prompt_bytes=prompt)
        (unit_dir / "prompt.md").write_bytes(prompt)
        (unit_dir / "launch_spec.json").write_text(
            spec.to_json() + "\n", encoding="utf-8"
        )
        for work_id in unit.ordered_work_item_ids:
            item = next(item for item in items if item.work_item_id == work_id)
            output = (
                f"# {work_id}\n\n**Verdict**: {verdict}\n"
                "**Severity**: Medium\n\nExact independent review with enough "
                "typed evidence to satisfy the production completion floor. "
                "The fixture binds these exact bytes through PhaseIO.\n"
            ).encode()
            proposal = _proposal(item)
            (root / item.expected_output_file).write_bytes(output)
            (root / f"verify_{work_id}.severity_proposal.json").write_bytes(proposal)
            shard_id = next(
                shard.shard_id
                for shard in plan.shards
                if work_id in shard.ordered_work_item_ids
            )
            identity = VerifierOutputIdentity.for_assignment(item, plan, shard_id)
            receipt = VerifierOutputReceipt.bind(
                identity,
                output,
                severity_proposal=proposal,
                launch_digest=spec.digest,
                verifier_backend=spec.backend,
            )
            _json(root / f"verify_{work_id}.identity.json", identity.to_dict())
            (root / f"verify_{work_id}.receipt.json").write_text(
                receipt.to_json(), encoding="utf-8"
            )
        dispatch = {
            "schema_version": "plamen.fixture.verifier_dispatch.v1",
            "dispatch_id": f"DISPATCH-{unit.work_unit_id}",
        }
        _json(unit_dir / "method_dispatch.json", dispatch)
        operator_digests = []
        for work_id in unit.ordered_work_item_ids:
            operator_path = root / f"verify_{work_id}.operator_receipt.json"
            _json(operator_path, {"fixture": "operator", "work_item_id": work_id})
            operator_digests.append(_sha(operator_path.read_bytes()))
        gate = unit_dir / "gate_receipt.json"
        _json(
            gate,
            {
                "schema_version": "plamen.verifier_unit_gate_receipt.v1",
                "state": "CLEAN",
                "work_unit_id": unit.work_unit_id,
                "work_unit_resume_digest": unit.resume_digest,
                "roster_digest": roster.digest,
                "launch_spec_digest": spec.digest,
                "method_dispatch_id": dispatch["dispatch_id"],
                "method_dispatch_sha256": _sha(
                    (unit_dir / "method_dispatch.json").read_bytes()
                ),
                "ordered_work_item_ids": list(unit.ordered_work_item_ids),
                "operator_receipt_digests": operator_digests,
                "output_sha256": {
                    name: _sha((root / name).read_bytes())
                    for name in unit.expected_output_files
                },
            },
        )
        unit_receipt = VerifierUnitReceipt.completed_for(
            unit,
            launch_spec_digest=spec.digest,
            output_receipt_digests=[
                _sha((root / f"verify_{work_id}.receipt.json").read_bytes())
                for work_id in unit.ordered_work_item_ids
            ],
            gate_receipt_digests=[_sha(gate.read_bytes())],
        )
        (unit_dir / "unit_receipt.json").write_text(
            unit_receipt.to_json() + "\n", encoding="utf-8"
        )
        shard_id = next(
            shard.shard_id
            for shard in plan.shards
            if unit.ordered_work_item_ids[0] in shard.ordered_work_item_ids
        )
        common = {
            "pipeline": "sc",
            "mode": "thorough",
            "ecosystem": "evm",
            "backend": "claude",
            "phase": shard_id,
        }
        prelaunch_contract = resolve_phase_io_contract(
            **common,
            work_unit_id=f"method_context.{unit.work_unit_id}",
            exact_inputs=(),
            exact_outputs=(
                f"_verifier_runtime_units/{unit.work_unit_id}/prompt.md",
                f"_verifier_runtime_units/{unit.work_unit_id}/launch_spec.json",
                f"_verifier_runtime_units/{unit.work_unit_id}/method_dispatch.json",
            ),
            exact_writer="DRIVER",
        )
        prelaunch_launch = LaunchSpec(
            work_unit_key=prelaunch_contract.key,
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            model="driver",
            timeout_s=300,
            exec_mode="python",
            tool_policy=("filesystem",),
        )
        # Mirror the production driver transaction: bind the complete output
        # prestate before the deterministic producer materializes any byte.
        prelaunch_output_bytes = {
            root / name: (root / name).read_bytes()
            for name in (
                f"_verifier_runtime_units/{unit.work_unit_id}/prompt.md",
                f"_verifier_runtime_units/{unit.work_unit_id}/launch_spec.json",
                f"_verifier_runtime_units/{unit.work_unit_id}/method_dispatch.json",
            )
        }
        for path in prelaunch_output_bytes:
            path.unlink()
        record_work_unit_inputs(
            root, root.parent, prelaunch_contract, prelaunch_launch, run_id=RUN_ID
        )
        for path, raw in prelaunch_output_bytes.items():
            path.write_bytes(raw)
        record_work_unit_artifacts(
            root,
            root.parent,
            prelaunch_contract,
            prelaunch_launch,
            run_id=RUN_ID,
            actor="DRIVER",
        )
        model_contract = resolve_phase_io_contract(
            **common,
            work_unit_id=f"method_model.{unit.work_unit_id}",
            exact_inputs=(
                "verification_queue.work_items.json",
                f"_verifier_runtime_units/{unit.work_unit_id}/prompt.md",
                f"_verifier_runtime_units/{unit.work_unit_id}/launch_spec.json",
                f"_verifier_runtime_units/{unit.work_unit_id}/method_dispatch.json",
            ),
            exact_outputs=tuple(
                next(item for item in items if item.work_item_id == work_id)
                .expected_output_file
                for work_id in unit.ordered_work_item_ids
            ),
        )
        model_launch = LaunchSpec(
            work_unit_key=model_contract.key,
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            model="claude-opus-4-8",
            timeout_s=300,
            exec_mode="pty",
            tool_policy=("filesystem", "shell", "foreground-only"),
        )
        # Preserve fixture bytes while replaying the production ordering: the
        # model denominator is bound before any verifier output is written.
        model_output_bytes = {
            root / name: (root / name).read_bytes()
            for name in unit.expected_output_files
        }
        for path in model_output_bytes:
            path.unlink()
        record_work_unit_inputs(
            root, root.parent, model_contract, model_launch, run_id=RUN_ID
        )
        for path, raw in model_output_bytes.items():
            path.write_bytes(raw)
        record_work_unit_artifacts(
            root,
            root.parent,
            model_contract,
            model_launch,
            run_id=RUN_ID,
            actor="MODEL",
        )
        control_contract = resolve_phase_io_contract(
            **common,
            work_unit_id=f"method_receipt.{unit.work_unit_id}",
            exact_inputs=tuple(
                next(item for item in items if item.work_item_id == work_id)
                .expected_output_file
                for work_id in unit.ordered_work_item_ids
            ),
            exact_outputs=(
                f"_verifier_runtime_units/{unit.work_unit_id}/gate_receipt.json",
                f"_verifier_runtime_units/{unit.work_unit_id}/unit_receipt.json",
                *(
                    f"verify_{work_id}.operator_receipt.json"
                    for work_id in unit.ordered_work_item_ids
                ),
            ),
            exact_writer="DRIVER",
        )
        control_launch = LaunchSpec(
            work_unit_key=control_contract.key,
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            model="driver",
            timeout_s=300,
            exec_mode="python",
            tool_policy=("filesystem",),
        )
        control_output_paths = (
            unit_dir / "gate_receipt.json",
            unit_dir / "unit_receipt.json",
            *(
                root / f"verify_{work_id}.operator_receipt.json"
                for work_id in unit.ordered_work_item_ids
            ),
        )
        control_output_bytes = {
            path: path.read_bytes() for path in control_output_paths
        }
        for path in control_output_bytes:
            path.unlink()
        record_work_unit_inputs(
            root, root.parent, control_contract, control_launch, run_id=RUN_ID
        )
        for path, raw in control_output_bytes.items():
            path.write_bytes(raw)
        record_work_unit_artifacts(
            root,
            root.parent,
            control_contract,
            control_launch,
            run_id=RUN_ID,
            actor="DRIVER",
        )
        ledger = read_artifact_ledger(root)
        for contract in (
            prelaunch_contract,
            model_contract,
            control_contract,
        ):
            recorded = ledger["work_units"][contract.key]
            assert recorded["semantic_status"] == "ACTIVE"
            assert recorded["execution_state"] == "OUTPUT_COMMITTED"
            for output in contract.outputs:
                binding = ledger["artifact_bindings"][output.identity]
                assert binding["status"] == "ACTIVE"
                assert binding["owner_key"] == contract.key


def _write_mandatory_chain(
    root: Path,
    aliases: list[str],
    *,
    verdict: str,
    shared_work_item: bool = False,
    include_completion: bool = True,
    work_ids: list[str] | None = None,
) -> list[QueueWorkItem]:
    authority_path = root / SO.AUTHORITY_FILE
    candidates = []
    selected_ids = work_ids or [f"INV-{index:03d}" for index in range(1, len(aliases) + 1)]
    assert len(selected_ids) == len(aliases)
    for index, alias in enumerate(aliases, 1):
        work_id = selected_ids[0] if shared_work_item else selected_ids[index - 1]
        candidates.append(
            {
                "obligation_kind": "RECOVERY_INDEPENDENT_VERIFICATION",
                "candidate_id": work_id,
                "source_candidate_id": work_id,
                "source_artifact": SO.AUTHORITY_FILE,
                "source_artifact_sha256": _sha(authority_path.read_bytes()),
                "source_proposal_id": f"PROP-{index:03d}",
                "source_obligation_id": alias,
                "candidate_content_sha256": hashlib.sha256(alias.encode()).hexdigest(),
                "premise": "Exact alias-scoped security obligation premise.",
                "harm": "The candidate retains its proposed material harm.",
                "evidence": "Post-depth structural authority and bound candidate.",
            }
        )
    denominator = build_mandatory_reverification_denominator(
        run_id=RUN_ID,
        candidates=candidates,
        source_bindings=[
            {"artifact": SO.AUTHORITY_FILE, "sha256": _sha(authority_path.read_bytes())}
        ],
    )
    _json(root / DENOMINATOR_FILE, denominator)
    if shared_work_item:
        items = [_item(selected_ids[0], tuple(aliases))]
    else:
        items = [
            _item(selected_ids[index - 1], (alias,))
            for index, alias in enumerate(aliases, 1)
        ]
    active, routing = route_mandatory_reverification(
        denominator=denominator, active_items=items, fallback_items=()
    )
    assert active == tuple(items)
    _json(root / ROUTING_FILE, routing)
    _write_runtime(root, items, verdict=verdict)
    plan = QueueWorkPlan.from_json(
        (root / "verification_queue.work_plan.json").read_text(encoding="utf-8")
    )
    roster = VerifierWorkRoster.from_json(
        (root / "verification_runtime_roster.json").read_text(encoding="utf-8")
    )
    assignment = bind_mandatory_reverification_assignments(
        denominator=denominator,
        routing=routing,
        queue_plan=plan,
        roster=roster,
    )
    _json(root / ASSIGNMENT_FILE, assignment)
    if include_completion:
        evidence = {
            item.work_item_id: {
                "completion_authorized": True,
                "output_sha256": _sha((root / item.expected_output_file).read_bytes()),
                "receipt_sha256": _sha(
                    (root / f"verify_{item.work_item_id}.receipt.json").read_bytes()
                ),
            }
            for item in items
        }
        completion = reconcile_mandatory_reverification_completion(
            denominator=denominator,
            assignment=assignment,
            completion_evidence=evidence,
        )
        _json(root / COMPLETION_FILE, completion)
    return items


def _setup(tmp_path: Path, *, count: int = 2) -> tuple[Path, list[str]]:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    return root, _security_denominator(root, count=count)


def test_missing_mandatory_chain_reopens_every_exact_alias(tmp_path: Path) -> None:
    root, aliases = _setup(tmp_path)

    authority = L.build_security_obligation_lifecycle(root)

    assert [row["alias_id"] for row in authority["rows"]] == aliases
    assert {row["state"] for row in authority["rows"]} == {"OPEN_REPAIR"}
    assert authority["status"] == "DEGRADED_HUMAN_REVIEW"
    assert authority["denominator_complete"] is False


def test_exact_confirmed_completion_is_retained_and_projection_replays(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path)
    _write_mandatory_chain(root, aliases, verdict="CONFIRMED")

    authority = L.write_security_obligation_lifecycle(root)

    assert {row["state"] for row in authority["rows"]} == {"VERIFIED_CONFIRMED"}
    assert all(row["retention"] == "RETAIN" for row in authority["rows"])
    assert authority["terminal_negative_count"] == 0
    assert L.validate_security_obligation_lifecycle(root) == []
    assert (root / L.PROJECTION_FILE).read_text(encoding="utf-8") == L.render_security_obligation_lifecycle(authority)


def test_dynamic_markdown_inputs_are_raw_current_and_do_not_degrade(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    items = _write_mandatory_chain(root, aliases, verdict="CONFIRMED")

    authority = L.build_security_obligation_lifecycle(root)
    bindings = {
        row["artifact"]: row for row in authority["input_bindings"]
    }

    assert bindings[items[0].expected_output_file]["binding_state"] == "CURRENT"
    assert bindings[items[0].expected_output_file]["sha256"] == _sha(
        (root / items[0].expected_output_file).read_bytes()
    )
    assert authority["status"] == "COMPLETE"
    assert not any(
        row["binding_state"] == "MALFORMED"
        for row in authority["input_bindings"]
        if str(row["artifact"]).endswith(".md")
    )


def test_missing_completion_is_pending_not_zero_clean(tmp_path: Path) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(
        root, aliases, verdict="CONFIRMED", include_completion=False
    )

    authority = L.build_security_obligation_lifecycle(root)

    assert authority["rows"][0]["state"] == "VERIFY_PENDING"
    assert authority["status"] == "DEGRADED_HUMAN_REVIEW"
    assert authority["denominator_complete"] is True


def test_refuted_verifier_without_central_closure_is_retained(tmp_path: Path) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="REFUTED")

    row = L.build_security_obligation_lifecycle(root)["rows"][0]

    assert row["state"] == "NEGATIVE_PROPOSAL_RETAINED"
    assert row["terminal_negative_authority"] is False
    assert row["retention"] == "RETAIN"


def test_one_alias_central_closure_cannot_close_its_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, aliases = _setup(tmp_path)
    _write_mandatory_chain(
        root, aliases, verdict="REFUTED", shared_work_item=True
    )

    monkeypatch.setattr(L, "load_central_negative_closure_authority", lambda _root: object())

    def resolve(_authority: object, *, work_item: dict[str, object], requested_effect: str) -> dict[str, object]:
        alias = str(work_item["candidate_id"])
        if alias != aliases[0]:
            return {
                "schema_version": "plamen.central_negative_closure_decision.v1",
                "status": "DEBT",
                "outcome": "NO_AUTHORITY",
                "requested_effect": requested_effect,
                "candidate_id": alias,
                "work_item_id": "INV-001",
                "candidate_premise_ids": [],
                "reopen_required": True,
                "debt_reasons": ["NO_PROVIDER_AUTHORITY"],
                "resolution_digest": "",
            }
        unsigned = {
            "schema_version": "plamen.central_negative_closure_decision.v1",
            "status": "AUTHORIZED",
            "outcome": "REFUTED_FULL",
            "requested_effect": requested_effect,
            "candidate_id": alias,
            "work_item_id": "INV-001",
            "candidate_premise_ids": [],
            "candidate_content_sha256": hashlib.sha256(alias.encode()).hexdigest(),
            "subject_digest": "3" * 64,
            "evidence_manifest_digest": "4" * 64,
            "provider_id": "fixture.provider.v1",
            "provider_kind": "AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION",
            "provider_completion_sha256": "5" * 64,
            "provider_publish_sha256": "6" * 64,
            "bundle_digest": "7" * 64,
            "survivor_id": None,
            "survivor_identity_sha256": None,
            "reopen_required": False,
            "debt_reasons": [],
        }
        digest = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return {**unsigned, "resolution_digest": digest}

    monkeypatch.setattr(L, "resolve_central_negative_closure", resolve)

    rows = L.build_security_obligation_lifecycle(root)["rows"]
    by_alias = {row["alias_id"]: row for row in rows}

    assert by_alias[aliases[0]]["state"] == "AUTHORIZED_NEGATIVE"
    assert by_alias[aliases[0]]["terminal_negative_authority"] is True
    assert by_alias[aliases[1]]["state"] == "NEGATIVE_PROPOSAL_RETAINED"
    assert by_alias[aliases[1]]["terminal_negative_authority"] is False
    retention = L.render_security_obligation_report_retention(
        L.build_security_obligation_lifecycle(root)
    )
    assert aliases[0] not in retention
    assert aliases[1] in retention


@pytest.mark.parametrize("tamper", ["completion", "verifier"])
def test_tampered_completion_or_verifier_bytes_reopen_verification_debt(
    tmp_path: Path, tamper: str
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    items = _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    target = (
        root / COMPLETION_FILE
        if tamper == "completion"
        else root / items[0].expected_output_file
    )
    target.write_bytes(target.read_bytes() + b"tamper")

    authority = L.build_security_obligation_lifecycle(root)

    assert authority["rows"][0]["state"] == "VERIFICATION_DEBT"
    assert authority["rows"][0]["terminal_negative_authority"] is False


def test_projection_tamper_is_detected_without_mutating_authority(tmp_path: Path) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="CONTESTED")
    authority = L.write_security_obligation_lifecycle(root)
    assert authority["rows"][0]["state"] == "VERIFIED_CONTESTED"
    (root / L.PROJECTION_FILE).write_text("forged\n", encoding="utf-8")

    issues = L.validate_security_obligation_lifecycle(root)

    assert any("projection" in issue for issue in issues)
    recorded = json.loads((root / L.AUTHORITY_FILE).read_text(encoding="utf-8"))
    assert recorded == authority


def test_missing_selected_phaseio_ledger_reopens_verification_debt(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    (root / "_artifact_state.json").unlink()

    row = L.build_security_obligation_lifecycle(root)["rows"][0]

    assert row["state"] == L.VERIFICATION_DEBT
    assert "CURRENT_TYPED_VERIFIER_COMPLETION_AUTHORITY_INVALID" in row["debt_reasons"]


@pytest.mark.parametrize("semantic_leaf", ["launch_spec.json", "method_dispatch.json"])
def test_stale_selected_model_semantic_input_reopens_debt(
    tmp_path: Path, semantic_leaf: str
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    unit = VerifierWorkRoster.from_json(
        (root / "verification_runtime_roster.json").read_text(encoding="utf-8")
    ).work_units[0]
    path = root / "_verifier_runtime_units" / unit.work_unit_id / semantic_leaf
    path.write_bytes(path.read_bytes() + b"\n")

    row = L.build_security_obligation_lifecycle(root)["rows"][0]

    assert row["state"] == L.VERIFICATION_DEBT


def test_fake_gate_and_unknown_sibling_receipt_cannot_certify(tmp_path: Path) -> None:
    root, aliases = _setup(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    unit = VerifierWorkRoster.from_json(
        (root / "verification_runtime_roster.json").read_text(encoding="utf-8")
    ).work_units[0]
    gate = root / "_verifier_runtime_units" / unit.work_unit_id / "gate_receipt.json"
    _json(gate, {"fixture": "fake-gate"})
    row = L.build_security_obligation_lifecycle(root)["rows"][0]
    assert row["state"] == L.VERIFICATION_DEBT
    assert "TYPED_VERIFIER_GATE_AUTHORITY_INVALID" in row["debt_reasons"]

    (tmp_path / "sibling").mkdir()
    root2, aliases2 = _setup(tmp_path / "sibling", count=1)
    _write_mandatory_chain(root2, aliases2, verdict="CONFIRMED")
    (root2 / "verify_INV-001.unknown.receipt.json").write_text(
        "{}\n", encoding="utf-8"
    )
    sibling_row = L.build_security_obligation_lifecycle(root2)["rows"][0]
    assert sibling_row["state"] == L.VERIFICATION_DEBT
    assert "TYPED_VERIFIER_AUTHORITY_PATH_UNSAFE" in sibling_row["debt_reasons"]


def test_delimiter_scoped_receipts_do_not_prefix_collide(tmp_path: Path) -> None:
    root, aliases = _setup(tmp_path, count=2)
    _write_mandatory_chain(
        root, aliases, verdict="CONFIRMED", work_ids=["H-1", "H-10"]
    )

    rows = L.build_security_obligation_lifecycle(root)["rows"]

    assert {row["state"] for row in rows} == {L.VERIFIED_CONFIRMED}


def _apply_successor(root: Path, work_id: str) -> Path:
    identity_path = root / f"verify_{work_id}.identity.json"
    identity_path.write_text(
        json.dumps(
            json.loads(identity_path.read_text(encoding="utf-8")),
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    plan_path = root / "verification_queue.work_plan.json"
    plan = QueueWorkPlan.from_json(plan_path.read_text(encoding="utf-8"))
    plan_path.write_bytes((plan.to_json() + "\n").encode("utf-8"))
    result = {
        "verify_file": f"verify_{work_id}.md",
        "finding_id": work_id,
        "language": "evm",
        "test_file_resolved": "test/Fixture.t.sol",
        "test_function": "test_fixture",
        "test_command_used": "forge test --match-test test_fixture -vv",
        "status": "PASS",
        "duration_s": 1.0,
        "stdout_tail": "1 passed; 0 failed",
        "recommended_tag": "[POC-PASS]",
        "race_mode": False,
    }
    manifest = root / "mechanical_verify_manifest.json"
    _json(
        manifest,
        {
            "generated_at": "2026-07-19T12:00:00",
            "counts": {"PASS": 1},
            "results": [result],
        },
    )
    apply_mechanical_successor(
        root / f"verify_{work_id}.md",
        result,
        manifest,
        run_identity=RUN_ID,
        driver_identity="sha256:" + "d" * 64,
    )
    return root / f"verify_{work_id}.mechanical_successor.receipt.json"


@pytest.mark.parametrize("tamper", [None, "output", "prefix", "receipt"])
def test_mechanical_successor_exact_replay_or_tamper_debt(
    tmp_path: Path, tamper: str | None
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    items = _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    output = root / items[0].expected_output_file
    original_size = len(output.read_bytes())
    successor = _apply_successor(root, items[0].work_item_id)
    if tamper == "output":
        output.write_bytes(output.read_bytes() + b"tamper")
    elif tamper == "prefix":
        raw = bytearray(output.read_bytes())
        raw[min(10, original_size - 1)] ^= 1
        output.write_bytes(bytes(raw))
    elif tamper == "receipt":
        successor.write_bytes(successor.read_bytes() + b"tamper")

    authority = L.build_security_obligation_lifecycle(root)
    row = authority["rows"][0]

    if tamper is None:
        assert row["state"] == L.VERIFIED_CONFIRMED
        assert row["verifier_output_sha256"] == _sha(output.read_bytes())
        assert items[0].expected_output_file not in {
            binding["artifact"] for binding in authority["input_bindings"]
        }
        assert successor.name in {
            binding["artifact"] for binding in authority["input_bindings"]
        }
    else:
        assert row["state"] == L.VERIFICATION_DEBT


def test_valid_successor_does_not_mask_unrelated_stale_phaseio_input(
    tmp_path: Path,
) -> None:
    root, aliases = _setup(tmp_path, count=1)
    items = _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    _apply_successor(root, items[0].work_item_id)
    unit = VerifierWorkRoster.from_json(
        (root / "verification_runtime_roster.json").read_text(encoding="utf-8")
    ).work_units[0]
    prompt = root / "_verifier_runtime_units" / unit.work_unit_id / "prompt.md"
    prompt.write_bytes(prompt.read_bytes() + b"stale\n")

    row = L.build_security_obligation_lifecycle(root)["rows"][0]

    assert row["state"] == L.VERIFICATION_DEBT
    assert "CURRENT_TYPED_VERIFIER_COMPLETION_AUTHORITY_INVALID" in row["debt_reasons"]
