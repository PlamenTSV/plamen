from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import verification_method_compiler as V


ROOT = Path(__file__).resolve().parent.parent


def _row(
    work_item_id: str = "H-01",
    *,
    poc_class: str = "unit",
    bug_class: str = "state-accounting",
    artifact: str = "src/Vault.sol",
    symbol: str = "settle",
) -> dict[str, object]:
    return {
        "work_item_id": work_item_id,
        "poc_class": poc_class,
        "bug_class": bug_class,
        "location_records": [
            {
                "artifact": artifact,
                "start_line": 10,
                "end_line": 20,
                "symbol": symbol,
                "note": None,
            }
        ],
        "primary_artifacts": ["depth_state_findings.md"],
        "title": "State transition can violate the queued harm premise",
    }


def _packet(work_item_id: str = "H-01", *, state: str = "RESOLVED") -> dict[str, object]:
    unsigned = {
        "packet_id": f"VCTX-{work_item_id}",
        "work_item_id": work_item_id,
        "state": state,
        "seed_locations": ["src/Vault.sol:10-20:settle"],
        "graph_matches": [
            {
                "artifact": "caller_map.md",
                "line": 2,
                "excerpt": "settle <- finalize",
            }
        ] if state == "RESOLVED" else [],
        "expansion_candidates": ["src/Router.sol"],
        "hub_truncated": False,
        "fanout_limit": 8,
        "primary_artifact_bindings": [
            {
                "artifact": "depth_state_findings.md",
                "scope": "SCRATCHPAD",
                "status": "BOUND",
                "sha256": "a" * 64,
                "size_bytes": 1,
            }
        ],
        "primary_artifact_binding_complete": True,
        "graph_binding_complete": True,
    }
    return {**unsigned, "packet_digest": V.stable_digest(unsigned)}


def _dispatch(
    *,
    pipeline: str = "sc",
    ecosystem: str = "evm",
    backend: str = "claude",
    row: dict[str, object] | None = None,
    packet: dict[str, object] | None = None,
) -> dict[str, object]:
    item = row or _row()
    ctx = packet or _packet(str(item["work_item_id"]))
    return V.compile_verification_method_dispatch(
        pipeline=pipeline,
        ecosystem=ecosystem,
        backend=backend,
        rows=[item],
        context_packets={str(item["work_item_id"]): ctx},
        manifest_path="_verifier_runtime_units/verify-0001/manifest.md",
        scratchpad_path="C:/audit/.scratchpad",
    )


def _valid_proposal(dispatch: dict[str, object]) -> dict[str, object]:
    row = dispatch["rows"][0]
    packet_digest = row["context_packet_digest"]
    operators = []
    for operator_id in row["operator_ids"]:
        operators.append(
            {
                "operator_id": operator_id,
                "status": "APPLIED",
                "evidence": [
                    {
                        "source": "src/Vault.sol:10-20",
                        "detail": "Traced the exact state transition and its caller.",
                    }
                ],
                "predicate": None,
                "debt_code": None,
                "blocker_evidence": [],
            }
        )
    return {
        "schema_version": V.OPERATOR_PROPOSAL_SCHEMA,
        "work_item_id": row["work_item_id"],
        "method_dispatch_id": dispatch["dispatch_id"],
        "selected_module_hashes": row["module_hashes"],
        "context_packet_digest": packet_digest,
        "context_status": "RESOLVED",
        "context_expansion": [],
        "operators": operators,
        "new_observations": [],
    }


@pytest.mark.parametrize(
    "pipeline,ecosystem",
    [
        ("sc", "evm"),
        ("sc", "solana"),
        ("sc", "aptos"),
        ("sc", "sui"),
        ("sc", "soroban"),
        ("l1", "go"),
        ("l1", "rust"),
        ("l1", "mixed"),
    ],
)
@pytest.mark.parametrize("backend", ["claude", "codex"])
def test_compiler_generates_backend_neutral_complete_prompt(
    pipeline: str, ecosystem: str, backend: str
) -> None:
    dispatch = _dispatch(pipeline=pipeline, ecosystem=ecosystem, backend=backend)
    prompt = str(dispatch["prompt_markdown"])

    assert dispatch["schema_version"] == V.DISPATCH_SCHEMA
    assert dispatch["backend"] == backend
    assert dispatch["dispatch_id"] in prompt
    assert "Impact:" in prompt and "Likelihood:" in prompt
    assert "Independent Severity:" in prompt
    assert "Rules Applied:" in prompt
    assert "operator_application.json" in prompt
    assert "CONTEXT_UNRESOLVED" in prompt
    assert "one bounded expansion" in prompt.lower()
    assert prompt.index("Classify the claimed bug class") < prompt.index("REFUTED")
    assert "skeptic worker" not in prompt.lower()
    assert "cross-batch consistency agent" not in prompt.lower()
    assert len(prompt.encode("utf-8")) < 18000


def test_executor_modules_are_conditionally_selected() -> None:
    evm = _dispatch(ecosystem="evm")
    solana = _dispatch(ecosystem="solana")
    move = _dispatch(ecosystem="aptos")
    l1 = _dispatch(pipeline="l1", ecosystem="mixed")

    assert "executor.evm" in evm["selected_module_ids"]
    assert "executor.rust_sc" not in evm["selected_module_ids"]
    assert "executor.rust_sc" in solana["selected_module_ids"]
    assert "executor.move" in move["selected_module_ids"]
    assert {"executor.l1_go", "executor.l1_rust"}.issubset(
        set(l1["selected_module_ids"])
    )


def test_bug_and_poc_selectors_do_not_enable_unrelated_modules() -> None:
    serial = _dispatch(row=_row(bug_class="cross-vm serialization", poc_class="property"))
    structural = _dispatch(row=_row(bug_class="access boundary", poc_class="structural"))
    assert "bug.serialization" in serial["selected_module_ids"]
    assert "poc.executable" in serial["selected_module_ids"]
    assert "bug.serialization" not in structural["selected_module_ids"]
    assert "poc.structural" in structural["selected_module_ids"]


def test_context_packet_uses_reference_graph_and_bounds_hubs(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    (project / "src").mkdir(parents=True)
    scratch.mkdir()
    (scratch / "depth_state_findings.md").write_text(
        "bound candidate evidence\n", encoding="utf-8"
    )
    (project / "src" / "Vault.sol").write_text(
        "\n" * 8 + "function settle() external {}\n", encoding="utf-8"
    )
    (scratch / "caller_map.md").write_text(
        "# Callers\n" + "\n".join(
            f"settle <- caller{i} src/Router{i}.sol" for i in range(30)
        ),
        encoding="utf-8",
    )
    payload = V.build_verification_context_packets(
        rows=[_row()], scratchpad=scratch, project_root=project, fanout_limit=4
    )
    packet = payload["packets"][0]
    assert packet["state"] == "RESOLVED"
    assert len(packet["graph_matches"]) == 4
    assert packet["hub_truncated"] is True
    assert len(packet["expansion_candidates"]) <= 4


def test_missing_context_is_visible_and_cannot_become_safe(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    project.mkdir()
    scratch.mkdir()
    packets = V.build_verification_context_packets(
        rows=[_row()], scratchpad=scratch, project_root=project
    )
    packet = packets["packets"][0]
    assert packet["state"] == "CONTEXT_UNRESOLVED"
    dispatch = _dispatch(packet=packet)
    proposal = _valid_proposal(dispatch)
    proposal["context_status"] = "CONTEXT_UNRESOLVED"
    proposal["operators"][0] = {
        "operator_id": proposal["operators"][0]["operator_id"],
        "status": "BLOCKED",
        "evidence": [],
        "predicate": None,
        "debt_code": "CONTEXT_UNRESOLVED",
        "blocker_evidence": ["caller/state graph has no matching edge"],
    }
    with pytest.raises(V.VerificationMethodError, match="terminal negative"):
        V.validate_operator_application_proposal(
            proposal, dispatch=dispatch, verdict="REFUTED"
        )
    checked = V.validate_operator_application_proposal(
        proposal, dispatch=dispatch, verdict="CONTESTED"
    )
    assert checked["has_blocked_operators"] is True


def test_context_expansion_must_come_from_bound_packet_candidates() -> None:
    dispatch = _dispatch()
    proposal = _valid_proposal(dispatch)
    proposal["context_status"] = "EXPANDED_RESOLVED"
    proposal["context_expansion"] = ["src/Unissued.sol"]
    with pytest.raises(V.VerificationMethodError, match="not issued"):
        V.validate_operator_application_proposal(
            proposal, dispatch=dispatch, verdict="CONTESTED"
        )

    proposal["context_expansion"] = ["src/Router.sol"]
    checked = V.validate_operator_application_proposal(
        proposal, dispatch=dispatch, verdict="CONTESTED"
    )
    assert checked["context_expansion"] == ["src/Router.sol"]


def test_false_applied_and_invalid_module_binding_are_rejected() -> None:
    dispatch = _dispatch()
    proposal = _valid_proposal(dispatch)
    proposal["operators"][0]["evidence"] = []
    with pytest.raises(V.VerificationMethodError, match="APPLIED.*evidence"):
        V.validate_operator_application_proposal(proposal, dispatch=dispatch)

    proposal = _valid_proposal(dispatch)
    proposal["selected_module_hashes"] = dict(proposal["selected_module_hashes"])
    proposal["selected_module_hashes"][next(iter(proposal["selected_module_hashes"]))] = "0" * 64
    with pytest.raises(V.VerificationMethodError, match="module hash"):
        V.validate_operator_application_proposal(proposal, dispatch=dispatch)


def test_not_applicable_requires_registry_predicate() -> None:
    dispatch = _dispatch()
    proposal = _valid_proposal(dispatch)
    target = next(
        row for row in proposal["operators"] if row["operator_id"] == "realistic-parameters"
    )
    target.update(
        status="NOT_APPLICABLE",
        evidence=[],
        predicate="NO_PARAMETER_DOMAIN",
        debt_code=None,
        blocker_evidence=[],
    )
    V.validate_operator_application_proposal(proposal, dispatch=dispatch)
    target["predicate"] = "MODEL_SAYS_NA"
    with pytest.raises(V.VerificationMethodError, match="predicate"):
        V.validate_operator_application_proposal(proposal, dispatch=dispatch)


def test_blocker_and_new_observation_are_non_authoritative_debt_and_proposal() -> None:
    dispatch = _dispatch()
    proposal = _valid_proposal(dispatch)
    proposal["operators"][0].update(
        status="BLOCKED",
        evidence=[],
        predicate=None,
        debt_code="EVIDENCE_UNAVAILABLE",
        blocker_evidence=["build log: toolchain unavailable"],
    )
    proposal["new_observations"] = [
        {
            "title": "Independent state transition requires separate review",
            "mechanism": "A distinct transition was observed outside this row's proof scope.",
            "location": "src/Vault.sol:42",
            "evidence": "src/Vault.sol:42",
        }
    ]
    checked = V.validate_operator_application_proposal(
        proposal, dispatch=dispatch, verdict="CONTESTED"
    )
    assert checked["new_observations"][0]["candidate_state"] == "PROPOSED"
    assert checked["new_observations"][0]["terminal_authority"] is False
    assert checked["debts"][0]["report_visible"] is True


def test_driver_binding_is_hash_bound_and_idempotent(tmp_path: Path) -> None:
    dispatch = _dispatch()
    proposal = _valid_proposal(dispatch)
    proposal_path = tmp_path / "verify_H-01.operator_application.json"
    verify_path = tmp_path / "verify_H-01.md"
    receipt_path = tmp_path / "verify_H-01.operator_receipt.json"
    proposal_path.write_text(json.dumps(proposal), encoding="utf-8")
    verify_path.write_text("# Verification\nVerdict: CONTESTED\n", encoding="utf-8")

    first = V.bind_operator_application_receipt(
        proposal_path=proposal_path,
        verify_path=verify_path,
        receipt_path=receipt_path,
        dispatch=dispatch,
        launch_digest="a" * 64,
        verdict="CONTESTED",
    )
    before = receipt_path.stat().st_mtime_ns
    second = V.bind_operator_application_receipt(
        proposal_path=proposal_path,
        verify_path=verify_path,
        receipt_path=receipt_path,
        dispatch=dispatch,
        launch_digest="a" * 64,
        verdict="CONTESTED",
    )
    assert first == second
    assert receipt_path.stat().st_mtime_ns == before
    verify_path.write_text("# Verification\nVerdict: REFUTED\n", encoding="utf-8")
    with pytest.raises(V.VerificationMethodError, match="existing operator receipt"):
        V.bind_operator_application_receipt(
            proposal_path=proposal_path,
            verify_path=verify_path,
            receipt_path=receipt_path,
            dispatch=dispatch,
            launch_digest="a" * 64,
            verdict="REFUTED",
        )


def test_dispatch_changes_only_when_method_or_context_changes() -> None:
    first = _dispatch()
    second = _dispatch()
    assert first["dispatch_id"] == second["dispatch_id"]
    packet = _packet()
    packet["graph_matches"][0]["excerpt"] = "settle <- anotherCaller"
    unsigned = {key: value for key, value in packet.items() if key != "packet_digest"}
    packet["packet_digest"] = V.stable_digest(unsigned)
    changed = _dispatch(packet=packet)
    assert changed["dispatch_id"] != first["dispatch_id"]


def test_reachability_manifest_has_no_orphan_and_detects_injected_orphan(tmp_path: Path) -> None:
    result = V.validate_methodology_reachability(ROOT)
    assert result["ok"] is True, result["issues"]
    assert any(
        row["disposition"] == "MOVED_TO_INDEPENDENT_CONSUMER"
        for row in result["entries"]
    )
    assert any(
        row["disposition"] == "RETIRED_WITH_RATIONALE"
        for row in result["entries"]
    )

    copied = tmp_path / "repo"
    copied.mkdir()
    (copied / "verification_policy").mkdir()
    manifest = json.loads(
        (ROOT / "verification_policy" / "methodology_reachability.v1.json").read_text(
            encoding="utf-8"
        )
    )
    (copied / "verification_policy" / "methodology_reachability.v1.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    (copied / "prompts" / "evm").mkdir(parents=True)
    (copied / "prompts" / "evm" / "phase5-verification-prompt.md").write_text(
        "## UNMAPPED METHOD (MANDATORY)\nDo something.\n", encoding="utf-8"
    )
    result = V.validate_methodology_reachability(copied)
    assert result["ok"] is False
    assert any(issue["code"] == "ORPHAN_MANDATORY_RULE" for issue in result["issues"])


def test_reachability_rejects_moved_without_consumer_and_retired_without_rationale(
    tmp_path: Path,
) -> None:
    manifest = {
        "schema_version": V.REACHABILITY_SCHEMA,
        "scan_paths": ["legacy.md"],
        "entries": [
            {
                "rule_id": "moved",
                "source_pattern": "MOVED RULE",
                "disposition": "MOVED_TO_INDEPENDENT_CONSUMER",
                "owner": "skeptic",
                "compiled_module": None,
                "schema_field": "challenge",
                "consumer_path": "missing.md",
                "test_path": "missing_test.py",
                "rationale": "independent discriminator",
            },
            {
                "rule_id": "retired",
                "source_pattern": "RETIRED RULE",
                "disposition": "RETIRED_WITH_RATIONALE",
                "owner": "none",
                "compiled_module": None,
                "schema_field": None,
                "consumer_path": None,
                "test_path": "missing_test.py",
                "rationale": "",
            },
        ],
    }
    (tmp_path / "verification_policy").mkdir()
    (tmp_path / "verification_policy" / "methodology_reachability.v1.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    (tmp_path / "legacy.md").write_text(
        "## MOVED RULE (MANDATORY)\n## RETIRED RULE (MANDATORY)\n",
        encoding="utf-8",
    )
    result = V.validate_methodology_reachability(tmp_path)
    codes = {issue["code"] for issue in result["issues"]}
    assert "MISSING_INDEPENDENT_CONSUMER" in codes
    assert "MISSING_RETIREMENT_RATIONALE" in codes


def test_registry_contains_no_target_specific_methodology() -> None:
    text = json.dumps(V.load_verification_method_registry(ROOT), sort_keys=True).lower()
    banned = ("spectra", "dodo", "h-01", "b_rate", "zetachain", "specific protocol")
    assert not any(token in text for token in banned)
