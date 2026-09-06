"""P1-C typed feature-fact and security-obligation authority fixtures."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from artifact_ledger import (
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
import security_obligation_authority as A
import asset_representation_foundation as F
import semantic_invariant_authority as S


RUN_ID = "12345678-1234-4234-9234-123456789abc"
SNAPSHOT = "a" * 64
SOURCE_SCOPE = "b" * 64


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


def _checkpoint(
    root: Path,
    *,
    ecosystem: str = "evm",
    mode: str = "thorough",
    run_id: str = RUN_ID,
    snapshot: str = SNAPSHOT,
) -> None:
    payload = {
        "completed": ["recon"],
        "degraded": [],
        "rate_limited_at": None,
        "run_id": run_id,
        "config": {
            "pipeline": "l1" if ecosystem in {"go", "rust"} else "sc",
            "language": ecosystem,
            "mode": mode,
        },
        "audit_snapshot": {
            "schema": "plamen.audit-input-snapshot.v1",
            "snapshot_digest": snapshot,
            "components": {"source_scope": {"digest": SOURCE_SCOPE}},
        },
    }
    (root / "_v2_checkpoint.json").write_text(
        json.dumps(payload, sort_keys=True), encoding="utf-8"
    )


def _graph(
    root: Path,
    *,
    functions: dict[str, dict[str, object]] | None = None,
    var_refs: dict[str, dict[str, object]] | None = None,
    source: str = "evm-source",
) -> None:
    payload = {
        "schema_version": "plamen.mechanical-graph.v2",
        "source": source,
        "functions": functions or {},
        "var_refs": var_refs or {},
        "state_symbols": [],
    }
    (root / "_mechanical_graph.json").write_text(
        json.dumps(payload, sort_keys=True), encoding="utf-8"
    )


def _build(root: Path, **kwargs: object) -> dict[str, object]:
    return A.write_security_obligation_authority(root, **kwargs)


def _fake_bound_depth_receipt(root: Path, receipt_line: str) -> None:
    """Write the old artifact-binding-only shape, which is not authority."""
    output = "depth_state_trace_findings.md"
    (root / output).write_text(
        "<!-- PLAMEN_ARTIFACT: depth_state_trace_findings.md -->\n"
        "<!-- PLAMEN_OWNER: depth-state-trace -->\n"
        "<!-- PLAMEN_PHASE: depth -->\n"
        "# Depth\n\n"
        f"{receipt_line}\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )
    (root / "_depth_worker_pool_contract.json").write_text(
        json.dumps(
            {
                "version": 2,
                "phase": "depth",
                "canonical_outputs": [output],
                "outputs": [output],
                "jobs": [{"agent_id": "depth-state-trace", "output": output}],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    output_sha = _sha((root / output).read_bytes()).lower()
    (root / "_artifact_state.json").write_text(
        json.dumps(
            {
                "version": 2,
                "artifacts": {},
                "work_units": {},
                "artifact_bindings": {
                    f"scratchpad:{output}": {
                        "identity": f"scratchpad:{output}",
                        "run_id": RUN_ID,
                        "writer": "MODEL",
                        "status": "ACTIVE",
                        "sha256": output_sha,
                    }
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _launch(contract, *, model: str, exec_mode: str) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model=model,
        timeout_s=120,
        exec_mode=exec_mode,
        tool_policy=("filesystem",),
    )


def test_wrapper_semantics_are_generic_and_opaque_symbols_are_not_authority() -> None:
    assert {"wrapped", "wrap", "unwrap"} <= A._CONCEPT_TOKENS["wrapped_asset"]
    assert "wrapped" in A._identifier_tokens("native_wrapper_approve")
    assert "wrapped" in A._identifier_tokens("native_wrapping_approve")
    assert "wrapped" not in A._identifier_tokens("native_WRITE_approve")
    assert "wrapped" not in A._identifier_tokens("native_wcoin_approve")


def _record_pre_authority(root: Path) -> None:
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="security_obligations.pre_depth",
        exact_inputs=("_mechanical_graph.json",),
    )
    launch = _launch(contract, model="driver", exec_mode="python")
    record_work_unit_inputs(root, root.parent, contract, launch, run_id=RUN_ID)
    record_work_unit_artifacts(
        root,
        root.parent,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )


def _record_post_authority(root: Path) -> None:
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="security_obligations.post_depth",
        exact_inputs=(
            "_mechanical_graph.json",
            "_depth_worker_pool_contract.json",
            "depth_state_trace_findings.md",
        ),
    )
    launch = _launch(contract, model="driver", exec_mode="python")
    record_work_unit_inputs(root, root.parent, contract, launch, run_id=RUN_ID)
    record_work_unit_artifacts(
        root,
        root.parent,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )


def _materialize_valid_semantic_final_byte_authority(
    root: Path, *, backend: str = "claude"
) -> None:
    """Use the public P1-D providers to satisfy the real depth PRE contract."""

    S.write_semantic_invariant_authority(root)
    worklist = json.loads((root / S.WORKLIST_FILE).read_text(encoding="utf-8"))
    payload = {
        "schema_version": S.APPLICATION_TRACE_SCHEMA,
        "run_binding_digest": worklist["run_binding"]["binding_digest"],
        "authority_digest": worklist["authority_digest"],
        "worklist_digest": worklist["worklist_digest"],
        "producer_operator_digest": "c" * 64,
        "rows": [],
    }
    payload["payload_digest"] = S.payload_digest(payload)
    semantic = (
        "# Semantic invariants\n\n"
        "The empty fixture state denominator was enumerated exactly.\n\n"
        f"{S.TRACE_BEGIN}\n"
        + json.dumps(payload, indent=2, sort_keys=True)
        + f"\n{S.TRACE_END}\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )
    (root / "semantic_invariants.md").write_text(semantic, encoding="utf-8")
    receipt = S.reconcile_semantic_invariant_application(root)
    assert receipt["status"] == "APPLIED"
    pre = S.write_semantic_invariant_pass2_pre_authority(root, backend=backend)
    assert pre["status"] == "READY"
    with (root / "semantic_invariants.md").open("a", encoding="utf-8") as stream:
        stream.write(
            "\n## Pass 2: Recursive Semantic Gap Trace\n\n"
            "No additional state obligation exists in the empty fixture.\n"
        )
    final = S.write_semantic_invariant_final_byte_authority(root, backend=backend)
    assert final["status"] == "VALID_FINAL_BYTES"
    assert S.validate_semantic_invariant_final_byte_authority(
        root, backend=backend
    ) == []


def _real_bound_depth_receipt(
    root: Path,
    receipt_line: str,
    *,
    finding_id: str = "",
    finding_evidence: str | None = None,
    receipt_after_finding: bool = False,
    structured_aliases: list[dict[str, object]] | None = None,
) -> None:
    """Bind a depth output to the exact PRE sidecars before model execution."""
    output = "depth_state_trace_findings.md"
    for name in ("findings_inventory.md", "semantic_invariants.md"):
        (root / name).write_text(f"# {name}\n", encoding="utf-8")
    _materialize_valid_semantic_final_byte_authority(root)
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="worker.depth-state-trace",
        exact_outputs=(output,),
    )
    launch = _launch(contract, model="opus", exec_mode="pty")
    record_work_unit_inputs(root, root.parent, contract, launch, run_id=RUN_ID)
    if finding_id and finding_evidence is None:
        authority = json.loads((root / A.AUTHORITY_FILE).read_text(encoding="utf-8"))
        if structured_aliases is None:
            selected: list[dict[str, object]] = []
            for obligation in authority.get("obligations", []):
                if not isinstance(obligation, dict):
                    continue
                aliases = [
                    alias
                    for alias in obligation.get("trigger_aliases", [])
                    if isinstance(alias, dict)
                ]
                for alias in aliases:
                    if str(alias.get("alias_id") or "") in receipt_line:
                        selected.append(alias)
                if (
                    " ALIAS:" not in receipt_line
                    and str(obligation.get("display_id") or "") in receipt_line
                    and len(aliases) == 1
                ):
                    selected.extend(aliases)
            structured_aliases = selected
        markers = [
            "<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: "
            + json.dumps(
                {
                    "schema_version": (
                        "plamen.security-obligation-evidence-binding.v1"
                    ),
                    "alias_id": str(alias.get("alias_id") or ""),
                    "subject_id": str(alias.get("subject_id") or ""),
                    "relation_id": str(alias.get("relation_id") or ""),
                    "object_id": str(alias.get("object_id") or ""),
                    "symbol": str(alias.get("symbol") or ""),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + " -->"
            for alias in structured_aliases
        ]
        finding_evidence = (
            "Exact structured security-obligation evidence.\n" + "\n".join(markers)
        )
    finding = (
        f"\n### Finding [{finding_id}]\n\n{finding_evidence or 'Bound referent.'}\n"
        if finding_id
        else ""
    )
    receipt_block = f"{receipt_line}\n" if not receipt_after_finding else ""
    trailing_receipt_block = (
        f"\n{receipt_line}\n" if receipt_after_finding else ""
    )
    (root / output).write_text(
        "<!-- PLAMEN_ARTIFACT: depth_state_trace_findings.md -->\n"
        "<!-- PLAMEN_OWNER: depth-state-trace -->\n"
        "<!-- PLAMEN_PHASE: depth -->\n"
        "# Depth\n\n"
        f"{receipt_block}"
        f"{finding}"
        f"{trailing_receipt_block}"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )
    record_work_unit_artifacts(
        root,
        root.parent,
        contract,
        launch,
        run_id=RUN_ID,
        actor="MODEL",
    )
    (root / "_depth_worker_pool_contract.json").write_text(
        json.dumps(
            {
                "version": 2,
                "phase": "depth",
                "canonical_outputs": [output],
                "outputs": [output],
                "jobs": [{"agent_id": "depth-state-trace", "output": output}],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _by_rule(payload: dict[str, object], rule_id: str) -> dict[str, object] | None:
    return next(
        (
            row
            for row in payload["obligations"]  # type: ignore[index]
            if row["rule_id"] == rule_id
        ),
        None,
    )


@pytest.mark.parametrize(
    ("ecosystem", "source", "identity"),
    (
        ("evm", "evm-source", "vault::native_wcoin_approve"),
        ("rust", "rust-source", "node::native_wcoin_approve"),
        ("sui", "move-source", "module::native_wcoin_approve"),
    ),
)
def test_ambiguous_wrapper_symbol_is_review_debt_not_wrapper_authority(
    tmp_path: Path,
    ecosystem: str,
    source: str,
    identity: str,
) -> None:
    _checkpoint(tmp_path, ecosystem=ecosystem)
    _graph(
        tmp_path,
        source=source,
        functions={
            identity: {
                "bare": identity.rsplit("::", 1)[-1],
                "loc": "src/module.move:L10" if ecosystem == "sui" else "src/module.rs:L10",
                "callers": [],
                "callees": [],
            }
        },
    )

    payload = _build(tmp_path)

    assert _by_rule(payload, "security.native_wrapped_asset.v1") is None
    debt = _by_rule(payload, "security.wrapped_asset_classification.v1")
    assert debt is not None
    assert debt["state"] == "UNACCOUNTED"
    assert debt["target_ids"][0].startswith("SWR-")
    assert debt["trigger_aliases"][0]["subject_id"] == f"fn:{identity}"


def test_current_graph_relation_adds_context_but_cannot_suppress_debt(tmp_path: Path) -> None:
    identity = "vault::native_wcoin_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_wcoin_approve",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    graph_path = tmp_path / "_mechanical_graph.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    graph["feature_facts"] = [
        {
            "subject_id": f"fn:{identity}",
            "concept": "wrapped_asset",
            "polarity": "PRESENT",
            "relation": {
                "kind": "WRAPPED_ASSET_CLASSIFICATION",
                "object_id": f"graph:function:{identity}#identifier:wcoin",
                "symbol": "wcoin",
            },
            "evidence_identity": "bake:wrapper-conversion-edge:1",
        }
    ]
    graph_path.write_text(json.dumps(graph, sort_keys=True), encoding="utf-8")

    payload = _build(tmp_path)

    assert _by_rule(payload, "security.native_wrapped_asset.v1") is not None
    debt = _by_rule(payload, "security.wrapped_asset_classification.v1")
    assert debt is not None
    facts = json.loads(
        (tmp_path / A.FEATURE_FACT_FILE).read_text(encoding="utf-8")
    )["facts"]
    declared = next(
        row
        for row in facts
        if row["evidence_identity"] == "bake:wrapper-conversion-edge:1"
    )
    assert declared["terminal_application_authority"] is False


def test_ordinary_uppercase_word_never_mints_wrapper_authority(tmp_path: Path) -> None:
    identity = "vault::native_WRITE_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_WRITE_approve",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )

    payload = _build(tmp_path)

    assert _by_rule(payload, "security.native_wrapped_asset.v1") is None
    assert _by_rule(payload, "security.wrapped_asset_classification.v1") is None


@pytest.mark.parametrize(
    ("bare", "object_id"),
    (
        ("native_wCoin_approve", "wCoin"),
        ("native_wASSET_approve", "wASSET"),
        ("native_w_coin_approve", "wcoin"),
        ("native_w_unit_approve", "wunit"),
        ("native_w_object_approve", "wobject"),
        ("nativeWCoinApprove", "WCoin"),
        ("nativeWASSETApprove", "WASSET"),
    ),
)
def test_wrapper_classification_debt_handles_common_identifier_spellings(
    tmp_path: Path,
    bare: str,
    object_id: str,
) -> None:
    identity = f"vault::{bare}"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": bare,
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )

    debt = _by_rule(_build(tmp_path), "security.wrapped_asset_classification.v1")

    assert debt is not None
    assert [row["symbol"] for row in debt["trigger_aliases"]] == [object_id]


@pytest.mark.parametrize(
    "word",
    ("withdraw", "writable", "WRITE", "when", "with", "while", "wallet"),
)
def test_owned_or_structural_w_words_are_not_wrapper_classification_debt(
    tmp_path: Path,
    word: str,
) -> None:
    bare = f"native_{word}_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            f"vault::{bare}": {
                "bare": bare,
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )

    payload = _build(tmp_path)

    assert _by_rule(payload, "security.wrapped_asset_classification.v1") is None


def test_var_reference_can_create_relation_scoped_wrapper_classification_debt(
    tmp_path: Path,
) -> None:
    identity = "vault::native_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_approve",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
        var_refs={
            "vault.wcoin": {
                "bare": "wcoin",
                "refs": [identity],
            }
        },
    )

    debt = _by_rule(_build(tmp_path), "security.wrapped_asset_classification.v1")

    assert debt is not None
    assert debt["target_ids"][0].startswith("SWR-")
    assert [row["symbol"] for row in debt["trigger_aliases"]] == ["wcoin"]
    assert debt["trigger_aliases"][0]["object_id"] == "graph:var:vault.wcoin"


def test_v2_typed_recon_wrapper_relation_is_proposal_only_migration_debt(
    tmp_path: Path,
) -> None:
    identity = "vault::native_wcoin_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_wcoin_approve",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    (tmp_path / A.RECON_FEATURE_FILE).write_text(
        json.dumps(
            {
                "schema_version": A.RECON_FEATURE_SCHEMA,
                "run_id": RUN_ID,
                "source_snapshot_digest": SNAPSHOT,
                "ecosystem": "evm",
                "facts": [
                    {
                        "subject_id": f"fn:{identity}",
                        "concept": "wrapped_asset",
                        "polarity": "PRESENT",
                        "relation": {
                            "kind": "WRAPPED_ASSET_CLASSIFICATION",
                            "object_id": (
                                f"graph:function:{identity}#identifier:wcoin"
                            ),
                            "symbol": "wcoin",
                        },
                        "evidence_identity": "recon:wrapper-edge:wcoin",
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    payload = _build(tmp_path)

    assert _by_rule(payload, "security.native_wrapped_asset.v1") is not None
    assert _by_rule(payload, "security.wrapped_asset_classification.v1") is not None


def _write_attested_wrapper_feature_facts(
    root: Path,
    identity: str,
    rows: tuple[tuple[str, str], ...],
) -> None:
    facts = []
    binding = {
        "run_id": RUN_ID,
        "source_snapshot_digest": SNAPSHOT,
        "ecosystem": "evm",
        "mode": "thorough",
    }
    for object_id, polarity in rows:
        row = {
            "subject_id": f"fn:{identity}",
            "concept": "wrapped_asset",
            "polarity": polarity,
            "relation": {
                "kind": "WRAPPED_ASSET_CLASSIFICATION",
                "object_id": (
                    f"graph:function:{identity}#identifier:{object_id}"
                ),
                "symbol": object_id,
            },
            "evidence_identity": (
                f"operator:wrapper-edge:{object_id}:{polarity.casefold()}"
            ),
        }
        attestation = F.make_operator_attestation(
            row,
            run_binding=binding,
            attestor_id="fixture:asset-model-owner",
            evidence_sha256=_sha(
                f"{identity}:{object_id}:{polarity}".encode("utf-8")
            ),
        )
        row["provenance"] = {
            "authority": F.OPERATOR_ATTESTED,
            "attestation_id": attestation["attestation_id"],
        }
        row["_fixture_attestation"] = attestation
        facts.append(row)
    attestations = [row.pop("_fixture_attestation") for row in facts]
    attestation_path = root / F.OPERATOR_ATTESTATION_FILE
    attestation_path.write_text(
        json.dumps(
            F.build_operator_attestation_registry(
                attestations, run_binding=binding
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    checkpoint_path = root / "_v2_checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    checkpoint["operator_attestation_bindings"] = {
        F.OPERATOR_ATTESTATION_FILE: _sha(attestation_path.read_bytes())
    }
    checkpoint_path.write_text(
        json.dumps(checkpoint, sort_keys=True), encoding="utf-8"
    )
    (root / A.RECON_FEATURE_FILE).write_text(
        json.dumps(
            {
                "schema_version": A.RECON_FEATURE_SCHEMA_V3,
                "run_id": RUN_ID,
                "source_snapshot_digest": SNAPSHOT,
                "ecosystem": "evm",
                "facts": facts,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _write_wrapper_feature_facts(
    root: Path,
    identity: str,
    object_ids: tuple[str, ...],
) -> None:
    _write_attested_wrapper_feature_facts(
        root, identity, tuple((object_id, "PRESENT") for object_id in object_ids)
    )


def _enable_test_only_terminal_attestation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise relation algebra without creating a production authority path.

    Scratchpad operator claims are deliberately non-terminal.  These few
    fixtures test exact suppression/conflict mechanics below that boundary, so
    they upgrade only an already structurally valid reserved attestation in
    process.  No runtime module imports this helper or recognizes this state.
    """

    real = F.resolve_feature_authority

    def resolve(*args, **kwargs):
        authority, issues = real(*args, **kwargs)
        if authority.get("authority_state") == (
            "RESERVED_OPERATOR_OUT_OF_TREE_AUTHORITY_UNAVAILABLE"
        ):
            authority = {
                **authority,
                "authority_state": "TEST_ONLY_TERMINAL_FIXTURE",
                "terminal_application_authority": True,
            }
        return authority, issues

    monkeypatch.setattr(F, "resolve_feature_authority", resolve)


@pytest.mark.parametrize(
    ("proven_objects", "remaining_objects"),
    (
        ((), ("wasset", "wcoin")),
        (("wcoin",), ("wasset",)),
        (("wcoin", "wasset"), ()),
    ),
)
def test_wrapper_debt_is_exact_per_symbol_relation(
    tmp_path: Path,
    proven_objects: tuple[str, ...],
    remaining_objects: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = "vault::native_wcoin_wasset_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_wcoin_wasset_approve",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _write_wrapper_feature_facts(tmp_path, identity, proven_objects)
    _enable_test_only_terminal_attestation(monkeypatch)

    debt = _by_rule(_build(tmp_path), "security.wrapped_asset_classification.v1")

    if not remaining_objects:
        assert debt is None
    else:
        assert debt is not None
        aliases = debt["trigger_aliases"]
        assert tuple(row["symbol"] for row in aliases) == remaining_objects
        assert len({row["alias_id"] for row in aliases}) == len(remaining_objects)


def test_legacy_subject_only_wrapper_fact_cannot_clear_two_relations(
    tmp_path: Path,
) -> None:
    identity = "vault::native_wcoin_wasset_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_wcoin_wasset_approve",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    graph_path = tmp_path / "_mechanical_graph.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    graph["feature_facts"] = [
        {
            "subject_id": f"fn:{identity}",
            "concept": "wrapped_asset",
            "polarity": "PRESENT",
            "evidence_identity": "legacy:bake:subject-wrapper-edge",
        }
    ]
    graph_path.write_text(json.dumps(graph, sort_keys=True), encoding="utf-8")

    debt = _by_rule(_build(tmp_path), "security.wrapped_asset_classification.v1")

    assert debt is not None
    assert tuple(row["symbol"] for row in debt["trigger_aliases"]) == (
        "wasset",
        "wcoin",
    )


def test_wrapper_candidates_enumerate_function_callee_var_and_fallback_objects(
    tmp_path: Path,
) -> None:
    identity = "vault::native_walpha_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_walpha_approve",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": ["adapter::wbeta"],
            }
        },
        var_refs={
            "vault.wcoin": {
                "bare": "wcoin",
                "refs": [identity],
            }
        },
    )
    (tmp_path / "external_interfaces.md").write_text(
        "| src/adapter.sol:L40 | native wasset approve |\n",
        encoding="utf-8",
    )

    debt = _by_rule(_build(tmp_path), "security.wrapped_asset_classification.v1")

    assert debt is not None
    aliases = debt["trigger_aliases"]
    assert sorted(row["symbol"] for row in aliases) == [
        "walpha",
        "wasset",
        "wbeta",
        "wcoin",
    ]
    assert len({row["relation_id"] for row in aliases}) == 4
    assert any(row["object_id"].startswith("graph:function:") for row in aliases)
    assert any(row["object_id"].startswith("graph:callee:") for row in aliases)
    assert any(row["object_id"].startswith("graph:var:") for row in aliases)
    assert any(row["object_id"].startswith("fallback:") for row in aliases)


def test_same_wrapper_symbol_in_two_subjects_remains_two_exact_relations(
    tmp_path: Path,
) -> None:
    identities = ("alpha::native_wcoin_approve", "beta::native_wcoin_approve")
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_wcoin_approve",
                "loc": f"src/{index}.sol:L10",
                "callers": [],
                "callees": [],
            }
            for index, identity in enumerate(identities, start=1)
        },
    )

    debt = _by_rule(_build(tmp_path), "security.wrapped_asset_classification.v1")

    assert debt is not None
    assert len(debt["trigger_aliases"]) == 2
    assert {row["subject_id"] for row in debt["trigger_aliases"]} == {
        f"fn:{identity}" for identity in identities
    }
    assert len(set(debt["target_ids"])) == 2


def test_duplicate_fallback_occurrences_merge_sources_into_one_relation(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    sentence = "| src/adapter.sol:L40 | native wcoin approve |\n"
    (tmp_path / "external_interfaces.md").write_text(sentence, encoding="utf-8")
    (tmp_path / "integration_points.md").write_text(sentence, encoding="utf-8")

    debt = _by_rule(_build(tmp_path), "security.wrapped_asset_classification.v1")
    facts = json.loads((tmp_path / A.FEATURE_FACT_FILE).read_text(encoding="utf-8"))[
        "facts"
    ]
    ambiguous = [
        row for row in facts if row["concept"] == "wrapped_asset_ambiguous"
    ]

    assert debt is not None and len(debt["trigger_aliases"]) == 1
    assert len(ambiguous) == 1
    assert {row["artifact"] for row in ambiguous[0]["sources"]} == {
        "external_interfaces.md",
        "integration_points.md",
    }


def test_relation_conflict_retains_only_the_conflicted_object_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = "vault::native_wcoin_wasset_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_wcoin_wasset_approve",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _write_attested_wrapper_feature_facts(
        tmp_path,
        identity,
        (
            ("wcoin", "PRESENT"),
            ("wcoin", "ABSENT"),
            ("wasset", "PRESENT"),
        ),
    )
    _enable_test_only_terminal_attestation(monkeypatch)

    payload = _build(tmp_path)
    debt = _by_rule(payload, "security.wrapped_asset_classification.v1")
    native = _by_rule(payload, "security.native_wrapped_asset.v1")

    assert debt is not None
    assert [row["symbol"] for row in debt["trigger_aliases"]] == ["wcoin"]
    assert debt["state"] == "CONFLICTED_REVIEW"
    assert native is not None
    conflicts = json.loads(
        (tmp_path / A.FEATURE_FACT_FILE).read_text(encoding="utf-8")
    )["conflicts"]
    assert len(conflicts) == 1
    assert conflicts[0]["relation_id"].startswith("SWR-")


@pytest.mark.parametrize("schema", (A.RECON_FEATURE_SCHEMA, A.LEGACY_RECON_FEATURE_SCHEMA))
def test_malformed_or_legacy_recon_relation_cannot_suppress_object_debt(
    tmp_path: Path,
    schema: str,
) -> None:
    identity = "vault::native_wcoin_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_wcoin_approve",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    (tmp_path / A.RECON_FEATURE_FILE).write_text(
        json.dumps(
            {
                "schema_version": schema,
                "run_id": RUN_ID,
                "source_snapshot_digest": SNAPSHOT,
                "ecosystem": "evm",
                "facts": [
                    {
                        "subject_id": f"fn:{identity}",
                        "concept": "wrapped_asset",
                        "polarity": "PRESENT",
                        "relation": {
                            "kind": "WRAPPED_ASSET_CLASSIFICATION",
                            "object_id": "",
                            "symbol": "wcoin",
                        },
                        "evidence_identity": "recon:malformed-wrapper-edge",
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    payload = _build(tmp_path)
    debt = _by_rule(payload, "security.wrapped_asset_classification.v1")

    assert debt is not None
    assert [row["symbol"] for row in debt["trigger_aliases"]] == ["wcoin"]
    assert any("relation" in issue for issue in payload["issues"])
    assert payload["status"] == "DEGRADED_HUMAN_REVIEW"


def test_relation_symbol_mismatch_cannot_suppress_the_bound_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = "vault::native_wcoin_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_wcoin_approve",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _write_wrapper_feature_facts(tmp_path, identity, ("wcoin",))
    recon_path = tmp_path / A.RECON_FEATURE_FILE
    recon = json.loads(recon_path.read_text(encoding="utf-8"))
    recon["facts"][0]["relation"]["symbol"] = "wevil"
    recon_path.write_text(json.dumps(recon, sort_keys=True), encoding="utf-8")
    _enable_test_only_terminal_attestation(monkeypatch)

    payload = _build(tmp_path)
    debt = _by_rule(payload, "security.wrapped_asset_classification.v1")

    assert debt is not None
    assert [row["symbol"] for row in debt["trigger_aliases"]] == ["wcoin"]
    assert any("does not bind" in issue for issue in payload["issues"])


def test_duplicate_bare_var_ref_uses_exact_locus_instead_of_last_write_wins(
    tmp_path: Path,
) -> None:
    alpha = "alpha::native_approve"
    beta = "beta::native_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            alpha: {
                "bare": "native_approve",
                "loc": "src/alpha.sol:L10",
                "callers": [],
                "callees": [],
            },
            beta: {
                "bare": "native_approve",
                "loc": "src/beta.sol:L20",
                "callers": [],
                "callees": [],
            },
        },
        var_refs={
            "vault.wcoin": {
                "bare": "wcoin",
                "refs": ["native_approve (src/alpha.sol:L10)"],
            }
        },
    )

    payload = _build(tmp_path)
    debt = _by_rule(payload, "security.wrapped_asset_classification.v1")

    assert debt is not None
    assert [row["subject_id"] for row in debt["trigger_aliases"]] == [f"fn:{alpha}"]
    assert not any("ambiguous function binding" in issue for issue in payload["issues"])


def test_ambiguous_bare_var_ref_enumerates_all_subjects_and_flags_binding_debt(
    tmp_path: Path,
) -> None:
    identities = ("alpha::native_approve", "beta::native_approve")
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_approve",
                "loc": f"src/{index}.sol:L10",
                "callers": [],
                "callees": [],
            }
            for index, identity in enumerate(identities, start=1)
        },
        var_refs={
            "vault.wcoin": {
                "bare": "wcoin",
                "refs": ["native_approve"],
            }
        },
    )

    payload = _build(tmp_path)
    debt = _by_rule(payload, "security.wrapped_asset_classification.v1")

    assert debt is not None
    assert {row["subject_id"] for row in debt["trigger_aliases"]} == {
        f"fn:{identity}" for identity in identities
    }
    assert any("ambiguous function binding" in issue for issue in payload["issues"])
    assert payload["status"] == "DEGRADED_HUMAN_REVIEW"


def test_projection_exposes_every_exact_alias_symbol_and_object(tmp_path: Path) -> None:
    identity = "vault::native_wcoin_wasset_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_wcoin_wasset_approve",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )

    payload = _build(tmp_path, stage="pre_depth")
    debt = _by_rule(payload, "security.wrapped_asset_classification.v1")
    projection = (tmp_path / A.PROJECTION_FILE).read_text(encoding="utf-8")

    assert debt is not None
    assert "## Exact Trigger Aliases" in projection
    assert "### Exact finding evidence bindings" in projection
    assert "PLAMEN_SECURITY_OBLIGATION_EVIDENCE" in projection
    assert "plamen.security-obligation-evidence-binding.v1" in projection
    for alias in debt["trigger_aliases"]:
        assert alias["alias_id"] in projection
        assert alias["symbol"] in projection
        assert alias["object_id"] in projection
    assert "ALIAS:<SOT-ID>" in projection


def test_real_depth_prompt_requires_exact_finding_binding_marker() -> None:
    prompt = (
        Path(__file__).resolve().parents[1]
        / "prompts"
        / "shared"
        / "v2"
        / "phase4b-depth.md"
    ).read_text(encoding="utf-8")

    assert "PLAMEN_SECURITY_OBLIGATION_EVIDENCE" in prompt
    assert "copy the complete generated marker" in prompt.casefold()
    assert "normalized prose" in prompt.casefold()
    assert "remains queueable" in prompt.casefold()


@pytest.mark.parametrize(
    ("pipeline", "language", "role", "agent_id", "output"),
    (
        (
            "sc",
            "evm",
            "state_trace",
            "depth-state-trace",
            "depth_state_trace_findings.md",
        ),
        (
            "l1",
            "go",
            "state_trace",
            "depth-state-trace",
            "depth_state_trace_findings.md",
        ),
    ),
)
def test_real_depth_worker_prompt_carries_exact_binding_contract(
    tmp_path: Path,
    pipeline: str,
    language: str,
    role: str,
    agent_id: str,
    output: str,
) -> None:
    import plamen_driver as D

    job = {
        "agent_id": agent_id,
        "role": role,
        "output": output,
        "category": "standard",
        "focus": f"{pipeline} exact receipt binding",
    }
    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config={
            "language": language,
            "mode": "core",
            "pipeline": pipeline,
            "cli_backend": "claude",
        },
        attempt=1,
    )

    assert "PLAMEN_SECURITY_OBLIGATION_EVIDENCE" in prompt
    assert "copy the complete generated marker" in prompt.casefold()
    assert "original case" in prompt.casefold()
    assert "normalized prose" in prompt.casefold()
    assert "cannot bind" in prompt.casefold()
    if pipeline == "l1":
        methodology = (
            Path(__file__).resolve().parents[1]
            / "prompts"
            / "l1"
            / "phase4b-depth-driver.md"
        ).read_text(encoding="utf-8")
        assert "PLAMEN_SECURITY_OBLIGATION_EVIDENCE" in methodology
        assert "original case" in methodology.casefold()


@pytest.mark.parametrize(
    ("ecosystem", "provider"),
    (("sui", "move-source"), ("rust", "rust-source"), ("go", "go-source")),
)
def test_source_fallback_bake_preserves_callees_and_single_function_symbols(
    tmp_path: Path,
    ecosystem: str,
    provider: str,
) -> None:
    import recon_prepass as R

    _checkpoint(tmp_path, ecosystem=ecosystem)
    status = R._finalize_source_graph(
        tmp_path,
        provider,
        {"native_approve": "src/module.move:L10"},
        {"wcoin": {"native_approve"}},
        {"native_approve": {"wcoin"}},
    )
    assert status == "WRITTEN"
    graph = json.loads((tmp_path / "_mechanical_graph.json").read_text())
    assert graph["functions"]["native_approve"]["callees"] == ["wcoin"]
    assert graph["var_refs"]["wcoin"]["refs"] == [
        "native_approve (src/module.move:L10)"
    ]

    debt = _by_rule(_build(tmp_path), "security.wrapped_asset_classification.v1")

    assert debt is not None
    assert {row["symbol"] for row in debt["trigger_aliases"]} == {"wcoin"}
    assert {
        row["object_id"].split(":", 2)[1] for row in debt["trigger_aliases"]
    } == {"callee", "var"}


@pytest.mark.parametrize(
    ("covered_count", "expected_state"),
    (
        (1, "PARTIAL_PENDING_INDEPENDENT_VERIFICATION"),
        (2, "PENDING_INDEPENDENT_VERIFICATION"),
    ),
)
def test_bound_depth_receipts_cover_multi_alias_obligation_exactly(
    tmp_path: Path,
    covered_count: int,
    expected_state: str,
) -> None:
    identity = "vault::native_wcoin_wasset_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_wcoin_wasset_approve",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    pre = _build(tmp_path, stage="pre_depth")
    debt = _by_rule(pre, "security.wrapped_asset_classification.v1")
    assert debt is not None and len(debt["trigger_aliases"]) == 2
    _record_pre_authority(tmp_path)
    lines = "\n".join(
        "[OBLIG:security_obligations.md:SO-009] "
        f"ALIAS:{alias['alias_id']} STATUS:R "
        f"KEY:relation-{index} -> INV-001"
        for index, alias in enumerate(
            debt["trigger_aliases"][:covered_count], start=1
        )
    )
    _real_bound_depth_receipt(tmp_path, lines, finding_id="INV-001")

    post = _build(tmp_path, stage="post_depth")
    post_debt = _by_rule(post, "security.wrapped_asset_classification.v1")

    assert post_debt is not None
    assert post_debt["state"] == expected_state
    covered = {
        alias
        for receipt in post_debt["receipts"]
        for alias in receipt["covered_alias_ids"]
    }
    assert all(
        receipt["terminal_authority"] is False
        and receipt["pending_independent_verification"] is True
        for receipt in post_debt["receipts"]
    )
    assert covered == {
        alias["alias_id"] for alias in debt["trigger_aliases"][:covered_count]
    }
    pending = A.read_pending_security_obligation_verification(tmp_path)
    assert {row["alias_id"] for row in pending} == {
        alias["alias_id"] for alias in debt["trigger_aliases"][:covered_count]
    }
    repair = A.read_repairable_security_obligations(tmp_path)
    assert A.read_queueable_security_obligations(tmp_path) == repair
    if covered_count == 2:
        assert repair == []
    else:
        assert len(repair) == 1
        assert repair[0]["alias_id"] == debt["trigger_aliases"][1]["alias_id"]
        assert repair[0]["symbol"] == debt["trigger_aliases"][1]["symbol"]

    import mandatory_reverification as M

    bindings, candidates, adapter_debt, denominator = (
        M._compile_security_obligation_reverification_sources(tmp_path)
    )
    assert denominator == covered_count
    assert adapter_debt == []
    assert len(bindings) == 1
    assert len(candidates) == covered_count


def test_phaseio_bound_so010_hyphenated_identity_becomes_pending(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "Vault.native-token-route": {
                "bare": "native-token-route",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": ["Token.approve"],
            }
        },
    )
    pre = _build(tmp_path, stage="pre_depth")
    boundary = _by_rule(pre, "security.asset_representation_boundary.v1")
    assert boundary is not None and len(boundary["trigger_aliases"]) == 1
    alias = boundary["trigger_aliases"][0]
    assert "-" in alias["subject_id"] and "-" in alias["object_id"]
    _record_pre_authority(tmp_path)
    _real_bound_depth_receipt(
        tmp_path,
        "[OBLIG:security_obligations.md:SO-010] "
        f"ALIAS:{alias['alias_id']} STATUS:R KEY:exact-boundary -> INV-010",
        finding_id="INV-010",
    )

    post = _build(tmp_path, stage="post_depth")
    post_boundary = _by_rule(post, "security.asset_representation_boundary.v1")

    assert post_boundary is not None
    assert post_boundary["state"] == "PENDING_INDEPENDENT_VERIFICATION"
    assert post_boundary["receipts"][0]["terminal_authority"] is False
    assert (
        post_boundary["receipts"][0]["pending_independent_verification"] is True
    )


def test_phaseio_bound_so011_colon_occurrence_becomes_pending(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    occurrence = "occ:Vault:native-token:edge:7"
    graph = {
        "schema_version": F.MECHANICAL_GRAPH_SCHEMA_V3,
        "source": "typed-semantic-v3",
        "functions": {},
        "var_refs": {},
        "state_symbols": [],
        "semantic_edges": [
            {
                "kind": "REPRESENTATION_TRANSITION",
                "subject_id": "fn:Vault.native-token",
                "object_id": "type:WrappedAsset",
                "occurrence_id": occurrence,
                "source_path": "C:src/Vault.sol",
                "source_line": 7,
                "source_column": 3,
                "source_sha256": "c" * 64,
                "provider": "typed-semantic-v3",
            }
        ],
    }
    (tmp_path / "_mechanical_graph.json").write_text(
        json.dumps(graph, sort_keys=True), encoding="utf-8"
    )
    pre = _build(tmp_path, stage="pre_depth")
    repair = _by_rule(pre, "security.asset_representation_edge_repair.v1")
    assert repair is not None and len(repair["trigger_aliases"]) == 1
    alias = repair["trigger_aliases"][0]
    assert alias["object_id"] == occurrence and ":" in alias["symbol"]
    _record_pre_authority(tmp_path)
    _real_bound_depth_receipt(
        tmp_path,
        "[OBLIG:security_obligations.md:SO-011] "
        f"ALIAS:{alias['alias_id']} STATUS:R KEY:exact-occurrence -> INV-011",
        finding_id="INV-011",
    )

    post = _build(tmp_path, stage="post_depth")
    post_repair = _by_rule(post, "security.asset_representation_edge_repair.v1")

    assert post_repair is not None
    assert post_repair["state"] == "PENDING_INDEPENDENT_VERIFICATION"


def test_same_symbol_in_two_subjects_binds_only_exact_phaseio_alias(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "A.native_approve": {
                "bare": "native_approve",
                "loc": "src/A.sol:L10",
                "callers": [],
                "callees": [],
            },
            "B.native_approve": {
                "bare": "native_approve",
                "loc": "src/B.sol:L10",
                "callers": [],
                "callees": [],
            },
        },
        var_refs={
            "A.wCoin": {
                "bare": "wCoin",
                "refs": ["A.native_approve(src/A.sol:10)"],
            },
            "B.wCoin": {
                "bare": "wCoin",
                "refs": ["B.native_approve(src/B.sol:10)"],
            },
        },
    )
    pre = _build(tmp_path, stage="pre_depth")
    debt = _by_rule(pre, "security.wrapped_asset_classification.v1")
    assert debt is not None
    aliases = [
        alias
        for alias in debt["trigger_aliases"]
        if alias["object_id"] in {"graph:var:A.wCoin", "graph:var:B.wCoin"}
    ]
    assert len(aliases) == 2
    alias_a = next(alias for alias in aliases if alias["subject_id"].startswith("fn:A."))
    alias_b = next(alias for alias in aliases if alias["subject_id"].startswith("fn:B."))
    _record_pre_authority(tmp_path)
    receipt_lines = "\n".join(
        (
            "[OBLIG:security_obligations.md:SO-009] "
            f"ALIAS:{alias_a['alias_id']} STATUS:R KEY:exact-A -> INV-009",
            "[OBLIG:security_obligations.md:SO-009] "
            f"ALIAS:{alias_b['alias_id']} STATUS:R KEY:claimed-B -> INV-009",
        )
    )
    _real_bound_depth_receipt(
        tmp_path,
        receipt_lines,
        finding_id="INV-009",
        structured_aliases=[alias_a],
    )

    post = _build(tmp_path, stage="post_depth")
    post_debt = _by_rule(post, "security.wrapped_asset_classification.v1")
    pending = A.read_pending_security_obligation_verification(tmp_path)

    assert post_debt is not None
    assert post_debt["state"] == "PARTIAL_PENDING_INDEPENDENT_VERIFICATION"
    assert {row["alias_id"] for row in pending} == {alias_a["alias_id"]}
    b_receipt = next(
        receipt
        for receipt in post_debt["receipts"]
        if alias_b["alias_id"] in receipt["covered_alias_ids"]
    )
    assert b_receipt["pending_independent_verification"] is False


def test_exact_a_wcoin_binding_does_not_bind_b_wcoin() -> None:
    alias_a = {
        "alias_id": "SOT-" + "A" * 24,
        "subject_id": "fn:A.route",
        "relation_id": "SWR-" + "1" * 24,
        "object_id": "graph:var:A.wCoin",
        "symbol": "wCoin",
    }
    alias_b = {
        "alias_id": "SOT-" + "B" * 24,
        "subject_id": "fn:B.route",
        "relation_id": "SWR-" + "2" * 24,
        "object_id": "graph:var:B.wCoin",
        "symbol": "wCoin",
    }
    receipt = {
        "referent_alias_bindings": [
            {
                "schema_version": (
                    "plamen.security-obligation-evidence-binding.v1"
                ),
                **alias_a,
            }
        ]
    }

    assert A._reported_receipt_matches_alias(receipt, alias_a) is True
    assert A._reported_receipt_matches_alias(receipt, alias_b) is False


def test_case_distinct_path_siblings_and_legacy_normalized_evidence_do_not_cross_bind(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "Upper.native-token": {
                "bare": "native-token",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": ["Token.approve"],
            },
            "Lower.native-token": {
                "bare": "native-token",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": ["Token.approve"],
            },
        },
    )
    pre = _build(tmp_path, stage="pre_depth")
    boundary = _by_rule(pre, "security.asset_representation_boundary.v1")
    assert boundary is not None and len(boundary["trigger_aliases"]) == 2
    upper = next(
        alias for alias in boundary["trigger_aliases"]
        if alias["subject_id"].startswith("fn:Upper.")
    )
    lower = next(
        alias for alias in boundary["trigger_aliases"]
        if alias["subject_id"].startswith("fn:Lower.")
    )
    exact_receipt = {
        "referent_alias_bindings": [
            A._alias_evidence_binding(upper)
        ]
    }
    legacy_receipt = {
        "referent_identifiers": ["native", "token"],
        "referent_identifiers_exact": ["native", "token"],
        "referent_normalized": "uppernativetokensrcvaultsol",
    }

    assert A._reported_receipt_matches_alias(exact_receipt, upper) is True
    assert A._reported_receipt_matches_alias(exact_receipt, lower) is False
    assert A._reported_receipt_matches_alias(legacy_receipt, upper) is False
    assert A._reported_receipt_matches_alias(legacy_receipt, lower) is False


def test_attention_repair_preserves_one_queue_row_per_security_alias(
    tmp_path: Path,
) -> None:
    import plamen_mechanical as M

    identity = "vault::native_wcoin_wasset_approve"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": "native_wcoin_wasset_approve",
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    payload = _build(tmp_path, stage="post_depth")
    debt = _by_rule(payload, "security.wrapped_asset_classification.v1")
    assert debt is not None

    items = [
        row
        for row in M._build_attention_repair_items(tmp_path, "thorough")
        if row["kind"] == "security-obligation"
    ]

    assert [row["target"] for row in items] == [
        alias["alias_id"] for alias in debt["trigger_aliases"]
    ]
    assert {symbol for row in items for symbol in ("wasset", "wcoin") if symbol in row["reason"]} == {
        "wasset",
        "wcoin",
    }


def test_attention_repair_never_caps_exact_security_aliases_at_ten(
    tmp_path: Path,
) -> None:
    import plamen_mechanical as M

    symbols = [f"wcoin{index}" for index in range(12)]
    bare = "native_" + "_".join(symbols) + "_approve"
    identity = f"vault::{bare}"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": bare,
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    payload = _build(tmp_path, stage="post_depth")
    debt = _by_rule(payload, "security.wrapped_asset_classification.v1")
    assert debt is not None and len(debt["trigger_aliases"]) == 12

    items = [
        row
        for row in M._build_attention_repair_items(tmp_path, "thorough")
        if row["kind"] == "security-obligation"
    ]

    assert len(items) == 12
    assert {row["target"] for row in items} == {
        alias["alias_id"] for alias in debt["trigger_aliases"]
    }


@pytest.mark.parametrize("symbol_count", (1, 2))
def test_unrelated_reported_finding_cannot_self_certify_alias_application(
    tmp_path: Path,
    symbol_count: int,
) -> None:
    bare = (
        "native_wcoin_approve"
        if symbol_count == 1
        else "native_wcoin_wasset_approve"
    )
    identity = f"vault::{bare}"
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            identity: {
                "bare": bare,
                "loc": "src/Vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    pre = _build(tmp_path, stage="pre_depth")
    debt = _by_rule(pre, "security.wrapped_asset_classification.v1")
    assert debt is not None and len(debt["trigger_aliases"]) == symbol_count
    _record_pre_authority(tmp_path)
    lines = "\n".join(
        "[OBLIG:security_obligations.md:SO-009] "
        f"ALIAS:{alias['alias_id']} STATUS:R KEY:unrelated -> INV-777"
        for alias in debt["trigger_aliases"]
    )
    _real_bound_depth_receipt(
        tmp_path,
        lines,
        finding_id="INV-777",
        finding_evidence="Unrelated arithmetic observation in another component.",
    )

    post = _build(tmp_path, stage="post_depth")
    post_debt = _by_rule(post, "security.wrapped_asset_classification.v1")

    assert post_debt is not None and post_debt["state"] == "UNACCOUNTED"
    assert all(
        receipt["terminal_authority"] is False
        for receipt in post_debt["receipts"]
    )
    assert len(A.read_queueable_security_obligations(tmp_path)) == symbol_count
    assert A.read_pending_security_obligation_verification(tmp_path) == []
    assert any("lacks structural evidence" in issue for issue in post["issues"])


def test_documentation_only_keywords_do_not_create_obligations(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    (tmp_path / "recon_summary.md").write_text(
        "The documentation discusses an asset, a revert, and a struct.\n",
        encoding="utf-8",
    )

    payload = _build(tmp_path)

    assert payload["status"] == "COMPLETE"
    assert payload["obligations"] == []
    assert A.read_queueable_security_obligations(tmp_path) == []


def test_code_derived_graph_facts_fire_with_exact_provenance(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "bridge::refund_transfer_to_recipient": {
                "bare": "refund_transfer_to_recipient",
                "loc": "src/bridge.sol:L21",
                "callers": [],
                "callees": ["token.transfer (src/token.sol:L4)"],
            }
        },
        var_refs={
            "bridge.asset_balance": {
                "bare": "asset_balance",
                "refs": ["refund_transfer_to_recipient (src/bridge.sol:L21)"],
            }
        },
    )

    payload = _build(tmp_path)
    obligation = _by_rule(payload, "security.asset_binding.v1")

    assert obligation is not None
    assert obligation["state"] == "UNACCOUNTED"
    assert obligation["rule_version"] == "1.0.0"
    assert obligation["trigger_source"] == "TYPED_GRAPH_FACTS"
    assert len(obligation["fact_ids"]) >= 3
    assert obligation["trigger_aliases"]
    fact_payload = json.loads(
        (tmp_path / A.FEATURE_FACT_FILE).read_text(encoding="utf-8")
    )
    assert fact_payload["run_binding"]["run_id"] == RUN_ID
    assert fact_payload["run_binding"]["source_snapshot_digest"] == SNAPSHOT
    graph_binding = next(
        row
        for row in fact_payload["input_bindings"]
        if row["artifact"] == "_mechanical_graph.json"
    )
    assert graph_binding["sha256"] == _sha(
        (tmp_path / "_mechanical_graph.json").read_bytes()
    )


def test_required_features_must_cooccur_in_one_structural_context(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount": {
                "bare": "transfer_asset_amount",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            },
            "vault::recipient_address": {
                "bare": "recipient_address",
                "loc": "src/vault.sol:L30",
                "callers": [],
                "callees": [],
            },
        },
    )
    assert _by_rule(_build(tmp_path), "security.asset_binding.v1") is None

    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    assert _by_rule(_build(tmp_path), "security.asset_binding.v1") is not None


def test_repeated_fallback_prose_is_one_rule_owned_obligation(tmp_path: Path) -> None:
    _checkpoint(tmp_path, ecosystem="sui")
    sentence = (
        "| src/router.move:L44 | transfer asset amount to recipient address |\n"
    )
    (tmp_path / "external_interfaces.md").write_text(sentence, encoding="utf-8")
    (tmp_path / "integration_points.md").write_text(sentence, encoding="utf-8")

    payload = _build(tmp_path)
    rows = [
        row
        for row in payload["obligations"]
        if row["rule_id"] == "security.asset_binding.v1"
    ]

    assert len(rows) == 1
    assert rows[0]["trigger_source"] == "STRUCTURED_FALLBACK"
    assert len(rows[0]["trigger_aliases"]) == 1
    assert payload["status"] == "DEGRADED_HUMAN_REVIEW"


def test_current_depth_receipt_accounts_only_its_obligation(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _build(tmp_path, stage="pre_depth")
    _record_pre_authority(tmp_path)
    _real_bound_depth_receipt(
        tmp_path,
        "[OBLIG:security_obligations.md:SO-001] STATUS:R "
        "KEY:bound-transfer -> INV-001",
        finding_id="INV-001",
    )

    payload = _build(tmp_path, stage="post_depth")
    obligation = _by_rule(payload, "security.asset_binding.v1")

    assert obligation is not None
    assert obligation["state"] == "PENDING_INDEPENDENT_VERIFICATION"
    assert obligation["receipts"][0]["source_artifact"] == "depth_state_trace_findings.md"
    assert obligation["receipts"][0]["terminal_authority"] is False
    assert A.read_queueable_security_obligations(tmp_path) == []
    pending = A.read_pending_security_obligation_verification(tmp_path)
    assert len(pending) == 1
    assert pending[0]["display_id"] == "SO-001"
    assert set(pending[0]) == {
        "obligation_id",
        "display_id",
        "alias_id",
        "relation_id",
        "object_id",
        "symbol",
        "finding_id",
        "receipt_id",
        "question",
        "source_artifact",
        "source_artifact_sha256",
        "alias_binding_sha256",
    }
    assert pending[0]["finding_id"] == "INV-001"
    assert pending[0]["source_artifact"] == A.AUTHORITY_FILE
    assert len(pending[0]["source_artifact_sha256"]) == 64
    assert len(pending[0]["alias_binding_sha256"]) == 64
    assert pending[0]["source_artifact_sha256"].islower()
    assert pending[0]["alias_binding_sha256"].islower()

    import mandatory_reverification as M

    bindings, candidates, debts, denominator = (
        M._compile_security_obligation_reverification_sources(tmp_path)
    )
    assert denominator == 1
    assert debts == []
    assert len(bindings) == 1
    assert len(candidates) == 1
    assert candidates[0]["candidate_id"] == "INV-001"
    assert candidates[0]["source_candidate_id"] == pending[0]["alias_id"]


def test_reported_receipt_after_its_finding_is_pending_not_terminal(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _build(tmp_path, stage="pre_depth")
    _record_pre_authority(tmp_path)
    _real_bound_depth_receipt(
        tmp_path,
        "[OBLIG:security_obligations.md:SO-001] STATUS:R "
        "KEY:bound-transfer -> INV-001",
        finding_id="INV-001",
        receipt_after_finding=True,
    )

    payload = _build(tmp_path, stage="post_depth")
    obligation = _by_rule(payload, "security.asset_binding.v1")

    assert obligation is not None
    assert obligation["state"] == "PENDING_INDEPENDENT_VERIFICATION"
    assert A.read_repairable_security_obligations(tmp_path) == []
    assert len(A.read_pending_security_obligation_verification(tmp_path)) == 1


def test_explicit_unknown_alias_cannot_fall_back_to_the_only_current_alias(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _build(tmp_path, stage="pre_depth")
    _record_pre_authority(tmp_path)
    _real_bound_depth_receipt(
        tmp_path,
        "[OBLIG:security_obligations.md:SO-001] "
        "ALIAS:SOT-000000000000000000000000 STATUS:R "
        "KEY:wrong-alias -> INV-001",
        finding_id="INV-001",
    )

    payload = _build(tmp_path, stage="post_depth")
    obligation = _by_rule(payload, "security.asset_binding.v1")

    assert obligation is not None and obligation["state"] == "UNACCOUNTED"
    assert len(A.read_repairable_security_obligations(tmp_path)) == 1
    assert A.read_pending_security_obligation_verification(tmp_path) == []
    assert any("unknown current alias" in issue for issue in payload["issues"])


def test_post_ownership_transfer_keeps_exact_pre_history_authoritative(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _build(tmp_path, stage="pre_depth")
    _record_pre_authority(tmp_path)
    _real_bound_depth_receipt(
        tmp_path,
        "[OBLIG:security_obligations.md:SO-001] STATUS:R "
        "KEY:bound-transfer -> INV-001",
        finding_id="INV-001",
    )
    first_post = _build(tmp_path, stage="post_depth")
    assert (
        _by_rule(first_post, "security.asset_binding.v1")["state"]
        == "PENDING_INDEPENDENT_VERIFICATION"
    )
    _record_post_authority(tmp_path)

    rederived = _build(tmp_path, stage="post_depth")

    assert (
        _by_rule(rederived, "security.asset_binding.v1")["state"]
        == "PENDING_INDEPENDENT_VERIFICATION"
    )


def test_one_legacy_receipt_cannot_clear_multiple_structural_targets(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            },
            "queue::send_token_balance_to_beneficiary": {
                "bare": "send_token_balance_to_beneficiary",
                "loc": "src/queue.sol:L22",
                "callers": [],
                "callees": [],
            },
        },
    )
    _build(tmp_path, stage="pre_depth")
    _record_pre_authority(tmp_path)
    _real_bound_depth_receipt(
        tmp_path,
        "[OBLIG:security_obligations.md:SO-001] STATUS:R "
        "KEY:one-target -> INV-001",
        finding_id="INV-001",
    )

    payload = _build(tmp_path, stage="post_depth")
    obligation = _by_rule(payload, "security.asset_binding.v1")

    assert obligation is not None
    assert len(obligation["trigger_aliases"]) == 2
    # A legacy receipt without an exact alias cannot choose one member of a
    # multi-relation obligation. Treating it as partial would let producer
    # prose self-certify which relation was covered.
    assert obligation["state"] == "UNACCOUNTED"
    assert A.read_queueable_security_obligations(tmp_path)[0]["id"] == "SO-001"


def test_pre_depth_stage_never_consumes_current_partial_receipts(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _build(tmp_path, stage="pre_depth")
    _record_pre_authority(tmp_path)
    _real_bound_depth_receipt(
        tmp_path,
        "[OBLIG:security_obligations.md:SO-001] STATUS:R "
        "KEY:bound-transfer -> INV-001",
        finding_id="INV-001",
    )

    pre = _build(tmp_path, stage="pre_depth")
    pre_obligation = _by_rule(pre, "security.asset_binding.v1")
    assert pre["stage"] == "pre_depth"
    assert pre_obligation is not None
    assert pre_obligation["state"] == "UNACCOUNTED"
    assert pre_obligation["receipts"] == []

    post = _build(tmp_path, stage="post_depth")
    assert post["stage"] == "post_depth"
    assert (
        _by_rule(post, "security.asset_binding.v1")["state"]
        == "PENDING_INDEPENDENT_VERIFICATION"
    )


def test_stage_is_explicit_and_rejects_unknown_values(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    with pytest.raises(ValueError, match="pre_depth or post_depth"):
        _build(tmp_path, stage="during_depth")
    with pytest.raises(ValueError, match="pre_depth or post_depth"):
        A.security_obligation_input_artifacts(tmp_path, stage="during_depth")


def test_pre_input_artifacts_are_the_exact_existing_common_denominator(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    (tmp_path / A.RECON_FEATURE_FILE).write_text("{}\n", encoding="utf-8")
    (tmp_path / "external_interfaces.md").write_text("# interfaces\n", encoding="utf-8")
    (tmp_path / "caller_map.md").write_text("# callers\n", encoding="utf-8")
    (tmp_path / "unrelated.md").write_text("not a derivation input\n", encoding="utf-8")
    (tmp_path / A.APPLICATION_RECEIPT_FILE).write_text("{}\n", encoding="utf-8")

    inputs = A.security_obligation_input_artifacts(tmp_path, stage="pre_depth")

    assert inputs == tuple(sorted(inputs))
    assert set(inputs) == {
        "_mechanical_graph.json",
        "_v2_checkpoint.json",
        "caller_map.md",
        "external_interfaces.md",
        A.RECON_FEATURE_FILE,
    }


def test_post_input_artifacts_follow_safe_declared_outputs_and_receipt_evidence(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    pre = _build(tmp_path, stage="pre_depth")
    for name in (
        "depth_a_findings.md",
        "depth_b_findings.md",
        "depth_c_findings.md",
        "verify_evidence.md",
        "unrelated.md",
        "_artifact_state.json",
    ):
        (tmp_path / name).write_text(f"{name}\n", encoding="utf-8")
    contract = {
        "phase": "depth",
        "canonical_outputs": [
            "depth_a_findings.md",
            "../escape.md",
            "_artifact_state.json",
        ],
        "outputs": ["depth_b_findings.md", "missing.md"],
        "jobs": [
            {"output": "depth_c_findings.md"},
            {"output": "..\\escape.md"},
        ],
    }
    (tmp_path / "_depth_worker_pool_contract.json").write_text(
        json.dumps(contract), encoding="utf-8"
    )
    receipt = {
        "schema_version": A.APPLICATION_RECEIPT_SCHEMA,
        "run_id": RUN_ID,
        "source_snapshot_digest": SNAPSHOT,
        "authority_universe_digest": pre["authority_universe_digest"],
        "receipts": [
            {
                "disposition": "REPORTED",
                "reason": "candidate delivered",
                "evidence_bindings": [
                    {"artifact": "verify_evidence.md", "sha256": "0" * 64},
                    {"artifact": "../outside.md", "sha256": "0" * 64},
                    {"artifact": "_artifact_state.json", "sha256": "0" * 64},
                    {"artifact": "missing_evidence.md", "sha256": "0" * 64},
                ],
            }
        ],
    }
    (tmp_path / A.APPLICATION_RECEIPT_FILE).write_text(
        json.dumps(receipt), encoding="utf-8"
    )

    inputs = A.security_obligation_input_artifacts(tmp_path, stage="post_depth")

    assert inputs == tuple(sorted(inputs))
    assert set(inputs) == {
        "_depth_worker_pool_contract.json",
        "_mechanical_graph.json",
        "_v2_checkpoint.json",
        A.APPLICATION_RECEIPT_FILE,
        "depth_a_findings.md",
        "depth_b_findings.md",
        "depth_c_findings.md",
        "verify_evidence.md",
    }
    assert "_artifact_state.json" not in inputs
    assert "unrelated.md" not in inputs

    receipt["run_id"] = "87654321-4321-4321-8321-cba987654321"
    (tmp_path / A.APPLICATION_RECEIPT_FILE).write_text(
        json.dumps(receipt), encoding="utf-8"
    )
    stale_inputs = A.security_obligation_input_artifacts(
        tmp_path, stage="post_depth"
    )
    assert "verify_evidence.md" not in stale_inputs
    assert A.APPLICATION_RECEIPT_FILE in stale_inputs


def test_malformed_dynamic_parent_is_bound_without_guessing_child_inputs(
    tmp_path: Path,
) -> None:
    (tmp_path / "_depth_worker_pool_contract.json").write_text(
        '{"phase":"depth","outputs":', encoding="utf-8"
    )
    (tmp_path / A.APPLICATION_RECEIPT_FILE).write_text(
        '{"receipts":', encoding="utf-8"
    )
    (tmp_path / "depth_a_findings.md").write_text("child\n", encoding="utf-8")
    (tmp_path / "verify_evidence.md").write_text("child\n", encoding="utf-8")

    inputs = A.security_obligation_input_artifacts(tmp_path, stage="post_depth")

    assert inputs == (
        "_depth_worker_pool_contract.json",
        A.APPLICATION_RECEIPT_FILE,
    )


def test_artifact_binding_without_real_worker_unit_is_not_receipt_authority(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _fake_bound_depth_receipt(
        tmp_path,
        "[OBLIG:security_obligations.md:SO-001] STATUS:R "
        "KEY:unowned -> INV-001",
    )

    payload = _build(tmp_path, stage="post_depth")
    obligation = _by_rule(payload, "security.asset_binding.v1")
    assert obligation is not None and obligation["state"] == "UNACCOUNTED"
    assert any("owner work unit" in issue for issue in payload["issues"])


@pytest.mark.parametrize(
    "mutation",
    (
        "missing_prelaunch_sidecar",
        "missing_pre_producer",
        "output_record_drift",
        "pre_output_contract_drift",
        "pre_output_launch_drift",
        "pre_global_binding_drift",
    ),
)
def test_depth_receipt_requires_exact_worker_and_pre_sidecar_authority(
    tmp_path: Path,
    mutation: str,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _build(tmp_path, stage="pre_depth")
    _record_pre_authority(tmp_path)
    _real_bound_depth_receipt(
        tmp_path,
        "[OBLIG:security_obligations.md:SO-001] STATUS:R "
        "KEY:bound-transfer -> INV-001",
        finding_id="INV-001",
    )
    ledger_path = tmp_path / "_artifact_state.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    output_identity = "scratchpad:depth_state_trace_findings.md"
    owner_key = ledger["artifact_bindings"][output_identity]["owner_key"]
    owner = ledger["work_units"][owner_key]
    if mutation == "missing_prelaunch_sidecar":
        owner["input_bindings"].pop(
            "scratchpad:security_obligation_authority.json"
        )
        owner["input_set_digest"] = A._input_set_digest(owner["input_bindings"])
    elif mutation == "missing_pre_producer":
        pre_key = owner["input_bindings"][
            "scratchpad:security_obligation_authority.json"
        ]["producer_work_unit_key"]
        ledger["work_units"].pop(pre_key)
    elif mutation == "output_record_drift":
        owner["artifacts"][output_identity]["sha256"] = "0" * 64
    else:
        pre_identity = "scratchpad:security_obligation_authority.json"
        pre_key = owner["input_bindings"][pre_identity]["producer_work_unit_key"]
        pre_owner = ledger["work_units"][pre_key]
        if mutation == "pre_output_contract_drift":
            pre_owner["artifacts"][pre_identity]["contract_digest"] = "0" * 64
        elif mutation == "pre_output_launch_drift":
            pre_owner["artifacts"][pre_identity]["launch_digest"] = "0" * 64
        else:
            ledger["artifact_bindings"][pre_identity]["sha256"] = "0" * 64
    ledger_path.write_text(json.dumps(ledger, sort_keys=True), encoding="utf-8")

    payload = _build(tmp_path, stage="post_depth")
    obligation = _by_rule(payload, "security.asset_binding.v1")
    assert obligation is not None and obligation["state"] == "UNACCOUNTED"
    assert any("unbound depth receipt artifact ignored" in issue for issue in payload["issues"])


@pytest.mark.parametrize("disposition", ("REPORTED", "DISMISSED_EVIDENCE"))
def test_unowned_typed_application_receipt_is_review_evidence_not_terminal(
    tmp_path: Path, disposition: str
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    pre = _build(tmp_path, stage="pre_depth")
    obligation = _by_rule(pre, "security.asset_binding.v1")
    assert obligation is not None
    evidence = tmp_path / "verify_receipt.md"
    evidence.write_text("independent authority is intentionally absent\n", encoding="utf-8")
    receipt = {
        "schema_version": A.APPLICATION_RECEIPT_SCHEMA,
        "run_id": RUN_ID,
        "source_snapshot_digest": SNAPSHOT,
        "authority_universe_digest": pre["authority_universe_digest"],
        "receipts": [
            {
                "display_id": obligation["display_id"],
                "obligation_id": obligation["obligation_id"],
                "disposition": disposition,
                "reason": "typed producer proposed this outcome",
                "covered_alias_ids": obligation["trigger_aliases"],
                "evidence_bindings": [
                    {
                        "artifact": evidence.name,
                        "sha256": _sha(evidence.read_bytes()),
                    }
                ],
            }
        ],
    }
    (tmp_path / A.APPLICATION_RECEIPT_FILE).write_text(
        json.dumps(receipt, sort_keys=True), encoding="utf-8"
    )

    post = _build(tmp_path, stage="post_depth")
    current = _by_rule(post, "security.asset_binding.v1")

    assert current is not None and current["state"] == "UNACCOUNTED"
    assert current["receipts"][0]["terminal_authority"] is False
    assert any("unowned typed application receipt" in issue for issue in post["issues"])


@pytest.mark.parametrize(
    ("status", "target"),
    (("D", "locally-safe"), ("C", "verify")),
)
def test_producer_dismissal_or_carry_receipt_never_terminally_accounts(
    tmp_path: Path,
    status: str,
    target: str,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _build(tmp_path, stage="pre_depth")
    _record_pre_authority(tmp_path)
    _real_bound_depth_receipt(
        tmp_path,
        f"[OBLIG:security_obligations.md:SO-001] STATUS:{status} "
        f"KEY:producer-proposal -> {target}",
    )

    payload = _build(tmp_path, stage="post_depth")
    obligation = _by_rule(payload, "security.asset_binding.v1")
    assert obligation is not None and obligation["state"] == "UNACCOUNTED"
    assert obligation["receipts"][0]["terminal_authority"] is False
    assert A.read_queueable_security_obligations(tmp_path)[0]["id"] == "SO-001"
    assert A.read_pending_security_obligation_verification(tmp_path) == []


def test_reported_receipt_without_bound_finding_referent_stays_queueable(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _build(tmp_path, stage="pre_depth")
    _record_pre_authority(tmp_path)
    _real_bound_depth_receipt(
        tmp_path,
        "[OBLIG:security_obligations.md:SO-001] STATUS:R "
        "KEY:missing-referent -> INV-404",
    )

    payload = _build(tmp_path, stage="post_depth")
    obligation = _by_rule(payload, "security.asset_binding.v1")
    assert obligation is not None and obligation["state"] == "UNACCOUNTED"
    assert any("finding referent is not bound" in issue for issue in payload["issues"])


def test_stale_or_malformed_receipt_does_not_hide_work(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    (tmp_path / "depth_state_trace_findings.md").write_text(
        "[OBLIG:security_obligations.md:SO-001] STATUS:D KEY: -> safe\n",
        encoding="utf-8",
    )
    # No current worker-pool contract: arbitrary Markdown is not authority.
    payload = _build(tmp_path)
    obligation = _by_rule(payload, "security.asset_binding.v1")
    assert obligation is not None and obligation["state"] == "UNACCOUNTED"
    assert A.read_queueable_security_obligations(tmp_path)[0]["id"] == "SO-001"
    assert A.read_pending_security_obligation_verification(tmp_path) == []


def test_conflicting_typed_facts_remain_additive_review_work(tmp_path: Path) -> None:
    _checkpoint(tmp_path, ecosystem="solana")
    _graph(
        tmp_path,
        source="rust-source",
        functions={
            "program::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/lib.rs:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    recon = {
        "schema_version": A.RECON_FEATURE_SCHEMA,
        "run_id": RUN_ID,
        "source_snapshot_digest": SNAPSHOT,
        "ecosystem": "solana",
        "facts": [
            {
                "subject_id": "fn:program::transfer_asset_amount_to_recipient",
                "concept": "movement",
                "polarity": "ABSENT",
                "evidence_identity": "recon-row-7",
            }
        ],
    }
    (tmp_path / A.RECON_FEATURE_FILE).write_text(
        json.dumps(recon, sort_keys=True), encoding="utf-8"
    )

    payload = _build(tmp_path)
    obligation = _by_rule(payload, "security.asset_binding.v1")

    assert obligation is not None
    assert obligation["state"] == "CONFLICTED_REVIEW"
    assert obligation["conflict_ids"]
    assert A.read_queueable_security_obligations(tmp_path)[0]["id"] == "SO-001"


def test_non_evm_graph_facts_use_the_same_generic_rules(tmp_path: Path) -> None:
    _checkpoint(tmp_path, ecosystem="sui")
    _graph(
        tmp_path,
        source="move-source",
        functions={
            "bridge::decode_gateway_message_source_sender": {
                "bare": "decode_gateway_message_source_sender",
                "loc": "sources/bridge.move:L18",
                "callers": [],
                "callees": [],
            }
        },
    )

    payload = _build(tmp_path)
    obligation = _by_rule(payload, "security.cross_domain_message.v1")

    assert obligation is not None
    assert obligation["trigger_source"] == "TYPED_GRAPH_FACTS"
    assert payload["ecosystem"] == "sui"


def test_input_drift_invalidates_authority_and_projection_tamper_is_detected(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _build(tmp_path)
    assert A.validate_security_obligation_authority(tmp_path) == []

    graph_path = tmp_path / "_mechanical_graph.json"
    graph_path.write_text(graph_path.read_text() + "\n", encoding="utf-8")
    issues = A.validate_security_obligation_authority(tmp_path)
    assert any("authority differs from current inputs" in issue for issue in issues)

    _build(tmp_path)
    projection = tmp_path / A.PROJECTION_FILE
    projection.write_text(projection.read_text() + "tamper\n", encoding="utf-8")
    issues = A.validate_security_obligation_authority(tmp_path)
    assert any("projection differs" in issue for issue in issues)


def test_reader_rejects_self_digested_authority_stale_to_current_inputs(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    _build(tmp_path, stage="post_depth")
    graph_path = tmp_path / "_mechanical_graph.json"
    graph_path.write_text(graph_path.read_text() + "\n", encoding="utf-8")

    queue = A.read_queueable_security_obligations(tmp_path)

    assert queue[0]["id"] == "SO-000"
    assert queue[0]["signals"] == "FEATURE_FACT_AUTHORITY_STALE"
    pending = A.read_pending_security_obligation_verification(tmp_path)
    assert len(pending) == 1
    assert pending[0]["display_id"] == "SO-000"
    assert pending[0]["finding_id"] == ""
    assert "FEATURE_FACT_AUTHORITY_STALE" in pending[0]["question"]


def test_missing_feature_substrate_emits_visible_queueable_debt(tmp_path: Path) -> None:
    _checkpoint(tmp_path)

    payload = _build(tmp_path)
    queue = A.read_queueable_security_obligations(tmp_path)

    assert payload["status"] == "DEGRADED_HUMAN_REVIEW"
    assert payload["obligations"][0]["display_id"] == "SO-000"
    assert queue == [
        {
            "id": "SO-000",
            "class": "feature_fact_coverage_debt",
            "question": A.FEATURE_FACT_COVERAGE_QUESTION,
            "signals": "FEATURE_FACT_SUBSTRATE_UNAVAILABLE",
            "canonical_id": payload["obligations"][0]["obligation_id"],
            "state": "DEGRADED_REVIEW",
        }
    ]


def test_wrong_run_recon_fact_is_rejected_without_suppressing_graph_work(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    (tmp_path / A.RECON_FEATURE_FILE).write_text(
        json.dumps(
            {
                "schema_version": A.RECON_FEATURE_SCHEMA,
                "run_id": "87654321-4321-4321-8321-cba987654321",
                "source_snapshot_digest": SNAPSHOT,
                "ecosystem": "evm",
                "facts": [],
            }
        ),
        encoding="utf-8",
    )

    payload = _build(tmp_path)
    obligation = _by_rule(payload, "security.asset_binding.v1")

    assert obligation is not None and obligation["state"] == "UNACCOUNTED"
    assert any("run_id mismatch" in issue for issue in payload["issues"])
    assert payload["status"] == "DEGRADED_HUMAN_REVIEW"


def test_authority_is_idempotent_and_markdown_is_exact_projection(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )

    first = _build(tmp_path)
    files_before = {
        name: (tmp_path / name).read_bytes()
        for name in (A.FEATURE_FACT_FILE, A.AUTHORITY_FILE, A.PROJECTION_FILE)
    }
    second = _build(tmp_path)

    assert first == second
    assert files_before == {
        name: (tmp_path / name).read_bytes()
        for name in (A.FEATURE_FACT_FILE, A.AUTHORITY_FILE, A.PROJECTION_FILE)
    }


def test_reader_fails_open_to_review_when_authority_is_corrupt(tmp_path: Path) -> None:
    (tmp_path / A.AUTHORITY_FILE).write_text("{broken", encoding="utf-8")

    rows = A.read_queueable_security_obligations(tmp_path)

    assert rows[0]["id"] == "SO-000"
    assert rows[0]["class"] == "feature_fact_authority_debt"


def test_live_mechanical_reader_never_reconstructs_from_markdown(tmp_path: Path) -> None:
    import plamen_mechanical as mechanical

    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    assert mechanical._write_security_obligations(tmp_path, "thorough") == 1
    projection = tmp_path / A.PROJECTION_FILE
    projection.write_text(
        projection.read_text(encoding="utf-8")
        + "| SO-008 | fake | encoding_schema | UNACCOUNTED | fake | fake | fake |\n",
        encoding="utf-8",
    )

    rows = mechanical._parse_security_obligation_items(tmp_path)

    assert [row["id"] for row in rows] == ["SO-001"]
