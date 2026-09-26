"""Run12 security-obligation authority grammar and replay regressions."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import security_obligation_authority as A


RUN_ID = "12345678-1234-4234-9234-123456789abc"
PRE_KEY = "sc/thorough/evm/claude/depth/security_obligations.pre_depth"
POST_KEY = "sc/thorough/evm/claude/depth/security_obligations.post_depth"
DEPTH_KEY = "sc/thorough/evm/claude/depth/worker.state-trace"
SIDECARS = (
    A.FEATURE_FACT_FILE,
    A.AUTHORITY_FILE,
    A.PROJECTION_FILE,
)


def _output_spec(identity: str, owner_key: str) -> dict[str, object]:
    return {
        "identity": identity,
        "owner_key": owner_key,
        "artifact_class": "DRIVER_GENERATED",
        "writer": "DRIVER",
        "write_mode": "REPLACE",
        "schema_version": "fixture.v1",
        "minimum_gate": "EXACT_FIXTURE",
        "consumers": ["depth"],
        "condition_id": "",
    }


def _record(
    identity: str,
    owner_key: str,
    contract_digest: str,
    launch_digest: str,
    sha256: str,
) -> dict[str, object]:
    return {
        **_output_spec(identity, owner_key),
        "path": identity.split(":", 1)[1],
        "root": "scratchpad",
        "run_id": RUN_ID,
        "contract_digest": contract_digest,
        "launch_digest": launch_digest,
        "physical_identity": f"file:1:{len(identity)}",
        "status": "ACTIVE",
        "authority_level": "ACTIVE_AUTHORITY",
        "updated_at": "2026-09-10T00:00:00+00:00",
        "mtime_ns": 100 + len(identity),
        "size": len(identity),
        "sha256": sha256,
    }


def _manifest(owner_key: str) -> dict[str, object]:
    return {
        "key": owner_key,
        "model_invoked": False,
        "outputs": [
            _output_spec(f"scratchpad:{name}", owner_key)
            for name in SIDECARS
        ],
    }


def _replay_fixture() -> tuple[dict[str, object], dict[str, object]]:
    pre_manifest = _manifest(PRE_KEY)
    post_manifest = _manifest(POST_KEY)
    pre_digest = A._manifest_digest(pre_manifest)
    post_digest = A._manifest_digest(post_manifest)
    pre_launch = "a" * 64
    post_launch = "b" * 64
    pre_records: dict[str, dict[str, object]] = {}
    post_records: dict[str, dict[str, object]] = {}
    inputs: dict[str, dict[str, object]] = {}
    bindings: dict[str, dict[str, object]] = {}
    for ordinal, name in enumerate(SIDECARS, start=1):
        identity = f"scratchpad:{name}"
        pre = _record(identity, PRE_KEY, pre_digest, pre_launch, f"{ordinal}" * 64)
        post = _record(identity, POST_KEY, post_digest, post_launch, f"{ordinal + 3}" * 64)
        retired = copy.deepcopy(pre)
        retired.update(
            {
                "status": "SUPERSEDED",
                "authority_level": "RETIRED",
                "superseded_by_owner_key": POST_KEY,
            }
        )
        pre_records[identity] = pre
        post_records[identity] = post
        bindings[identity] = {**post, "history": [retired]}
        inputs[identity] = {
            "identity": identity,
            "input_class": "IMMUTABLE",
            "status": "ACTIVE",
            "size": pre["size"],
            "sha256": pre["sha256"],
            "producer_work_unit_key": PRE_KEY,
            "producer_contract_digest": pre_digest,
        }
    pre_owner = {
        "run_id": RUN_ID,
        "semantic_status": "ACTIVE",
        "contract_manifest": pre_manifest,
        "contract_digest": pre_digest,
        "launch_digest": pre_launch,
        "artifacts": pre_records,
    }
    post_owner = {
        "run_id": RUN_ID,
        "semantic_status": "ACTIVE",
        "execution_state": "OUTPUT_COMMITTED",
        "contract_manifest": post_manifest,
        "contract_digest": post_digest,
        "launch_digest": post_launch,
        "artifacts": post_records,
    }
    depth_owner = {
        "semantic_status": "ACTIVE",
        "contract_manifest": {
            "immutable_inputs": sorted(inputs),
            "bounded_lookup_inputs": [],
        },
        "input_bindings": inputs,
        "input_set_digest": A._input_set_digest(inputs),
    }
    ledger: dict[str, object] = {
        "artifact_bindings": bindings,
        "work_units": {
            PRE_KEY: pre_owner,
            POST_KEY: post_owner,
            DEPTH_KEY: depth_owner,
        },
    }
    return ledger, depth_owner


def test_finding_heading_grammar_accepts_h2_h3_h4_variants_and_ignores_fences() -> None:
    issues: list[str] = []
    text = (
        "## Finding [COLON-1]: colon title\ncolon body\n"
        "### Finding [DASH-A-2] - dash title\ndash body\n"
        "#### Finding [SPACE-3] whitespace title\nspace body\n"
        "## Finding [NO-TITLE-4]\nno-title body\n"
        "```markdown\n## Finding [FENCED-5]: example\n```\n"
    )

    sections = A._finding_sections(text, issues=issues, source_label="depth.md")

    assert set(sections) == {
        "colon-1",
        "dash-a-2",
        "space-3",
        "no-title-4",
    }
    assert issues == []


def test_duplicate_finding_ids_are_invalidated_case_insensitively() -> None:
    issues: list[str] = []
    sections = A._finding_sections(
        "## Finding [BLIND-A-1]: first\nfirst\n"
        "#### Finding [blind-a-1] - duplicate\nsecond\n"
        "## Finding [UNIQUE-2]\nkept\n",
        issues=issues,
        source_label="depth.md",
    )

    assert set(sections) == {"unique-2"}
    assert issues == [
        "duplicate finding referent invalidated locally: depth.md:blind-a-1"
    ]


def test_reported_target_resolves_unique_actual_multi_hyphen_id() -> None:
    sections = A._finding_sections(
        "## Finding [A-1]: short\nshort\n"
        "### Finding [BLIND-A-1] - full\nfull\n"
    )

    assert A._resolve_finding_referent("finding `blind-a-1`", sections) == (
        "blind-a-1"
    )
    assert A._resolve_finding_referent("A-1 and BLIND-A-1", sections) == ""
    assert A._resolve_finding_referent("BLIND-A-10", sections) == ""


def _depth_receipt_file(root: Path, body: str) -> None:
    output = "depth_state_trace_findings.md"
    (root / output).write_text(
        "<!-- PLAMEN_PHASE: depth -->\n"
        f"{body}\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )
    (root / "_depth_worker_pool_contract.json").write_text(
        json.dumps(
            {
                "phase": "depth",
                "canonical_outputs": [output],
                "outputs": [output],
                "jobs": [{"agent_id": "state-trace", "output": output}],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_fifty_four_exact_aliases_remain_distinct_and_never_collapse_to_so000(
    tmp_path: Path,
) -> None:
    (tmp_path / "_v2_checkpoint.json").write_text(
        json.dumps(
            {
                "run_id": RUN_ID,
                "config": {
                    "pipeline": "sc",
                    "language": "evm",
                    "mode": "thorough",
                },
                "audit_snapshot": {
                    "snapshot_digest": "c" * 64,
                    "components": {"source_scope": {"digest": "d" * 64}},
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    symbols = [f"wcoin{ordinal}" for ordinal in range(54)]
    bare = "native_" + "_".join(symbols) + "_approve"
    (tmp_path / "_mechanical_graph.json").write_text(
        json.dumps(
            {
                "schema_version": "plamen.mechanical-graph.v2",
                "source": "evm-source",
                "functions": {
                    f"vault::{bare}": {
                        "bare": bare,
                        "loc": "src/Vault.sol:L10",
                        "callers": [],
                        "callees": [],
                    }
                },
                "var_refs": {},
                "state_symbols": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    authority = A.write_security_obligation_authority(
        tmp_path, stage=A.PRE_DEPTH_STAGE
    )
    obligation = next(
        row
        for row in authority["obligations"]
        if row["rule_id"] == "security.wrapped_asset_classification.v1"
    )
    aliases = obligation["trigger_aliases"]

    assert obligation["display_id"] == "SO-009"
    assert len(aliases) == 54
    assert len({row["alias_id"] for row in aliases}) == 54
    assert {row["symbol"] for row in aliases} == set(symbols)
    assert all(row["alias_id"].startswith("SOT-") for row in aliases)


def test_depth_receipt_binds_case_insensitive_multi_hyphen_actual_section(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _depth_receipt_file(
        tmp_path,
        "[OBLIG:security_obligations.md:SO-001] STATUS:R "
        "KEY:exact -> blind-a-1\n"
        "### Finding [BLIND-A-1]: exact finding\nBound body.",
    )
    monkeypatch.setattr(
        A,
        "_bound_depth_output",
        lambda *args, **kwargs: (
            {
                "artifact": "_artifact_state.json#fixture",
                "role": "depth_output_run_binding",
                "sha256": "a" * 64,
                "byte_count": 1,
            },
            "",
        ),
    )
    issues: list[str] = []

    receipts = A._depth_receipts(
        tmp_path,
        [],
        issues,
        {"run_id": RUN_ID, "source_snapshot_digest": "c" * 64},
    )

    assert len(receipts) == 1
    assert receipts[0]["finding_id"] == "BLIND-A-1"
    assert issues == []


@pytest.mark.parametrize("status", ("C", "D"))
def test_carry_and_dismissal_accept_bounded_freeform_punctuation_but_stay_debt(
    status: str,
) -> None:
    target = "reviewed: path/to:file.sol#L7 (reason? yes!)"
    assert A._valid_legacy_receipt(status, "bounded-key", target) is True
    assert A._valid_legacy_receipt(status, "bounded-key", "n/a") is False
    assert A._valid_legacy_receipt(
        status,
        "bounded-key",
        "x" * (A._MAX_LEGACY_RECEIPT_TARGET_LENGTH + 1),
    ) is False
    obligation = {
        "obligation_id": "SOBL-" + "A" * 24,
        "display_id": "SO-001",
        "state": "UNACCOUNTED",
        "conflict_ids": [],
        "trigger_aliases": [],
        "receipts": [],
    }
    receipt = {
        "receipt_id": "SOR-" + "B" * 24,
        "receipt_kind": "BOUND_DEPTH_MARKDOWN",
        "display_id": "SO-001",
        "status": status,
        "target": target,
        "terminal_authority": False,
        "pending_independent_verification": False,
    }

    A._apply_receipts([obligation], [receipt], [])

    assert obligation["state"] == "UNACCOUNTED"
    assert obligation["receipts"][0]["terminal_authority"] is False
    assert obligation["receipts"][0]["pending_independent_verification"] is False


@pytest.mark.parametrize("status", ("C", "D"))
def test_depth_carry_and_dismissal_diagnostic_waits_for_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    target = "reviewed: path/to:file.sol#L7 (reason? yes!)"
    _depth_receipt_file(
        tmp_path,
        "[OBLIG:security_obligations.md:SO-001] "
        f"STATUS:{status} KEY:bounded-key -> {target}",
    )
    monkeypatch.setattr(
        A,
        "_bound_depth_output",
        lambda *args, **kwargs: (
            {
                "artifact": "_artifact_state.json#fixture",
                "role": "depth_output_run_binding",
                "sha256": "a" * 64,
                "byte_count": 1,
            },
            "",
        ),
    )
    issues: list[str] = []

    receipts = A._depth_receipts(
        tmp_path,
        [],
        issues,
        {"run_id": RUN_ID, "source_snapshot_digest": "c" * 64},
    )

    assert len(receipts) == 1
    assert receipts[0]["target"] == target
    assert receipts[0]["terminal_authority"] is False
    assert receipts[0]["pending_independent_verification"] is False
    assert issues == []


def test_run19_mixed_report_and_queueable_dispositions_cover_alias_denominator_without_phase_debt() -> None:
    alias_a = "SOT-" + "A" * 24
    alias_b = "SOT-" + "B" * 24
    obligation = {
        "obligation_id": "SOBL-" + "C" * 24,
        "display_id": "SO-001",
        "state": "UNACCOUNTED",
        "conflict_ids": [],
        "trigger_aliases": [
            {"alias_id": alias_a, "subject_id": "fn:Vault.a"},
            {"alias_id": alias_b, "subject_id": "fn:Vault.b"},
        ],
        "receipts": [],
    }
    receipts = [
        {
            "receipt_id": "SOR-" + "1" * 24,
            "receipt_kind": "BOUND_DEPTH_MARKDOWN",
            "display_id": "SO-001",
            "status": "C",
            "covered_alias_ids": [alias_a],
            "pending_independent_verification": False,
            "terminal_authority": False,
        },
        {
            "receipt_id": "SOR-" + "2" * 24,
            "receipt_kind": "BOUND_DEPTH_MARKDOWN",
            "display_id": "SO-001",
            "status": "D",
            "covered_alias_ids": [alias_a],
            "pending_independent_verification": False,
            "terminal_authority": False,
        },
        {
            "receipt_id": "SOR-" + "3" * 24,
            "receipt_kind": "BOUND_DEPTH_MARKDOWN",
            "display_id": "SO-001",
            "status": "C",
            "covered_alias_ids": [alias_b],
            "pending_independent_verification": False,
            "terminal_authority": False,
        },
        {
            "receipt_id": "SOR-" + "4" * 24,
            "receipt_kind": "BOUND_DEPTH_MARKDOWN",
            "display_id": "SO-001",
            "status": "R",
            "covered_alias_ids": [alias_b],
            "pending_independent_verification": False,
            "terminal_authority": False,
            "referent_alias_bindings": [
                A._alias_evidence_binding(
                    {"alias_id": alias_b, "subject_id": "fn:Vault.b"}
                )
            ],
        },
    ]
    issues: list[str] = []

    A._apply_receipts([obligation], receipts, issues)
    A._append_unresolved_producer_disposition_issues([obligation], issues)

    assert obligation["state"] == "PARTIAL_PENDING_INDEPENDENT_VERIFICATION"
    assert issues == []
    # The unresolved C/D alias remains encoded in the obligation/receipt
    # denominator for the repair consumer; it is not converted into a depth
    # phase-integrity error.
    assert {
        receipt["status"]
        for receipt in obligation["receipts"]
        if alias_a in receipt.get("covered_alias_ids", [])
    } == {"C", "D"}


def test_mixed_dispositions_fail_visible_when_depth_pool_omits_structural_alias() -> None:
    alias_a = "SOT-" + "A" * 24
    alias_b = "SOT-" + "B" * 24
    obligation = {
        "obligation_id": "SOBL-" + "C" * 24,
        "display_id": "SO-001",
        "state": "UNACCOUNTED",
        "conflict_ids": [],
        "trigger_aliases": [
            {"alias_id": alias_a, "subject_id": "fn:Vault.a"},
            {"alias_id": alias_b, "subject_id": "fn:Vault.b"},
        ],
        "receipts": [],
    }
    receipts = [
        {
            "receipt_id": "SOR-" + "1" * 24,
            "receipt_kind": "BOUND_DEPTH_MARKDOWN",
            "display_id": "SO-001",
            "status": "R",
            "covered_alias_ids": [alias_b],
            "pending_independent_verification": False,
            "terminal_authority": False,
            "referent_alias_bindings": [
                A._alias_evidence_binding(
                    {"alias_id": alias_b, "subject_id": "fn:Vault.b"}
                )
            ],
        },
    ]
    issues: list[str] = []

    A._apply_receipts([obligation], receipts, issues)

    assert obligation["state"] == "PARTIAL_PENDING_INDEPENDENT_VERIFICATION"
    assert issues == [
        "SO-001 depth receipt set does not enumerate every structural target alias",
    ]


def test_empty_depth_receipt_set_cannot_silently_skip_alias_denominator() -> None:
    alias = "SOT-" + "A" * 24
    obligation = {
        "obligation_id": "SOBL-" + "C" * 24,
        "display_id": "SO-001",
        "state": "UNACCOUNTED",
        "conflict_ids": [],
        "trigger_aliases": [
            {"alias_id": alias, "subject_id": "fn:Vault.only"},
        ],
        "receipts": [],
    }
    issues: list[str] = []

    A._apply_receipts([obligation], [], issues)

    assert obligation["state"] == "UNACCOUNTED"
    assert issues == [
        "SO-001 depth receipt set does not enumerate every structural target alias",
    ]


def test_post_source_lifecycle_without_depth_contract_has_no_receipt_denominator() -> None:
    alias = "SOT-" + "A" * 24
    obligation = {
        "obligation_id": "SOBL-" + "C" * 24,
        "display_id": "SO-001",
        "state": "UNACCOUNTED",
        "conflict_ids": [],
        "trigger_aliases": [
            {"alias_id": alias, "subject_id": "fn:Vault.only"},
        ],
        "receipts": [],
    }
    issues: list[str] = []

    A._apply_receipts(
        [obligation], [], issues, require_depth_enumeration=False
    )

    assert obligation["state"] == "UNACCOUNTED"
    assert issues == []


def test_singleton_carry_without_alias_enumerates_contract_denominator() -> None:
    alias = "SOT-" + "A" * 24
    obligation = {
        "obligation_id": "SOBL-" + "C" * 24,
        "display_id": "SO-001",
        "state": "UNACCOUNTED",
        "conflict_ids": [],
        "trigger_aliases": [
            {"alias_id": alias, "subject_id": "fn:Vault.only"},
        ],
        "receipts": [],
    }
    receipt = {
        "receipt_id": "SOR-" + "1" * 24,
        "receipt_kind": "BOUND_DEPTH_MARKDOWN",
        "display_id": "SO-001",
        "status": "C",
        "covered_alias_ids": [],
        "pending_independent_verification": False,
        "terminal_authority": False,
    }
    issues: list[str] = []

    A._apply_receipts([obligation], [receipt], issues)

    assert issues == []
    assert obligation["receipts"][0]["covered_alias_ids"] == [alias]


def test_full_pre_to_post_supersession_replays_all_three_sidecars() -> None:
    ledger, depth_owner = _replay_fixture()

    assert A._validate_pre_sidecar_consumption(
        ledger, depth_owner, run_id=RUN_ID
    ) == ""


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        ("missing_history", "history missing"),
        ("unrelated_superseder", "not the POST authority"),
        ("inactive_post", "not currently active"),
        ("wrong_post_unit", "not the POST authority"),
        ("history_owner_drift", "does not replay"),
        ("history_hash_drift", "does not replay"),
        ("history_writer_drift", "does not replay"),
        ("history_schema_drift", "does not replay"),
        ("history_physical_drift", "does not replay"),
        ("history_contract_drift", "does not replay"),
        ("wrong_superseded_by", "does not replay"),
    ),
)
def test_pre_to_post_supersession_rejects_tamper(
    mutation: str, expected: str
) -> None:
    ledger, depth_owner = _replay_fixture()
    identity = f"scratchpad:{A.AUTHORITY_FILE}"
    binding = ledger["artifact_bindings"][identity]
    history = binding["history"][0]
    post_owner = ledger["work_units"][POST_KEY]
    if mutation == "missing_history":
        binding["history"] = []
    elif mutation == "unrelated_superseder":
        binding["owner_key"] = "sc/thorough/evm/claude/depth/worker.other"
    elif mutation == "inactive_post":
        binding["status"] = "RETIRED"
    elif mutation == "wrong_post_unit":
        wrong = "sc/thorough/evm/claude/depth/security_obligations.pre_depth"
        binding["owner_key"] = wrong
    elif mutation == "history_owner_drift":
        history["owner_key"] = "sc/thorough/evm/claude/depth/worker.other"
    elif mutation == "history_hash_drift":
        history["sha256"] = "f" * 64
    elif mutation == "history_writer_drift":
        history["writer"] = "MODEL"
    elif mutation == "history_schema_drift":
        history["schema_version"] = "tampered.v1"
    elif mutation == "history_physical_drift":
        history["physical_identity"] = "file:9:9"
    elif mutation == "history_contract_drift":
        history["contract_digest"] = "f" * 64
    elif mutation == "wrong_superseded_by":
        history["superseded_by_owner_key"] = PRE_KEY
    else:  # pragma: no cover - closed parametrization
        raise AssertionError(mutation)

    issue = A._validate_pre_sidecar_consumption(
        ledger, depth_owner, run_id=RUN_ID
    )

    assert expected in issue
    assert post_owner["semantic_status"] == "ACTIVE"


def test_active_pre_replay_remains_valid_before_post_publication() -> None:
    ledger, depth_owner = _replay_fixture()
    pre_owner = ledger["work_units"][PRE_KEY]
    ledger["artifact_bindings"] = {
        identity: {**copy.deepcopy(record), "history": []}
        for identity, record in pre_owner["artifacts"].items()
    }

    assert A._validate_pre_sidecar_consumption(
        ledger, depth_owner, run_id=RUN_ID
    ) == ""


STAGED_OUTPUT = "scratchpad:depth_state_trace_findings.md"


def _staged_alias(
    ordinal: int = 1,
    *,
    subject_id: str = "src/Vault.sol::withdraw",
) -> dict[str, str]:
    return {
        "alias_id": f"SOT-{ordinal:024X}",
        "subject_id": subject_id,
        "relation_id": f"REL-{ordinal}",
        "object_id": f"asset:{ordinal}",
        "symbol": f"wCOIN{ordinal}",
    }


def _staged_pre_authority(
    display_aliases: tuple[tuple[str, list[dict[str, str]]], ...] | None = None,
) -> bytes:
    if display_aliases is None:
        display_aliases = (("SO-001", [_staged_alias()]),)
    obligations: list[dict[str, object]] = []
    for ordinal, (display, aliases) in enumerate(display_aliases, start=1):
        obligations.append(
            {
                "obligation_id": f"SOBL-{ordinal:024X}",
                "display_id": display,
                "rule_id": f"security.fixture.{ordinal}.v1",
                "rule_version": "1.0.0",
                "fact_ids": [f"SFF-{ordinal:024X}"],
                "target_ids": [aliases[0]["subject_id"]] if aliases else [],
                "trigger_aliases": aliases,
            }
        )
    run_binding = {
        "run_id": RUN_ID,
        "source_snapshot_digest": "C" * 64,
        "source_scope_digest": "D" * 64,
        "ecosystem": "evm",
        "mode": "thorough",
        "pipeline": "sc",
    }
    run_binding["binding_digest"] = A._sha256_value(run_binding)
    authority: dict[str, object] = {
        "schema_version": A.OBLIGATION_SCHEMA,
        "stage": A.PRE_DEPTH_STAGE,
        "run_binding": run_binding,
        "authority_universe_digest": A._universe_digest(obligations),
        "obligation_count": len(obligations),
        "obligations": obligations,
    }
    authority["authority_digest"] = A._payload_digest(authority)
    return json.dumps(authority, sort_keys=True, separators=(",", ":")).encode()


def _staged_marker(alias: dict[str, str]) -> str:
    return (
        "<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: "
        + json.dumps(
            A._alias_evidence_binding(alias),
            sort_keys=True,
            separators=(",", ":"),
        )
        + " -->"
    )


def _staged_receipt(
    *,
    display: str = "SO-001",
    alias_id: str | None = "SOT-000000000000000000000001",
    status: str = "R",
    target: str = "BLIND-A-1",
) -> str:
    alias = f" ALIAS:{alias_id}" if alias_id is not None else ""
    return (
        f"[OBLIG:security_obligations.md:{display}]{alias} "
        f"STATUS:{status} KEY:fixture -> {target}"
    )


def _compile_staged_context(
    display_aliases: tuple[tuple[str, list[dict[str, str]]], ...] | None = None,
) -> dict[str, object]:
    return A.compile_depth_staged_gate_context(
        _staged_pre_authority(display_aliases), STAGED_OUTPUT
    )


def test_rendered_obligations_supply_copy_exact_receipt_prefix() -> None:
    authority = json.loads(
        _staged_pre_authority(
            ((
                "SO-004",
                [
                    {
                        "alias_id": "SOT-2AE966B6A6EE218D0A36981A",
                        "subject_id": (
                            "fn:contracts/GatewaySend.sol::"
                            "GatewaySend.onCall@L341:C5"
                        ),
                        "relation_id": "",
                        "object_id": "",
                        "symbol": "",
                    }
                ],
            ),)
        )
    )

    rendered = A.render_security_obligations(authority)

    assert "### Exact receipt prefixes" in rendered
    assert (
        "`[OBLIG:security_obligations.md:SO-004] "
        "ALIAS:SOT-2AE966B6A6EE218D0A36981A STATUS:`"
    ) in rendered
    assert "copy its complete canonical prefix" in rendered.casefold()


def test_staged_context_accepts_real_sparse_alias_shape() -> None:
    alias = {
        "alias_id": "SOT-000000000000000000000001",
        "subject_id": "fn:superWithdraw",
        "fact_ids": ["SFF-000000000000000000000001"],
        "trigger_source": "TYPED_GRAPH_FACTS",
    }
    context = _compile_staged_context((("SO-001", [alias]),))
    projected = context["display_alias_roster"][0]["aliases"][0]

    assert projected == A._alias_evidence_binding(alias)
    text = "\n".join(
        (
            _staged_receipt(),
            "## Finding [BLIND-A-1]: exact",
            _staged_marker(alias),
        )
    )
    assert _validate_staged(text, context) == []


def _validate_staged(text: str, context: dict[str, object]) -> list[str]:
    """BLOCKING issues only -- what a staged caller may discard on."""

    return A.staged_depth_obligation_receipt_validator(
        {STAGED_OUTPUT: text.encode()}, context
    )


def _staged_result(text: str, context: dict[str, object]):
    """The typed verdict: blocking defects AND visible debt."""

    return A.staged_depth_obligation_receipt_check(
        {STAGED_OUTPUT: text.encode()}, context
    )


def _props(result) -> set[str]:
    return {defect.property_violated for defect in result.defects}


@pytest.mark.parametrize(
    "heading",
    (
        "## Finding [BLIND-A-1]: colon",
        "### Finding [BLIND-A-1] - dash",
        "#### Finding [BLIND-A-1] whitespace",
        "## Finding [BLIND-A-1]",
    ),
)
def test_staged_gate_accepts_exact_same_section_marker_for_h2_h3_h4(
    heading: str,
) -> None:
    alias = _staged_alias()
    text = "\n".join(
        (_staged_receipt(), heading, "body", _staged_marker(alias))
    )

    assert _validate_staged(text, _compile_staged_context()) == []


def test_staged_gate_accepts_marker_in_real_h3_postcondition_layout() -> None:
    alias = _staged_alias()
    text = "\n".join(
        (
            _staged_receipt(),
            "### Finding [BLIND-A-1]: exact",
            "**Verdict**: CONFIRMED",
            "### Postcondition Analysis (if CONFIRMED or PARTIAL)",
            "**Postconditions Created**: stale accounting persists",
            _staged_marker(alias),
        )
    )

    assert _validate_staged(text, _compile_staged_context()) == []


def test_run_c_sibling_same_level_postcondition_marker_is_bound() -> None:
    """Replay the exact sibling-propagation section shape from DODO Run C."""

    alias = {
        "alias_id": "SOT-A6DFA707447AE9C6C77D1B71",
        "subject_id": (
            "fn:contracts/GatewayCrossChain.sol::"
            "GatewayCrossChain._doMixSwap@L337:C5"
        ),
        "relation_id": "",
        "object_id": "",
        "symbol": "",
    }
    context = _compile_staged_context((("SO-002", [alias]),))
    text = "\n".join(
        (
            "### Finding [SP-1]: GatewayCrossChain callback can spend a "
            "decoded token unrelated to the delivered asset",
            "**Verdict**: CANDIDATE",
            "### Postcondition Analysis",
            "**Postconditions Created**: Router authority is granted over a "
            "token not bound to the gateway delivery.",
            _staged_marker(alias),
            "[OBLIG:security_obligations.md:SO-002] "
            "ALIAS:SOT-A6DFA707447AE9C6C77D1B71 STATUS:R "
            "KEY:cross-chain swap fields diverge from delivered tuple -> SP-1",
            "### Finding [SP-2]: next finding",
        )
    )

    assert _validate_staged(text, context) == []


def test_run_c_blind_spot_b_short_alias_typo_is_debt_and_stays_unharvested() -> None:
    """Run C omitted one hex nibble from the SO-004 alias in attempt one."""

    alias = {
        "alias_id": "SOT-2AE966B6A6EE218D0A36981A",
        "subject_id": "fn:contracts/GatewaySend.sol::GatewaySend.onCall@L341:C5",
        "relation_id": "",
        "object_id": "",
        "symbol": "",
    }
    context = _compile_staged_context((("SO-004", [alias]),))
    text = (
        "[OBLIG:security_obligations.md:SO-004] "
        # Exact attempt-one typo: one of the adjacent 6s is missing.
        "ALIAS:SOT-2AE966B6AEE218D0A36981A STATUS:C "
        "KEY:gateway-only guard proven; source-domain and source-sender "
        "authentication unavailable -> dependency verification phase"
    )

    result = _staged_result(text, context)

    # The typo'd alias is 23 hex nibbles, so the line cannot parse as a
    # receipt.  That is recall-safe by construction: an unparsed receipt is
    # never harvested, so SO-004 stays OPEN and the worker gets no credit.
    # Blocking here bought nothing and discarded the whole analysis.
    assert result.should_discard is False
    assert "receipt.line_grammar" in _props(result)
    assert _validate_staged(text, context) == []
    debt = [
        defect
        for defect in result.debt_defects
        if defect.property_violated == "receipt.line_grammar"
    ]
    assert debt and debt[0].physical_line == 1 and debt[0].repair_hint


def test_staged_gate_accepts_casefolded_multi_hyphen_finding_and_singleton_alias() -> None:
    alias = _staged_alias()
    text = "\n".join(
        (
            _staged_receipt(alias_id=None, target="finding `blind-a-1`"),
            "### Finding [BLIND-A-1] - exact",
            _staged_marker(alias),
        )
    )

    assert _validate_staged(text, _compile_staged_context()) == []


def test_run19_da_table_only_upstream_referents_remain_rejected() -> None:
    """Run19 DA attempt one used inventory IDs only as table candidates."""

    alias = _staged_alias()
    text = "\n".join(
        (
            "| Finding ID | Verdict |",
            "|---|---|",
            "| INV-008 | UNRESOLVED |",
            _staged_receipt(target="INV-008"),
            "### Obligation evidence bindings for INV-008",
            _staged_marker(alias),
        )
    )

    result = _staged_result(text, _compile_staged_context())

    assert result.should_discard is True
    assert [d.property_violated for d in result.blocking_defects] == [
        "identity.receipt_finding_referent"
    ]
    assert result.blocking_defects[0].physical_line == 4


@pytest.mark.parametrize("status", ("C", "D"))
def test_staged_gate_accepts_bounded_punctuation_for_nonterminal_debt(
    status: str,
) -> None:
    text = _staged_receipt(
        alias_id=None,
        status=status,
        target="reviewed: path/to:file.sol#L7 (reason? yes!)",
    )

    assert _validate_staged(text, _compile_staged_context()) == []


@pytest.mark.parametrize(
    ("body", "expected", "closure"),
    (
        (
            "## Finding [BLIND-A-1]: exact\n{wrong_marker}",
            "evidence.same_section_alias_marker",
            A.AS.DEBT,
        ),
        (
            "## Finding [BLIND-A-1]: exact\n```\n{marker}\n```",
            "evidence.fenced_marker",
            A.AS.DEBT,
        ),
        (
            "## Finding [BLIND-A-1]: exact\n{marker}\n{marker}",
            "evidence.same_section_alias_marker",
            A.AS.DEBT,
        ),
        (
            "## Finding [OTHER-1]: wrong section\n{marker}\n"
            "## Finding [BLIND-A-1]: exact\nbody",
            "evidence.same_section_alias_marker",
            A.AS.DEBT,
        ),
        (
            "## Finding [BLIND-A-1]: first\n{marker}\n"
            "### Finding [blind-a-1]: duplicate\nbody",
            "identity.duplicate_finding_declaration",
            A.AS.FAIL_CLOSED,
        ),
    ),
)
def test_staged_gate_reports_wrong_fenced_duplicate_or_wrong_section_marker(
    body: str,
    expected: str,
    closure: str,
) -> None:
    """The alias marker is a SUPPORTING record: placement, count and fencing
    degrade to visible debt, while an ambiguous finding IDENTITY still blocks.

    Downgrading the marker conjuncts loses no recall: the derivation path's
    ``_reported_receipt_matches_alias`` still requires the exact marker inside
    the referent section, so a misplaced, duplicated, conflicting or fenced
    marker leaves its alias undischarged and queued for repair.  The only
    thing that changed is that a complete analysis is no longer thrown away.
    """
    alias = _staged_alias()
    wrong_alias = {**alias, "subject_id": "src/Evil.sol::withdraw"}
    text = _staged_receipt() + "\n" + body.format(
        marker=_staged_marker(alias),
        wrong_marker=_staged_marker(wrong_alias),
    )

    result = _staged_result(text, _compile_staged_context())

    assert expected in _props(result)
    matched = [d for d in result.defects if d.property_violated == expected]
    assert all(d.closure == closure for d in matched)
    assert all(d.repair_hint for d in matched)
    assert result.should_discard is (closure == A.AS.FAIL_CLOSED)


def test_staged_gate_rejects_conflicting_marker_for_same_alias() -> None:
    alias = _staged_alias()
    conflicting = {**alias, "object_id": "asset:conflict"}
    text = "\n".join(
        (
            _staged_receipt(),
            "## Finding [BLIND-A-1]: exact",
            _staged_marker(alias),
            _staged_marker(conflicting),
        )
    )

    result = _staged_result(text, _compile_staged_context())

    # Two different payloads for one alias leave it unmatched downstream, so
    # the obligation stays open. Visible debt, not a discarded artifact.
    assert "evidence.same_section_alias_marker" in _props(result)
    assert result.should_discard is False


@pytest.mark.parametrize(
    ("receipt", "expected", "blocks"),
    (
        (
            _staged_receipt(display="SO-099"),
            "identity.receipt_display_binding",
            True,
        ),
        (
            _staged_receipt(alias_id="SOT-FFFFFFFFFFFFFFFFFFFFFFFF"),
            "identity.receipt_alias_binding",
            True,
        ),
        (
            "[OBLIG:security_obligations.md:SO-001] STATUS:R "
            "KEY:fixture => BLIND-A-1",
            "receipt.line_grammar",
            False,
        ),
    ),
)
def test_staged_gate_reports_unknown_or_malformed_reported_receipt(
    receipt: str,
    expected: str,
    blocks: bool,
) -> None:
    """ADVERSARIAL: a receipt naming an obligation or alias that is NOT in the
    current roster is a false discharge claim -- closed family, still blocks.
    A grammar typo cannot be harvested at all, so it is debt."""
    alias = _staged_alias()
    text = "\n".join(
        (receipt, "## Finding [BLIND-A-1]: exact", _staged_marker(alias))
    )

    result = _staged_result(text, _compile_staged_context())

    assert expected in _props(result)
    assert result.should_discard is blocks


def test_staged_gate_rejects_implicit_alias_for_nonsingleton_display() -> None:
    aliases = [_staged_alias(1), _staged_alias(2)]
    context = _compile_staged_context((("SO-001", aliases),))
    text = "\n".join(
        (
            _staged_receipt(alias_id=None),
            "## Finding [BLIND-A-1]: exact",
            _staged_marker(aliases[0]),
        )
    )

    result = _staged_result(text, context)

    assert "identity.receipt_alias_binding" in _props(result)
    assert result.should_discard is True


def test_staged_gate_rejects_duplicate_reported_alias_claim() -> None:
    alias = _staged_alias()
    text = "\n".join(
        (
            _staged_receipt(),
            _staged_receipt(target="BLIND-A-2"),
            "## Finding [BLIND-A-1]: first",
            _staged_marker(alias),
            "## Finding [BLIND-A-2]: second",
            "body",
        )
    )

    result = _staged_result(text, _compile_staged_context())

    assert "dedup.receipt_alias_claim" in _props(result)
    assert result.should_discard is True


def test_staged_gate_reports_fenced_reported_receipt_as_debt() -> None:
    alias = _staged_alias()
    text = "\n".join(
        (
            "```text",
            _staged_receipt(),
            "```",
            "## Finding [BLIND-A-1]: exact",
            _staged_marker(alias),
        )
    )

    result = _staged_result(text, _compile_staged_context())

    # A fenced receipt is not harvested by the derivation path either, so the
    # obligation stays open. Report it; do not destroy the analysis.
    assert "receipt.fenced_placement" in _props(result)
    assert result.should_discard is False


@pytest.mark.parametrize(
    "field",
    (
        "source_authority_sha256",
        "authority_digest",
        "authority_universe_digest",
        "run_binding_digest",
        "output_identity",
        "display_alias_roster",
        "context_digest",
    ),
)
def test_staged_gate_rejects_context_tamper(field: str) -> None:
    context = copy.deepcopy(_compile_staged_context())
    if field == "output_identity":
        context[field] = "scratchpad:other.md"
    elif field == "display_alias_roster":
        context[field][0]["aliases"][0]["subject_id"] = "tampered"
    else:
        context[field] = "F" * 64

    result = A.staged_depth_obligation_receipt_check(
        {STAGED_OUTPUT: b"valid bytes"}, context
    )

    assert result.should_discard is True
    assert [d.property_violated for d in result.blocking_defects] == [
        "identity.staged_gate_context"
    ]


def test_staged_gate_rejects_wrong_or_multiple_output_denominator() -> None:
    context = _compile_staged_context()

    for outputs in (
        {"scratchpad:other.md": b"body"},
        {STAGED_OUTPUT: b"body", "scratchpad:other.md": b"body"},
    ):
        result = A.staged_depth_obligation_receipt_check(outputs, context)
        assert result.should_discard is True
        assert [d.property_violated for d in result.blocking_defects] == [
            "identity.staged_output_denominator"
        ]


@pytest.mark.parametrize(
    "mutation",
    (
        "post_stage",
        "authority_digest",
        "universe_digest",
        "run_binding_digest",
        "duplicate_json_key",
    ),
)
def test_staged_context_compiler_rejects_invalid_pre_authority(
    mutation: str,
) -> None:
    raw = _staged_pre_authority()
    authority = json.loads(raw)
    if mutation == "post_stage":
        authority["stage"] = A.POST_DEPTH_STAGE
        authority["authority_digest"] = A._payload_digest(authority)
        raw = json.dumps(authority).encode()
    elif mutation == "authority_digest":
        authority["authority_digest"] = "F" * 64
        raw = json.dumps(authority).encode()
    elif mutation == "universe_digest":
        authority["authority_universe_digest"] = "F" * 64
        authority["authority_digest"] = A._payload_digest(authority)
        raw = json.dumps(authority).encode()
    elif mutation == "run_binding_digest":
        authority["run_binding"]["binding_digest"] = "F" * 64
        authority["authority_digest"] = A._payload_digest(authority)
        raw = json.dumps(authority).encode()
    elif mutation == "duplicate_json_key":
        raw = raw[:-1] + b',"stage":"pre_depth"}'

    with pytest.raises(ValueError):
        A.compile_depth_staged_gate_context(raw, STAGED_OUTPUT)


@pytest.mark.parametrize(
    "output_identity",
    ("depth.md", "scratchpad:../depth.md", "scratchpad:depth.txt", ""),
)
def test_staged_context_compiler_rejects_noncanonical_output_identity(
    output_identity: str,
) -> None:
    with pytest.raises(ValueError):
        A.compile_depth_staged_gate_context(
            _staged_pre_authority(), output_identity
        )


def test_trailing_prose_after_a_complete_marker_is_not_malformed() -> None:
    """The marker's binding is its JSON payload, not the whole line.

    The driver's own obligation list renders each marker inside a list item
    after a label, so anchoring the recognizer on the entire line rejected
    artifacts for the very shape the driver published.
    """
    alias = _staged_alias()
    text = (
        _staged_receipt()
        + "\n## Finding [BLIND-A-1]: exact\n"
        + f"- SO-004 `SOT-1`: {_staged_marker(alias)} (covered)\n"
    )

    issues = _validate_staged(text, _compile_staged_context())

    assert not any(
        "malformed structured obligation evidence" in issue for issue in issues
    ), issues


def test_two_different_markers_on_one_line_still_conflict() -> None:
    """Control: every marker on the line is parsed, so a second payload for
    the same alias is still a conflict."""
    alias = _staged_alias()
    other = {**alias, "subject_id": "src/Evil.sol::withdraw"}
    text = (
        _staged_receipt()
        + "\n## Finding [BLIND-A-1]: exact\n"
        + f"{_staged_marker(alias)} and {_staged_marker(other)}\n"
    )

    result = _staged_result(text, _compile_staged_context())

    assert "evidence.conflicting_markers" in _props(result)


# ==========================================================================
# DODO run48 depth (2026-09-20): the real bytes that were rejected.
# Every core depth worker SUCCEEDED, wrote its artifact and staged it -- and
# the staged obligation validator rejected it, so nothing published and the
# depth phase could not complete.  These are the exact shapes.
# ==========================================================================

_RUN48_BACKTICKED_RECEIPT = (
    "`[OBLIG:security_obligations.md:SO-001] "
    "ALIAS:SOT-0CD90FD1A8E615C833DEDF75 STATUS:R "
    "KEY:slippage declaration is the unbound input to amountInMax -> DE-1`"
)
_RUN48_PROSE_MENTION = (
    "generated `PLAMEN_SECURITY_OBLIGATION_EVIDENCE` marker for that alias "
    "is present inside that same finding section above."
)


def test_run48_backticked_receipt_is_a_valid_claim() -> None:
    """depth_edge_case_findings.md:1288-1291 -- rejected as malformed.

    The worker wrapped each receipt in backticks so it renders as code.  That
    is presentation; the receipt text itself is exact.
    """
    line = A.AS.surface(_RUN48_BACKTICKED_RECEIPT).lines[0]
    _, match = A._receipt_claim(line)

    assert match is not None
    assert match.group("alias").upper() == "SOT-0CD90FD1A8E615C833DEDF75"


def test_run48_prose_marker_mention_is_not_a_marker() -> None:
    """validation_sweep_findings.md:655 (also blind_spot_a:735,
    niche_semantic_gap:1166) -- rejected as malformed evidence.

    The line NAMES the marker token while explaining placement; it asserts no
    marker, so it carries no binding and no defect.
    """
    assert A._EVIDENCE_BINDING_RE.search(_RUN48_PROSE_MENTION) is None
    assert "<!--" not in _RUN48_PROSE_MENTION


def test_an_asserted_but_malformed_marker_is_still_rejected() -> None:
    """Control: a line that really asserts a marker must still parse."""
    line = "<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: not-json -->"
    assert "<!--" in line
    assert A._EVIDENCE_BINDING_RE.search(line) is None


def test_a_typo_receipt_claim_is_still_rejected() -> None:
    """Control: opener-anchored text is held to the exact grammar."""
    line = A.AS.surface(
        "`[OBLIG:security_obligations.md:SO-001] STATUS=R KEY:x -> DE-1`"
    ).lines[0]
    _, match = A._receipt_claim(line)

    assert match is None
