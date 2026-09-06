from __future__ import annotations

import json
from pathlib import Path

import pytest

import skill_selection_authority as S
import plamen_driver as D
import plamen_validators as V
from artifact_ledger import (
    apply_semantic_invalidation,
    read_artifact_ledger,
    semantic_dependency_invalidation_plan,
)
from phase_io_contracts import resolve_phase_io_contract


def _catalog(tmp_path: Path, *, conflict: bool = False) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    index = tmp_path / "skill-index.md"
    index.write_text(
        """# Skill Index

## EVM Skills

| Skill | Trigger Pattern | Used By |
|---|---|---|
| ORACLE_ANALYSIS | ORACLE flag | breadth agents, depth-external, depth-edge-case |
| TOKEN_FLOW_TRACING | BALANCE flag | breadth agents, depth-token-flow |
| ALWAYS_SAFE | Always (EVM) | breadth agents |

## Solana Skills

| Skill | Trigger Pattern | Used By |
|---|---|---|
| ACCOUNT_VALIDATION | Always (Solana) | breadth agents, depth agents |

## Injectable Skills

| Skill | Protocol Type Trigger | Inject Into |
|---|---|---|
| LENDING_PROTOCOL_SECURITY | lending | breadth agents, depth-token-flow, depth-edge-case, depth-state-trace |
| CROSS_VM_SERIALIZATION_CONFORMANCE | foreign VM encoding | Breadth cross-chain/encoding agent, depth-external |

## Niche Agents

| Niche Agent | Trigger Flag | Budget | Description |
|---|---|---|---|
| SIGNATURE_VERIFICATION_AUDIT | HAS_SIGNATURES | 1 slot | signatures |
""",
        encoding="utf-8",
    )
    root = tmp_path / "skills"
    specs = {
        ("evm", "oracle-analysis"): (
            "Breadth agents, depth-external, depth-state-trace"
            if conflict
            else "Breadth agents, depth-external, depth-edge-case"
        ),
        ("evm", "token-flow-tracing"): "Breadth agents, depth-token-flow",
        ("evm", "always-safe"): "Breadth agents",
        ("solana", "account-validation"): "Breadth agents, depth agents",
        ("injectable", "lending-protocol-security"): (
            "Breadth agents, depth-token-flow, depth-edge-case, depth-state-trace"
        ),
        ("injectable", "cross-vm-serialization-conformance"): (
            "Breadth cross-chain/encoding agent, depth-external"
        ),
    }
    for (scope, slug), consumers in specs.items():
        path = root / scope / slug / "SKILL.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"---\nname: {slug}\n---\n\n> **Inject Into**: {consumers}\n",
            encoding="utf-8",
        )
    niche = root / "niche" / "signature-verification-audit" / "SKILL.md"
    niche.parent.mkdir(parents=True, exist_ok=True)
    niche.write_text(
        "---\nname: signature-verification-audit\n---\n\n"
        "> **Agent Type**: standalone niche agent\n",
        encoding="utf-8",
    )
    return index, root


def _selection_table(rows: list[tuple[str, str]]) -> str:
    body = "\n".join(f"| {name} | trigger | {state} | evidence |" for name, state in rows)
    return (
        "# Template Recommendations\n\n## BINDING MANIFEST\n\n"
        "| Skill | Trigger | Required | Rationale |\n"
        "|---|---|---|---|\n" + body + "\n"
    )


def _build(
    tmp_path: Path,
    source_texts: dict[str, str],
    *,
    conflict: bool = False,
    backend: str = "claude-pty",
) -> dict:
    index, root = _catalog(tmp_path, conflict=conflict)
    return S.build_skill_selection_catalog(
        skill_index_path=index,
        skill_root=root,
        ecosystem="evm",
        pipeline="sc",
        mode="thorough",
        backend=backend,
        source_texts=source_texts,
    )


def _by_id(catalog: dict) -> dict[str, dict]:
    return {row["skill_id"]: row for row in catalog["skills"]}


def test_applicable_catalog_rows_matches_builder_projection(tmp_path: Path):
    index, root = _catalog(tmp_path)
    rows = S.applicable_skill_catalog_rows(
        skill_index_path=index,
        skill_root=root,
        ecosystem="evm",
        pipeline="sc",
    )
    catalog = S.build_skill_selection_catalog(
        skill_index_path=index,
        skill_root=root,
        ecosystem="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
        source_texts={},
    )

    assert [row["skill_id"] for row in rows] == [
        row["skill_id"] for row in catalog["skills"]
    ]
    assert "ACCOUNT_VALIDATION" not in {row["skill_id"] for row in rows}


def test_bindable_recon_rows_exclude_standalone_niches(tmp_path: Path):
    index, root = _catalog(tmp_path)

    rows = S.bindable_skill_selection_rows(
        skill_index_path=index,
        skill_root=root,
        ecosystem="evm",
        pipeline="sc",
    )
    ids = {row["skill_id"] for row in rows}

    assert "LENDING_PROTOCOL_SECURITY" in ids
    assert "SIGNATURE_VERIFICATION_AUDIT" not in ids
    assert S.selection_signal_issues(
        '<!-- PLAMEN_SIGNALS: {"required_skills":["SIGNATURE_VERIFICATION_AUDIT"]} -->',
        rows,
    ) == [
        {"code": "UNKNOWN_SKILL_ID", "skill_id": "SIGNATURE_VERIFICATION_AUDIT"}
    ]


def test_applicable_catalog_rows_applies_methodology_ecosystem_filter(tmp_path: Path):
    index, root = _catalog(tmp_path)
    oracle = root / "evm" / "oracle-analysis" / "SKILL.md"
    oracle.write_text(
        oracle.read_text(encoding="utf-8") + "\n> **Languages**: Solana\n",
        encoding="utf-8",
    )

    rows = S.applicable_skill_catalog_rows(
        skill_index_path=index,
        skill_root=root,
        ecosystem="evm",
        pipeline="sc",
    )

    assert "ORACLE_ANALYSIS" not in {row["skill_id"] for row in rows}


def test_selection_signal_accepts_exact_canonical_subset(tmp_path: Path):
    index, root = _catalog(tmp_path)
    rows = S.applicable_skill_catalog_rows(
        skill_index_path=index,
        skill_root=root,
        ecosystem="evm",
        pipeline="sc",
    )
    text = '<!-- PLAMEN_SIGNALS: {"required_skills":["ORACLE_ANALYSIS"]} -->'

    assert S.selection_signal_issues(text, rows) == []
    assert S.selection_signal_issues(
        '<!-- PLAMEN_SIGNALS: {"required_skills":[]} -->', rows
    ) == []


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ("no signal", "MISSING_SELECTION_SIGNAL"),
        (
            '<!-- PLAMEN_SIGNALS: {"required_skills":[]} -->\n'
            '<!-- PLAMEN_SIGNALS: {"required_skills":[]} -->',
            "DUPLICATE_SELECTION_SIGNAL",
        ),
        (
            '<!-- PLAMEN_SIGNALS: {\n"required_skills":[]\n} -->',
            "MULTILINE_SELECTION_SIGNAL",
        ),
        ('<!-- PLAMEN_SIGNALS: {bad json} -->', "MALFORMED_SELECTION_SIGNAL"),
        (
            '<!-- PLAMEN_SIGNALS: {"required_skills":[],"required_skills":["ORACLE_ANALYSIS"]} -->',
            "DUPLICATE_SIGNAL_KEY",
        ),
        ('<!-- PLAMEN_SIGNALS: {"other":[]} -->', "MISSING_REQUIRED_SKILLS"),
        ('<!-- PLAMEN_SIGNALS: {"required_skills":"ORACLE_ANALYSIS"} -->', "REQUIRED_SKILLS_NOT_LIST"),
        ('<!-- PLAMEN_SIGNALS: {"required_skills":["oracle-analysis"]} -->', "NON_CANONICAL_SKILL_ID"),
        ('<!-- PLAMEN_SIGNALS: {"required_skills":["ACCESS_CONTROL"]} -->', "UNKNOWN_SKILL_ID"),
        (
            '<!-- PLAMEN_SIGNALS: {"required_skills":["ORACLE_ANALYSIS","ORACLE_ANALYSIS"]} -->',
            "DUPLICATE_SKILL_ID",
        ),
    ],
)
def test_selection_signal_rejects_malformed_duplicate_or_invented_ids(
    tmp_path: Path, text: str, code: str
):
    index, root = _catalog(tmp_path)
    rows = S.applicable_skill_catalog_rows(
        skill_index_path=index,
        skill_root=root,
        ecosystem="evm",
        pipeline="sc",
    )

    assert code in {issue["code"] for issue in S.selection_signal_issues(text, rows)}


def test_selection_signal_is_optional_only_when_explicitly_requested(tmp_path: Path):
    index, root = _catalog(tmp_path)
    rows = S.applicable_skill_catalog_rows(
        skill_index_path=index,
        skill_root=root,
        ecosystem="evm",
        pipeline="sc",
    )

    assert S.selection_signal_issues("no signal", rows, required=False) == []


def test_exact_table_polarity_three_yes_thirty_no_three_na(tmp_path: Path):
    rows = [(f"NEG_{i:02d}", "NO") for i in range(30)]
    rows += [(f"NA_{i:02d}", "N/A (not applicable)") for i in range(3)]
    # Unknown catalog IDs are debts, never accidental selections.
    rows += [
        ("ORACLE_ANALYSIS", "YES"),
        ("TOKEN_FLOW_TRACING", "YES"),
        ("LENDING_PROTOCOL_SECURITY", "YES"),
    ]
    catalog = _build(tmp_path, {"recon_templates_patterns.md": _selection_table(rows)})
    selected = {r["skill_id"] for r in catalog["skills"] if r["state"] == "REQUIRED"}
    assert selected == {
        "ORACLE_ANALYSIS",
        "TOKEN_FLOW_TRACING",
        "LENDING_PROTOCOL_SECURITY",
        "ALWAYS_SAFE",  # catalog-owned always-on state
    }
    assert len([d for d in catalog["debts"] if d["code"] == "UNKNOWN_SKILL_ID"]) == 33


@pytest.mark.parametrize(
    "negative",
    ["NO", "N/A", "N/A (not applicable)", "NOT SET", "SKIP", "false", "0"],
)
def test_exact_negative_aliases_never_become_required(tmp_path: Path, negative: str):
    catalog = _build(
        tmp_path,
        {"recon_templates_patterns.md": _selection_table([("ORACLE_ANALYSIS", negative)])},
    )
    assert _by_id(catalog)["ORACLE_ANALYSIS"]["state"] == "NOT_REQUIRED"


def test_structured_empty_is_explicit_empty_not_prose_fallback(tmp_path: Path):
    text = (
        "## Skill Recommendations\n\nORACLE_ANALYSIS is strongly recommended.\n\n"
        '<!-- PLAMEN_SIGNALS: {"required_skills":[]} -->\n'
    )
    catalog = _build(tmp_path, {"recon_templates_patterns.md": text})
    assert _by_id(catalog)["ORACLE_ANALYSIS"]["state"] == "NOT_REQUIRED"
    assert catalog["source_semantics"][0]["structured_selection"] == "EXPLICIT_EMPTY"


def test_driver_prepass_default_no_is_not_recon_selection_evidence(tmp_path: Path):
    text = (
        "# Template Recommendations\n\n"
        "[LLM TO ENRICH] Pre-pass stub. Every row below is Required=NO by default.\n\n"
        "## BINDING MANIFEST\n\n"
        "| Skill | Trigger | Required | Rationale |\n"
        "|---|---|---|---|\n"
        "| ORACLE_ANALYSIS | ORACLE | NO | [LLM TO ENRICH] |\n\n"
        '<!-- PLAMEN_SIGNALS: {"required_skills":["ORACLE_ANALYSIS"]} -->\n'
    )
    catalog = _build(tmp_path, {"template_recommendations.md": text})
    assert _by_id(catalog)["ORACLE_ANALYSIS"]["state"] == "REQUIRED"
    assert not any(d["code"] == "SELECTION_STATE_CONFLICT" for d in catalog["debts"])


def test_canonical_merge_unions_mechanical_required_row_into_typed_signal(
    tmp_path: Path,
):
    """DODO regression: mechanical external-protocol evidence cannot vanish.

    The isolated recon selector may legitimately omit a dependency it could
    not enumerate while the deterministic source scan has already marked the
    integration-hazard lane Required=YES.  Canonical normalization must make
    that positive visible to both Markdown consumers and the typed catalog.
    """
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    canonical = scratch / "template_recommendations.md"
    canonical.write_text(
        _selection_table(
            [
                ("ALWAYS_SAFE", "NO"),
                ("ORACLE_ANALYSIS", "NO"),
                ("LENDING_PROTOCOL_SECURITY", "YES"),
            ]
        )
        + '\n<!-- PLAMEN_SIGNALS: {"required_skills":["ALWAYS_SAFE"]} -->\n',
        encoding="utf-8",
    )
    # The raw shard remains the pre-normalization worker snapshot.  Once a
    # canonical manifest exists it must no longer outrank deterministic merge
    # output when the typed selection receipt is built.
    (scratch / "recon_templates_patterns.md").write_text(
        '<!-- PLAMEN_SIGNALS: {"required_skills":["ALWAYS_SAFE"]} -->\n',
        encoding="utf-8",
    )

    assert V._reconcile_skill_manifest_sources(scratch) == 1
    normalized = canonical.read_text(encoding="utf-8")
    assert (
        '<!-- PLAMEN_SIGNALS: {"required_skills":["ALWAYS_SAFE",'
        '"LENDING_PROTOCOL_SECURITY"]} -->'
    ) in normalized
    assert V._reconcile_skill_manifest_sources(scratch) == 0
    assert V._skill_selection_source_texts(scratch) == {
        "template_recommendations.md": normalized
    }

    catalog = _build(tmp_path / "catalog", {"template_recommendations.md": normalized})
    row = _by_id(catalog)["LENDING_PROTOCOL_SECURITY"]
    assert row["state"] == "REQUIRED"
    assert row["conflict"] is False


def test_positive_prose_without_row_is_unknown_not_selected(tmp_path: Path):
    catalog = _build(
        tmp_path,
        {"legacy.md": "## Skill Recommendations\nORACLE_ANALYSIS is recommended.\n"},
    )
    assert _by_id(catalog)["ORACLE_ANALYSIS"]["state"] == "UNKNOWN"
    assert any(d["code"] == "PROSE_ONLY_RECOMMENDATION" for d in catalog["debts"])


def test_duplicate_conflicting_structured_states_are_loud_unknown(tmp_path: Path):
    text = _selection_table([("ORACLE_ANALYSIS", "YES"), ("ORACLE_ANALYSIS", "NO")])
    catalog = _build(tmp_path, {"duplicate.md": text})
    row = _by_id(catalog)["ORACLE_ANALYSIS"]
    assert row["state"] == "UNKNOWN"
    assert row["conflict"] is True
    assert any(d["code"] == "SELECTION_STATE_CONFLICT" for d in catalog["debts"])


def test_structured_signals_survive_transport_marker_stripping():
    source = (
        "<!-- PLAMEN_STATUS: COMPLETE -->\n"
        "<!-- PLAMEN_OWNER: R4 -->\n"
        '<!-- PLAMEN_SIGNALS: {"required_skills":["ORACLE_ANALYSIS"]} -->\n'
        "| ORACLE_ANALYSIS | ORACLE | YES | evidence |\n"
    )
    stripped, receipt = S.strip_recon_transport_markers(source)
    assert "PLAMEN_STATUS" not in stripped and "PLAMEN_OWNER" not in stripped
    assert "PLAMEN_SIGNALS" in stripped
    assert receipt["structured_signal_blocks_before"] == 1
    assert receipt["structured_signal_blocks_after"] == 1
    assert receipt["authority_loss"] is False


def test_malformed_signal_is_preserved_and_typed_as_debt(tmp_path: Path):
    malformed = '<!-- PLAMEN_SIGNALS: {bad json} -->\n'
    stripped, receipt = S.strip_recon_transport_markers(malformed)
    assert stripped.strip() == malformed.strip()
    assert receipt["malformed_signal_blocks"] == 1
    catalog = _build(tmp_path, {"bad.md": stripped})
    assert any(d["code"] == "MALFORMED_STRUCTURED_SIGNAL" for d in catalog["debts"])


def test_wrong_ecosystem_skill_never_inherited(tmp_path: Path):
    catalog = _build(
        tmp_path,
        {"recon.md": _selection_table([("ACCOUNT_VALIDATION", "YES")])},
    )
    assert "ACCOUNT_VALIDATION" not in _by_id(catalog)
    assert any(d["code"] == "WRONG_ECOSYSTEM_SKILL" for d in catalog["debts"])


def _scheduled() -> list[dict]:
    return [
        {"consumer_id": "breadth:B1", "kind": "breadth", "focus": "oracle_core"},
        {"consumer_id": "breadth:B2", "kind": "breadth", "focus": "access_control"},
        {"consumer_id": "depth:external", "kind": "depth", "role": "external"},
        {"consumer_id": "depth:edge_case", "kind": "depth", "role": "edge_case"},
    ]


def _r51_depth_only_catalog() -> dict:
    return {
        "authority": {},
        "artifact_sha256": "r51-catalog",
        "skills": [
            {
                "skill_id": "CROSS_CHAIN_TIMING",
                "state": "REQUIRED",
                "consumer_metadata_status": "CURRENT",
                "index_consumers": ["depth:external"],
            },
            {
                "skill_id": "STORAGE_LAYOUT_SAFETY",
                "state": "REQUIRED",
                "consumer_metadata_status": "CURRENT",
                "index_consumers": ["depth:edge_case", "depth:state_trace"],
            },
            {
                "skill_id": "INTEGRATION_HAZARD_RESEARCH",
                "state": "REQUIRED",
                "consumer_metadata_status": "CURRENT",
                "index_consumers": ["depth:external"],
            },
        ],
    }


def _r51_scheduled_consumers() -> list[dict]:
    return [
        {"consumer_id": "breadth:B4", "kind": "breadth", "focus": "token_flow_timing"},
        {"consumer_id": "breadth:B5", "kind": "breadth", "focus": "storage_layout_upgrade"},
        {"consumer_id": "depth:external", "kind": "depth", "role": "external"},
        {"consumer_id": "depth:edge_case", "kind": "depth", "role": "edge_case"},
        {"consumer_id": "depth:state_trace", "kind": "depth", "role": "state_trace"},
    ]


def test_r51_breadth_ineligible_pairs_are_exact_debt_and_never_effective():
    coverage = S.build_skill_consumer_coverage(
        selection_catalog=_r51_depth_only_catalog(),
        scheduled_consumers=_r51_scheduled_consumers(),
        existing_bindings={
            "breadth:B4": ["CROSS_CHAIN_TIMING"],
            "breadth:B5": [
                "STORAGE_LAYOUT_SAFETY",
                "INTEGRATION_HAZARD_RESEARCH",
            ],
        },
    )

    assert coverage["status"] == "UNKNOWN"
    assert {
        (debt["consumer_id"], debt["skill_id"])
        for debt in coverage["debts"]
        if debt["code"] == "INELIGIBLE_EXISTING_BINDING"
    } == {
        ("breadth:B4", "CROSS_CHAIN_TIMING"),
        ("breadth:B5", "STORAGE_LAYOUT_SAFETY"),
        ("breadth:B5", "INTEGRATION_HAZARD_RESEARCH"),
    }
    assert "breadth:B4" not in coverage["effective_bindings"]
    assert "breadth:B5" not in coverage["effective_bindings"]


def test_r51_declared_depth_pairs_are_current_and_effective():
    coverage = S.build_skill_consumer_coverage(
        selection_catalog=_r51_depth_only_catalog(),
        scheduled_consumers=_r51_scheduled_consumers(),
        existing_bindings={
            "depth:external": [
                "CROSS_CHAIN_TIMING",
                "INTEGRATION_HAZARD_RESEARCH",
            ],
            "depth:edge_case": ["STORAGE_LAYOUT_SAFETY"],
            "depth:state_trace": ["STORAGE_LAYOUT_SAFETY"],
        },
    )

    assert coverage["status"] == "CURRENT"
    assert coverage["debts"] == []
    assert coverage["effective_bindings"]["depth:external"] == [
        "CROSS_CHAIN_TIMING",
        "INTEGRATION_HAZARD_RESEARCH",
    ]
    assert coverage["effective_bindings"]["depth:edge_case"] == [
        "STORAGE_LAYOUT_SAFETY"
    ]
    assert coverage["effective_bindings"]["depth:state_trace"] == [
        "STORAGE_LAYOUT_SAFETY"
    ]


def test_spawn_manifest_schedule_and_existing_binding_projection(tmp_path: Path):
    catalog = _build(
        tmp_path,
        {
            "recon.md": _selection_table(
                [("ORACLE_ANALYSIS", "YES"), ("SIGNATURE_VERIFICATION_AUDIT", "YES")]
            )
        },
    )
    manifest = """# Spawn Manifest

## Breadth Agents

| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |
|---|---|---|---|---|---|---|
| AGENT | ORACLE_ANALYSIS | YES | B1 | oracle_core | analysis_oracle.md | QUEUED |
| AGENT | GENERAL | YES | B2 | access_control | analysis_access.md | QUEUED |

## Skill Bindings

| Skill | Type | Inject Into | Delivery Mode |
|---|---|---|---|
| ORACLE_ANALYSIS | Standard | depth-external | Full SKILL.md |
"""
    scheduled, existing = S.scheduled_consumers_from_spawn_manifest(
        manifest_text=manifest,
        selection_catalog=catalog,
        pipeline="sc",
        mode="thorough",
    )
    ids = {row["consumer_id"] for row in scheduled}
    assert {"breadth:B1", "breadth:B2", "depth:external", "depth:edge_case"} <= ids
    assert "niche:auto:signature-verification-audit" in ids
    assert existing["breadth:B1"] == ["ORACLE_ANALYSIS"]
    assert existing["depth:external"] == ["ORACLE_ANALYSIS"]


def test_consumer_digest_normalizes_hyphenated_niche_slugs_once(tmp_path: Path):
    catalog = _build(
        tmp_path,
        {"recon.md": _selection_table([("SIGNATURE_VERIFICATION_AUDIT", "YES")])},
    )
    scheduled = [
        {
            "consumer_id": "niche:auto:signature-verification-audit",
            "kind": "niche",
            "role": "signature-verification-audit",
            "focus": "signature-verification-audit",
        }
    ]
    coverage = S.build_skill_consumer_coverage(
        selection_catalog=catalog,
        scheduled_consumers=scheduled,
        existing_bindings={},
    )

    assert coverage["authority"]["scheduled_consumers_sha256"] == (
        S.scheduled_consumers_sha256(scheduled)
    )


def test_selected_skill_missing_consumers_adds_every_scheduled_binding(tmp_path: Path):
    catalog = _build(
        tmp_path,
        {"recon.md": _selection_table([("ORACLE_ANALYSIS", "YES")])},
    )
    coverage = S.build_skill_consumer_coverage(
        selection_catalog=catalog,
        scheduled_consumers=_scheduled(),
        existing_bindings={"breadth:B1": ["ORACLE_ANALYSIS"]},
    )
    oracle = next(r for r in coverage["skills"] if r["skill_id"] == "ORACLE_ANALYSIS")
    by_consumer = {r["consumer_id"]: r["status"] for r in oracle["consumers"]}
    assert by_consumer == {
        "breadth:B1": "DISPATCHED",
        "breadth:B2": "ADDED_BINDING",
        "depth:external": "ADDED_BINDING",
        "depth:edge_case": "ADDED_BINDING",
    }
    assert coverage["effective_bindings"]["depth:external"] == ["ORACLE_ANALYSIS"]


def test_nonselected_skill_is_never_injected(tmp_path: Path):
    catalog = _build(
        tmp_path,
        {"recon.md": _selection_table([("ORACLE_ANALYSIS", "NO")])},
    )
    coverage = S.build_skill_consumer_coverage(
        selection_catalog=catalog,
        scheduled_consumers=_scheduled(),
        existing_bindings={},
    )
    assert not any(
        "ORACLE_ANALYSIS" in skills for skills in coverage["effective_bindings"].values()
    )


def test_unscheduled_declared_consumer_gets_mode_scoped_disposition(tmp_path: Path):
    catalog = _build(
        tmp_path,
        {"recon.md": _selection_table([("ORACLE_ANALYSIS", "YES")])},
    )
    coverage = S.build_skill_consumer_coverage(
        selection_catalog=catalog,
        scheduled_consumers=[
            {"consumer_id": "breadth:B1", "kind": "breadth", "focus": "oracle"}
        ],
        existing_bindings={},
    )
    oracle = next(r for r in coverage["skills"] if r["skill_id"] == "ORACLE_ANALYSIS")
    assert {d["declared_consumer"] for d in oracle["dispositions"]} == {
        "depth:external",
        "depth:edge_case",
    }
    assert {d["status"] for d in oracle["dispositions"]} == {"NOT_SCHEDULED_MODE"}


def test_cross_chain_encoding_declaration_falls_back_to_deterministic_breadth_owner(
    tmp_path: Path,
):
    catalog = _build(
        tmp_path,
        {
            "recon.md": _selection_table(
                [("CROSS_VM_SERIALIZATION_CONFORMANCE", "YES")]
            )
        },
    )
    coverage = S.build_skill_consumer_coverage(
        selection_catalog=catalog,
        scheduled_consumers=[
            {"consumer_id": "breadth:B2", "kind": "breadth", "focus": "access_control"},
            {"consumer_id": "breadth:B1", "kind": "breadth", "focus": "core_state"},
            {"consumer_id": "depth:external", "kind": "depth", "role": "external"},
        ],
        existing_bindings={},
    )
    row = next(
        item for item in coverage["skills"]
        if item["skill_id"] == "CROSS_VM_SERIALIZATION_CONFORMANCE"
    )
    assert {item["consumer_id"] for item in row["consumers"]} == {
        "breadth:B1",
        "depth:external",
    }
    assert row["dispositions"] == []


def test_index_skill_metadata_conflict_is_unknown_and_never_injected(tmp_path: Path):
    catalog = _build(
        tmp_path,
        {"recon.md": _selection_table([("ORACLE_ANALYSIS", "YES")])},
        conflict=True,
    )
    coverage = S.build_skill_consumer_coverage(
        selection_catalog=catalog,
        scheduled_consumers=_scheduled(),
        existing_bindings={},
    )
    row = next(r for r in coverage["skills"] if r["skill_id"] == "ORACLE_ANALYSIS")
    assert row["status"] == "UNKNOWN"
    assert not any(
        "ORACLE_ANALYSIS" in skills for skills in coverage["effective_bindings"].values()
    )
    assert any(d["code"] == "CONSUMER_METADATA_CONFLICT" for d in coverage["debts"])


def test_catalog_and_coverage_are_digest_bound_and_idempotent(tmp_path: Path):
    source = {"recon.md": _selection_table([("ORACLE_ANALYSIS", "YES")])}
    catalog = _build(tmp_path, source)
    p = tmp_path / "skill_selection_catalog.json"
    S.write_authority_artifact(p, catalog)
    first = p.read_bytes()
    S.write_authority_artifact(p, catalog)
    assert p.read_bytes() == first
    loaded = json.loads(first)
    assert loaded["authority"]["mode"] == "thorough"
    assert loaded["authority"]["ecosystem"] == "evm"
    assert loaded["authority"]["backend"] == "claude-pty"
    assert loaded["authority"]["skill_index_sha256"]
    assert loaded["authority"]["methodology_set_sha256"]
    assert loaded["artifact_sha256"] == S.authority_artifact_digest(loaded)


def test_crlf_and_lf_have_same_selection_semantics(tmp_path: Path):
    lf = _selection_table([("ORACLE_ANALYSIS", "YES")])
    a = _build(tmp_path / "a", {"recon.md": lf})
    b = _build(tmp_path / "b", {"recon.md": lf.replace("\n", "\r\n")})
    assert [(r["skill_id"], r["state"]) for r in a["skills"]] == [
        (r["skill_id"], r["state"]) for r in b["skills"]
    ]


def test_backend_descriptors_change_only_bound_backend_fields(tmp_path: Path):
    source = {"recon.md": _selection_table([("ORACLE_ANALYSIS", "YES")])}
    claude = _build(tmp_path / "c", source, backend="claude-pty")
    codex = _build(tmp_path / "x", source, backend="codex")
    c = S.semantic_authority_projection(claude)
    x = S.semantic_authority_projection(codex)
    assert c == x


@pytest.mark.parametrize("ecosystem", ["evm", "solana", "aptos", "sui", "soroban"])
def test_production_catalog_resolves_only_active_ecosystem_and_shared_skills(ecosystem: str):
    root = Path(__file__).resolve().parents[1]
    catalog = S.build_skill_selection_catalog(
        skill_index_path=root / "rules" / "skill-index.md",
        skill_root=root / "agents" / "skills",
        ecosystem=ecosystem,
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
        source_texts={},
    )
    assert catalog["skills"]
    assert all(row["methodology_sha256"] != "MISSING" for row in catalog["skills"])
    assert all(row["consumer_metadata_status"] == "CURRENT" for row in catalog["skills"])
    assert all(
        row["catalog_scope"] in {ecosystem, "injectable", "niche"}
        for row in catalog["skills"]
    )
    cross_vm = {row["skill_id"] for row in catalog["skills"]} & {
        "CROSS_VM_SERIALIZATION_CONFORMANCE"
    }
    assert bool(cross_vm) is (ecosystem == "evm")


def test_validator_materializers_write_selection_and_consumer_authority(
    tmp_path: Path, monkeypatch
):
    index, skills = _catalog(tmp_path / "home")
    home = index.parent
    # Validator hooks resolve the production layout under plamen_home().
    rules = home / "rules"
    rules.mkdir(exist_ok=True)
    index.replace(rules / "skill-index.md")
    agents_skills = home / "agents" / "skills"
    agents_skills.parent.mkdir(parents=True, exist_ok=True)
    skills.replace(agents_skills)
    monkeypatch.setattr(V, "plamen_home", lambda: home)

    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "recon_templates_patterns.md").write_text(
        _selection_table([("ORACLE_ANALYSIS", "YES")])
        + '<!-- PLAMEN_SIGNALS: {"required_skills":["ORACLE_ANALYSIS"]} -->\n',
        encoding="utf-8",
    )
    (scratch / "spawn_manifest.md").write_text(
        """# Spawn Manifest

## Breadth Agents

| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |
|---|---|---|---|---|---|---|
| AGENT | ORACLE_ANALYSIS | YES | B1 | oracle | analysis_oracle.md | QUEUED |
| AGENT | GENERAL | YES | B2 | access_control | analysis_access.md | QUEUED |
""",
        encoding="utf-8",
    )

    catalog, selection_issues = V._materialize_skill_selection_authority(
        scratch,
        language="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )
    coverage, coverage_issues = V._materialize_skill_consumer_authority(
        scratch,
        language="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )
    assert selection_issues == []
    assert coverage_issues == []
    assert (scratch / "skill_selection_catalog.json").is_file()
    assert (scratch / "skill_consumer_coverage.json").is_file()
    oracle = next(row for row in coverage["skills"] if row["skill_id"] == "ORACLE_ANALYSIS")
    assert {row["consumer_id"] for row in oracle["consumers"]} == {
        "breadth:B1",
        "breadth:B2",
        "depth:external",
        "depth:edge_case",
    }
    assert V._skill_authority_gate_issues(
        scratch,
        language="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    ) == []


def test_validator_gate_detects_tampered_authority_receipt(tmp_path: Path, monkeypatch):
    index, skills = _catalog(tmp_path / "home")
    home = index.parent
    rules = home / "rules"
    rules.mkdir(exist_ok=True)
    index.replace(rules / "skill-index.md")
    agents_skills = home / "agents" / "skills"
    agents_skills.parent.mkdir(parents=True, exist_ok=True)
    skills.replace(agents_skills)
    monkeypatch.setattr(V, "plamen_home", lambda: home)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "recon_templates_patterns.md").write_text(
        _selection_table([("ORACLE_ANALYSIS", "YES")]), encoding="utf-8"
    )
    (scratch / "spawn_manifest.md").write_text(
        "| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |\n"
        "|---|---|---|---|---|---|---|\n"
        "| AGENT | ORACLE_ANALYSIS | YES | B1 | oracle | analysis_oracle.md | QUEUED |\n",
        encoding="utf-8",
    )
    V._materialize_skill_consumer_authority(
        scratch,
        language="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )
    path = scratch / "skill_consumer_coverage.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["effective_bindings"]["breadth:B1"] = []
    path.write_text(json.dumps(value), encoding="utf-8")
    issues = V._skill_authority_gate_issues(
        scratch,
        language="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )
    assert any("digest mismatch" in issue for issue in issues)


def test_validator_gate_detects_recon_source_and_full_methodology_drift(
    tmp_path: Path, monkeypatch
):
    index, skills = _catalog(tmp_path / "home")
    home = index.parent
    rules = home / "rules"
    rules.mkdir(exist_ok=True)
    index.replace(rules / "skill-index.md")
    agents_skills = home / "agents" / "skills"
    agents_skills.parent.mkdir(parents=True, exist_ok=True)
    skills.replace(agents_skills)
    monkeypatch.setattr(V, "plamen_home", lambda: home)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    source = scratch / "recon_templates_patterns.md"
    source.write_text(_selection_table([("ORACLE_ANALYSIS", "YES")]), encoding="utf-8")
    (scratch / "spawn_manifest.md").write_text(
        "| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |\n"
        "|---|---|---|---|---|---|---|\n"
        "| AGENT | ORACLE_ANALYSIS | YES | B1 | oracle | analysis_oracle.md | QUEUED |\n",
        encoding="utf-8",
    )
    V._materialize_skill_consumer_authority(
        scratch,
        language="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )
    source.write_text(source.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
    nonselected = agents_skills / "evm" / "token-flow-tracing" / "SKILL.md"
    nonselected.write_text(nonselected.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
    issues = V._skill_authority_gate_issues(
        scratch,
        language="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )
    assert "skill selection authority recon source digests are stale" in issues
    assert "skill selection authority methodology-set digest is stale" in issues


def _runtime_home(tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
    """Install the compact fixture catalog under the production directory shape."""
    index, skills = _catalog(tmp_path / "home")
    home = index.parent
    rules = home / "rules"
    rules.mkdir(exist_ok=True)
    index.replace(rules / "skill-index.md")
    agents_skills = home / "agents" / "skills"
    agents_skills.parent.mkdir(parents=True, exist_ok=True)
    skills.replace(agents_skills)
    monkeypatch.setattr(V, "plamen_home", lambda: home)
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    return home, agents_skills


def _runtime_manifest(*, template: str = "ORACLE_ANALYSIS") -> str:
    return f"""# Spawn Manifest

## Breadth Agents

| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |
|---|---|---|---|---|---|---|
| AGENT | {template} | YES | B1 | oracle | analysis_oracle.md | QUEUED |
| AGENT | GENERAL | YES | B2 | access_control | analysis_access.md | QUEUED |
"""


def _stub_recon_validator_dependencies(monkeypatch) -> None:
    """Keep the ordering fixtures scoped to recon's final producer boundary."""
    monkeypatch.setattr(D, "gate_passes", lambda *_args, **_kwargs: (True, []))
    monkeypatch.setattr(
        D,
        "_ensure_recon_dependency_parity",
        lambda *_args, **_kwargs: {"researched": 0, "unresolved": 0},
    )
    monkeypatch.setattr(
        D, "_detect_foreign_phase_writes", lambda *_args, **_kwargs: []
    )
    monkeypatch.setattr(
        D, "_materialize_sc_slither_flat_files", lambda *_args, **_kwargs: []
    )
    monkeypatch.setattr(
        D,
        "_validate_recon_content_structure",
        lambda *_args, **_kwargs: ([], []),
    )
    monkeypatch.setattr(
        D, "_reconcile_skill_manifest_sources", lambda *_args, **_kwargs: 0
    )
    monkeypatch.setattr(
        D, "_skill_manifest_reconciliation_issues", lambda *_args, **_kwargs: []
    )
    monkeypatch.setattr(
        D, "_selected_skill_manifest_issues", lambda *_args, **_kwargs: []
    )
    monkeypatch.setattr(
        D, "_validate_injectable_promotion", lambda *_args, **_kwargs: []
    )


def _recon_validator_config(project: Path, scratch: Path) -> dict[str, object]:
    return {
        "project_root": str(project),
        "scratchpad": str(scratch),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude-pty",
    }


def test_live_recon_and_instantiate_boundaries_materialize_and_phaseio_bind(
    tmp_path: Path, monkeypatch
):
    _runtime_home(tmp_path, monkeypatch)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "recon_templates_patterns.md").write_text(
        _selection_table([("ORACLE_ANALYSIS", "YES")]), encoding="utf-8"
    )
    (scratch / "spawn_manifest.md").write_text(
        _runtime_manifest(), encoding="utf-8"
    )
    config = {
        "project_root": str(tmp_path),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude-pty",
        "_run_id": "skill-live-test",
    }

    recon_issues = D._materialize_live_skill_selection_boundary(scratch, config)
    instantiate_issues = D._materialize_live_skill_consumer_boundary(scratch, config)

    assert recon_issues == []
    assert instantiate_issues == []
    assert (scratch / "skill_selection_catalog.json").is_file()
    assert (scratch / "skill_consumer_coverage.json").is_file()
    ledger = json.loads((scratch / "_artifact_state.json").read_text(encoding="utf-8"))
    keys = set(ledger["work_units"])
    assert any(key.endswith("/recon/skill_selection_authority") for key in keys)
    assert any(key.endswith("/instantiate/skill_consumer_authority") for key in keys)


def test_live_skill_selection_resumes_exact_prebind_after_precommit_crash(
    tmp_path: Path, monkeypatch
):
    _runtime_home(tmp_path, monkeypatch)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "recon_templates_patterns.md").write_text(
        _selection_table([("ORACLE_ANALYSIS", "YES")]), encoding="utf-8"
    )
    config = {
        "project_root": str(tmp_path),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude-pty",
        "_run_id": "skill-precommit-crash",
    }
    original_commit = D._commit_deterministic_driver_work_unit
    monkeypatch.setattr(
        D,
        "_commit_deterministic_driver_work_unit",
        lambda **_kwargs: ["simulated crash before output commit"],
    )

    first = D._materialize_live_skill_selection_boundary(scratch, config)

    assert first == ["simulated crash before output commit"]
    output = scratch / "skill_selection_catalog.json"
    assert output.is_file()
    ledger = read_artifact_ledger(scratch)
    unit = next(
        row
        for key, row in ledger["work_units"].items()
        if key.endswith("/recon/skill_selection_authority")
    )
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert unit["output_prestates"][
        "scratchpad:skill_selection_catalog.json"
    ]["status"] == "ABSENT"

    monkeypatch.setattr(
        D, "_commit_deterministic_driver_work_unit", original_commit
    )
    assert D._materialize_live_skill_selection_boundary(scratch, config) == []
    ledger = read_artifact_ledger(scratch)
    unit = next(
        row
        for key, row in ledger["work_units"].items()
        if key.endswith("/recon/skill_selection_authority")
    )
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert not (scratch / "recon.degraded").exists()


def test_live_skill_consumer_never_rewrites_committed_selection_input(
    tmp_path: Path, monkeypatch
):
    _runtime_home(tmp_path, monkeypatch)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "recon_templates_patterns.md").write_text(
        _selection_table([("ORACLE_ANALYSIS", "YES")]), encoding="utf-8"
    )
    (scratch / "spawn_manifest.md").write_text(
        _runtime_manifest(), encoding="utf-8"
    )
    config = {
        "project_root": str(tmp_path),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude-pty",
        "_run_id": "skill-consumer-no-rewrite",
    }
    assert D._materialize_live_skill_selection_boundary(scratch, config) == []
    selection = scratch / "skill_selection_catalog.json"
    before = selection.read_bytes()

    assert D._materialize_live_skill_consumer_boundary(scratch, config) == []

    assert selection.read_bytes() == before
    ledger = read_artifact_ledger(scratch)
    binding = ledger["artifact_bindings"][
        "scratchpad:skill_selection_catalog.json"
    ]
    assert binding["owner_key"].endswith("/recon/skill_selection_authority")


def test_recon_late_validation_failure_does_not_commit_selection_authority(
    tmp_path: Path, monkeypatch
):
    """A failed producer attempt must not publish a terminal authority row."""
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _stub_recon_validator_dependencies(monkeypatch)
    monkeypatch.setattr(
        D,
        "_validate_recon_coverage",
        lambda *_args, **_kwargs: ["late recon coverage failure"],
    )
    calls: list[str] = []
    monkeypatch.setattr(
        D,
        "_materialize_live_skill_selection_boundary",
        lambda *_args, **_kwargs: calls.append("materialized") or [],
    )
    phase = next(row for row in D.SC_PHASES if row.name == "recon")

    passed, missing = D._run_phase_validators(
        phase,
        _recon_validator_config(project, scratch),
        scratch,
        D.SC_PHASES,
        0,
        {},
    )

    assert passed is False
    assert any("late recon coverage failure" in str(row) for row in missing)
    assert calls == []


def test_recon_selection_authority_observes_committed_source_without_gate_mutation(
    tmp_path: Path, monkeypatch
):
    """The read-only gate binds the renderer's already-committed source."""
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    source = scratch / "recon_templates_patterns.md"
    source.write_text("# CANONICAL-PROMOTED source\n", encoding="utf-8")
    _stub_recon_validator_dependencies(monkeypatch)
    monkeypatch.setattr(
        D, "_validate_recon_coverage", lambda *_args, **_kwargs: []
    )

    observed: list[str] = []

    def _observe(root: Path, _config: dict[str, object]) -> list[str]:
        observed.append(
            (Path(root) / source.name).read_text(encoding="utf-8")
        )
        return []

    monkeypatch.setattr(
        D,
        "_reconcile_skill_manifest_sources",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("recon gate must not mutate canonical source")
        ),
    )
    monkeypatch.setattr(D, "_materialize_live_skill_selection_boundary", _observe)
    phase = next(row for row in D.SC_PHASES if row.name == "recon")

    passed, missing = D._run_phase_validators(
        phase,
        _recon_validator_config(project, scratch),
        scratch,
        D.SC_PHASES,
        0,
        {},
    )

    assert passed is True
    assert missing == []
    assert len(observed) == 1
    assert "CANONICAL-PROMOTED" in observed[0]


def test_live_selection_boundary_authorizes_input_driven_deterministic_refresh(
    tmp_path: Path, monkeypatch
):
    _runtime_home(tmp_path, monkeypatch)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    source = scratch / "recon_templates_patterns.md"
    source.write_text(
        _selection_table([("ORACLE_ANALYSIS", "YES")]), encoding="utf-8"
    )
    config = {
        "project_root": str(tmp_path),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude-pty",
        "_run_id": "skill-retry-test",
    }
    assert D._materialize_live_skill_selection_boundary(scratch, config) == []
    source.write_text(
        source.read_text(encoding="utf-8") + "\n## Retry evidence\n",
        encoding="utf-8",
    )

    issues = D._materialize_live_skill_selection_boundary(scratch, config)

    assert issues == []
    assert not (scratch / "recon.degraded").exists()
    ledger = read_artifact_ledger(scratch)
    unit = next(
        row
        for key, row in ledger["work_units"].items()
        if key.endswith("/recon/skill_selection_authority")
    )
    assert unit["semantic_status"] == "ACTIVE"
    history = unit["semantic_reexecution_history"]
    assert len(history) == 1
    assert history[0]["changed_input_identities"] == [
        "scratchpad:recon_templates_patterns.md"
    ]


def test_live_selection_boundary_accepts_preapplied_exact_invalidation(
    tmp_path: Path, monkeypatch
):
    _runtime_home(tmp_path, monkeypatch)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    source = scratch / "recon_templates_patterns.md"
    source.write_text(
        _selection_table([("ORACLE_ANALYSIS", "YES")]), encoding="utf-8"
    )
    config = {
        "project_root": str(tmp_path),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude-pty",
        "_run_id": "skill-retry-authorized-test",
    }
    assert D._materialize_live_skill_selection_boundary(scratch, config) == []
    source.write_text(
        source.read_text(encoding="utf-8") + "\n## Retry evidence\n",
        encoding="utf-8",
    )

    ledger = read_artifact_ledger(scratch)
    plan = semantic_dependency_invalidation_plan(
        ledger,
        ["scratchpad:recon_templates_patterns.md"],
        run_id=config["_run_id"],
    )
    assert len(plan["invalidated_work_unit_keys"]) == 1
    assert plan["invalidated_work_unit_keys"][0].endswith(
        "/recon/skill_selection_authority"
    )
    apply_semantic_invalidation(
        scratch, plan, run_id=config["_run_id"]
    )

    assert D._materialize_live_skill_selection_boundary(scratch, config) == []
    assert not (scratch / "recon.degraded").exists()
    ledger = read_artifact_ledger(scratch)
    unit = next(
        row
        for key, row in ledger["work_units"].items()
        if key.endswith("/recon/skill_selection_authority")
    )
    assert unit["semantic_status"] == "ACTIVE"
    history = unit["semantic_reexecution_history"]
    assert len(history) == 1
    assert history[0]["plan_digest"] == plan["plan_digest"]


def test_clean_typed_consumer_authority_supersedes_conflicting_manifest_prose(
    tmp_path: Path, monkeypatch
):
    _runtime_home(tmp_path, monkeypatch)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    # Recon's exact-polarity producer says TOKEN_FLOW is not selected.  The
    # later Markdown manifest nevertheless claims it is assigned to B1.
    (scratch / "recon_templates_patterns.md").write_text(
        _selection_table(
            [("ORACLE_ANALYSIS", "YES"), ("TOKEN_FLOW_TRACING", "NO")]
        ),
        encoding="utf-8",
    )
    (scratch / "spawn_manifest.md").write_text(
        _runtime_manifest(template="ORACLE_ANALYSIS + TOKEN_FLOW_TRACING"),
        encoding="utf-8",
    )
    V._materialize_skill_consumer_authority(
        scratch,
        language="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )

    breadth, depth = D._parse_sc_skill_bindings(
        scratch,
        "evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )

    assert breadth["oracle"] == ["ALWAYS_SAFE", "ORACLE_ANALYSIS"]
    assert "TOKEN_FLOW_TRACING" not in {
        skill for values in [*breadth.values(), *depth.values()] for skill in values
    }
    # The declared breadth consumer closes over every scheduled breadth lane.
    assert breadth["access_control"] == ["ALWAYS_SAFE", "ORACLE_ANALYSIS"]
    assert set(depth) == {"edge_case", "external"}


def test_invalid_typed_authority_falls_back_additively_and_records_visible_debt(
    tmp_path: Path, monkeypatch
):
    _runtime_home(tmp_path, monkeypatch)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "recon_templates_patterns.md").write_text(
        _selection_table([("ORACLE_ANALYSIS", "YES")]), encoding="utf-8"
    )
    (scratch / "spawn_manifest.md").write_text(
        _runtime_manifest(template="ORACLE_ANALYSIS + TOKEN_FLOW_TRACING"),
        encoding="utf-8",
    )
    V._materialize_skill_consumer_authority(
        scratch,
        language="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )
    coverage_path = scratch / "skill_consumer_coverage.json"
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    coverage["effective_bindings"]["breadth:B1"] = []
    coverage_path.write_text(json.dumps(coverage), encoding="utf-8")

    breadth, _depth = D._parse_sc_skill_bindings(
        scratch,
        "evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )

    assert breadth["oracle"] == ["ORACLE_ANALYSIS", "TOKEN_FLOW_TRACING"]
    debt = scratch / "instantiate.degraded"
    assert debt.is_file()
    assert "SKILL_CONSUMER_AUTHORITY_DEBT" in debt.read_text(encoding="utf-8")


def test_typed_niche_auto_schedule_supersedes_missing_manifest_niche_row(
    tmp_path: Path, monkeypatch
):
    _runtime_home(tmp_path, monkeypatch)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "recon_templates_patterns.md").write_text(
        _selection_table([("SIGNATURE_VERIFICATION_AUDIT", "YES")]),
        encoding="utf-8",
    )
    (scratch / "spawn_manifest.md").write_text(
        _runtime_manifest(template="GENERAL"), encoding="utf-8"
    )
    V._materialize_skill_consumer_authority(
        scratch,
        language="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )

    jobs = D._required_niche_worker_jobs(
        scratch,
        language="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )

    assert [job["agent_id"] for job in jobs] == [
        "niche-signature-verification-audit"
    ]
    assert jobs[0]["output"] == "niche_signature_verification_audit_findings.md"


def test_resume_contract_rejects_stale_selection_and_consumer_sources(
    tmp_path: Path, monkeypatch
):
    _runtime_home(tmp_path, monkeypatch)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    source = scratch / "recon_templates_patterns.md"
    source.write_text(
        _selection_table([("ORACLE_ANALYSIS", "YES")]), encoding="utf-8"
    )
    manifest = scratch / "spawn_manifest.md"
    manifest.write_text(_runtime_manifest(), encoding="utf-8")
    V._materialize_skill_consumer_authority(
        scratch,
        language="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )
    recon_phase = next(phase for phase in D.SC_PHASES if phase.name == "recon")
    instantiate_phase = next(
        phase for phase in D.SC_PHASES if phase.name == "instantiate"
    )

    source.write_text(source.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
    recon_issues = D._resume_phase_contract_issues(
        scratch,
        str(tmp_path),
        recon_phase,
        "thorough",
        "evm",
        "sc",
        "claude-pty",
    )
    assert "skill selection authority recon source digests are stale" in recon_issues

    # Restore selection, then drift the consumer schedule independently.
    V._materialize_skill_consumer_authority(
        scratch,
        language="evm",
        pipeline="sc",
        mode="thorough",
        backend="claude-pty",
    )
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace("access_control", "admin"),
        encoding="utf-8",
    )
    instantiate_issues = D._resume_phase_contract_issues(
        scratch,
        str(tmp_path),
        instantiate_phase,
        "thorough",
        "evm",
        "sc",
        "claude-pty",
    )
    assert any("scheduled-consumer digest is stale" in issue for issue in instantiate_issues)


def test_phase_io_registers_exact_skill_authority_sources_and_outputs():
    selection = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude-pty",
        phase="recon",
        work_unit_id="skill_selection_authority",
        exact_inputs=("recon_templates_patterns.md",),
    )
    assert {spec.identity for spec in selection.outputs} == {
        "scratchpad:skill_selection_catalog.json"
    }
    assert selection.immutable_inputs == (
        "scratchpad:recon_templates_patterns.md",
    )
    assert selection.model_invoked is False

    consumers = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude-pty",
        phase="instantiate",
        work_unit_id="skill_consumer_authority",
    )
    assert {spec.identity for spec in consumers.outputs} == {
        "scratchpad:skill_consumer_coverage.json"
    }
    assert set(consumers.immutable_inputs) == {
        "scratchpad:skill_selection_catalog.json",
        "scratchpad:spawn_manifest.md",
    }
    assert consumers.model_invoked is False
