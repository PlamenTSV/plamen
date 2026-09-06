"""Binding-manifest authority and mode-safe breadth sizing.

Regression source: a Light EVM canary left the canonical Required column at NO
while appending eight positive skill recommendations in prose.  Instantiate
trusted the prose (good for recall) but then followed the shared Complex >=7
instruction (bad for the documented Light 3-4 contract) and spawned 9 workers.

The deterministic boundary must therefore:
  * promote positive prose/signal recommendations into the canonical table;
  * never demote an existing YES and never promote an explicit negative;
  * enforce Light=3-4 independently of codebase tier; and
  * reject a manifest that reaches the cap by silently dropping a required
    skill.  Explicit depth-role carryover is a valid, visible overflow route.
"""
from __future__ import annotations

from pathlib import Path

import plamen_validators as V


_BREADTH_HEADER = (
    "| Row Type | Template | Required? | Agent ID | Focus Area | "
    "Expected Output | Status |\n"
    "|---|---|---|---|---|---|---|\n"
)


def _write_recommendations(sp: Path, prose: str = "") -> None:
    (sp / "template_recommendations.md").write_text(
        "# Template Recommendations\n\n"
        "## BINDING MANIFEST\n\n"
        "### EVM Skills\n\n"
        "| Skill | Trigger | Required | Rationale |\n"
        "|---|---|---|---|\n"
        "| `ORACLE_ANALYSIS` | ORACLE flag | NO | [LLM TO ENRICH] |\n"
        "| `TOKEN_FLOW_TRACING` | BALANCE_DEPENDENT flag | NO | [LLM TO ENRICH] |\n"
        "| `MIGRATION_ANALYSIS` | MIGRATION flag | NO | [LLM TO ENRICH] |\n"
        "| `SEMI_TRUSTED_ROLES` | role flag | YES | existing evidence |\n\n"
        "### Injectable Skills\n\n"
        "| Skill | Trigger | Required | Rationale |\n"
        "|---|---|---|---|\n"
        "| `VAULT_ACCOUNTING` | vault | NO | [LLM TO ENRICH] |\n\n"
        + prose,
        encoding="utf-8",
    )


def _row(template: str, n: int) -> str:
    return (
        f"| AGENT | {template} | YES | B{n} | focus_{n} | "
        f"analysis_{n}.md | QUEUED |\n"
    )


def _write_spawn(sp: Path, templates: list[str], extra: str = "") -> None:
    rows = "".join(_row(t, i + 1) for i, t in enumerate(templates))
    (sp / "spawn_manifest.md").write_text(
        "# Spawn Manifest\n\n## Breadth Agents\n\n"
        + _BREADTH_HEADER
        + rows
        + extra,
        encoding="utf-8",
    )


def test_reconcile_positive_prose_to_canonical_table_without_demoting(tmp_path):
    _write_recommendations(
        tmp_path,
        "## Template / Skill Recommendations\n\n"
        "**Injectable skills (protocol-type):**\n"
        "- `VAULT_ACCOUNTING` -- vault behavior is present; strong trigger.\n\n"
        "**Always-on EVM skills relevant to this codebase:**\n"
        "- `ORACLE_ANALYSIS` -- price boundary evidence.\n"
        "- `TOKEN_FLOW_TRACING` -- balance accounting evidence.\n"
        "- `MIGRATION_ANALYSIS` -- not triggered; no migration path observed.\n",
    )

    changed = V._reconcile_skill_manifest_sources(tmp_path)
    text = (tmp_path / "template_recommendations.md").read_text(encoding="utf-8")

    assert changed == 3
    for skill in (
        "ORACLE_ANALYSIS", "TOKEN_FLOW_TRACING", "VAULT_ACCOUNTING",
        "SEMI_TRUSTED_ROLES",
    ):
        assert skill in V._required_skill_tokens_from_binding_manifest(text)
    assert "MIGRATION_ANALYSIS" not in V._required_skill_tokens_from_binding_manifest(text)


def test_reconcile_accepts_machine_signal_and_is_idempotent(tmp_path):
    _write_recommendations(
        tmp_path,
        '<!-- PLAMEN_SIGNALS: {"required_skills":["ORACLE_ANALYSIS"]} -->\n',
    )
    # One signal-selected row is promoted, and the pre-existing mechanical
    # Required=YES row is added back into the typed signal.
    assert V._reconcile_skill_manifest_sources(tmp_path) == 2
    first = (tmp_path / "template_recommendations.md").read_bytes()
    assert b'"required_skills":["ORACLE_ANALYSIS","SEMI_TRUSTED_ROLES"]' in first
    assert V._reconcile_skill_manifest_sources(tmp_path) == 0
    assert (tmp_path / "template_recommendations.md").read_bytes() == first


def test_catalog_trigger_text_and_explicit_negative_do_not_promote(tmp_path):
    _write_recommendations(
        tmp_path,
        "## Template / Skill Recommendations\n\n"
        "- `MIGRATION_ANALYSIS` -- not triggered.\n",
    )
    assert V._reconcile_skill_manifest_sources(tmp_path) == 0


def test_light_rejects_nine_workers_even_when_complex_floor_would_allow(tmp_path):
    _write_recommendations(tmp_path)
    _write_spawn(
        tmp_path,
        ["ORACLE_ANALYSIS", "TOKEN_FLOW_TRACING", "SEMI_TRUSTED_ROLES"]
        + ["GENERAL"] * 6,
    )
    issues = V._validate_spawn_manifest_schema(tmp_path, mode="light")
    assert any("Light mode requires 3-4" in issue for issue in issues), issues


def test_light_four_workers_passes_count_policy(tmp_path):
    _write_recommendations(tmp_path)
    _write_spawn(
        tmp_path,
        ["ORACLE_ANALYSIS", "TOKEN_FLOW_TRACING", "SEMI_TRUSTED_ROLES", "GENERAL"],
    )
    issues = V._validate_spawn_manifest_schema(tmp_path, mode="light")
    assert not any("Light mode requires 3-4" in issue for issue in issues), issues


def test_light_cap_cannot_silently_drop_required_skill(tmp_path):
    _write_recommendations(
        tmp_path,
        "## Template / Skill Recommendations\n\n"
        "- `ORACLE_ANALYSIS` -- strong trigger.\n",
    )
    assert V._reconcile_skill_manifest_sources(tmp_path) == 1
    _write_spawn(
        tmp_path,
        ["TOKEN_FLOW_TRACING", "SEMI_TRUSTED_ROLES", "GENERAL", "GENERAL"],
    )
    issues = V._validate_spawn_manifest_schema(tmp_path, mode="light")
    assert any("required skill binding missing" in issue and "ORACLE_ANALYSIS" in issue
               for issue in issues), issues


def test_light_overflow_may_be_explicitly_carried_to_depth(tmp_path):
    _write_recommendations(
        tmp_path,
        "## Template / Skill Recommendations\n\n"
        "- `ORACLE_ANALYSIS` -- strong trigger.\n",
    )
    assert V._reconcile_skill_manifest_sources(tmp_path) == 1
    _write_spawn(
        tmp_path,
        ["TOKEN_FLOW_TRACING", "SEMI_TRUSTED_ROLES", "GENERAL", "GENERAL"],
        extra=(
            "\n## Skill Bindings\n\n"
            "| Skill | Required? | Inject Into | Delivery |\n"
            "|---|---|---|---|\n"
            "| ORACLE_ANALYSIS | YES | depth-external | full methodology |\n"
        ),
    )
    issues = V._validate_spawn_manifest_schema(tmp_path, mode="light")
    assert not any("required skill binding missing" in issue for issue in issues), issues


def test_decorative_or_nonexistent_assignment_does_not_fake_coverage(tmp_path):
    _write_recommendations(
        tmp_path,
        "## Template / Skill Recommendations\n\n"
        "- `ORACLE_ANALYSIS` -- strong trigger.\n",
    )
    assert V._reconcile_skill_manifest_sources(tmp_path) == 1
    _write_spawn(
        tmp_path,
        ["TOKEN_FLOW_TRACING", "SEMI_TRUSTED_ROLES", "GENERAL", "GENERAL"],
        extra=(
            "\n## Skill Bindings\n\n"
            "| Skill | Required? | Assigned To | Delivery |\n"
            "|---|---|---|---|\n"
            "| ORACLE_ANALYSIS | YES | B99 later | full methodology |\n"
        ),
    )
    issues = V._validate_spawn_manifest_schema(tmp_path, mode="light")
    assert any("required skill binding missing" in issue for issue in issues), issues
