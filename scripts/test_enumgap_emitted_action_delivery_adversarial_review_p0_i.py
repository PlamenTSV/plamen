"""Reviewer-owned adversarial fixtures for P0-I promotion delivery authority."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import enumeration_gate as EG
import plamen_driver as D
import plamen_validators as V
from enumgap_markdown import enumgap_reference_heading_ids
from exploration_clear_lifecycle import compile_initial_receipt, write_lifecycle_artifacts
from finding_producer_registry import validated_enumgap_obligation_dispositions
from operational_markdown import operational_markdown_view
from plamen_types import Phase


def _phase() -> Phase:
    return Phase(
        "enumgap_exploration",
        ["Phase 4b.7"],
        ["enumgap_exploration_findings.md"],
        base_timeout_s=120,
        modes={"core", "thorough"},
        critical=False,
        model="sonnet",
    )


def _inventory_phase() -> Phase:
    return Phase(
        "inventory",
        ["Phase 4a"],
        ["findings_inventory.md"],
        base_timeout_s=120,
        modes={"core", "thorough"},
        critical=True,
        model="sonnet",
    )


def _config(project: Path) -> dict[str, object]:
    return {
        "project_root": str(project),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "_run_id": "52345678-1234-4567-8abc-1234567890ab",
    }


def _finding_block(
    action_id: str = "NEXP-1",
    *,
    title: str = "traced candidate",
    description: str = "A concrete traced candidate remains for verification.",
    heading: str = "##",
) -> str:
    return (
        f"{heading} Finding [{action_id}]: {title}\n\n"
        "**Severity**: Low\n\n"
        "**Location**: src/Unit.sol:L1\n\n"
        f"**Description**: {description}\n\n"
    )


def _seed_emitted_action(
    project: Path,
    *,
    finding_text: str | None = None,
) -> tuple[Path, str]:
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    (project / "src").mkdir()
    (project / "src" / "Unit.sol").write_text("one\ntwo\n", encoding="utf-8")
    source = scratch / "exploration_skeptic_findings.md"
    source.write_text(
        "# Exploration\n\n## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| BASE-1 | sibling | inverse | NO-GAP | vague wording |\n",
        encoding="utf-8",
    )
    initial = compile_initial_receipt(
        source, production_root=project, canonical_prior_ids={}
    )
    write_lifecycle_artifacts(scratch, initial)
    obligation_id = initial.obligations[0].obligation_id
    assert D._bind_typed_model_phase_inputs(
        _inventory_phase(), scratch, _config(project)
    ) == []
    (scratch / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Seed\n"
        "**Source IDs**: [BASE-0]\n"
        "**Severity**: Low\n"
        "**Location**: src/Unit.sol:L1\n"
        "**Description**: retained seed.\n",
        encoding="utf-8",
    )
    assert D._record_typed_model_phase_artifacts(
        _inventory_phase(), scratch, _config(project)
    ) == []
    worklist, issues = D._prepare_enumgap_disposition_worklist(
        _phase(), _config(project), scratch
    )
    assert issues == [] and worklist["count"] == 1
    assert D._bind_typed_model_phase_inputs(
        _phase(), scratch, _config(project)
    ) == []
    (scratch / "enumgap_exploration_findings.md").write_text(
        "# Enumgap\n\n"
        + (finding_text if finding_text is not None else _finding_block())
        + "## Coverage Record\n\n"
        "| Obligation | Relationship | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        f"| {obligation_id} | sibling / inverse | FINDING | NEXP-1 |\n",
        encoding="utf-8",
    )
    assert D._record_typed_model_phase_artifacts(
        _phase(), scratch, _config(project)
    ) == []
    receipt, reconcile_issues = D._reconcile_enumgap_dispositions(
        _phase(), _config(project), scratch
    )
    assert reconcile_issues == [] and receipt["status"] == "CLEAN"
    return scratch, obligation_id


def _delivery(scratch: Path, obligation_id: str) -> tuple[dict, dict]:
    V._promote_depth_findings_to_inventory(scratch)
    payload = json.loads(
        (scratch / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = next(
        item for item in payload["actions"] if item["action_id"] == obligation_id
    )
    return row, payload


def _assert_delivery_debt(scratch: Path, obligation_id: str) -> None:
    row, payload = _delivery(scratch, obligation_id)
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_REQUIRED"
    assert "promotion_delivery_id" not in row
    assert payload["accounted_action_count"] == 0


def test_inventory_append_failure_cannot_dispose_parsed_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_emitted_action(project)
    inventory = scratch / "findings_inventory.md"
    monkeypatch.setattr(
        EG,
        "_atomic_inventory_replace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("injected inventory append failure")
        ),
    )
    outcome = EG.promote_enumgap_exploration_to_inventory(scratch)
    assert outcome["parsed"] == 1
    assert outcome["emitted"] == 0
    assert outcome.get("debt")
    monkeypatch.undo()

    assert "NEXP-1" not in inventory.read_text(encoding="utf-8")
    assert not (scratch / "enumgap_exploration_promotion_receipt.json").exists()
    _assert_delivery_debt(scratch, obligation_id)


def test_concurrent_inventory_suffix_is_never_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_emitted_action(project)
    inventory = scratch / "findings_inventory.md"
    original = EG._append_inventory_blocks
    injected = b"\n<!-- concurrent inventory writer -->\n"

    def race(
        current: str, header: str, blocks: list[str],
    ) -> str:
        rendered = original(current, header, blocks)
        inventory.write_bytes(inventory.read_bytes() + injected)
        return rendered

    monkeypatch.setattr(EG, "_append_inventory_blocks", race)
    outcome = EG.promote_enumgap_exploration_to_inventory(scratch)

    assert injected in inventory.read_bytes()
    assert outcome.get("emitted") == 0
    assert outcome.get("debt")
    _assert_delivery_debt(scratch, obligation_id)


def test_live_driver_inventory_append_has_exact_phaseio_merge_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, _ = _seed_emitted_action(project)

    outcome = D._promote_enumgap_exploration_transaction(
        _phase(), _config(project), scratch
    )

    assert outcome == {"parsed": 1, "emitted": 1}
    state = json.loads(
        (scratch / "_artifact_state.json").read_text(encoding="utf-8")
    )
    key = "sc/thorough/evm/claude/enumgap_delivery/inventory_append"
    assert state["work_units"][key]["semantic_status"] == "ACTIVE"
    assert state["work_units"][key]["execution_state"] == "OUTPUT_COMMITTED"
    assert D._promote_enumgap_exploration_transaction(
        _phase(), _config(project), scratch
    ) == {"parsed": 1, "emitted": 0}


def test_non_utf8_enumgap_source_is_visible_delivery_debt(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_emitted_action(project)
    source = scratch / "enumgap_exploration_findings.md"
    source.write_bytes(source.read_bytes() + b"\xff")

    outcome = EG.promote_enumgap_exploration_to_inventory(scratch)

    assert outcome.get("emitted") == 0
    assert outcome.get("debt")
    _assert_delivery_debt(scratch, obligation_id)


def test_json_receipt_write_failure_repairs_without_duplicate_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_emitted_action(project)

    original_json_write = EG._write_json_atomic

    def fail_json_receipt(path: Path, payload: dict) -> None:
        if path.name == "enumgap_exploration_promotion_receipt.json":
            raise OSError("injected JSON receipt failure")
        original_json_write(path, payload)

    monkeypatch.setattr(EG, "_write_json_atomic", fail_json_receipt)
    first = EG.promote_enumgap_exploration_to_inventory(scratch)
    assert first["parsed"] == 1
    assert first["emitted"] == 1
    assert first.get("debt")
    assert not (scratch / "enumgap_exploration_promotion_receipt.json").exists()
    _assert_delivery_debt(scratch, obligation_id)
    inventory_before = (scratch / "findings_inventory.md").read_text(encoding="utf-8")

    monkeypatch.undo()
    assert EG.promote_enumgap_exploration_to_inventory(scratch) == {
        "parsed": 1,
        "emitted": 0,
    }
    assert (scratch / "findings_inventory.md").read_text(
        encoding="utf-8"
    ) == inventory_before
    assert "NEXP-1" in EG.validated_enumgap_promotion_deliveries(scratch)


def test_total_receipt_failure_resume_does_not_duplicate_delivered_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_emitted_action(project)
    monkeypatch.setattr(EG, "_write_enumgap_promotion_receipts", lambda *args: False)
    first = EG.promote_enumgap_exploration_to_inventory(scratch)
    assert first["parsed"] == 1
    assert first["emitted"] == 1
    assert first.get("debt")
    _assert_delivery_debt(scratch, obligation_id)
    inventory_before = (scratch / "findings_inventory.md").read_text(encoding="utf-8")

    monkeypatch.undo()
    assert EG.promote_enumgap_exploration_to_inventory(scratch) == {
        "parsed": 1,
        "emitted": 0,
    }
    assert (scratch / "findings_inventory.md").read_text(
        encoding="utf-8"
    ) == inventory_before


def test_bound_source_and_inventory_block_drift_revoke_delivery(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, _ = _seed_emitted_action(project)
    assert EG.promote_enumgap_exploration_to_inventory(scratch)["emitted"] == 1

    source = scratch / "enumgap_exploration_findings.md"
    original_source = source.read_text(encoding="utf-8")
    source.write_text(original_source.replace("traced candidate", "changed title"), encoding="utf-8")
    with pytest.raises(ValueError, match="binding mismatch"):
        EG.validated_enumgap_promotion_deliveries(scratch)

    source.write_text(original_source, encoding="utf-8")
    inventory = scratch / "findings_inventory.md"
    inventory.write_text(
        inventory.read_text(encoding="utf-8").replace(
            "A concrete traced candidate remains for verification.",
            "A drifted inventory description.",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="binding mismatch|identity mismatch"):
        EG.validated_enumgap_promotion_deliveries(scratch)


def test_duplicate_source_action_id_cannot_gain_first_writer_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    duplicate = _finding_block(
        title="first body", description="First conflicting action body."
    ) + _finding_block(
        title="second body", description="Second conflicting action body."
    )
    scratch, obligation_id = _seed_emitted_action(
        project, finding_text=duplicate
    )
    EG.promote_enumgap_exploration_to_inventory(scratch)
    _assert_delivery_debt(scratch, obligation_id)


def test_duplicate_inventory_id_revokes_delivery_identity(tmp_path: Path) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_emitted_action(project)
    assert EG.promote_enumgap_exploration_to_inventory(scratch)["emitted"] == 1
    inventory = scratch / "findings_inventory.md"
    inventory.write_text(
        inventory.read_text(encoding="utf-8")
        + "\n### Finding [INV-002]: conflicting duplicate\n"
        "**Source IDs**: OTHER-1\n"
        "**Severity**: Low\n"
        "**Location**: src/Unit.sol:L1\n"
        "**Description**: conflicting reused inventory identity.\n",
        encoding="utf-8",
    )

    _assert_delivery_debt(scratch, obligation_id)


def test_rehashed_receipt_cannot_redirect_to_second_provenance_claim(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_emitted_action(project)
    assert EG.promote_enumgap_exploration_to_inventory(scratch)["emitted"] == 1
    inventory = scratch / "findings_inventory.md"
    inventory.write_text(
        inventory.read_text(encoding="utf-8")
        + "\n### Finding [INV-999]: forged alternate delivery\n"
        "**Source IDs**: NEXP-1\n"
        "**Severity**: Low\n"
        "**Location**: src/Unit.sol:L1\n"
        "**Description**: an alternate block claiming the same source.\n",
        encoding="utf-8",
    )
    receipt_path = scratch / "enumgap_exploration_promotion_receipt.json"
    forged = json.loads(receipt_path.read_text(encoding="utf-8"))
    blocks = EG._inventory_finding_blocks(inventory.read_text(encoding="utf-8"))
    forged["deliveries"][0]["inventory_id"] = "INV-999"
    forged["deliveries"][0]["inventory_block_sha256"] = blocks["INV-999"][
        "block_sha256"
    ]
    forged["receipt_sha256"] = EG._promotion_receipt_digest(forged)
    receipt_path.write_text(json.dumps(forged), encoding="utf-8")

    _assert_delivery_debt(scratch, obligation_id)


def test_rehashed_inventory_provenance_requires_exact_token_boundary(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_emitted_action(project)
    assert EG.promote_enumgap_exploration_to_inventory(scratch)["emitted"] == 1
    inventory = scratch / "findings_inventory.md"
    inventory.write_text(
        inventory.read_text(encoding="utf-8").replace(
            "**Source IDs**: NEXP-1", "**Source IDs**: PREFIX_NEXP-1"
        ),
        encoding="utf-8",
    )
    receipt_path = scratch / "enumgap_exploration_promotion_receipt.json"
    forged = json.loads(receipt_path.read_text(encoding="utf-8"))
    blocks = EG._inventory_finding_blocks(inventory.read_text(encoding="utf-8"))
    forged["deliveries"][0]["inventory_block_sha256"] = blocks["INV-002"][
        "block_sha256"
    ]
    forged["receipt_sha256"] = EG._promotion_receipt_digest(forged)
    receipt_path.write_text(json.dumps(forged), encoding="utf-8")

    _assert_delivery_debt(scratch, obligation_id)


def test_parser_excludes_coverage_sibling_and_fenced_finding_lookalikes() -> None:
    text = (
        _finding_block()
        + "## Coverage Record\n\n"
        "```markdown\n"
        + _finding_block("NEXP-9", title="fenced lookalike")
        + "```\n"
    )
    parsed = EG.parse_enumgap_exploration_findings(text)
    assert [row["id"] for row in parsed] == ["NEXP-1"]
    assert "Coverage Record" not in parsed[0]["block"]
    assert "NEXP-9" not in parsed[0]["block"]


def test_parser_excludes_finding_lookalikes_in_nonoperational_html() -> None:
    containers = (
        ("<!--\n", "-->\n"),
        ("<pre>\n", "</pre>\n"),
        ("<script>\n", "</script>\n"),
        ("<style>\n", "</style>\n"),
    )
    for opening, closing in containers:
        text = (
            _finding_block()
            + "## Coverage Record\n\n"
            + opening
            + _finding_block("NEXP-9", title="hidden HTML lookalike")
            + closing
        )
        parsed = EG.parse_enumgap_exploration_findings(text)
        assert [row["id"] for row in parsed] == ["NEXP-1"], opening.strip()


def test_operational_view_preserves_offsets_for_closed_and_unclosed_containers() -> None:
    cases = (
        "α\r\n<!-- ## Hidden -->\r\n## Live\r\n",
        "α\n<!--\n## Hidden\n-->\n## Live\n",
        "## Live\n<!--\n## Hidden\n",
        "α\n<pre>## Hidden</pre>\n## Live\n",
        "α\n<script>\n## Hidden\n</script>\n## Live\n",
        "α\n<style data-x='1'>\n## Hidden\n</STYLE>\n## Live\n",
        "## Live\n<pre>\n## Hidden\n",
    )
    for source in cases:
        view = operational_markdown_view(source)
        assert len(view) == len(source)
        assert [index for index, char in enumerate(view) if char in "\r\n"] == [
            index for index, char in enumerate(source) if char in "\r\n"
        ]
        assert view.index("## Live") == source.index("## Live")
        assert "## Hidden" not in view


def test_inline_code_markers_do_not_mask_later_live_coverage() -> None:
    for literal in ("`<!--`", "`<pre>`"):
        source = (
            _finding_block(
                description=f"The literal marker {literal} is code, not a container."
            )
            + "## Coverage Record\n\n"
            "| Obligation | Relationship | Disposition | Evidence |\n"
        )
        view = operational_markdown_view(source)
        assert view.index("## Coverage Record") == source.index(
            "## Coverage Record"
        ), literal
        assert [row["id"] for row in EG.parse_enumgap_exploration_findings(source)] == [
            "NEXP-1"
        ]


def test_standalone_backticks_cannot_hide_intervening_commonmark_blocks() -> None:
    # Reviewed CommonMark token evidence: each lone backtick is a text child in
    # its own paragraph; the intervening heading/paragraphs are separate block
    # tokens, so no code_inline child spans (or hides) NEXP-9.
    source = (
        _finding_block()
        + "`\n"
        + _finding_block("NEXP-9", title="inline-code lookalike")
        + "`\n"
    )
    view = operational_markdown_view(source)
    assert len(view) == len(source)
    assert "NEXP-9" in view
    assert [row["id"] for row in EG.parse_enumgap_exploration_findings(source)] == [
        "NEXP-1",
        "NEXP-9",
    ]
    assert enumgap_reference_heading_ids(source) == frozenset(
        {"NEXP-1", "NEXP-9"}
    )


def test_escaped_backtick_and_comment_text_cannot_hide_commonmark_blocks() -> None:
    # Reviewed CommonMark token evidence: ``\`<!--`` is a text child (the
    # backtick is escaped and the opener is not an html_block); the following
    # finding is therefore ordinary operational heading/paragraph content.
    source = (
        _finding_block()
        + "\\`<!--\n"
        + _finding_block("NEXP-9", title="comment lookalike")
        + "-->`\n"
    )
    view = operational_markdown_view(source)
    assert len(view) == len(source)
    assert "NEXP-9" in view
    assert [row["id"] for row in EG.parse_enumgap_exploration_findings(source)] == [
        "NEXP-1",
        "NEXP-9",
    ]
    assert enumgap_reference_heading_ids(source) == frozenset(
        {"NEXP-1", "NEXP-9"}
    )


def test_level_four_emitted_heading_has_reconcile_and_promotion_parity(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_emitted_action(
        project,
        finding_text=_finding_block(
            heading="####", title="level-four traced candidate"
        ),
    )
    assert EG.promote_enumgap_exploration_to_inventory(scratch) == {
        "parsed": 1,
        "emitted": 1,
    }
    row, _ = _delivery(scratch, obligation_id)
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_DISPOSED"
    assert row["resolution_kind"] == "EMITTED_ACTION"


def test_markdown_projection_disagreement_cannot_override_valid_json(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_emitted_action(project)
    assert EG.promote_enumgap_exploration_to_inventory(scratch)["emitted"] == 1
    markdown = scratch / "enumgap_exploration_promotion_receipt.md"
    markdown.write_text(
        "# Enumeration-Obligation Exploration Promotion Receipt\n\n"
        "NEXP-1 -> INV-999\n",
        encoding="utf-8",
    )

    assert "NEXP-1" in EG.validated_enumgap_promotion_deliveries(scratch)
    row, _ = _delivery(scratch, obligation_id)
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_DISPOSED"
    assert EG.promote_enumgap_exploration_to_inventory(scratch) == {
        "parsed": 1,
        "emitted": 0,
    }
    assert "NEXP-1 -> INV-002" in markdown.read_text(encoding="utf-8")


def test_successful_resume_is_byte_idempotent(tmp_path: Path) -> None:
    project = tmp_path / "project"
    scratch, _ = _seed_emitted_action(project)
    assert EG.promote_enumgap_exploration_to_inventory(scratch)["emitted"] == 1
    paths = (
        scratch / "findings_inventory.md",
        scratch / "enumgap_exploration_promotion_receipt.md",
        scratch / "enumgap_exploration_promotion_receipt.json",
    )
    before = {path.name: path.read_bytes() for path in paths}

    assert EG.promote_enumgap_exploration_to_inventory(scratch) == {
        "parsed": 1,
        "emitted": 0,
    }
    assert {path.name: path.read_bytes() for path in paths} == before


def _canonical_record() -> dict[str, object]:
    immutable = {
        "artifact": "depth_findings.md",
        "local_id": "h-1",
        "title": "bound prior",
        "location": "src/unit.sol:l1",
        "root_cause": "",
        "source_ids": "",
    }
    digest = hashlib.sha256(
        json.dumps(immutable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "canonical_id": "CID-" + digest[:16].upper(),
        "fingerprint": "sha256:" + digest,
        "artifact": "depth_findings.md",
        "offset": 0,
        "local_id": "H-1",
        "local_id_raw": "H-1",
        "title": "Bound prior",
        "severity": "Low",
        "location": "src/Unit.sol:L1",
        "root_cause": "",
        "source_ids_text": "",
        "referenced_ids": [],
        "raw_block_len": 100,
    }


def test_bad_emitted_delivery_does_not_revoke_unrelated_clear_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    (project / "src").mkdir()
    (project / "src" / "Unit.sol").write_text("one\ntwo\n", encoding="utf-8")
    source = scratch / "exploration_skeptic_findings.md"
    source.write_text(
        "# Exploration\n\n## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| BASE-1 | sibling | inverse | NO-GAP | vague wording |\n"
        "| BASE-2 | boundary | zero | NO-GAP | vague wording |\n"
        "| BASE-3 | direction | reverse | NO-GAP | vague wording |\n",
        encoding="utf-8",
    )
    initial = compile_initial_receipt(
        source, production_root=project, canonical_prior_ids={}
    )
    write_lifecycle_artifacts(scratch, initial)
    by_source = {item.source_finding: item.obligation_id for item in initial.obligations}
    (scratch / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Seed\n"
        "**Source IDs**: BASE-0\n"
        "**Severity**: Low\n"
        "**Location**: src/Unit.sol:L1\n"
        "**Description**: retained seed.\n",
        encoding="utf-8",
    )
    record = _canonical_record()
    (scratch / "_canonical_finding_ids.json").write_text(
        json.dumps(
            {
                "schema_version": "plamen.canonical_finding_ids.v1",
                "generated_at": "2026-07-18T00:00:00+00:00",
                "last_phase": "depth",
                "pipeline": "sc",
                "mode": "thorough",
                "record_count": 1,
                "records": [record],
            }
        ),
        encoding="utf-8",
    )
    (scratch / "exploration_clear_prior_aliases.json").write_text(
        json.dumps(D._exploration_clear_prior_alias_payload(scratch)), encoding="utf-8"
    )
    worklist, issues = D._prepare_enumgap_disposition_worklist(
        _phase(), _config(project), scratch
    )
    assert issues == [] and worklist["count"] == 3
    assert D._bind_typed_model_phase_inputs(
        _phase(), scratch, _config(project)
    ) == []
    (scratch / "enumgap_exploration_findings.md").write_text(
        "# Enumgap\n\n"
        + _finding_block()
        + "## Coverage Record\n\n"
        "| Obligation | Relationship | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        f"| {by_source['BASE-1']} | sibling | FINDING | NEXP-1 |\n"
        f"| {by_source['BASE-2']} | boundary | CLEAR | src/Unit.sol:L2 |\n"
        f"| {by_source['BASE-3']} | direction | CLEAR | H-1 |\n",
        encoding="utf-8",
    )
    assert D._record_typed_model_phase_artifacts(
        _phase(), scratch, _config(project)
    ) == []
    receipt, reconcile_issues = D._reconcile_enumgap_dispositions(
        _phase(), _config(project), scratch
    )
    assert reconcile_issues == [] and receipt["status"] == "CLEAN"
    assert EG.promote_enumgap_exploration_to_inventory(scratch)["emitted"] == 1
    promotion_receipt = scratch / "enumgap_exploration_promotion_receipt.json"
    corrupted = json.loads(promotion_receipt.read_text(encoding="utf-8"))
    corrupted["receipt_sha256"] = "0" * 64
    promotion_receipt.write_text(json.dumps(corrupted), encoding="utf-8")

    resolved = validated_enumgap_obligation_dispositions(
        scratch, production_root=project
    )
    assert by_source["BASE-1"] not in resolved
    assert resolved[by_source["BASE-2"]]["resolution_kind"] == "PRODUCTION_LOCUS"
    assert resolved[by_source["BASE-3"]]["resolution_kind"] == "CANONICAL_PRIOR"
