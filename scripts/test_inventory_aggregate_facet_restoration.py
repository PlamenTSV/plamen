"""Python transcribes source facets; the shard is not a data bus.

An `inventory_chunk_*` shard is asked to copy upstream facet text byte-for-byte
into its own detail blocks. That is transcription, not judgment, and a model
does not do it reliably -- DODO run35's attempt 2 received 11 exact source
facets in its prompt and reworded them anyway. What goes missing is the
structured evidence: a 28-row privilege inventory, a boundary-substitution fee
table. Those are exactly the bytes depth, chain, and verify need.

So the driver transcribes. It happens at the AGGREGATE because that is where
the authority lives: `findings_inventory.md` is what downstream phases read,
and `inventory/canonical_aggregate` is an already-registered projection
handoff. Repairing the chunk file in place is refused by construction -- no
`_REGISTERED_PROJECTION_HANDOFFS` entry exists for
`findings_inventory_chunk_*.md`, and `inventory_reemit_authority._build_intent`
rejects one-to-one chunk repair with "repair the canonical projection instead".

The bound that keeps this honest: restoration is additive and applies ONLY to
unambiguous one-to-one retention. A many-to-one collapse, an authorized merge,
or a refutation must never have source bytes spliced into its survivor --
that would manufacture exactly the equivalence those dispositions exist to
withhold.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import inventory_aggregate_authority as A  # noqa: E402


_TABLE_FACET = (
    "Step 1 privilege inventory: | # | Function | Category | | 1 | "
    "`_authorizeUpgrade` | UPGRADE_CONTROL | | 2 | `setGateway` | FUND |"
)


def _row(**over):
    row = {
        "disposition": "HUMAN_REVIEW_DEBT",
        "reason_code": "CHUNK_SEMANTIC_PRESERVATION_DEBT",
        "proposed_relation_kind": "ONE_TO_ONE_RETENTION_PROPOSAL",
        "proposed_target_finding_id": "CC-10",
        "required_preservation_axes": ["ROOT_CAUSE"],
        "source_root_cause": _TABLE_FACET,
        "source_impact": "",
        "source_preconditions": "",
        "source_artifact": "analysis_centralization_risk.md",
        "source_finding_id": "B6-10",
        "repair_action_id": "INVR-DEADBEEF",
    }
    row.update(over)
    return row


def _patch(monkeypatch, rows):
    monkeypatch.setattr(
        A, "reconcile_inventory",
        lambda root, phase_name, persist: {"candidates": rows},
    )


def _entry(**over):
    entry = {"local_id": "CC-10", "root_cause": "a shortened paraphrase"}
    entry.update(over)
    return entry


def test_missing_table_facet_is_restored(monkeypatch, tmp_path) -> None:
    _patch(monkeypatch, [_row()])
    entries = [_entry()]
    restored = A._restore_unpreserved_source_facets(
        tmp_path, "findings_inventory_chunk_a.md", entries,
    )
    assert len(restored) == 1
    assert restored[0]["axis"] == "ROOT_CAUSE"
    text = entries[0]["root_cause"]
    assert _TABLE_FACET in text, "the source table did not reach the aggregate"
    assert "a shortened paraphrase" in text, "model text was replaced, not kept"
    assert "analysis_centralization_risk.md:B6-10" in text, "no provenance"


def test_restoration_satisfies_the_preservation_test(monkeypatch, tmp_path):
    """The point of restoring bytes is that containment then holds."""
    import inventory_reconciliation as IR

    _patch(monkeypatch, [_row()])
    entries = [_entry()]
    A._restore_unpreserved_source_facets(
        tmp_path, "findings_inventory_chunk_a.md", entries,
    )
    assert IR._semantic_preservation_deltas(
        {"source_root_cause": _TABLE_FACET, "source_impact": "x",
         "source_preconditions": "x"},
        {"root_cause": entries[0]["root_cause"], "description": "",
         "impact": "x", "preconditions": "x"},
    ) == []


def test_restoration_is_idempotent(monkeypatch, tmp_path) -> None:
    _patch(monkeypatch, [_row()])
    entries = [_entry()]
    first = A._restore_unpreserved_source_facets(
        tmp_path, "findings_inventory_chunk_a.md", entries,
    )
    after_first = entries[0]["root_cause"]
    second = A._restore_unpreserved_source_facets(
        tmp_path, "findings_inventory_chunk_a.md", entries,
    )
    assert first and second == []
    assert entries[0]["root_cause"] == after_first


@pytest.mark.parametrize("axis,field", [
    ("IMPACT", "impact"), ("PRECONDITIONS", "preconditions"),
])
def test_every_restorable_axis(monkeypatch, tmp_path, axis, field) -> None:
    source_field = f"source_{field}"
    _patch(monkeypatch, [_row(
        required_preservation_axes=[axis],
        source_root_cause="",
        **{source_field: _TABLE_FACET},
    )])
    entries = [_entry(**{field: "short"})]
    assert A._restore_unpreserved_source_facets(
        tmp_path, "findings_inventory_chunk_a.md", entries,
    )
    assert _TABLE_FACET in entries[0][field]


# --------------------------------------------------------------------------
# Bounds. Each of these would manufacture authority that was withheld.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("over", [
    {"proposed_relation_kind": "AMBIGUOUS_MANY_TO_ONE"},
    {"disposition": "AUTHORIZED_MERGE"},
    {"disposition": "RETAINED"},
    {"reason_code": "MULTI_SOURCE_COLLAPSE_REQUIRES_EQUIVALENCE"},
    {"reason_code": "REEMIT_UNPARSEABLE_SOURCE_DEBT"},
    {"proposed_target_finding_id": ""},
])
def test_non_one_to_one_rows_are_never_restored(
    monkeypatch, tmp_path, over,
) -> None:
    _patch(monkeypatch, [_row(**over)])
    entries = [_entry()]
    assert A._restore_unpreserved_source_facets(
        tmp_path, "findings_inventory_chunk_a.md", entries,
    ) == []
    assert entries[0]["root_cause"] == "a shortened paraphrase"


def test_two_sources_claiming_one_target_are_not_restored(
    monkeypatch, tmp_path,
) -> None:
    """If the relation is not one-to-one, no source owns the block's facets."""
    _patch(monkeypatch, [_row(), _row(source_finding_id="B6-11")])
    entries = [_entry()]
    assert A._restore_unpreserved_source_facets(
        tmp_path, "findings_inventory_chunk_a.md", entries,
    ) == []
    assert entries[0]["root_cause"] == "a shortened paraphrase"


def test_unparseable_axis_has_no_bytes_to_restore(monkeypatch, tmp_path):
    """The SOURCE never rendered the facet; it must stay debt, not be invented."""
    _patch(monkeypatch, [_row(
        required_preservation_axes=["UNPARSEABLE_ROOT_CAUSE"],
        source_root_cause="",
    )])
    entries = [_entry()]
    assert A._restore_unpreserved_source_facets(
        tmp_path, "findings_inventory_chunk_a.md", entries,
    ) == []


def test_reconciliation_failure_never_fails_the_aggregate(
    monkeypatch, tmp_path,
) -> None:
    def _boom(root, phase_name, persist):
        raise RuntimeError("reconciliation unavailable")

    monkeypatch.setattr(A, "reconcile_inventory", _boom)
    entries = [_entry()]
    assert A._restore_unpreserved_source_facets(
        tmp_path, "findings_inventory_chunk_a.md", entries,
    ) == []
    assert entries[0]["root_cause"] == "a shortened paraphrase"


def test_restored_table_never_becomes_a_parseable_row(monkeypatch, tmp_path):
    """The reason the shard summarized tables in the first place.

    DODO run35 attempt 1 DID copy source tables verbatim as multi-line
    Markdown, and the legacy chunk parser then read 94 rows out of 49 findings
    -- 45 phantom entries harvested from table rows inside detail blocks. The
    aggregate rejects that outright ("accepted chunk material denominator
    differs from parsed rows"). Attempt 2 dropped the tables and parsed 49/49.

    Driver restoration sidesteps the whole dilemma: the facet is whitespace-
    collapsed onto the existing field's line, so its pipes can never begin a
    table row. If this ever emits a newline, restoring a table would resurrect
    the phantom-row failure it exists to avoid.
    """
    _patch(monkeypatch, [_row()])
    entries = [_entry()]
    A._restore_unpreserved_source_facets(
        tmp_path, "findings_inventory_chunk_a.md", entries,
    )
    value = str(entries[0]["root_cause"])
    assert "|" in value, "fixture no longer carries table syntax"
    assert "\n" not in value and "\r" not in value, (
        "restoration emitted a line break; a following `|` line would be "
        "harvested as a phantom finding row"
    )
    assert not value.lstrip().startswith("|")


def test_restoration_is_wired_into_the_derivation(monkeypatch) -> None:
    """A helper nothing calls repairs nothing."""
    source = (_SCRIPTS / "inventory_aggregate_authority.py").read_text("utf-8")
    body = source.split("def _derivation_entries", 1)[1]
    assert "_restore_unpreserved_source_facets(" in body.split("def ", 1)[0], (
        "the aggregate derivation does not invoke facet restoration"
    )

# --------------------------------------------------------------------------
# "Masking AND recovery": a silent repair is the failure mode, not the fix.
# --------------------------------------------------------------------------

def test_restoration_is_reported_not_silent() -> None:
    """Avizienis et al. (IEEE TDSC 1(1), 2004) on fault masking: it
    "will conceal a possibly progressive and eventually fatal loss of
    protective redundancy", so compensation must be paired with detection that
    reports what it masked.

    A repair that succeeds quietly also trains the pipeline to accept a
    widening deviation, and -- per Kali (Qi et al., ISSTA 2015) -- a count that
    keeps climbing is indistinguishable from correct behaviour at any single
    point. Only the reported TREND separates them.
    """
    source = (_SCRIPTS / "inventory_aggregate_authority.py").read_text("utf-8")
    # Carried out of the pure derivation...
    assert "restored_source_facet_count" in source, (
        "the splice count is not emitted as run telemetry"
    )
    assert "restored_source_facets" in source
    # ...and rendered into the committed human-readable receipt.
    assert "Driver-Restored Source Facets" in source, (
        "the receipt does not name which facets were repaired"
    )
    assert "Driver-restored source facets:" in source


def test_receipt_rows_carry_full_provenance(monkeypatch, tmp_path) -> None:
    """Each reported row must identify chunk, finding, axis and source."""
    _patch(monkeypatch, [_row()])
    entries = [_entry()]
    restored = A._restore_unpreserved_source_facets(
        tmp_path, "findings_inventory_chunk_a.md", entries,
    )
    assert restored and set(restored[0]) >= {
        "chunk", "finding_id", "axis", "source", "repair_action_id",
    }
    assert restored[0]["source"] == "analysis_centralization_risk.md:B6-10"


# --------------------------------------------------------------------------
# The safety property: the gate must exempt EXACTLY what the splice repairs.
# --------------------------------------------------------------------------

def test_gate_exemption_and_splice_share_one_predicate() -> None:
    """If these two sets ever diverge, the divergence IS silent content loss.

    The gate stops blocking on rows the aggregate will restore verbatim. An
    exemption the splice then declines would drop upstream content with no
    debt recorded anywhere -- strictly worse than the gate failure it replaced.
    Sharing `driver_restorable_preservation_row` makes them the same set by
    construction; these assertions stop a future edit from forking them.
    """
    import inventory_reconciliation as IR

    validators = (_SCRIPTS / "plamen_validators.py").read_text("utf-8")
    assert "driver_restorable" in validators, (
        "the chunk gate no longer consults the driver-restorable flag"
    )
    aggregate = (_SCRIPTS / "inventory_aggregate_authority.py").read_text("utf-8")
    assert "driver_restorable_preservation_row(row)" in aggregate, (
        "the splice no longer uses the shared predicate; it can now diverge "
        "from what the gate exempted"
    )
    assert hasattr(IR, "driver_restorable_preservation_row")


@pytest.mark.parametrize("over,why", [
    ({"proposed_relation_kind": "AMBIGUOUS_MANY_TO_ONE"},
     "many-to-one: no single source owns the block"),
    ({"disposition": "AUTHORIZED_MERGE"}, "merge authority is not preservation"),
    ({"reason_code": "REEMIT_UNPARSEABLE_SOURCE_DEBT"}, "wrong debt class"),
    ({"proposed_target_finding_id": ""}, "no target to splice into"),
    ({"required_preservation_axes": []}, "nothing named to restore"),
    ({"required_preservation_axes": ["UNPARSEABLE_ROOT_CAUSE"],
      "source_root_cause": ""}, "source never rendered the facet"),
    ({"source_root_cause": ""}, "no bytes to copy"),
])
def test_unrestorable_rows_keep_their_gate(over, why) -> None:
    """Exempting any of these would wave through content nothing repairs."""
    import inventory_reconciliation as IR

    assert not IR.driver_restorable_preservation_row(_row(**over)), why


def test_a_plain_restorable_row_is_exempt() -> None:
    import inventory_reconciliation as IR

    assert IR.driver_restorable_preservation_row(_row())

def test_mixed_axis_row_is_restorable_for_the_half_that_exists() -> None:
    """run37 chunk_c's residual 3 rows, and why they must not gate.

    `['ROOT_CAUSE', 'UNPARSEABLE_IMPACT']` means the source HAS a root cause and
    never rendered an impact. The splice repairs the root cause; nothing can
    repair the impact, because those bytes do not exist upstream -- not a
    retry, not a rewrite, not a better prompt. Gating the row on its unwinnable
    half forces a whole-artifact rewrite to fix a gap the rewrite cannot touch,
    which is exactly the churn this work exists to stop.
    """
    import inventory_reconciliation as IR

    row = _row(required_preservation_axes=["ROOT_CAUSE", "UNPARSEABLE_IMPACT"])
    assert IR.driver_restorable_preservation_row(row)


def test_mixed_axis_row_restores_only_the_real_axis(monkeypatch, tmp_path):
    """The UNPARSEABLE half must not be invented, only skipped."""
    _patch(monkeypatch, [_row(
        required_preservation_axes=["ROOT_CAUSE", "UNPARSEABLE_IMPACT"],
        source_impact="",
    )])
    entries = [_entry(impact="untouched")]
    restored = A._restore_unpreserved_source_facets(
        tmp_path, "findings_inventory_chunk_a.md", entries,
    )
    assert [r["axis"] for r in restored] == ["ROOT_CAUSE"]
    assert entries[0]["impact"] == "untouched", "an absent facet was fabricated"


def test_all_unparseable_row_is_not_restorable() -> None:
    """Nothing to splice means nothing to exempt."""
    import inventory_reconciliation as IR

    assert not IR.driver_restorable_preservation_row(_row(
        required_preservation_axes=["UNPARSEABLE_ROOT_CAUSE"],
        source_root_cause="",
    ))


def test_partial_restoration_is_reported_separately() -> None:
    """Upstream debt must not hide inside a healthy restoration count."""
    validators = (_SCRIPTS / "plamen_validators.py").read_text("utf-8")
    assert "upstream artifact debt" in validators, (
        "partially-restored rows are not distinguished from cleanly-restored "
        "ones; a growing upstream gap would be invisible"
    )
