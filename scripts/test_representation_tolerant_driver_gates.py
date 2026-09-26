"""Metamorphic + adversarial contract for the representation-bound gates in
``plamen_driver``.

Principle 4 (metamorphic / property-based testing): semantically equivalent
inputs MUST produce equivalent verdicts.  Every mutation exercised here was
MEASURED to flip its gate from PASS to a run-destroying rejection on real
DODO run46/run47/run48 worker bytes; each now asserts the verdict is
UNCHANGED.

Every relaxation is paired with an ADVERSARIAL control proving a mutation
that really does change MEANING is still rejected.  A fix that accepts
everything would be a worse bug than the one being fixed.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import artifact_surface as A  # noqa: E402
import plamen_driver as D  # noqa: E402


# ==========================================================================
# Fixtures: real run48 worker bytes, pasted (never read at runtime).
# ==========================================================================

# Verbatim from run48
# .worker_transactions/depth/worker.depth-token-flow/attempts/
# attempt-e143ed776b2b4bca9edcd274/output/depth_token_flow_findings.md
# (lines 55-68).  Note the BACKTICKS: that is how the real worker wrote them.
RUN48_TOKEN_FLOW_GRAPH_BLOCK = """\
## Exact Graph Artifact Consumption

`[GRAPH-ARTIFACT: CONSUMED:caller_map.md]`

`[GRAPH-ARTIFACT: CONSUMED:callee_map.md]`

`[GRAPH-ARTIFACT: CONSUMED:state_write_map.md]`

`[GRAPH-ARTIFACT: CONSUMED:function_summary.md]`
"""


def _write_graph_inputs(root: Path) -> None:
    for name in D._DEPTH_GRAPH_CONSUMPTION_INPUTS:
        (root / name).write_text(
            f"# {name}\n\n| Symbol | Evidence |\n|---|---|\n"
            f"| fixture | src/Vault.sol:L10 |\n",
            encoding="utf-8",
        )


def _graph_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    _write_graph_inputs(tmp_path)
    monkeypatch.setattr(
        D, "_depth_candidate_negative_gate_required", lambda _job: False
    )
    context, _ = D._compile_depth_worker_staged_gate_context(
        job={
            "output": "depth_token_flow_findings.md",
            "agent_id": "depth-token-flow",
            "role": "token-flow",
            "category": "standard",
        },
        scratchpad=tmp_path,
        config={"pipeline": "sc", "mode": "thorough", "_run_id": "metamorphic"},
        registered_inputs=D._DEPTH_GRAPH_CONSUMPTION_INPUTS,
        attempt=1,
    )
    return context


IDENTITY = "scratchpad:depth_token_flow_findings.md"


def _verdict(body: str, context: dict) -> D._SurfaceCheckResult:
    return D._staged_depth_composite_receipt_result(
        {IDENTITY: body.encode("utf-8")}, context
    )


def _graph_defects(result) -> tuple[str, ...]:
    return tuple(
        d.property_violated for d in result.defects
        if d.property_violated.startswith("graph.")
    )


# ==========================================================================
# GATE: graph-consumption acknowledgement
# property: graph.consumption_acknowledgement -> DEBT (never discards)
# ==========================================================================


def test_run48_backticked_markers_are_accepted(tmp_path, monkeypatch):
    """The real run48 bytes.  Baseline for every mutation below."""
    context = _graph_context(tmp_path, monkeypatch)
    result = _verdict(RUN48_TOKEN_FLOW_GRAPH_BLOCK, context)
    assert _graph_defects(result) == ()
    assert result.should_discard is False


@pytest.mark.parametrize(
    "name,mutate",
    [
        # (a) ONE added space after CONSUMED: -- measured FAIL
        ("added_space", lambda t: t.replace("CONSUMED:", "CONSUMED: ")),
        # (d) space removed after GRAPH-ARTIFACT: -- measured FAIL
        ("removed_space", lambda t: t.replace("GRAPH-ARTIFACT: ", "GRAPH-ARTIFACT:")),
        # (c) lowercase -- measured FAIL
        ("lowercased", lambda t: t.replace("CONSUMED:", "consumed:")),
        # (e) path-qualified name -- measured FAIL
        ("path_qualified", lambda t: t.replace("CONSUMED:", "CONSUMED:scratchpad:")),
        # decoration variants that already passed, asserted so they stay passing
        ("bolded", lambda t: t.replace("`[GRAPH", "**[GRAPH").replace("]`", "]**")),
        ("list_items", lambda t: t.replace("`[GRAPH", "- `[GRAPH")),
        ("crlf", lambda t: t.replace("\n", "\r\n")),
        ("restated", lambda t: t + t),
        # EN-dash / punctuation churn elsewhere in the document
        ("endash_noise", lambda t: t + "\nNote -- projections reviewed – done.\n"),
    ],
)
def test_graph_marker_presentation_mutations_do_not_change_the_verdict(
    tmp_path, monkeypatch, name, mutate
):
    context = _graph_context(tmp_path, monkeypatch)
    baseline = _verdict(RUN48_TOKEN_FLOW_GRAPH_BLOCK, context)
    mutated = _verdict(mutate(RUN48_TOKEN_FLOW_GRAPH_BLOCK), context)
    assert _graph_defects(mutated) == _graph_defects(baseline), name
    assert mutated.should_discard is False


def test_graph_marker_soft_wrapped_across_two_physical_lines_is_one_marker(
    tmp_path, monkeypatch
):
    """(b) soft wrap -- measured FAIL."""
    context = _graph_context(tmp_path, monkeypatch)
    wrapped = RUN48_TOKEN_FLOW_GRAPH_BLOCK.replace(
        "CONSUMED:caller_map.md", "CONSUMED:\ncaller_map.md"
    )
    result = _verdict(wrapped, context)
    assert _graph_defects(result) == ()


def test_graph_acknowledgement_in_plain_prose_is_an_acknowledgement(
    tmp_path, monkeypatch
):
    """(f) semantically identical prose -- measured FAIL."""
    context = _graph_context(tmp_path, monkeypatch)
    prose = "\n".join(
        f"I read and consumed the bound graph projection {name} in full."
        for name in D._DEPTH_GRAPH_CONSUMPTION_INPUTS
    ) + "\n"
    result = _verdict(prose, context)
    assert _graph_defects(result) == ()


def test_one_stray_fence_no_longer_blinds_the_gate(tmp_path, monkeypatch):
    """THE measured run48 discard: three characters destroyed a 25-minute,
    $6-9 completed analysis by deleting every acknowledgement below it."""
    context = _graph_context(tmp_path, monkeypatch)
    for stray in ("```", "    ```", "~~~"):
        mutated = (
            "# DEPTH ANALYSIS\n\n" + stray + "\n\n"
            + RUN48_TOKEN_FLOW_GRAPH_BLOCK
        )
        result = _verdict(mutated, context)
        assert _graph_defects(result) == (), stray
        assert result.should_discard is False


# -------------------------- adversarial controls --------------------------


def test_adversarial_missing_acknowledgement_is_still_reported(
    tmp_path, monkeypatch
):
    context = _graph_context(tmp_path, monkeypatch)
    body = RUN48_TOKEN_FLOW_GRAPH_BLOCK.replace(
        "`[GRAPH-ARTIFACT: CONSUMED:callee_map.md]`\n", ""
    )
    result = _verdict(body, context)
    assert "graph.consumption_acknowledgement" in _graph_defects(result)
    assert "callee_map.md" in result.defects[0].repair_hint
    # ... but it is DEBT: a completed analysis is never discarded for it.
    assert result.should_discard is False


def test_adversarial_false_unavailable_claim_is_still_reported(
    tmp_path, monkeypatch
):
    context = _graph_context(tmp_path, monkeypatch)
    body = RUN48_TOKEN_FLOW_GRAPH_BLOCK.replace(
        "CONSUMED:callee_map.md", "UNAVAILABLE:callee_map.md"
    )
    result = _verdict(body, context)
    assert "graph.consumption_honesty" in _graph_defects(result)


def test_adversarial_negated_claim_is_not_an_acknowledgement(
    tmp_path, monkeypatch
):
    context = _graph_context(tmp_path, monkeypatch)
    body = (
        "I did not read caller_map.md.\n"
        "callee_map.md was never opened.\n"
        "state_write_map.md, function_summary.md\n"
    )
    result = _verdict(body, context)
    hint = " ".join(d.repair_hint for d in result.defects)
    for name in D._DEPTH_GRAPH_CONSUMPTION_INPUTS:
        assert name in hint, name


def test_adversarial_bare_filename_mention_is_not_an_acknowledgement(
    tmp_path, monkeypatch
):
    context = _graph_context(tmp_path, monkeypatch)
    body = "Bound inputs: " + ", ".join(D._DEPTH_GRAPH_CONSUMPTION_INPUTS) + "\n"
    result = _verdict(body, context)
    assert "graph.consumption_acknowledgement" in _graph_defects(result)


def test_adversarial_fenced_or_commented_marker_still_proves_nothing(
    tmp_path, monkeypatch
):
    context = _graph_context(tmp_path, monkeypatch)
    body = "```\n" + RUN48_TOKEN_FLOW_GRAPH_BLOCK + "```\n"
    assert "graph.consumption_acknowledgement" in _graph_defects(
        _verdict(body, context)
    )
    commented = "\n".join(
        f"<!-- [GRAPH-ARTIFACT: CONSUMED:{name}] -->"
        for name in D._DEPTH_GRAPH_CONSUMPTION_INPUTS
    )
    assert "graph.consumption_acknowledgement" in _graph_defects(
        _verdict(commented, context)
    )


# ==========================================================================
# GATE: bound-input consumption receipts
# property: receipt.bound_input_consumption* -> DEBT
# ==========================================================================


def _consumption_context(profiles: list[dict]) -> dict:
    gate = {
        "schema_version": D._DEPTH_BOUND_INPUT_CONSUMPTION_SCHEMA,
        "profiles": profiles,
    }
    gate["context_digest"] = D._depth_gate_canonical_digest(gate)
    context = {
        "schema_version": D._DEPTH_STAGED_GATE_CONTEXT_SCHEMA,
        "output_identity": IDENTITY,
        "exact_gate": None,
        "security_obligation_gate": None,
        "candidate_negative_gate": None,
        "bound_input_consumption_gate": gate,
    }
    context["context_digest"] = D._depth_gate_canonical_digest(
        {k: v for k, v in context.items()}
    )
    return context


def _profiles() -> list[dict]:
    return [
        {
            "schema_version": D._DEPTH_BOUND_INPUT_CONSUMPTION_SCHEMA,
            "identity": f"scratchpad:{name}",
            "sha256": hashlib.sha256(name.encode()).hexdigest(),
            "table_row_count": index + 1,
            "table_rows_sha256": hashlib.sha256(
                f"rows-{name}".encode()
            ).hexdigest(),
            # A realistic driver-derived status_profile: long, free-text-derived.
            "status_profile": "ROW_STATUS:" + ",".join(
                f"ENFORCED_BY_REQUIRE_AT_L{n}" for n in range(index, index + 40)
            ),
        }
        for index, name in enumerate(D._STATE_TRACE_REQUIRED_BOUND_INPUTS)
    ]


def _receipts(profiles: list[dict]) -> str:
    return "\n".join(
        D._render_depth_bound_input_consumption_receipt(p) for p in profiles
    ) + "\n"


def _consumption_defects(result) -> tuple[str, ...]:
    return tuple(
        d.property_violated for d in result.defects
        if d.property_violated.startswith("receipt.bound_input")
    )


def test_bound_input_receipts_baseline_accepted():
    profiles = _profiles()
    result = _verdict(_receipts(profiles), _consumption_context(profiles))
    assert _consumption_defects(result) == ()
    assert result.should_discard is False


def test_bound_input_receipt_order_and_restatement_are_irrelevant():
    """(b) swap, (c) duplicate -- both measured FAIL, both meaning-preserving."""
    profiles = _profiles()
    context = _consumption_context(profiles)
    swapped = _receipts(list(reversed(profiles)))
    assert _consumption_defects(_verdict(swapped, context)) == ()
    duplicated = _receipts(profiles) + _receipts(profiles[:1])
    assert _consumption_defects(_verdict(duplicated, context)) == ()


def test_bound_input_receipt_unknown_field_is_ignored_not_fatal():
    """(d) an extra field -- measured FAIL.  A field the gate does not
    consume can never make an artifact invalid (Principle 1)."""
    profiles = _profiles()
    context = _consumption_context(profiles)
    enriched = [{**p, "note": "read in full"} for p in profiles]
    assert _consumption_defects(_verdict(_receipts(enriched), context)) == ()


def test_bound_input_receipt_may_be_backticked_or_quoted():
    profiles = _profiles()
    context = _consumption_context(profiles)
    decorated = "\n".join(
        "`" + D._render_depth_bound_input_consumption_receipt(p) + "`"
        for p in profiles
    ) + "\n"
    assert _consumption_defects(_verdict(decorated, context)) == ()


def test_bound_input_prose_naming_the_marker_is_ignored_not_rejected():
    """The literal run48 'malformed structured obligation evidence ignored'
    shape: a PROSE sentence that NAMES the marker token."""
    profiles = _profiles()
    context = _consumption_context(profiles)
    body = (
        _receipts(profiles)
        + "I placed one PLAMEN_BOUND_INPUT_CONSUMPTION marker per bound input.\n"
        + "<!-- PLAMEN_BOUND_INPUT_CONSUMPTION: {not json} -->\n"
    )
    assert _consumption_defects(_verdict(body, context)) == ()


# -------------------------- adversarial controls --------------------------


def test_adversarial_one_character_of_content_drift_is_still_reported():
    """(a) ONE character removed from a 3,353-char driver-derived blob.  It
    is a real transcription defect and is still REPORTED -- but as DEBT with
    a repair hint, not by destroying a completed analysis."""
    profiles = _profiles()
    context = _consumption_context(profiles)
    drifted = [dict(p) for p in profiles]
    drifted[0]["status_profile"] = drifted[0]["status_profile"][:-1]
    result = _verdict(_receipts(drifted), context)
    assert "receipt.bound_input_consumption_content" in _consumption_defects(result)
    assert "content-inaccurate" in result.defects[0].repair_hint
    assert result.should_discard is False


def test_adversarial_missing_receipt_is_still_reported():
    profiles = _profiles()
    context = _consumption_context(profiles)
    result = _verdict(_receipts(profiles[:1]), context)
    assert "receipt.bound_input_consumption" in _consumption_defects(result)
    assert profiles[1]["identity"] in result.defects[0].repair_hint


def test_adversarial_receipt_for_a_foreign_identity_does_not_satisfy_the_gate():
    profiles = _profiles()
    context = _consumption_context(profiles)
    foreign = [dict(profiles[0]), dict(profiles[1])]
    foreign[1]["identity"] = "scratchpad:some_other_file.md"
    result = _verdict(_receipts(foreign), context)
    assert "receipt.bound_input_consumption" in _consumption_defects(result)


# ==========================================================================
# FAIL_CLOSED conjunct: identity still blocks, on the NORMALIZED value.
# ==========================================================================


def test_identity_conjunct_still_discards_on_a_foreign_output(
    tmp_path, monkeypatch
):
    """STEP 7 negative control: widening the presentational conjuncts must
    not widen the identity conjunct."""
    context = _graph_context(tmp_path, monkeypatch)
    result = D._staged_depth_composite_receipt_result(
        {"scratchpad:some_other_worker.md": b"anything"}, context
    )
    assert result.should_discard is True
    assert result.blocking_defects[0].property_violated == (
        "identity.staged_output_binding"
    )


def test_identity_conjunct_still_discards_on_a_tampered_context(
    tmp_path, monkeypatch
):
    context = dict(_graph_context(tmp_path, monkeypatch))
    context["output_identity"] = "scratchpad:depth_token_flow_findings.md "
    result = D._staged_depth_composite_receipt_result(
        {IDENTITY: RUN48_TOKEN_FLOW_GRAPH_BLOCK.encode()}, context
    )
    assert result.should_discard is True


def test_presentational_defects_are_never_blocking(tmp_path, monkeypatch):
    """The whole point: no presentational defect may discard an artifact."""
    context = _graph_context(tmp_path, monkeypatch)
    result = _verdict("no acknowledgement at all\n", context)
    assert result.defects
    assert result.blocking_defects == ()
    assert result.should_discard is False
    for defect in result.defects:
        assert defect.closure == A.DEBT
        assert defect.repair_hint


def test_closure_is_read_from_the_property_family_not_by_judgement():
    assert A.closure_for_property("identity.staged_output_binding") == A.FAIL_CLOSED
    assert A.closure_for_property("graph.consumption_acknowledgement") == A.DEBT
    assert A.closure_for_property("receipt.bound_input_consumption") == A.DEBT


# ==========================================================================
# GATE: _depth_bound_input_consumption_profile (the content witness itself)
# The witness must be stable under presentation churn in its DRIVER-authored
# input, or cosmetic churn silently changes the bytes a worker must
# transcribe and the receipt gate then rejects an honest transcription.
# ==========================================================================

_CONSTRAINT_VARIABLES = (
    "# Constraint Variables\n"
    "\n"
    "> **Status**: ENFORCED\n"
    "\n"
    "| Variable | Source Location | Bound / Enforcement | Setter | Status |\n"
    "|---|---|---|---|---|\n"
    "| feePercent | contracts/Gateway.sol:L35 | <= 1000 | setFeePercent | ENFORCED |\n"
    "| gasLimit | contracts/Gateway.sol:L41 | none | setGasLimit | UNENFORCED |\n"
)


def _profile(text: str) -> dict:
    return D._depth_bound_input_consumption_profile(
        text.encode("utf-8"), "scratchpad:constraint_variables.md"
    )


@pytest.mark.parametrize(
    "name,mutated",
    [
        (
            "trailing_space_on_a_row",
            _CONSTRAINT_VARIABLES.replace(
                "| ENFORCED |\n", "| ENFORCED |  \n"
            ),
        ),
        (
            "swapped_rows",
            _CONSTRAINT_VARIABLES.replace(
                "| feePercent | contracts/Gateway.sol:L35 | <= 1000 | setFeePercent | ENFORCED |\n"
                "| gasLimit | contracts/Gateway.sol:L41 | none | setGasLimit | UNENFORCED |\n",
                "| gasLimit | contracts/Gateway.sol:L41 | none | setGasLimit | UNENFORCED |\n"
                "| feePercent | contracts/Gateway.sol:L35 | <= 1000 | setFeePercent | ENFORCED |\n",
            ),
        ),
        ("crlf", _CONSTRAINT_VARIABLES.replace("\n", "\r\n")),
        (
            "status_plain_dash",
            _CONSTRAINT_VARIABLES.replace(
                "> **Status**: ENFORCED", "Status - ENFORCED"
            ),
        ),
        (
            "status_colon_inside_bold",
            _CONSTRAINT_VARIABLES.replace(
                "> **Status**: ENFORCED", "**Status:** ENFORCED"
            ),
        ),
        (
            "status_as_a_two_cell_row",
            _CONSTRAINT_VARIABLES.replace(
                "> **Status**: ENFORCED", "| Status | ENFORCED |"
            ),
        ),
        (
            "status_as_a_list_item",
            _CONSTRAINT_VARIABLES.replace(
                "> **Status**: ENFORCED", "- **Status**: ENFORCED"
            ),
        ),
        (
            "decorated_cells",
            _CONSTRAINT_VARIABLES.replace("| feePercent |", "| `feePercent` |"),
        ),
    ],
)
def test_content_witness_is_stable_under_presentation_churn(name, mutated):
    baseline = _profile(_CONSTRAINT_VARIABLES)
    observed = _profile(mutated)
    for key in ("table_row_count", "table_rows_sha256", "status_profile"):
        assert observed[key] == baseline[key], f"{name}/{key}"


def test_adversarial_content_witness_still_changes_on_real_content_change():
    baseline = _profile(_CONSTRAINT_VARIABLES)
    changed = _profile(
        _CONSTRAINT_VARIABLES.replace("<= 1000", "<= 10000")
    )
    assert changed["table_rows_sha256"] != baseline["table_rows_sha256"]
    dropped = _profile(
        _CONSTRAINT_VARIABLES.replace(
            "| gasLimit | contracts/Gateway.sol:L41 | none | setGasLimit | UNENFORCED |\n",
            "",
        )
    )
    assert dropped["table_row_count"] == baseline["table_row_count"] - 1
    assert dropped["status_profile"] == baseline["status_profile"]


# ==========================================================================
# GATE: _staged_methodology_repair_output_validator (+ its field reader and
# finding-block scoper).  14 of 17 semantically-neutral mutations were
# MEASURED to flip this gate from PASS to a DISCARD of a completed repair.
# ==========================================================================

import methodology_application as MA  # noqa: E402

_OBLIGATION_ID = "MAO-0123456789ABCDEF0123"
_REPAIR_WORKER = "METHODOLOGY_APPLICATION_REPAIR_BREADTH"
_REPAIR_DIGEST = "e" * 64


def _repair_context() -> dict:
    return {
        "schema": D._METHODOLOGY_REPAIR_STAGED_GATE_SCHEMA,
        "output_identity": f"scratchpad:{D._METHODOLOGY_REPAIR_OUTPUT}",
        "source_phase": "breadth",
        "finding_id_prefix": "MAB",
        "worker_id": _REPAIR_WORKER,
        "dispatch_contract_sha256": _REPAIR_DIGEST,
        "expected_obligations": [
            {"obligation_id": _OBLIGATION_ID, "skill": "ORACLE_ANALYSIS", "step": "2"},
        ],
    }


def _repair_trace(obligation_id: str = _OBLIGATION_ID) -> str:
    return (
        "## Step Execution Trace\n\n"
        + MA.TRACE_JSON_BEGIN
        + "\n"
        + json.dumps(
            {
                "schema_version": 1,
                "rows": [
                    {
                        "skill": "ORACLE_ANALYSIS",
                        "step": "2",
                        "executed": "yes",
                        "evidence": "src/Oracle.sol:L2",
                        "result": f"{obligation_id}: exact result",
                    }
                ],
            }
        )
        + "\n"
        + MA.TRACE_JSON_END
        + "\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )


_REPAIR_FINDING = (
    "## Finding [MAB-1]: Stale oracle read\n"
    "\n"
    "**Verdict**: PARTIAL\n"
    "**Step Execution**: ORACLE_ANALYSIS step 2 executed\n"
    "**Rules Applied**: [R16:OK]\n"
    "**Preferred Tag**: CODE-TRACE\n"
    "**Severity**: Medium\n"
    "**Location**: src/Oracle.sol:L2\n"
    "**Root Cause**: The staleness guard is absent.\n"
    "**Description**: Consumers can observe stale state.\n"
    "**Impact**: Quotes are computed from a stale price.\n"
    "**Material Harm** (MANDATORY): Depositors receive less than their share.\n"
    "**Evidence**: src/Oracle.sol:L2 shows the absent update.\n"
    "\n"
)


def _repair_artifact(finding: str = _REPAIR_FINDING, trace: str | None = None) -> str:
    markers = MA.worker_dispatch_markers(
        "breadth_repair", _REPAIR_WORKER, D._METHODOLOGY_REPAIR_OUTPUT,
        _REPAIR_DIGEST,
    )
    return markers + "\n\n" + finding + (trace if trace is not None else _repair_trace())


def _repair_verdict(body: str, context: dict | None = None):
    ctx = context or _repair_context()
    return D._staged_methodology_repair_output_result(
        {ctx["output_identity"]: body.encode("utf-8")}, ctx
    )


def test_repair_baseline_is_accepted():
    result = _repair_verdict(_repair_artifact())
    assert result.defects == ()
    assert result.should_discard is False


@pytest.mark.parametrize(
    "name,mutate",
    [
        # heading depth: measured "repair output has neither findings nor a
        # No Findings account"
        ("h4_heading", lambda t: t.replace("## Finding [MAB-1]", "#### Finding [MAB-1]")),
        # a heading spelling the written contract explicitly authorises
        ("candidate_heading", lambda t: t.replace("## Finding [MAB-1]", "## Candidate [MAB-1]")),
        ("issue_heading", lambda t: t.replace("## Finding [MAB-1]", "## Issue [MAB-1]")),
        ("bold_heading", lambda t: t.replace("## Finding [MAB-1]", "## **Finding [MAB-1]**")),
        ("bare_identity", lambda t: t.replace("## Finding [MAB-1]", "## Finding MAB-1")),
        # ONE \r per line produced ALL ELEVEN fields "missing"
        ("crlf", lambda t: t.replace("\n", "\r\n")),
        # fields as list items
        ("list_item_fields", lambda t: t.replace("\n**", "\n- **")),
        # colon inside the bold
        ("colon_inside_bold", lambda t: t.replace("**: ", ":** ")),
        # plain labels, no bold at all
        ("unbolded_fields", lambda t: t.replace("**", "")),
        # blockquoted fields
        ("blockquoted", lambda t: t.replace("\n**", "\n> **")),
        # the other legal spelling of the MANDATORY qualifier
        (
            "material_harm_qualifier_inside_bold",
            lambda t: t.replace(
                "**Material Harm** (MANDATORY):", "**Material Harm (MANDATORY)**:"
            ),
        ),
        # zero-padded finding id
        ("zero_padded_id", lambda t: t.replace("[MAB-1]", "[MAB-01]")),
        ("lowercase_id", lambda t: t.replace("[MAB-1]", "[mab-1]")),
        # a dispatch marker restated once
        (
            "restated_dispatch_marker",
            lambda t: t.replace(
                "<!-- PLAMEN_DISPATCH_WORKER: " + _REPAIR_WORKER + " -->",
                "<!-- PLAMEN_DISPATCH_WORKER: " + _REPAIR_WORKER + " -->\n"
                "<!-- PLAMEN_DISPATCH_WORKER: " + _REPAIR_WORKER + " -->",
            ),
        ),
        # a PROSE sentence that NAMES the COMPLETE sentinel: the literal run48
        # "prose named the marker" cause
        (
            "prose_names_the_complete_sentinel",
            lambda t: t.replace(
                "## Step Execution Trace",
                "I will end with <!-- PLAMEN_STATUS: COMPLETE --> when done.\n\n"
                "## Step Execution Trace",
            ),
        ),
        # lowercase obligation id in the trace row (the gate upper()d the
        # capture but matched the prefix case-sensitively -- a live bug)
        (
            "lowercase_obligation_id",
            lambda t: t.replace(_OBLIGATION_ID + ":", _OBLIGATION_ID.lower() + ":"),
        ),
    ],
)
def test_repair_presentation_mutations_do_not_change_the_verdict(name, mutate):
    baseline = _repair_verdict(_repair_artifact())
    mutated = _repair_verdict(mutate(_repair_artifact()))
    assert [d.property_violated for d in mutated.defects] == [
        d.property_violated for d in baseline.defects
    ], f"{name}: {[d.repair_hint for d in mutated.defects]}"
    assert mutated.should_discard is False


def test_repair_soft_wrapped_field_value_is_still_the_field():
    body = _repair_artifact(
        _REPAIR_FINDING.replace(
            "**Severity**: Medium\n", "**Severity**:\nMedium\n"
        )
    )
    assert _repair_verdict(body).defects == ()


# -------------------------- adversarial controls --------------------------


def test_adversarial_a_genuinely_missing_field_is_still_reported():
    body = _repair_artifact(
        _REPAIR_FINDING.replace(
            "**Material Harm** (MANDATORY): Depositors receive less than their share.\n",
            "",
        )
    )
    result = _repair_verdict(body)
    assert any(
        "lacks explicit nonempty Material Harm" in d.repair_hint
        for d in result.defects
    )
    assert result.should_discard is False


def test_adversarial_placeholder_field_value_is_still_missing():
    for placeholder in ("N/A", "none", "TBD", "<fill me in>"):
        body = _repair_artifact(
            _REPAIR_FINDING.replace(
                "**Severity**: Medium", f"**Severity**: {placeholder}"
            )
        )
        assert any(
            "lacks explicit nonempty" in d.repair_hint
            for d in _repair_verdict(body).defects
        ), placeholder


def test_adversarial_foreign_namespace_finding_id_still_blocks():
    """STEP 7 negative control: identity is still FAIL_CLOSED -- on the
    NORMALIZED value.  MAB-01 is MAB-1; FOREIGN-TOKEN-1 is not."""
    body = _repair_artifact(_REPAIR_FINDING.replace("[MAB-1]", "[FOREIGN-TOKEN-1]"))
    result = _repair_verdict(body)
    assert result.should_discard is True
    assert result.blocking_defects[0].property_violated == (
        "identity.methodology_repair_finding_id"
    )


def test_adversarial_conflicting_dispatch_marker_is_still_reported():
    body = _repair_artifact().replace(
        "<!-- PLAMEN_DISPATCH_WORKER: " + _REPAIR_WORKER + " -->",
        "<!-- PLAMEN_DISPATCH_WORKER: SOME_OTHER_WORKER -->",
    )
    result = _repair_verdict(body)
    assert any(
        "PLAMEN_DISPATCH_WORKER marker mismatch" in d.repair_hint
        for d in result.defects
    )


def test_adversarial_absent_completion_marker_is_still_reported():
    body = _repair_artifact(trace=_repair_trace().replace(
        "<!-- PLAMEN_STATUS: COMPLETE -->", ""
    ))
    assert any(
        "COMPLETE marker" in d.repair_hint for d in _repair_verdict(body).defects
    )


def test_adversarial_wrong_obligation_denominator_is_still_reported():
    body = _repair_artifact(trace=_repair_trace("MAO-DEADBEEFDEADBEEFDEAD"))
    assert any(
        "GAP-obligation multiset" in d.repair_hint
        for d in _repair_verdict(body).defects
    )


def test_adversarial_foreign_output_identity_still_blocks():
    ctx = _repair_context()
    result = D._staged_methodology_repair_output_result(
        {"scratchpad:some_other.md": _repair_artifact().encode()}, ctx
    )
    assert result.should_discard is True


def test_repair_publication_validator_publishes_on_debt(tmp_path):
    """STEP 6 at the call site: a presentational defect must not reach the
    transport as a rejection."""
    ctx = {**_repair_context(), "scratchpad": str(tmp_path)}
    body = _repair_artifact(
        _REPAIR_FINDING.replace("**Impact**: Quotes are computed from a stale price.\n", "")
    )
    assert D._staged_methodology_repair_publication_validator(
        {ctx["output_identity"]: body.encode()}, ctx
    ) == ()
    ledger = tmp_path / D._SURFACE_DEBT_LEDGER
    assert ledger.is_file()
    rows = [json.loads(line) for line in ledger.read_text().splitlines() if line]
    assert any("lacks explicit nonempty Impact" in r["repair_hint"] for r in rows)


def test_repair_publication_validator_still_rejects_an_identity_defect(tmp_path):
    ctx = {**_repair_context(), "scratchpad": str(tmp_path)}
    body = _repair_artifact(_REPAIR_FINDING.replace("[MAB-1]", "[FOREIGN-TOKEN-1]"))
    issues = D._staged_methodology_repair_publication_validator(
        {ctx["output_identity"]: body.encode()}, ctx
    )
    assert issues and "identity.methodology_repair_finding_id" in issues[0]
