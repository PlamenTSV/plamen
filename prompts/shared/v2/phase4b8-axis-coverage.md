# Multi-Axis Coverage Meta-Pass (Phase 4b.8)

> **Purpose**: Interrogate every driver-assigned hot-function/risk-axis work
> item exactly once. This is targeted depth exploration, not a
> validate-or-dismiss filter.
>
> **Authoritative input**: `axis_disposition_worklist.json`
>
> **Required outputs**: `axis_coverage_findings.md` and
> `axis_coverage_dispositions.json`
>
> **Finding format**: follow
> `~/.claude/rules/finding-output-format.md`

---

## Authority boundary

The driver has already constructed and validated the exact worklist. Read
`axis_disposition_worklist.json` first and process its `items` in their given
order. Each item provides an immutable `work_item_id` (`AXW-...`), function
identity, assigned axis, source-relative path and locus, source and matrix-cell
hashes, and a `required_action_id`.

The Markdown matrix and prior analysis artifacts are context, not authority.
Do not reconstruct the denominator from `hot_function_axes.md`,
`_hot_function_axes.json`, findings Markdown, the inventory, directory
contents, or your memory. Do not add, remove, merge, rename, or silently skip
AXW rows. If an authoritative row cannot be analyzed, dispose it as
`UNRESOLVED`; never convert an input or evidence problem into `CLEAR`.

Read the source at the exact path/locus named by each AXW row. You may follow
the immediate state, callees, and registered evidence referenced by
`axis_execution_evidence_authority.json`, but must not use unregistered
post-phase files to self-certify the result.

---

## Assigned risk axes

Interrogate only the axis assigned in each AXW row:

- **theft** — Trace every value or privilege effect to the ultimate recipient
  and amount. Determine whether value can reach an unauthorized party or
  exceed what is owed.
- **liveness** — Trace reachable edge states through the terminal outcome.
  Determine whether a core action can permanently revert, lock, or become
  unusable.
- **accounting** — Check the relevant conservation, share, total, or arithmetic
  relation under boundary values and meaningful parameter variations.
- **provenance** — Trace external values to their source and test the explicit
  freshness, identity, and trust assumptions on which the function relies.
- **boundary** — Execute the reasoning at zero, one, maximum, empty,
  duplicate, first/last, and type-edge inputs that are meaningful for the
  assigned locus.
- **identity** — Compare the authorizing actor with every subject whose funds,
  permissions, allowance, or state are changed, including delegation limits.

Use the closed evidence vocabulary from the finding format, including concrete
`[BOUNDARY:...]`, `[VARIATION:...]`, `[TRACE:...]`, and, where applicable,
`[EXTERNAL-ASSUMPTION:...]` or `[CROSS-DOMAIN-DEP: external]` tags. A summary
without a concrete source locus and trace is not a valid clear.

---

## One disposition per AXW row

For every `work_item_id`, emit exactly one of:

- `FINDING`: the assigned interrogation supports material harm. Emit the
  standard finding block under the row's exact `required_action_id`.
- `UNRESOLVED`: safety was not established, including missing source,
  conflicting evidence, insufficient context, or an unproved external
  premise. Emit an unresolved candidate block under the row's exact
  `required_action_id` so verification retains it.
- `CLEAR`: the assigned interrogation establishes safety with concrete,
  source-grounded evidence. `CLEAR` must not reference an action and must not
  create a finding block.

`FINDING` and `UNRESOLVED` must reference exactly the row's
`required_action_id`; do not mint a different ID. Do not fabricate a finding
to fill a quota. You have no authority to drop, merge, or downgrade an
existing finding.

---

## Strict JSON authority

Write `axis_coverage_dispositions.json` as strict JSON with no comments,
trailing commas, prose, or Markdown fences:

```json
{
  "schema_version": "plamen.axis_model_dispositions.v1",
  "run_id": "<copy the exact worklist run_id>",
  "worklist_hash": "<copy the exact worklist_hash>",
  "producer": "MODEL",
  "items": [
    {
      "work_item_id": "AXW-...",
      "disposition": "CLEAR",
      "action_id": "",
      "evidence": [
        {
          "kind": "SOURCE_LOCUS",
          "source_relpath": "relative/path.ext",
          "source_locus": "L123",
          "source_hash": "<copy the exact AXW source_hash>"
        }
      ],
      "invariant_commitment": {
        "ci_id": "AXIS-CI-<unique uppercase token>",
        "ci_block_sha256": "<sha256 of the other eight canonical commitment fields>",
        "locus": "relative/path.ext:L123",
        "shape": "NO_REVERT_AT_BOUNDARY",
        "assertion": "Concrete falsifiable safety property for this AXW row.",
        "falsify_class": "boundary",
        "provenance": "AXW:AXW-...",
        "source_hash": "<copy the exact AXW source_hash>",
        "evidence_sha256": "<sha256 of canonical JSON for the evidence array>"
      },
      "rationale": "Concrete, source-grounded conclusion."
    }
  ],
  "sidecar_digest": "<sha256 of canonical JSON for every other top-level field>"
}
```

The `items` array must contain exactly one object for every authoritative
worklist item and no other object. Preserve each `work_item_id` exactly and
copy `run_id` and `worklist_hash` exactly. Set `producer` to `MODEL`. Compute
`sidecar_digest` over the other top-level fields using UTF-8 JSON with sorted
keys, no insignificant whitespace, and separators `,` and `:`. The only
permitted dispositions are `FINDING`, `UNRESOLVED`, and `CLEAR`.

For `FINDING` or `UNRESOLVED`, `action_id` must equal that AXW row's
`required_action_id` and the matching Markdown action block must exist. That
block must include non-empty `Severity`, `Location`, `Work Item ID`, and
`Description` fields. For `CLEAR`, `action_id` must be the empty string,
`evidence` must contain exactly one typed object (`SOURCE_LOCUS`,
`CANONICAL_PRIOR`, or registered `EXECUTION_RECEIPT`), and the row must not
reference an action. Every `CLEAR` must also contain exactly one
`invariant_commitment` object with the nine keys shown above. Its locus must be
the exact production `source_relpath:source_locus`; shape must be one of
`CONSERVATION`, `REQUESTED_EQ_DELIVERED`, `APPROVE_EQ_SPEND`,
`NO_REVERT_AT_BOUNDARY`, `ROUNDTRIP`, or `FRESHNESS`; falsify class must be one
of `property`, `boundary`, `roundtrip`, or `conservation`; provenance must be
exactly `AXW:<work_item_id>`; and the source/evidence hashes must bind the exact
AXW source and typed evidence array. `ci_id` and `ci_block_sha256` must each be
unique across all rows. For `FINDING` or `UNRESOLVED`, set
`invariant_commitment` to JSON `null`.
Never encode missing analysis as an empty or vague clear.

If the driver intentionally supplies an exact zero-item worklist, copy its
hash, emit an empty `items` array, and record the zero-work explanation in
Markdown. Do not infer zero work from missing or malformed input.

---

## Markdown support projection

Write `axis_coverage_findings.md` with:

1. One standard finding/candidate block for every JSON item disposed
   `FINDING` or `UNRESOLVED`, keyed by the exact action ID.
2. A human-readable coverage table containing every AXW ID, assigned function
   and axis, disposition, action ID where applicable, and concrete evidence.
3. `<!-- PLAMEN_STATUS: COMPLETE -->` only after both required artifacts cover
   the exact authoritative worklist.

Markdown is not authority for worklist cardinality or dispositions. The
strict JSON is authoritative; Markdown supplies reviewable finding prose and
must agree with it. Any mismatch is a reconciliation failure and must be
repaired by the bounded repair workflow, not guessed away.

---

## Method discipline

This methodology encodes how to interrogate an assigned risk axis, never a
protocol-specific answer. Protocol, contract, function, variable, or asset
names belong only in current-run evidence and finding bodies. Write only the
two assigned output artifacts and stop.
