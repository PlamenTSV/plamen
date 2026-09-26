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

`FINDING` and `UNRESOLVED` must use the row's exact `required_action_id` in the
Markdown action block; the driver derives the JSON route. Do not mint a
different ID. Do not fabricate a finding to fill a quota. You have no
authority to drop, merge, or downgrade an existing finding.

---

## Semantic JSON authority

Write `axis_coverage_dispositions.json` as strict JSON with no comments,
trailing commas, prose, or Markdown fences. Emit only model-owned judgments;
the driver binds all IDs, routes, loci, hashes, schema and provenance fields:

```json
{
  "items": [
    {
      "disposition": "CLEAR",
      "evidence": [
        {
          "kind": "SOURCE_LOCUS"
        }
      ],
      "invariant_commitment": {
        "ci_id": "AXIS-CI-<unique uppercase token>",
        "shape": "NO_REVERT_AT_BOUNDARY",
        "assertion": "Concrete falsifiable safety property for this AXW row.",
        "falsify_class": "boundary"
      },
      "rationale": "Concrete, source-grounded conclusion."
    }
  ]
}
```

The `items` array must contain exactly one object for every authoritative
worklist item and no other object, in exact worklist order. The only permitted
dispositions are `FINDING`, `UNRESOLVED`, and `CLEAR`.

For `FINDING` or `UNRESOLVED`, the matching Markdown action block must exist.
That block must write the four non-empty metadata labels exactly as
`**Severity**:`, `**Location**:`, `**Work Item ID**:`, and
`**Description**:`. For `CLEAR`, `evidence` contains exactly one typed object:
`SOURCE_LOCUS` needs only `kind`; `CANONICAL_PRIOR` also names `canonical_id`;
registered `EXECUTION_RECEIPT` also names `evidence_id`. Every `CLEAR` contains
exactly one `invariant_commitment` with the four semantic keys shown above.
Shape must be one of
`CONSERVATION`, `REQUESTED_EQ_DELIVERED`, `APPROVE_EQ_SPEND`,
`NO_REVERT_AT_BOUNDARY`, `ROUNDTRIP`, or `FRESHNESS`; falsify class must be one
of `property`, `boundary`, `roundtrip`, or `conservation`; `ci_id` must be
unique across all rows. For `FINDING` or `UNRESOLVED`, set
`invariant_commitment` to JSON `null`.
Never encode missing analysis as an empty or vague clear.

If the driver intentionally supplies an exact zero-item worklist, emit an
empty `items` array, and record the zero-work explanation in
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
