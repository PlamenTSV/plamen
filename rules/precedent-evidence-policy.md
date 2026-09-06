# External Precedent Evidence Policy

This policy applies to RAG, vulnerability-database, WebSearch, audit-report,
incident, and methodology/literature results in every ecosystem and phase.

## Evidence-domain separation

Generic methodology literature supplies context only, with zero mechanism/code
confidence uplift. Historical similarity is not evidence that a mechanism is
present, reachable, harmful, or absent in the audited code. A supporting or
refuting external source may never clear or demote a candidate, force
`CONTESTED`, upgrade/downgrade severity, satisfy a proof obligation, or reduce
investigation depth. Code-derived facts and executed evidence retain sole
authority over those decisions.

An exact precedent is recognized only when all of these are present:

1. a primary precedent source whose exact bytes/reference are bound by a
   neutral driver-owned source-evidence receipt for the current run/snapshot;
2. a current finding fact with clean `EXPLICIT_TYPED_FIELDS` origin (an opaque
   per-finding identity or prose-derived label is never semantic equality);
3. the same typed mechanism class as the current finding; and
4. matching preconditions, compared as an exact typed set.

Generic articles, secondary summaries, shared vocabulary, similar titles,
nearby bug classes, match counts, and model/tool confidence scores are context,
not exact precedent. Contradicting or refuting articles are context only and do
not prove the current code safe.

## Allowed effects

Exact precedent may raise investigation priority and supply clearly labelled
report context only. It still contributes `0.0` to mechanism/code confidence.
No precedent result may reduce the remaining analysis or verification budget.
Unavailable, offline, timeout, empty-database, and tool-error states are
`UNSCORED`, not a floor score and not evidence for or against a finding.
Likewise, a proposed primary source without the neutral receipt is
`SOURCE_UNBOUND_CONTEXT_ONLY`: it is report-ineligible, does not raise
investigation priority, and is not exact precedent.

## Typed reconciliation

The research worker writes one bounded proposal block between
`PLAMEN_PRECEDENT_PROPOSALS_JSON_BEGIN` and
`PLAMEN_PRECEDENT_PROPOSALS_JSON_END`. It proposes source kind, relation,
mechanism class, and precondition classes; it never writes decision authority.
The driver extracts and validates that block, then reconciles it against the
independently derived finding facts into
`precedent_evidence_authority.json`. `precedent_context.md` is an investigation
projection; `precedent_report_context.md` is a separate eligible-only report projection
of that typed authority.

Proposal JSON is strict: duplicate keys, non-finite values, unknown fields,
decision-shaped fields, duplicate identities, unsafe source references, and
missing denominator rows become visible debt and no uplift. The driver creates
complete per-finding `UNSCORED` fallback rows when research or transport fails.
The proposal worker cannot create or edit finding facts, neutral source
receipts, the authority, or its projection.

Family propagation requires typed equivalence whose current record binds both
finding identities, the same mechanism class, the same precondition set, and
source evidence. Without that equivalence, only the directly matched member
receives an exact-precedent priority signal; every sibling remains unscored.

The typed authority is deliberately capability-limited:

- `mechanism_confidence_delta = 0.0`
- `may_clear_or_demote = false`
- `may_force_contested = false`
- `may_change_severity = false`
- `may_reduce_investigation_depth = false`

Malformed, duplicated, stale, out-of-run, out-of-snapshot, ambiguous, or
unbound proposal/equivalence records produce visible reconciliation debt and no
uplift. Research failure degrades to the same no-authority state and never
halts the audit.
