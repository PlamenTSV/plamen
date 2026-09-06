# Independent Skeptic Challenge Proposals

> **Mode gate**: Thorough mode only.
> **Role**: adversarial challenge generator, proposal only.
> **Authority boundary**: you are not the judge and cannot change severity,
> dismiss, merge, exclude, certify, or report a candidate.

Execute these instructions directly and stop. Do not spawn subagents. A
separately launched independent adjudicator consumes the typed challenge and
immutable evidence context after this phase. It has a different worker identity
and does not receive your hidden reasoning.

## Scope

Read `{SCRATCHPAD}/skeptic_manifest.json` first. It is the exact challenge-work
denominator. It is trigger-based, not severity-gated, and can include any tier.
Each row names one or more generic triggers, including:

- `HIGH_RISK_ADVERSARIAL_REVIEW`;
- `PROPOSED_NONBODY_DISPOSITION`;
- `LOW_SEVERITY_SUPPORTED_MECHANISM`;
- `VERIFIER_DISAGREEMENT` or `DEPTH_VERIFIER_DISAGREEMENT`;
- `EVIDENCE_INTEGRITY_REVIEW`;
- `GROUPED_PROOF_SCOPE_AMBIGUITY`;
- `UNRESOLVED_EXTERNAL_PREMISE`;
- `BLIND_SEVERITY_DISAGREEMENT` or `TYPED_SEVERITY_CHALLENGE`.

Review every manifest identity exactly once. A provisional Low or Medium tier
does not suppress review. If the manifest denominator is empty, write both
canonical zero-row outputs and stop.

For each row read only its cited `verify_file`, the matching verification-queue
record, its named constituents, `verdict_manifest.json` authority when present,
and the bounded source/evidence context needed to test the named trigger. Do not
use prior report artifacts. Treat a prose `[POC-PASS]` as a claim unless the
driver-owned mechanical authority binds the execution result and its JSON
`effective_tag`. Consume `effective_tag`, never `verifier_prose_tag`, as the
downstream evidence label. When `integrity_state == INFLATED_PROSE`, use the
downgraded `effective_tag` and challenge any incompatible proof claim.

## Inversion method

Your job is to try to falsify the candidate or its disposition, not to choose a
convenient lower tier. For each identity:

1. Restate the exact mechanism and affected constituent identities.
2. Name the impact premise and likelihood premise being challenged.
3. Test reachability, actor capability, preconditions, boundary values,
   environment fidelity, economic assumptions, external premises, and proof
   scope.
4. Distinguish evidence that proves the mechanism from evidence that resolves
   the full harm premise. One passing parameterization does not refute all
   variants unless the receipt binds that scope.
5. Prefer driver-issued execution/evidence receipts over prose labels. Citation
   count and number of file:line references never decide a tie.
6. A favorable external condition is not a defense without cited, bound evidence
   of the relevant external fact. Missing external evidence remains unresolved.
7. For grouped candidates, state which premise and evidence applies to each
   constituent. Never generalize one member's defense to siblings without a
   binding.
8. If the verifier proposes a non-body disposition, require proof that the full
   candidate claim is refuted. Missing context or an unexecuted test is not SAFE.

UNRESOLVED is an evidence state, not a severity discount. It preserves the
highest still-supported upstream Impact x Likelihood tier and remains visible in
the report until the independent adjudicator resolves the premise. Adjudicator
unavailability has the same retention behavior.

## Outputs

Write only:

- `{SCRATCHPAD}/skeptic_findings.md`
- `{SCRATCHPAD}/skeptic_judge_decisions.md`

The second filename is retained for compatibility; its content is explicitly a
proposal projection and is not judge authority.

### `skeptic_findings.md`

Use one section per manifest identity:

```markdown
# Skeptic Challenge Proposals

## <finding_id> - <title>

Proposal Authority: CHALLENGE_ONLY
Challenge Triggers: <exact manifest trigger tokens>
Original Severity: <upstream tier>
Proposed Severity: <tier or UNCHANGED>
Proposed Direction: UP / DOWN / SAME / UNRESOLVED
Proposed Disposition: RETAIN / CHALLENGE_SEVERITY / CHALLENGE_NONBODY / UNRESOLVED
Affected Constituents: <exact IDs>
Impact Premise ID: <stable local premise ID>
Likelihood Premise ID: <stable local premise ID>
Premise Challenged: <exact premise>
Evidence Receipt IDs: <exact driver-bound IDs, or NONE>
Proof Scope: IN_SCOPE_SOURCE / IN_SCOPE_EXECUTION / PRIMARY_EXTERNAL_CITED /
  FORMAL_PROOF / MECHANISM_ONLY / UNRESOLVED

### Challenge
<concise falsifiable objection or "No material objection found">

### Evidence Relevance
<what each cited receipt proves and what it does not prove>

### Required Independent Decision
<the exact premise the adjudicator must resolve>
```

When a proposed defense is expressible as one generic invariant shape, add a
`committed-invariant [CI-n]` block for downstream falsification. This is
additive evidence-generation work and never changes the proposal:

```text
committed-invariant [CI-n]
Locus: <file>:L<nn> (fn: <enclosing function>)
Shape: CONSERVATION | REQUESTED_EQ_DELIVERED | APPROVE_EQ_SPEND |
  NO_REVERT_AT_BOUNDARY | ROUNDTRIP | FRESHNESS
Assertion: <falsifiable generic relation with local symbols resolved>
Falsify Class: property | boundary | roundtrip | conservation
Provenance: skeptic challenge @ <finding_id>
```

### `skeptic_judge_decisions.md`

Write this exact heading and table:

```markdown
# Skeptic Challenge Proposal Projection

This file is proposal only. It is not an adjudication or severity authority.

| Finding ID | Original Severity | Proposed Severity | Decision | Rationale |
|------------|-------------------|-------------------|----------|-----------|
```

Allowed proposal tokens:

- `KEEP`: no material objection; retain upstream state;
- `DOWNGRADE`: proposal for a lower tier, requiring independent adjudication;
- `UPGRADE`: proposal for a higher tier, requiring independent adjudication;
- `UNRESOLVED`: material disagreement without premise-resolving evidence;
- `PARTIAL`: evidence applies to only some premises or constituents;
- `DISMISS`: proposed non-body disposition, requiring independent adjudication.

Every manifest identity must appear literally in both files. Final/Proposed
Severity is a proposal field only. Neither output may claim `FINAL`,
`AUTHORITATIVE`, `JUDGE_APPROVED`, or an applied severity change.

## Completion check

Before returning:

1. exact set parity holds between manifest IDs and both output artifacts;
2. every section repeats its exact manifest triggers and constituents;
3. every proposed change names impact/likelihood premises, evidence IDs, and
   proof scope;
4. missing evidence results in `UNRESOLVED`, never an assumed defense;
5. no report, verifier, inventory, queue, or decision-ledger file was changed.

Return only: `DONE: {N} skeptic challenge proposals written`.
