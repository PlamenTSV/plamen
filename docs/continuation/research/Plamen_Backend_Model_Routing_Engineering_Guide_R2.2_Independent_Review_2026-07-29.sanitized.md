# Plamen Backend Model Routing Engineering Guide R2.2
## Independent Blocking Review Receipt

Date: 2026-07-29

Reviewer role: independent architecture and implementation-readiness reviewer

## 0. Disposition

**Verdict: BLOCK PENDING R2.3 TRANSACTIONAL AND SCHEMA CLOSURE**

**Architecture direction: PASS**

R2.2 closes the material standards, cross-runtime canonicalization, provider-fact,
effort-precedence, thinking-enum, generation-transition, ratio-semantics, canary-plan,
launch-authority, native-budget, route-debt, and citation defects identified in the
R2.1 review. The guide is now substantially stronger and is close to
implementation-ready.

It is not yet safe to use as the sole executable specification. Seven bounded gaps
remain. The most important is that the common resource ledger defines attempt
reservations but the provider-launch authorization chain does not bind the launched
attempt to its reservation. Other gaps concern duplicated thinking evidence,
customization-set identity, cross-field budget equations, ledger replay semantics,
comparison-schema nullability, and canary evidence membership.

These are repairable specification defects. They do not justify reverting to a
different routing architecture. They do justify one final schema-focused revision
before production implementation or cutover.

No provider was called, no audit was launched, and no repository, runtime
configuration, guide, or implementation file was modified during this review.

## 1. Frozen Review Boundary

Artifact reviewed:

`<LOCAL_USER_ROOT>\Downloads\Plamen_Backend_Model_Routing_Engineering_Guide_R2.2_2026-07-29.md`

Observed SHA-256:

`1077CA061F6CBBF93A4A9FB410CEC9A0431CA3B5CF0A16366E113E3925E28A62`

Observed file properties:

- 45,778 bytes
- 1,626 lines
- ASCII only
- LF line endings only

Prior independent R2.1 receipt:

`<LOCAL_USER_ROOT>\Downloads\Plamen_Backend_Model_Routing_Engineering_Guide_R2.1_Independent_Review_2026-07-29.md`

Prior receipt SHA-256:

`3569D77097801A95477281188EED0583A23F2C1B970B434F298C8E3B3023F69B`

R2.2 is reviewed as a delta layered over the retained rules in R2.1. That layering
itself creates one of the remaining ambiguities: a retained observation field and a
new replacement-like field coexist without a replacement or equality law.

## 2. Review Standard

The review re-applied every original blocking concern B1 through B7 and stress-tested:

- cross-runtime canonical JSON behavior;
- I-JSON number limits;
- Unicode normalization and identity handling;
- semantic-set ordering;
- exact Claude effort precedence and sealing;
- closed thinking-control enums;
- generation transition identity;
- compare-and-swap resource accounting across generations;
- BudgetAuthority cross-field consistency;
- ratio and range denominators;
- CanaryPlan claim mutation law;
- launch, native-budget, and route-debt schemas;
- official provider and standards citations;
- examples, contradictions, encoding, and artifact identity.

A design is treated as implementation-ready only when two independent conforming
implementations would accept, reject, hash, reserve, launch, reconcile, compare, and
mutate the same inputs identically.

## 3. Original Blocking Areas

| Area | R2.2 result | Disposition |
|---|---|---|
| B1. Model identifiers and current provider capabilities | Officially supported and properly scoped | PASS |
| B2. Context/output limits and effort capability facts | Current values and support boundaries are correctly cited | PASS |
| B3. Effective effort precedence and launch sealing | Core precedence repaired; customization-set identity remains underspecified | PARTIAL / BLOCK |
| B4. Closed thinking request semantics | Request enum repaired; observed-field and launch-control authority remain incomplete | PARTIAL / BLOCK |
| B5. Generation transition semantics | Model/effort changes correctly require a new generation | PASS |
| B6. Canary and launch evidence integrity | Plan mutation law and launch authority improved; attempt binding and evidence membership remain open | PARTIAL / BLOCK |
| B7. Resource, budget, ratio, and reconciliation semantics | Major redesign is sound; exact equations, journal replay, and comparison schema remain open | PARTIAL / BLOCK |

## 4. Repairs Accepted

### 4.1 Canonicalization is now cross-runtime viable

R2.2 correctly restricts canonical JSON integers to the exact interoperable range
`0..2^53-1`, rejects wider JSON integer values, and allows wider internal arithmetic
without placing those values directly in canonical JSON.

Identity-bearing strings are required to be NFC and rejected when they are not,
rather than silently normalized. The narrowly identified free-text
`required_operator_action` field is normalized before hashing.

Semantic sets are sorted using canonical UTF-8 byte order, with cross-runtime Python,
JavaScript, and .NET vectors. This closes the earlier ambiguity caused by relying on
host-language string comparison.

The RFC 8785 and RFC 7493 citations support these constraints. This portion is a
PASS.

### 4.2 Claude effort authority is materially repaired

The effective launch strategy now:

- sets `CLAUDE_CODE_EFFORT_LEVEL` to the routed effort;
- sets the explicit `--effort` argument to the same routed effort;
- checks customization sources that can override ordinary session configuration;
- fails closed when the effective effort cannot be proven;
- binds effort authority into the launch chain.

This directly addresses skill/frontmatter precedence and the stronger environment
override described by current Claude Code documentation. The remaining B3 defect is
not the precedence strategy; it is the missing exact schema and ordering law for the
loaded customization set and the absence of an explicit equality constraint between
its two digest references.

### 4.3 Thinking request space is closed

R2.2 replaces an open-ended thinking string with a closed request matrix and rejects
invalid provider/model combinations. This is the correct approach. It also avoids
pretending that unavailable or unobservable provider internals are equivalent to
verified launch state.

The remaining issue is the authority/evidence chain described in finding 2 below.

### 4.4 Generation transitions are now correctly scoped

Changes to model or reasoning effort create a new generation rather than an
untracked retry or a new attempt within the old generation. Resource accounting is
organized around an arm family and compare-and-swap journal so that generations
remain related without overwriting one another.

This is the right identity model and closes B5.

### 4.5 Ratio semantics are substantially clearer

R2.2 distinguishes:

- observed-to-grant utilization; and
- pair-resource comparison.

It also specifies the run-level 1,000-1,500 basis-point interval rather than leaving
an ambiguous ratio denominator or treating a point target as a universal law.

The remaining defect is a basis-dependent field-shape conflict in
`PairResourceComparisonV1`, not the analytical policy.

### 4.6 Canary plan mutation law is now explicit

The exact CanaryPlan and field-level claim framework now prevents unproven canary
results from silently mutating production routing fields. Field claims, route debt,
and the post-canary mutation rule are a meaningful governance improvement.

The remaining gap is that claim evidence is digest-referenced but not structurally
proven to be a member or projection of the receipt's raw evidence.

### 4.7 Launch, native-budget, route-debt, and citation repairs pass

The LaunchAuthority and AttemptLaunchEnvelope split is sound in principle.
Native-budget and route-debt identity schemas are materially improved, and route
identity is no longer implicitly inferred from incomplete fields.

The guide now cites official OpenAI, Anthropic, Claude Code, and RFC sources for the
facts used in the routing design. The provider-fact and source-citation review
passes.

## 5. Blocking Findings

### 5.1 Attempt reservations are not bound into the provider launch chain

Severity: BLOCKING

Affected areas: B6, B7

Evidence:

- The common resource journal defines `RESERVE_ATTEMPT` and attempt resource entries.
- Backend arm and LaunchAuthority records bind a generation reservation event digest.
- `AttemptLaunchEnvelopeV1` identifies the attempt and binds the arm, launch
  authority, materialized arguments, environment, prompt, working directory, and
  launch time.
- The envelope does not bind an attempt-reservation event digest, the corresponding
  attempt resource-entry digest, or the post-reservation resource-ledger snapshot.
- No normative transition says a successful attempt reservation must occur before
  materialization and provider execution.

Why this matters:

The system can produce a cryptographically coherent launch envelope for an attempt
whose attempt-level allocation was never reserved, was reserved under a stale
generation snapshot, or belongs to a different attempt. Later reconciliation cannot
recover the expected per-attempt denominator from the envelope alone. A process
implementation might enforce the intended sequence, but the specification does not.

Required R2.3 repair:

1. Require a successful compare-and-swap `RESERVE_ATTEMPT` before launch
   materialization or provider execution.
2. Add to the launch envelope:
   - `attempt_reservation_event_digest`;
   - `attempt_resource_entry_digest`;
   - `resource_ledger_digest_after_attempt_reservation`.
3. Require the observation and reconciliation records to bind the same attempt
   allocation or an unambiguous derivative of it.
4. Define the exact failure state when reservation loses the CAS race.
5. Add production fixtures for:
   - launch without an attempt reservation;
   - a stale generation or ledger digest;
   - reservation for another attempt;
   - idempotent reservation retry;
   - duplicate provider launch after an already-consumed reservation.

### 5.2 Thinking evidence is duplicated and current launch controls are not fully sealed

Severity: BLOCKING

Affected area: B4, B6

Evidence:

R2.2 states that `ProviderExecutionObservationV3` retains the R2.1 V2 fields and adds
`observed_thinking_state`. R2.1 V2 already contains
`observed_thinking_mode | null`. R2.2 does not remove the old field or state an
equality, projection, precedence, or conflict rule between the two.

The thinking mapping defines `ADAPTIVE_EXPLICIT` and an exact provider vector, but
the effort customization scan does not equivalently seal the current Claude Code
thinking controls. Current official Claude Code documentation exposes controls such
as `MAX_THINKING_TOKENS`, the always-thinking setting or toggle, and session-level
thinking controls. Those controls can change effective execution independently of
the routed request.

Why this matters:

Two conforming implementations may accept conflicting observed thinking fields or
may launch the same declared route with different effective thinking behavior due
to unbound local controls. This undermines both canary attribution and cost/quality
comparison.

Required R2.3 repair:

1. Make V3 explicitly replace `observed_thinking_mode`, or define an exact
   one-to-one projection and reject conflicts.
2. Add a `ClaudeThinkingAuthorityV1`, analogous to effort authority, that inventories
   and seals all applicable CLI, environment, settings, frontmatter, and session
   controls.
3. Define whether adaptive thinking is:
   - an explicit provider control with an exact serialized vector; or
   - a verified omission/default state with every competing control proven absent.
4. When the effective thinking state is not observable, require route debt or a
   non-proven canary claim rather than inferring it.
5. Add mutation fixtures for every currently supported control source and for
   conflicting observation fields.

### 5.3 Loaded customization-set identity and ordering remain underspecified

Severity: BLOCKING

Affected area: B3

Evidence:

`ClaudeEffortAuthorityV2` includes arrays of customization-source rows and a
`customization_set_digest`. Those arrays are not declared semantic sets, nor do they
have a normative precedence order or row ordinal. The exact schema committed by
`customization_set_digest` is not specified.

LaunchAuthority separately contains `loaded_customization_set_digest`, but there is
no explicit rule requiring it to equal the digest sealed by the effort authority.

Why this matters:

The effort precedence algorithm can be correct while two runtimes hash the same
loaded sources in different orders. Worse, the launch can bind one customization
set while the effort authority attests to another. This is a deterministic
application gap, not merely a naming issue.

Required R2.3 repair:

1. Define a machine-readable `LoadedCustomizationSetV1` and row schema.
2. Specify whether rows form:
   - an ordered precedence sequence with a mandatory ordinal and uniqueness rules;
     or
   - a semantic set sorted by the canonical set-ordering law.
3. State exactly which bytes or canonical record the digest commits to.
4. Require:
   `LaunchAuthority.loaded_customization_set_digest ==
   ClaudeEffortAuthority.customization_set_digest`.
5. Add reordered-row, duplicate-source, shadowed-source, path-alias, and post-scan
   mutation fixtures.

### 5.4 BudgetAuthority and the common ledger lack exact cross-field equations

Severity: BLOCKING

Affected area: B7

Evidence:

`BudgetAuthorityV2` contains `requested_common_reservation` plus repeated
turn/retry/wall/tool/driver limits. It does not state exact equality or less-than-or-
equal equations connecting the duplicated values.

The budget also carries `currency_micros_limit`, while the arm-family common resource
vector does not include currency. Creating a new generation can therefore renew API
monetary authority even while the non-monetary resources are controlled across the
family.

`TokenBudgetDerivationV1` is joined by digest, but there is no complete normative
equation requiring the token grants in BudgetAuthority to equal or fit the
derivation output.

Why this matters:

Duplicated unconstrained limits permit internally inconsistent authorities.
Generation changes can accidentally multiply monetary spend. A derivation digest
can be present without its results governing the actual budget.

Required R2.3 repair:

1. State exact cross-field equations between
   `requested_common_reservation` and every duplicated common limit, or remove the
   duplicates.
2. Place `currency_micros_limit` in the provider-family ledger, or define a separate
   cumulative monetary ledger with the same CAS and reconciliation guarantees.
3. Define exact equations between token derivation outputs and budget token fields.
4. Reject overflows, negative deltas, inconsistent units, and a generation whose
   family-wide monetary reservation is exhausted.
5. Add fixtures for a generation rollover that attempts to renew monetary budget
   and for each inconsistent duplicated field.

### 5.5 Resource-journal replay semantics are not yet fully deterministic

Severity: BLOCKING

Affected areas: B6, B7

Evidence:

Resource-ledger snapshots contain arrays of generation and attempt entry digests,
but those arrays have no explicit ordering or semantic-set declaration.

`ResourceLedgerEventV1.generation` is mandatory even for family-wide event kinds
such as `CLOSE_FAMILY` or family-wide `MARK_DEBT`, without a nullable or sentinel
rule.

The event union lacks an exact per-kind required/null/zero field matrix for
reservation deltas, reconciliation deltas, token derivation, budget authority, and
attempt fields. Genesis sequence/previous-digest behavior and the legal entry-state
transition table are also not fully normative.

Why this matters:

Independent implementations can create different snapshot digests, use incompatible
sentinels, or accept different event shapes and state transitions. CAS alone does
not make a journal deterministic when the accepted event language and replay
function are open.

Required R2.3 repair:

1. Declare snapshot digest arrays to be either ordered sequences with a normative
   order or semantic sets using the canonical set rule.
2. Make generation nullable for family events or define one exact canonical
   sentinel that cannot collide with a real generation.
3. Publish a per-event required/null/zero field matrix.
4. Define genesis event sequence, previous digest, initial snapshot, and close
   behavior.
5. Define the legal state-transition table for family, generation, and attempt
   entries.
6. Add cross-runtime journal-replay golden vectors, including rejected traces.

### 5.6 PairResourceComparison has a basis-dependent field-shape contradiction

Severity: BLOCKING

Affected area: B7

Evidence:

The schema requires all authority and usage digests to be non-null. Its prose says:

- observed-to-observed comparison requires usage digests;
- reserved-to-reserved comparison requires authority digests;
- mixed comparisons are invalid.

The irrelevant digest pair cannot be null under the schema and therefore may contain
arbitrary values. No equality or ignored-field law resolves this.

Why this matters:

The comparison basis is intended to prevent denominator substitution. Requiring
unrelated, unconstrained digests reintroduces ambiguity into the exact object that
is supposed to prevent it.

Required R2.3 repair:

Use either separate schemas for observed and reserved comparison, or nullable
basis-dependent fields with an exact matrix:

- `OBSERVED_TO_OBSERVED`: usage digests required; authority digests null.
- `RESERVED_TO_RESERVED`: authority digests required; usage digests null.
- every mixed or over-populated shape rejected.

Also type and bind the exact denominator authority used by
`ObservedToGrantUtilizationV1`.

### 5.7 Canary claim evidence is not proven to belong to the receipt evidence

Severity: BLOCKING

Affected area: B6

Evidence:

`CanaryFieldClaimV1` references an `evidence_digest_set_digest`.
`CanaryReceiptV1` references `raw_evidence_digest` and executed case identifiers.
There is no exact manifest or membership rule proving that the claim's evidence set
is a projection of, or a member set within, the raw evidence committed by the
receipt. Executed case identifiers prove intended or recorded execution identity,
not the outcomes used to prove a field claim.

Why this matters:

A syntactically valid `PROVEN` field claim can point to an arbitrary evidence-set
digest that has no structural relationship to the receipt. The post-canary mutation
law is strong only if claim evidence is transitively bound to executed case results.

Required R2.3 repair:

1. Define a canonical `CanaryEvidenceManifestV1`.
2. Define per-case result records with case identity, expected outcome, observed
   outcome, raw artifact digests, and pass/fail disposition.
3. Bind the manifest to `CanaryReceiptV1.raw_evidence_digest`.
4. Allow a field claim to cite only manifest members and only case outcomes that
   satisfy that field's proof rule.
5. Add fixtures for an arbitrary evidence-set digest, swapped case result,
   incomplete required case set, post-receipt evidence mutation, and a PROVEN claim
   backed by a failed case.

## 6. Non-Blocking Precision and Engineering Notes

### 6.1 Publish one consolidated specification

R2.2 is a delta over R2.1. That is reviewable, but implementation should not require
engineers to mentally merge multiple documents. The duplicated thinking observation
field demonstrates the risk.

R2.3 should be a consolidated guide or should normatively import machine-readable
schemas whose versioned definitions supersede prose fields. A short change log can
remain separate.

### 6.2 Prefer schemas plus executable conformance vectors

The remaining defects share a pattern: the high-level rule is sound, but field
presence, identity, ordering, or transition behavior is not mechanically closed.
Adding more narrative alone is unlikely to solve this reliably.

The highest-value R2.3 deliverables are:

- JSON Schemas or typed models for every authority, envelope, observation, journal
  event, snapshot, comparison, evidence manifest, and debt record;
- explicit cross-record invariants;
- canonicalization and replay golden vectors consumable by Python, JavaScript, and
  .NET;
- negative vectors for forbidden unions and transitions;
- a reference state-transition reducer.

### 6.3 Retain fail-closed production behavior

The guide's direction is correct: unavailable or unprovable provider state should
create route debt, block promotion, or fall back to a known-safe route. It should
not be silently interpreted as proof that the requested effort or thinking state
was applied.

## 7. Source and Fact Check

The cited fact set is adequate for the architecture:

- Official OpenAI documentation supports the named current Codex model families,
  their context/output limits, effort options, and availability boundaries used by
  the guide.
- Official Anthropic model, migration, effort, extended-thinking, Claude Code model
  configuration, and model API documentation support the Claude model and control
  claims.
- Current Claude Code documentation supports the stronger environment-level effort
  precedence and the existence of skill/subagent customization sources.
- RFC 8785 and RFC 7493 support the interoperable-number and canonicalization
  constraints.

Provider facts are temporally unstable. The guide correctly treats the registry and
canary process as the operational authority rather than embedding research prose as
permanent truth. Any later provider upgrade still requires refreshed source pins
and canary evidence.

## 8. Implementation and Cutover Decision

Do not cut over production routing from R2.2 alone.

The safe next sequence is:

1. Produce a consolidated R2.3 with the seven bounded schema repairs.
2. Publish machine-readable schemas, invariant checks, and cross-runtime golden
   vectors.
3. Obtain an independent review of R2.3 focused only on the repaired joins and
   transitions.
4. Implement behind dual-write or shadow-mode boundaries.
5. Run deterministic conformance, journal-replay, mutation, crash/restart, and
   cross-runtime tests before any live canary.
6. Run governed canaries only after launch authorization and attempt reservation are
   transitively bound.
7. Permit field-level promotion only through the repaired evidence manifest and
   mutation law.

The architecture is worth continuing. The remaining work is narrow enough that a
fresh redesign would have worse risk and lower return than closing these
transactional joins.

## 9. Final Verdict

R2.2 is a strong architectural revision and repairs the substantive provider and
canonicalization defects from R2.1. It is not yet an executable, cross-runtime
contract because several adjacent records can still disagree without violating a
normative rule.

**Final disposition: BLOCK PENDING R2.3 TRANSACTIONAL AND SCHEMA CLOSURE.**

**Architecture disposition: PASS.**

The blockers are bounded and actionable:

1. bind attempt reservations to launches;
2. unify and seal thinking authority/evidence;
3. canonicalize customization-set identity;
4. close BudgetAuthority and family-cost equations;
5. specify the complete journal event/replay language;
6. repair comparison-schema field shapes; and
7. bind canary claims to actual receipt evidence.

Once those joins have schemas and executable negative/golden vectors, the guide is a
credible implementation and canary foundation.
