# Plamen Backend Model Routing Engineering Guide R2.5

Date: 2026-07-30

Status: author conformance candidate; self-validated, not independently
accepted and not authorized for production integration.

## 1. Purpose and exact correction boundary

R2.5 is the additive normative successor to the frozen R2.3 and R2.4 design
packages. It corrects the independent R2.4 blocking review without changing
any production, test, provider, install, audit, default, commit, or push
state. Frozen R2.4 bytes remain prerequisites, not edit targets.

The exact blocking review is:

- file:
  `backend_model_routing_r2_4_independent_review_r1_20260730.md`
- whole SHA-256:
  `40c3468e08a5a615295e93e9189c7a53eb7af668a49f48e45a834aa55c1e06b8`
- body SHA-256:
  `0d076d5f78947fdcf9fba9dcd8c451cbf4226d5121fad9323191b30fe9f2f207`
- accepted negative probes converted to durable vectors: 48 of 48

The review declares its 2,851-byte restricted-JSON negative-outcome manifest
as `61981cac2042e9c7854737e6de759ef6fae2f3fe7ad405f721b431e8dbceabca`.
Reconstructing the stated sorted-key compact JSON from the 48 exact Section 4
labels produces the same declared byte count but SHA-256
`fad68edc4f82e09c0eed8d5bc1139e389e32c70f14efa783bb419d93bcbf8f9b`.
R2.5 preserves both values explicitly and binds the exact whole/body review
hashes plus the exact ordered labels. It does not silently treat the internal
manifest-hash discrepancy as resolved; the independent reviewer must
adjudicate it.

R2.5 adds 48 author adversarial vectors, for 96 new vectors. Its validator
also hash-checks and executes the frozen R2.3 186-vector and R2.4 314-vector
denominators. This deliberate predecessor replay is the preservation proof;
it does not claim 596 unique requirements.

## 2. Normative artifacts

- this guide
- `Plamen_Backend_Model_Routing_R2.5_Schemas_2026-07-30.json`
- `Plamen_Backend_Model_Routing_R2.5_Conformance_Vectors_2026-07-30.json`
- `validate_plamen_model_routing_r2_5.py`
- `Plamen_Backend_Model_Routing_R2.5_Validation_Receipt_2026-07-30.json`
- amended joint implementation plan:
  `claude_r3_backend_routing_joint_implementation_plan_r5_20260730.md`

The schema and vector artifacts are ASCII, LF-only, final-LF JSON. Parsing
rejects duplicate object members, floats, non-finite values, negative zero,
out-of-range integers, and non-ASCII member names. Identity hashes use
deterministic sorted-key, compact UTF-8 JSON.

## 3. Design law: one rooted, acyclic authority graph

R2.4 allowed individually self-consistent records to be rehashed around a
substituted parent. R2.5 requires validation against the actual typed parent
objects supplied to one closure operation. A child self-digest is necessary
but never sufficient.

```text
R2.3 loaded-customization / effort / thinking
                         |
                         v
predecessor projection -> routing root
                         | \
                         |  +-> profile-semantics root -> profiles -> registry
                         |  +-> environment policy -> public projection
                         |  +-> provider manifest -> model/tuple -> capability
                         |                           \-> price/fallback/time
                         v
customization -> route -> request -> WorkPlan -> PhaseIO
                       \-> control -> launch -> arm -> attempt
                                      \              |
                                       +-> V3 projection
                                               \     |
                                                -> V4 envelope
                                                     |
                                                  consume
                                                     |
                                  evidence manifest -> observation
```

The root points only to predecessor or independently established authority
digests. Descendants point down the graph. No record contains a digest that
requires hashing itself or a descendant, so there is no digest cycle.

`RoutingRootAuthorityV1` preserves these R2.3 identities verbatim:

- loaded customization set;
- effort authority;
- thinking authority.

`CustomizationAuthorityProjectionV1` separately proves the exact
predecessor-to-successor mapping. Successor request, WorkPlan, PhaseIO,
control, launch, arm, attempt, envelope, observation, and resume identities
carry the relevant root/customization authority. A new self-consistent
descendant cannot replace an ancestor without the closure validator observing
the mismatch.

The route-selection authority does not merely copy requested effort and
thinking strings. Its model-family identity, requested effort, thinking mode,
and manual budget are compared to the actual preserved R2.3 effort and
thinking authority records when applicable. `NOT_APPLICABLE` is legal only
when the typed provider model capability declares it; the requested value
must then be null while the predecessor effort-authority digest remains
explicitly preserved as historical input. It cannot be silently dropped or
reinterpreted as an applied value.

The closure operation receives the independently frozen expected routing-root
digest separately from the root object and compares them before validating
descendants. Consequently, consistently rehashing the root and every
descendant still fails; the root is not self-authorizing.

The root also commits every pre-root selection input needed to make the
successor route unique: execution axes; exact selected profile/row/registry;
public environment; capability, price, fallback, context-budget, and budget
authorities; evidence-field and proof-policy authorities; WorkPlan identity;
and the PhaseIO LaunchSpec identity. A typed
`ProviderRouteSelectionAuthorityV1` commits the chosen manifest model row,
route tuple, effort applicability/value, thinking mode/manual budget, and
budget identities. `ModelRouteV4` is derived from that parent. The root does
not point to `ModelRouteV4`, which would create a cycle.

Post-root transactional facts cannot be placed in the root. The closure
therefore receives their actual typed parents separately: generation and
attempt reservations, resource entries and ledgers, consume event/CAS,
materialized prompt and working-directory identities, preparation time,
reconciliation receipt, and incorporated output set. Envelope, consume,
resume, and incorporation evidence are checked against those objects rather
than accepted as arbitrary digest-shaped strings.

## 4. Exhaustive join rule

The implementation contract is enumerate-all, diff, and reconcile:

1. validate every record against its exact schema and version;
2. recompute every record self-digest;
3. supply actual parent records, not caller-provided expected digests;
4. compare every duplicated child value to the authoritative parent field;
5. reject on the first stable invariant category;
6. never infer a parent solely from a child's digest.

The validator covers all joins named by the blocking review:

- WorkPlan and PhaseIO to request and each other;
- request to root, axes, semantic plan, profile semantics, registry, selected
  profile, customization, route, all four independent input domains, tools,
  WorkPlan/PhaseIO/output contracts, context budget, and budget authority;
- control to request, semantic plan, axes, profile, customization, route,
  effort, thinking, environment policy, materialized arguments, public
  environment, and secret-proof policy;
- launch to root, semantic plan, axes, profile, customization, route, budget,
  control, WorkPlan, PhaseIO, tools, generation, and family;
- arm and attempt to their complete actual ancestors;
- V4 envelope to attempt, arm, launch, request, control, customization,
  public environment, policy, arguments, and exact V3 projection;
- consume to the exact V4/V3/attempt identity;
- observation to request, axes, profile, route, attempt, envelope, consume,
  environment, customization, effort, thinking, and evidence claims.

Separately frozen expected digests are supplied for the root, axes, selected
profile, route-selection authority, customization result, public environment,
and route result. This defends the stronger attack where an otherwise legal
alternate selection and every descendant are consistently rehashed.

This is the executable form of R2.4 amendments A3-A6 and A9.

## 5. Immutable profile semantics

`ClaudeProviderProfileSemanticsAuthorityV2` commits all semantic fields for
exactly four route-neutral profiles. Rows are unique and sorted by profile
identifier. Each selected profile must equal its rooted row field-for-field,
including:

- environment policy set names;
- settings and MCP selection policy;
- stream byte and event ceilings;
- isolation policy;
- permission, tools, network, filesystem, subagent, and output policy.

The registry binds the same semantics root and exact ordered profile
identifiers and digests. A stable policy identifier cannot conceal a changed
semantic field. Model, effort, account, authentication, tier, and other route
fields remain forbidden from profiles.

## 6. Public environment completeness and ephemeral integrity

`PublicEnvironmentPolicyAuthorityV2` enumerates the complete managed
environment namespace for the host family. Every raw name must have exactly
one policy row; undeclared names, case-fold collisions, missing required
names, row omissions, projection omissions, presence drift, and secrecy/source
misclassification reject.

Each public projection row binds its policy row and authorities. Non-secret
values are public. Secret values are represented only by presence/absence
markers; raw values are never serialized in a durable record.

`EphemeralSecretProofV2` is an in-memory HMAC-SHA-256 capability. Its payload
uses a fixed domain and 64-bit length prefixes over:

1. the complete canonical V4 envelope, including its self-digest;
2. the complete canonical predecessor V3 envelope projection;
3. a 32-byte process nonce;
4. a 32-byte object nonce;
5. each policy-ordered secret name and UTF-8 raw value.

The key is 32 bytes and remains caller-owned ephemeral state. Historical V3
records cannot masquerade as V4. Copy, deep-copy, pickle/serialization, and
revealing representation are prohibited. `SpawnCapabilityV2` immutably binds
the same V4 envelope, V3 projection, consumed authority, attempt, and proof
object. Mutation or substitution after construction rejects.

## 7. Provider manifest, route, and time authority

Every route resolves through a typed provider manifest:

- exact dated model identifier, never `provider-default-*`, `auto-*`, or
  `latest-*`;
- model-family and effort/thinking capability row;
- closed account/auth/tier/transport/assurance tuple;
- explicit evaluation-time authority;
- capability validity interval where `from < until`, `evaluation >= from`,
  and `evaluation < until`;
- price and fallback authorities joined to the same manifest/model/time.

The closed authentication tuples are:

- stored subscription / Claude Code OAuth / subscription;
- API key / Anthropic API key / API standard.

Effort is either applicable with an allowed concrete level or not applicable
with no requested effort. A not-applicable capability uses the
`not_applicable` support sentinel. Manual thinking has a positive manual
budget only when `MANUAL_ON`; adaptive and manual-off modes require null.

These rules correct A10 and prevent plausible-looking aliases, tuple swaps,
malformed timestamps, inverted intervals, and expiry-boundary acceptance.

## 8. Resume V2 exact law

`ResumeIdentityVectorV2` contains 33 ordered identity axes, including all
R2.3 customization/effort/thinking identities. The validator recomputes the
changed-field set from the actual before and after vectors.

| Decision | Exact condition |
| --- | --- |
| `RETRY_SAME_GENERATION` | no identity change; same generation; attempt ordinal increments exactly once; no terminal evidence |
| `NEW_GENERATION` | one or more exactly enumerated identity changes; generation increments exactly once; attempt ordinal resets to zero; no terminal evidence |
| `NO_RELAUNCH_COMPLETED` | no identity change; same generation and attempt; exact PhaseIO incorporation evidence binds PhaseIO, attempt, observation, reconciliation, and output set |
| `AMBIGUOUS_CONSUMED_DEBT` | no identity change; same generation and attempt; exact ambiguity evidence binds envelope, consume, attempt, post-consumption ledger, and ambiguous spawn state |

Caller-authored changed sets or arbitrary lifecycle digests have no authority.
This is the executable correction for A7.

## 9. Observation and downstream evidence

Every observed model, effort, thinking state, fallback state, and terminal
category has exactly one typed field claim. Each claim binds:

- field name;
- digest of the observed value;
- proof rule;
- one or more raw artifact digests.

The evidence manifest binds the exact claim set and exact raw-artifact union.
The observation must reference each actual claim digest, and thinking evidence
must be a member of the thinking claim. An arbitrary self-consistent evidence
digest is not accepted.

Codex parity is computed by a neutral validator from actual before/after
artifact bytes and actual fixture receipts. The caller cannot supply the
compared digest truth. A downstream component may be `COMPLETE` only when its
row binds the exact independently accepted receipt and frozen postimage.
Neither record authorizes cutover. These rules correct A11 and A12.

## 10. A1-A12 R2.5 disposition

| Amendment | R2.5 author-conformance disposition |
| --- | --- |
| A1 axes orthogonality | Preserved from frozen R2.4's closed product and replayed |
| A2 route-neutral profiles | Closed by the immutable full-semantics root and exact registry |
| A3 tagged request | Closed with rooted R2.3 customization/effort/thinking identities |
| A4 deterministic compiler join | Closed by reusable constructed-operation validators; vector dispatch does not manufacture expected errors |
| A5 WorkPlan/PhaseIO cut | Closed by complete actual-parent validation |
| A6 compile/reserve/consume/spawn | Closed by complete V4/V3 proof and immutable spawn capability |
| A7 resume law | Closed by ResumeAuthorityV2 and typed terminal evidence |
| A8 privacy plus integrity | Closed by policy completeness and envelope-bound ephemeral proof |
| A9 independent identities | Closed by the routing root and 33-axis resume identity |
| A10 capability/price/fallback | Closed by manifest, tuple, evaluation-time, interval, and membership validation |
| A11 Codex unchanged | Remains unproven until neutral real-byte evidence exists; fabricated witness rejects |
| A12 delayed closure | COMPLETE requires independent receipt/postimage; cutover remains false |

This table is an author-conformance claim only. Independent review may block
any row.

## 11. Conformance denominator and anti-theater rule

The 96 R2.5 scenarios instantiate a valid closure, perform a concrete
operation or mutation, recompute affected record digests where appropriate,
and invoke a reusable validator also used on the positive closure. Scenario
dispatch is not permitted to directly raise its expected result.

Coverage consists of:

- 48 exact unexpected-accept classes from the independent R2.4 review;
- 48 author adversarial cases covering predecessor preservation, illegal
  effort/thinking combinations, successor joins, evidence membership,
  proof boundaries, policy completeness, profile roots, route membership,
  time boundaries, and multi-axis resume changes;
- frozen R2.3 186-vector execution;
- frozen R2.4 314-vector execution;
- positive closure, proof, spawn, all resume terminal forms, neutral parity,
  and downstream evidence checks.

The <PRIVATE_REGRESSION_TARGET> audit and any other motivating repository are not scored here.
This package is generic and contains no protocol name, protocol answer, or
finding-specific rule.

## 12. Implementation and cutover law

Production work may begin only after an independent reviewer accepts the exact
R2.5 guide, schema, vectors, validator, receipt, and amended plan bytes.

The required sequence is:

```text
R2.5 exact package -> independent R2.5 PASS
-> J4-0 frozen preimage/replay gate
-> J4-1 R2.3-preserving authority core
-> J4-2 exact profile/request/compiler seam
-> J4-3 policy-complete projection and envelope-bound proof
-> J4-4 full closure validator and transactional cut
-> J4-5 through J4-13 downstream sequence
```

Every implementation slice is fixture-first, preserves the accepted
denominators, has a rollback boundary, and is independently reviewed before
the next cut. No authored receipt, including the R2.5 receipt, can substitute
for independent acceptance.

## 13. Limits and non-claims

R2.5 does not prove:

- real Claude or Codex provider behavior;
- actual pricing or current model availability;
- recall or precision change on real audits;
- production integration correctness;
- downstream runtime, evaluator, BB, repair, packaging, CI, or cross-OS
  completion;
- authorization to merge, commit, push, install, change defaults, or run an
  audit.

It defines the authority and conformance contract those later stages must
implement and independently verify.

End of R2.5 engineering guide body.
