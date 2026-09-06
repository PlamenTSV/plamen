# Plamen Backend Model-Routing Engineering Guide R2.1

## Fresh Independent Review

Date: 2026-07-29

Verdict: BLOCK PENDING R2.2 NORMATIVE REFINEMENT

Architecture direction: PASS

Provider facts: PASS

Original B1-B7 closure: PARTIAL

Cutover authorization: NONE

R2.1 makes the central architecture correction required by the R2 review. It
keeps `SemanticWorkPlan` backend-neutral, places provider route/context/budget
under a backend arm, and places attempt ordinal only under attempt identity.
It also isolates N0 and legacy, separates thinking capability from request
state, defines exact 0/0 arithmetic, treats reasoning as a subset of output,
and carries the required child, safeguard, refusal, Light-mode, and held-out
cutover rules.

It is not yet safe to implement literally. Seven remaining specification
defects can create different digests across runtimes, silent effort drift,
invalid retry identity, grant renewal across generations, or incomparable
resource receipts. These are narrower than the R2 topology block, but they are
not editorial because they sit on certifying identity and resource-authority
paths.

This review did not edit the guide, repository, configuration, or provider
state. It did not call a model provider or launch an audit. It wrote only this
independent review artifact.

## 1. Frozen review boundary

Reviewed guide:

- Path:
  `<LOCAL_USER_ROOT>\Downloads\Plamen_Backend_Model_Routing_Engineering_Guide_R2.1_2026-07-29.md`
- Author-provided SHA-256:
  `f5dd8c48ff6e4951526425a4685905c313085ebf959f79d8d9bab4391bb13894`
- Independently observed SHA-256:
  `F5DD8C48FF6E4951526425A4685905C313085EBF959F79D8D9BAB4391BB13894`
- Size:
  71,399 bytes
- Lines:
  2,043
- Encoding:
  ASCII only, LF only

Controlling prior review:

- Path:
  `<LOCAL_USER_ROOT>\Downloads\Plamen_Backend_Model_Routing_Engineering_Guide_R2_Independent_Review_2026-07-29.md`
- SHA-256:
  `21CEC836FE9BAB7821EADAB7789620CB32C3D6BD3AD67B54529DF86D55E9E6AF`

Governing identity inputs:

| Artifact | SHA-256 |
| --- | --- |
| Claude/Codex backend parity blueprint | `5FE66E35CC46A8BDF078B1B24B49889FD559E14C3E508CDF340BA57322A3028D` |
| WorkerTransaction P0-AM design | `F63C4A602D75294B24C72709B59465381B3390C6C52C1D289E4624B9B8163C81` |
| Current `scripts/semantic_work_plan.py` | `D3A89ACCE8A7F0275112E964A1CD40A7D49E68474F02637A64CBF4C8AA10FF67` |

The current source still explicitly assigns backend-neutral work/grants to
`SemanticWorkPlan`, backend/model/generation to
`BackendArmExecutionIdentity`, and attempt ordinal to
`ExecutionAttemptIdentity`. R2.1 now agrees with that ownership split.

## 2. Current provider and standards facts

### 2.1 OpenAI

PASS.

Official current documentation continues to support the R2.1 facts:

- exact IDs `gpt-5.6-sol`, `gpt-5.6-terra`, and `gpt-5.6-luna`;
- the unsuffixed `gpt-5.6` alias routes to Sol and therefore is unsuitable as
  a certifying exact route;
- all three current model pages publish a 1,050,000-token context window,
  922,000 maximum input, and 128,000 maximum output;
- the greater-than-272K boundary is a pricing threshold;
- GPT-5.6 supports `none`, `low`, `medium`, `high`, `xhigh`, and `max`,
  while Plamen policy may correctly stop at `xhigh`;
- safeguards can pause, block, or refuse legitimate dual-use work;
- requested and observed service tiers can differ.

Official sources:

- https://developers.openai.com/api/docs/guides/latest-model
- https://developers.openai.com/api/docs/models/gpt-5.6-sol
- https://developers.openai.com/api/docs/models/gpt-5.6-terra
- https://developers.openai.com/api/docs/models/gpt-5.6-luna
- https://developers.openai.com/api/reference/resources/responses/methods/create
- https://developers.openai.com/api/pricing

### 2.2 Anthropic

PASS, with one integration consequence not closed by R2.1.

Official current documentation supports:

- exact API IDs `claude-opus-5`, `claude-sonnet-5`, and
  `claude-haiku-4-5-20251001`;
- Fable 5 as Anthropic's most capable widely released model;
- Opus 5 and Sonnet 5 at 1M context and 128K maximum output;
- Haiku 4.5 at 200K context and 64K maximum output;
- `low`, `medium`, `high`, `xhigh`, and `max` on Opus 5 and Sonnet 5;
- effort not applying to Haiku 4.5, while Haiku supports manual extended
  thinking;
- adaptive thinking on Opus 5/Sonnet 5 and the Opus 5 400 response when
  disabled thinking is combined with `xhigh` or `max`;
- silent organization effort clamping in JSON/stream-JSON modes;
- Opus 5 cyber classifier fallback to Opus 4.8 and successful-transport
  structured refusal;
- Models API maximum-input, maximum-output, and capability fields, including
  nullable SDK representations.

The current Claude Code documentation also says that skill/subagent
frontmatter effort overrides session effort, while
`CLAUDE_CODE_EFFORT_LEVEL` outranks those sources. That fact creates the
remaining B3 block in Section 5.2.

Official sources:

- https://platform.claude.com/docs/en/about-claude/models/overview
- https://platform.claude.com/docs/en/about-claude/models/migration-guide
- https://platform.claude.com/docs/en/build-with-claude/effort
- https://platform.claude.com/docs/en/about-claude/models/extended-thinking-models
- https://code.claude.com/docs/en/model-config
- https://platform.claude.com/docs/en/api/models/list
- https://platform.claude.com/docs/en/about-claude/pricing

### 2.3 Canonical JSON

R2.1's use of RFC 8785 is directionally sound, but its 63-bit JSON number
range is not an interoperable exact-number profile.

RFC 8785 builds on I-JSON and ECMAScript number serialization. RFC 7493 says a
receiver cannot be expected to treat an integer outside
`[-(2^53)+1, (2^53)-1]` exactly and recommends strings for larger exact
integers. R2.1 permits unsigned values through `2^63-1`.

Primary sources:

- https://www.rfc-editor.org/rfc/rfc8785.html
- https://www.rfc-editor.org/rfc/rfc7493.html

## 3. Original B1-B7 disposition

| Prior block | R2.1 result | Independent result |
| --- | --- | --- |
| B1 Haiku effort | `not_applicable`, exact manual thinking state | PASS |
| B2 actual model/fallback | ordered model/usage/transition evidence and strict exclusion | PASS AS DESIGN |
| B3 effort precedence | environment and organization handling | PARTIAL/BLOCK |
| B4 context/input conflation | context, max input, max output, request ceiling, and price threshold separated | PASS |
| B5 Light terminal negative | material/unknown material stays unresolved without R3 | PASS |
| B6 route/receipt denominator | one-way topology and most schemas corrected | PARTIAL/BLOCK |
| B7 cost denominator | exact ratio cases and reasoning subset corrected | PARTIAL/BLOCK |

The change from the prior B3 PASS is evidence-driven, not stylistic. The
current official Claude Code precedence documentation exposes a skill
frontmatter override path that R2.1's launch rules do not bind or forbid.

## 4. Material corrections accepted

R2.1 correctly closes the following R2 blockers:

1. `SemanticWorkPlanV2` has no provider/model/route/context/provider-budget,
   generation, attempt, service, or provider environment fields.
2. Claude and Codex arms share the same semantic-plan bytes and digest.
3. The graph is one-way:

```text
SemanticWorkPlan
  -> BackendArmExecutionIdentity
  -> ExecutionAttemptIdentity
  -> ProviderExecutionObservation
```

4. Route/context/budget are provider-arm records, not semantic-plan members.
5. Attempt ordinal appears only in `ExecutionAttemptIdentityV2`.
6. N0 is a separate native union member with no fake provider sentinels.
7. Legacy remains outside V2 route and semantic types.
8. Own-digest exclusion, exact field sets, closed enums, set/ordered arrays,
   and the seed/canary direction are substantially specified.
9. Capability and requested thinking state are separated.
10. 0/0, positive/zero, exact cross multiplication, overflow debt, and the
    reasoning-output subset are specified.
11. Child spawning, safeguards, refusal, Light-mode uncertainty, and held-out
    cutover rules are retained.

These changes are sufficient to pass the architecture direction. They are not
sufficient to pass the guide as an executable specification.

## 5. Blocking findings

### R2.1-BLOCK-01: The JCS profile permits non-interoperable exact integers

Impact: cross-runtime digest divergence or rounded resource authority

Evidence:

- Section 4.1 permits JSON integers from zero through
  9,223,372,036,854,775,807.
- Section 4.2 applies RFC 8785/ECMAScript canonical number serialization.
- The guide requires cross-OS and independently replayable identity.
- RFC 7493 does not guarantee exact interchange above
  9,007,199,254,740,991.

Python can preserve a 63-bit integer internally while a JavaScript/RFC-8785
implementation can round it through IEEE-754. Two conforming-looking
implementations could hash different semantic values or accept a value that
cannot round-trip exactly.

There is a second canonicalization contradiction:

- Section 4.2 says to normalize all strings to NFC.
- Checkpoint 1 says a non-NFC identity must fail closed.
- RFC 8785 says canonicalization itself does not alter parsed Unicode strings.

Required correction:

1. Limit JSON numeric identity/resource fields to
   `0..9,007,199,254,740,991`, or encode every wider exact integer as a
   canonical decimal string with a closed grammar and no leading zeros.
2. Keep checked 128-bit sums and cross-products internal; serialize only a
   validated safe integer or canonical decimal string.
3. Reject non-NFC identity strings before canonicalization.
4. For explicitly declared free-text fields, normalize before record
   validation and then do not mutate the validated record during JCS.
5. Define set-element ordering in exact code-unit or byte terms and add
   Python/JavaScript/.NET golden vectors, not only OS fixtures.

This is both B6 identity and B7 arithmetic authority.

### R2.1-BLOCK-02: Claude effort precedence still has an unsealed override path

Impact: a route can request one effort while a loaded skill executes another

Evidence:

- R2.1 Section 9.2 removes or fails on `CLAUDE_CODE_EFFORT_LEVEL` and passes
  the requested `--effort`.
- Its config/skill/role sanitization rule is scoped to preventing child-agent
  re-enablement.
- Its effort fixture checks that an environment override is absent and that a
  late environment override aborts.
- Current Claude Code documentation says skill and subagent frontmatter can
  override session effort, below the environment variable but above the
  ordinary session level.

Removing the highest-precedence environment authority while permitting skills
can therefore expose a lower-precedence override. The strict observed-effort
gate catches this only when effective effort is observable; it does not make
the expected launch identity correct.

Required correction:

Choose and specify one exact strategy:

1. set `CLAUDE_CODE_EFFORT_LEVEL` to the exact route effort in the fresh
   allowlisted environment and bind it as intentional authority, while also
   passing an equal CLI value; or
2. prove that every loaded skill, role, subagent definition, settings layer,
   and control request lacks an effort override.

In either case:

- define a closed precedence-source registry, not only environment keys;
- bind every loaded customization digest to the route/launch authority;
- make disagreement prelaunch debt;
- keep organization clamping as runtime effective-effort debt;
- add production-path fixtures for skill frontmatter, settings, control
  requests, environment, and organization cap.

This reopens only B3. The requested-versus-observed separation itself remains
sound.

### R2.1-BLOCK-03: The thinking cross-product is not actually closed

Impact: an implementation can map the same route state to different provider
arguments

Evidence:

- Section 6.3 calls its table a closed cross-product.
- The Opus/Sonnet low/medium/high cell permits `ADAPTIVE_ON` or "an explicitly
  supported non-adaptive mode proven by canary."
- The closed requested-mode enum contains no `DISABLED` value.
- `MANUAL_OFF` says no provider flag may be emitted. On Opus 5/Sonnet 5,
  omission defaults to adaptive thinking, so it cannot represent disabled
  execution.
- `observed_thinking_mode` is not assigned its own closed observation enum or
  exact mapping from transport events.

Required correction:

- For V2, make every Opus 5/Sonnet 5 route use `ADAPTIVE_ON` at all allowed
  efforts. This matches the proposed Plamen routing table.
- Reserve `MANUAL_OFF` and `MANUAL_ON` for Haiku 4.5.
- If disabled Opus/Sonnet thinking is genuinely needed later, introduce an
  explicit `DISABLED` request value, exact provider argument mapping, allowed
  effort cross-product, observation rule, and canary evidence in a new
  registry/schema revision.
- Define the closed observed-thinking states and eligibility mapping.

The capability/request split passes. Its supposedly exact current
cross-product does not.

### R2.1-BLOCK-04: Two policy rows still change effort inside an attempt

Impact: retry identity can violate its immutable route

Evidence:

- Section 3.5 correctly says a retry cannot change effort or thinking.
- Section 8.2 says typed `xhigh` "may require a new attempt."
- Checkpoint 4 says an operational transition closes N and restarts as N+1,
  without saying whether N is an attempt or generation.
- The governing blueprint requires model/effort/fallback changes to produce a
  new backend-arm generation or debt.

An R3-high attempt cannot become xhigh in attempt 2 while preserving the route
digest. A model transition cannot restart as a retry of the transitioned
route.

Required correction:

- Replace both `xhigh may require a new attempt` rows with:
  `xhigh requires a new backend arm/generation with the same semantic plan`.
- State that transition N and N+1 are backend-arm generations, not attempt
  ordinals.
- Reset attempt ordinal within the new arm and never merge certifying evidence
  across generations.
- Add fixtures showing that changed effort/model cannot parse as a retry.

### R2.1-BLOCK-05: The common grant can be renewed once per generation

Impact: fallback or escalation can multiply the supposedly fixed resource
authority

Evidence:

- Section 3.3 says every common-grant limit is cumulative across all of one
  backend's generations and retries.
- Section 6.5 says one `BudgetAuthorityV1` is cumulative only across one
  backend-arm generation and its retries.
- Each generation's local invariant merely requires its limits to be no
  greater than the common grant.
- No exact cross-generation reservation/reconciliation record or atomic
  update is defined.

Generation 1 and generation 2 can therefore each reserve the full common
grant while both individually validate. The held-out aggregate can detect
overspend after execution, but post-hoc scoring is not resource authorization.
Different provider tokenizers also prevent safely enforcing a provider-neutral
byte grant by simply summing token grants.

Required correction:

Add an exact backend-semantic resource ledger keyed by:

```text
semantic_plan_digest + provider arm family
```

It must:

- reserve and reconcile every generation and unique attempt atomically;
- enforce the common byte/turn/retry/wall/tool/driver-work-unit ceilings across
  all generations;
- retain generation-local provider token budgets;
- record the exact byte-to-token derivation for each model/tokenizer;
- prevent a fallback or xhigh escalation from receiving a fresh common grant;
- emit typed debt only for the affected arm when the cumulative grant is
  unavailable;
- survive interruption, resume, and repair with CAS/idempotency fixtures.

This is a B7 authorization block, not a reason to halt the whole pipeline.

### R2.1-BLOCK-06: One ratio type has two incompatible denominators

Impact: budget compliance and candidate-versus-legacy cost can be confused

Evidence:

- Section 6.6 defines every `ExactRatioV1` as candidate divided by legacy.
- Section 6.8 places `metric_ratios[]` inside a per-attempt
  `BudgetReconciliationV1` that joins provider usage and budget authority.
- That record has no legacy usage-observation digest.
- The same record also produces `WITHIN_GRANT` or `EXCEEDED_GRANT`, which needs
  observed divided by authorized grant, not candidate divided by legacy.
- `ExactRatioV1` has no `ratio_kind` or named numerator/denominator authority.

An implementation cannot tell whether `3/2` means observed/grant,
candidate-reserved/legacy-reserved, or candidate-observed/legacy-observed.

The plan target is also under-specified:

- `BudgetAuthorityV1` has one
  `historical_plan_usage_target_basis_points` field.
- The text defines a 1,000-1,500 basis-point range per Thorough audit.
- A per-arm scalar cannot represent that run-level interval.

Required correction:

1. Use separate exact schemas:
   - `ObservedToGrantRatioV1` in attempt/arm reconciliation; and
   - `PairResourceComparisonV1` in the neutral evaluator.
2. Each ratio must name numerator authority, denominator authority, metric,
   aggregation scope, and exact 0/0 state.
3. The paired observed comparison must bind both candidate and legacy usage
   receipt digests.
4. Move the historical subscription target to a run-level evaluation policy
   with explicit lower and upper basis points.
5. Define null coupling for currency code/amount and prohibit comparison
   across currencies or pricing snapshots.

The arithmetic algorithm passes. The ownership and semantic denominator do
not.

### R2.1-BLOCK-07: A PASS canary does not bind enough of what it tested

Impact: a post-canary manifest can overclaim strict capability

Evidence:

- Section 6.1 says the canary receipt records exactly what it tested.
- Its exact receipt has only an opaque `canary_plan_digest`,
  `exact_requested_model_id`, and category-level evidence digests.
- It does not directly bind requested effort, thinking mode, service tier,
  fallback policies, child policy, negative test cases, or a field-level
  capability-claim set.
- No exact `CanaryPlanV1` schema is defined.
- The post-canary construction does not require all non-link fields to equal
  the seed or bind each permitted change to evidence.

A `PASS` result cannot by itself prove which manifest fields are strict. Two
implementations can promote different capability claims from the same receipt.

Required correction:

- Define an exact `CanaryPlanV1` schema and digest.
- Bind every requested model/effort/thinking/service/fallback/child/safety/
  refusal case.
- Add a closed `proven_manifest_fields[]` or typed claim records, each with its
  evidence digest and result.
- Require post-canary fields to equal the seed except for explicitly
  evidence-authorized changes.
- Make `PASS` field-scoped; a globally successful canary must not promote an
  untested capability.
- Add mutation fixtures proving that no new capability appears between seed
  and post-canary manifest without named evidence.

This is the remaining material B6 capability-denominator block.

## 6. Required precision amendments

The following should be fixed in the same R2.2 edit. They do not independently
change the verdict, but leaving them ambiguous would create avoidable
implementation divergence:

1. Section 6.2 says `route_id` uses a predeclared arm ID string, while the
   actual formula uses semantic-plan ID, provider, and generation. Keep the
   formula and remove the incorrect arm-ID sentence.
2. Section 11 says backend-arm identity owns a launch digest, but the exact arm
   schema has no launch digest. Either add an exact `LaunchAuthorityV1` digest
   or say route plus manifest plus environment authority is the complete
   launch authority.
3. Define the attempt-specific launch envelope mentioned in Section 3.5, or
   remove it from the normative graph.
4. Define the schema behind `native_budget_digest`; a dangling digest name is
   not an exact N0 budget authority.
5. Define deterministic `route_debt_id` construction.
6. Specify `currency_code`/`currency_micros` both-null-or-both-present rules.
7. Add the official Anthropic effort/thinking pages and RFC 8785/RFC 7493 to
   the guide's source list.

## 7. Disposition and safe next step

R2.1 should not be discarded. It resolves the largest architecture mistake in
R2 and is close to an implementable model-routing program. The remaining work
is a bounded R2.2 specification amendment, not a return to phase-wide model
hard-coding.

Safe sequence:

1. Publish R2.2 closing Blocks 01-07 and the precision amendments.
2. Obtain a fresh independent schema review.
3. Freeze current source and legacy hashes.
4. Implement pure records, validators, canonical golden vectors, and failing
   production-path fixtures first.
5. Keep all launch behavior on `legacy_claude_v1`.
6. Add dry-run/shadow routing only after schema fixtures pass.
7. Run governed provider canaries only at the guide's later authorized gate.
8. Run neutral held-out evaluation before any default change.

No motivating audit, provider capability page, canary, or same-repository
regression proves recall improvement. The architecture is worth building
because it can make route non-application and false-safe authority observable;
only held-out evaluation can show whether the selected models improve recall.

Final status:

```text
provider facts: PASS
B1: PASS
B2: PASS AS DESIGN
B3: PARTIAL/BLOCK
B4: PASS
B5: PASS
B6: PARTIAL/BLOCK
B7: PARTIAL/BLOCK
architecture direction: PASS
R2.1 executable specification: BLOCK
legacy_claude_v1: production default
semantic_v1 routing: experimental/not implemented
provider calls or audits authorized: none
cutover authorized: no
```

End of review.
