# Plamen Backend Model-Routing Engineering Guide R2

## Fresh Independent Review

Date: 2026-07-29

Verdict: BLOCK PENDING R2.1 SCHEMA REFINEMENT

Provider facts: PASS

Prior B1-B5 closure: PASS

Prior B6-B7 closure: PARTIAL

Architecture direction: PASS

Cutover authorization: NONE

The R2 guide correctly repairs the factual and policy defects in the original
recommendation. Its current model IDs, GPT-5.6 context/input/output limits,
Haiku effort treatment, Claude effort-precedence rules, Light-mode
false-safety rule, transition evidence, refusal handling, and resource-vector
direction are supported.

The guide is not yet safe to implement literally. Its normative schema topology
conflicts with the already-governing backend-neutral SemanticWorkPlan identity:
the route contains the semantic-plan digest while the migration plan also puts
the route back inside the semantic plan. It additionally puts attempt identity
inside an otherwise retry-stable route. Those are not editorial details. They
would make paired-arm identity, retry identity, generation repair, and digest
replay ambiguous.

This is a documentation/specification block, not a rejection of the routing
program. The required R2.1 changes are bounded and should be made before source
implementation begins.

No provider was invoked. No audit was launched. No guide or repository file was
edited. This review wrote only this verdict artifact.

## 1. Frozen review boundary

Reviewed guide:

- Path:
  `<LOCAL_USER_ROOT>\Downloads\Plamen_Backend_Model_Routing_Engineering_Guide_R2_2026-07-29.md`
- Author-provided SHA-256:
  `889d29fb5ceee4b986daa4cfabefe370be4068a434d0fc4d2e1693e108af860f`
- Independently observed SHA-256:
  `889D29FB5CEEE4B986DAA4CFABEFE370BE4068A434D0FC4D2E1693E108AF860F`
- Size:
  46,518 bytes
- Lines:
  1,123
- Encoding check:
  ASCII only, LF line endings

Governing inputs:

| Artifact | SHA-256 |
| --- | --- |
| Original routing recommendation | `4167D7976F2EA1735C68CC3EBF78CB0FEB4BF012F1DE86F0077A9A6E3E4B547E` |
| First independent routing review | `EDEE426E4BC885B0DE6AA3D595B1A8A8F5C683CF276D652C38A3FEADAB723015` |
| Claude/Codex backend parity blueprint | `5FE66E35CC46A8BDF078B1B24B49889FD559E14C3E508CDF340BA57322A3028D` |
| WorkerTransaction P0-AM design | `F63C4A602D75294B24C72709B59465381B3390C6C52C1D289E4624B9B8163C81` |
| Current `scripts/semantic_work_plan.py` | `D3A89ACCE8A7F0275112E964A1CD40A7D49E68474F02637A64CBF4C8AA10FF67` |

The current semantic-work-plan source explicitly assigns:

- backend-neutral work and grants to `SemanticWorkPlan`;
- backend/model/generation identity to `BackendArmExecutionIdentity`;
- exact attempt ordinal to `ExecutionAttemptIdentity`.

The backend-parity blueprint also requires one backend-neutral semantic roster
and plan, with backend/model fallback creating a new generation or debt.

## 2. Current official provider facts

### 2.1 OpenAI facts

PASS.

Official current documentation supports:

- `gpt-5.6-sol`, `gpt-5.6-terra`, and `gpt-5.6-luna`;
- the unsuffixed `gpt-5.6` alias currently resolving to Sol;
- GPT-5.6 effort values `none`, `low`, `medium`, `high`, `xhigh`, and `max`;
- user policy rejecting `max` and stopping at `xhigh`;
- for all three GPT-5.6 variants:
  - context window: 1,050,000 tokens;
  - maximum input: 922,000 tokens;
  - maximum output: 128,000 tokens;
- higher pricing for the complete request above 272K input;
- real-time cyber and biology safeguards that can block, refuse, or pause
  legitimate dual-use work;
- a response service tier that can differ from the requested tier.

The R2 guide correctly stores context window, maximum input, maximum output,
operational request ceiling, and pricing threshold separately.

Official sources:

- https://developers.openai.com/api/docs/guides/latest-model
- https://developers.openai.com/api/docs/models/gpt-5.6-sol
- https://developers.openai.com/api/docs/models/gpt-5.6-terra
- https://developers.openai.com/api/docs/models/gpt-5.6-luna
- https://developers.openai.com/api/reference/resources/responses/methods/create
- https://developers.openai.com/api/pricing

### 2.2 Anthropic facts

PASS.

Official current documentation supports:

- `claude-opus-5`, `claude-sonnet-5`, and
  `claude-haiku-4-5-20251001`;
- Fable 5 as the most capable widely released Anthropic model;
- Opus 5 as a reasonable lower-cost R3 candidate pending Plamen evaluation;
- Opus 5 and Sonnet 5 at 1M context and 128K maximum output;
- Haiku 4.5 at 200K context and 64K maximum output;
- the Models API exposing `max_input_tokens`, `max_tokens`, and capability
  information, with nullability handled by the client/API schema;
- no effort parameter on Haiku 4.5;
- `low`, `medium`, `high`, `xhigh`, and `max` on Opus 5 and Sonnet 5;
- organization effort caps silently clamping `stream-json` requests;
- `CLAUDE_CODE_EFFORT_LEVEL` taking precedence over other effort settings;
- unsupported requested effort falling to the highest supported level at or
  below it;
- distinct availability and content-classifier fallback behavior;
- Opus 5 cybersecurity fallback to Opus 4.8;
- Sonnet 5 refusal as a successful transport response with
  `stop_reason: "refusal"`;
- Opus 5 requiring Claude Code 2.1.219 or later;
- Opus 5 lacking Anthropic web fetch and Priority Tier.

The R2 guide is correct to distinguish requested effort from proven effective
effort and to treat unobservable effort as ineligible for strict paired
scoring.

Official sources:

- https://platform.claude.com/docs/en/about-claude/models/overview
- https://platform.claude.com/docs/en/about-claude/models/migration-guide
- https://code.claude.com/docs/en/model-config
- https://platform.claude.com/docs/en/api/models
- https://platform.claude.com/docs/en/about-claude/pricing

## 3. Prior B1-B7 disposition

| Prior block | R2 disposition | Review result |
| --- | --- | --- |
| B1 Haiku effort | Haiku is `not_applicable`; omit `--effort`; Sonnet-low is the explicit-effort alternative | PASS |
| B2 actual model/fallback | Ordered init/assistant/subagent/usage/notice evidence; mixed model cannot certify | PASS AS DESIGN |
| B3 effort precedence | Environment seal, organization cap, requested/supported/observed separation | PASS AS DESIGN |
| B4 context/input conflation | 1.05M context, 922K max input, 128K max output, operational ceiling separate | PASS |
| B5 Light terminal negative | R3 or visible unresolved state; objective risk is not severity-only | PASS |
| B6 route/receipt denominator | Most fields added, but ownership and digest topology remain contradictory | PARTIAL/BLOCK |
| B7 cost denominator | Resource vector added, but deterministic arithmetic and subset invariants remain incomplete | PARTIAL/BLOCK |

## 4. Blocking findings

### R2-BLOCK-01: Provider route contaminates the backend-neutral semantic plan

Impact: paired-arm identity failure, digest cycle, invalid comparison

Evidence:

- `ModelRouteV2` contains `semantic_plan_digest`.
- The implementation map says `semantic_work_plan.py` should bind
  `ModelRouteV2`, context budget, and budget authority.
- The migration table says `plamen.semantic-work-plan.v2` adds route, context,
  and budget digests.
- `BudgetAuthorityV1` itself contains provider and account mode.
- The governing current design says SemanticWorkPlan is backend-neutral while
  BackendArmExecutionIdentity owns backend/model/generation.

If the semantic plan contains the route digest and the route contains the
semantic-plan digest, construction is circular. If the cycle is avoided by
omitting one field from a digest without saying so, replay is ambiguous. If the
semantic plan is recomputed separately for Claude and Codex, the paired arms no
longer share one semantic denominator.

Required R2.1 ownership:

```text
SemanticWorkPlanV1/V2
  backend-neutral obligation, prompt, methodology, tools, outputs,
  semantic tier requirement, disposition authority, risk, and common grant
            |
            v
BackendArmExecutionIdentityV2
  semantic_plan_digest + provider-specific ModelRouteV2
  + ContextBudgetV2 + BudgetAuthorityV1 + generation
            |
            v
ExecutionAttemptIdentityV2
  backend_arm_digest + attempt_ordinal
            |
            v
ProviderExecutionObservationV2
```

Rules:

- The semantic plan must not contain provider, model, account mode, provider
  context limit, provider pricing, or route digest.
- `ModelRouteV2` may point one-way to `semantic_plan_digest`.
- Provider-specific context and budget records belong to the backend arm.
- A backend-neutral common resource grant may remain in SemanticWorkPlan, but
  provider-specific enforcement records reference it; they do not replace it.
- Claude and Codex arms for one paired work unit must share exactly one
  semantic-plan digest.

### R2-BLOCK-02: Attempt ordinal contradicts route stability

Impact: retries cannot preserve the route digest as required

Evidence:

- `ModelRouteV2` is described as one immutable route for one work unit.
- It includes `attempt_ordinal`.
- Checkpoint 4 requires retry to preserve the route digest.
- Current governing identity design assigns attempt ordinal to
  `ExecutionAttemptIdentity`, not to the semantic plan or backend route.

Attempt 2 necessarily has a different ordinal from attempt 1. If ordinal is in
the route digest, the route digest changes. If it is excluded from the digest,
the guide's exact-schema and mutation rules are false.

Required R2.1 correction:

- Remove `attempt_ordinal` and `attempt_id` from `ModelRouteV2`.
- Keep `generation` in the backend arm or route if a model change creates a
  new generation.
- Put the ordinal only in `ExecutionAttemptIdentityV2`.
- Define retry as same backend-arm and route digest, new attempt ordinal.
- Define model/account/transport/semantic-grant change as a new backend arm or
  generation, not a retry.

### R2-BLOCK-03: Normative schemas are not closed enough to implement

Impact: independently written validators can disagree while both claim R2
compliance

The guide says the schemas have exact key sets, closed enums, no floats, and
canonical digests. It does not yet define:

- the digest preimage and exclusion rule for each self-digest field;
- closed values for provider, transport, account mode, auth mode, observation
  capability, transition state, fallback outcome, terminal category, and
  effort-observation basis;
- legal N0 values for exact model, provider, transport, account, manifest,
  service, and observation fields;
- whether N0 uses `ModelRouteV2`, a separate `NativeRouteV2`, or explicit
  sentinels;
- equality constraints between duplicated
  `provider_supported_efforts[]` in the manifest, route, and observation;
- `effort_applicability` in `ProviderCapabilityManifestV2`, even though its
  rules assign Haiku `NOT_APPLICABLE`;
- whether `provider_max_output_tokens` and Models API fields may be null;
- the ordered normalization of model-usage rows and transition notices;
- the exact route-debt object emitted when a prelaunch route cannot be armed.

There is also a legacy contradiction. `ModelRouteV2.execution_profile` allows
`legacy_claude_v1`, while the migration rules say legacy continues to use its
existing schemas and must not be semantically reinterpreted. The new route
schema should be `semantic_v1` only. Legacy can receive an external observation
envelope that hashes old artifacts without becoming a V2 route.

Required R2.1 correction:

1. Publish machine-readable schemas or exact typed dataclasses with all enums
   and cross-field validation.
2. State that each digest is computed over the canonical object with only its
   own digest field omitted, unless a named envelope defines another scope.
3. Define N0 explicitly, preferably as a separate native route/arm rather than
   fake provider sentinels.
4. Remove legacy from ModelRouteV2 and keep the observation adapter external.
5. Require every duplicated capability value to equal the referenced manifest;
   otherwise emit `CAPABILITY_MISMATCH`.
6. Define a non-circular capability-canary chain. A canary receipt must bind the
   seed manifest it tested; a post-canary manifest may reference that receipt
   without the receipt claiming it tested its own future digest.

### R2-BLOCK-04: Thinking policy mixes capability with requested execution

Impact: unsupported combinations can fail at runtime or silently change the
reasoning contract

`thinking_policy` currently allows:

- `ADAPTIVE_ON`;
- `MANUAL_SUPPORTED`;
- `DISABLED_AUTHORIZED`;
- `NOT_APPLICABLE`.

`MANUAL_SUPPORTED` describes capability, not what the route requests. Haiku
4.5 supports manual extended thinking but effort does not apply, and manual
thinking is off by default. A certifying route must say whether manual thinking
is enabled and, if enabled, bind its token budget.

`DISABLED_AUTHORIZED` also needs a model/effort cross-field constraint.
Anthropic documents that Opus 5 with disabled thinking plus `xhigh` or `max`
returns HTTP 400. R2 forbids max but permits xhigh.

Required R2.1 correction:

- Split `thinking_capability` from `requested_thinking_mode`.
- Legal requested modes should express actual execution, for example
  `ADAPTIVE_ON`, `MANUAL_OFF`, `MANUAL_ON`, or `NOT_APPLICABLE`.
- `MANUAL_ON` must bind an exact manual-thinking token budget.
- Opus 5/Sonnet 5 xhigh requires `ADAPTIVE_ON`.
- Haiku carries `requested_effort=not_applicable` plus an explicit manual
  thinking state; do not infer the state from effort.
- Add cross-product fixtures for every exact model, effort, and thinking mode.

### R2-BLOCK-05: B7 arithmetic conflicts with the no-float rule

Impact: cost and attention comparisons are not deterministically replayable

The guide defines:

```text
candidate_to_legacy_ratio(metric)
  = candidate_aggregate(metric) / legacy_aggregate(metric)
```

It also prohibits floats. Most ratios are not integers. The guide defines
positive-over-zero but not zero-over-zero, rounding, precision, overflow, or
whether the scalar maximum compares rounded or exact values.

The budget also contains both:

- `output_grant_tokens_including_reasoning`; and
- `reasoning_reserve_tokens`.

It does not state whether the reasoning reserve is a subset of output grant or
an additional amount. That can double-count or under-reserve generation output.

Required R2.1 correction:

- Represent each ratio as reduced integer
  `{numerator, denominator, state}`, or as explicitly rounded basis points with
  a named rounding direction.
- Define `0/0` as `NO_LEGACY_OR_CANDIDATE_USE`, not as zero or one silently.
- Define positive/zero as `UNBOUNDED_REQUIRES_REVIEW`.
- Compare ratios by cross multiplication, not floats.
- State `reasoning_reserve_tokens <=
  output_grant_tokens_including_reasoning`; it is a subset, not additive.
- Reconcile visible output plus reasoning output to the one provider generation
  ceiling.
- Use integers for wall time and money, such as milliseconds and currency
  micros, or keep exact usage vectors separate from provider invoice data.

## 5. Required integration amendments

These are not independent reasons to reject the architecture, but they must
join the R2.1 fixtures.

### 5.1 Preserve driver-only child authority

Codex CLI 0.145.0 supports stable multi-agent behavior. The governing parity
plan requires `DRIVER_ONLY_NO_MODEL_CHILDREN` for `semantic_v1`.

The R2 command example binds model and effort but does not restate the child
policy. `tool_policy_digest` alone is not proof that the provider process
cannot spawn model-owned audit children.

Add production-path fixtures proving:

- Claude and Codex semantic launches deny model-owned child creation;
- every planned additional agent is a separate driver-owned WorkUnit and
  WorkerTransaction;
- no provider default, imported config, skill, or role re-enables nested audit
  agents;
- any observed subagent model event is route debt in a profile that forbids
  children.

### 5.2 Treat safeguard pauses as observable provider state

OpenAI documents that GPT-5.6 safeguards can pause generation for several
seconds while classifiers review output. A timeout during such a pause must be
provider/route debt, not a negative result.

Add:

- a safety-review-pause observation when the transport exposes one;
- bounded timeout grace as transport policy, not semantic budget expansion;
- a fixture proving a pause, timeout, or buffered refusal cannot become
  completed-safe evidence.

### 5.3 Refusal rules apply to every route

The guide explicitly names Sonnet and Opus. Haiku 4.5 documentation also
requires refusal handling. State the invariant provider-wide:

- every Claude model and every GPT-5.6 route treats structured refusal as
  adverse;
- R1 has no negative authority, but refusal still means incomplete/debt rather
  than a successful projection.

### 5.4 Resolve effective-effort evidence feasibility before full build

The guide correctly excludes an arm when effective effort is unobservable. It
does not define which evidence bases can prove effective effort for each
current transport.

Before implementing the full phase matrix:

1. Define a closed `effective_effort_observation_basis` enum.
2. Use offline stream fixtures for every claimed basis.
3. Run only the later governed provider canary to determine which basis the
   installed account/CLI transport actually exposes.
4. If neither Claude nor Codex can prove effective effort per attempt, retain
   the route as experimental and do not weaken the strict gate merely to make
   the A/B executable.

This is a feasibility gate, not permission for a live provider call during this
review.

## 6. Corrected implementation order

The safe order is:

1. Publish R2.1 with the one-way ownership graph and exact schemas.
2. Freeze legacy artifacts and the current backend-neutral semantic-plan
   schema.
3. Add pure schemas and red fixtures without changing launch behavior.
4. Add provider capability manifests and route dry-run.
5. Attach provider routes to BackendArmExecutionIdentity, not SemanticWorkPlan.
6. Attach attempt ordinal only to ExecutionAttemptIdentity.
7. Add context and budget arithmetic with exact integer reconciliation.
8. Add Claude environment, effort, model-sequence, transition, and refusal
   observation.
9. Add Codex exact route, service-tier, safeguard, and no-fallback observation.
10. Propagate route/arm/attempt/observation digests through WorkerTransaction,
    PhaseIO, resume, repair, RunBundle, and the neutral evaluator.
11. Prove driver-only child policy and N0 no-provider behavior across OS paths.
12. Shadow only, then governed canaries, then held-out paired evaluation.
13. Keep `legacy_claude_v1` as default until independent non-inferiority clears
    each backend separately.

## 7. Cutover and recall verdict

The R2 guide makes no unsupported recall promise and correctly refuses cutover
authorization. That remains the right position.

Once the schema blockers are corrected, the program is worth implementing and
testing because it directly targets:

- false-safe decisions made by underpowered or ambiguous routes;
- non-application hidden by phase-wide model choice;
- silent model and effort drift;
- fallback/refusal ambiguity;
- found-then-lost boundaries;
- uncontrolled frontier spend.

It does not establish that Opus 5, Sonnet 5, Sol, Terra, or Luna improve recall
on Plamen workloads. Only the neutral held-out evaluation can do that.

The R2.1 documentation correction should not trigger provider calls, audits,
or production cutover. It is a prerequisite for implementation, not a release
decision.

## 8. Final disposition

R2 closes the substantive intent of B1-B5 and most of B6-B7. It is markedly
better than the original recommendation. The model placement, Light behavior,
fallback/refusal policy, and held-out release gates should be retained.

Overall status:

```text
provider facts: PASS
B1-B5: PASS
B6-B7: PARTIAL
normative implementation topology: BLOCK
legacy_claude_v1: production default
semantic_v1 model routing: experimental/not implemented
cutover: not authorized
```

Required next artifact:

`Plamen_Backend_Model_Routing_Engineering_Guide_R2.1_2026-07-29.md`

R2.1 may be accepted when it:

- keeps SemanticWorkPlan backend-neutral;
- moves provider route/context/budget to BackendArmExecutionIdentity;
- moves attempt ordinal to ExecutionAttemptIdentity;
- publishes closed schemas, digest scopes, N0 representation, and capability
  equality rules;
- makes thinking execution state and model/effort combinations exact;
- makes cost arithmetic integer and replayable;
- adds child-policy, safeguard-pause, all-model refusal, and effort-evidence
  fixtures;
- preserves every existing held-out and legacy cutover gate.

End of review.
