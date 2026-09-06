# Plamen backend model-routing engineering guide R2

Date: 2026-07-29

Status: corrected implementation specification; not a cutover authorization

Change boundary: documentation only. This guide does not change Plamen source,
provider configuration, audit repositories, or provider state, and it does not
authorize a live audit.

## 0. Governing inputs and review boundary

This R2 guide supersedes the executable parts of the original recommendation:

- `Plamen_Backend_Model_Routing_Recommendation_2026-07-29.md`
- SHA-256:
  `4167d7976f2ea1735c68cc3ebf78cb0feb4bf012f1de86f0077a9a6e3e4b547e`

It incorporates every blocking correction in:

- `Plamen_Backend_Model_Routing_Independent_Review_Verdict_2026-07-29.md`
- SHA-256:
  `edee426e4bc885b0de6aa3d595b1a8a8f5c683cf276d652c38a3feadab723015`

The independent verdict is controlling where it conflicts with the original
recommendation. The original recommendation remains useful for its code survey,
phase placement, and staged evaluation design.

The source tree inspected by the independent review was a dirty shared tree
bound to file hashes, not merely to Git HEAD. Implementers must re-freeze their
own starting denominator before editing. File and line references in the two
governing inputs are therefore navigation aids, not current-state proof.

## 1. Final engineering verdict

The architectural direction is worth implementing behind `semantic_v1`:

1. Resolve semantic authority and risk per work unit.
2. Map that typed requirement to one exact provider route.
3. Seal model, effort, transport, environment, feature, context, and resource
   authorities before launch.
4. Observe the actual route after launch.
5. Treat fallback, refusal, unobservable effort, and route drift as execution
   debt, never as negative security evidence.
6. Preserve `legacy_claude_v1` unchanged as the production default and control
   arm until a neutral held-out evaluation clears cutover.

This directly addresses route underpowering at false-safe boundaries and makes
model/effort non-application observable. It does not prove that any new model
improves Plamen recall. Only held-out, ground-truth-blinded evaluation can prove
that outcome.

R2 is safe to use as an implementation guide only with all of these invariants:

- `max`, `ultracode`, provider-default effort, unknown effort, and any setting
  above the user-approved `xhigh` ceiling are rejected.
- Unknown model IDs, aliases, account modes, service tiers, features, or
  capability states never fall through to a cheaper/default route.
- No model transition is allowed inside one certifying semantic attempt.
- No refusal, classifier action, blocked fallback, actual-model ambiguity, or
  required-effort ambiguity may support `SAFE`, `REFUTED`, `DISMISSED`, or an
  equivalent terminal negative.
- Light mode cannot close a material R3-class candidate negatively with R2.
- Resource authorization is based on frozen token/time/turn/retry grants and
  observed plan use, not on the count of `xhigh` work units.
- New routing remains experimental until each backend independently clears a
  held-out non-inferiority gate.

## 2. Current provider facts used by R2

These are dated capability inputs, not eternal assumptions. A versioned
capability manifest and provider canary must re-observe them before launch.

### 2.1 OpenAI

Current official OpenAI documentation identifies:

- `gpt-5.6-sol` as the frontier GPT-5.6 tier;
- `gpt-5.6-terra` as the intelligence/cost balance;
- `gpt-5.6-luna` as the cost-sensitive high-volume tier;
- the unsuffixed `gpt-5.6` alias as routing to Sol;
- supported GPT-5.6 effort values including `none`, `low`, `medium`, `high`,
  `xhigh`, and `max`.

Plamen must use exact Sol/Terra/Luna IDs. It must reject `max` despite provider
support because the user-approved ceiling is `xhigh`.

The current model pages separately publish, for all three tiers:

- `context_window_tokens = 1050000`;
- `provider_max_input_tokens = 922000`;
- `provider_max_output_tokens = 128000`.

This corrects both the original guide and B4. The 1,050,000 number is a context
window, not a maximum-input synonym. OpenAI now also publishes a distinct
922,000 maximum input. Plamen must retain all three fields and still derive a
smaller operational source/prompt budget.

OpenAI also documents that prompts above 272,000 input tokens receive higher
pricing for the whole request. That is a pricing threshold, not a context
limit. The threshold belongs in the cost authority, not in the capability
field.

OpenAI's API reference states that the observed response service tier can
differ from the requested tier. Requested and observed service tier must be
separate receipt fields.

OpenAI documents real-time cyber and biology safeguards for GPT-5.6 that may
block or refuse legitimate dual-use work. Codex routes therefore require the
same refusal-safe negative-disposition rule as Claude routes.

Sources:

- [Using GPT-5.6](https://developers.openai.com/api/docs/guides/latest-model)
- [GPT-5.6 Sol](https://developers.openai.com/api/docs/models/gpt-5.6-sol)
- [GPT-5.6 Terra](https://developers.openai.com/api/docs/models/gpt-5.6-terra)
- [GPT-5.6 Luna](https://developers.openai.com/api/docs/models/gpt-5.6-luna)
- [OpenAI API pricing](https://developers.openai.com/api/pricing)
- [OpenAI Responses API reference](https://developers.openai.com/api/reference/resources/responses/methods/create)

### 2.2 Anthropic

Current official Anthropic documentation identifies:

- `claude-opus-5` for complex agentic coding and enterprise work;
- `claude-sonnet-5` for a speed/intelligence balance;
- `claude-haiku-4-5-20251001` for the fastest near-frontier tier;
- `claude-fable-5` as Anthropic's most capable widely released model.

R2 retains Opus 5 as the candidate R3 default. Fable 5 is not the default
because it has materially higher public API pricing and no Plamen-specific
held-out evidence. It may be evaluated later as a separate opt-in canary arm.
That is a cost/evidence choice, not a claim that Opus 5 is Anthropic's highest
capability model.

Anthropic currently publishes:

- Opus 5: 1M context, 128K maximum output;
- Sonnet 5: 1M context, 128K maximum output;
- Haiku 4.5: 200K context, 64K maximum output.

The Models API can report `max_input_tokens` and `max_tokens`. Runtime
preflight should bind those observed fields. Static policy must not derive a
Claude maximum input merely by relabeling the context window.

Anthropic explicitly states that effort is not available on Haiku 4.5. Opus 5
and Sonnet 5 support `low`, `medium`, `high`, `xhigh`, and `max`; Plamen still
rejects `max`.

Claude Code documents two distinct fallback mechanisms:

1. Availability fallback chains switch for the current turn.
2. Content-classifier fallback can re-run an Opus 5 cybersecurity-classified
   request on Opus 4.8 and then continue the session on Opus 4.8.

Claude Code also documents that:

- `CLAUDE_CODE_EFFORT_LEVEL` can override session effort;
- an organization can cap available effort, and Claude Code can use the
  highest supported level at or below the requested level;
- Sonnet 5 cybersecurity refusals can arrive in a successful HTTP response
  with `stop_reason: "refusal"`;
- Opus 5 requires Claude Code 2.1.219 or later;
- Opus 5 lacks Anthropic web fetch and Priority Tier.

Sources:

- [Claude models overview](https://platform.claude.com/docs/en/about-claude/models/overview)
- [Claude model migration guide](https://platform.claude.com/docs/en/about-claude/models/migration-guide)
- [Claude Code model configuration](https://code.claude.com/docs/en/model-config)
- [Claude Models API](https://platform.claude.com/docs/en/api/models/list)
- [Claude pricing](https://platform.claude.com/docs/en/about-claude/pricing)

## 3. Corrected semantic route policy

The tiers are Plamen authority classes. They do not claim provider capability
equivalence.

| Authority class | Claude candidate | Codex candidate | Requested effort |
| --- | --- | --- | --- |
| `R3_FRONTIER_REASONING` | `claude-opus-5` | `gpt-5.6-sol` | `high`; typed `xhigh` only |
| `R2_STANDARD_REASONING` | `claude-sonnet-5` | `gpt-5.6-terra` | `medium` or `high` |
| `R1_ECONOMY_STRUCTURED` | `claude-haiku-4-5-20251001` | `gpt-5.6-luna` | Claude `not_applicable`; Codex `low` |
| `N0_NATIVE_DETERMINISTIC` | no model | no model | `not_applicable` |

Claude R1 has two legal forms:

1. Haiku 4.5 with `requested_effort = not_applicable` and no `--effort`
   argument; or
2. Sonnet 5 with `requested_effort = low` when an explicit low-effort
   reasoning contract is semantically required.

The route compiler must not normalize Haiku `low` into an apparently accepted
route. It must reject that pair and require the planner to select one of the
two legal forms.

### 3.1 Mode policy

| Mode | Discovery/provisional work | Material terminal-negative work | Frontier effort |
| --- | --- | --- | --- |
| Light | R2 `medium`; R2 `high` where typed risk warrants | R3 required, or retain `UNRESOLVED_NEEDS_R3_REVIEW` | No planned R3 except when terminal closure is explicitly required |
| Core | R2 `high`; R3 `high` for depth and high-authority joins | R3 `high`; typed `xhigh` trigger may require another attempt | Conditional |
| Thorough | R2 `high`; R3 `high` for hard depth and high-authority joins | R3 `high`; typed `xhigh` trigger may require another attempt | Conditional |

Light's reduced cost is implemented by leaving expensive uncertainty visible,
not by converting it into safety. If a Light product contract demands a
terminal material negative, it must pay for the R3 attempt.

### 3.2 Objective negative-closure risk

The route compiler must not rely only on mutable severity. It computes:

```text
negative_closure_risk =
    NONE
  | MATERIAL
  | UNKNOWN_MATERIAL
```

`MATERIAL` is triggered by any typed fact such as:

- confirmed mechanism;
- material asset or control reach;
- surviving proof or execution artifact;
- unresolved external/environment/cross-chain premise;
- disputed harm or reachability trace;
- severity disagreement across evidence channels;
- candidate/report identity at risk of disappearance;
- unresolved negative methodology obligation;
- serious cross-component/cross-language composition.

Missing or contradictory risk evidence becomes `UNKNOWN_MATERIAL`, which has
the same closure authority requirement as `MATERIAL`. A Low or Informational
label cannot suppress these objective triggers.

### 3.3 Typed `xhigh` triggers

`xhigh` remains an exception. It is eligible only when:

1. a material terminal negative is proposed after an R3 `high` attempt and a
   negative obligation remains unresolved;
2. a demotion depends on an unresolved external or environmental premise;
3. a confirmed mechanism has disputed material harm or a material severity
   boundary;
4. independent evidence channels disagree on exploitability, reachability, or
   harm;
5. a large cross-component trace remains incomplete after R3 `high`; or
6. a surviving candidate or proof would otherwise disappear from the report.

Eligibility is not authorization. `BudgetAuthorityV1` must also reserve the
resources. If the required escalation is unavailable, the result remains
`UNRESOLVED_NEEDS_XHIGH_REVIEW`; it is not silently closed by the lower-effort
attempt.

### 3.4 Phase-family placement

The route is attached to the compiled work unit and role, never merely to a
phase name.

| Phase family | Base authority | Important rule |
| --- | --- | --- |
| Bake, parser, graph, exact joins | N0 | Never launch a provider |
| Recon | R2 | R3 only for a typed difficult cross-subsystem synthesis |
| Instantiate | R2 | Security-obligation instantiation stays reasoning work |
| Breadth | R2 | Selective R3 for high-risk seam/obligation shards |
| Rescan/per-contract | R2 | Core/Thorough use `high`; do not economy-route recall repair |
| Planner/queue/manifest | N0 target; R1 transitional | No semantic disposition authority |
| Inventory chunks | R2 | Semantic consolidation only |
| Inventory final merge | R3 plus N0 completeness | Preserve every identity mechanically |
| Semantic invariants | R2 | R3 for disputed global invariants |
| Core depth | R3 | Per-role route; `high` baseline, conditional `xhigh` |
| Niche depth | R2 | R3 only from typed scope/risk trigger |
| Attention/enum-gap repair | R2 | Bind to uncovered obligation denominator |
| Exploration/application skeptic | R3 for negative authority | No lower-tier terminal material negative |
| Semantic dedup | R3 proposal plus N0 preservation | Model groups; ledger never deletes |
| RAG/precedent sweep | R2 | Precedent cannot control disposition |
| Chain/composition | R3 | Conditional `xhigh` for disputed multi-hop traces |
| Verify queue/roster | N0 | Exact candidate denominator |
| Critical/High verification | R3 | Negative closure trigger is objective, not label-only |
| Medium verification | R2 positive path; R3 negative path | Frontier spend follows disposition authority |
| Low verification | R2 in Thorough | R3 if objective material/systemic facts trigger |
| Verify aggregate and mechanical gates | N0 | No model interpretation |
| Skeptic-judge | R3 | Independent negative challenge |
| Cross-batch reconciliation | N0 identity plus R2 semantic conflict | Never lose members |
| Severity adjudication shadow | R3 | `xhigh` only at typed material dispute |
| Report index | R3 plan plus N0 completeness | Known found-then-lost boundary |
| Report body | R2 | No authority to change identity, disposition, or severity |
| Tier projection/assembly | N0 target; R1 transitional | Haiku has no effort field |
| Report dedup | N0 preservation plus R3 disputed grouping | No delete authority |
| Report disposition | R3 for ambiguity; N0 policy | Last recall-loss boundary |
| Report floor | N0 | Policy, not prose |

The implementation fixture must enumerate every actual smart-contract and L1
phase/subphase/role from the executable registries. This table is the policy
shape, not permission to leave a registry row unmapped.

## 4. B1-B7 closure matrix

| Block | R2 correction | Mechanical enforcement |
| --- | --- | --- |
| B1 | Haiku 4.5 effort is `not_applicable`; omit `--effort` | Provider/model/effort capability matrix rejects Haiku plus any effort level |
| B2 | Observe every post-init assistant model, subagent model, `modelUsage` key, and transition notice in order | Strict transition policy; any mixed/unobservable route becomes debt |
| B3 | Seal environment precedence; distinguish requested, supported, and observed-effective effort | Scrub/fail closed on override variables; never relabel requested as actual |
| B4 | Store context, maximum input, maximum output, and operational budgets separately | Budget arithmetic and token-count canaries reject conflation/overflow |
| B5 | Light material negatives remain unresolved unless R3 runs | Disposition gate requires eligible R3 authority |
| B6 | Complete route/receipt denominator including transitions, service tier, capability, fallback/refusal, and budget | Versioned exact schemas and digest propagation |
| B7 | Gate cost by normalized resource grants and observed plan use, not xhigh counts | Vector budget reconciliation; unobservable plan use is explicit |

## 5. Normative schemas

All schemas below use canonical JSON, exact key sets, no floats, lowercase
SHA-256 digests, closed enums, and explicit schema versions. Unknown fields or
values become typed debt. They are not ignored.

### 5.1 `ProviderCapabilityManifestV2`

This is the dated, independently observed capability substrate:

```text
schema
manifest_version
manifest_digest
evaluation_utc
provider
transport
account_mode
auth_mode
provider_cli_name
minimum_provider_cli_version
observed_provider_cli_version
provider_cli_executable_sha256
exact_model_id
model_snapshot_or_alias_class
provider_supported_efforts[]
effort_observation_capability
effort_precedence_policy_id
effort_override_environment_keys[]
thinking_modes[]
context_window_tokens
provider_max_input_tokens | null
provider_max_output_tokens
pricing_class
pricing_snapshot_digest | null
service_tier_request_values[]
service_tier_observation_capability
actual_model_observation_capability
model_transition_observation_capability
refusal_observation_capability
availability_fallback_observation_capability
classifier_fallback_observation_capability
tool_capabilities[]
unsupported_features[]
source_document_urls[]
source_document_snapshot_digest
canary_receipt_digest | null
```

Rules:

- Haiku's `provider_supported_efforts` is empty and its applicability is
  `NOT_APPLICABLE`.
- A documentation snapshot can seed policy but cannot claim live entitlement,
  actual route, or runtime enforcement.
- A provider canary binds CLI version, account mode, transport, and observed
  event schema. Missing canary evidence is `UNKNOWN_BLOCKED` for strict paired
  evaluation.
- Opus 5's manifest lists Anthropic web fetch and Priority Tier as unsupported.
  A work unit requiring equivalent behavior must bind an explicit Plamen
  tool-level substitute or route elsewhere.
- Exact model text reduces alias drift but does not prove an immutable provider
  implementation. Bind evaluation date, provider response, CLI version, and
  any available system fingerprint/snapshot evidence.

### 5.2 `ModelRouteV2`

One immutable route is compiled for one work unit:

```text
schema
route_schema_version
route_id
route_digest
execution_profile
run_id
pipeline
mode
ecosystem
phase
subphase
work_unit_id
role_id
semantic_tier
disposition_authority
negative_closure_risk
route_reason_codes[]
provider
transport
account_mode
auth_mode
exact_requested_model_id
requested_effort
provider_supported_efforts[]
effort_applicability
thinking_policy
requested_service_tier
availability_fallback_policy_id
classifier_fallback_policy_id
model_transition_policy_id
minimum_provider_cli_version
provider_capability_manifest_version
provider_capability_manifest_digest
effort_precedence_policy_id
sanitized_environment_authority_digest
forbidden_environment_keys_digest
prompt_digest
methodology_digest_set_digest
tool_policy_digest
source_snapshot_digest
program_facts_digest
context_budget_digest
budget_authority_digest
semantic_plan_digest
generation
attempt_ordinal
```

Closed route values:

- `execution_profile`: `legacy_claude_v1` or `semantic_v1`;
- `disposition_authority`: `PROPOSAL_ONLY`, `POSITIVE_ONLY`,
  `TERMINAL_NEGATIVE_ELIGIBLE`, or `NO_SEMANTIC_AUTHORITY`;
- `requested_effort`: `low`, `medium`, `high`, `xhigh`, or
  `not_applicable`;
- `thinking_policy`: `ADAPTIVE_ON`, `MANUAL_SUPPORTED`,
  `DISABLED_AUTHORIZED`, or `NOT_APPLICABLE`;
- `requested_service_tier`: an exact supported tier,
  `NOT_APPLICABLE`, or `UNOBSERVABLE_REQUIRED_DEBT`;
- fallback policy IDs are separate for availability and classifier fallback.

Forbidden route values include:

- model aliases (`auto`, `default`, `latest`, family nicknames, unsuffixed
  `gpt-5.6`);
- `max`, `ultracode`, provider-default/auto effort, and unknown effort;
- unordered accepted-model sets;
- implicit service tier;
- a fallback that changes model or semantic tier within the same generation.

### 5.3 `ContextBudgetV2`

Capability and usable budget are different records:

```text
schema
context_budget_digest
context_window_tokens
provider_max_input_tokens | null
provider_max_output_tokens
request_input_ceiling_tokens
generation_output_ceiling_tokens
reserved_visible_output_tokens
reserved_reasoning_output_tokens
reserved_system_prompt_tokens
reserved_tool_definition_tokens
reserved_history_tokens
reserved_tool_result_tokens
reserved_compaction_tokens
reserved_safety_margin_tokens
source_payload_ceiling_tokens
large_context_authorization
pricing_thresholds[]
tokenizer_or_counter_authority_digest
```

The implementation enforces:

```text
generation_output_ceiling_tokens
  = reserved_visible_output_tokens + reserved_reasoning_output_tokens

request_input_ceiling_tokens
  <= provider_max_input_tokens                 when published/observed

request_input_ceiling_tokens
  + generation_output_ceiling_tokens
  <= context_window_tokens

source_payload_ceiling_tokens
  = request_input_ceiling_tokens
    - reserved_system_prompt_tokens
    - reserved_tool_definition_tokens
    - reserved_history_tokens
    - reserved_tool_result_tokens
    - reserved_compaction_tokens
    - reserved_safety_margin_tokens
```

All values must be non-negative and the source ceiling must be positive for a
model work unit. System messages, tool definitions, history, and tool results
are input consumption, not free headroom. Reasoning and visible output share
the provider generation limit where provider semantics say they do.

For GPT-5.6, current static seeds are context 1,050,000, maximum input 922,000,
and maximum output 128,000. Ordinary work remains in a much smaller
`ROUTINE_CAPPED` class. A large advertised window never authorizes a large
bundle by itself.

For Claude, use the live token-count/capability authority where available.
Until `max_input_tokens` is independently observed, keep it null and derive a
conservative request ceiling from the context and reserved output. Do not
persist `context_window_tokens` as `max_input_tokens`.

### 5.4 `BudgetAuthorityV1`

Cost and attention are authorized as a vector:

```text
schema
budget_authority_digest
run_id
work_unit_id
generation
provider
account_mode
plan_or_price_class
uncached_input_grant_tokens
cache_write_grant_tokens
cached_input_grant_tokens
output_grant_tokens_including_reasoning
reasoning_reserve_tokens
turn_limit
retry_limit
wall_time_limit_seconds
tool_call_limit
agent_fanout_limit
legacy_comparator_budget_digest | null
historical_plan_usage_target_basis_points
plan_usage_observation_policy
user_exception_authority_digest | null
```

The authoritative budget is the vector, not an `xhigh` job count.

For comparison with a legacy arm, each metric is normalized independently:

```text
candidate_to_legacy_ratio(metric)
  = candidate_aggregate(metric) / legacy_aggregate(metric)
```

If the legacy denominator is zero and the candidate is positive, the ratio is
`UNBOUNDED_REQUIRES_REVIEW`, not zero. A conservative reserved-attention index
may be reported as the maximum finite ratio across input, output, turns,
retries, wall time, tools, and fanout. The complete vector remains the
authority; a scalar cannot hide an oversized dimension.

Actual receipts reconcile:

- input, cached input, cache-write, output, and reasoning tokens where
  observable;
- turns and retries;
- wall time;
- provider refusals/fallbacks;
- actual API price-class cost for API-priced runs;
- actual attributed weekly-plan consumption for subscription runs.

API dollar estimates and subscription usage are separate. The user's historical
Claude x20 target is 10-15 percent of weekly use per Thorough audit. It is an
observed operational target, not a deterministic token-to-plan conversion. If
the client cannot attribute before/after plan use to one audit, record
`PLAN_CONSUMPTION_UNOBSERVABLE`; never claim that the 15 percent gate passed.
A wider envelope requires measured recall or demotion-soundness gain and
explicit user approval.

Raw count of `xhigh` work units is secondary telemetry only.

### 5.5 `ProviderExecutionObservationV2`

The provider-owned completion observation contains:

```text
schema
observation_digest
route_digest
generation
attempt_ordinal
attempt_id
provider
transport
account_mode
auth_mode
provider_cli_name
observed_provider_cli_version
provider_cli_executable_sha256
sanitized_environment_digest
requested_model_id
ordered_model_observations[]
model_usage_rows[]
model_transition_notices[]
observed_effective_model_id
effective_model_state
requested_effort
provider_supported_efforts[]
observed_effective_effort
effective_effort_observation_basis
thinking_policy
requested_service_tier
observed_service_tier
availability_fallback_outcome
classifier_fallback_outcome
refusal_category
provider_terminal_category
usage
turns
retries
wall_time
budget_reconciliation_digest
raw_stream_digest
```

Each `ordered_model_observations` row includes:

```text
sequence
event_uuid
root_or_subagent
parent_tool_use_id | null
model_id
event_digest
```

`model_usage_rows` retains every model key and its exact normalized usage
object. `model_transition_notices` retains the exact typed notice category,
source event, sequence, from-model, to-model, and notice digest.

`observed_effective_model_id` is populated only when all eligible model
observations and usage keys prove one exact model. Otherwise it is null and
`effective_model_state` is `MIXED`, `UNOBSERVABLE`, or `MISMATCHED`. Requested
model text is never copied into the observed field.

`observed_effective_effort` is one of:

- `low`, `medium`, `high`, or `xhigh` when the provider exposes trustworthy
  actual evidence;
- `not_applicable` for Haiku/N0;
- `EFFECTIVE_EFFORT_UNOBSERVABLE`;
- `EFFECTIVE_EFFORT_MISMATCH`;
- `EFFECTIVE_EFFORT_UNSUPPORTED`.

Requested effort is never copied into the observed field.

### 5.6 `DispositionEligibilityV1`

The mechanical eligibility projection is:

```text
ELIGIBLE_POSITIVE
ELIGIBLE_TERMINAL_NEGATIVE
PROVISIONAL_ONLY
UNRESOLVED_NEEDS_R3_REVIEW
UNRESOLVED_NEEDS_XHIGH_REVIEW
PROVIDER_ROUTE_DEBT
MODEL_REFUSAL
MODEL_TRANSITION_DEBT
EFFECTIVE_EFFORT_UNOBSERVABLE
SERVICE_TIER_UNOBSERVABLE
CAPABILITY_MISMATCH
```

`ELIGIBLE_TERMINAL_NEGATIVE` requires all of:

- exact current-generation route digest;
- required R3 authority for material/unknown-material risk;
- required effort authority;
- no refusal or classifier adverse event;
- exactly one allowed actual model for the attempt;
- no availability or content-classifier transition;
- all `modelUsage` keys consistent with the one observed model;
- required service-tier and capability evidence;
- independent negative adjudicator;
- complete candidate and evidence denominator.

All failure states preserve the candidate and make debt visible. They do not
halt unrelated work and they do not become safety evidence.

## 6. Provider-specific launch and observation rules

### 6.1 Claude

#### Command and environment

For Opus 5 or Sonnet 5:

```text
claude --model <exact-id> --effort <low|medium|high|xhigh> ...
```

For Haiku 4.5:

```text
claude --model claude-haiku-4-5-20251001 ...
```

No `--effort` is emitted for Haiku.

Before launch:

1. Build a fresh allowlisted environment.
2. Remove or fail closed on `CLAUDE_CODE_EFFORT_LEVEL`.
3. Remove model alias/default overrides unless they are explicitly required
   and route-bound for a third-party deployment.
4. Bind all forbidden/removed keys, their absence states, and the sanitized
   environment digest.
5. Bind the minimum and observed Claude Code versions.
6. Bind organization capability/effort restrictions when observable.

Because organization policy can cap effort, a clean environment and
`--effort` are necessary but not sufficient proof of effective effort.

The sealed precedence model is explicit:

| Layer | R2 treatment |
| --- | --- |
| Model capability | Defines whether effort applies and the provider-supported set |
| Organization effort cap | Intersects the supported set; unknown cap makes effective effort unobservable |
| `CLAUDE_CODE_EFFORT_LEVEL` | Officially overrides session effort; must be absent or launch fails closed |
| Explicit `--effort` | Becomes the requested effort only after higher-precedence uncertainty is removed |
| Persisted/session setting | Must not control a sealed non-interactive launch; bind sanitized settings/environment evidence |
| Provider execution | Supplies observed effective effort if the transport exposes trustworthy evidence |

The route records the precedence policy ID and sanitized environment authority.
The completion records requested, provider-supported, and observed-effective
effort separately. If the last value cannot be proved, it is
`EFFECTIVE_EFFORT_UNOBSERVABLE`; neither the command line nor provider default
may be substituted for it.

#### Post-init model proof

The stream parser must:

- verify `init.model`;
- collect every root and subagent `assistant.message.model` in stream order;
- collect every `result.modelUsage` key and usage record;
- retain structured availability/classifier transition notices;
- reject unknown/untyped transition notice shapes;
- bind the complete ordered sequence into the completion digest.

An init on Opus 5 followed by any assistant event or usage row on Opus 4.8 is
a model transition even if Opus 4.8 appeared in a predeclared set. Unordered
accepted-model sets are removed from certifying semantics.

Strict benchmark mode:

- any transition, transition ambiguity, missing assistant-model field, or
  unexplained `modelUsage` model terminates the attempt as debt;
- the attempt is excluded from paired scoring;
- no evidence from the mixed attempt is promoted.

Operational mode:

- a transition terminates the current semantic attempt;
- any retained output is proposal-only and cannot certify a negative;
- the driver may start a new authorized generation with the fallback model,
  a new route, new arm, new attempt ID, and unchanged frozen semantic
  obligation/source denominator;
- evidence from different models is never merged into one certifying attempt.

Availability fallback and content-classifier fallback retain different policy
and outcome fields. A generic `fallback_event = true` is insufficient.

#### Refusal

These are adverse terminal outcomes even when transport exits successfully:

- `stop_reason: "refusal"`;
- classifier refusal/flag;
- blocked fallback;
- successful envelope with refusal content/category;
- provider notice that prevents continuation;
- unobservable actual model after a classifier event.

They yield `MODEL_REFUSAL` or typed route debt. They cannot support a terminal
negative. This applies to Sonnet 5 as well as Opus 5.

### 6.2 Codex/OpenAI

The semantic route command must contain:

```text
codex exec
  --ignore-user-config
  --model <gpt-5.6-sol|gpt-5.6-terra|gpt-5.6-luna>
  -c model_reasoning_effort="<low|medium|high|xhigh>"
```

Rules:

- no unsuffixed `gpt-5.6`;
- no unknown/future alias fallback;
- no retry that drops `--model` or effort;
- no phase-wide model mutation after rejection/capacity failure;
- requested service tier is route-bound rather than hard-coded;
- observed service tier is retained separately;
- response/refusal/safeguard outcomes are adverse;
- actual model and effective effort are observed where the transport exposes
  them; otherwise strict paired eligibility is withheld.

ChatGPT entitlement, API-key, and other account modes are distinct. A retry
that needs another account mode or model is a new execution generation.

`--ignore-user-config` prevents user config drift but does not prove the actual
provider model, effort, service tier, or entitlement. Those remain observation
fields.

## 7. Exact implementation map

Use parallel versioned schemas. Do not mutate legacy serialized meaning in
place.

| Area/file | Current role | Required R2 change |
| --- | --- | --- |
| `scripts/backend_capability_registry.py` | Model policy, launch intent, capability observation/authority | Add V2 policy/route/capability records; provider-specific effort applicability; max-input field; service-tier/fallback/refusal/transition capabilities; reject provider-default reasoning |
| `scripts/plamen_types.py` | Legacy aliases and phase-wide `phase_model()` | Keep as legacy adapter; add fail-closed semantic route lookup; no unknown alias default |
| `scripts/semantic_work_plan.py` | Semantic plan, roster, generation/attempt identity | Bind `ModelRouteV2`, context budget, budget authority, disposition authority, and route digest per work unit/role |
| `scripts/phase_io_contracts.py` | `LaunchSpec` and PhaseIO contract | Add `LaunchSpecV2` or an exact V2 sibling; bind route/capability/context/budget digests and generation/attempt identity |
| `scripts/worker_transaction.py` | WorkPlan, arm, recovery, incorporation | Add V3 provider contract and WorkPlan schemas; require exact route through arm, execution, resume, repair, and incorporation |
| `scripts/worker_execution_receipts.py` | Provider-owned arm/completion/debt | Add V3 observation fields and budget reconciliation; no caller-authored actual route |
| `scripts/claude_headless_profile.py` | Sealed Claude profile | Add semantic V3 route/environment fields; preserve V1/V2 legacy profiles |
| `scripts/claude_provider_policy.py` | Claude launch policy | Compile exact model/effort/thinking/fallback controls; Haiku omission rule |
| `scripts/claude_provider_preparation.py` | Provider/runtime preparation | Seal sanitized effort/model environment, CLI minimum/actual version, capability manifest, and observation requirements |
| `scripts/claude_stream_json_evidence.py` | Claude stream proof | Add evidence V2: ordered all-event models, `modelUsage`, transition notices, refusal categories, effort/service observations |
| Codex command/stream adapter modules | Codex sealed launch and output | Bind exact model/effort/service tier and actual observations; remove same-generation model-dropping/fallback retries |
| `scripts/plamen_driver.py` | Orchestration and launch paths | Compile route once per work unit; all PTY/headless/resume/missing-only/dynamic paths consume the same WorkerTransaction |
| RunBundle v2 exporter/contracts | Neutral evaluator handoff | Export route, capability, observation, budget, eligibility, and generation digests without private auth/environment values |
| Neutral evaluator | Paired scoring | Exclude non-strict routes; report refusal/fallback/effort/service debt and cost vectors separately |

### 7.1 Schema migration table

| Existing schema | Candidate schema | Migration rule |
| --- | --- | --- |
| `plamen.model-policy-registry.v1` | `plamen.model-policy-registry.v2` | V1 stays readable/frozen; V2 adds provider-specific effort/capability semantics |
| `plamen.backend-launch-intent.v1` | `plamen.backend-launch-intent.v2` | Add route, sanitized environment, service, fallback, and budget authorities |
| `plamen.provider-observation-record.v2` | `plamen.provider-observation-record.v3` | Add maximum input and route-observability capabilities |
| `plamen.backend-capability-receipt.v1` | `plamen.backend-capability-receipt.v2` | Add service/effort/transition/refusal and maximum-input facts |
| `plamen.launch.v1` | `plamen.launch.v2` | New exact class; do not reinterpret V1 fields |
| `plamen.semantic-work-plan.v1` | `plamen.semantic-work-plan.v2` | Add route/context/budget and negative-authority digests |
| `plamen.worker_work_plan.v2` | `plamen.worker_work_plan.v3` | Exact route is part of provider contract |
| `plamen.worker_attempt_arm.v3` | `plamen.worker_attempt_arm.v4` | Bind V3 plan and route/environment authorities |
| `plamen.worker_execution_arm.v2` | `plamen.worker_execution_arm.v3` | Bind provider observation obligations |
| `plamen.worker_execution_completion.v2` | `plamen.worker_execution_completion.v3` | Carry actual route, effort, service, fallback/refusal, and budget evidence |
| `plamen.claude-expected-init/v2` | `plamen.claude-expected-init/v3` | Replace unordered accepted models with exact requested model and transition policy |
| `plamen.claude-stream-json-evidence/v1` | `plamen.claude-stream-json-evidence/v2` | Ordered model/usage/notice and refusal evidence |
| RunBundle v2 payload | RunBundle v2 additive record types | Keep bundle envelope; add versioned route records and strict eligibility join |

No migration rewrites historical artifacts. `legacy_claude_v1` continues to use
its existing schemas and exact argv/prompt/tool policy. The candidate path uses
new schemas. An external legacy observation envelope may hash existing legacy
artifacts for evaluation, but it must not inject new launch arguments into the
control arm.

## 8. Fixture-first implementation plan

Every checkpoint starts with failing fixtures. A fixture that only tests a
helper is insufficient when the defect is in a production caller.

### Checkpoint 0: freeze and inventory

Produce:

- exact legacy Claude route/argv/prompt/tool-policy/receipt hashes;
- exact current Codex route hashes;
- exhaustive SC/L1/ecosystem/mode/phase/subphase/role inventory;
- route dry-run output for every work unit without invoking providers;
- source hashes for all touched modules.

Pass condition: every executable work-unit row maps to exactly one route or one
explicit debt. There is no default branch.

### Checkpoint 1: policy and schema

Required red-to-green fixtures:

1. Haiku plus `low` is rejected.
2. Haiku plus `not_applicable` emits no `--effort`.
3. Sonnet plus `low` is accepted for explicit low-effort R1.
4. N0 launches no provider.
5. `max`, `ultracode`, provider-default, unknown, and above-xhigh effort fail.
6. Unknown/future model IDs and all forbidden aliases fail closed.
7. Every route field mutation changes the route digest.
8. Provider capability/model/effort mismatch yields typed debt.
9. Opus 5 route requiring Anthropic web fetch or Priority Tier is rejected
   unless an exact substitute capability is bound.
10. Every registry work unit has one route or explicit debt.

### Checkpoint 2: context and cost authority

Required red-to-green fixtures:

1. GPT-5.6 stores 1,050,000 context, 922,000 max input, and 128,000 max output
   as three fields.
2. A context window cannot be replayed as max input.
3. Source/system/tool/history/tool-result/output reservations cannot exceed
   context or max input.
4. Crossing 272K input changes the pricing class/receipt, not the context
   capability.
5. One huge `xhigh` work unit fails the budget even if fewer than 10 percent of
   work units use `xhigh`.
6. Many bounded work units reconcile by their full resource vector.
7. A candidate dimension with a zero legacy denominator requires review.
8. API cost and subscription-plan use cannot be combined.
9. Missing attributable plan use emits `PLAN_CONSUMPTION_UNOBSERVABLE`.
10. No receipt claims the 10-15 percent target passed without actual attributed
    plan telemetry.

### Checkpoint 3: Claude environment and stream proof

Required red-to-green fixtures:

1. `CLAUDE_CODE_EFFORT_LEVEL` is absent from the sealed child environment.
2. A forbidden override appearing after arm/before exec aborts to debt.
3. Environment digest changes when any allowed/forbidden state changes.
4. Organization effort cap unknown yields
   `EFFECTIVE_EFFORT_UNOBSERVABLE`, not requested effort.
5. Init Opus 5 then root assistant Opus 4.8 fails strict eligibility.
6. Init Opus 5 then subagent assistant Opus 4.8 fails strict eligibility.
7. Opus 5 assistant rows plus an Opus 4.8 `modelUsage` key fail.
8. A transition notice without an observed model transition fails closed.
9. An observed transition without a typed notice is still route debt.
10. Availability and classifier fallback produce distinct outcomes.
11. Operational transition ends generation N and can only restart as N+1.
12. No N+1 evidence can be merged into N's completion.
13. Sonnet `stop_reason=refusal` in a successful envelope is adverse.
14. Opus classifier refusal, blocked fallback, and missing transition evidence
    are adverse.
15. Missing actual model or effective-effort proof excludes a strict paired
    arm.
16. Unsupported CLI version is debt.

### Checkpoint 4: Codex route proof

Required red-to-green fixtures:

1. Exact Sol/Terra/Luna ID and effort appear in the sealed command.
2. `--ignore-user-config` is present.
3. `max` and forbidden aliases are rejected at every entry point.
4. ChatGPT-auth recovery cannot remove the exact model/effort in the same
   generation.
5. Capacity/model fallback creates debt or a new generation.
6. Requested and observed service tiers are retained separately.
7. An observed service-tier mismatch is visible and policy-classified.
8. Actual model/effort unobservable excludes strict paired scoring.
9. OpenAI safeguard/refusal output cannot certify a negative.
10. Retry preserves prompt, source, tools, route, and budget digest.

### Checkpoint 5: Light and disposition safety

Required red-to-green fixtures:

1. Light plus Low-labeled confirmed mechanism remains
   `UNRESOLVED_NEEDS_R3_REVIEW`.
2. Light plus unknown material risk remains unresolved.
3. Light R2 may emit positive/provisional candidates.
4. A terminal material negative becomes eligible only after independent R3.
5. A typed xhigh trigger without xhigh budget stays unresolved.
6. Refusal/fallback/effort/service/capability debt cannot be mapped to SAFE.
7. Report projection keeps unresolved candidates visible and re-queued.
8. Severity under-rating cannot suppress objective risk triggers.

### Checkpoint 6: lifecycle propagation

Required red-to-green fixtures:

- route/context/budget digests survive PhaseIO, WorkPlan, arm, runtime
  materialization, execution, completion/debt, incorporation, resume, repair,
  reconciliation, and RunBundle export;
- mismatched resume route is rejected;
- missing-only recovery uses the original route or a new typed generation;
- R10 and all finding identity joins are unchanged by route metadata;
- report-only workers cannot change identity/disposition/severity;
- N0 launches no provider on Windows, Linux, or macOS;
- long paths and non-ASCII project paths preserve canonical digests even though
  this guide and schema identifiers remain ASCII;
- unsupported OS/provider/version degrades loudly without a false phase
  completion or a pipeline halt.

### Checkpoint 7: independent review and full regression

At each checkpoint:

1. Freeze exact changed-file hashes.
2. Run focused fixtures.
3. Run blast-radius tests.
4. Run full fast-lane tests.
5. Run serial and parallel tests where concurrency is relevant.
6. Run clean-install/package tests on supported Python and OS matrices.
7. Run fault-injection/resume/recovery tests.
8. Give the frozen denominator to a reviewer who did not author the diff.
9. Repair every blocking finding fixture-first and re-freeze.

No same-repository motivating case counts as recall evidence.

## 9. Held-out A/B and cutover gates

The candidate route remains behind `semantic_v1`; `legacy_claude_v1` remains
the default.

Each paired arm must hold constant:

- source snapshot;
- semantic methodology/prompt denominator;
- program facts;
- adaptive-attention roster;
- tool/native-command policy;
- candidate denominator;
- work-unit resource ceilings;
- output/verification/report schemas;
- neutral grader and ground-truth boundary.

Each backend is scored independently. Claude/Codex role mapping does not permit
pooling them as one equivalent treatment.

Strict arm inclusion requires:

- one exact model for one generation;
- eligible actual-model evidence;
- eligible effective-effort evidence;
- no refusal or fallback;
- route/capability/service/budget receipts;
- no ground-truth exposure;
- no <PRIVATE_REGRESSION_TARGET> or another motivating regression case in the scored corpus.

Measure:

- strict root-cause recall;
- never-found misses;
- found-then-lost misses;
- false-safe/demotion rate;
- obligation application coverage;
- precision and root-cause fragmentation;
- severity calibration;
- proof execution honesty;
- report identity/completeness;
- tokens, turns, retries, wall time;
- refusal/fallback/route-debt rates;
- actual plan consumption where attributable.

Minimum release gates:

1. zero found-then-lost regression;
2. zero unauthorized terminal-negative closure;
3. zero silent model/effort/fallback/service drift;
4. no Critical/High held-out recall loss;
5. aggregate recall non-inferiority under the evaluator's predeclared interval;
6. precision, severity calibration, and report completeness non-inferiority
   under predeclared margins;
7. normal Claude Thorough use remains near the historical 10-15 percent weekly
   target when observable, unless a measured recall/demotion-soundness gain and
   explicit user approval authorize more.

Report-body R3-to-R2 and assembly R1-to-N0 moves are experiments, not assumed
behavior-preserving refactors. They need report-quality and completeness A/B
gates.

Cutover order:

1. Land V2 routing/receipt infrastructure with legacy behavior unchanged.
2. Shadow-route without disposition authority.
3. Clear provider canaries and independent review.
4. Clear held-out R1/R2 non-inferiority.
5. Clear R3 `high`.
6. Clear typed `xhigh` escalation last.
7. Preserve a one-command legacy rollback until multiple ecosystem, backend,
   and OS canaries pass.

## 10. Non-goals and anti-bloat rules

This work must not:

- encode protocol-specific vulnerability answers;
- increase every phase's model or agent count by default;
- let a model construct its own roster;
- replace independent verification or mechanical gates with self-check prose;
- convert deterministic queues, joins, projections, or gates back into model
  tasks;
- claim exact model strings are immutable provider snapshots;
- claim public API pricing predicts Claude x20 or ChatGPT entitlement use;
- claim route integrity itself proves recall improvement.

Additional agents are authorized only for a typed uncovered obligation or
independent evidence channel. Stronger effort is authorized only by semantic
risk plus resource authority. This preserves recall focus without phase-wide
brute-force bloat.

## 11. Definition of done

Backend routing is implementation-complete only when:

- B1-B7 each has a red-to-green production-path fixture;
- every executable SC/L1/ecosystem/mode/phase/role row has one exact route or
  explicit debt;
- legacy Claude hashes and semantics remain unchanged;
- all provider launches consume the same per-work-unit route through
  WorkerTransaction;
- all actual-route evidence propagates to RunBundle v2;
- refusal, fallback, transition, effort ambiguity, service ambiguity, and
  capability mismatch are mechanically barred from terminal negative
  authority;
- Light material negatives remain visible unless R3 adjudicates them;
- budget reconciliation uses full resource vectors and honest plan telemetry;
- focused, blast-radius, full, packaging, fault/recovery, cross-OS, and
  cross-ecosystem tests pass;
- independent review accepts a hash-frozen denominator;
- neutral held-out A/B proves non-inferiority before any default change.

Until all of those are evidenced, the honest status is:

```text
legacy_claude_v1: production default
semantic_v1 routing: experimental
new model quality/recall claim: unproven
```

End of guide.
