# Plamen backend model-routing engineering guide R2.2

Date: 2026-07-29

Status: bounded normative correction; not a cutover authorization

Change boundary: documentation only. This artifact changes no repository,
configuration, provider state, audit repository, commit, or launch behavior. It
does not authorize a provider call or audit.

## 0. Frozen governing boundary

R2.2 preserves the accepted architecture and B1/B2/B4/B5 behavior in:

- `Plamen_Backend_Model_Routing_Engineering_Guide_R2.1_2026-07-29.md`
- SHA-256:
  `f5dd8c48ff6e4951526425a4685905c313085ebf959f79d8d9bab4391bb13894`

It closes every block and precision amendment in:

- `Plamen_Backend_Model_Routing_Engineering_Guide_R2.1_Independent_Review_2026-07-29.md`
- SHA-256:
  `3569d77097801a95477281188eed0583a23f2c1b970b434f298c8e3b3023f69b`

R2.1 remains the baseline for provider facts, phase placement, Light-mode
authority, refusal/safeguard handling, driver-only child authority, lifecycle
propagation, held-out evaluation, and anti-bloat rules. R2.2 replaces the R2.1
rules for:

- canonical numbers, Unicode, and set ordering;
- Claude effort-precedence sealing;
- current thinking-mode cross-products;
- effort/model transition identity;
- common-grant authorization across generations;
- resource ratio ownership and run-level plan targets;
- capability canary plans and field-scoped claims;
- launch authority, attempt launch envelope, native budget, debt ID, currency,
  and cited standards.

Where the two artifacts conflict, R2.2 controls. Implementers must use the two
frozen hashes above; an unbound or edited R2.1 is not the R2.2 baseline.

R2.2 increments schema versions whenever it changes an R2.1 exact key set:
`BudgetAuthorityV2`, `BackendArmExecutionIdentityV3`,
`ProviderExecutionObservationV3`, `BudgetReconciliationV2`, and
`ProviderCapabilityCanaryReceiptV2`. It does not reinterpret serialized V1/V2
records or rewrite historical/legacy artifacts.

## 1. Preserved architecture and accepted behavior

The identity graph remains one-way:

```text
CommonResourceGrantV1
  -> SemanticWorkPlanV2
  -> ProviderArmFamilyIdentityV1
  -> BackendSemanticResourceLedgerV1
  -> provider generation records:
       ModelRouteV2
       ContextBudgetV2
       BudgetAuthorityV2
       LaunchAuthorityV1
       BackendArmExecutionIdentityV3
  -> ExecutionAttemptIdentityV2
  -> AttemptLaunchEnvelopeV1
  -> ProviderExecutionObservationV3
  -> reconciliation, eligibility, and neutral evaluation
```

The following R2.1 rules remain normative:

- `SemanticWorkPlanV2` is backend-neutral and contains no provider, route,
  context, provider budget, generation, attempt, service, provider environment,
  or provider price identity.
- Claude and Codex paired arms share byte-identical semantic-plan bytes and
  digest.
- Provider route, context, budget, launch authority, and generation belong
  below the provider arm family, never in the semantic plan.
- Attempt ordinal belongs only to `ExecutionAttemptIdentityV2`.
- N0 is a separate native union member and has no fake provider sentinels.
- Legacy remains outside V2 route, semantic, arm, and attempt types.
- Haiku effort is `not_applicable`; manual thinking state is explicit.
- Actual model, fallback, transition, refusal, safety, service, and effective
  effort remain observed state, never copied from request.
- GPT-5.6 context window, maximum input, maximum output, request ceiling, and
  pricing threshold remain distinct.
- Light cannot close material or unknown-material negatives without eligible
  R3 authority.
- No model-owned audit child can run. Every agent is a separate driver-owned
  WorkUnit and WorkerTransaction.
- Refusal, safety pause/timeout/block, transition, fallback, capability
  mismatch, or unobservable effective effort cannot support terminal safety.
- `max`, `ultracode`, provider-default/auto effort, and unknown model/effort
  values remain forbidden.
- `legacy_claude_v1` remains the production default until neutral held-out
  non-inferiority clears each backend separately.

## 2. Normative canonical encoding R2.2

### 2.1 JSON number profile

Every serialized JSON integer in an identity, policy, grant, observation,
usage, reconciliation, ratio, receipt, or debt record is in:

```text
0..9007199254740991
```

This is the non-negative I-JSON interoperable exact-integer range
`0..(2^53 - 1)`. Negative values and wider JSON numbers are invalid. R2.2 does
not introduce a decimal-string integer type.

Implementations may use checked unsigned 128-bit internal arithmetic for sums,
products, and comparisons. Before serialization:

1. an authoritative stored integer must be at most 9,007,199,254,740,991;
2. a reduced ratio numerator/denominator must each be in that range;
3. a wider internal result emits `ARITHMETIC_RANGE_DEBT`;
4. the implementation must not round, saturate, wrap, stringify ad hoc, or
   serialize a wider JSON number.

Cross-products used only for comparison need not be serialized. They use
checked unsigned 128-bit arithmetic. Overflow emits
`ARITHMETIC_OVERFLOW_DEBT`.

### 2.2 One Unicode policy

Record construction has two explicit string classes.

`IDENTITY_STRING` includes:

- schema/version names;
- IDs, digests, enum and registry values;
- provider/model/transport/account/auth/service values;
- normalized project-relative paths;
- URLs, currency codes, policy IDs, reason codes, and evidence keys.

An identity string must already be Unicode NFC before validation. A non-NFC
identity is rejected as `NON_NFC_IDENTITY`. The validator does not repair it.
ASCII-only fields remain subject to their tighter grammar.

`FREE_TEXT_STRING` is legal only for fields explicitly named:

```text
RouteDebtV2.required_operator_action
```

An input adapter normalizes free text to NFC before record validation. The
validated value is then immutable.

JCS does not normalize or otherwise mutate any validated string. Canonical
encoding is RFC 8785 over the already validated record. Unknown free-text
fields are invalid.

### 2.3 Set and ordered-array law

For every R2.2 field declared a semantic set:

1. validate and NFC-check each element;
2. compute each element's RFC-8785 canonical UTF-8 bytes;
3. sort by unsigned lexicographic byte order;
4. reject duplicate canonical byte strings;
5. hash the resulting array order.

This replaces R2.1's code-point wording. Observed/event arrays retain their
validated stream sequence. Numeric threshold arrays sort by strictly
increasing integer threshold.

Golden vectors are mandatory across:

- Python reference implementation;
- JavaScript RFC-8785 implementation;
- .NET implementation;
- Windows, Linux, and macOS.

Vectors include:

- 0, 1, 9,007,199,254,740,991;
- rejection of 9,007,199,254,740,992;
- internal 128-bit cross-products that remain un-serialized;
- precomposed/decomposed Unicode identity rejection;
- free-text pre-normalization;
- non-ASCII set ordering by canonical UTF-8 bytes;
- own-digest exclusion and nested-digest retention.

### 2.4 Digest law retained

Every digest remains lowercase hexadecimal SHA-256 over RFC-8785 canonical
UTF-8 bytes. The preimage is the complete validated record with only that
record's own digest field omitted. No other exclusion is legal. Nested digests
remain present.

## 3. Closed Claude effort-precedence authority

### 3.1 Selected strategy

R2.2 selects the intentional-environment strategy for Opus 5 and Sonnet 5.

For an applicable-effort Claude route:

1. create a fresh allowlisted child environment;
2. set `CLAUDE_CODE_EFFORT_LEVEL` to the exact route effort;
3. pass the equal explicit `--effort` value;
4. scan every loaded customization/control source;
5. reject any effort declaration that is neither absent nor exactly equal;
6. bind the complete authority and customization digest into the launch
   authority;
7. treat organization clamping as runtime effective-effort observation, not
   requested identity.

The environment variable is no longer removed for Opus/Sonnet. It is an
intentional route-bound authority. Environment and CLI disagreement is
prelaunch debt.

For Haiku 4.5:

- `requested_effort = not_applicable`;
- `CLAUDE_CODE_EFFORT_LEVEL` is absent;
- no `--effort` is emitted;
- every loaded skill, role, subagent definition, setting, and control request
  must lack an effort declaration;
- any declaration is `EFFORT_NOT_APPLICABLE_OVERRIDE_DEBT`.

No loaded subagent may execute under `semantic_v1`; its definition is still
scanned because merely loading customization can affect root execution.

### 3.2 Closed precedence-source registry

`ClaudeEffortAuthorityV2` has:

```text
schema
effort_authority_version
effort_authority_digest
semantic_plan_digest
provider_capability_manifest_digest
exact_model_id
effort_applicability
requested_effort
organization_cap_state
organization_cap_source
environment_source
cli_source
skill_frontmatter_sources[]
role_frontmatter_sources[]
subagent_frontmatter_sources[]
settings_sources[]
control_request_sources[]
session_default_source
customization_set_digest
precedence_policy_id
```

Exact schema/version:

```text
schema = plamen.claude-effort-authority.v2
effort_authority_version = 2
precedence_policy_id = CLAUDE_EFFORT_PRECEDENCE_R2_2
```

Each source row is:

```text
source_kind
source_id
source_digest
loaded
declared_effort | null
scan_result
```

Closed `source_kind`:

```text
ORGANIZATION_CAP
ENVIRONMENT
CLI_ARGUMENT
SKILL_FRONTMATTER
ROLE_FRONTMATTER
SUBAGENT_FRONTMATTER
SETTINGS_USER
SETTINGS_PROJECT
SETTINGS_LOCAL
CONTROL_REQUEST
SESSION_DEFAULT
```

Closed `scan_result`:

```text
ABSENT
PRESENT_EQUAL
PRESENT_CONFLICT
UNREADABLE
NOT_APPLICABLE
```

The provider-documented execution precedence used by R2.2 is:

```text
organization cap constrains effective runtime effort
CLAUDE_CODE_EFFORT_LEVEL controls configured effort
loaded skill/subagent frontmatter may override ordinary session effort
ordinary session/CLI/settings/control sources remain lower authorities
```

R2.2 does not depend on unresolved ordering among lower sources. Every loaded
lower source must be absent or equal to the route request. Any conflict or
unreadable loaded source is prelaunch debt.

The preparation layer enumerates the provider's resolved load graph, then
parses YAML/TOML frontmatter and JSON/settings with format-aware parsers. Regex
text matching is not authority. Symlink/real-path identity, precedence layer,
canonical content digest, and loaded/not-loaded state are sealed before exec.
An unenumerated or parse-failed customization is `UNREADABLE`.

`organization_cap_state` is:

```text
KNOWN_PERMITS_REQUEST
KNOWN_CLAMPS_REQUEST
UNKNOWN
NOT_APPLICABLE
```

Only `KNOWN_PERMITS_REQUEST` can help strict effective-effort eligibility.
`KNOWN_CLAMPS_REQUEST` is mismatch. `UNKNOWN` remains runtime
`EFFECTIVE_EFFORT_UNOBSERVABLE` unless per-attempt provider evidence proves the
exact effective effort.

### 3.3 Required effort fixtures

Production-path fixtures cover:

1. environment and CLI equal;
2. environment/CLI disagreement;
3. same-effort and conflicting skill frontmatter;
4. same-effort and conflicting role frontmatter;
5. loaded subagent frontmatter despite child execution being denied;
6. user/project/local settings;
7. control-request effort;
8. unreadable customization;
9. late mutation after arm and before exec;
10. known and unknown organization cap;
11. Haiku with every possible override source;
12. digest mutation for every loaded customization.

Requested effort is still not effective-effort proof. Strict eligibility
retains R2.1's per-attempt observation requirement.

## 4. Closed thinking request and observation

### 4.1 Current legal request matrix

R2.2 removes the open-ended non-adaptive clause.

| Exact model | Requested effort | Requested thinking mode |
| --- | --- | --- |
| `claude-opus-5` | low, medium, high, xhigh | `ADAPTIVE_ON` |
| `claude-sonnet-5` | low, medium, high, xhigh | `ADAPTIVE_ON` |
| `claude-haiku-4-5-20251001` | not_applicable | `MANUAL_OFF` or `MANUAL_ON` |
| GPT-5.6 exact IDs | low, medium, high, xhigh | `NOT_APPLICABLE` |

For Haiku `MANUAL_ON`, a positive exact manual-thinking token budget is
required. For Haiku `MANUAL_OFF`, the budget is null and no manual-thinking
flag is emitted.

Disabled Opus/Sonnet thinking is not representable in R2.2. If later required,
it needs a new requested enum, provider argument mapping, effort cross-product,
observation rule, canary case, registry version, and schema revision.

### 4.2 Exact argument mapping

`ThinkingLaunchMappingV2` has:

```text
schema
thinking_mapping_version
thinking_mapping_digest
exact_model_id
requested_effort
requested_thinking_mode
manual_thinking_budget_tokens | null
provider_argument_vector_digest
mapping_result
```

```text
schema = plamen.thinking-launch-mapping.v2
thinking_mapping_version = 2
```

Closed `mapping_result`:

```text
ADAPTIVE_EXPLICIT
MANUAL_ENABLED_EXPLICIT
MANUAL_DISABLED_BY_OMISSION
NOT_APPLICABLE
INVALID
```

The provider argument vector is exact and ordered. For Opus/Sonnet,
`ADAPTIVE_ON` must map to the documented adaptive-thinking control rather than
relying on an unrelated default. For Haiku, only its manual controls are legal.

### 4.3 Observed thinking states

`observed_thinking_state` is:

```text
ADAPTIVE_ON_CONFIRMED
MANUAL_ON_CONFIRMED
MANUAL_OFF_CONFIRMED
NOT_APPLICABLE
UNOBSERVABLE
MISMATCHED
```

`ProviderExecutionObservationV3` retains the accepted R2.1 V2 fields, replaces
its schema/version literals, and adds:

```text
arm_family_digest
resource_ledger_digest_at_launch
attempt_launch_digest
observed_thinking_state
thinking_observation_evidence_digest | null
```

```text
schema = plamen.provider-execution-observation.v3
observation_version = 3
```

Eligibility mapping:

- Opus/Sonnet `ADAPTIVE_ON` requires `ADAPTIVE_ON_CONFIRMED`.
- Haiku `MANUAL_ON` requires `MANUAL_ON_CONFIRMED`.
- Haiku `MANUAL_OFF` requires `MANUAL_OFF_CONFIRMED`.
- GPT-5.6 requires `NOT_APPLICABLE`.
- `UNOBSERVABLE` or `MISMATCHED` withholds strict eligibility when thinking
  state is part of the route contract.

The requested mode is never copied into the observed state.

## 5. Generation and attempt identity correction

### 5.1 Immutable retry rule

A retry preserves:

- semantic plan;
- provider arm family;
- backend arm/generation;
- exact model and effort;
- thinking mode;
- route, context, budget, launch authority, environment, source, prompt,
  methodology, tools, and common-grant reservation.

It changes only `ExecutionAttemptIdentityV2.attempt_ordinal`, `attempt_id`, and
the allowed retry reason. Ordinals begin at 1 in each backend-arm generation.

Changing model, effort, thinking, provider, transport, account, auth, service,
fallback policy, environment authority, semantic grant, source, prompt,
methodology, or tools cannot parse as a retry.

### 5.2 Escalation and transition

An R3-high result that triggers xhigh requires:

```text
same SemanticWorkPlanV2
same ProviderArmFamilyIdentityV1
new ModelRouteV2
new BudgetAuthorityV2 reservation under the same cumulative ledger
new LaunchAuthorityV1
new BackendArmExecutionIdentityV3 generation
attempt_ordinal = 1
```

Provider model/effort/fallback transition generation N closes backend-arm
generation N as debt. Any authorized continuation is backend-arm generation
N+1, not attempt N+1. Its attempt ordinal resets to 1.

Certifying evidence never merges across generations. Earlier proposal-only
evidence may remain provenance-linked, but the later generation independently
satisfies every certifying obligation.

Mode-policy wording is therefore:

```text
typed xhigh escalation requires a new backend arm/generation
with the same semantic plan and arm-family ledger
```

Fixtures prove changed effort/model cannot validate against a retry identity,
generation increment does not renew the common grant, and cross-generation
evidence cannot produce one certifying completion.

## 6. Atomic cross-generation resource authority

### 6.1 Provider arm family

`ProviderArmFamilyIdentityV1` is the stable resource family across all
generations for one semantic plan and provider:

```text
schema
arm_family_version
arm_family_id
arm_family_digest
semantic_plan_digest
common_resource_grant_digest
provider
evaluation_arm_label
```

Exact schema/version:

```text
schema = plamen.provider-arm-family-identity.v1
arm_family_version = 1
arm_family_id =
  "family:" + semantic_plan_id + ":" + provider
  + ":" + evaluation_arm_label

evaluation_arm_label =
  CLAUDE_CANDIDATE | CODEX_CANDIDATE
```

Account, transport, model, effort, and generation do not change the family and
therefore cannot renew its common grant. Claude and Codex have separate
families with the same semantic plan/common grant and are reconciled
independently. `ANTHROPIC` requires `CLAUDE_CANDIDATE`; `OPENAI` requires
`CODEX_CANDIDATE`.

### 6.2 Generation budget authority

`BudgetAuthorityV2` replaces the design-only R2.1 V1 schema:

```text
schema
budget_authority_version
budget_authority_digest
semantic_plan_digest
common_resource_grant_digest
context_budget_digest
arm_family_digest
resource_ledger_digest_at_compile
run_id
work_unit_id
generation
provider
account_mode
plan_or_price_class
requested_common_reservation
uncached_input_grant_tokens
cache_write_grant_tokens
cached_input_grant_tokens
output_grant_tokens_including_reasoning
reasoning_reserve_tokens
turn_limit
retry_limit
wall_time_limit_ms
tool_call_limit
model_owned_child_limit
driver_owned_work_unit_limit
plan_usage_observation_policy
currency_code | null
currency_micros_limit | null
pricing_snapshot_digest | null
user_exception_authority_digest | null
```

Exact schema/version:

```text
schema = plamen.budget-authority.v2
budget_authority_version = 2
```

`requested_common_reservation` uses the exact common resource vector in
Section 6.3. It is a request, not authorization. Launch requires the later
successful `RESERVE_GENERATION` event. The R2.1 fields
`historical_plan_usage_target_basis_points` and
`legacy_comparator_budget_digest` are forbidden; run targets and legacy
comparison belong to Section 7 evaluation records.

Currency code, limit, and pricing snapshot are either all null or all present
and obey Section 7.4. All R2.1 reasoning-as-output-subset and provider-token
ceiling invariants remain.

### 6.3 Ledger schema

`BackendSemanticResourceLedgerV1` is:

```text
schema
resource_ledger_version
resource_ledger_id
resource_ledger_digest
arm_family_digest
semantic_plan_digest
common_resource_grant_digest
ledger_revision
previous_ledger_digest | null
ledger_state
active_reserved_common_resources
reconciled_common_resources
remaining_common_resources
generation_entry_digests[]
attempt_entry_digests[]
last_event_sequence
last_event_digest | null
created_utc
updated_utc
```

Exact schema/version:

```text
schema = plamen.backend-semantic-resource-ledger.v1
resource_ledger_version = 1
resource_ledger_id = "ledger:" + arm_family_id
```

Closed `ledger_state`:

```text
ACTIVE
CLOSED
DEBT
```

Each common resource vector has exactly:

```text
source_payload_bytes
output_artifact_bytes
turns
retries
wall_time_ms
tool_calls
driver_owned_work_units
```

Every component is an R2.2 safe JSON integer. For every component:

```text
active_reserved + reconciled <= common grant
remaining =
  common grant - active_reserved - reconciled
```

An attempt can reconcile actual use above its reservation only by atomically
moving the ledger to `DEBT`; it never silently borrows or renews authority.

`GenerationResourceEntryV1` is:

```text
schema
generation_entry_version
generation_entry_digest
arm_family_digest
generation
budget_authority_digest
generation_reservation
unallocated_generation_reservation
active_attempt_allocation
reconciled_generation_use
token_budget_derivation_digest
entry_state
```

`AttemptResourceEntryV1` is:

```text
schema
attempt_entry_version
attempt_entry_digest
arm_family_digest
generation
attempt_identity_digest
generation_entry_digest
attempt_allocation
reconciled_attempt_use
entry_state
```

Exact schema/version:

```text
GenerationResourceEntryV1:
  schema = plamen.generation-resource-entry.v1
  generation_entry_version = 1

AttemptResourceEntryV1:
  schema = plamen.attempt-resource-entry.v1
  attempt_entry_version = 1

entry_state =
  RESERVED | ACTIVE | RECONCILED | RELEASED | DEBT
```

Generation entries partition the family ledger's active reservation. Attempt
entries partition their generation's reservation. The checked sums of all
active entries must equal the snapshot vectors.

### 6.4 Immutable event journal

Every mutation appends `ResourceLedgerEventV1`:

```text
schema
ledger_event_version
ledger_event_digest
arm_family_digest
event_sequence
previous_event_digest | null
expected_ledger_revision
idempotency_key
event_kind
generation
attempt_identity_digest | null
budget_authority_digest | null
reservation_delta
reconciliation_delta
token_budget_derivation_digest | null
event_utc
```

Exact schema/version:

```text
schema = plamen.resource-ledger-event.v1
ledger_event_version = 1
```

Closed `event_kind`:

```text
RESERVE_GENERATION
RESERVE_ATTEMPT
RECONCILE_ATTEMPT
RELEASE_UNUSED_RESERVATION
CLOSE_FAMILY
MARK_DEBT
```

`idempotency_key` is lowercase SHA-256 over:

```text
arm_family_digest
event_kind
generation
attempt_identity_digest | null
budget_authority_digest | null
reservation_delta
reconciliation_delta
token_budget_derivation_digest | null
```

Event semantics are exact:

- `RESERVE_GENERATION` moves its delta from family remaining to family active
  reservation and creates one generation entry. It requires the exact non-null
  BudgetAuthorityV2 digest and null attempt identity.
- `RESERVE_ATTEMPT` allocates within that generation's unallocated reservation;
  it does not increase family active reservation. Attempt and matching budget
  digests are non-null.
- `RECONCILE_ATTEMPT` moves actual use from active reservation to reconciled
  use and returns unused attempt allocation to the generation pool. Attempt and
  matching budget digests are non-null.
- `RELEASE_UNUSED_RESERVATION` returns unused generation reservation to family
  remaining after no active attempt can consume it; attempt identity is null.
- `CLOSE_FAMILY` requires no active attempt.
- `MARK_DEBT` preserves all prior accounting and prevents another launch until
  repaired.

### 6.5 Atomicity and recovery

The driver is the sole mutation authority. Each update:

1. acquires an OS-appropriate exclusive ledger lock;
2. reads and validates the complete hash-chained event prefix;
3. compare-and-swaps `expected_ledger_revision` and previous digest;
4. rejects a reservation exceeding any remaining common component;
5. appends and durably flushes the immutable event;
6. materializes a new snapshot to a temporary sibling;
7. durably flushes and atomically replaces the snapshot;
8. releases the lock.

A repeated identical idempotency key returns the original event/receipt and
does not mutate totals. Reuse with different canonical content is
`LEDGER_IDEMPOTENCY_CONFLICT`.

After interruption, resume/repair replays the longest completely valid
hash-chained prefix. A torn/unflushed tail is quarantined. It never reconstructs
a fresh zero ledger while a valid prior event exists. A CAS conflict retries
the prelaunch ledger mutation, not the provider semantic attempt. The driver
re-reads the ledger and recompiles BudgetAuthorityV2 plus the reservation event
against the new revision before constructing or launching the backend arm.

Unsupported filesystem locking, durable flush, or atomic replace capability
emits `LEDGER_ATOMICITY_UNAVAILABLE` for the affected arm family. The broader
pipeline continues, but no provider generation launches under that family.

Fixtures cover concurrent reservation, duplicate retry, crash before/after
event flush, crash before/after snapshot replace, stale CAS, resume, repair,
and Windows/Linux/macOS implementations.

### 6.6 Generation-local token derivation

Provider token budgets remain generation-local because models/tokenizers may
differ. They do not replace the family byte/resource ledger.

`TokenBudgetDerivationV1` is:

```text
schema
token_derivation_version
token_derivation_digest
arm_family_digest
generation
exact_model_id
tokenizer_or_counter_authority_digest
source_payload_digest
source_payload_bytes
output_artifact_bytes_reservation
system_prompt_digest
tool_definition_digest
history_digest
reserved_input_component_bytes
counted_input_tokens
requested_input_ceiling_tokens
requested_output_ceiling_tokens
derivation_method
rounding_policy
```

Exact schema/version:

```text
schema = plamen.token-budget-derivation.v1
token_derivation_version = 1
```

Closed values:

```text
derivation_method =
  PROVIDER_TOKEN_COUNT | PINNED_LOCAL_TOKENIZER | CONSERVATIVE_BOUND

rounding_policy =
  EXACT | ROUND_UP_ONLY
```

The family ledger reserves source/output bytes and common operational units
before generation launch. The generation budget then binds this exact
derivation. A fallback or xhigh generation uses remaining family authority; it
does not receive the original common grant again.

## 7. Separate resource denominators

### 7.1 Shared exact rational value

The arithmetic value embedded by both schemas is:

```text
numerator
denominator
ratio_state
```

Closed `ratio_state`:

```text
FINITE
NO_NUMERATOR_OR_DENOMINATOR_USE
UNBOUNDED_REQUIRES_REVIEW
UNOBSERVABLE
```

Rules:

- 0/0 -> `{0, 0, NO_NUMERATOR_OR_DENOMINATOR_USE}`;
- positive/0 -> `{positive, 0, UNBOUNDED_REQUIRES_REVIEW}`;
- zero/positive -> `{0, 1, FINITE}`;
- positive/positive -> reduce by gcd;
- missing authoritative value -> `UNOBSERVABLE`, never zero;
- finite comparison uses checked 128-bit cross multiplication.

### 7.2 Observed-to-grant reconciliation

`ObservedToGrantRatioV1` is:

```text
schema
observed_grant_ratio_version
observed_grant_ratio_digest
metric
aggregation_scope
numerator_usage_authority_digest
denominator_grant_authority_digest
numerator
denominator
ratio_state
```

Exact schema/version and closed scope:

```text
schema = plamen.observed-to-grant-ratio.v1
observed_grant_ratio_version = 1
aggregation_scope =
  ATTEMPT | GENERATION | ARM_FAMILY
```

`BudgetReconciliationV2` replaces the ambiguous R2.1 reconciliation:

```text
schema
budget_reconciliation_version
budget_reconciliation_digest
semantic_plan_digest
arm_family_digest
aggregation_scope
backend_arm_digest | null
attempt_identity_digest | null
budget_authority_digest | null
resource_ledger_digest
usage_receipt_set_digest
observed_grant_ratio_digests[]
budget_compliance_state
exceeded_metrics[]
reason_codes[]
```

```text
schema = plamen.budget-reconciliation.v2
budget_reconciliation_version = 2
```

Every ratio numerator is observed usage and every denominator is the exact
attempt allocation, generation reservation, or family ledger grant named by
its digest. Cross-field rules:

- `ATTEMPT`: backend arm, attempt, and budget digests are present.
- `GENERATION`: backend arm and budget are present; attempt is null.
- `ARM_FAMILY`: backend arm, attempt, and budget are null; the family ledger is
  the denominator.

`usage_receipt_set_digest` hashes only immutable `ProviderUsageV2` records and
native usage records, not ProviderExecutionObservationV3. Therefore the
observation may reference BudgetReconciliationV2 without a digest cycle. The
observation's `resource_ledger_digest_at_launch` is the reservation snapshot;
reconciliation names the later post-accounting ledger snapshot.

### 7.3 Candidate-to-legacy comparison

`PairResourceComparisonV1` belongs only to the neutral evaluator:

```text
schema
pair_comparison_version
pair_comparison_digest
evaluation_policy_digest
semantic_roster_digest
metric
comparison_basis
aggregation_scope
candidate_authority_digest
legacy_authority_digest
candidate_usage_receipt_set_digest
legacy_usage_receipt_set_digest
candidate_pricing_snapshot_digest | null
legacy_pricing_snapshot_digest | null
currency_code | null
numerator
denominator
ratio_state
```

Exact schema/version and closed values:

```text
schema = plamen.pair-resource-comparison.v1
pair_comparison_version = 1

comparison_basis =
  RESERVED_TO_RESERVED | OBSERVED_TO_OBSERVED

aggregation_scope =
  WORK_UNIT | PHASE | RUN
```

The numerator is always candidate; the denominator is always legacy.
`OBSERVED_TO_OBSERVED` requires both candidate and legacy usage receipt-set
digests. `RESERVED_TO_RESERVED` requires both grant-authority digests. Mixed
reserved/observed comparison is invalid.

### 7.4 Currency and pricing coupling

For every authority or usage record that carries an amount:

```text
currency_code = null iff currency_micros = null
```

For `BudgetAuthorityV2`, the paired amount field is
`currency_micros_limit`; currency code, limit, and pricing snapshot digest are
all null or all present. For usage records, if either currency member is
present, both are present. `currency_code` is an uppercase three-letter
ISO-4217 registry value. Currency micros is a safe JSON integer.

For `PairResourceComparisonV1`, `currency_code` and both pricing snapshot
digests are present exactly when `metric = CURRENCY_MICROS`; they are otherwise
null. Its numerator/denominator are the candidate/legacy currency-micros
amounts.

A pair comparison for money is legal only when:

- candidate and legacy currency codes are equal;
- both pricing snapshot digests are present and equal; and
- both money amounts are observed under those snapshots.

Otherwise the money ratio is `UNOBSERVABLE`. Subscription-plan usage is not
currency and never enters currency micros.

### 7.5 Run-level subscription target

The per-arm scalar in R2.1 is removed. `RunResourceEvaluationPolicyV1` is:

```text
schema
run_resource_policy_version
run_resource_policy_digest
evaluation_run_id
provider
evaluation_arm_label
account_mode
subscription_target_applicability
subscription_target_lower_basis_points | null
subscription_target_upper_basis_points | null
subscription_period
attribution_policy_id
resource_metric_set[]
```

Exact schema/version:

```text
schema = plamen.run-resource-evaluation-policy.v1
run_resource_policy_version = 1
subscription_period = WEEKLY
subscription_target_applicability =
  APPLICABLE | NOT_APPLICABLE
```

When applicable:

```text
0 <= lower <= upper <= 10000
lower = 1000
upper = 1500
```

The target applies to the complete Thorough audit run for the named backend and
account mode, not to each arm. When not applicable, both bounds are null.
Unattributable before/after plan telemetry is
`PLAN_CONSUMPTION_UNOBSERVABLE`; it cannot pass or fail the interval silently.

## 8. Field-scoped capability canary

### 8.1 Exact canary plan

`CanaryPlanV1` is:

```text
schema
canary_plan_version
canary_plan_id
canary_plan_digest
seed_manifest_digest
provider
transport
account_mode
auth_mode
provider_cli_executable_sha256
observed_provider_cli_version
exact_requested_model_id
requested_effort
effort_applicability
requested_thinking_mode
manual_thinking_budget_tokens | null
requested_service_tier
availability_fallback_policy_id
classifier_fallback_policy_id
model_transition_policy_id
child_policy
safety_case_ids[]
refusal_case_ids[]
fallback_case_ids[]
transition_case_ids[]
effort_case_ids[]
thinking_case_ids[]
service_case_ids[]
child_policy_case_ids[]
negative_case_ids[]
required_claim_fields[]
case_roster_digest
canary_tool_policy_digest
canary_input_fixture_set_digest
timeout_policy_digest
```

Exact schema/version:

```text
schema = plamen.capability-canary-plan.v1
canary_plan_version = 1
```

Every case ID resolves through a hash-frozen canary-case registry. The plan
binds positive and negative cases. An omitted required case makes the affected
claim `NOT_PROVEN`. All case-ID arrays, `required_claim_fields`,
`supporting_case_ids`, `executed_case_ids`, and field-claim digest arrays are
semantic sets ordered by Section 2.3.

`canary_plan_id` is:

```text
"canary-plan:" + sha256(
  RFC8785(CanaryPlanIdentityPreimageV1)
)
```

The exact preimage is:

```text
schema = plamen.canary-plan-identity-preimage.v1
identity_preimage_version = 1
seed_manifest_digest
provider
transport
account_mode
auth_mode
provider_cli_executable_sha256
observed_provider_cli_version
exact_requested_model_id
requested_effort
requested_thinking_mode
manual_thinking_budget_tokens | null
requested_service_tier
availability_fallback_policy_id
classifier_fallback_policy_id
model_transition_policy_id
child_policy
case_roster_digest
canary_input_fixture_set_digest
```

The preimage has no own digest field.

`case_roster_digest` hashes `CanaryCaseRosterV1`. Its exact fields are
`schema`, `case_roster_version`, `case_roster_digest`, all nine case-ID arrays,
and `required_claim_fields[]` from CanaryPlanV1. Its schema literal is
`plamen.canary-case-roster.v1`, its version is 1, and only its own digest field
is omitted from its digest preimage.

### 8.2 Field-level claim records

Each `CanaryFieldClaimV1` is:

```text
schema
canary_claim_version
canary_claim_digest
canary_plan_digest
manifest_field
seed_value_digest
proposed_value_digest
supporting_case_ids[]
evidence_digest_set_digest
claim_result
reason_codes[]
```

Exact schema/version:

```text
schema = plamen.canary-field-claim.v1
canary_claim_version = 1
claim_result =
  PROVEN | NOT_PROVEN | CONTRADICTED | NOT_APPLICABLE
```

Closed `manifest_field` values are:

```text
observed_provider_cli_version
provider_cli_executable_sha256
exact_model_id
model_identifier_class
effort_applicability
provider_supported_efforts
effort_observation_capability
effort_observation_bases
thinking_capabilities
context_window_tokens
provider_max_input_tokens
provider_max_output_tokens
service_tier_request_values
service_tier_observation_values
service_tier_observation_capability
actual_model_observation_capability
model_transition_observation_capability
refusal_observation_capability
safety_review_observation_capability
availability_fallback_observation_capability
classifier_fallback_observation_capability
child_policy
tool_capabilities
unsupported_features
```

A claim is `PROVEN` only when every required case for that field completed and
the evidence digest proves the proposed canonical value. Global canary process
success does not prove a field.

`seed_value_digest` and `proposed_value_digest` hash a
`CanaryFieldValueEnvelopeV1`:

```text
schema
field_value_version
manifest_field
canonical_field_value
```

```text
schema = plamen.canary-field-value-envelope.v1
field_value_version = 1
```

This prevents the same untyped JSON scalar from being replayed as a claim for a
different manifest field.

### 8.3 Canary receipt and post-canary manifest

`ProviderCapabilityCanaryReceiptV2` is:

```text
schema
canary_receipt_version
canary_receipt_digest
seed_manifest_digest
canary_plan_digest
canary_execution_utc
provider
transport
account_mode
auth_mode
exact_requested_model_id
requested_effort
requested_thinking_mode
requested_service_tier
availability_fallback_policy_id
classifier_fallback_policy_id
model_transition_policy_id
child_policy
executed_case_ids[]
field_claim_digests[]
canary_execution_result
raw_evidence_digest
```

Exact schema/version:

```text
schema = plamen.provider-capability-canary-receipt.v2
canary_receipt_version = 2
canary_execution_result =
  COMPLETE | PARTIAL | FAILED
```

`COMPLETE` means the plan completed; it is not a blanket capability PASS.
Strict capability is field-scoped to claims with `PROVEN`.

`COMPLETE` additionally requires every planned case ID in
`case_roster_digest` to appear in `executed_case_ids` and exactly one claim for
every `required_claim_fields` member. Each claim's supporting cases must be a
subset of executed cases. Otherwise the execution result is `PARTIAL` or
`FAILED`.

Post-canary construction:

1. freeze the seed manifest and plan;
2. execute only the later governed canary;
3. construct the receipt and field claims;
4. copy every seed-manifest field byte-for-byte;
5. change a field only when exactly one `PROVEN` claim names that field and
   its `seed_value_digest`/`proposed_value_digest` match;
6. set `seed_manifest_digest` and `canary_receipt_digest`;
7. compute the post-canary manifest digest.

Conflicting claims, an unclaimed mutation, or a claim for a field absent from
the closed enum is `CANARY_MANIFEST_PROMOTION_DEBT`.

Mutation fixtures attempt to add models, efforts, service tiers, observation
bases, fallback behavior, child permission, safety/refusal capability, tools,
and larger limits without a proven claim. Every case fails closed.

## 9. Exact launch authority and attempt envelope

### 9.1 Route and arm identity

The only route-ID formula is:

```text
route_id =
  "route:" + semantic_plan_id + ":" + provider + ":" + generation
```

No predeclared backend-arm ID is an input to this formula.

`ModelRouteV2` still contains no attempt ID/ordinal and no legacy profile.

`BackendArmExecutionIdentityV3` replaces the design-only R2.1 V2 record:

```text
schema
backend_arm_version
backend_arm_id
backend_arm_digest
semantic_plan_digest
common_resource_grant_digest
arm_family_digest
generation
arm_kind
model_route_digest
context_budget_digest
budget_authority_digest
launch_authority_digest
generation_reservation_event_digest
```

Exact schema/version and ID:

```text
schema = plamen.backend-arm-execution-identity.v3
backend_arm_version = 3
backend_arm_id =
  "arm:" + semantic_plan_id + ":" + provider + ":" + generation
```

The reservation event must be a successful `RESERVE_GENERATION` event for the
same family/generation and exact BudgetAuthorityV2 request. No provider process
launches before that join validates.

### 9.2 `LaunchAuthorityV1`

```text
schema
launch_authority_version
launch_authority_digest
semantic_plan_digest
arm_family_digest
generation
model_route_digest
provider_capability_manifest_digest
context_budget_digest
budget_authority_digest
generation_reservation_event_digest
effort_authority_digest | null
thinking_mapping_digest
sanitized_environment_authority_digest
loaded_customization_set_digest
forbidden_environment_keys_digest
tool_policy_digest
child_policy
ordered_argv_template_digest
stdin_prompt_template_digest
transport_policy_digest
safety_grace_policy_digest
```

Exact schema/version:

```text
schema = plamen.launch-authority.v1
launch_authority_version = 1
```

`effort_authority_digest` is required for Claude and null for Codex. All other
fields must equal the referenced route/manifest/semantic records. The launch
authority contains no attempt identity.

### 9.3 `AttemptLaunchEnvelopeV1`

```text
schema
attempt_launch_version
attempt_launch_digest
attempt_identity_digest
backend_arm_digest
launch_authority_digest
materialized_argv_digest
materialized_environment_digest
materialized_stdin_prompt_digest
working_directory_identity_digest
prepared_utc
```

Exact schema/version:

```text
schema = plamen.attempt-launch-envelope.v1
attempt_launch_version = 1
```

Materialization may substitute only the attempt-scoped paths/IDs authorized by
the templates. It cannot change provider/model/effort/thinking/service/tool/
source/methodology/resource authority. `ProviderExecutionObservationV3`
must bind the exact launched envelope through `attempt_launch_digest`.

## 10. Exact N0 budget authority

`NativeBudgetAuthorityV2` is the record behind `native_budget_digest`:

```text
schema
native_budget_version
native_budget_digest
semantic_plan_digest
common_resource_grant_digest
native_operation_id
native_executable_manifest_digest
source_payload_bytes_ceiling
output_artifact_bytes_ceiling
retry_limit
wall_time_limit_ms
tool_call_limit
driver_owned_work_unit_limit
```

Exact schema/version:

```text
schema = plamen.native-budget-authority.v2
native_budget_version = 2
```

Every component is equal to or more restrictive than the common grant. N0 has
no provider token, effort, model, service, fallback, price, or provider-plan
field. Native retries reconcile through the existing native attempt/receipt
lifecycle and cannot renew the common native WorkUnit grant.

`NativeExecutionArmV2.native_budget_digest` must resolve to this exact schema.

## 11. Deterministic route-debt identity

`RouteDebtIdentityPreimageV1` is:

```text
schema
debt_identity_version
semantic_plan_digest
backend_arm_digest | null
attempt_identity_digest | null
stage
debt_code
evidence_digest_set_digest
```

```text
schema = plamen.route-debt-identity-preimage.v1
debt_identity_version = 1
```

Construction:

```text
route_debt_id =
  "debt:" + sha256(
    RFC8785(RouteDebtIdentityPreimageV1)
  )
```

The preimage schema has no own digest field. Its strings obey R2.2 NFC rules.
Repeated observation of the same cause joins the same debt ID and updates
`first_observed_utc`/`last_observed_utc` under the route-debt record's
idempotent update rule. Different evidence, stage, code, arm, or attempt yields
a different ID.

`required_operator_action` does not participate in debt identity, though it
remains in the full route-debt digest.

## 12. Corrected fixtures and implementation order

### 12.1 Canonical and schema fixtures

Add red-to-green fixtures for:

- I-JSON safe boundary and wider-value rejection;
- Python/JavaScript/.NET golden hashes;
- reject-before-JCS identity NFC;
- pre-normalized free text;
- canonical UTF-8 set ordering;
- exact route ID and deterministic debt ID;
- LaunchAuthority and AttemptLaunchEnvelope joins;
- exact NativeBudgetAuthority resolution;
- both-null-or-both-present currency;
- source URL/hash preservation.

### 12.2 Effort and thinking fixtures

Add every Section 3 precedence source, including skill/frontmatter after the
intentional environment authority. Add exhaustive model/effort/thinking request
and observed-state matrices. No open "supported non-adaptive" branch remains.

### 12.3 Generation and ledger fixtures

Prove:

- xhigh/model/fallback change creates a new generation and attempt ordinal 1;
- changed effort/model cannot parse as retry;
- new generation uses the same arm-family ledger;
- concurrent generations cannot each reserve the full common grant;
- unique attempts reconcile once;
- idempotent resume/repair cannot renew or double-spend;
- unsupported atomicity degrades only the affected family;
- tokenizer changes alter local token derivation, not common byte authority.

### 12.4 Ratio and canary fixtures

Prove:

- observed/grant and candidate/legacy schemas cannot parse as each other;
- every ratio binds numerator/denominator authority and scope;
- paired observed ratios bind both usage receipt sets;
- run-level 1,000-1,500 basis-point bounds cannot attach to one arm;
- money comparison rejects currency/pricing mismatch;
- canary COMPLETE does not imply all fields proven;
- post-canary mutation needs one matching PROVEN field claim;
- negative child/refusal/safety/fallback cases are bound.

### 12.5 Safe order

1. Obtain fresh independent acceptance of this exact R2.2 hash.
2. Freeze source, executable registries, semantic schema, and legacy artifacts.
3. Add pure schemas/validators and cross-runtime golden vectors.
4. Add failing production-path fixtures.
5. Implement effort/thinking/launch authorities without changing launches.
6. Implement atomic resource ledger and recovery before any candidate launch.
7. Implement separate reconciliations and neutral pair comparisons.
8. Implement dry-run capability plans and field-scoped claims.
9. Propagate all digests through WorkerTransaction, PhaseIO, resume, repair,
   RunBundle, and evaluator.
10. Keep `legacy_claude_v1` as the only production default.
11. Shadow candidate routing.
12. Run governed canaries only at the later approved gate.
13. Run neutral held-out evaluation before any default change.

## 13. Sources added by R2.2

Primary sources:

- RFC 8785, JSON Canonicalization Scheme:
  https://www.rfc-editor.org/rfc/rfc8785.html
- RFC 7493, I-JSON:
  https://www.rfc-editor.org/rfc/rfc7493.html
- Anthropic effort:
  https://platform.claude.com/docs/en/build-with-claude/effort
- Anthropic extended thinking:
  https://platform.claude.com/docs/en/about-claude/models/extended-thinking-models
- Claude Code model and effort configuration:
  https://code.claude.com/docs/en/model-config
- Anthropic model overview:
  https://platform.claude.com/docs/en/about-claude/models/overview
- Anthropic migration guide:
  https://platform.claude.com/docs/en/about-claude/models/migration-guide

The dated OpenAI and Anthropic provider sources in R2.1 remain part of the
frozen baseline.

## 14. Definition of done and status

R2.2 is implementable only after an independent reviewer accepts:

- safe interoperable canonical numbers and one NFC policy;
- sealed Claude environment/CLI/frontmatter/settings/control precedence;
- closed current thinking mappings and observations;
- generation-not-retry escalation and transition;
- atomic family ledger across all generations and attempts;
- distinct observed/grant and candidate/legacy denominators;
- run-level plan-use interval;
- exact field-scoped canary promotion;
- exact launch/native/debt/currency identities;
- all preserved R2.1 lifecycle, Light, refusal, child, and cutover gates.

This guide makes no recall or precision claim. Route integrity, canaries, and
same-repository regressions are not recall evidence.

Current status:

```text
provider facts: accepted as dated inputs
B1: preserved PASS
B2: preserved PASS AS DESIGN
B3: corrected; fresh review required
B4: preserved PASS
B5: preserved PASS
B6: corrected; fresh review required
B7: corrected; fresh review required
architecture direction: preserved PASS
legacy_claude_v1: production default
semantic_v1 routing: experimental/not implemented
provider calls or audits authorized: none
cutover authorized: no
```

End of R2.2 correction.
