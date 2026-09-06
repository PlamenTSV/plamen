# Plamen backend model-routing engineering guide R2.1

Date: 2026-07-29

Status: corrected implementation specification; not a cutover authorization

Change boundary: documentation only. This guide does not change Plamen source,
provider configuration, audit repositories, provider state, or launch behavior.
It does not authorize a provider call or a live audit.

## 0. Governing boundary

R2.1 supersedes the executable specification in:

- `Plamen_Backend_Model_Routing_Engineering_Guide_R2_2026-07-29.md`
- SHA-256:
  `889d29fb5ceee4b986daa4cfabefe370be4068a434d0fc4d2e1693e108af860f`

It incorporates the blocking amendments in:

- `Plamen_Backend_Model_Routing_Engineering_Guide_R2_Independent_Review_2026-07-29.md`
- SHA-256:
  `21cec836fe9bab7821eadab7789620cb32c3d6bd3ad67b54529df86d55e9e6af`

The fresh independent review controls where it conflicts with R2. R2.1 retains
the accepted B1-B5 behavior and closes the B6-B7 ownership, identity,
canonicalization, execution-state, and arithmetic gaps. It also incorporates
the required child-authority, safeguard, refusal, effort-feasibility, and
cutover amendments.

Implementation must start by freezing the actual dirty-tree file hashes,
schemas, executable registries, and legacy launch artifacts. File names in this
guide describe ownership; they are not proof of current source state.

## 1. Engineering verdict and non-negotiable invariants

The model-routing program remains worth implementing behind `semantic_v1`.
The safe architecture is:

1. Compile exactly one backend-neutral semantic work plan.
2. Derive a provider-specific backend arm from that frozen plan.
3. Compile an exact model route, context budget, and budget authority inside
   the backend arm.
4. Derive one or more execution attempts from the immutable backend arm.
5. Observe actual provider execution without allowing provider output to
   rewrite expected identity.
6. Gate disposition and paired evaluation using the joined expected and
   observed records.

The following invariants are mandatory:

- `SemanticWorkPlan` contains no provider, model, transport, account, provider
  context, provider price, route, backend arm, or attempt identity.
- Claude and Codex arms for one paired work unit share one exact
  `semantic_plan_digest`.
- The route points one-way to the semantic plan. The semantic plan never points
  back to the route.
- Attempt ordinal exists only in `ExecutionAttemptIdentityV2`.
- Retry means the same backend arm and route plus a new attempt ordinal.
- Model, account, transport, semantic grant, source, prompt, methodology, or
  tool-policy change is a new backend arm or generation, not a retry.
- N0 is a native execution arm. It never uses fake provider/model sentinels and
  never constructs `ModelRouteV2`.
- Legacy remains outside all V2 semantic-route types.
- `max`, `ultracode`, provider-default effort, auto effort, unknown effort, and
  any effort above the user-approved `xhigh` ceiling are rejected.
- No model-owned audit child may run. The driver owns every agent as a separate
  WorkUnit and WorkerTransaction.
- No model transition is allowed inside one certifying semantic attempt.
- Refusal, safeguard pause/timeout/block, fallback, actual-model ambiguity,
  effective-effort ambiguity, service ambiguity, or capability mismatch cannot
  support `SAFE`, `REFUTED`, `DISMISSED`, or an equivalent terminal negative.
- Light mode cannot close a material or unknown-material R3 candidate
  negatively using R2 authority.
- Resource authorization uses frozen integer vectors and exact observations.
  It never uses `xhigh` work-unit count as the authority.
- `legacy_claude_v1` remains the production default until each candidate
  backend independently clears neutral held-out non-inferiority.

This program targets false-safe decisions caused by weak or ambiguous routes
and makes model/effort non-application observable. It does not prove that any
candidate model improves recall. Only governed, blinded, held-out evaluation
can establish that.

## 2. Dated provider facts

These facts seed capability manifests. They must be re-observed by a governed
canary before candidate-route evaluation.

### 2.1 OpenAI

Current official documentation identifies exact model IDs
`gpt-5.6-sol`, `gpt-5.6-terra`, and `gpt-5.6-luna`. The unsuffixed
`gpt-5.6` alias is forbidden. GPT-5.6 supports effort values through `max`, but
Plamen policy stops at `xhigh`.

Each current GPT-5.6 model page publishes:

- context window: 1,050,000 tokens;
- maximum input: 922,000 tokens;
- maximum output: 128,000 tokens.

The 272,000-input price boundary is a pricing threshold, not a context or input
limit. Requested and observed service tier are separate because the response
tier can differ from the requested tier. GPT-5.6 safeguards can pause, block,
or refuse legitimate dual-use work, so all GPT-5.6 routes require adverse-state
handling.

Official sources:

- https://developers.openai.com/api/docs/guides/latest-model
- https://developers.openai.com/api/docs/models/gpt-5.6-sol
- https://developers.openai.com/api/docs/models/gpt-5.6-terra
- https://developers.openai.com/api/docs/models/gpt-5.6-luna
- https://developers.openai.com/api/reference/resources/responses/methods/create
- https://developers.openai.com/api/pricing

### 2.2 Anthropic

Current official documentation identifies `claude-opus-5`,
`claude-sonnet-5`, and `claude-haiku-4-5-20251001`. Fable 5 is the most
capable widely released Anthropic model, but is not a default route because it
has no Plamen held-out evidence and materially higher public API pricing.

Current published limits are:

- Opus 5: 1M context and 128K maximum output;
- Sonnet 5: 1M context and 128K maximum output;
- Haiku 4.5: 200K context and 64K maximum output.

The Models API can expose maximum input and maximum output; a null
maximum-input fact remains null rather than being replaced with context size.
Effort does not apply to Haiku 4.5. Opus 5 and Sonnet 5 support effort through
`max`; Plamen rejects `max`.

Claude Code can apply distinct availability and content-classifier fallbacks.
The latter can move an Opus 5 cybersecurity request to Opus 4.8.
`CLAUDE_CODE_EFFORT_LEVEL` can override session effort, and organization policy
can cap effort. Structured refusal can arrive with successful transport.
Refusal handling applies to Haiku, Sonnet, and Opus.

Official sources:

- https://platform.claude.com/docs/en/about-claude/models/overview
- https://platform.claude.com/docs/en/about-claude/models/migration-guide
- https://code.claude.com/docs/en/model-config
- https://platform.claude.com/docs/en/api/models
- https://platform.claude.com/docs/en/about-claude/pricing

## 3. Identity and ownership topology

### 3.1 One-way graph

The normative graph is:

```text
CommonResourceGrantV1
          |
          v
SemanticWorkPlanV1/V2
  backend-neutral obligation, prompt, methodology, tools, outputs,
  semantic authority, risk, disposition authority, and common grant
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
          |
          v
DispositionEligibilityV1 and neutral evaluation
```

The route, context budget, and budget authority may each reference the frozen
semantic plan and common grant. No referenced upstream object may reference a
downstream digest.

### 3.2 Backend-neutral semantic plan

`SemanticWorkPlanV2` may add backend-neutral negative-risk and semantic
authority fields to V1. It must remain backend-neutral. Its exact allowed
semantic content is:

```text
schema
semantic_plan_version
semantic_plan_id
semantic_plan_digest
run_id
pipeline
mode
ecosystem
phase
subphase
work_unit_id
role_id
obligation_ids[]
prompt_digest
methodology_digest_set_digest
tool_policy_digest
source_snapshot_digest
program_facts_digest
output_contract_digest
semantic_tier_requirement
disposition_authority_requirement
negative_closure_risk
risk_reason_codes[]
common_resource_grant
```

`common_resource_grant` is an embedded `CommonResourceGrantV1`. The semantic
plan contains none of:

- provider or model;
- transport, account, or authentication mode;
- provider capability or canary identity;
- provider context, maximum input/output, tokenizer, or pricing;
- provider token budget or invoice projection;
- route, backend arm, generation, attempt, service tier, or fallback policy;
- requested or observed effort/thinking state;
- provider environment or executable identity.

The same semantic-plan bytes and digest are used for all paired provider arms.
A compiler that changes the semantic plan for one backend has produced a
different experiment and cannot call the arms paired.

### 3.3 Common resource grant

The embedded `CommonResourceGrantV1` uses provider-neutral units:

```text
schema
grant_version
grant_id
common_resource_grant_digest
source_payload_bytes_ceiling
output_artifact_bytes_ceiling
turn_limit
retry_limit
wall_time_limit_ms
tool_call_limit
model_owned_child_limit
driver_owned_work_unit_limit
```

All values are unsigned integers. `model_owned_child_limit` must equal zero for
`semantic_v1`. Provider token budgets are derived enforcement records; they do
not replace or mutate this common grant. For each evaluated backend, every
limit is cumulative for the semantic WorkUnit across all of that backend's
generations and retries, not renewed per attempt or fallback. Paired backends
each receive the same common grant and are reconciled separately.

### 3.4 Backend arm identity

`BackendArmExecutionIdentityV2` is the provider-specific generation identity:

```text
schema
backend_arm_version
backend_arm_id
backend_arm_digest
semantic_plan_digest
common_resource_grant_digest
generation
arm_kind
model_route_digest
context_budget_digest
budget_authority_digest
```

For a provider arm, `arm_kind = PROVIDER_MODEL`, all three provider-specific
digests are required. All three referenced records carry the same
`semantic_plan_digest`. Route and budget carry the same work-unit identity and
generation as the arm. Context carries the same capability-manifest digest as
the route and may be reused only when its complete canonical bytes are
identical.

N0 uses the separate native arm in Section 7. `BackendArmExecutionIdentityV2`
is not used to insert fake provider data into N0.

`generation` is a positive unsigned integer scoped to the semantic plan and
arm family. A model, provider, transport, account, authentication, semantic
grant, source, prompt, methodology, output contract, or tool-policy change
requires a new backend arm and generation.

### 3.5 Attempt identity

`ExecutionAttemptIdentityV2` is:

```text
schema
attempt_identity_version
attempt_id
attempt_identity_digest
backend_arm_digest
attempt_ordinal
retry_reason
```

`attempt_ordinal` is a positive unsigned integer, unique and monotonically
increasing within one backend arm. Attempt 2 preserves the backend-arm, route,
semantic-plan, context-budget, budget-authority, source, prompt, methodology,
tool-policy, and provider launch-configuration authorities from attempt 1. An
attempt-specific launch envelope may bind the new attempt identity, but cannot
change those authorities.

`retry_reason` is one of:

```text
INITIAL
TRANSIENT_TRANSPORT
PROVIDER_SAFETY_PAUSE_TIMEOUT
PROCESS_INTERRUPTION
EXPLICIT_OPERATOR_RETRY
```

A retry cannot change provider, model, effort, thinking mode, service tier,
account, transport, environment authority, fallback policy, common grant, or
semantic content. If any of those must change, close the attempt as debt and
create a new backend arm/generation.

Neither `attempt_id` nor `attempt_ordinal` appears in `ModelRouteV2`.

## 4. Canonical encoding and digest law

### 4.1 Types

All R2.1 records use:

- UTF-8 JSON;
- exact key sets;
- signed-free integers in the range 0 through 9,223,372,036,854,775,807;
- booleans;
- strings;
- arrays;
- explicit `null` only where this guide declares `| null`;
- no floats, decimal numbers, timestamps with local offsets, duplicate keys,
  NaN, infinity, or unknown fields.

Schema identifiers, enum values, IDs, and digest text are ASCII. Free-text
paths and provider evidence strings are normalized to Unicode NFC before
encoding. Absolute host paths are never identity fields unless a schema
explicitly requires a normalized project-relative path.

Times are UTC strings in the exact form `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
Durations are integer milliseconds. Currency is integer micros paired with an
ISO-4217 uppercase currency code. Token and byte counts are integers.

### 4.2 Canonical JSON

`PLAMEN_CANONICAL_JSON_V1` is:

1. Validate the record and every nested record before hashing.
2. Normalize all strings to Unicode NFC.
3. Apply RFC 8785 JSON Canonicalization Scheme object-key ordering and string
   serialization. Because R2.1 rejects floats, only its integer serialization
   path is legal.
4. Preserve array order unless the field is declared a set in Section 4.3.
5. Encode to UTF-8 without a byte-order mark or insignificant whitespace.

Every digest is lowercase hexadecimal SHA-256 over these canonical bytes.

For a record with its own digest field, the digest preimage is the complete
validated canonical record with only that record's own digest field omitted.
Nested record digests remain present. No other omission is permitted.

An envelope digest uses the exact named envelope schema and therefore hashes
its complete validated payload with only the envelope's own digest omitted.
Implementations must not invent undocumented exclusion lists.

### 4.3 Ordered and set arrays

The following are semantic sets and are normalized by sorting unique canonical
elements lexicographically before hashing:

```text
obligation_ids
risk_reason_codes
route_reason_codes
reason_codes
preserved_candidate_ids
provider_supported_efforts
thinking_capabilities
effort_observation_bases
service_tier_request_values
service_tier_observation_values
tool_capabilities
unsupported_features
source_document_urls
effort_override_environment_keys
```

Duplicate elements are invalid.

The following arrays preserve observed or authored order:

```text
ordered_model_observations
model_usage_rows
model_transition_notices
safety_events
provider_terminal_events
```

The normalized raw stream assigns a contiguous zero-based sequence to every
event. Projected observation rows retain that source sequence, are strictly
increasing and unique within their array, and may contain gaps. A projected row
without an exact source sequence is invalid except for the explicitly nullable
usage-row field below. `model_usage_rows` are ordered first by the first stream
sequence that names their exact model key, then by exact model ID. A usage-only
key has `first_observed_sequence = null` and sorts after sequence-bearing rows
by exact model ID. Transition, safety, and terminal notices remain in stream
order. `pricing_thresholds` are ordered by strictly increasing integer input
threshold; duplicate thresholds are invalid.

### 4.4 Schema literals and identity construction

The exact schema literals and version integers are:

| Type | `schema` literal | version |
| --- | --- | --- |
| Common resource grant | `plamen.common-resource-grant.v1` | 1 |
| Semantic work plan | `plamen.semantic-work-plan.v2` | 2 |
| Backend arm identity | `plamen.backend-arm-execution-identity.v2` | 2 |
| Attempt identity | `plamen.execution-attempt-identity.v2` | 2 |
| Capability manifest | `plamen.provider-capability-manifest.v2` | 2 |
| Canary receipt | `plamen.provider-capability-canary-receipt.v1` | 1 |
| Model route | `plamen.model-route.v2` | 2 |
| Context budget | `plamen.context-budget.v2` | 2 |
| Budget authority | `plamen.budget-authority.v1` | 1 |
| Exact ratio | `plamen.exact-ratio.v1` | 1 |
| Provider observation | `plamen.provider-execution-observation.v2` | 2 |
| Provider usage | `plamen.provider-usage.v2` | 2 |
| Budget reconciliation | `plamen.budget-reconciliation.v1` | 1 |
| Route debt | `plamen.route-debt.v2` | 2 |
| Native arm | `plamen.native-execution-arm.v2` | 2 |
| Native observation | `plamen.native-execution-observation.v2` | 2 |
| Legacy envelope | `plamen.legacy-observation-envelope.v1` | 1 |

The field named `manifest_version` is 2; `route_schema_version` is 2; all
other version fields equal the table. Any other literal or version is an
unknown schema, not a compatible alias.

Human-readable identity-chain IDs do not replace digests. They are
deterministic:

```text
semantic_plan_id =
  "swp:" + run_id + ":" + work_unit_id

grant_id =
  "grant:" + semantic_plan_id

route_id =
  "route:" + semantic_plan_id + ":" + provider + ":" + generation

backend_arm_id =
  "arm:" + semantic_plan_id + ":" + provider + ":" + generation

attempt_id =
  "attempt:" + backend_arm_id + ":" + attempt_ordinal

native_arm_id =
  "native:" + semantic_plan_id + ":" + native_operation_id + ":" + generation
```

The strings used in IDs must already satisfy the registry's ASCII identifier
grammar `[A-Za-z0-9._:-]+`. A collision or nonconforming identifier is typed
debt; it is never repaired by provider-specific rewriting.

## 5. Closed common enums

Unknown values fail closed as `SCHEMA_UNKNOWN_ENUM`. They are not mapped to a
nearest known value.

```text
pipeline =
  SMART_CONTRACT | L1

mode =
  LIGHT | CORE | THOROUGH

provider =
  ANTHROPIC | OPENAI

transport =
  CLAUDE_CODE_STREAM_JSON | CODEX_EXEC_JSONL

exact_candidate_model_id =
  claude-opus-5 | claude-sonnet-5 |
  claude-haiku-4-5-20251001 |
  gpt-5.6-sol | gpt-5.6-terra | gpt-5.6-luna

model_identifier_class =
  EXACT_PROVIDER_ID_NONIMMUTABLE | SNAPSHOT_PINNED

account_mode =
  CLAUDE_SUBSCRIPTION | ANTHROPIC_API |
  CHATGPT_ENTITLEMENT | OPENAI_API

auth_mode =
  CLAUDE_LOGIN | ANTHROPIC_API_KEY |
  CHATGPT_LOGIN | OPENAI_API_KEY

semantic_tier =
  R3_FRONTIER_REASONING | R2_STANDARD_REASONING |
  R1_ECONOMY_STRUCTURED | N0_NATIVE_DETERMINISTIC

disposition_authority =
  PROPOSAL_ONLY | POSITIVE_ONLY |
  TERMINAL_NEGATIVE_ELIGIBLE | NO_SEMANTIC_AUTHORITY

negative_closure_risk =
  NONE | MATERIAL | UNKNOWN_MATERIAL

effort_applicability =
  APPLICABLE | NOT_APPLICABLE

provider_effort_capability =
  none | low | medium | high | xhigh | max

requested_effort =
  low | medium | high | xhigh | not_applicable

thinking_capability =
  ADAPTIVE | MANUAL | NONE

requested_thinking_mode =
  ADAPTIVE_ON | MANUAL_OFF | MANUAL_ON | NOT_APPLICABLE

large_context_authorization =
  ROUTINE_CAPPED | LARGE_CONTEXT_APPROVED

observation_capability =
  STRUCTURED | DERIVABLE_FROM_STRUCTURED_EVENTS |
  NOT_EXPOSED | UNKNOWN_BLOCKED

model_effective_state =
  EXACT | MIXED | MISMATCHED | UNOBSERVABLE

effort_effective_state =
  EXACT | NOT_APPLICABLE | MISMATCHED |
  UNSUPPORTED | UNOBSERVABLE

effective_effort_observation_basis =
  PROVIDER_RESPONSE_FIELD | PROVIDER_STREAM_FIELD |
  VERIFIED_CLI_EFFECTIVE_CONFIG_FIELD |
  NOT_APPLICABLE | UNOBSERVABLE

transition_state =
  NONE_OBSERVED | AVAILABILITY_TRANSITION |
  CLASSIFIER_TRANSITION | UNTYPED_TRANSITION |
  OBSERVED_WITHOUT_NOTICE | NOTICE_WITHOUT_OBSERVED_CHANGE

fallback_outcome =
  NOT_CONFIGURED | NOT_TRIGGERED | BLOCKED |
  TRANSITIONED | AMBIGUOUS | UNOBSERVABLE

refusal_category =
  NONE_OBSERVED | STRUCTURED_MODEL_REFUSAL |
  STRUCTURED_CLASSIFIER_REFUSAL | BLOCKED_FALLBACK |
  PROVIDER_BLOCK | UNPARSEABLE_ADVERSE

safety_review_state =
  NONE_OBSERVED | PAUSE_OBSERVED | PAUSE_TIMEOUT |
  BLOCK_OBSERVED | UNOBSERVABLE_AFTER_SIGNAL

provider_terminal_category =
  COMPLETED | REFUSAL | SAFETY_BLOCK | SAFETY_PAUSE_TIMEOUT |
  TRANSITION_DEBT | TRANSPORT_ERROR | TIMEOUT |
  INCOMPLETE | UNKNOWN_ADVERSE

service_tier_state =
  EXACT | MISMATCHED | NOT_APPLICABLE | UNOBSERVABLE

usage_observation_state =
  EXACT | PARTIAL | UNOBSERVABLE | INVALID

budget_compliance_state =
  WITHIN_GRANT | EXCEEDED_GRANT | UNOBSERVABLE | INVALID

resource_metric =
  UNCACHED_INPUT_TOKENS | CACHE_WRITE_TOKENS | CACHED_INPUT_TOKENS |
  OUTPUT_TOKENS_INCLUDING_REASONING | REASONING_TOKENS_SUBSET |
  TURNS | RETRIES | WALL_TIME_MS | TOOL_CALLS |
  DRIVER_OWNED_WORK_UNITS | CURRENCY_MICROS

child_policy =
  DRIVER_ONLY_NO_MODEL_CHILDREN

arm_kind =
  PROVIDER_MODEL
```

Exact ecosystem, phase, subphase, role, obligation, tool-policy, and service
tier values come from a hash-frozen executable registry. The same applies to
pricing classes, fallback/transition/precedence policy IDs, plan-observation
policies, reason codes, and native operation IDs. A record must bind the
registry or policy digest that validated those values. There is no string
fallback.

Legal provider tuples are exact:

| Provider | Transport | Account/auth pairs |
| --- | --- | --- |
| `ANTHROPIC` | `CLAUDE_CODE_STREAM_JSON` | `CLAUDE_SUBSCRIPTION` + `CLAUDE_LOGIN`; `ANTHROPIC_API` + `ANTHROPIC_API_KEY` |
| `OPENAI` | `CODEX_EXEC_JSONL` | `CHATGPT_ENTITLEMENT` + `CHATGPT_LOGIN`; `OPENAI_API` + `OPENAI_API_KEY` |

Cross-provider tuple combinations are invalid. Fable is not in the candidate
model enum; adding it requires a new registry version, canary, and distinct
held-out arm rather than an alias substitution.

## 6. Exact provider schemas

The field lists in this section are exact. `| null` is the only nullable
notation. `[]` is an array. Nested type names mean the validated full nested
record or the named digest, as written.

### 6.1 `ProviderCapabilityManifestV2`

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
model_identifier_class
effort_applicability
provider_supported_efforts[]
effort_observation_capability
effort_observation_bases[]
effort_precedence_policy_id
effort_override_environment_keys[]
thinking_capabilities[]
context_window_tokens
provider_max_input_tokens | null
provider_max_output_tokens | null
pricing_class
pricing_snapshot_digest | null
service_tier_request_values[]
service_tier_observation_values[]
service_tier_observation_capability
actual_model_observation_capability
model_transition_observation_capability
refusal_observation_capability
safety_review_observation_capability
availability_fallback_observation_capability
classifier_fallback_observation_capability
child_policy
tool_capabilities[]
unsupported_features[]
source_document_urls[]
source_document_snapshot_digest
seed_manifest_digest | null
canary_receipt_digest | null
```

Manifest rules:

- Haiku has `effort_applicability = NOT_APPLICABLE` and an empty
  `provider_supported_efforts`.
- Opus 5 and Sonnet 5 list the provider-supported `low`, `medium`, `high`,
  `xhigh`, and `max`. GPT-5.6 manifests additionally list provider-supported
  `none`. Capability recording is not route authorization: `ModelRouteV2`
  independently forbids `none` and `max`, and permits only the user-approved
  requested-effort enum through `xhigh`.
- `provider_max_input_tokens` and `provider_max_output_tokens` may be null only
  when the provider schema or installed transport does not expose a trustworthy
  value. Null capability cannot authorize a request ceiling by itself.
- `service_tier_request_values` is the complete closed set for the exact
  provider/account/transport tuple. If the transport has no selectable tier,
  its sole member is `NOT_APPLICABLE`. A route value must be byte-equal to one
  member. `service_tier_observation_values` separately closes legal response
  values; an observed value outside it is `SERVICE_TIER_MISMATCH`.
- Every duplicated capability value in a route or observation must equal its
  referenced manifest. A mismatch yields `CAPABILITY_MISMATCH`.
- `child_policy` must equal `DRIVER_ONLY_NO_MODEL_CHILDREN`.

Canary construction is non-circular:

1. Build a seed manifest with both `seed_manifest_digest = null` and
   `canary_receipt_digest = null`.
2. The canary receipt binds that immutable seed manifest digest and records
   exactly what it tested.
3. Build a post-canary manifest with `seed_manifest_digest` equal to the tested
   seed and `canary_receipt_digest` equal to the receipt.
4. The receipt never claims to have tested the future post-canary manifest
   digest.

Documentation facts can seed a manifest but cannot claim live account
entitlement or observed execution.

`ProviderCapabilityCanaryReceiptV1` has the exact fields:

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
observed_provider_cli_version
provider_cli_executable_sha256
exact_requested_model_id
observed_model_evidence_digest
observed_effort_evidence_digest
observed_service_evidence_digest
observed_transition_evidence_digest
observed_refusal_evidence_digest
observed_safety_evidence_digest
observed_child_policy_evidence_digest
canary_result
reason_codes[]
raw_evidence_digest
```

`canary_result` is `PASS`, `PARTIAL`, or `FAIL`. Only `PASS` can support strict
capability, and only for fields actually proven by its named evidence digests.
`PARTIAL` and `FAIL` remain typed capability debt.

### 6.2 `ModelRouteV2`

`ModelRouteV2` exists only for `execution_profile = semantic_v1`.

```text
schema
route_schema_version
route_id
route_digest
execution_profile
registry_digest
semantic_plan_digest
common_resource_grant_digest
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
generation
provider
transport
account_mode
auth_mode
exact_requested_model_id
requested_effort
effort_applicability
provider_supported_efforts[]
requested_thinking_mode
manual_thinking_budget_tokens | null
requested_service_tier
availability_fallback_policy_id
classifier_fallback_policy_id
model_transition_policy_id
child_policy
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
output_contract_digest
context_budget_digest
budget_authority_digest
```

Route rules:

- `execution_profile` has the sole legal value `semantic_v1`.
- `route_id = "route:" + semantic_plan_id + ":" + provider + ":" +
  generation`. The semantic plan supplies the plan ID; provider and generation
  are route inputs. No backend-arm digest is used.
- `attempt_id` and `attempt_ordinal` are forbidden.
- Provider/model/transport/account/auth tuples must be exact manifest tuples.
- `provider_supported_efforts` must equal the referenced manifest array after
  set normalization.
- If applicability is `APPLICABLE`, requested effort must be a supported
  manifest member and one of `low`, `medium`, `high`, or `xhigh`. If it is
  `NOT_APPLICABLE`, the supported array is empty and requested effort is
  `not_applicable`.
- No aliases (`auto`, `default`, `latest`, family nicknames, unsuffixed
  `gpt-5.6`) are legal.
- `max`, `ultracode`, provider-default/auto effort, and unknown effort are
  illegal.
- Requested service tier must be a value in the referenced manifest or an exact
  route-specific `NOT_APPLICABLE`; implicit service is illegal.
- Fallback policy IDs separately describe availability and classifier behavior.
  A fallback that changes model cannot complete this route.
- `child_policy` must equal `DRIVER_ONLY_NO_MODEL_CHILDREN`.
- Every upstream semantic identity field must equal the referenced semantic
  plan. Any mismatch is construction debt.

`route_id` does not create a digest cycle because the backend-arm digest is not
part of the route. The deterministic ID uses the predeclared arm ID string, not
the future arm digest.

### 6.3 Thinking capability and requested execution

Capability and request are separate:

- The manifest declares `thinking_capabilities`.
- The route declares `requested_thinking_mode`.
- The launch record binds the exact provider argument/configuration.
- The observation records the execution evidence and whether it is observable.

Closed cross-product rules:

| Exact model family | Effort | Legal requested thinking |
| --- | --- | --- |
| Opus 5 / Sonnet 5 | low, medium, high | `ADAPTIVE_ON` or an explicitly supported non-adaptive mode proven by canary |
| Opus 5 / Sonnet 5 | xhigh | `ADAPTIVE_ON` only |
| Haiku 4.5 | not_applicable | `MANUAL_OFF` or `MANUAL_ON` |
| GPT-5.6 | low, medium, high, xhigh | `NOT_APPLICABLE` |

For `MANUAL_ON`, `manual_thinking_budget_tokens` is a positive integer and must
not exceed `output_grant_tokens_including_reasoning`. For every other mode it
must be null.

Haiku manual thinking is not inferred from effort. Haiku always carries
`requested_effort = not_applicable`; the manual state is explicit. For
`MANUAL_OFF`, no manual-thinking budget or provider flag may be emitted.

An Opus 5 or Sonnet 5 `xhigh` route with disabled/non-adaptive thinking is
invalid. The implementation must have cross-product fixtures for every exact
model, requested effort, requested thinking mode, and nullable budget state.

### 6.4 `ContextBudgetV2`

```text
schema
context_budget_version
context_budget_digest
semantic_plan_digest
common_resource_grant_digest
provider_capability_manifest_digest
context_window_tokens
provider_max_input_tokens | null
provider_max_output_tokens | null
request_input_ceiling_tokens
generation_output_ceiling_tokens
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

Each `pricing_thresholds` row is:

```text
input_tokens_exclusive_lower_bound
pricing_class
pricing_snapshot_digest
```

Rows sort by strictly increasing
`input_tokens_exclusive_lower_bound`. This represents a rule such as "above
272,000" without float or inclusive-bound ambiguity.

All count fields are non-negative integers. The implementation enforces:

```text
request_input_ceiling_tokens <= provider_max_input_tokens
  when provider_max_input_tokens is non-null

generation_output_ceiling_tokens <= provider_max_output_tokens
  when provider_max_output_tokens is non-null

request_input_ceiling_tokens + generation_output_ceiling_tokens
  <= context_window_tokens

source_payload_ceiling_tokens =
  request_input_ceiling_tokens
  - reserved_system_prompt_tokens
  - reserved_tool_definition_tokens
  - reserved_history_tokens
  - reserved_tool_result_tokens
  - reserved_compaction_tokens
  - reserved_safety_margin_tokens
```

Every subtraction is checked before evaluation; underflow is
`CONTEXT_BUDGET_INVALID`. Source payload must be positive for a model arm.
System, tool, history, tool-result, and compaction content consumes input.

GPT-5.6 static seeds retain context 1,050,000, maximum input 922,000, and
maximum output 128,000 as three fields. Ordinary work stays in a much smaller
operational class. For Claude, null maximum input stays null; it is never
replaced by context size.

### 6.5 `BudgetAuthorityV1`

```text
schema
budget_authority_version
budget_authority_digest
semantic_plan_digest
common_resource_grant_digest
context_budget_digest
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
wall_time_limit_ms
tool_call_limit
model_owned_child_limit
driver_owned_work_unit_limit
legacy_comparator_budget_digest | null
historical_plan_usage_target_basis_points
plan_usage_observation_policy
currency_code | null
currency_micros_limit | null
user_exception_authority_digest | null
```

All numeric fields are non-negative integers. The exact invariants are:

```text
reasoning_reserve_tokens
  <= output_grant_tokens_including_reasoning

visible_output_reserve_tokens =
  output_grant_tokens_including_reasoning
  - reasoning_reserve_tokens

model_owned_child_limit = 0

output_grant_tokens_including_reasoning
  <= generation_output_ceiling_tokens

turn_limit <= common_resource_grant.turn_limit
retry_limit <= common_resource_grant.retry_limit
wall_time_limit_ms <= common_resource_grant.wall_time_limit_ms
tool_call_limit <= common_resource_grant.tool_call_limit
driver_owned_work_unit_limit
  <= common_resource_grant.driver_owned_work_unit_limit
```

`reasoning_reserve_tokens` is a subset of the one output grant. It is not added
to it. The provider generation ceiling must be at least
`output_grant_tokens_including_reasoning`; no equation adds the reasoning
reserve a second time.

When the provider exposes a total output count including reasoning and a
reasoning subset:

```text
0 <= observed_reasoning_tokens <= observed_output_tokens_including_reasoning

observed_visible_output_tokens =
  observed_output_tokens_including_reasoning - observed_reasoning_tokens
```

If the provider exposes visible and reasoning counts separately:

```text
observed_output_tokens_including_reasoning =
  observed_visible_output_tokens + observed_reasoning_tokens
```

If it exposes only total output, the subset components remain null and total
reconciliation still applies. A caller must not manufacture a zero reasoning
count. If reasoning exceeds total, or visible plus reasoning differs from
total, emit `USAGE_SUBSET_MISMATCH`.

Provider token ceilings are derived from the common source/output byte ceilings
by the route-bound tokenizer/counter authority. The derived mapping and its
rounding direction are included in the budget-construction evidence. A provider
budget cannot expand the common grant or semantic authority. `retry_limit`
counts attempts after the initial attempt, so the greatest legal attempt
ordinal is `retry_limit + 1`.

Every grant in `BudgetAuthorityV1` is cumulative across the whole backend arm
generation, including all retries. It is not a fresh grant per attempt.
Attempt receipts record incremental use; deterministic arm reconciliation sums
each unique attempt identity once and compares the sum with the one authority.

### 6.6 Exact ratio arithmetic

Each resource comparison is `ExactRatioV1`:

```text
schema
ratio_version
metric
numerator
denominator
state
```

`state` is:

```text
FINITE
NO_LEGACY_OR_CANDIDATE_USE
UNBOUNDED_REQUIRES_REVIEW
```

For candidate `c` and legacy `l`:

1. If `c = 0` and `l = 0`, store `{0, 0,
   NO_LEGACY_OR_CANDIDATE_USE}`.
2. If `c > 0` and `l = 0`, store `{c, 0,
   UNBOUNDED_REQUIRES_REVIEW}`.
3. If `l > 0`, reduce by `gcd(c, l)`. Thus zero over positive is stored as
   `{0, 1, FINITE}`.

There is no float conversion or rounding. Compare finite ratios `a/b` and
`c/d` by comparing `a*d` with `c*b`. Input values are signed-free 63-bit
integers; aggregate sums and cross-products use checked unsigned 128-bit
intermediates. An aggregate above the signed-free 63-bit storage ceiling is
debt before ratio construction. A cross-product above unsigned 128-bit is also
debt. Neither case may saturate, wrap, round, or use a float.

The reserved-attention index is:

- `UNBOUNDED_REQUIRES_REVIEW` if any metric is unbounded;
- otherwise the greatest finite ratio by exact cross multiplication;
- `NO_LEGACY_OR_CANDIDATE_USE` if every metric is 0/0.

0/0 dimensions are excluded from a finite maximum. The full vector remains
authoritative; a scalar never hides an oversized dimension.

Metrics include uncached input, cache write, cached input, total output
including reasoning, reasoning subset, turns, retries, wall-time milliseconds,
tool calls, driver-owned WorkUnits, and currency micros when comparable.
Provider invoice data and subscription-plan use remain separate vectors.
Different currencies or pricing snapshots are not directly summed.

Reserved aggregates sum each unique backend-arm budget once across the paired
semantic-plan roster. Observed aggregates sum every actually launched unique
attempt, including retry, refusal, fallback, safety, timeout, and debt attempts;
evaluation exclusion never erases incurred use. Worker wall time is summed for
the attention vector. End-to-end run elapsed time is separate telemetry and is
not substituted for summed worker time. Aggregation order is ascending
`semantic_plan_digest`, `backend_arm_digest`, then `attempt_identity_digest`;
checked integer addition makes the result replayable independent of scheduling.

Historical Claude x20 use of 10-15 percent per Thorough audit is an operational
target, represented as 1,000-1,500 basis points. It is not a token conversion.
Absent attributable before/after telemetry yields
`PLAN_CONSUMPTION_UNOBSERVABLE`; the target cannot be marked passed.

### 6.7 `ProviderExecutionObservationV2`

```text
schema
observation_version
observation_digest
attempt_identity_digest
backend_arm_digest
route_digest
semantic_plan_digest
provider_capability_manifest_digest
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
observed_effective_model_id | null
effective_model_state
requested_effort
effort_applicability
provider_supported_efforts[]
observed_effective_effort | null
effective_effort_state
effective_effort_observation_basis
requested_thinking_mode
observed_thinking_mode | null
requested_service_tier
observed_service_tier | null
service_tier_state
availability_fallback_outcome
classifier_fallback_outcome
transition_state
refusal_category
safety_review_state
safety_events[]
provider_terminal_category
provider_terminal_events[]
usage
turns
retries
wall_time_ms
budget_reconciliation_digest
raw_stream_digest
```

An ordered model row is:

```text
sequence
event_uuid
event_actor
parent_tool_use_id | null
model_id
event_digest
```

`event_actor` is `ROOT_MODEL` or `MODEL_OWNED_CHILD`. Any
`MODEL_OWNED_CHILD` row is `MODEL_CHILD_POLICY_VIOLATION` under
`semantic_v1`, even if its model matches the root.

Every requested/provider/transport/account/auth/generation/attempt field must
equal the joined route, arm, and attempt records. The sanitized environment at
exec must satisfy the route-bound authority and equal that authority's expected
environment digest. The executable identity/version must satisfy the manifest
and minimum version. Divergence is route debt, never caller-authored repair.

A model-usage row is:

```text
model_id
first_observed_sequence | null
uncached_input_tokens | null
cached_input_tokens | null
cache_write_input_tokens | null
output_tokens_including_reasoning | null
reasoning_tokens_subset | null
usage_row_digest
```

A transition-notice row is:

```text
sequence
source_event_uuid
notice_category
from_model_id | null
to_model_id | null
notice_digest
```

`notice_category` is `AVAILABILITY`, `CLASSIFIER`, or `UNTYPED_ADVERSE`.

A safety-event row is:

```text
sequence
source_event_uuid
safety_event_category
observed_pause_ms | null
safety_event_digest
```

`safety_event_category` is `PAUSE`, `BLOCK`, `REVIEW_COMPLETE`, or
`UNTYPED_ADVERSE`.

A provider-terminal row is:

```text
sequence
source_event_uuid
provider_terminal_category
terminal_event_digest
```

An effective model is `EXACT` only when all required init, assistant, and usage
evidence proves one exact requested model and no transition or child event
exists. Requested model text is never copied into the observed field.

Effective effort is `EXACT` only when:

1. the basis is one of `PROVIDER_RESPONSE_FIELD`,
   `PROVIDER_STREAM_FIELD`, or `VERIFIED_CLI_EFFECTIVE_CONFIG_FIELD`;
2. an offline fixture has validated that basis for the exact
   provider/transport/CLI event schema;
3. a governed capability canary has shown that the installed account and
   transport expose the basis;
4. the observed value equals the requested value and is supported by the
   referenced manifest.

The proving event must occur inside, or be cryptographically/structurally bound
to, the exact attempt's raw stream and attempt identity. A canary or manifest
alone proves capability to observe; it does not prove a later attempt's
effective effort.

Command-line input, a clean environment, manifest support, or requested effort
alone is not proof of effective effort. If no eligible basis is exposed,
`observed_effective_effort = null`, state is `UNOBSERVABLE`, basis is
`UNOBSERVABLE`, and the arm is excluded from strict paired scoring.

For Haiku, observed effort is null, state is `NOT_APPLICABLE`, and basis is
`NOT_APPLICABLE`. Manual-thinking execution is observed separately. For N0,
there is no provider observation at all.

All capability arrays or applicability values duplicated in an observation
must equal the referenced manifest. A mismatch is `CAPABILITY_MISMATCH`.
`observed_service_tier = null` is legal only with service state
`UNOBSERVABLE` or `NOT_APPLICABLE`; a non-null value must occur in the
manifest's observation-value set. `observed_thinking_mode = null` is legal only
when the transport cannot expose the requested state, which withholds strict
eligibility for a route whose thinking state is required.

### 6.8 Usage and budget reconciliation

The nested `usage` object is `ProviderUsageV2`:

```text
schema
usage_version
usage_digest
uncached_input_tokens | null
cached_input_tokens | null
cache_write_input_tokens | null
output_tokens_including_reasoning | null
reasoning_tokens_subset | null
visible_output_tokens | null
tool_calls | null
currency_code | null
currency_micros | null
provider_plan_usage_basis_points | null
usage_observation_state
raw_provider_usage_digest
```

Null means not exposed, not zero. `EXACT` requires every field needed by the
route's budget policy. `PARTIAL` may support telemetry but not a strict budget
claim. `UNOBSERVABLE` cannot pass budget eligibility. `INVALID` includes subset
mismatch, negative/overflow input, unknown currency, or contradictory provider
rows. When model-usage rows and aggregate usage expose the same metric, their
checked sum must equal the aggregate value; mismatch is invalid rather than
silently choosing one source.

`BudgetReconciliationV1` is:

```text
schema
budget_reconciliation_version
budget_reconciliation_digest
semantic_plan_digest
backend_arm_digest
attempt_identity_digest
budget_authority_digest
provider_usage_digest
observed_turns
observed_retries
observed_wall_time_ms
observed_tool_calls
observed_driver_owned_work_units
budget_compliance_state
exceeded_metric | null
metric_ratios[]
legacy_comparator_budget_digest | null
plan_consumption_state
reason_codes[]
```

`metric_ratios` contains exactly one `ExactRatioV1` per comparable
`resource_metric`, in the enum order in Section 5. A metric absent from both
arms uses the exact 0/0 state. A metric absent from only one arm is
unobservable unless its authoritative observation explicitly proves zero.

`plan_consumption_state` is `EXACT`, `PARTIAL`, `UNOBSERVABLE`, or
`NOT_APPLICABLE`. No null token, time, turn, retry, tool, or money value is
converted to zero. The reconciliation digest named by the provider observation
must equal this record.

### 6.9 `RouteDebtV2`

Every prelaunch or runtime failure that prevents a certifying route emits:

```text
schema
route_debt_version
route_debt_id
route_debt_digest
semantic_plan_digest
backend_arm_digest | null
attempt_identity_digest | null
stage
debt_code
reason_codes[]
first_observed_utc
last_observed_utc
retryable
preserved_candidate_ids[]
required_operator_action
evidence_digest_set_digest
```

`stage` is:

```text
PLAN_COMPILE | ARM_COMPILE | PREFLIGHT | LAUNCH |
STREAM_OBSERVATION | COMPLETION | RESUME | REPAIR |
RECONCILIATION | EXPORT | EVALUATION
```

Core `debt_code` values are:

```text
SCHEMA_UNKNOWN_FIELD
SCHEMA_UNKNOWN_ENUM
DIGEST_MISMATCH
IDENTITY_MISMATCH
CAPABILITY_MISMATCH
CAPABILITY_CANARY_MISSING
CONTEXT_BUDGET_INVALID
BUDGET_AUTHORITY_INVALID
USAGE_SUBSET_MISMATCH
ARITHMETIC_OVERFLOW_DEBT
ROUTE_UNARMABLE
MODEL_MISMATCH
MODEL_TRANSITION_DEBT
MODEL_CHILD_POLICY_VIOLATION
EFFECTIVE_EFFORT_UNOBSERVABLE
EFFECTIVE_EFFORT_MISMATCH
SERVICE_TIER_UNOBSERVABLE
SERVICE_TIER_MISMATCH
MODEL_REFUSAL
PROVIDER_SAFETY_PAUSE_TIMEOUT
PROVIDER_SAFETY_BLOCK
FALLBACK_DEBT
TRANSPORT_INCOMPLETE
PLAN_CONSUMPTION_UNOBSERVABLE
```

Unknown debt codes are schema errors. A new code requires a schema version.
Route debt preserves candidates and halts only the affected semantic attempt.
It never fabricates phase completion or safety evidence.

## 7. Native N0 and legacy isolation

### 7.1 N0

N0 uses `NativeExecutionArmV2`, not `ModelRouteV2`:

```text
schema
native_arm_version
native_arm_id
native_arm_digest
registry_digest
semantic_plan_digest
common_resource_grant_digest
run_id
pipeline
mode
ecosystem
phase
subphase
work_unit_id
role_id
semantic_tier
native_operation_id
native_tool_policy_digest
native_executable_manifest_digest
native_budget_digest
generation
child_policy
```

Required values:

- `semantic_tier = N0_NATIVE_DETERMINISTIC`;
- `child_policy = DRIVER_ONLY_NO_MODEL_CHILDREN`;
- no provider/model/transport/account/auth/manifest/service/effort/thinking/
  fallback/observation field exists;
- no provider command is constructed;
- completion uses `NativeExecutionObservationV2`, not
  `ProviderExecutionObservationV2`.

`NativeExecutionObservationV2` is:

```text
schema
native_observation_version
native_observation_digest
native_arm_digest
semantic_plan_digest
native_operation_id
native_executable_manifest_digest
started_utc
completed_utc
exit_category
exit_code | null
output_artifact_digest | null
native_usage_digest
raw_execution_digest
```

`exit_category` is `COMPLETED`, `PROCESS_ERROR`, `TIMEOUT`, `INTERRUPTED`, or
`OUTPUT_INVALID`. Only `COMPLETED` with a valid output contract can satisfy the
native WorkUnit. `exit_code`, when present, is the platform result normalized
to unsigned 32-bit form before canonical encoding. No provider, model, effort,
thinking, service, fallback, safeguard, or provider-observation field is legal.

N0 has no fake `NOT_APPLICABLE` provider values. Schema union discrimination is
by record schema, not sentinel strings.

### 7.2 Legacy

`legacy_claude_v1` continues to use its frozen existing schemas, argv, prompt,
tool policy, receipts, and retry semantics. It is not a legal
`ModelRouteV2.execution_profile` value and is not wrapped in a V2 semantic plan
or backend arm.

Evaluation may create `LegacyObservationEnvelopeV1`:

```text
schema
legacy_envelope_version
legacy_envelope_digest
legacy_run_id
legacy_artifact_manifest_digest
legacy_launch_artifact_digest
legacy_completion_artifact_digest
legacy_resource_observation_digest | null
adapter_version
adapter_source_digest
```

The envelope hashes existing artifacts without changing them. It cannot inject
arguments, model/effort claims, semantic V2 identity, route identity, or
negative authority into the legacy control. Adapter uncertainty remains
explicit and can exclude a comparison.

## 8. Semantic route policy

### 8.1 Authority classes

| Authority | Claude candidate | Codex candidate | Requested effort |
| --- | --- | --- | --- |
| `R3_FRONTIER_REASONING` | `claude-opus-5` | `gpt-5.6-sol` | `high`; typed `xhigh` only |
| `R2_STANDARD_REASONING` | `claude-sonnet-5` | `gpt-5.6-terra` | `medium` or `high` |
| `R1_ECONOMY_STRUCTURED` | Haiku 4.5 or Sonnet 5 | `gpt-5.6-luna` | Haiku `not_applicable`; Sonnet/Codex `low` |
| `N0_NATIVE_DETERMINISTIC` | no model | no model | no route |

Claude R1 has two legal forms:

1. Haiku 4.5 with no effort argument and explicit `MANUAL_OFF` or
   budget-bound `MANUAL_ON`.
2. Sonnet 5 with requested effort `low` when an explicit low-effort reasoning
   contract is required.

Haiku plus `low` is rejected, not normalized.

### 8.2 Mode policy

| Mode | Discovery/provisional | Material terminal negative |
| --- | --- | --- |
| Light | R2 `medium`; R2 `high` on typed risk | R3, or remain `UNRESOLVED_NEEDS_R3_REVIEW` |
| Core | R2 `high`; selected R3 `high` | R3 `high`; typed `xhigh` may require a new attempt |
| Thorough | R2 `high`; R3 for hard depth/joins | R3 `high`; typed `xhigh` may require a new attempt |

Light reduces cost by retaining uncertainty, not by converting it to safety.

### 8.3 Objective negative-closure risk

`negative_closure_risk` is `MATERIAL` when any typed evidence indicates:

- confirmed mechanism;
- material asset/control reach;
- surviving proof or execution artifact;
- unresolved external, environment, or cross-chain premise;
- disputed harm or reachability;
- severity disagreement across evidence channels;
- candidate/report identity at risk of disappearance;
- unresolved negative methodology obligation;
- serious cross-component or cross-language composition.

Missing or contradictory risk evidence becomes `UNKNOWN_MATERIAL`, which has
the same closure-authority requirement as `MATERIAL`. A mutable Low or
Informational label cannot suppress an objective trigger.

### 8.4 Typed `xhigh`

`xhigh` is eligible only when:

1. a material terminal negative remains unresolved after R3 `high`;
2. demotion depends on an unresolved external/environment premise;
3. a confirmed mechanism has disputed material harm or severity;
4. independent channels disagree on exploitability, reachability, or harm;
5. a large composition trace remains incomplete after R3 `high`; or
6. a surviving candidate/proof would otherwise disappear.

Eligibility is not authorization. Budget authority must reserve the resources.
If unavailable, preserve `UNRESOLVED_NEEDS_XHIGH_REVIEW`.

### 8.5 Phase-family placement

Routing attaches to a compiled work unit and role, never only to a phase:

| Phase family | Base | Rule |
| --- | --- | --- |
| Bake/parser/graph/exact joins | N0 | Never launch a provider |
| Recon/instantiate/breadth | R2 | Selective R3 from typed seam/synthesis risk |
| Rescan/per-contract | R2 high | Do not economy-route recall repair |
| Planner/queue/manifest | N0 target | Transitional R1 has no disposition authority |
| Inventory chunks | R2 | Semantic consolidation only |
| Inventory final merge | R3 + N0 | Preserve all identity mechanically |
| Semantic invariants | R2 | R3 for disputed global invariants |
| Core depth | R3 | High baseline; typed conditional xhigh |
| Niche/attention repair | R2 | Bind to uncovered obligation denominator |
| Skeptic/negative challenge | R3 | No lower-tier material terminal negative |
| Semantic dedup | R3 proposal + N0 | Model groups; ledger never deletes |
| RAG/precedent | R2 | Precedent cannot control disposition |
| Chain/composition | R3 | Conditional xhigh on disputed multi-hop trace |
| Verify roster/aggregate/gates | N0 | Exact denominator; no model interpretation |
| Critical/High verification | R3 | Objective negative-risk rule |
| Medium verification | R2 positive, R3 negative | Authority follows disposition |
| Low verification | R2 in Thorough | R3 when objective material facts trigger |
| Skeptic-judge | R3 | Independent negative challenge |
| Reconciliation | N0 identity + R2 conflict | Never lose members |
| Severity adjudication shadow | R3 | xhigh only on typed material dispute |
| Report index | R3 plan + N0 completeness | Protect found-then-lost boundary |
| Report body | R2 | Cannot change identity/disposition/severity |
| Assembly/projection | N0 target | Transitional R1 has no semantic authority |
| Report floor | N0 | Policy, not prose |

The implementation fixture must enumerate every actual smart-contract and L1
pipeline/mode/ecosystem/phase/subphase/role row. Every row maps to exactly one
route/native arm or explicit debt. There is no default branch.

## 9. Launch, child, fallback, safeguard, and refusal rules

### 9.1 Driver-only child authority

Every `semantic_v1` launch binds:

```text
child_policy = DRIVER_ONLY_NO_MODEL_CHILDREN
model_owned_child_limit = 0
```

Provider configuration, imported user/workspace configuration, skills, role
files, and tool grants must not re-enable nested audit agents. The launch
preflight proves:

- child-spawn/model-agent tools are absent or denied;
- provider config is ignored or sanitized;
- every planned parallel agent has a separate driver-created WorkUnit,
  backend arm, WorkerTransaction, and attempt;
- no worker may delegate orchestration.

An observed provider-owned subagent event is adverse route debt regardless of
whether its model matches. The provider worker's root tool calls remain subject
to the exact tool policy; they are not child agents.

### 9.2 Claude launch and observation

Opus/Sonnet commands bind exact model and effort. Haiku binds the exact model
and omits effort. Before launch:

1. Build a fresh allowlisted environment.
2. Remove or fail closed on `CLAUDE_CODE_EFFORT_LEVEL`.
3. Remove model aliases/default overrides.
4. Bind allowed/forbidden key states and sanitized environment digest.
5. Bind minimum and observed Claude Code version.
6. Bind observable organization restrictions.
7. Deny model-owned agent spawning.

Organization caps mean environment plus argument proves requested effort, not
effective effort. Effective effort requires an eligible observation basis.

The stream parser collects in order:

- init model;
- every root assistant model;
- every model-owned-child event, which is immediately adverse;
- every `modelUsage` key and normalized record;
- typed availability/classifier transitions;
- typed refusal and safety events;
- effective-effort/service evidence where exposed.

Any model transition terminates the semantic attempt. Strict evaluation
excludes the arm and promotes no mixed-attempt evidence. Operational mode may
retain partial output as proposal-only, then create a newly authorized
generation with unchanged semantic obligation/source denominator. Evidence
from generations is never merged into one certifying attempt.

### 9.3 Codex launch and observation

The semantic command binds:

```text
codex exec
  --ignore-user-config
  --model <gpt-5.6-sol|gpt-5.6-terra|gpt-5.6-luna>
  -c model_reasoning_effort="<low|medium|high|xhigh>"
```

It also binds child-tool denial and the route's service/account authorities.
No retry may remove or mutate model/effort. Capacity, account, transport, or
model change creates debt or a new generation. Requested and observed service
tier remain separate. `--ignore-user-config` does not prove actual model,
effective effort, service tier, entitlement, or child-policy enforcement;
observation and production-path fixtures do.

### 9.4 Safeguards

Safety review is provider state, not semantic evidence. When the transport
exposes it, record `PAUSE_OBSERVED`, `BLOCK_OBSERVED`, or another exact
structured state. A bounded grace period may be added by transport policy. It:

- is bound before launch;
- changes no semantic or token budget;
- has a fixed integer millisecond ceiling;
- cannot be extended recursively by the worker.

A pause ending in timeout yields `PROVIDER_SAFETY_PAUSE_TIMEOUT`. A pause,
timeout, block, buffered/truncated result after a safety signal, or unknown
post-signal state cannot become completed-safe evidence.

### 9.5 Refusal

The invariant applies to every Claude model and every GPT-5.6 route, including
R1:

- structured provider refusal;
- structured classifier refusal;
- structured provider block;
- blocked fallback;
- incomplete/buffered output after a refusal or safety signal;
- unparseable terminal state after an adverse structured signal

is adverse and yields refusal or typed route debt. Successful process/HTTP
transport does not change that.

Natural-language lexical matching may raise a conservative review flag, but it
cannot by itself prove refusal, completion, safety, or negative eligibility.
Structured events and validated transport state are authoritative. A transport
without required structured refusal evidence is unobservable and ineligible
for strict pairing.

R1 refusal is incomplete/debt, not a successful projection. Partial useful
content may be retained as proposal-only with provenance, but may not certify a
positive or negative disposition.

## 10. Disposition eligibility

`DispositionEligibilityV1` values are:

```text
ELIGIBLE_POSITIVE
ELIGIBLE_TERMINAL_NEGATIVE
PROVISIONAL_ONLY
UNRESOLVED_NEEDS_R3_REVIEW
UNRESOLVED_NEEDS_XHIGH_REVIEW
PROVIDER_ROUTE_DEBT
MODEL_REFUSAL
MODEL_TRANSITION_DEBT
MODEL_CHILD_POLICY_VIOLATION
PROVIDER_SAFETY_DEBT
EFFECTIVE_EFFORT_UNOBSERVABLE
SERVICE_TIER_UNOBSERVABLE
CAPABILITY_MISMATCH
```

`ELIGIBLE_TERMINAL_NEGATIVE` requires:

- exact current semantic-plan/backend-arm/route/attempt digests;
- required R3 authority for material/unknown-material risk;
- required requested and effective effort;
- exactly one allowed actual model;
- no model-owned child;
- no transition, fallback, refusal, safeguard adverse event, or timeout;
- consistent usage model keys;
- required service and capability evidence;
- reconciled resource vector;
- independent negative adjudicator;
- complete candidate and evidence denominator.

`ELIGIBLE_POSITIVE` still requires a complete, non-refused attempt for promotion
as completed provider evidence. Partial adverse-attempt content remains
proposal-only.

Every failure preserves candidate identity, re-queue state, and evidence. It
halts only the affected attempt and never becomes safety evidence.

## 11. Implementation ownership and migration

Do not mutate legacy serialized meaning in place.

| Area | R2.1 ownership |
| --- | --- |
| Backend capability registry | V2 manifests, exact capability enums, seed/canary chain |
| Semantic work plan | Backend-neutral work, authority, risk, common grant only |
| Backend arm identity | Route/context/budget/launch digests and generation |
| Attempt identity | Attempt ordinal and retry reason only |
| PhaseIO/LaunchSpec | Exact arm and attempt digests; no caller-authored observation |
| WorkerTransaction | Carries semantic, arm, attempt, execution, completion, debt joins |
| Provider preparation | Environment, CLI, capability and child-policy preflight |
| Claude stream evidence | Ordered model/usage/transition/refusal/safety/effort evidence |
| Codex stream evidence | Exact model/effort/service/safety/refusal evidence |
| Driver | Sole agent owner; compiles routes; no model-owned children |
| RunBundle | Exports route/arm/attempt/observation/budget/debt without secrets |
| Neutral evaluator | Strict joins, exclusions, recall/precision/resource scoring |

Required migration rules:

- Freeze `plamen.semantic-work-plan.v1`. If V2 is introduced, it adds only
  backend-neutral authority/risk/common-grant fields.
- Add `BackendArmExecutionIdentityV2`; provider route/context/budget attach
  there, not to SemanticWorkPlan.
- Add `ExecutionAttemptIdentityV2`; ordinal appears nowhere else as expected
  identity.
- `ModelRouteV2` is `semantic_v1` only.
- Add provider observation and route-debt schemas without allowing callers to
  author actual-route facts.
- Keep RunBundle envelope compatibility through additive versioned record
  types.
- Legacy receives only the external observation envelope in Section 7.
- No historical artifact is rewritten.

## 12. Fixture-first checkpoints

Every checkpoint begins with failing production-path fixtures. Helper-only
tests are insufficient when a production caller is the defect.

### Checkpoint 0: freeze

Freeze:

- legacy Claude argv/prompt/tool-policy/receipt hashes;
- current Codex launch hashes;
- current backend-neutral semantic-plan schema/hash behavior;
- exhaustive SC/L1/ecosystem/mode/phase/subphase/role inventory;
- source hashes for every later touched module.

Pass: every executable WorkUnit maps to one native/provider route or explicit
debt in a dry run. No provider is invoked and no default branch exists.

### Checkpoint 1: topology, schemas, and digests

Fixtures prove:

1. SemanticWorkPlan rejects provider, route, context, budget, generation, and
   attempt fields.
2. Claude/Codex paired arms share byte-identical semantic plan/digest.
3. Route binds semantic plan one-way with no digest cycle.
4. Attempt ordinal is absent from route and arm.
5. Retry changes only attempt identity; route/arm digests remain stable.
6. Model/account/transport/grant change requires a new arm/generation.
7. Every field mutation changes its owning record digest.
8. Only the owning digest field is omitted from each preimage.
9. Set-array normalization and ordered-array preservation are deterministic on
   Windows, Linux, and macOS.
10. Unknown field/enum, duplicate key/set element, non-NFC identity, float, or
    out-of-range integer fails closed.
11. N0 uses `NativeExecutionArmV2`, has no provider fields, and launches none.
12. Legacy cannot parse as ModelRouteV2 or receive V2 semantic identity.
13. Exact RouteDebtV2 emits for an unarmable route.

### Checkpoint 2: capability and model cross-products

Fixtures prove:

1. Haiku plus any effort is rejected; `not_applicable` emits no effort.
2. Sonnet-low is legal for explicit R1.
3. `max`, `ultracode`, default/auto/unknown effort and model aliases fail.
4. Manifest/route/observation duplicated capability values must equal.
5. Missing canary evidence blocks strict eligibility.
6. Canary receipt binds the seed manifest, never its future post-canary digest.
7. Exact model/effort/thinking cross-product is exhaustive.
8. Opus/Sonnet xhigh requires adaptive thinking.
9. Haiku manual-on requires an exact positive budget; manual-off forbids one.
10. Null provider limits never become copied context limits.

### Checkpoint 3: context and exact resource arithmetic

Fixtures prove:

1. GPT-5.6 stores context, max input, and max output separately.
2. Input/output reservations cannot exceed provider or context ceilings.
3. Reasoning reserve is a subset of total output, never additive.
4. Visible plus reasoning reconciles to total where both are exposed.
5. Reasoning greater than total and false zero manufacture are debt.
6. Ratio cases cover positive/positive, zero/positive, positive/zero, and 0/0.
7. Ratios reduce by gcd and compare by checked cross multiplication.
8. 0/0 is excluded from finite maximum; unbounded dominates the scalar.
9. Integer overflow is debt on every supported runtime/OS.
10. 272K changes price class, not context capability.
11. API currency and subscription-plan use cannot be combined.
12. Missing attributed plan use cannot claim the 10-15 percent target passed.

### Checkpoint 4: child policy and provider observations

Fixtures run through production launch construction and prove:

1. Claude and Codex deny model-owned child creation.
2. Imported config, skills, roles, and provider defaults cannot re-enable it.
3. Every parallel agent is a separate driver-owned WorkUnit/transaction.
4. Any observed child event is route debt.
5. Claude effort override is absent and a late override aborts.
6. Init/assistant/usage model disagreement is transition debt.
7. Availability and classifier transitions remain distinct.
8. Operational transition closes N and can restart only as N+1.
9. No N+1 evidence merges into N.
10. Each claimed effective-effort basis has an offline stream fixture.
11. Unobservable effective effort excludes strict pairing.
12. Unsupported provider CLI/version/capability is debt.

### Checkpoint 5: safeguard, refusal, and timeout

For every Claude exact model and every GPT-5.6 exact model, fixtures prove:

1. Structured refusal on successful transport is adverse.
2. Classifier refusal, block, and blocked fallback are distinct adverse states.
3. Safety pause is observed where exposed.
4. Grace is fixed transport time, not semantic/token expansion.
5. Pause timeout cannot become completed-safe.
6. Buffered/truncated output after adverse signal is incomplete.
7. No lexical content heuristic can certify refusal or completion.
8. R1 refusal is debt, not successful projection.
9. Partial adverse output remains proposal-only.
10. Unknown terminal/adverse event fails closed.

### Checkpoint 6: Light and lifecycle preservation

Fixtures prove:

1. Light plus Low-labeled confirmed mechanism remains unresolved for R3.
2. Unknown-material risk remains unresolved.
3. R2 may generate positive/provisional candidates.
4. Terminal material negative needs independent eligible R3.
5. Typed xhigh trigger without budget remains unresolved.
6. Every adverse/debt state is mechanically barred from SAFE.
7. Report projection keeps unresolved candidates visible/re-queued.
8. Severity under-rating cannot suppress objective risk.
9. Semantic/arm/route/attempt/observation/budget/debt digests survive PhaseIO,
   WorkerTransaction, resume, repair, reconciliation, RunBundle, and evaluator.
10. R10 and all finding identity joins are unchanged.
11. Report-only workers cannot alter identity/disposition/severity.
12. Unsupported OS/provider/version degrades loudly without false completion
    or whole-pipeline halt.

### Checkpoint 7: independent review and full regression

At each checkpoint:

1. Freeze exact changed-file hashes.
2. Run focused fixtures.
3. Run blast-radius and full fast-lane suites.
4. Run serial/parallel concurrency tests where relevant.
5. Run clean install/package tests on supported Python/OS matrices.
6. Run fault-injection, interruption, resume, and repair tests.
7. Give the frozen denominator to a reviewer who did not author the diff.
8. Repair every blocker fixture-first and re-freeze.

No motivating repository case counts as recall evidence.

## 13. Safe implementation order

1. Independently accept this R2.1 artifact.
2. Freeze legacy artifacts and the backend-neutral semantic-plan schema.
3. Add pure schemas, validators, canonicalization, and red fixtures without
   changing launch behavior.
4. Add capability manifests, seed/canary chain, and route dry-run.
5. Add backend-arm identity with provider route/context/budget.
6. Add attempt identity with ordinal only there.
7. Add exact context, usage-subset, and ratio arithmetic.
8. Add Claude environment/model/effort/transition/refusal/safety observation.
9. Add Codex model/effort/service/safeguard/refusal observation.
10. Prove no-model-child and N0 behavior across OS launch paths.
11. Propagate digests through transaction, resume, repair, RunBundle, and
    neutral evaluation.
12. Run shadow mode only.
13. Run governed provider canaries to establish effective-effort feasibility.
14. Run held-out paired evaluation.
15. Keep legacy default until each backend independently clears every gate.

If neither current provider transport can prove effective effort per attempt,
candidate routing remains experimental. The strict gate must not be weakened
to make an A/B executable.

## 14. Held-out evaluation and cutover

Candidate routing remains behind `semantic_v1`.
`legacy_claude_v1` remains the production default.

Paired arms hold constant:

- one semantic plan and common grant;
- source snapshot;
- methodology and prompt;
- program facts;
- adaptive-attention roster;
- tool/native-command policy;
- candidate denominator;
- output/verification/report schemas;
- neutral grader and ground-truth boundary.

Each backend is scored independently. Claude and Codex results are not pooled
as one equivalent treatment.

Strict inclusion requires:

- exact semantic/arm/route/attempt joins;
- one exact model for one generation;
- eligible actual-model and effective-effort evidence;
- no child, transition, fallback, refusal, safety, service, or route debt;
- complete capability and budget receipts;
- no ground-truth exposure;
- no motivating regression repository in the scored corpus.

Measure:

- strict root-cause recall;
- never-found and found-then-lost misses;
- false-safe/demotion rate;
- methodology-obligation application;
- precision and root-cause fragmentation;
- severity calibration;
- proof execution honesty;
- report identity/completeness;
- token vector, turns, retries, time, and tool use;
- refusal/fallback/safeguard/route-debt rates;
- attributable plan consumption where observable.

Minimum release gates:

1. zero found-then-lost regression;
2. zero unauthorized terminal-negative closure;
3. zero silent model/effort/fallback/service/child drift;
4. no Critical/High held-out recall loss;
5. aggregate recall non-inferiority under a predeclared interval;
6. precision, severity, and report-completeness non-inferiority under
   predeclared margins;
7. normal Claude Thorough use stays near the observed 10-15 percent weekly
   target when attributable, unless measured recall/soundness gain and explicit
   user approval authorize more.

Cutover order:

1. Land schemas and observations with legacy behavior unchanged.
2. Shadow without disposition authority.
3. Clear offline fixtures and independent review.
4. Clear governed capability canaries.
5. Clear held-out R1/R2 non-inferiority per backend.
6. Clear R3 high per backend.
7. Clear typed xhigh last.
8. Preserve one-command legacy rollback through multiple ecosystem/backend/OS
   canaries.

No documentation, same-repository regression, capability canary, or vendor
benchmark authorizes cutover. The user remains the acceptance gate after
independent evidence.

## 15. Anti-bloat and non-goals

This program must not:

- encode protocol-specific vulnerability answers;
- increase every phase's model or agent count by default;
- let a model construct its own roster or children;
- replace independent verification/mechanical gates with self-check prose;
- convert deterministic queues, joins, projections, or gates into model work;
- claim exact model strings are immutable provider snapshots;
- claim API pricing predicts subscription-plan consumption;
- claim route integrity proves recall improvement.

Additional driver-owned agents require a typed uncovered obligation or
independent evidence channel. Stronger effort requires semantic risk plus
resource authority. No route may use `max`.

## 16. Definition of done

Backend routing is implementation-complete only when:

- B1-B7 each has a red-to-green production-path fixture;
- independent review accepts this one-way identity and schema specification;
- every SC/L1/ecosystem/mode/phase/role maps to one exact native/provider arm or
  explicit debt;
- SemanticWorkPlan remains backend-neutral and paired arms share it exactly;
- route/context/budget live only under backend-arm identity;
- attempt ordinal lives only under attempt identity;
- N0 and legacy isolation are proven;
- canonical digests and integer arithmetic replay across supported OSs;
- model/effort/thinking/service/child/safeguard/refusal state is observable or
  explicit debt;
- all lifecycle joins preserve candidate and finding identity;
- legacy hashes and behavior remain unchanged;
- focused, blast-radius, full, package, fault/recovery, cross-OS, and
  cross-ecosystem tests pass;
- neutral held-out A/B proves non-inferiority before any default change.

Until then:

```text
legacy_claude_v1: production default
semantic_v1 routing: experimental/not implemented
new model quality or recall claim: unproven
provider calls or audits authorized by this guide: none
cutover authorized: no
```

End of guide.
