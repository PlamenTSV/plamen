# Plamen backend model-routing engineering guide R2.3

Date: 2026-07-29

Status: consolidated executable design correction; not a cutover authorization

Change boundary: documentation and out-of-repository conformance artifacts
only. This package changes no Plamen repository, installed configuration,
provider state, audit repository, commit, launch, or production default. It
does not authorize a provider call or audit.

## 0. Normative package and precedence

R2.3 consolidates the accepted R2.2 design and closes every blocking issue in
its independent review. Implementers do not need to mentally merge R2.2 and
the review to obtain the corrected record shapes.

Frozen inputs:

- `Plamen_Backend_Model_Routing_Engineering_Guide_R2.2_2026-07-29.md`
  - SHA-256:
    `1077ca061f6cbbf93a4a9fb410cec9a0431ca3b5cf0a16366e113e3925e28a62`
- `Plamen_Backend_Model_Routing_Engineering_Guide_R2.2_Independent_Review_2026-07-29.md`
  - SHA-256:
    `fd08144e400297bec4e941c86072548ab6df6eaab3152f565d3244fdb0e712d4`

Normative R2.3 package:

- this guide: cross-record invariants, state transitions, lifecycle, policy,
  and implementation order;
- `Plamen_Backend_Model_Routing_R2.3_Schemas_2026-07-29.json`
  - SHA-256:
    `1da3f14c3e18325e818e3236cd1907a87f3032bbdeca5957fdc6fdfd1c0bedcf`
  - exact record key sets, types, enums, required values, and the event
    required/null/zero union;
- `Plamen_Backend_Model_Routing_R2.3_Conformance_Vectors_2026-07-29.json`
  - SHA-256:
    `6e9e0db8df0727dd37c78483151e62bd041f8951a1ddcf0d7698f367cd37d625`
  - golden and negative vectors;
- `validate_plamen_model_routing_r2_3.py`
  - SHA-256:
    `584fbc05a60929a761a1987928a8d97eb1931593d2c8445c42d3c622eb938581`
  - offline validator and reference resource reducer.

The schema bundle controls exact serialized shapes. This guide controls
cross-record equality, ordering, replay, and lifecycle rules not expressible
in JSON Schema. The vectors and validator define the minimum conformance
behavior. A production implementation may use another language only if it
passes the same expanded vectors byte-for-byte and error-for-error.

R2.3 replaces the R2.2 definitions of:

- Claude effort and thinking authority;
- token derivation and generation budget authority;
- generation and attempt resource entries;
- family resource ledger and event journal;
- launch authority, launch envelope, and observation;
- pair resource comparisons;
- canary evidence, field claims, and receipt;
- route debt.

Historical serialized records are not reinterpreted. R2.3 uses new schema
names or versions.

## 1. Preserved laws and scope

The following accepted rules remain mandatory:

- `SemanticWorkPlanV2` is backend-neutral. Provider, route, model, effort,
  context, service, price, budget, launch, generation, and attempt data never
  enter it.
- Paired Claude and Codex arms consume byte-identical semantic-plan bytes and
  the same semantic-plan digest.
- Route, context, budget, launch, generation, and attempt authority are below
  the provider arm family.
- Attempt ordinal belongs only to attempt identity.
- N0 is a native union member. It has no fake provider sentinels.
- Legacy remains outside semantic-v1 route, plan, arm, and attempt types.
- Actual model, fallback, transition, refusal, safety, service, effort, and
  thinking are observations, never copied from a request.
- Light cannot close a material or unknown-material negative without eligible
  R3 authority.
- Every child is a separately authorized driver-owned WorkUnit and
  WorkerTransaction. Model-owned audit children are forbidden.
- Refusal, safety pause/timeout/block, transition, fallback, capability
  mismatch, unobservable effort, or unobservable thinking cannot support a
  terminal safety claim.
- `max`, `ultracode`, provider-default/auto effort, and unknown model or
  effort values are forbidden. User policy caps deliberate reasoning at
  `xhigh`.
- `legacy_claude_v1` remains the production default until neutral, held-out
  non-inferiority clears a backend independently.
- A same-repository regression, a canary, schema conformance, or route
  integrity is not recall evidence.

The corrected identity graph is:

```text
CommonResourceGrantV1
  -> SemanticWorkPlanV2
  -> ProviderArmFamilyIdentityV1
  -> BackendSemanticResourceLedgerV2
  -> ModelRouteV2
  -> ContextBudgetV2
  -> TokenBudgetDerivationV2
  -> BudgetAuthorityV3
  -> LoadedCustomizationSetV1
  -> ClaudeEffortAuthorityV3              [Claude only]
  -> ClaudeProviderControlVectorV1        [Claude only]
  -> ClaudeThinkingAuthorityV1            [Claude only]
  -> LaunchAuthorityV2
  -> BackendArmExecutionIdentityV3
  -> ExecutionAttemptIdentityV2
  -> GenerationResourceEntryV2(RESERVED)
  -> RESERVE_ATTEMPT
  -> GenerationResourceEntryV2(ACTIVE)
  -> AttemptResourceEntryV2(RESERVED)
  -> post-reservation BackendSemanticResourceLedgerV2
  -> AttemptLaunchEnvelopeV2
  -> CONSUME_ATTEMPT_LAUNCH
  -> AttemptResourceEntryV2(LAUNCH_CONSUMED)
  -> post-consumption BackendSemanticResourceLedgerV2
  -> provider spawn
  -> ProviderExecutionObservationV4
  -> RECONCILE_ATTEMPT
  -> GenerationResourceEntryV2(ACTIVE, reconciled projection)
  -> AttemptResourceEntryV2(RECONCILED)
  -> post-reconciliation BackendSemanticResourceLedgerV2
  -> reconciliation, eligibility, and neutral evaluation
```

## 2. Canonical encoding and digest law

### 2.1 JSON profile

All signed or hashed records use the RFC 8785 JSON Canonicalization Scheme and
the I-JSON interoperable integer subset.

- Integers are inclusive `0..9007199254740991`.
- Negative integers, floats, exponent forms, NaN, infinity, negative zero,
  and integers outside the range are rejected.
- Lone UTF-16 surrogate escapes are rejected.
- JSON booleans are not integers.
- Object member names in this version are ASCII schema keys only. A non-ASCII
  member name or duplicate member is rejected before canonicalization. Within
  that restricted profile, member names are sorted by JCS.
- Serialization is UTF-8 without a BOM or insignificant whitespace.
- A record digest is lowercase SHA-256 of canonical bytes with its own digest
  member omitted.
- Referenced digests remain present.

The supplied validator is a restricted reference implementation for these
records. A production implementation must use a complete RFC 8785 library if
it later admits number types outside this restricted profile.

### 2.2 Unicode

Identity-bearing strings must already be NFC. Non-NFC identity input is
rejected; it is not silently normalized.

Identity-bearing strings include schema values, IDs, enums, provider/model/
transport/account/auth/service values, source IDs, paths before path hashing,
currency codes, event categories, and idempotency input.

Free text is normalized to NFC before record construction. In particular,
`required_operator_action` is pre-normalized and then treated as immutable.

### 2.3 Arrays

Arrays are either ordered sequences or semantic sets.

- Ordered sequences preserve declared order. Examples: customization
  precedence rows, event journal order, provider argument vector, and raw
  observation stream.
- Semantic sets are duplicate-free and sorted by the unsigned lexicographic
  order of each element's canonical UTF-8 bytes. Examples: digest member
  arrays in ledger snapshots and canary manifests.
- A producer must not sort by locale, platform path comparison, insertion
  order, or hexadecimal interpretation.

The vector `utf8-set-order` freezes the non-ASCII ordering rule.

## 3. Loaded customization closure

### 3.1 One authoritative inventory

Before launch preparation, the driver constructs exactly one
`LoadedCustomizationSetV1`. It is an ordered sequence of every configuration
source that was examined, including absent, ignored, and conflicting sources.
It is not a list of only successfully loaded files.

Each `CustomizationRow` is exact per the schema and records:

- its self-digest;
- contiguous zero-based `ordinal`;
- fixed numeric `precedence_rank`;
- `source_kind`;
- canonical source identity;
- canonical-realpath digest for an existing file-backed source, otherwise
  null;
- content digest for a present readable source, otherwise null;
- whether loaded;
- declared effort or null;
- thinking-controls digest or null;
- scan result.

Source-kind tie order is:

```text
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

`precedence_rank` must equal the zero-based index of `source_kind` in that
table. It is not producer-authored policy.

Rows sort by:

```text
(precedence_rank, source-kind tie rank, canonical UTF-8 bytes(source_id))
```

Ordinals must equal array positions. Source IDs and non-null
canonical-realpath digests are unique. Virtual sources (`ENVIRONMENT`,
`CLI_ARGUMENT`, `CONTROL_REQUEST`, and `SESSION_DEFAULT`) have null realpath.
An absent file source has null realpath and content; a present but unreadable
file has a realpath digest and null content. A symlink, case, junction, or
alternate-path alias that resolves to an already represented realpath is a
hard ambiguity, not a second source.

`customization_registry_digest` fixes the supported source-kind registry.
`CustomizationDiscoveryAuthorityV1` separately freezes and self-digests the
resolution root, registry, and exact ordered source instances expected before
content loading. `LoadedCustomizationSetV1.discovery_authority_digest` and
its source-identity projection must equal that independent authority.
`discovery_manifest_digest` then binds the authority to the format-aware scan
result, and `expected_row_count == len(rows)`. A producer cannot claim
closure by lowering its own count or hashing a partial list; missing and
extra rows fail the authority join. Every row and the containing set
recompute their own digest under section 2.

Row-state equations are exact:

- `ABSENT` and `NOT_APPLICABLE`: not loaded and all value/content/path fields
  null;
- `UNREADABLE`: not loaded, null content/value fields, and a realpath only
  when the file exists;
- `PRESENT_SHADOWED`: not loaded, non-null content, and at least one declared
  effort or thinking value;
- `PRESENT_EQUAL` and `PRESENT_CONFLICT`: loaded, non-null content, and at
  least one declared effort or thinking value.

The inventory parser must be format-aware:

- JSON and JSONC use a real parser;
- YAML/TOML/frontmatter use the grammar appropriate to that source;
- environment and CLI values are captured from the materialized launch
  authority;
- prose is never regex-parsed as configuration.

Unknown source, alias, post-scan mutation, malformed configuration, or
reordered precedence yields route debt and no candidate launch.

### 3.2 Exact join

For Claude:

```text
LaunchAuthorityV2.loaded_customization_set_digest
  == ClaudeEffortAuthorityV3.customization_set_digest
  == ClaudeThinkingAuthorityV1.customization_set_digest
  == digest(LoadedCustomizationSetV1)
```

The materialized environment and argument vector must be derived from this
same frozen inventory. Rescanning after authority construction is forbidden;
a content change requires a new authority and generation.

This closes the case where a scanner proved one source set but the launcher
used another.

## 4. Claude effort and thinking closure

### 4.1 Current request matrix

```text
Exact model          Requested effort                 Thinking request
claude-opus-5        low|medium|high|xhigh             ADAPTIVE_ON
claude-sonnet-5      low|medium|high|xhigh             ADAPTIVE_ON
claude-haiku-4-5     not_applicable                    MANUAL_ON|MANUAL_OFF
GPT-5.6 exact IDs    low|medium|high|xhigh             NOT_APPLICABLE
```

The aliases and exact IDs accepted by production must come from a separately
frozen provider manifest. The schema does not authorize a model merely
because a string parses.

For Opus 5 and Sonnet 5, R2.3 selects an explicit adaptive-thinking control.
For Haiku 4.5, manual thinking is explicit. `MANUAL_ON` requires a positive
exact manual token budget; `MANUAL_OFF` requires null and proves no manual
budget was emitted.

### 4.2 Precedence and competing controls

`ClaudeEffortAuthorityV3` binds the requested effort, winning source, complete
customization digest, and materialized control digests. No lower-precedence
source may conflict with the winner.

`ClaudeThinkingAuthorityV1` inventories each control that can alter thinking,
including:

- explicit adaptive-thinking request;
- `MAX_THINKING_TOKENS`;
- always-thinking toggle;
- manual-thinking token budget;
- environment;
- CLI arguments;
- user and project settings;
- session overrides;
- skill or agent frontmatter;
- provider control request.

`ordered_controls` is not one row per coarse category. For every ordered
`LoadedCustomizationSetV1` row, it contains exactly four control rows, in
control-name order, bound to that customization row's ordinal, source kind,
source ID, and row digest. Multiple settings files or frontmatter sources
remain distinct. `customization_row_count` and the ordered projection must
equal the actual typed customization set exactly inside the launch-seal join;
an opaque customization digest or a hard-coded source-kind list is
insufficient. Replacing, duplicating, or relabeling a source group fails even
after all downstream record digests are recomputed.

For `ADAPTIVE_ON`, the adaptive control is `EXPLICIT`; every competing manual,
maximum-token, and always-thinking control is either `PROVEN_ABSENT` or
present with exactly equal non-conflicting semantics. Unknown is not absence.

The selected R2.3 encoding is stricter: the single explicit winning adaptive
or manual control is the `CONTROL_REQUEST` row; every other source/control
pair is `PROVEN_ABSENT`. A later policy that permits present-equal duplicates
needs a new authority version and conformance vectors.

For Haiku, the manual control is exact and adaptive controls are proven
absent. For Codex, Claude thinking authority is absent and thinking is
`NOT_APPLICABLE`.

An unobservable or conflicting source produces route debt. It cannot be
repaired by copying requested state into observed state.

`ClaudeProviderControlVectorV1` is the canonical, self-digested launch
projection of exact model, effort authority/request, thinking mode, manual
budget, materialized argv, and materialized environment.
`ClaudeThinkingAuthorityV1` binds its digest. `LaunchAuthorityV2` binds both
effort- and thinking-authority digests, and
`AttemptLaunchEnvelopeV2` binds both the launch-authority digest and the exact
argv/environment digests. All projections must be equal before consumption.
Both Claude authorities and their customization-set digests must be exact and
`SEALED`; a correctly self-digested and fully propagated `DEBT` authority
still cannot authorize launch.
An arbitrary digest label, a recomputed authority pointing at another control
vector, or an envelope with different argv/environment is route debt.

### 4.3 One observation field

`ProviderExecutionObservationV4` contains only
`observed_thinking_state`. The R2.2 `observed_thinking_mode` field is
forbidden by `additionalProperties: false`; there is no dual-write or
projection.

Legal observations are:

```text
ADAPTIVE_ON_CONFIRMED
MANUAL_ON_CONFIRMED
MANUAL_OFF_CONFIRMED
NOT_APPLICABLE
UNOBSERVABLE
MISMATCHED
```

Confirmation needs independently captured provider/launcher evidence bound by
`thinking_observation_evidence_digest`. Request equality alone is not
confirmation. `UNOBSERVABLE` and `MISMATCHED` produce debt and cannot support
terminal safety.

Disposition also binds the self-digested `ClaudeThinkingAuthorityV1`,
`LaunchAuthorityV2`, consumed `AttemptResourceEntryV2`, and
`AttemptLaunchEnvelopeV2`. A non-adverse confirmation must match the launched
request exactly:

```text
ADAPTIVE_ON -> ADAPTIVE_ON_CONFIRMED
MANUAL_ON   -> MANUAL_ON_CONFIRMED
MANUAL_OFF  -> MANUAL_OFF_CONFIRMED
```

A different confirmed-mode label is not accepted as safe; the producer must
classify the disagreement as `MISMATCHED` and route it to debt.

The same disposition join carries `ClaudeEffortAuthorityV3`. A Claude
observation is non-adverse only when effective model state and effort state
are both `EXACT`, the observed model equals the thinking/effort authorities,
and observed effort equals the effort request. Mixed, mismatched, unsupported,
or unobservable model/effort evidence also follows the typed debt transaction;
thinking state is not the sole fail-closed axis.

`NOT_APPLICABLE` requires null thinking evidence. Every other observation
state, including both debt states, requires a non-null evidence digest.
`ProviderExecutionObservationV4` is self-digested; changing either state or
evidence invalidates the observation.

An `UNOBSERVABLE` or `MISMATCHED` observation cannot flow directly to
reconciliation or terminal-safety eligibility. Its exact digest must enter
`RouteDebtV3` evidence and a `MARK_CONSUMED_ATTEMPT_DEBT` event for the same
attempt, resource entry, and consumed launch. Only confirmed or policy-valid
not-applicable observations may enter ordinary reconciliation.

The debt event must additionally equal the consumed entry on arm family,
generation, budget authority, token-budget derivation, attempt identity,
and launch digest. The observation's reserved entry must be the entry bound by
the envelope, and the consumed entry must cite that exact reserved predecessor.
The debt event cites a typed `DEBT` attempt successor, whose predecessor is the
consumed entry, and that successor cites a typed `DEBT` generation successor.
Matching only the observation's loose labels is insufficient.

The debt event is accepted under exact CAS against the typed post-consumption
ledger. A typed post-debt snapshot must then cite the event and both DEBT
successors, preserve the resource totals, advance the journal by exactly one,
and set family state to `DEBT`. A self-digested event with a stale expected
revision is rejected. This snapshot chain is the mechanical evidence for the
claim that attempt, generation, and family fail closed atomically.

## 5. Exact budget derivation

### 5.1 Family authority

`BackendSemanticResourceLedgerV2.grant` is the single arm-family grant for:

```text
source_payload_bytes
output_artifact_bytes
turns
retries
wall_time_ms
tool_calls
driver_owned_work_units
currency_micros
```

The ledger is keyed by provider arm family, not model, effort, generation,
account retry, or transport retry. Model changes, fallbacks, and xhigh
escalations cannot renew it.

If money is governed, `currency_code` is a fixed ISO-style three-letter code
and `grant.currency_micros` is positive. If money is not governed,
`currency_code` is null and `currency_micros` is zero in `grant`,
`active_reserved`, `reconciled`, and `remaining`. Conversely, a non-null
currency code with a zero family grant is invalid. Pricing snapshots are
separately bound by budget and comparison authority; prices are not inferred
after execution.

### 5.2 Generation derivation

`TokenBudgetDerivationV2` records the deterministic inputs and resulting
`derived_token_grant`. It keeps context window, maximum input, maximum output,
request ceiling, reserved system/tool/output space, tokenizer identity, and
derivation policy distinct.

Required equations:

```text
usable_context
  = context_window
  - reserved_system
  - reserved_tools
  - reserved_output

input_grant
  <= min(maximum_input, usable_context, request_input_ceiling)

output_tokens_including_reasoning
  <= min(maximum_output, request_output_ceiling, reserved_output)

reasoning_tokens_subset
  <= output_tokens_including_reasoning
```

The exact provider-specific allocation equation is named by
`derivation_policy_digest` and executed with safe checked arithmetic. A
different tokenizer, model, context, or policy creates a different derivation.

`BudgetAuthorityV3.token_grant` must equal
`TokenBudgetDerivationV2.derived_token_grant` field-for-field. Approximation,
copying a previous generation, or accepting a smaller/larger independently
authored grant is forbidden.

The byte reservation is also exact:

```text
requested_family_reservation.source_payload_bytes
  == TokenBudgetDerivationV2.source_payload_bytes

requested_family_reservation.output_artifact_bytes
  == TokenBudgetDerivationV2.output_artifact_bytes_reservation
```

The authority joins the self-digested derivation, so its payload digest,
family, generation, context, tokenizer, and policy inputs cannot be replaced
while retaining the byte reservation.

### 5.3 No duplicated common grant

`BudgetAuthorityV3` has one `requested_family_reservation` resource vector.
It does not repeat unconstrained family limits in per-generation fields.

Before reservation:

```text
requested_family_reservation <= current family ledger remaining
```

The reservation includes `currency_micros`; therefore a second generation
cannot obtain a fresh monetary cap.

`RESERVE_GENERATION` is accepted only when its semantic plan, common grant,
budget, token derivation, arm family, and generation equal the self-digested
ledger and authorities; the budget's
`resource_ledger_digest_at_compile` equals the exact prestate; its reservation
delta equals `requested_family_reservation` field-for-field and fits within
prestate `remaining`; and currency code/value semantics match the ledger.
The typed event also satisfies
`event_sequence == prestate.ledger_revision` and
`previous_event_digest == prestate.last_event_digest`; abstract replay
coverage does not substitute for this cross-record CAS/journal join.
The event cannot independently invent a smaller, larger, or differently
dimensioned reservation.

## 6. Resource ledger exactness

### 6.1 Genesis

The only valid genesis `BackendSemanticResourceLedgerV2` snapshot has:

```text
ledger_revision                       0
ledger_state                          ACTIVE
active_reserved                       zero vector
reconciled                            zero vector
remaining                             grant
generation_entry_digests              []
attempt_entry_digests                 []
event_digests                         []
last_event_sequence                   null
last_event_digest                     null
```

All digest arrays are semantic sets, not journal order. The journal itself is
ordered by `event_sequence`.

### 6.2 Journal chain and CAS

The first event has:

```text
event_sequence             0
previous_event_digest      null
expected_ledger_revision   0
```

Every later accepted event has:

```text
event_sequence             prior sequence + 1
previous_event_digest      exact prior event digest
expected_ledger_revision   exact current ledger revision
```

Every non-genesis snapshot has:

```text
previous_ledger_digest     non-null exact prior snapshot digest
last_event_sequence        ledger_revision - 1
last_event_digest          non-null and a member of event_digests
len(event_digests)         ledger_revision
```

These are snapshot invariants in addition to the journal transition rules.
A snapshot cannot omit history, cite a foreign last event, or claim a
revision inconsistent with its event set.

Application is compare-and-swap. A stale revision fails
`LEDGER_CAS_LOST`. An already accepted idempotency key with byte-identical
event payload returns the existing post-state. Reuse with a different payload
fails `IDEMPOTENCY_CONFLICT`.

The reducer must check every vector operation for underflow, overflow, and:

```text
active_reserved + reconciled + remaining == grant
```

field-for-field.

### 6.3 Event required/null/zero union

All universal event fields are required. The machine schema enforces the
following exact variants:

| Event | generation | attempt | budget | derivation | attempt entry | launch | reservation | reconciliation | release |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RESERVE_GENERATION | value | null | value | value | null | null | value | zero | zero |
| RESERVE_ATTEMPT | value | value | value | value | value | null | value | zero | zero |
| CONSUME_ATTEMPT_LAUNCH | value | value | value | value | value | value | zero | zero | zero |
| RECONCILE_ATTEMPT | value | value | value | value | value | value | zero | value-or-zero | zero |
| RELEASE_ATTEMPT | value | value | value | value | value | null | zero | zero | value |
| RELEASE_UNUSED_GENERATION | value | null | value | value | null | null | zero | zero | value-or-zero |
| CLOSE_FAMILY | null | null | null | null | null | null | zero | zero | zero |
| MARK_FAMILY_DEBT | null | null | null | null | null | null | zero | zero | zero |
| MARK_GENERATION_DEBT | value | null | value | value | null | null | zero | zero | zero |
| MARK_RESERVED_ATTEMPT_DEBT | value | value | value | value | value | null | zero | zero | zero |
| MARK_CONSUMED_ATTEMPT_DEBT | value | value | value | value | value | exact consumed launch | zero | zero | zero |

`value-or-zero` permits a real zero-use reconciliation/release while still
requiring the explicitly present vector. A zero reservation for generation or
attempt is invalid at the semantic reducer even though each component is
individually schema-valid.

### 6.4 Entry states

Generation transitions:

```text
RESERVED -> ACTIVE
RESERVED -> RELEASED
ACTIVE   -> RECONCILED
ACTIVE   -> RELEASED
RESERVED -> DEBT
ACTIVE   -> DEBT
```

Attempt transitions:

```text
RESERVED        -> LAUNCH_CONSUMED
RESERVED        -> RELEASED
RESERVED        -> DEBT
LAUNCH_CONSUMED -> RECONCILED
LAUNCH_CONSUMED -> DEBT
```

Every `AttemptResourceEntryV2` carries the budget and derivation digests,
previous attempt-entry digest, and nullable/exact launch digest. `RESERVED`
has no predecessor or launch and zero use. `LAUNCH_CONSUMED` cites the exact
reserved predecessor and launch with zero use. `RECONCILED` cites the exact
launch-consumed predecessor and launch; its allocation equals the original
reserved allocation and its `reconciled_use` equals the reconciliation-event
delta. That equal use vector must also be componentwise less than or equal to
the original allocation under checked safe-vector arithmetic.

`GenerationResourceEntryV2` and every attempt-entry state are self-digested
typed records, not flattened digest labels. Generation entries are also
versioned: `previous_generation_entry_digest` is null only for `RESERVED`;
each `ACTIVE`, `RECONCILED`, `RELEASED`, or `DEBT` projection cites its exact
predecessor. Attempt reservation changes the generation projection from all
unallocated to an active allocation; launch consumption does not change the
resource totals; reconciliation returns unused allocation and moves actual
use into the reconciled projection.

For every snapshot, generation reservation must equal:

```text
unallocated generation reservation
+ reconciled generation use
+ sum(active attempt allocations)
```

The family ledger must project the same quantities: its grant equals the
generation reservation, `active_reserved` equals unallocated plus active
attempt allocation, `reconciled` equals generation reconciled use, and
`remaining` is the unreserved family grant. A snapshot that is internally
conservative but disagrees with these typed entries is invalid.

The portable lifecycle vector composes versioned generation entries and actual
RESERVED, LAUNCH_CONSUMED, and RECONCILED attempt entries with their
reserve/consume/reconcile events, three ledger snapshots, envelope, and
observation. Post-digest mutation, predecessor substitution, allocation
change, over-use, stale CAS, foreign-attempt envelope, unrelated observation
entry, snapshot substitution, and wrong family totals each fail
independently.

`RELEASE_ATTEMPT` is the only ordinary transition for a reserved attempt that
never launched. It returns the complete attempt allocation to the generation
before generation release. A consumed attempt cannot be released.
`MARK_RESERVED_ATTEMPT_DEBT` requires null launch authority.
`MARK_CONSUMED_ATTEMPT_DEBT` requires the exact consumed launch digest. Both
propagate generation and family state to DEBT atomically and do not free the
attempt allocation. A DEBT family cannot consume or launch another attempt.

`RECONCILED`, `RELEASED`, and `DEBT` are terminal for launch. A terminal
attempt can never be consumed or reconciled again.

Family transitions:

```text
ACTIVE -> ACTIVE
ACTIVE -> DEBT
ACTIVE -> CLOSED
```

`CLOSED` is terminal. `DEBT` is fail-closed for candidate launch; a separately
specified repair transaction may create a new verified ledger authority, but
ordinary events cannot silently return it to ACTIVE.

### 6.5 Deterministic replay

Replaying genesis and the canonical journal must reproduce the byte-identical
final ledger digest and every entry digest. Snapshot state is a cache, not
authority. A mismatch is ledger debt.

The supplied Python validator includes a reference reducer that constructs the
hash-chained journal, enforces exact sequence/previous digest/CAS/idempotency
ordering, updates family/generation/attempt state, checks conservation, and
emits a golden final-state digest. It covers launch, reconciliation, attempt
release/debt, generation release, family close/debt, duplicate launch,
cross-generation currency renewal, exact idempotent replay, stale revision,
broken journal links, invalid terminal transitions, and conflicting
idempotency payloads.

## 7. Reserve, consume, launch, observe

### 7.1 Two-step transaction

The only candidate launch order is:

1. Accept `RESERVE_GENERATION`.
2. Accept `RESERVE_ATTEMPT` under CAS.
3. Persist `AttemptResourceEntryV2` in `RESERVED`.
4. Persist the post-reservation ledger snapshot.
5. Construct and persist `AttemptLaunchEnvelopeV2`, binding the reservation
   event, attempt entry, and post-reservation snapshot.
6. Accept `CONSUME_ATTEMPT_LAUNCH` under CAS, binding the envelope digest.
7. Move the attempt entry to `LAUNCH_CONSUMED`.
8. Persist the post-consumption ledger snapshot.
9. Only now spawn the provider process.

The provider spawn primitive accepts only a successfully consumed
`AttemptLaunchEnvelopeV2`. It does not accept loose argv, environment, prompt,
route, or budget arguments.

If step 6 is repeated, the reducer returns
`ATTEMPT_LAUNCH_ALREADY_CONSUMED`. If the process crashes after consumption
and before spawn, recovery marks debt or follows a separately explicit
never-spawned release protocol; it never launches by guessing.

### 7.2 Envelope binding

`AttemptLaunchEnvelopeV2` binds:

- attempt and backend-arm identity;
- `LaunchAuthorityV2`;
- `RESERVE_ATTEMPT` event digest;
- reserved attempt-entry digest;
- post-reservation ledger digest;
- exact materialized argv, environment, stdin prompt, and working directory.

Every equality is checked before consumption. A reservation belonging to
another generation, attempt, ledger revision, or budget is rejected.

### 7.3 Observation binding

`ProviderExecutionObservationV4` binds:

- the consumed launch envelope;
- reservation event and the exact reserved attempt entry;
- the exact launch-consumed attempt entry as a separate field;
- post-reservation ledger snapshot;
- launch-consumption event;
- post-consumption ledger snapshot;
- raw stream and usage evidence.

The reserved and consumed entry digests have distinct meanings and cannot be
collapsed into one ambiguous field. The observation's two ledger digests must
equal the typed post-reservation and post-consumption snapshots, not merely
opaque digest labels supplied by the observer. An observation without all
transactional joins is ineligible. Prose that claims the test or provider ran
cannot replace these joins.

The post-consumption snapshot must be `ACTIVE`, remain on the exact semantic
plan and arm family authorized for launch, contain both the envelope-bound
reservation event and the consumption event, cite the current generation and
consumed attempt entries, and reproduce their resource projection. A
self-digested snapshot on another semantic plan, in `CLOSED`/`DEBT`, or with
the reservation predecessor omitted is not eligible for reconciliation.

Reconciliation extends the same join rather than beginning a new identity
chain. The `RECONCILE_ATTEMPT` event and reconciled entry must equal the
observation/reservation on arm family, generation, attempt, budget,
derivation, launch, and prior/current entry digests. The reconciled entry
cannot substitute an unrelated allocation, and its use vector must equal the
event delta field-for-field. The post-reconciliation ledger must cite the
reconciliation event, the reconciled attempt entry, and the successor
generation entry, and must reproduce their exact resource projection.

This is the mechanical answer to the R2.2 launch race: reservation is not just
documented; it is a consumed precondition of the only spawn API.

## 8. Resource comparison without basis confusion

R2.3 deletes the overloaded `PairResourceComparisonV1`. It provides two
disjoint record types:

- `ReservedPairResourceComparisonV1` compares candidate and legacy grant
  authorities.
- `ObservedPairResourceComparisonV1` compares candidate and legacy usage
  receipt sets.

Neither type contains nullable fields belonging to the other basis.
`additionalProperties: false` rejects over-population.

The metric is a closed `ResourceMetric`, not an arbitrary string:

```text
SOURCE_PAYLOAD_BYTES
OUTPUT_ARTIFACT_BYTES
TURNS
RETRIES
WALL_TIME_MS
TOOL_CALLS
DRIVER_OWNED_WORK_UNITS
CURRENCY_MICROS
UNCACHED_INPUT_TOKENS
CACHE_WRITE_TOKENS
CACHED_INPUT_TOKENS
OUTPUT_TOKENS_INCLUDING_REASONING
```

`ObservedToGrantUtilizationV1` is a third, one-arm record. It names:

- numerator usage authority;
- denominator authority type;
- denominator authority digest;
- aggregation scope.

Therefore candidate-to-legacy and observed-to-grant ratios cannot parse as
each other.

Observed-to-grant scope fixes denominator authority exactly:

```text
ATTEMPT    -> ATTEMPT_RESOURCE_ENTRY
GENERATION -> GENERATION_RESOURCE_ENTRY
ARM_FAMILY -> FAMILY_LEDGER
```

For a currency metric:

- both sides use the same non-null currency code;
- both pricing snapshot digests are non-null and equal;
- the aggregation scope is equal;
- both numerator and denominator are computed under that snapshot.

For a non-currency metric, currency and both pricing snapshots are null.
Cost is never reconstructed from current pricing after a run.

Subscription targets such as the accepted Thorough-run interval are run-level
policy claims. They cannot attach to one arm, one phase, or a reserved-vs-used
mixed denominator.

## 9. Canary evidence is transitive authority

### 9.1 Case results and manifest

`CanaryPlanAuthorityV1` is the self-digested required-case authority. Receipt
execution must cover its canonical required-case set.

`CanaryProofRuleAuthorityV1` is a self-digested, canary-plan-bound canonical
mapping from each claimable manifest field to its allowed proof-rule IDs.
Field rows and rule sets are canonical semantic sets. The authority digest is
bound by each case result, evidence manifest, field claim, and receipt.

Each executed canary case emits one `CanaryCaseResultV1`; the typed chain
carries `case_results[]`, not a privileged singular result. It provides:

- plan, proof-rule authority, and case identity;
- expected and observed outcome;
- raw artifact digests;
- proof-rule IDs actually satisfied.

`CanaryEvidenceManifestV1` contains the sorted semantic set of case-result
digests and the sorted union of all transitively cited raw artifact digests.
Its digest changes if a case result or raw artifact membership changes.

### 9.2 Field claims

A `CanaryFieldClaimV2` is valid only when:

1. its receipt and manifest digests join exactly;
2. every `supporting_case_result_digest` is a member of that manifest;
3. every supporting result has the named case ID;
4. every supporting result is `PASS`;
5. the receipt lists that case ID as executed and passed;
6. a satisfied proof-rule ID authorizes the exact claimed field;
7. every transitively cited raw artifact digest is in the manifest union.

Arbitrary evidence digests, failed cases, swapped case IDs, or prose summaries
cannot prove a field. A proof rule satisfied for one field cannot be reused
for another field even when the attacker recomputes the claim and receipt
digests.

A `PROVEN` claim has at least one support tuple. Parallel support arrays have
equal cardinality and canonical order. The manifest case-result set and raw
artifact set are duplicate-free canonical semantic sets. The raw-artifact
union equals the exact transitive union from case results, and
`raw_artifact_union_digest` recomputes from that ordered set.

### 9.3 Receipt

`ProviderCapabilityCanaryReceiptV3` binds the seed manifest, canary plan,
proof-rule authority, `evidence_manifest_digest`, executed case IDs, field
claims, and execution result. It separately binds `passed_case_ids`, which
must equal the PASS
projection of receipt-bound case results and be a subset of executed IDs. The
separately hashed plan binds executable, request, and transition policy under
the preserved R2.2 plan schema.
`COMPLETE` means execution completed. It does not mean every possible field is
proven.

The typed chain enforces the same composition rules as the flattened evidence
model: executed IDs equal the manifest case projection, passed IDs equal its
PASS projection, required plan cases are executed, support arrays have equal
cardinality and exact case/result/rule correspondence, and the manifest raw
set plus union digest equal the transitive union from all member results.
Case IDs and result digests are unique semantic sets. A valid two-case chain
and swapped-result/missing-required negatives prove the plural path.

Only a matching, valid `CanaryFieldClaimV2` may promote one field to PROVEN.
Post-receipt mutation invalidates the digest chain.

Canaries prove observability and route capabilities, not audit recall or
precision.

## 10. Route debt and adverse state

`RouteDebtV3` uses deterministic identity over:

- semantic plan and arm family;
- provider generation and attempt where known;
- failed authority or join;
- stable reason code;
- evidence digest set;
- required operator action.

Debt reasons include at least:

```text
CUSTOMIZATION_SOURCE_AMBIGUOUS
CUSTOMIZATION_DIGEST_MISMATCH
THINKING_CONTROL_CONFLICT
THINKING_UNOBSERVABLE
TOKEN_BUDGET_DERIVATION_MISMATCH
FAMILY_GRANT_EXHAUSTED
LEDGER_CAS_LOST
LEDGER_REPLAY_MISMATCH
ATTEMPT_NOT_RESERVED
ATTEMPT_LAUNCH_ALREADY_CONSUMED
LAUNCH_OBSERVATION_JOIN_MISMATCH
CAPABILITY_EVIDENCE_NOT_MEMBER
REFUSAL
SAFETY_BLOCK
SAFETY_PAUSE_TIMEOUT
TRANSITION_DEBT
UNKNOWN_ADVERSE
```

Repair-then-degrade remains the pipeline policy: deterministic infrastructure
failure does not erase analysis artifacts, but candidate routing fails closed
and the run gets an explicit human-review item. Debt is not terminal safety.

## 11. Closure of the seven review blocks

| Review block | R2.3 closure | Executable evidence |
| --- | --- | --- |
| Reservation not consumed by launch | budget-to-generation reservation, two-step attempt reserve/consume, spawn-only consumed envelope, and reconciliation back to the same allocation | wrong-delta/stale-budget, missing-reservation, duplicate-launch, unrelated-entry, and allocation/use vectors |
| Duplicate thinking evidence and unsealed controls | observation V4 has one field and debt-disposition law; exact effort/thinking authorities bind a typed provider-control vector through launch argv/environment | observation evidence/debt, sealed-authority, control-vector, argv, environment, and thinking-control vectors |
| Customization set underspecified | separately frozen discovery authority, exact ordered schema, parser rule, uniqueness, alias guard, and typed launch equality | missing/extra/reordered and digest-mismatch vectors |
| Duplicate/unconstrained budgets and renewable money | BudgetAuthorityV3 has one reservation, exact token and byte derivation equality, family-wide currency ledger | token/byte joins, currency-unit vectors, and cross-generation renewal vectors |
| Ledger not exactly replayable | exact vector, genesis and non-genesis snapshot laws, event union, CAS, state transitions, journal chain, reference reducer | snapshot, schema event variants, and transaction vectors |
| Pair comparison basis contradiction | separate reserved and observed types | valid observed and over-populated negative vectors |
| Canary claims not tied to receipt evidence | required-case plan authority, plan-bound proof-rule authority, receipt projection, transitive raw union, exact field/rule join | member, arbitrary, failed, swapped-case, missing-execution, raw-substitution, and recomputed wrong-field vectors |

No closure depends on a protocol name, audit finding, model prose, or regex over
Markdown.

## 12. Required implementation sequence

This is an implementation gate sequence, not authorization to begin cutover:

1. Independently review this exact guide, schema, vector, and validator hash
   set.
2. Vendor or pin a complete JCS implementation in every supported runtime.
3. Run the supplied validator unchanged on Windows, Linux, and macOS with all
   supported Python versions.
4. Port schemas to production types while keeping unknown-field rejection.
5. Add `LoadedCustomizationSetV1` and format-aware discovery in dry-run mode.
6. Add Claude effort/thinking authorities and prove the three-way digest join.
7. Add pure token derivation and BudgetAuthorityV3; do not launch candidates.
8. Add ledger genesis, event union, CAS reducer, persistence, replay, and
   crash-injection tests.
9. Add reserve/envelope/consume launch preparation behind a non-spawning test
   adapter.
10. Make the real spawn API accept only a consumed envelope.
11. Add observation V4 and reconciliation.
12. Add the disjoint comparison types.
13. Add canary case-result/manifest/claim/receipt chain.
14. Propagate all digests through WorkerTransaction, PhaseIO, resume, repair,
    RunBundle, evaluator, packaging, and BB wrapper surfaces.
15. Run exact-tree and cross-OS packaging checks.
16. Keep `legacy_claude_v1` as production default.
17. Shadow candidate routing, then governed canaries.
18. Run neutral held-out evaluation before any backend default decision.

At each step:

- write red fixtures before the production change;
- run local unit, integration, crash, resume, packaging, and existing
  repository suites;
- independently review the diff;
- reject a checkpoint if legacy behavior changes outside the approved slice;
- preserve a deterministic rollback to the last accepted authority version.

## 13. Minimum additional fixtures

The 186 supplied vectors are the portable semantic minimum. Production also
needs:

- two simultaneous reservations against one remaining grant;
- two simultaneous consume attempts for one envelope;
- crash before reservation persist;
- crash after reservation and before envelope;
- crash after envelope and before consumption;
- crash after consumption and before process spawn;
- crash after spawn and before observation persist;
- journal truncation, reordering, duplication, and foreign-event splice;
- snapshot corruption with valid journal recovery;
- idempotency reuse with a different payload;
- vector underflow and I-JSON overflow in every resource field;
- currency cap spanning model, effort, transport, and account changes;
- settings/frontmatter/session aliases and post-scan mutation;
- unknown Claude thinking controls;
- requested state copied into observation;
- old observation field injected into V4;
- reservation from another attempt/generation;
- reserved-entry/consumed-entry observation substitution;
- post-reservation/post-consumption observation-ledger substitution;
- temporally impossible generation-entry or family-ledger projection;
- stale consume CAS with otherwise consistently rehashed descendants;
- observed and reserved comparison type confusion;
- canary manifest addition/removal/reordering and raw-artifact substitution;
- refusal, safety, fallback, transition, and unobservable paths;
- Light R3 material-negative prohibition;
- model-owned child rejection;
- Windows path/case/junction and POSIX symlink cases.

Fuzz the reducer as a state machine. The oracle is replay equality plus
conservation, single consumption, and terminal-state invariants.

## 14. Model-routing policy retained

R2.3 is an integrity design, not a new phase map. The accepted policy remains:

- legacy Claude remains the baseline route;
- Claude Opus-class reasoning is used for high-judgment orchestration,
  semantic depth, composition, verification adjudication, and report
  judgment;
- Sonnet-class capacity is used where throughput and bounded analysis provide
  better cost-adjusted coverage;
- Haiku-class capacity is limited to low-judgment structured work when an
  explicit route permits it;
- Codex GPT-5.6 Sol/Terra/Luna arms remain experimental until separately
  validated by backend and phase;
- deliberate effort does not exceed `xhigh`;
- additional agents are authorized by independent semantic work units, not by
  a blanket multiplier;
- higher counts are justified only when held-out marginal recall exceeds the
  added cost and fragmentation.

Static model IDs, limits, prices, and capabilities are dated manifest inputs.
The implementation must refresh and review a manifest; it must not hard-code
this guide as eternal provider truth.

## 15. Primary sources

Canonicalization:

- RFC 8785, JSON Canonicalization Scheme:
  https://www.rfc-editor.org/rfc/rfc8785.html
- RFC 7493, I-JSON:
  https://www.rfc-editor.org/rfc/rfc7493.html

Anthropic:

- effort:
  https://platform.claude.com/docs/en/build-with-claude/effort
- extended thinking:
  https://platform.claude.com/docs/en/about-claude/models/extended-thinking-models
- Claude Code model and effort configuration:
  https://code.claude.com/docs/en/model-config
- model overview:
  https://platform.claude.com/docs/en/about-claude/models/overview
- migration guide:
  https://platform.claude.com/docs/en/about-claude/models/migration-guide
- model API:
  https://platform.claude.com/docs/en/api/models
- pricing:
  https://platform.claude.com/docs/en/about-claude/pricing

OpenAI:

- latest-model guide:
  https://developers.openai.com/api/docs/guides/latest-model
- GPT-5.6 Sol:
  https://developers.openai.com/api/docs/models/gpt-5.6-sol
- GPT-5.6 Terra:
  https://developers.openai.com/api/docs/models/gpt-5.6-terra
- GPT-5.6 Luna:
  https://developers.openai.com/api/docs/models/gpt-5.6-luna
- Responses create reference:
  https://developers.openai.com/api/reference/resources/responses/methods/create
- pricing:
  https://developers.openai.com/api/pricing

Provider pages are evidence for the dated manifest, not authority to bypass a
capability canary or held-out evaluation.

## 16. Conformance command and expected result

Run:

```text
python <LOCAL_USER_ROOT>\Downloads\validate_plamen_model_routing_r2_3.py
```

Expected:

```text
R2.3_CONFORMANCE=PASS
TOTAL_VECTORS=186
CANONICAL_VECTORS=10
SCHEMA_VECTORS=59
JOINS_VECTORS=91
TRANSACTIONS_VECTORS=18
CANARY_VECTORS=8
SCHEMA_SHA256=1da3f14c3e18325e818e3236cd1907a87f3032bbdeca5957fdc6fdfd1c0bedcf
VECTORS_SHA256=6e9e0db8df0727dd37c78483151e62bd041f8951a1ddcf0d7698f367cd37d625
```

The current validator intentionally uses the installed `jsonschema` package
for Draft 2020-12 validation. Production must pin and vulnerability-scan its
chosen validator and canonicalization dependencies.

## 17. Definition of done

R2.3 design closure is complete only when an independent reviewer verifies:

- the five package hashes and ASCII/LF transport properties;
- all schemas pass Draft 2020-12 meta-schema validation;
- all 186 vectors pass and each negative fails for the intended reason;
- a second implementation reproduces canonical bytes and reducer outcomes;
- the spawn primitive is unreachable without successful consumption;
- duplicate launch is impossible across crash/restart;
- money cannot renew across generations;
- customization and thinking controls are complete for the actual launcher;
- canary claims cannot cite evidence outside the receipt manifest;
- full lifecycle propagation has no lossy Markdown/regex identity join;
- existing Claude, Codex, BB, packaging, and cross-OS suites remain green;
- neutral held-out evaluation, not same-repository regression, governs
  cutover.

Current disposition:

```text
architecture direction: PASS AS CORRECTED DESIGN
seven R2.2 review blocks: CLOSED IN SPECIFICATION AND CONFORMANCE PACKAGE
production implementation: NOT PERFORMED BY THIS PACKAGE
legacy_claude_v1: production default
semantic_v1 routing: experimental/not implemented by this package
provider calls or audits authorized: none
cutover authorized: no
recall or precision improvement claimed: no
```

End of R2.3 correction.
