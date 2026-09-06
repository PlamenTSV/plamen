# Plamen Backend Model Routing R2.5.5 RED Engineering Plan

Date: 2026-07-30

Status: bounded design and executable RED-denominator candidate only. No
GREEN implementation, production integration, provider execution, audit,
default, configuration, commit, push, merge, or cutover is authorized.

## 1. Exact review boundary

This successor responds only to the sealed R2.5.4 blockers:

```text
backend_model_routing_r2_5_4_red_independent_review_r1_20260730.md
body SHA-256:
25723133c196edd6a94a2e7f677811d3535fd2c65a3fd9364de5c044cf046ebd
whole SHA-256:
82b0bdb39cca446bacb2bddc596c81562b22cec9e2be0e3c5268a9fb53f4b9c9
verdict: BLOCK
```

The independently accepted R2.5.4 offline replay-source authority contract
is preserved byte-for-byte through its frozen source operations. Its honest
limits remain: production source provenance and real OS no-follow I/O are
not proven by this package.

R2.5.5 closes exactly:

1. open lifecycle payload and branch schemas;
2. synthetic P15 expected-error generation;
3. generic graph shells and missing end-to-end lifecycle branch composition.

## 2. Closed intended-interface record schemas

The companion Draft 2020-12 schema defines the records that a future adapter
must expose. These are not generic name/scope envelopes.

Lifecycle records are distinct closed types:

```text
ConsumedAttemptLaunchAuthorityV2
SpawnIntentAuthorityV1
SpawnAmbiguityAuthorityV1
SpawnAmbiguityResolutionAuthorityV1
SpawnedAttemptAuthorityV1
TerminalAttemptAuthorityV1
CompletedCurrentAuthorityV1
```

Each type binds an exact event-kind discriminator to one closed payload.
Every outer record and payload rejects additional properties. Required
fields, constants, enums, types, self-digest, run scope, revision, CAS,
parent, and semantic joins are normative.

The non-lifecycle replay graph uses distinct closed types for root, attempt,
route, V4/V3 envelopes, environment policy, public environment, provider
artifact, provider/launcher neutral claims, reconciliation, and prior Resume
identity. Every type has an exact field set and self-digest.

For every record type the denominator derives:

- missing record;
- corrupt self-digest;
- extra field followed by a valid reseal;
- deleted required field followed by a valid reseal;
- wrong type followed by a valid reseal;
- semantic field substitution followed by a valid reseal.

Thus self-digest checks cannot mask schema or semantic validation.

## 3. Closed lifecycle grammar

### 3.1 Resolution branches

Only three resolution outcomes exist:

```text
OBSERVED_SPAWNED
CONFIRMED_NOT_SPAWNED_ABORT
UNRESOLVED_DEBT
```

`OBSERVED_SPAWNED` requires process and transport identities and may only
advance to `S`. The two no-spawn resolutions forbid those fields and may
only advance to their exact launcher terminal.

### 3.2 Terminal compatibility

The exact parent/outcome table is:

| Immediate branch parent | Allowed terminal outcome |
| --- | --- |
| direct `I` | `SPAWN_FAILED` |
| direct or observed `S` | `PROVIDER_TERMINAL`, `PROCESS_EXIT_NO_PROVIDER_FRAME`, `TIMEOUT`, `CANCELLED`, `TRANSPORT_FAILURE`, `EMPTY_PROVIDER_OUTPUT`, `MALFORMED_PROVIDER_OUTPUT` |
| `Q:CONFIRMED_NOT_SPAWNED_ABORT` | `AMBIGUITY_ABORTED_NOT_SPAWNED` |
| `Q:UNRESOLVED_DEBT` | `AMBIGUITY_UNRESOLVED_DEBT` |

Every resolution x next-event and branch-parent x terminal-outcome
cross-product is executed. Known incompatible pairs and invented enums
reject. `PROVIDER_TERMINAL` requires a provider digest and a spawned parent.
Every other outcome forbids a provider digest.

### 3.3 Payload closure derivation

For each lifecycle kind, the operation generator reads the normative schema
and derives:

- `EXTRA_FIELD_RESEALED`;
- `DELETE_FIELD_RESEALED` for every required payload field;
- `WRONG_TYPE_RESEALED` for every payload field;
- `REHASHED_VALUE` for every payload field;
- schema/kind discriminator mismatch;
- outer extra-field and required-field operations.

The validator schema-validates before semantic joins. Unknown fields and
unknown outcome values can never become acceptable merely because the caller
passes the same invented value to a comparison function.

## 4. Evidence-bound P15 preservation

Each P15 operation binds:

```text
operation ID
frozen implementation hash
fixture constructor ID
target callable
canonical input digest
observed result
observed error
```

The adapter reconstructs the exact frozen fixture, applies the mutation,
calls the real frozen validator/consumer, and captures its actual outcome.
Expected errors are used only after execution for comparison.

The evaluator must reject an unknown fixture ID, unknown target, wrong input
digest, or fabricated expected error before counting an operation. No branch
may raise `item.expected_error` or otherwise manufacture the observation.

The frozen aggregate predecessor validator remains an additional check, not
a substitute for these 15 calls.

## 5. Semantic branch-composed replay graph

### 5.1 Actual records and derived edges

Graph fixtures contain canonical bytes for the closed record types in
Section 2. Parent edges are fields inside those records; there is no open
edge envelope. The record catalog declares each schema, digest field,
semantic field, and parent field. The validator:

1. validates the exact record schema;
2. verifies the record self-digest;
3. validates run/generation/attempt scope;
4. resolves every declared parent field to the exact parent record digest;
5. applies record-specific semantic validation.

Edge mutations modify the real child parent field, reseal the child and
dependent descendants, and require rejection for wrong parent or scope.

### 5.2 Branch fixtures

The generator constructs these branch families end-to-end:

- direct spawned, crossed with all seven spawned terminal outcomes;
- observed-spawned recovery, crossed with all seven spawned terminal
  outcomes and retaining `A` and `Q`;
- direct conclusive spawn failure `C,I,T,K`;
- confirmed-not-spawned abort `C,I,A,Q,T,K`;
- unresolved debt `C,I,A,Q,T,K`.

Provider-terminal branches include a closed provider artifact and provider
neutral claim. Every other terminal branch omits provider bytes and uses a
closed launcher neutral claim. All terminal branches include reconciliation
and completed-current. Resume adds a closed prior-identity record.

### 5.3 Consumer composition

Positive and mutation operations execute the applicable real branch prefix
at:

```text
launch_replay_validator
proof_mint
spawn_authentication
provider_spool_acceptance
completed_current_construction
current_replay_validator
resume_authorization
```

Provider spool is derived for both direct-spawned and observed-spawned
prefixes. Completed-current, current replay, and Resume are derived for all
17 terminal branch fixtures. The no-spawn and ambiguity branches therefore
cannot pass lifecycle-only tests while remaining unsupported by consumers.

Every consumer/branch has a positive operation, preventing reject-all or
single-branch implementations from passing.

## 6. Denominator integrity

Every materialized operation has exactly:

```text
operation_id
family
fixture_constructor_id
target_consumer
mutation_operator
mutation_target
expected_result
expected_error
```

Operation IDs, count, canonical bytes, and manifest SHA-256 are frozen.
Every operation dispatches through a closed constructor/consumer registry.
Unknown IDs reject before execution.

The validator independently executes:

- the frozen R2.5.4 package;
- the accepted 43 source operations;
- all 14 atomic B5 operations;
- all 15 evidence-bound P15 operations;
- lifecycle schema and branch cross-products;
- semantic record and parent mutations across every branch/consumer.

Executed calls, not prose labels, form the denominator.

## 7. Acceptance and scope

Design/RED acceptance requires:

1. Draft 2020-12 meta-schema validity and runtime validation of every record;
2. rejection of unknown outer/payload fields and invented Q/T outcomes;
3. exact branch cross-product results;
4. 15 actual P15 calls with input/implementation/target/result binding;
5. semantic mutations on real records at every applicable consumer;
6. positive provider, launcher-no-output, spawn-failure, abort, debt, and
   observed-spawn branches through current and Resume;
7. two byte-stable validator runs;
8. fresh independent reconstruction outside scenario dispatch.

PASS would authorize only a separately designed and reviewed offline GREEN
adapter. It would not prove production provenance, OS no-follow behavior,
provider behavior, audit recall, or precision.

Production integration, provider calls, audit launches, network calls,
installs, defaults, configuration edits, commits, pushes, merges, cutover,
and recall/precision claims remain unauthorized.

End of R2.5.5 RED engineering plan.
