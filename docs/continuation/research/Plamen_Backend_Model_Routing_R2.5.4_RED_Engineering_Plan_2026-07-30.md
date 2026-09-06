# Plamen Backend Model Routing R2.5.4 RED Engineering Plan

Date: 2026-07-30

Status: bounded design and executable RED-denominator candidate only. No
GREEN implementation, production integration, provider execution, audit,
default, configuration, commit, push, merge, or cutover is authorized.

## 1. Exact predecessor boundary

This successor responds only to the three blockers in the sealed review:

```text
backend_model_routing_r2_5_3_red_independent_review_r1_20260730.md
body SHA-256:
71a549c72522e4ad57229b75ffbf2115353eefd0d85b46ae2392a2c55421e075
whole SHA-256:
70f0c07214f0e18145070cd315b4129d99c054105f03f94134fe2fd45ef580c3
verdict: BLOCK
```

The accepted R2.5.3 B5 direction is preserved: launch closure is genuinely
pre-provider, contains exactly its launch graph, and does not call a complete
current/post-provider closure. The 15 predecessor preservation operations and
the atomic B5 operations remain in the successor denominator.

R2.5.4 closes exactly:

1. a source-owned, sealed exact key-to-byte-and-scope replay manifest;
2. a formal append-only lifecycle with complete restart and terminal paths;
3. an atomic executable operation denominator mechanically derived across
   every applicable graph node, parent edge, and consumer.

## 2. Authority boundary: source-owned replay manifest

### 2.1 Trusted source selection

The orchestrator selects a `ReplayAuthoritySourceV1` before reading any
caller-controlled scratchpad record. The selected source and its expected
manifest-root digest are supplied through a trusted runtime/configuration
boundary, never through a replay reference, provider response, phase output,
environment value, or module-reflected constructor.

This offline package models that boundary with an immutable in-memory source.
It proves deterministic contract behavior only. It does not claim production
provenance, OS keystore integrity, or deployment access control.

### 2.2 ReplayManifestAuthorityV1

The source owns canonical, duplicate-free manifest bytes and the externally
selected expected manifest-root digest. The closed manifest binds:

- manifest schema and version;
- authority and source identifiers;
- bytewise key policy identifier;
- an ordered, unique map of exact artifact key to:
  - SHA-256 digest and byte length;
  - stage (`LAUNCH` or `CURRENT`);
  - store snapshot digest;
  - run, generation, and attempt;
- manifest self-digest/root over canonical bytes excluding that digest.

The source rejects when the canonical manifest root differs from the trusted
expected root. A caller never supplies or overrides the expected root.

### 2.3 Inert replay references

`LaunchReplayReferenceV2` and `CurrentReplayReferenceV2` are untrusted
selectors. Each contains an exact artifact key and claimed digest, length,
stage, snapshot, run, generation, and attempt. Every claim must equal the
source-owned manifest row. No reference field is authority.

References cannot contain a root, filesystem path, URI, raw bytes, manifest,
source object, expected digest, validation result, registry token, issuer, or
alternate store. Unknown fields reject.

### 2.4 Exact key and path law

Manifest keys are ASCII bytes interpreted byte-for-byte. They match:

```text
^[a-z0-9][a-z0-9._-]{0,127}$
```

They are case-sensitive and are never Unicode-normalized or filesystem
case-folded. `/`, `\`, `:`, NUL, percent-encoding, dot segments, absolute
paths, drive prefixes, UNC forms, URI schemes, and non-ASCII bytes reject.
The consumer requests a manifest key, never a path.

A production source adapter must perform contained, no-follow, regular-file
opening or use a content-addressed object store, and must reject symlink,
junction, mount, and reparse aliases. These requirements are represented by
source fault fixtures; this design package does not implement OS I/O.

### 2.5 Single-read, no-TOCTOU replay

For one consumer decision:

1. validate the trusted manifest root;
2. exact-key lookup the single source-owned row;
3. compare every untrusted reference claim to that row;
4. read artifact bytes exactly once through the selected source;
5. check byte length and digest on that buffer;
6. parse and validate that same buffer;
7. pass the immutable parsed value to the consumer without reopening.

Manifest or artifact replacement, second-read dependence, cross-source
substitution, and cross-snapshot substitution reject. The conformance source
counts reads and can mutate on a hypothetical second read; a valid consumer
must read once.

## 3. Preserved genuine pre-provider launch closure

The R2.5.3 launch graph is unchanged. Its exact payload remains:

1. routing root;
2. execution attempt;
3. selected route;
4. V4 launch envelope;
5. V3 predecessor envelope;
6. environment policy;
7. public materialized environment;
8. consumed-attempt authority.

Provider observation, evidence, terminal, usage, raw stream, neutral claim,
reconciliation, completed-current, incorporation, raw environment, and
legacy flat compatibility records are absent. Missing post-provider records
must not prevent valid launch replay; any smuggled post-provider field
rejects. Proof mint and spawn authentication repeat total launch replay.

## 4. Formal append-only lifecycle

### 4.1 Event law

Every event is a closed, canonical, self-digested record with exact run,
generation, attempt, event revision, CAS revision, and immediate-parent
digest. Revisions increase by exactly one. All events in one attempt retain
the same run scope and launch replay digest. Events are immutable and
append-only; a later event never changes an earlier status field.

Tokens used below:

- `C`: `ConsumedAttemptLaunchAuthorityV2`;
- `I`: `SpawnIntentAuthorityV1`;
- `A`: `SpawnAmbiguityAuthorityV1`;
- `Q`: `SpawnAmbiguityResolutionAuthorityV1`;
- `S`: `SpawnedAttemptAuthorityV1`;
- `T`: `TerminalAttemptAuthorityV1`;
- `K`: `CompletedCurrentAuthorityV1`.

`I` binds `C`, the launch replay, planned transport/spool identity, and a
unique intent nonce. `S` binds `I` directly or an `OBSERVED_SPAWNED`
resolution, plus exact process and transport identities. `T` binds its exact
immediate parent and records a launcher-authenticated terminal outcome even
when no valid provider terminal frame exists. `K` binds `T` and the complete
current replay graph.

### 4.2 Exact valid prefixes

Only these token sequences are valid:

```text
C
C,I
C,I,S
C,I,S,T
C,I,S,T,K
C,I,T
C,I,T,K
C,I,A
C,I,A,Q
C,I,A,Q,S
C,I,A,Q,S,T
C,I,A,Q,S,T,K
C,I,A,Q,T
C,I,A,Q,T,K
```

The `Q,S` branch is valid only for `OBSERVED_SPAWNED`. The `Q,T` branch is
valid only for `CONFIRMED_NOT_SPAWNED_ABORT` or `UNRESOLVED_DEBT`. Direct
`I,T` is valid only for a conclusive launcher `SPAWN_FAILED` outcome. Every
other subset, order, duplicate, gap, branch combination, or post-terminal
event rejects.

### 4.3 Derived restart states and actions

| Prefix | State | Only permitted next action |
| --- | --- | --- |
| `C` | `CONSUMED_NOT_SPAWNED` | CAS-append `I` |
| `C,I` | `INTENT_OUTCOME_UNKNOWN` | observe; on restart append `A`; never relaunch |
| `C,I,A` | `AMBIGUITY_OPEN` | append governed `Q`; never relaunch |
| `C,I,A,Q` observed-spawned | `OBSERVED_SPAWN_PENDING_RECORD` | append exact `S` |
| `C,I,A,Q` other | `AMBIGUITY_RESOLVED_NO_SPAWN` | append launcher `T` |
| any valid prefix ending `S` | `SPAWNED_NO_TERMINAL` | observe then append `T` |
| any valid prefix ending `T` | `TERMINAL_NOT_RECONCILED` | reconcile and append `K` |
| any valid prefix ending `K` | `RECONCILED_CURRENT` | incorporation/Resume law |

An intent-only restart does not infer not-spawned. `Q` is governed evidence:

- `OBSERVED_SPAWNED` binds an observed process and transport identity;
- `CONFIRMED_NOT_SPAWNED_ABORT` binds authoritative non-occurrence evidence
  and permanently aborts the same attempt;
- `UNRESOLVED_DEBT` records an adverse/unknown terminal debt and permanently
  forbids same-attempt relaunch.

All three preserve the no-blind-relaunch rule. A new attempt requires normal
attempt-allocation law; it cannot reuse the same attempt or intent nonce.

### 4.4 Terminal without provider output

`TerminalAttemptAuthorityV1` is authenticated by the launcher, not by
provider prose. Its exact outcome enum is:

```text
PROVIDER_TERMINAL
SPAWN_FAILED
PROCESS_EXIT_NO_PROVIDER_FRAME
TIMEOUT
CANCELLED
TRANSPORT_FAILURE
EMPTY_PROVIDER_OUTPUT
MALFORMED_PROVIDER_OUTPUT
AMBIGUITY_ABORTED_NOT_SPAWNED
AMBIGUITY_UNRESOLVED_DEBT
```

`PROVIDER_TERMINAL` requires the provider terminal/frame digest and a spawned
parent. The other outcomes forbid a provider terminal digest and bind the
launcher process/spool observation applicable to their branch. Thus a known
process failure advances to conservative reconciliation rather than leaving
the pipeline permanently at `SPAWNED_NO_TERMINAL`.

### 4.5 Exact namespaces

Each event appends one immutable store revision:

- consume namespace: launch records plus `C`;
- intent namespace: previous namespace plus `I`;
- ambiguity namespace: previous namespace plus `A`, then `Q`;
- spawned namespace: previous namespace plus `S`;
- terminal namespace: previous namespace plus `T` and provider bytes only
  for `PROVIDER_TERMINAL`;
- completed namespace: previous namespace plus neutral/reconciliation/current
  records and `K`.

Rollback, missing intermediate revisions, same-revision conflicts, duplicate
typed events, conflicting branch events, or rewriting an earlier key reject.

## 5. Total replay graph and consumers

The companion schema contains one canonical node/edge graph and exact
consumer applicability sets. Consumers are:

```text
launch_replay_validator
proof_mint
spawn_authentication
provider_spool_acceptance
completed_current_construction
current_replay_validator
resume_authorization
```

Each consumer must validate every applicable node and edge from the exact
single-read replay buffer. Provider-spool acceptance includes the manifest,
launch, intent, and spawned prefix. Completed-current construction includes
the manifest, complete launch prefix, spawned/terminal prefix, provider or
launcher outcome, neutral projection, reconciliation, and current record.
Completed-current construction, current replay, and Resume each derive two
canonical matrices: one with a valid provider artifact and one with a
launcher terminal that contains no provider artifact. The latter joins the
launcher terminal directly to conservative neutral reconciliation.

For every consumer the validator mechanically derives:

- one positive exact-replay operation;
- `DELETE_NODE` and `CORRUPT_NODE_SEAL` for every applicable node;
- `WRONG_PARENT_DIGEST` and `WRONG_SCOPE_JOIN` for every applicable edge.

The expanded operation IDs and canonical operation-manifest digest are
frozen. A consumer-specific graph omission therefore changes the denominator
or digest rather than silently passing.

## 6. Atomic executable operation denominator

Every operation has exactly:

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

There are no `or` scenarios. One operation invokes one constructor, one
consumer, and one mutation. Unknown constructors, consumers, mutations,
results, or errors reject before execution.

The denominator consists of:

1. the 15 exact predecessor preservation operations, replayed through the
   frozen predecessor;
2. atomic B5 launch absence/smuggling/call-graph operations;
3. atomic source-manifest key, digest, scope, source, path, substitution, and
   TOCTOU operations;
4. every valid lifecycle prefix and terminal outcome as a positive operation;
5. every forbidden prefix, branch, parent, run, generation, attempt,
   revision, nonce, process, transport, and terminal join mutation;
6. the mechanically expanded consumer node/edge matrix.

The RED validator executes a pure reference contract and the frozen R2.5.3
baseline. It does not implement provider or production behavior. A future
GREEN adapter must execute the same frozen operation manifest against its
real public consumers; it cannot replace reference results with labels or
skip unsupported operation IDs.

Executed operations, not row labels, are counted. A reject-all
implementation cannot pass because every valid prefix, every terminal
outcome, and every consumer has a positive acceptance operation.

## 7. Acceptance and sequencing

This package may pass design/RED review only if:

1. the sealed R2.5.3 review and frozen predecessor hashes bind exactly;
2. all source-root, key, digest, scope, path, substitution, and single-read
   operations execute;
3. all valid lifecycle prefixes and recovery outcomes accept;
4. all invalid prefixes and parent/scope/revision joins reject;
5. every graph-derived node/edge mutation rejects at every applicable
   consumer and every positive consumer replay accepts;
6. the materialized operation count and manifest digest equal the schema
   derivation;
7. the validator runs twice with byte-identical stdout;
8. a fresh independent reviewer reconstructs representative operations
   outside the scenario dispatcher and issues PASS.

Only after that review may a separate GREEN design/build be proposed.
Production integration, provider calls, audit launches, network calls,
installs, defaults, configuration edits, commits, pushes, merges, cutover,
and recall/precision claims remain unauthorized.

End of R2.5.4 RED engineering plan.
