# Plamen Backend Model Routing R2.5.3 RED Engineering Plan

Date: 2026-07-30

Status: plan and RED-denominator candidate only; no successor
implementation, production integration, provider execution, audit, default,
commit, push, or cutover authorization.

## 1. Exact predecessor boundary

This plan responds only to the three defects in:

```text
backend_model_routing_r2_5_2_independent_review_r1_20260730.md
body SHA-256:
4a1757a50169d7bd003e20e4a2b03ce085679f35fa6e75c8250d0ec79e8528b9
whole SHA-256:
0bca91a40d52b14ab2bac0147da599afe45a06d40cc79090cb2bde844aa2db57
fresh focused operations: 8
unexpected accepts: 5
disposition: BLOCK
```

The sealed root defects are:

- B5: false pre-provider separation because launch mint still calls the
  complete post-provider closure;
- B6: no authenticated durable spawn-occurrence transition or restart
  grammar;
- B7: reflected module issuers/registries mint authority and consumers do
  not totally revalidate canonical payloads.

R2.5.3 must preserve the independently demonstrated 15/15 rejection of the
R2.5.1 unexpected accepts. It may not reopen, rename away, or denominator-drop
those cases.

## 2. Scope law

This is not another capability wrapper. The successor architecture has three
changes only:

1. a genuinely pre-provider launch-only closure validator;
2. an append-only authenticated spawn occurrence and derived restart state;
3. deterministic external replay with total consumer validation, safe even
   when a caller reflects constructors or mutates module registries.

No model choice, provider fact, price, phase count, audit methodology,
finding, severity, protocol hint, account route, cost policy, default, or
production caller changes.

## 3. Remove in-process issuance from the security argument

### 3.1 Inert references

`LaunchReplayReferenceV1` and `CurrentReplayReferenceV1` are inert lookup
references, not proof objects. Each contains only:

- reference version and kind;
- exact externally assigned artifact key;
- canonical artifact digest;
- store snapshot digest;
- run, generation, and attempt.

Constructing, copying, serializing, reflecting, or editing a reference grants
no authority.

### 3.2 External replay source

Every consumer calls a separately established
`ReplayAuthoritySource`:

```text
reference
-> exact-key lookup in governed source
-> immutable canonical bytes
-> digest and run-scope validation
-> complete stage-specific validation
-> consumer decision
```

The caller cannot provide a path, raw record dictionary, alternate store,
issuer, registry entry, validation result, or expected digest. A nonexistent
or mismatched reference rejects.

The offline GREEN conformance fixture must use immutable replay artifacts in
a directory outside the validator module and an exact manifest frozen before
scenario dispatch. It must not use a module-global secret, module-global
issuer object, registry membership, Python underscore name, or object
identity as provenance. Production later requires an access-controlled
process or OS-backed broker; the offline manifest proves only deterministic
replay behavior.

### 3.3 Total validation

Every proof, spawn, provider-spool, completed-current, and Resume consumer
replays and revalidates the complete applicable canonical graph. It never
trusts a prior boolean, registry entry, object type, copied digest, or
constructor path.

A reflectively constructed reference may point to a valid governed artifact,
in which case total replay is safe, or to no/mismatched artifact, in which
case it rejects. There is no privileged in-process constructor to steal.

## 4. B5: causal launch-only closure

### 4.1 Exact launch payload

The launch authorization payload is exactly:

1. routing root;
2. execution attempt;
3. selected route;
4. V4 launch envelope;
5. V3 predecessor envelope;
6. environment policy;
7. public materialized environment;
8. consumed-attempt authority.

It contains no:

- provider observation or evidence;
- provider artifact, frame, terminal, usage, fallback observation, or raw
  stream digest;
- neutral claim or reconciliation;
- completed-current or incorporation record;
- raw environment value;
- flat legacy transaction compatibility dictionary.

Unknown launch-payload fields reject.

### 4.2 Required pre-provider ancestors

The replay source also supplies the exact pre-provider ancestors needed to
validate the eight payload records:

- root preimage and launch-run authority;
- reservation, materialization, and consumption parents;
- route selection, axes, manifest, evaluation, capability, price, fallback,
  profile semantics, profile registry, and customization authorities;
- request, work plan, PhaseIO launch contract, control, launch, backend arm,
  secret policy, and public environment.

The launch store namespace excludes prior Resume, proof rules, provider
artifact/evidence, terminal reconciliation, and incorporation. Those records
cannot exist yet.

### 4.3 Launch validation

`validate_launch_replay` independently validates:

- every record's closed schema and self-digest;
- exact external artifact and snapshot digests;
- exact store key, revision, run, generation, and attempt;
- root-to-route-to-attempt-to-envelope ancestry;
- V4/V3 projection;
- policy rows, public environment, and raw-environment projection supplied
  ephemerally at the sink;
- reservation/materialization/consumption parent joins;
- consumed CAS and `CONSUMED_NOT_SPAWNED`.

It does not call `validate_closure_v251`, `validate_closure_v252`, or any
validator that reads observation, evidence, terminal, usage, fallback
observation, raw stream, reconciliation, or incorporation.

Proof mint and spawn authentication each call `validate_launch_replay`
again. There is no reusable trusted result that can bypass replay.

## 5. B6: append-only spawn occurrence and restart grammar

### 5.1 Immutable pre-spawn consume

`ConsumedAttemptLaunchAuthorityV2` remains the immutable CAS record proving
that resources were consumed before spawn. Its
`CONSUMED_NOT_SPAWNED` label describes that event's lifecycle point; it is
never mutated into a current-state claim.

### 5.2 SpawnIntentAuthorityV1

Immediately before the OS/process spawn call, the external launcher appends
a closed, CAS-ordered `SpawnIntentAuthorityV1`. It binds the consumed
attempt, launch replay, planned transport/spool identity, and a unique
spawn-event nonce digest. The intent is durable before the non-atomic
external side effect.

If the launcher crashes after intent persistence but before it can
authenticate the outcome, restart derives an ambiguous/no-blind-relaunch
state. It must observe the process/transport or require governed recovery;
it cannot infer not-spawned from absence of a spawned record.

### 5.3 SpawnedAttemptAuthorityV1

At the actual process-spawn boundary, the external launcher appends a closed,
self-digested `SpawnedAttemptAuthorityV1` containing:

- exact store key and revision;
- run, generation, and attempt;
- routing root and execution-attempt digests;
- V4 envelope and consumed-launch digests;
- launch replay artifact digest;
- spawn-intent authority digest;
- monotonic spawn-event and spawn-CAS revisions;
- process identity digest;
- transport/spool identity digest;
- spawn occurrence state `SPAWNED_NO_TERMINAL`.

The provider spool and completed-current validator require this record.
Caller records, module-local constructors, or provider bytes cannot mint it.

### 5.4 Derived restart state

Restart state is derived from an append-only exact prefix, not a mutable
best-effort status string:

| Present authenticated prefix | Derived state | Permitted action |
| --- | --- | --- |
| consume only | `CONSUMED_NOT_SPAWNED` | CAS-create spawn intent |
| consume + intent, no authenticated outcome | `SPAWN_INTENT_AMBIGUOUS` | observe/governed recovery; never blind relaunch |
| consume + intent + spawned | `SPAWNED_NO_TERMINAL` | observe/reconcile; never blind relaunch |
| consume + intent + spawned + terminal artifact | `TERMINAL_NOT_RECONCILED` | neutral reconcile only |
| consume + intent + spawned + terminal + completed current | `RECONCILED_CURRENT` | incorporate/Resume law |

Spawned without intent, terminal without spawned, completed current without
terminal, multiple conflicting transitions, decreasing/reused CAS/event
revisions, cross-run edges, or digest gaps reject.

Ambiguous spawn is represented by a separate append-only
`SpawnAmbiguityAuthorityV1` joined to the consumed attempt and launcher
event. Its restart action is observe/no blind relaunch. It cannot be
normalized to not-spawned.

## 6. Completed-current closure

The completed-current replay graph is built only after authenticated spawn
and terminal provider bytes exist. It contains:

- the complete valid launch replay graph;
- spawn-intent authority;
- spawned-attempt authority;
- authenticated immutable provider artifact and terminal frame;
- closed neutral claims, usage, raw digest, and proof rules;
- exact neutral-to-legacy projection;
- neutral reconciliation and completed-current authority.

`validate_current_replay` performs the complete rooted closure, neutral
derivation/projection, reconciliation, spawned, terminal, store/run, and
restart-prefix validation from canonical external bytes on every use.

Resume accepts only an inert current replay reference, loads the prior
identity from the governed completed namespace, replays the current graph,
recomputes current identity, and then applies the frozen Resume transition
law.

## 7. Stage-specific namespaces

The launch namespace is a strict pre-provider namespace. The completed
namespace is a later immutable snapshot/revision that adds:

- spawned attempt;
- provider terminal artifact;
- proof rules;
- neutral reconciliation;
- prior Resume/current identity authorities.

The completed snapshot cannot replace or rewrite the consumed, launch, or
spawned records. It joins their exact digests. Revision rollback,
cross-snapshot substitution, missing prefix records, and extra untyped/raw
secret records reject.

## 8. RED denominator

The companion RED denominator contains:

- 15 frozen preservation cases from the R2.5.1 unexpected-accept replay;
- 10 B5 launch-causality cases;
- 13 B6 spawn/restart cases;
- 10 B7 reflected-construction/total-replay cases;
- total declared denominator: 48.

RED means the frozen R2.5.2 implementation cannot satisfy the successor
contract. Some RED cases are unsafe accepts; others are required valid states
or APIs that R2.5.2 cannot represent. Each row records the exact baseline
observation and the required GREEN result.

The denominator must be independently reviewed before any GREEN
implementation begins. No row may be silently dropped, merged without an
alias, or changed from reject to accept semantics after review.

## 9. Required GREEN acceptance

A future R2.5.3 implementation may claim author conformance only if:

1. all 15 preservation operations still reject at intended successor
   consumers;
2. all 33 new causal/replay rows produce their declared GREEN results;
3. launch validation succeeds with every post-provider artifact absent;
4. smuggled post-provider launch fields reject;
5. valid append-only crash prefixes derive exactly one restart state;
6. impossible prefixes and all cross-run/CAS/digest mutations reject;
7. direct reflected constructors and registry insertions confer no authority;
8. every consumer replays and totally validates canonical external bytes;
9. frozen predecessor validators execute unchanged;
10. a fresh independent reviewer recreates the five R2.5.2 unexpected
    accepts and proves they no longer pass.

## 10. Sequencing

```text
R2.5.3 plan + RED denominator author freeze
-> independent exact-hash plan/denominator acceptance
-> offline GREEN schemas/replay fixtures/validator
-> fresh independent GREEN exact-hash review
-> only then reconsider J4-0 production fixture design
```

Production integration, provider calls, audit launches, network calls,
installs, defaults, commits, pushes, merges, recall claims, and precision
claims remain unauthorized.

End of R2.5.3 RED engineering plan.
