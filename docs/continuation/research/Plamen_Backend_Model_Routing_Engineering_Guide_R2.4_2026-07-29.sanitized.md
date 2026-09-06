# Plamen backend model-routing engineering guide R2.4

Date: 2026-07-29

Status: DESIGN-ONLY NORMATIVE ADDITIVE CORRECTION; AUTHOR SELF-VALIDATED;
INDEPENDENT REVIEW REQUIRED; NO CUTOVER AUTHORIZATION

## 0. Authority, exact denominator, and precedence

R2.4 is an additive successor to the independently accepted R2.3
design/conformance package. It does not mutate, reinterpret, or weaken an R2.3
record. It resolves the Claude R3 compatibility preflight amendments A1-A12,
with particular emphasis on the A8 privacy conflict.

The exact accepted R2.3 six-file denominator is:

| Artifact | SHA-256 |
| --- | --- |
| Plamen_Backend_Model_Routing_Engineering_Guide_R2.3_2026-07-29.md | d047d994f9aa114dea0ca9435b06922234c9ba54002321ca18f4d80a5e8b9d5f |
| Plamen_Backend_Model_Routing_R2.3_Schemas_2026-07-29.json | 1da3f14c3e18325e818e3236cd1907a87f3032bbdeca5957fdc6fdfd1c0bedcf |
| Plamen_Backend_Model_Routing_R2.3_Conformance_Vectors_2026-07-29.json | 6e9e0db8df0727dd37c78483151e62bd041f8951a1ddcf0d7698f367cd37d625 |
| validate_plamen_model_routing_r2_3.py | 584fbc05a60929a761a1987928a8d97eb1931593d2c8445c42d3c622eb938581 |
| Plamen_Backend_Model_Routing_R2.3_Validation_Receipt_2026-07-29.json | 3df640bac21c0adfb70ad82d5c3d085409a562427a395c12acfb81cd6b1cfe46 |
| Plamen_Backend_Model_Routing_R2.3_Independent_Review_2026-07-29.md | a97ee6bcf1c905d634fb3643a29d1ba629c4a7ea8416ceb1ca4686d644f6523d |

The R2.4 author package is:

| Artifact | Role | SHA-256 |
| --- | --- | --- |
| Plamen_Backend_Model_Routing_R2.4_Schemas_2026-07-29.json | exact successor record shapes | 1d8895bbfbda3d44c5dd58acf3df029b700664b9bca9e1986dbc8d83dbcc4381 |
| Plamen_Backend_Model_Routing_R2.4_Conformance_Vectors_2026-07-29.json | R2.3 preservation binding plus numbered R2.4 vectors | e046e589cf830ba31fa608ab0ec2c650e2aff555f1fe2a5698f261f12f2079c9 |
| validate_plamen_model_routing_r2_4.py | isolated offline preservation and successor validator | 47c0d70771abe13713d7bd2cf6e87773ae1ea30eab755da712a789d8ec42ff87 |

The schema bundle controls exact serialized key sets, required fields, types,
and closed enums. This guide controls cross-record equality, lifecycle,
privacy, ordering, state-transition, and authority rules that JSON Schema
cannot express. The vectors and validator define the minimum executable
behavior.

Precedence is:

1. R2.4 controls every type named as an R2.4 successor.
2. R2.3 controls all unchanged routing/resource/canary behavior.
3. Historical V1/V2/V3 records remain diagnostic and replay inputs only where
   their original specifications permit. They never gain successor launch
   authority by reinterpretation.
4. The R3 implementation plan controls production file ownership and caller
   migration, as amended by the joint R4 implementation plan.

This package changes no repository production/test/policy/lock/evaluator/BB
file, provider state, audit state, commit, branch, push, or default. It
authorizes no provider call, audit, install, cutover, or recall claim.

## 1. Corrected architecture

The compatible authority chain is:

```text
SemanticWorkPlanV2                         provider neutral
  + CommonResourceGrantV1                 family wide
  + ExecutionAxesV1                       backend/routing/transport/assurance
  + ModelRouteV3                          exact route; no fallback
  + ClaudeProviderProfileV1               closed and route neutral
  + ExecutionInputAuthoritySetV1          four independent input identities
  -> ClaudeHeadlessExecutionRequestV2     tagged BASELINE or SEMANTIC request
  -> deterministic public compiler join  never selects route and never spawns
  -> WorkPlanRoutingBindingV2
  -> PhaseIORoutingBindingV2
  -> ClaudeProviderControlVectorV2
  -> LaunchAuthorityV3
  -> BackendArmExecutionIdentityV4
  -> ExecutionAttemptIdentityV3
  -> reserve generation and attempt
  -> materialize argv/environment/prompt in the launch process
  -> PublicMaterializedEnvironmentV1
  -> process-local EphemeralSecretProof
  -> AttemptLaunchEnvelopeV3
  -> consume under CAS
  -> ConsumedAttemptLaunchAuthorityV1
  -> non-serializable SemanticSpawnCapability
  -> exact final proof verification
  -> provider process creation
  -> ProviderExecutionObservationV5
  -> reconciliation or typed route/resource debt
  -> exactly-once PhaseIO incorporation
```

There is no direct edge from request compilation to process creation.
Transport selection does not select routing. A provider profile does not
select route. Capability evidence does not grant permission. An observation
does not self-certify a finding disposition.

## 2. A1: routing, transport, assurance, and backend are orthogonal

`ExecutionAxesV1` carries four independent discriminators:

```text
backend:
  claude | codex | native

routing_profile:
  legacy_claude_v1 | semantic_v1 |
  codex_existing_v1 | native_existing_v1

transport:
  HEADLESS_PROOF | LEGACY_PTY_NON_PROOF |
  CODEX_EXISTING | NATIVE_EXISTING

assurance_class:
  TRANSACTIONAL_PROOF_CANDIDATE | LEGACY_PTY_NON_PROOF |
  EXISTING_CODEX_ASSURANCE | EXISTING_NATIVE_ASSURANCE
```

The compatibility matrix is closed in production. The schema enumerates
values; implementation invariants enforce legal combinations.

Important consequences:

- `HEADLESS_PROOF` does not imply `semantic_v1`.
- `legacy_claude_v1` may be exercised through a separately named headless
  baseline without becoming a semantic route.
- `LEGACY_PTY_NON_PROOF` is explicit, visibly stamped, and cannot be selected
  by omission, invalid input, exception fallback, or resume inference.
- R3-8 may change the fresh-run transport default only. It may not change the
  routing-profile default.
- `legacy_claude_v1` remains the routing default until neutral held-out
  non-inferiority is independently accepted.

Historical configuration without a transport is legacy/non-proof and requires
explicit migration. It is never silently promoted to headless proof.

## 3. A2: ClaudeProviderProfileV1 is closed and route neutral

The only initial profile IDs are:

- `analysis_filesystem`;
- `analysis_read_only`;
- `adjudication_staged_write`;
- `stdout_json_no_tools`.

`ClaudeProviderProfilePolicyAuthorityV1` fixes the semantics ID and exact
four-profile ID denominator. Each profile binds that independent parent
authority and is a self-digested member of one self-digested
`ClaudeProviderProfileRegistryV1`. The registry binds the same parent, has a
fixed sorted ID denominator, and carries exact member digests. This
parent-profile-registry direction avoids a hash cycle; a profile never hashes
its containing registry. The request binds the selected profile, registry,
and parent policy. Unknown, duplicate, missing, reordered, semantically
mislabelled, or modified members invalidate the join.

A profile may own only:

- permission mode and closed builtin-tool set;
- filesystem, network, and subagent constraints;
- output contract/profile;
- named environment-policy sets;
- settings and MCP selection policies;
- stream byte/event ceilings;
- isolation policy.

A profile must not contain or choose:

- backend or routing profile;
- model, effort, or thinking mode;
- transport or assurance;
- account class or auth route;
- service tier or provider fallback;
- context, price, budget, generation, attempt, or resource grant.

`additionalProperties: false` makes those route-owned fields illegal. The
compiler may reject an incompatible profile and route. It may not rewrite
either.

`stdout_json_no_tools` has an empty tool set, denied network, no model
filesystem, forbidden subagents, and
`CLAUDE_STREAM_RESULT_ASSIGNED_OUTPUT`. It cannot gain Read, Write, Bash, MCP,
network, Task, Agent, or any convenience tool.

Profile stream ceilings are upper bounds only. They must be equal to or
tighter than `ContextBudgetV2` and `BudgetAuthorityV3`; they never mint
resources.

## 4. A3 and A4: tagged request and deterministic compiler join

`ClaudeHeadlessExecutionRequestV2` is a tagged union with:

- `BASELINE` plus `legacy_claude_v1`;
- `SEMANTIC` plus `semantic_v1`.

Both branches bind:

- `ExecutionAxesV1`;
- one route-neutral provider profile;
- `ExecutionInputAuthoritySetV1`;
- backend-neutral semantic plan;
- WorkPlan contract authority;
- PhaseIO contract authority;
- output contract;
- timeout and stream ceiling.

The semantic branch additionally binds:

- `ModelRouteV3`;
- provider arm family;
- context budget;
- budget authority.

The baseline branch carries null semantic route/budget members. Historical
legacy route behavior is not redefined.

The request binds WorkPlan and PhaseIO contract authorities known before
compilation, not descendant execution records. This avoids an impossible
hash cycle:

```text
request
  -> WorkPlanRoutingBindingV2(request)
  -> PhaseIORoutingBindingV2(request, WorkPlan binding)
  -> LaunchAuthorityV3(all three)
```

The sole public compiler is a pure deterministic join:

```text
compile(request, axes, route, profile, input authorities,
        capability, price, fallback, budgets, host/public policies)
  -> compiled launch preparation authority | typed debt
```

It does not:

- select or alter route;
- infer ambient credentials;
- accept model aliases or provider defaults;
- broaden profile tools;
- renew budget;
- reserve resources;
- consume a launch;
- create a process.

For a semantic request, the effective accepted-model denominator is exactly
one dated `ModelRouteV3.exact_requested_model_id`. There is no free
`accepted_models` list in the request. Zero, two, alias, `latest`, `auto`,
provider-default, unknown, or implicit fallback values are invalid.

Account/auth mapping is closed. An unavailable requested API-key or stored
subscription route becomes typed capability debt; it cannot silently select
the other route.

## 5. A8: secret-safe environment identity

### 5.1 The public digest is a projection, never a raw-environment hash

`public_materialized_environment_digest` is the self-digest of
`PublicMaterializedEnvironmentV1`. It is computed with restricted R2.3 JCS
and SHA-256 over exactly:

- schema and version;
- environment-policy-set digest;
- host-policy-authority digest;
- exact entry count;
- ordered entries.

Every policy-declared environment name has exactly one entry, including an
absent optional secret. Entries are unique and sorted by canonical UTF-8
bytes of `name`. An entry contains exactly:

- environment variable name;
- closed source class;
- redaction marker;
- duplicate-free, canonically ordered policy-authority digests;
- exact non-secret value, or null for a secret.

Closed source classes are:

```text
POLICY_LITERAL_NON_SECRET
HOST_DERIVED_NON_SECRET
TOOLCHAIN_DERIVED_NON_SECRET
RUNTIME_PATH_NON_SECRET
SECRET_RUNTIME
```

Closed redaction markers are:

```text
NON_SECRET_VALUE_INCLUDED
SECRET_VALUE_PRESENT_REDACTED
SECRET_VALUE_ABSENT
```

For `NON_SECRET_VALUE_INCLUDED`, the exact non-secret value is present and the
source class is non-secret. For either secret marker, source class is
`SECRET_RUNTIME` and `non_secret_value` is null.

Therefore:

- rotating only a present secret value leaves the public digest unchanged;
- changing a name, source class, redaction/presence marker, policy authority,
  public policy, host authority, or non-secret value changes the digest;
- a secret becoming absent or present changes its marker and digest;
- no raw secret value or stable secret-derived digest is public.

The old ambiguous `materialized_environment_digest` is forbidden from
`ClaudeProviderControlVectorV2` and `AttemptLaunchEnvelopeV3`. V1/V2 records
that contain it remain diagnostic; they cannot authorize semantic launch or
trusted resume.

### 5.2 Exact secret integrity is process local

Public stability is intentionally not exact secret-value integrity. Exact
in-memory integrity uses a fresh `EphemeralSecretProof` object:

1. Generate a cryptographically random 256-bit process nonce at process
   initialization. Never persist it.
2. Generate a fresh cryptographically random 256-bit HMAC key and object
   nonce for each launch object.
3. After the V3 envelope is built, compute HMAC-SHA-256 over:
   - domain separator `plamen.ephemeral-secret-proof.v1` plus NUL;
   - process nonce;
   - object nonce;
   - exact `AttemptLaunchEnvelopeV3.attempt_launch_digest`;
   - canonical length-delimited ordered pairs for every final child
     environment name and exact value, including secret and non-secret values.
4. Hold key, tag, nonces, and raw environment only inside one non-serializable
   process-local launch object.
5. Immediately before the only process-creation primitive, recompute and
   constant-time compare the tag against the exact environment passed to the
   child and the same V3 envelope.
6. Mark the proof consumed before process creation. A crash or exception after
   consumption is ambiguous consumed debt; recovery never relaunches by
   guessing.
7. Best-effort overwrite mutable key/tag buffers after the spawn attempt and
   drop all references. Language/runtime limitations to guaranteed
   zeroization are explicit.

The object must reject serialization, pickling, copying, process transfer,
logging, representation of key/tag, and reuse. A proof from another process
nonce or object nonce is invalid. The spawn capability wraps the exact
`ConsumedAttemptLaunchAuthorityV1` and this proof; it is also non-serializable.

No proof key, tag, nonce, raw secret, or digest computed from a secret may
enter:

- argv;
- stdout/stderr;
- logs or exceptions;
- route/resource debt;
- WorkPlan, WTx, WER, PhaseIO, or resume;
- ArtifactLedger or RunBundle;
- evaluator or BB artifacts;
- CI evidence, crash journals, fixtures, snapshots, or benchmark bundles.

Because neither tag nor key is durable, a low-entropy credential dictionary
has no durable verifier. The public digest is identical for different present
secret values. Persisting a keyed tag "for debugging" violates R2.4.

### 5.3 Threat boundary

The ephemeral proof detects mutation or substitution between final
materialization and process creation, accidental cross-object reuse, and
cross-process replay. It does not defend against an attacker with arbitrary
code execution inside the authorized launcher process who can read/alter both
environment and key. That case requires OS/process-integrity and containment
controls and must not be oversold.

## 6. Updated route, control, identity, envelope, and observation types

R2.4 adds successors; it does not edit prior schemas:

| Prior concept | R2.4 successor | New authority |
| --- | --- | --- |
| ModelRouteV2 | ModelRouteV3 | axes, exact dated model, capability, price, fallback, context, budget |
| ClaudeProviderControlVectorV1 | ClaudeProviderControlVectorV2 | request/profile/route plus public environment and proof policy |
| LaunchAuthorityV2 | LaunchAuthorityV3 | request, inputs, WorkPlan, PhaseIO, control vector |
| BackendArmExecutionIdentityV3 | BackendArmExecutionIdentityV4 | complete request/profile/input/route/transaction closure |
| ExecutionAttemptIdentityV2 | ExecutionAttemptIdentityV3 | V4 arm plus exact attempt ordinal |
| AttemptLaunchEnvelopeV2 | AttemptLaunchEnvelopeV3 | public environment and proof-policy binding; no secret-derived digest |
| ProviderExecutionObservationV4 | ProviderExecutionObservationV5 | V3 envelope/consumed authority, profile/route/input joins, fallback state |

Every successor has a new schema string and version. Historical bytes never
parse as a successor.

`ClaudeProviderControlVectorV2` binds:

- request, semantic plan, axes, profile, and route;
- exact singleton model;
- effort and thinking authorities;
- exact argv digest;
- public environment digest and policy-set digest;
- secret-proof policy digest.

It contains no proof key/tag/nonce and no raw environment digest.

`AttemptLaunchEnvelopeV3` binds:

- V3 launch authority, V2 request, and V2 control vector;
- exact attempt, backend arm, reservation event/entry, and
  post-reservation ledger;
- exact argv, public environment, environment-policy set, proof policy,
  prompt, and working directory;
- whether the selected public policy requires an ephemeral secret proof.

`ProviderExecutionObservationV5` binds:

- V4 backend arm and V3 attempt;
- V2 request, axes, profile, and V3 route;
- V3 envelope and consumed launch authority;
- public environment digest;
- independently observed model, effort, thinking, fallback, terminal, usage,
  evidence-manifest, and raw-stream state.

Requested values copied into observation fields are not evidence. Missing or
contradictory provider evidence makes the observation adverse. Any different
model, fallback, transition, refusal, safety state, unknown effort/thinking,
or unobservable state routes to typed debt and cannot support safety,
dismissal, severity reduction, negative closure, or ordinary reconciliation.

## 7. A5: WorkPlan and PhaseIO are versioned once

R3-2 first creates the non-spawning public profile/request/compiler seam.
After the pure routing core exists, R3-3 performs one transaction migration:

- `WorkPlanRoutingBindingV2` binds request, axes, profile, independent inputs,
  semantic plan, route, output contract, and exact WorkPlan.
- `PhaseIORoutingBindingV2` binds the request, WorkPlan binding, PhaseIO
  contract/launch, independent inputs, output contract, and exactly-once
  incorporation policy.
- `LaunchAuthorityV3`, WTx, WER, observation, reconciliation, and resume bind
  both.

Historical WorkPlan/PhaseIO records remain diagnostic. They cannot authorize
semantic launch, trusted resume, completion, or incorporation.

This cut happens once to avoid one R3 transaction migration followed by a
second routing migration.

## 8. A6: compile, reserve, consume, and spawn are separate

The only semantic launch sequence is:

1. Compile and persist a secret-free request/profile/route join.
2. Reserve generation resources under family-ledger CAS.
3. Reserve attempt resources under CAS and persist the reserved entry and
   post-reservation ledger.
4. Materialize exact argv, final child environment, prompt, and working
   directory in the launcher process.
5. Construct the public environment projection and process-local secret
   proof.
6. Persist `AttemptLaunchEnvelopeV3`.
7. Consume that exact envelope under CAS.
8. Persist launch-consumed attempt entry, consumption event,
   post-consumption ledger, and `ConsumedAttemptLaunchAuthorityV1`.
9. Construct a non-serializable spawn capability from the consumed authority
   and proof.
10. Verify and consume the proof against the exact child environment and V3
    envelope.
11. Call the sole process-creation primitive.

The compiler cannot reserve or spawn. Reservation requires compiled
authority. Consumption requires the exact persisted V3 envelope and expected
ledger revision. Spawn accepts only the non-serializable capability. A
function accepting loose argv/environment/request or an unconsumed envelope is
not the semantic spawn sink.

Crash windows fail closed:

- before consumption: retry only through exact reducer/idempotency rules;
- after consumption and before process creation: ambiguous consumed debt;
- after process creation and before observation: reconcile from independent
  process/stream evidence or debt; never relaunch automatically.

## 9. A7: exact retry, generation, and resume law

`ResumeAuthorityV1` compares one closed identity vector:

- model, effort, thinking;
- transport and assurance;
- account, auth, service, fallback;
- public environment policy/projection;
- source, prompt, methodology, Program Facts;
- tools and provider profile;
- common family resource grant;
- WorkPlan and PhaseIO identities.

Rules:

1. `RETRY_SAME_GENERATION` requires byte-identical identity closure,
   byte-identical family grant, no changed identity fields, the same
   generation, and attempt ordinal exactly prior plus one.
2. Any authorized change to the identity vector requires
   `NEW_GENERATION`, generation exactly prior plus one, attempt ordinal zero,
   a changed closure digest, and a non-empty exact changed-field set.
3. A new generation does not renew the arm-family grant or currency.
4. Model transition, provider fallback, xhigh escalation, transport change,
   or account/auth change is never an attempt retry.
5. Completed exactly-once PhaseIO incorporation yields
   `NO_RELAUNCH_COMPLETED`.
6. Consumed-but-unproven spawn state yields
   `AMBIGUOUS_CONSUMED_DEBT`.
7. Historical raw-Claude launch specs cannot mint a successor authority.

Resume validates all typed ancestors and descendants, not only a top-level
digest label. Consistently rehashing a substituted descendant fails its join
to the independently frozen parent authority.

## 10. A9: source, prompt, methodology, and Program Facts are independent

`ExecutionInputAuthoritySetV1` contains four typed identities:

```text
plamen.source-snapshot-authority.v1
plamen.prompt-authority.v1
plamen.methodology-authority.v1
plamen.program-facts-authority.v2
```

It also binds tool policy and an explicit four-way domain-separation marker.
The identities remain separate through request, WorkPlan, WTx/WER, PhaseIO,
resume, repair, observation, RunBundle, evaluator, and BB.

`SHA-256(prompt_raw)` is not a methodology identity. Equal payload bytes do
not collapse authority domains. Missing Program Facts is explicit debt; it
does not become an empty digest or "no facts" safety.

Program Facts driver hook order, startup sentinel behavior, run lock,
checkpoint semantics, and serialized ownership remain frozen across the
Claude/routing implementation.

## 11. A10: capability, cost, budget, and fallback are versioned

R2.4 adds:

- `ProviderRouteCapabilityAuthorityV1`;
- `ProviderPriceAuthorityV1`;
- `ProviderFallbackAuthorityV1`.

The current backend capability registry and old resource records are not
reinterpreted.

Capability authority binds:

- exact dated model identifier;
- dated provider manifest;
- transitive R2.3 canary field claim;
- exact supported efforts and transports;
- exact observable fields;
- validity interval.

Canary evidence is observation evidence, not permission, recall evidence, or
default-flip authority. `max`, `ultracode`, provider-default, auto, latest,
aliases, unknown values, and unclaimed fields are forbidden. Deliberate
reasoning is capped at `xhigh`.

Price authority binds exact model, currency, unit basis, four token-price
categories, observation time, and provider snapshot. Cost is never
reconstructed from a newer price after execution.

Fallback authority has one policy:

```text
FORBID_IMPLICIT_PROVIDER_FALLBACK
```

The requested model count is one. A different observed model is route debt.
An authorized continuation is a new generation with a new route. Fallback
cannot ordinary-reconcile as success.

The R2.3 family ledger remains authoritative for source/output bytes, turns,
retries, wall time, tool calls, driver-owned work units, and currency.
Additional agents consume `driver_owned_work_units`; a model/profile/transport
change cannot renew any grant. Profile ceilings cannot exceed route/budget
ceilings.

## 12. A11: Codex remains unchanged

R2.4 does not redesign Codex argv, environment, auth, output, retry, resume,
WorkPlan, WTx, WER, or PhaseIO behavior.

Successor production unions retain the exact existing Codex branch. Claude
fields are illegal there. `CodexParityWitnessV1` records:

- before/after schema identity;
- before/after canonical bytes digest;
- before/after semantic fixture-set digest;
- absence of Claude-only fields.

All three pairs must be equal. The witness does not itself grant Codex
authority; it makes unchanged behavior mechanically reviewable.

Paired Claude/Codex experiments still use byte-identical backend-neutral
semantic-plan bytes. Provider-specific identities remain separate below that
plan.

## 13. A12: downstream propagation and final closure are delayed

Initial R3/routing work is not final closure.

After every runtime caller is migrated and independently accepted, exact
secret-free identities must propagate through:

- resume and repair;
- ArtifactLedger and RunBundle;
- neutral evaluator;
- BB wrapper;
- public packaging/install/uninstall;
- final CI/runtime dependency closure.

`DownstreamPropagationStatusV1` is `PENDING` until every listed surface is
complete on exact frozen bytes. A local unsigned RunBundle remains
`UNSIGNED_LOCAL_INTEGRITY`; it is not provenance, harvest authority, provider
proof, recall proof, or cutover authority.

The final CI/runtime manifest is regenerated only after the last routing,
Claude, RunBundle, evaluator, BB, packaging, and repair byte is frozen.
Earlier manifests are intermediate, not final.

No semantic routing default may change before:

- complete offline/runtime integration;
- native Windows, Linux, macOS, and governed WSL evidence;
- separately human-authorized provider canaries;
- neutral governed held-out non-inferiority.

<PRIVATE_REGRESSION_TARGET> and other motivating repositories are regression-only and never
scored recall evidence.

## 14. Exact A1-A12 disposition

| Amendment | R2.4 resolution |
| --- | --- |
| A1 | `ExecutionAxesV1` separates backend, routing, transport, assurance. |
| A2 | Closed self-digested route-neutral `ClaudeProviderProfileV1` and registry. |
| A3 | Tagged secret-free `ClaudeHeadlessExecutionRequestV2`. |
| A4 | Public compiler is an exact deterministic join and cannot route/reserve/spawn. |
| A5 | V2 WorkPlan/PhaseIO bindings land once with the routing transaction cut. |
| A6 | Compile, reserve, materialize, consume, and spawn are distinct authorities. |
| A7 | `ResumeAuthorityV1` gives exact retry/generation/no-relaunch/debt laws. |
| A8 | Public secret-free projection plus non-durable process/object keyed proof. |
| A9 | Four typed domain-separated source/prompt/methodology/Program Facts identities. |
| A10 | Versioned capability, price, fallback, and unchanged family-ledger authority. |
| A11 | Codex branch remains exact and is checked by a parity witness. |
| A12 | Downstream propagation, CI closure, canaries, benchmark, and default decision are delayed. |

## 15. Joint R3 implementation order

The required order is:

1. Independently review and freeze this R2.4 package.
2. Independently freeze Program Facts and its exact driver postimage.
3. R3-2a: add `ExecutionAxesV1`, profile registry, tagged request, and sole
   public compiler in non-spawning mode.
4. Prove public/private compiler parity for the existing main lane; remove the
   private compiler only after parity.
5. Routing core: port R2.3 plus R2.4 JCS, route, inputs, capability, price,
   fallback, budget, ledger, reducer, and crash-safe persistence in dry-run
   mode.
6. R3-3 plus routing transaction cut: add V2 WorkPlan/PhaseIO bindings,
   control vector V2, launch authority V3, arm V4, attempt V3, envelope V3,
   consumed authority, non-serializable spawn capability, stream result,
   observation V5, reconciliation, and debt.
7. R3-4: migrate dynamic verifier and recovery.
8. R3-5: migrate application/candidate skeptic.
9. R3-6: migrate severity adjudication.
10. R3-7: run exact final-child ecosystem and OS matrix with secret-safe
    receipts.
11. R3-8: change fresh-run transport default only; keep legacy routing default.
12. Propagate through resume, repair, RunBundle, evaluator, BB, and packaging.
13. Freeze and independently review final runtime/CI closure.
14. Run local shadow/dry-run routing comparisons.
15. Run provider canaries only with separate human authorization.
16. Run neutral held-out evaluation before any routing default decision.

At each checkpoint:

- red fixtures precede production edits;
- owned preimages are re-hashed immediately before editing;
- focused, fault/crash/resume, blast-radius, package, and cross-OS tests run;
- one non-author reviewer examines production diff and exact test denominator;
- no skipped/xfail row is counted as pass;
- rollback returns to the prior accepted authority version;
- no aggregate pass count hides a failed mandatory row.

## 16. Conformance package

The R2.4 vector file preserves the exact R2.3 denominator by:

1. binding all six accepted R2.3 hashes;
2. checking ASCII, LF-only, final-LF transport;
3. checking the exact R2.3 vector group counts;
4. running the frozen R2.3 validator under isolated Python;
5. requiring its exact nine-line result for all 186 vectors.

It then runs 128 numbered R2.4 vectors:

```text
R2.4-001 through R2.4-128
```

The new vectors cover:

- public environment projection and mutation sensitivity;
- secret rotation stability;
- process/object proof mutation/replay/serialization;
- low-entropy dictionary resistance of durable artifacts;
- orthogonal axes;
- closed route-neutral profiles;
- tagged request and compiler ownership;
- independent input authorities;
- control, launch, WorkPlan, PhaseIO, arm, attempt, envelope, consumed, and
  observation joins;
- exact retry/generation law;
- capability, cost, budget, fallback;
- Codex parity;
- delayed downstream closure and routing default.

Run:

```text
python -I <LOCAL_USER_ROOT>\Downloads\validate_plamen_model_routing_r2_4.py
```

Expected:

```text
R2.4_CONFORMANCE=PASS
R2_3_PRESERVED_VECTORS=186
R2_4_NEW_VECTORS=128
TOTAL_VECTORS=314
SCHEMA_SHA256=1d8895bbfbda3d44c5dd58acf3df029b700664b9bca9e1986dbc8d83dbcc4381
VECTORS_SHA256=e046e589cf830ba31fa608ab0ec2c650e2aff555f1fe2a5698f261f12f2079c9
AUTHOR_DISPOSITION=SELF_VALIDATED_NOT_INDEPENDENT_PASS
```

The author result is not an independent PASS. A different reviewer must
re-run, inspect negative quality, inject additional attacks, and stamp exact
bytes.

## 17. Minimum production fixtures beyond the portable vectors

Production must additionally test:

- two concurrent reserve and consume attempts;
- every crash window before/after envelope, consume, proof verification,
  process creation, observation, reconciliation, and PhaseIO incorporation;
- process/object proof copy, fork/spawn transfer, pickle, deepcopy, repr,
  exception, logging, and crash-dump surfaces;
- secret rotation, absence/presence, low-entropy dictionaries, Unicode,
  spaces, long paths, Windows case/junction, POSIX symlink;
- final child environment equality at the actual process-creation API;
- profile registry truncation/reorder/duplicate/unknown field;
- exact source/prompt/methodology/Program Facts substitution with consistently
  rehashed descendants;
- WorkPlan/WTx/WER/PhaseIO historical-record confusion;
- requested value copied into provider observation;
- fallback/transition/refusal/safety/timeout/unobservable paths;
- family grant conservation across model/effort/transport/account changes and
  agent-count increases;
- Codex before/after byte and behavior parity;
- all SC ecosystems, L1, BB, packaging, native OS jobs, and final installed
  tree;
- RunBundle local integrity never promoted to provenance or recall evidence.

The OS/process-containment claims require their own native evidence. Fake
executables prove policy application and tool discovery only.

## 18. Definition of done and current verdict

R2.4 design/conformance closure is ready for independent review when:

- all author artifacts are ASCII, LF-only, final-LF and hash-stamped;
- Draft 2020-12 meta-schema validation passes;
- exact R2.3 preservation executes all 186 vectors;
- all 128 R2.4 vectors execute error-for-error;
- secret/private material is absent from durable bytes;
- a reviewer verifies the ephemeral proof cannot be serialized or used as a
  durable low-entropy verifier;
- a reviewer checks that request/WorkPlan/PhaseIO identities are acyclic;
- a reviewer checks A1-A12 one by one;
- no production or provider action occurred.

Current verdict:

```text
R2.3 preserved: AUTHOR SELF-VALIDATED
A1-A12 design closure: AUTHOR SELF-VALIDATED
A8 normative clarification: PRESENT
production implementation: NOT PERFORMED
cross-runtime/cross-OS behavior: NOT PROVEN
provider capability: NOT PROVEN
audit recall/precision: NOT PROVEN
legacy_claude_v1 routing default: RETAINED
semantic_v1 launch/default: NOT AUTHORIZED
independent PASS: REQUIRED
```

End of R2.4 design correction.
