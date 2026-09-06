# Ecosystem program-facts provider contract

Status: normative provider and consumer contract
Runtime authority: additive evidence only; never negative authority

## 1. Decision

Program analysis enrichments are published as a dedicated typed Program Facts
bundle, not by extending the lossy legacy mechanical-graph Markdown/JSON
projection.

The canonical logical bundle consists of:

- `mechanical_program_facts.v1.json`
- `mechanical_program_facts_receipt.v1.json`
- `mechanical_program_facts_debt.v1.json`

The checked-in schemas, provider registry, methodology authority, source
manifest, provider API, and PhaseIO/WorkerTransaction bindings define the
implementation boundary. A future legacy graph version may reference the
validated bundle by digest but must not copy and reconstruct its arrays.

## 2. Authority invariants

1. Source identity comes from the same frozen source/scope policy as the audit
   snapshot. Providers do not implement private source walkers.
2. Build identity includes every configuration that changes semantics.
3. Provider implementation, parser, executable, toolchain, arguments, allowed
   environment, config, raw output, and transitive runtime dependencies are
   digest-bound.
4. Provider processes write only to WorkerTransaction staging.
5. PhaseIO is the sole canonical publisher.
6. Schemas are closed and canonical; unknown keys, duplicate identities,
   dangling references, invalid paths, floats, noncanonical JSON, and digest
   mismatch fail validation.
7. Facts are additive evidence. They cannot suppress, demote, close, mark
   examined, prove safe, or establish unreachable.
8. Unsupported, unavailable, partial, stale, or conflicting analysis still
   publishes a valid zero-or-partial bundle plus explicit debt.
9. Absence of a fact proves nothing outside a stated positive fact.
10. Provider disagreement creates work; no confidence winner silently erases
    another attestation.
11. Resume requires exact equality of all source, build, provider, parser,
    tool, schema, capability, PhaseIO, and worker bindings.
12. Ground truth is grader-only and forbidden from provider selection,
    configuration, facts, slices, prompts, and rankings.

## 3. Artifact model

### 3.1 Portable payload

The payload contains normalized:

- source and build-variant identities;
- nodes and exact or explicitly weak occurrences;
- typed facts and endpoint references;
- provider attestations;
- capability-scoped coverage;
- disagreement references; and
- `terminal_negative_authority: false`.

Portable fact identity excludes run-local process identifiers. It includes the
normalized semantic relation, endpoints, occurrences, build variant,
capability, precision, and semantic context. Independent provider attestations
of the same portable fact remain attributable.

`FULL` coverage is legal only when the exact eligible denominator equals the
covered denominator and no capability-scoped debt remains. Even `FULL`
coverage does not authorize absence-based suppression.

### 3.2 Execution receipt

The receipt is environment-specific. It binds:

- audit and source snapshot;
- provider registry and schema package;
- exact provider plans and implementations;
- toolchain, parser, command, environment, configuration, and raw outputs;
- WorkerTransaction plan, arm, attempt, terminal, process-scope, CAS, and
  incorporation identities;
- requested, emitted, unavailable, and partial capabilities; and
- hashes and sizes of payload and debt bytes.

A provider process does not mint this authority through self-report.

### 3.3 Debt

Debt always exists as a typed artifact, including when empty. Closed reasons
cover at least unsupported ecosystem or capability, unavailable or drifting
toolchain, incomplete build/source denominator, parser failure, timeout,
process-leak uncertainty, truncation, stale input, disagreement, invalid
occurrence, unsupported semantics, output mutation, and receipt/publication
failure.

Debt binds affected sources, builds, providers, capabilities, retries, reuse
blocking, and evidence. Every row states
`terminal_negative_authority: false`.

Missing artifacts are invalid or stale authority, never a clean empty graph.

### 3.4 Capability, precision, coverage, and execution vocabulary

The four dimensions are orthogonal:

| Concept | Closed values | Meaning |
|---|---|---|
| fact precision | `EXACT`, `MAY`, `HEURISTIC`, `SYNTACTIC` | strength of one positive fact within one capability |
| coverage | `FULL`, `PARTIAL`, `UNSUPPORTED`, `UNKNOWN` | eligible-denominator coverage; never absence authority |
| execution/publication | `WRITTEN`, `REUSED`, `DEGRADED`, `UNAVAILABLE`, `FAILED`, `STALE` | provider attempt and bundle state |
| debt | schema-closed reason enum | affected-subject uncertainty, retryability, and reuse blocking |

`EXACT` means the provider relation and occurrences replay under the exact
bound source/build/tool semantics. It does not prove business intent or safety.
`MAY` is a conservative positive over-approximation. `HEURISTIC` is an
approximate positive route that requires independent source confirmation.
`SYNTACTIC` is a lexical or source-parser observation without semantic
resolution.

Precision is comparable only within the same capability and semantic context.
No global confidence average may upgrade a fact. Fallback maximum precision
cannot exceed the reviewed registry row.

The conversion rules are monotonic:

| Input state | Maximum output |
|---|---|
| replayable provider fact within exact denominator | declared fact precision, up to `EXACT` |
| conservative dependency/reachability result | `MAY` |
| provider approximation with named limitations | `HEURISTIC` |
| source/regex/parser fallback | `SYNTACTIC` or `HEURISTIC`, never `EXACT` |
| partial, truncated, conflicting, or unknown result | retained facts plus `PARTIAL`/`UNKNOWN` coverage and debt |
| unavailable, failed, stale, or unsupported execution | zero-or-partial facts plus matching execution state and debt |

`DEGRADED`, `PARTIAL`, `UNKNOWN`, `UNAVAILABLE`, `FAILED`, `STALE`, and
`UNSUPPORTED` cannot convert upward to exact/full and cannot mint a negative.
A dominating predicate is not automatically an access guard; a reference is
not automatically a call; a generic language fact is not automatically a
host-semantic fact.

## 4. Provider registry

`rules/program-facts-provider-registry.v1.json` is a closed reviewed map. Each
row declares:

- provider and adapter identity;
- ecosystem/language/toolchain selectors;
- capabilities and maximum precision;
- raw schema and parser binding;
- required source/build inputs;
- bounded command, environment, files, bytes, processes, and wall time;
- supported OS/filesystem/process-scope profiles;
- fallback provider and maximum fallback precision; and
- license/distribution constraints.

Runtime environment discovery cannot add an unknown provider. An unknown,
unpinned, license-incompatible, or drifting provider yields debt.

## 5. Provider lifecycle

1. Validate the installed methodology package, schemas, registry, source
   authority, and audit snapshot.
2. Compile one deterministic provider plan for each selected provider/build
   variant.
3. Register the exact PhaseIO inputs and three outputs.
4. Arm a native WorkerTransaction with deny-by-default environment and exact
   write scope.
5. Execute into an attempt-local staging root.
6. Join the process scope and validate terminal state, raw output denominator,
   parser identity, and attempt CAS.
7. Normalize provider contributions without reading mutable live source.
8. Compose every completed or debt contribution in stable ID order.
9. Validate cross-references, coverage, disagreements, payload, receipt, and
   debt.
10. Revalidate exact input and output prestates.
11. Incorporate the three exact byte strings through PhaseIO.
12. Record artifact authority and the provider reuse key.

No provider may launch a subprocess directly or write the canonical bundle.

## 6. Source and path rules

- Artifact paths are normalized project-relative POSIX paths.
- Absolute, drive-relative, UNC, traversal, device, alternate-stream, control
  character, and aliasing paths are rejected.
- Symlinks, junctions, reparse points, hardlinks, non-regular files, and
  case-fold collisions receive explicit platform handling.
- Occurrences bind exact source-file digest, byte or line range, and source
  manifest entry.
- Source fallback facts are labeled `SOURCE_PARSE` with bounded syntactic
  precision.
- A source mutation between capture, launch, parse, composition, and PhaseIO
  commit invalidates or quarantines the attempt.

## 7. Ecosystem capability separation

### EVM

Precise EVM capabilities may include typed call, CFG, storage access,
inheritance, modifier, data-dependency, and replayable domination facts from a
pinned Slither/compiler/build environment. The profile binds ABI and source-map
availability, storage layout, compiler/EVM version, optimizer, remappings,
dependency aliases, generated files, and every selected build profile. Proxy
resolution, aliases, modifier expansion, dynamic dispatch, assembly/Yul,
partial compilation, missing source maps, and truncated analysis remain
capability-scoped debt.

### Go

Go SSA capabilities bind Go version, module/workspace files, build tags,
GOOS/GOARCH, cgo policy, replacements, vendor state, generated-file policy,
package patterns, and exact package/file denominator. Package/type/SSA loading
and static calls are distinct from reachability. `MAY_REACH_CHA`,
`MAY_REACH_RTA`, and `MAY_REACH_VTA` remain separately labelled and bind their
exact root set and algorithm limits. Interface dispatch, reflection, `unsafe`,
cgo, generated code, goroutines, channel send/receive/close, and scheduler or
runtime behavior are either explicit facts with named capability or debt.

### Rust, Solana, and Soroban

Generic Rust reference or MIR facts remain separate from host-semantic facts.
The profile states whether each fact originates in HIR, MIR, SCIP/reference,
macro-expanded source, or a named syntactic approximation. Trait/dynamic
dispatch, macro and feature selection, generated code, `unsafe`, FFI, and
unresolved expansion remain explicit facts or debt. Solana account
privilege/ownership/signer behavior and Soroban authorization, storage,
invocation, and host-value behavior require their own capability providers.
Generic Rust facts cannot be promoted to those meanings.

### Aptos and Sui

Aptos Move and Sui Move use distinct provider capabilities and bind their exact
compiler/CLI, package, lockfile, named-address, dependency, bytecode/source-map,
edition, feature, object/resource, ability, generic/phantom, native-call, and
upgrade context. Missing source maps, unresolved generics or native behavior,
and incomplete dependency/upgrade context are debt. Facts from one Move
ecosystem are not semantic authority for the other.

### Daml

Until a provider is implemented, Daml deterministically emits an unsupported
bundle and debt. It must not silently disappear from the product matrix.

## 8. Consumer contract

Consumers request bounded fact slices by exact work-unit subject and required
capabilities. They receive validated facts, coverage, disagreement, provenance,
precision, and debt banners—not raw tool output or the complete payload by
default.

Allowed consumer effects are:

- add or reopen an obligation or candidate;
- attach evidence or a disagreement;
- raise a nonnegative prioritization score while preserving the legacy floor;
- propose a relation or composition work item; and
- expose coverage/debt to assurance and scheduling.

Forbidden effects are:

- remove or demote a legacy obligation;
- authorize safe/no-finding/unreachable;
- record method application from fact availability;
- clear a candidate, premise, or lifecycle debt; or
- treat unsupported or absent facts as a negative feature.

Each consumer is a separate deterministic PhaseIO work unit with a typed output
and receipt. Consumers cut over and roll back independently.

## 9. Resume, crash, and concurrency

The reuse key binds source snapshot and manifest, build variants, provider
registry and identity, schemas, requested capabilities, toolchain/parser,
configuration, WorkPlan, and PhaseIO authority.

One frozen roster covers the bake; provider/build attempts may run in parallel.
A deterministic composer waits for every required attempt to become completed
or debt and is the only producer of the staged bundle. Lock order is:

`run -> roster/attempt registry -> provider mutation lease -> PhaseIO`

Timeout, cancellation, process death, stream overflow, nonzero exit, parser
failure, denominator mismatch, output mutation, or crash produces durable debt
or quarantine. A valid provider may contribute to a degraded bundle when
another fails; failed raw output cannot mint facts.

## 10. Cross-OS and backend behavior

Windows, Linux, and macOS use their reviewed process-scope and filesystem
profiles. Lack of a proven process containment mechanism produces unavailable
debt, not an alternate direct launcher.

For the same frozen source, build, toolchain, parser, and provider, the portable
payload is backend-neutral. Claude and Codex may differ only in explicitly
environment-specific orchestration receipt fields. Native program facts are
not model-generated.

## 11. Rollout and claims

The frozen staged order is:

1. contract, schema, canonicalization, source, registry, loader, unsupported
   bundle, and PhaseIO/WorkerTransaction authority;
2. EVM emit-only;
3. measured additive EVM consumers, one independently switchable consumer per
   release;
4. Go;
5. generic Rust, Solana, and Soroban as separate capability profiles;
6. Aptos and Sui as separate Move profiles;
7. optional digest reference from the legacy graph; and
8. the separately measured adaptive-attention interaction experiment.

Daml remains explicitly unsupported. Provider failure preserves the exact
legacy behavior and emits debt. M1 and every legacy denominator/floor remain
unchanged throughout emit-only rollout and until the relevant additive
consumer passes its own neutral gate.

No provider or consumer receives negative authority. Effectiveness claims
require neutral held-out evidence, at least one independently verified eligible
gain for the claimed ecosystem, no denominator or lifecycle loss, visible
debt, deterministic replay, fault/cross-OS/backend evidence, and independent
review. A motivating regression is not held-out evidence.

## 12. Provider conformance matrix

Every provider profile must pass the following capability-specific matrix:

| Area | Required conformance evidence |
|---|---|
| symbol and entity identity | stable qualified IDs, overload/generic/alias collision handling |
| source occurrence | exact path/digest/range replay and source-map limitation debt |
| build variants | complete selected matrix, deterministic variant IDs, missing-build debt |
| calls/control | static/dynamic/unknown dispatch labels, CFG and reachability truthfulness |
| reads/writes/data | typed locations, storage/object/resource identity, conservative dependency semantics |
| generated and expanded code | named inclusion policy, provenance, and unresolved expansion debt |
| ecosystem semantics | host-specific auth/account/storage/object/runtime capability separation |
| fallback | maximum precision enforced; failure never upgrades fallback or clears debt |
| freshness/reuse | source/build/tool/parser/config/capability drift invalidates exact dependents |
| determinism | randomized provider and filesystem order yields byte-identical portable payload |
| transaction safety | arm, crash, cancel, timeout, mutation, CAS, PhaseIO, and recovery faults |
| platform parity | Windows/Linux/macOS portable-payload equality or explicit unsupported debt |

`FULL` in this matrix means full coverage of the exact fixture denominator for
the named capability. It is not a clean audit or negative claim. Conformance is
run for tool-present, tool-absent, partial-build, unsupported, and adversarial
raw-output cases and for every claimed ecosystem/backend/OS cell.

## 13. Current implementation debt

The current worktree contains the schema/type/provider-registry/source/API and
PhaseIO/WorkerTransaction substrate. Final acceptance must still prove the
exact provider families and additive consumers intended for release, packaging
and pinned toolchain closure, cross-OS parity, independent source/runtime
review, and neutral G0A0/G1A0/G0A1/G1A1 evaluation. This document does not
promote partial substrate into production semantic authority.
