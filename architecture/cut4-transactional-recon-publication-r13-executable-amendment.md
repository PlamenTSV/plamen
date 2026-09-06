# Cut-4 transactional recon publication R13 executable amendment

Date: 2026-08-10
Status: Part-0 executable preimplementation successor
Supersedes: only the three rejected clauses of R12
Authority: all production, provider, ArtifactLedger, G3, audit, commit, push,
install, cutover, release, readiness, and protocol-answer authority is false

## 0. Decision and artifact boundary

R13 is not another prose-only repair. Its normative preimplementation is the
pure, fixture-scoped reference model
`review_fixtures/cut4_transactional_recon_publication_r13_reference_model.py`.
Its executable proof is the fixture-first module
`tests/test_cut4_transactional_recon_publication_r13_reference_model.py`.
The test module was created and run before the reference model existed; the
initial collection failure was the required RED. The same bounded module is
now green without editing any existing production or predecessor file.

R1-R12 remain immutable. R13 preserves R12's accepted payload byte primitive,
R11's nonempty exhausted c3 continuation, R8-R11 ownership and projections,
the fixed source_graph/build_probe/daml_source_graph provider slots, MODEL shard
and dependency-unit boundaries, legacy non-adoption, sole DRIVER canonical
merge, compatibility projection, project-root containment, and Part-0 ceiling.

The model is intentionally generic. Its sample graph contains only synthetic
prompt, tool, runtime-reader, and non-reaching nodes. It contains no protocol
finding, audit conclusion, or production activation path.

## 1. Authenticated repair input

The complete mandatory R12 independent REPAIR review was authenticated and
read before either executable artifact was authored:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `review_fixtures/cut4_transactional_recon_publication_r12_amendment_independent_review_20260810.md` | 21,892 | `7078e7c7b002fc0e4abadf255d36f280acbcc72f255b790235a736da39ae467e` |
| `architecture/cut4-transactional-recon-publication-r12-amendment.md` | 74,557 | `3e8125cbfc25e1eb8c110490cdf1847fadbac130d36885a694406dfce872d2b0` |
| `review_fixtures/cut4_transactional_recon_publication_r12_amendment_author_receipt_20260810.md` | 4,470 | `dadfb5b11439fe6cf4cb5ce83b3ec993ac7fd282115bda8c13edb0650c4c8b9b` |

The review's three findings are the exact repair boundary.

## 2. Executable byte model

The reference model uses frozen slotted dataclasses, recursive canonical
conversion, UTF-8 JSON with sorted keys and compact separators, explicit byte
base64, ordinary SHA-256 for physical bytes, and domain-separated SHA-256 for
semantic identities. `canonical_file_bytes` adds exactly one LF. All builders
are pure: inputs produce values; no function reads or mutates disk, launches a
provider, contacts a network, or writes ArtifactLedger.

Every validator raises one stable `ModelError.code`. Success returns normally.
This makes negative fixtures assert the exact failed invariant rather than a
generic exception or aggregate hash mismatch.

## 3. Source semantics are derived, not self-declared

### 3.1 Authenticated inputs and BAKE adapters

`SourceByteVector` contains the exact path, bytes, size, ordinary SHA-256, row
ID, ordered-row digest, and vector digest. `validate_source_vector` recomputes
all of them.

`BakeAdapterRegistry` is a closed lexical registry for:

```text
aptos, daml, evm, go, rust, solana, soroban, sui
```

Every adapter row carries parser adapter ID/version/config digest and exact
same-run BAKE identities/digests for:

```text
scratchpad:mechanical_program_facts.v1.json
scratchpad:mechanical_program_facts_receipt.v1.json
scratchpad:mechanical_program_facts_debt.v1.json
```

The reference model does not pretend its generic tokenizer is an ecosystem
parser. A production implementation must consume the ecosystem adapter's
authenticated BAKE output/receipt/debt slots. Missing adapter, receipt, or any
of the eight registry rows fails before enumeration.

### 3.2 Deterministic raw-node denominator

`RawNodeSpec` is parser output, not a semantic verdict. From source bytes,
adapter receipt, analyzer identity/version/config, and raw specs,
`build_enumeration_receipt` deterministically constructs `RawNodeRow` values.
Each row binds:

```text
file ID/path/SHA, exact half-open byte span, span length/SHA,
recomputable source-anchor digest, raw node/grammar kind, callsite fields,
analyzer identity/version/config, parser adapter, BAKE receipt
```

`validate_enumeration_receipt` independently rebuilds the complete ordered
multiset. It detects row omission, fabrication, duplicate ID, source alias,
span substitution, anchor substitution, analyzer change, adapter change, row
digest change, and receipt change.

### 3.3 Independent total mode mapping

`ModeRuleRegistry` is sealed separately from raw enumeration. Its exact generic
rules map PROMPT_LOAD to STATIC_EDGE/MODEL, TOOL_ARG to STATIC_EDGE/TOOL,
RUNTIME_READ to PROBE_REQUIRED/RUNTIME, CONTROL to STATIC_EDGE/CONTROL,
NON_REACH to NON_REACHING/NONE, and every unknown raw kind to
UNCLASSIFIABLE/UNRESOLVED debt. `ModeMappingReceipt` contains exactly one
rule/evidence row per raw node. Its validation independently reconstructs the
expected row from the rule registry; a STATIC_EDGE or PROBE_REQUIRED relabel to
NON_REACHING therefore fails even when a writer updates the relabeled row ID.

### 3.4 Generic graph and non-vacuous absence

`BaseSemanticRow` is derived exclusively from the authenticated raw row and
its independent mode row. Callers cannot pass a writer-chosen base set to the
builder. `CanonicalEdge` is then a total projection: STATIC_EDGE,
PROBE_REQUIRED, and UNCLASSIFIABLE produce respectively GRAPH, PROBE, and
UNPROJECTABLE rows; NON_REACHING produces none. Exact ordered multisets are
recomputed at every boundary.

Every `ReferenceSpec` projects every exact-identity edge. A reference with no
edge becomes PROVED_NONE only when `WholeGraphNegativeProof` binds the source
vector, enumeration receipt, mode receipt, complete base/edge digests, and the
nonempty exact ordered list of every inspected raw-node ID. Missing or partial
proof produces UNRESOLVED_FALLBACK with
`MISSING_WHOLE_GRAPH_NEGATIVE_PROOF`; zero applicable probes cannot prove
absence. The graph validator reconstructs base, edge, reference, proof, and
denominator arrays, so omission, fabrication, duplicate, relabel, or vacuous
negative cannot make all expected sets shrink together.

Future S v6/P0/D/M4/R4 integration must bind source-vector, adapter,
enumeration, mode-map, base, edge, negative-proof, reference, and denominator
digests from this same construction. R13 does not authorize that production
integration.

## 4. Dependency-total query construction and journal

### 4.1 Total DAG

The model's `DEPENDENCY_NODES`, `DEPENDENCY_EDGES`,
`REQUIRED_DEPENDENCY_FIELDS`, and independently declared
`FIELD_DEPENDENCIES` are executable. `validate_dependency_dag` requires unique
nodes/edges, known endpoints, strict declared order, a zero Kahn remainder,
and exact equality between required and mapped dependency-field denominators.
The current result is 24 nodes, 44 edges, zero cycles, and zero unmapped or
extra dependency fields.

The nodes explicitly include prior envelope, private plan, predicate evidence,
invalid-file fact, previous record, abort, provider receipt, provider-private,
normalizer outcome, terminal record, publication link, M4, R4, and completion
receipt. The staged constructor remains:

```text
PriorEnvelope + BaseRequestIntent
  -> request_digest
  -> AttemptAllocation(previous record, generation)
  -> InvocationRecord(private plan, predicates, exact inputs/config)
  -> PayloadRecord -> ProviderReceipt -> ProviderPrivateV3
  -> NormalizerOutcome -> NormalizedSemanticRow
  -> TerminalEnvelope -> terminal JournalRecord
  -> PublicationLink -> M4 -> R4 -> CompletionReceipt
```

`AbortedUnobserved` is an explicit alternate successor of allocation and an
optional invocation. Its `invocation_state` is ABSENT with an exact empty
digest or PRESENT with a 64-hex digest; no ambiguous optional value exists.
The ID/digest binds request, attempt, allocation, presence state, invocation,
and bounded reason. A retry is a new attempt sequence and ID.

`PublicationLink` has a closed ID/digest and binds the exact R13 terminal
record digest, terminal envelope identity/digest, canonical public identity,
byte size/SHA, and publication receipt. Replay locates exactly one terminal
record for the request and returns the stored canonical terminal bytes.

### 4.2 Live-PhaseIO-compatible single-artifact contract

The reference registry contains one exact live-class `PhaseIOContract`:

```text
key: sc/core/evm/codex/recon/transactional_journal_r13
identity: scratchpad:_cut4_r13/private/recon_query_journal_state.v1.json
class: DRIVER_GENERATED
writer: DRIVER
write mode: REPLACE
schema: cut4.r13.query_journal_state.v1
gate: CAS_ATOMIC_REWRITE_AND_TERMINAL_REPLAY_VALID
consumer: recon/canonical_publication_successor_v2
model_invoked: false
required_commit_actor: DRIVER
```

The three exact BAKE artifacts are immutable, same-run, DRIVER-produced input
requirements. The contract is instantiated with the current
`ArtifactSpec`, `InputAuthorityRequirement`, `PhaseIOContract`, canonical
six-part key, and `WriteObservation` classes; its single observed changed path
passes live write validation. No `private:` root, slash-only identity, dynamic
child output, or glob is used.

This is a reference registration, not an installed resolver entry. A future
authorized cutover must add this exact shape to the production resolver in the
same atomic change as its driver consumer. R13 changes neither resolver nor
ArtifactLedger.

### 4.3 Composite state, CAS, generation, and recovery

`JournalState` is one canonical composite artifact. It includes namespace,
request, generation, prior-state SHA, header, invalid-fact roster/digest,
ordered records/digest, and state digest. Record zero names the exact header
digest and canonical header byte size/SHA. Later records name the prior record
digest and prior record bytes size/SHA. Every record binds ordinal, kind,
request, attempt, exact staged-object identity/digest, canonical object bytes,
length, and ordinary SHA.

`atomic_rewrite` checks the physical preimage SHA, validates the entire next
state, allows only same-generation append or generation+1 recovery, rejects a
same-generation non-prefix rewrite, and returns deterministic canonical bytes,
size, and SHA for an atomic-temp/fsync/replace operation. This is modeled, not
performed.

`rotate_generation_once` unions invalid facts by derived fact ID. A new fact
creates exactly generation+1, binds the committed preimage SHA, and starts a
new record chain. An already sealed fact is a no-op, preventing infinite
successor generations. `reconcile_torn_temp` retains committed bytes unchanged
and emits a typed TORN_TEMP fact for the next CAS. Stale CAS, invalid record
chain, duplicate facts, nonappend rewrite, and malformed preimage fail closed.

SUCCESS and SUCCESS_EMPTY preserve a nonempty c3 cursor even when exhausted;
replay returns that exact terminal envelope. TIMEOUT/FAILURE/MALFORMED/
NOT_APPLICABLE have empty cursor-out and a durable terminal record. Crash after
allocation or invocation creates ABORTED_UNOBSERVED and a distinct attempt;
only a durable terminal is replayable.

## 5. Payload, Kp, normalizer, diff, M4, and R4 closure

`PayloadRecord` is a closed slotted dataclass whose ID commits provider, private
plan, invocation, ordinal, content type, byte size, raw SHA, and payload digest.
Validation decodes exact bytes and recomputes every field.

`ProviderReceipt` is the provider outcome. Its closed statuses are
NOT_APPLICABLE, NOT_SELECTED, SUCCESS, FAILURE, TIMEOUT, MALFORMED, and
PARTIAL_DEBT. Only PARTIAL_DEBT may retain partial payloads, and it requires
`PARTIAL_PROVIDER_PAYLOAD_DEBT`. All other failure/nonselected statuses require
an empty payload roster. This resolves R12's partial/status contradiction.

`ProviderPrivateV3` embeds exactly one full PayloadRecord, names the provider
receipt, binds the source snapshot, and serializes the inherited Kp in this
exact order:

```text
private_plan_row_id, semantic_row_id, private_source_identity, provider_id,
consumer_id, flow_instance_id, multiplicity_key, multiplicity_ordinal,
applicability_predicate_id, selection_predicate_id, accept_disposition,
accept_projected_identity
```

Outcome and provider-private payload tuples must be byte-identical ordered
multisets. Kp and source snapshot must equal the private plan.

Every payload has exactly one `NormalizerOutcome`. ACCEPTED names one or more
normalized rows and empty debt. REJECTED, DEBT, FAILURE, TIMEOUT, or MALFORMED
may name zero rows only with a typed debt code and authenticated evidence/
receipt/outcome digest. `NormalizedSemanticRow` carries all twelve Kp fields,
payload and provider receipt FKs, normalizer/version, semantic kind/identity,
closed normalized fields, fields digest, authenticated plan snapshot, row
digest, and row ID. The validator conserves outcome row IDs exactly and rejects
an untyped zero.

The executable `DIFF_KINDS` and `DIFF_SOURCE_MAP` contain twelve closed kinds.
`make_diff_row` rejects an unregistered kind and derives exact expected/
observed source kinds, counts, byte digests, row digest, and row ID. Empty sides
are ordinary empty bytes with a nonempty ordinary SHA.

M4, R4, and CompletionReceipt are closed dataclasses. Their builders derive
provider-private, normalized, and diff array digests, then nonrecursive
manifest and object digests. R4 repeats the exact M4 data arrays and names M4;
the completion receipt names M4, R4, every data-array digest, and the exact
publication link. Validation reconstructs every object; duplicate/extra,
missing, field mutation, or receipt mutation fails.

## 6. Fixture-first proof and boundedness

The test module freezes 36 named mutation cases with roster SHA-256
`5044d6f029d0d45103fa7ca9c902fa77500049d1ac223ed66f6e97667f96aa80`.
They cover every R12 independent-review counterexample plus raw-node/base/edge/
reference omission, fabrication, relabel, and duplicate; vacuous PROVED_NONE;
prior/private-plan/provider-receipt swaps; previous record and invalid-fact
tampering; crash before/after invocation; abort optionality; terminal-link
swap; stale CAS; nonappend and torn-temp recovery; timeout; exhausted c3;
payload duplicate/content-type/byte-SHA/partial debt; normalizer zero; Kp;
unknown diff; M4/R4/receipt mutation.

The bounded module currently collects 64 tests. It imports only the fixture
reference model and existing PhaseIO types. No test enumerates a project,
launches a subprocess other than pytest itself, calls a provider, or writes a
project/scratchpad artifact. Repeated sample builds compare canonical bytes and
digests, and repeated atomic rewrites compare exact committed bytes/SHA.

Future ownership, if separately authorized, is indivisible: one fixture worker
may own only this R13 test module and evidence; one DRIVER cutover worker must
own source compiler, registered journal state, provider-private/normalizer,
M4/R4, and canonical-publication integration atomically. MODEL prompts,
shards, dependency units, providers, ArtifactLedger, and G3 remain outside the
R13 change.

## 7. Claim ceiling

The model proves internal construction, failure detection, byte determinism,
dependency acyclicity/coverage, and compatibility with current PhaseIO value
shapes. It does not prove production resolver registration, filesystem atomicity
on a target host, ecosystem parser correctness, provider availability,
ArtifactLedger cutover, audit completeness, or release readiness. Those are
future implementation/review obligations. All authority remains false.
