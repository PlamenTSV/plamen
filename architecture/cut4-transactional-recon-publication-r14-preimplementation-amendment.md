# Cut-4 transactional recon publication R14 preimplementation amendment

Date: 2026-08-10
Status: Part-0 architecture-only repair awaiting independent architecture review
Supersedes: only the four rejected R13 preimplementation gates
Authority: all fixture, model, implementation, production, provider,
ArtifactLedger, G3, audit, commit, push, install, cutover, release, readiness,
and protocol-answer authority is false

## 0. Decision and present boundary

R14 defines the preimplementation contract that a future fixture and model must
satisfy. This turn creates only this amendment and its author receipt. It does
not create, edit, run, or authorize an R14 fixture, model, transcript, provider,
or production path.

R13 artifacts are immutable historical inputs and are explicitly forbidden as
fixture-first, RED, GREEN, implementation, or acceptance authority for R14.
No R13 test hash, run, receipt, model result, mutation roster, or reviewer
decision may satisfy an R14 gate. A future R14 receipt may list R13 only under
`non_authoritative_history`; every R14 authority FK must resolve to a new
versioned R14 artifact below.

R1-R13 ownership, provider slots, MODEL shards, dependency units, legacy
non-adoption, project-root containment, sole canonical merge, nonempty
exhausted c3, and Part-0 ceiling remain unchanged unless this amendment
expressly tightens a rejected R13 preimplementation clause.

## 1. Authenticated repair input

The complete R13 independent REPAIR review was authenticated and read end to
end before R14 was authored:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `review_fixtures/cut4_transactional_recon_publication_r13_independent_review_20260810.md` | 21,861 | `a40740a4285fac9de741f5136bb29b09e96e51a241f4e03176fa69421619693d` |
| `architecture/cut4-transactional-recon-publication-r13-executable-amendment.md` | 15,786 | `22523cc8a2fadec6e4947036aa4f06f2fb14724b4235150d18b7ed84e3c5af24` |
| `review_fixtures/cut4_transactional_recon_publication_r13_reference_model.py` | 97,750 | `5119fea25b5410917a14b2871b714983d9c36926469b029198c2af1ff377937c` |
| `tests/test_cut4_transactional_recon_publication_r13_reference_model.py` | 18,976 | `a6c8554ea70f91d0fa8ecb87e231164f7a714e1ece548f0d04a76a9cca0dcff1` |
| `review_fixtures/cut4_transactional_recon_publication_r13_author_receipt_20260810.md` | 5,859 | `e7002cc73dab9cc3114579e7767594e9471e570ce11829ef60e397fa2f0e0846` |

The review's four findings are the complete repair boundary.

## 2. Versioned paths and strict principal DAG

### 2.1 Closed future path registry

The following paths are exact. None except the present amendment/receipt is
authorized or created now.

```json
{
  "schema": "cut4.r14.path_registry.v1",
  "architecture_amendment": "architecture/cut4-transactional-recon-publication-r14-preimplementation-amendment.md",
  "architecture_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r14_amendment_author_receipt_20260810.md",
  "architecture_independent_review": "review_fixtures/cut4_transactional_recon_publication_r14_amendment_independent_review_20260810.md",
  "red_test": "tests/test_cut4_transactional_recon_publication_r14_preimplementation.py",
  "model": "review_fixtures/cut4_transactional_recon_publication_r14_reference_model.py",
  "red_failed_run": "review_fixtures/cut4_transactional_recon_publication_r14_red_failed_run_20260810.json",
  "red_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r14_red_author_receipt_20260810.json",
  "red_independent_review": "review_fixtures/cut4_transactional_recon_publication_r14_red_independent_review_20260810.md",
  "green_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r14_green_author_receipt_20260810.json",
  "green_independent_review": "review_fixtures/cut4_transactional_recon_publication_r14_green_independent_review_20260810.md"
}
```

Every path is single-writer and immutable after its gate. No alias, R13 path,
date-less path, overwrite, rename adoption, or dynamically chosen substitute
is authoritative.

### 2.2 Principals and chronology

Six authenticated principals are required:

| principal | sole role |
|---|---|
| `P_ARCH_AUTHOR` | writes only R14 amendment and author receipt |
| `P_ARCH_REVIEWER` | independently returns architecture ACCEPT or REPAIR |
| `P_FIXTURE_AUTHOR` | after ACCEPT, writes only RED test/transcript/receipt |
| `P_RED_REVIEWER` | independently reviews frozen fixture and RED evidence |
| `P_MODEL_IMPLEMENTER` | after RED ACCEPT, writes only R14 model/green author receipt |
| `P_GREEN_REVIEWER` | independently reproduces GREEN and returns final decision |

All six `principal_id` and signing-key fingerprints must be pairwise distinct.
No principal may act through a delegate, shared signing key, shared receipt
issuer, or nominal alias. The fixture author cannot edit the model; the model
implementer cannot edit the fixture; reviewers cannot author reviewed bytes.

The normative DAG is:

```json
{
  "schema": "cut4.r14.principal_dag.v1",
  "nodes": [
    "R14_ARCH_AUTHORED",
    "R14_ARCH_ACCEPTED",
    "R14_FIXTURE_FROZEN",
    "R14_RED_FAILED_RUN_CAPTURED",
    "R14_RED_AUTHOR_RECEIPT_SEALED",
    "R14_RED_INDEPENDENT_ACCEPTED",
    "R14_MODEL_IMPLEMENTED",
    "R14_GREEN_AUTHOR_RECEIPT_SEALED",
    "R14_GREEN_INDEPENDENT_ACCEPTED"
  ],
  "edges": [
    ["R14_ARCH_AUTHORED", "R14_ARCH_ACCEPTED"],
    ["R14_ARCH_ACCEPTED", "R14_FIXTURE_FROZEN"],
    ["R14_FIXTURE_FROZEN", "R14_RED_FAILED_RUN_CAPTURED"],
    ["R14_RED_FAILED_RUN_CAPTURED", "R14_RED_AUTHOR_RECEIPT_SEALED"],
    ["R14_ARCH_ACCEPTED", "R14_RED_AUTHOR_RECEIPT_SEALED"],
    ["R14_FIXTURE_FROZEN", "R14_RED_AUTHOR_RECEIPT_SEALED"],
    ["R14_RED_AUTHOR_RECEIPT_SEALED", "R14_RED_INDEPENDENT_ACCEPTED"],
    ["R14_ARCH_ACCEPTED", "R14_RED_INDEPENDENT_ACCEPTED"],
    ["R14_RED_INDEPENDENT_ACCEPTED", "R14_MODEL_IMPLEMENTED"],
    ["R14_FIXTURE_FROZEN", "R14_MODEL_IMPLEMENTED"],
    ["R14_MODEL_IMPLEMENTED", "R14_GREEN_AUTHOR_RECEIPT_SEALED"],
    ["R14_RED_INDEPENDENT_ACCEPTED", "R14_GREEN_AUTHOR_RECEIPT_SEALED"],
    ["R14_FIXTURE_FROZEN", "R14_GREEN_AUTHOR_RECEIPT_SEALED"],
    ["R14_GREEN_AUTHOR_RECEIPT_SEALED", "R14_GREEN_INDEPENDENT_ACCEPTED"]
  ],
  "principal_by_node": {
    "R14_ARCH_AUTHORED": "P_ARCH_AUTHOR",
    "R14_ARCH_ACCEPTED": "P_ARCH_REVIEWER",
    "R14_FIXTURE_FROZEN": "P_FIXTURE_AUTHOR",
    "R14_RED_FAILED_RUN_CAPTURED": "P_FIXTURE_AUTHOR",
    "R14_RED_AUTHOR_RECEIPT_SEALED": "P_FIXTURE_AUTHOR",
    "R14_RED_INDEPENDENT_ACCEPTED": "P_RED_REVIEWER",
    "R14_MODEL_IMPLEMENTED": "P_MODEL_IMPLEMENTER",
    "R14_GREEN_AUTHOR_RECEIPT_SEALED": "P_MODEL_IMPLEMENTER",
    "R14_GREEN_INDEPENDENT_ACCEPTED": "P_GREEN_REVIEWER"
  },
  "required_decisions": {
    "R14_ARCH_ACCEPTED": "ACCEPT",
    "R14_RED_INDEPENDENT_ACCEPTED": "ACCEPT",
    "R14_GREEN_INDEPENDENT_ACCEPTED": "ACCEPT"
  }
}
```

The graph has exactly 9 unique nodes and 14 unique edges. Every edge must be
forward in the listed order and Kahn elimination must leave zero nodes.
`P_FIXTURE_AUTHOR` legitimately owns three consecutive evidence nodes, but no
other role may share that principal.

## 3. Gate C1: independently provable fixture-first chronology

### 3.1 Allowed sequence

1. `P_ARCH_REVIEWER` authenticates this amendment/receipt and writes an R14
   architecture review whose decision is ACCEPT. Until then no R14 fixture or
   model may be authored.
2. `P_FIXTURE_AUTHOR` starts from a snapshot in which the exact R14 model path
   is absent. It records the architecture ACCEPT bytes/hash and an absence fact
   before creating the test.
3. The fixture author writes only the exact R14 test path, freezes its canonical
   bytes/SHA and ordered collected-node/mutation rosters, rechecks model
   absence, and runs the exact bounded RED command with cache and bytecode
   writes disabled.
4. The nonzero failed run is captured byte-for-byte. The test remains unchanged
   and the model remains absent. The fixture author seals the RED receipt.
5. `P_RED_REVIEWER` independently authenticates the architecture ACCEPT,
   fixture, absence facts, command/environment, transcript bytes, nonzero exit,
   expected failures, and mutation denominator, then returns ACCEPT or REPAIR.
6. Only an ACCEPT authorizes `P_MODEL_IMPLEMENTER` to create the exact model
   path. The model implementer may not edit the frozen test or RED evidence.
7. The green author receipt repeats the unchanged fixture SHA/node/mutation
   digests and binds the architecture/RED ACCEPT reviews, model SHA, exact
   commands, outputs, source/build hashes, and results.
8. `P_GREEN_REVIEWER` independently reproduces from those exact bytes and
   returns ACCEPT or REPAIR.

Filesystem timestamps, prose chronology, Git order, final-file constants, and
R13 receipts are never chronology authority.

### 3.2 Closed RED evidence schema

All SHA values below are lowercase 64-hex ordinary SHA-256 of exact bytes.
`canonical_receipt_digest` is the domain-separated digest of the receipt body
with that field removed. Transcript stdout/stderr are separately immutable
files or base64 fields whose decoded bytes reproduce size/SHA.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r14.red_author_receipt.schema.v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema", "principal_id", "signing_key_fingerprint",
    "architecture_accept_identity", "architecture_accept_sha256",
    "fixture_identity", "fixture_byte_size", "fixture_sha256",
    "ordered_node_ids", "ordered_node_ids_digest",
    "mutation_case_ids", "mutation_case_ids_digest",
    "model_absence_before_fixture", "model_absence_before_run",
    "command_argv", "working_directory_identity", "environment_rows",
    "expected_failure_stage", "expected_error_codes",
    "exit_code", "stdout_byte_size", "stdout_sha256",
    "stderr_byte_size", "stderr_sha256", "failed_run_receipt_sha256",
    "r13_authority", "r13_evidence_digests",
    "previous_gate_receipt_digest", "canonical_receipt_digest"
  ],
  "properties": {
    "schema": {"const": "cut4.r14.red_author_receipt.v1"},
    "principal_id": {"const": "P_FIXTURE_AUTHOR"},
    "signing_key_fingerprint": {"type": "string", "minLength": 1},
    "architecture_accept_identity": {"const": "review_fixtures/cut4_transactional_recon_publication_r14_amendment_independent_review_20260810.md"},
    "architecture_accept_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "fixture_identity": {"const": "tests/test_cut4_transactional_recon_publication_r14_preimplementation.py"},
    "fixture_byte_size": {"type": "integer", "minimum": 1},
    "fixture_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "ordered_node_ids": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
    "ordered_node_ids_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "mutation_case_ids": {"type": "array", "minItems": 64, "maxItems": 64, "items": {"type": "string", "minLength": 1}},
    "mutation_case_ids_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "model_absence_before_fixture": {"$ref": "#/$defs/AbsenceFact"},
    "model_absence_before_run": {"$ref": "#/$defs/AbsenceFact"},
    "command_argv": {"type": "array", "minItems": 3, "items": {"type": "string"}},
    "working_directory_identity": {"type": "string", "minLength": 1},
    "environment_rows": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/EnvironmentRow"}},
    "expected_failure_stage": {"enum": ["COLLECTION_MODEL_ABSENT", "EXECUTION_UNIMPLEMENTED"]},
    "expected_error_codes": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
    "exit_code": {"type": "integer", "not": {"const": 0}},
    "stdout_byte_size": {"type": "integer", "minimum": 0},
    "stdout_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "stderr_byte_size": {"type": "integer", "minimum": 0},
    "stderr_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "failed_run_receipt_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "r13_authority": {"const": false},
    "r13_evidence_digests": {"type": "array", "maxItems": 0},
    "previous_gate_receipt_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "canonical_receipt_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
  },
  "$defs": {
    "AbsenceFact": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "exact_path", "exists", "parent_snapshot_digest", "observation_command_digest", "fact_digest"],
      "properties": {
        "schema": {"const": "cut4.r14.path_absence_fact.v1"},
        "exact_path": {"const": "review_fixtures/cut4_transactional_recon_publication_r14_reference_model.py"},
        "exists": {"const": false},
        "parent_snapshot_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "observation_command_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "fact_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
      }
    },
    "EnvironmentRow": {
      "type": "object", "additionalProperties": false,
      "required": ["name", "value_digest"],
      "properties": {
        "name": {"enum": ["python_executable", "python_version", "pytest_version", "platform", "PYTHONDONTWRITEBYTECODE", "PYTEST_ADDOPTS"]},
        "value_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
      }
    }
  }
}
```

Both absence facts are distinct observations and bind the same absent path.
The failed-run JSON additionally carries stdout/stderr base64 and recomputation
fields. The RED reviewer verifies every digest from bytes, checks the fixture
SHA is unchanged after the run, checks the model path still absent, checks all
64 mutations collected, and signs the RED author receipt digest. Model work
before that independent ACCEPT permanently invalidates the chronology; deleting
and recreating the model cannot repair it.

## 4. Gate C2: source-derived total parser, rules, modes, and negative proof

### 4.1 Authenticated parser inputs

The future model accepts no `RawNodeSpec`, candidate list, mode rules, or
negative-proof inspected-node list from a caller. Its only source-semantic
inputs are:

1. the sealed canonical source-byte vector;
2. exact BAKE facts, receipt, and debt artifact bytes;
3. a parser package byte snapshot and immutable configuration; and
4. the selected ecosystem from the sealed pipeline plan.

For each BAKE artifact, `BakeArtifactBinding` contains canonical scratchpad
identity, exact bytes base64, byte size, ordinary SHA, parsed schema, run ID,
producer six-part work-unit key, producer contract digest, launch digest,
adapter ID/version/config digest, ecosystem, and artifact semantic digest. The
parser rejects any missing slot, duplicate slot, schema/byte mismatch, wrong
run/ecosystem, wrong producer, stale contract/launch, or debt omission.

The adapter registry is compiled into the future R14 model source. It is a
literal exact eight-row tuple for aptos/daml/evm/go/rust/solana/soroban/sui.
Its exact canonical row bytes, row count, and registry digest are fixture
constants frozen before the model exists; the model cannot accept a substitute
registry argument. The model source SHA is not guessed by the fixture. It is
computed from the later model bytes, bound by the GREEN author receipt, and
independently reproduced by the GREEN reviewer. Parser package ID/version,
post-implementation source SHA, configuration digest, registry digest, and all
three BAKE bindings enter every enumeration receipt.

### 4.2 Total byte consumption

`parse_source_vector(vector, authenticated_adapter)` is the only raw-universe
constructor. For each source file it emits an ordered `ParserCoverageRow`
partition with exact half-open offsets. The equations are:

```text
first.byte_start = 0
last.byte_end = source_file.byte_size
row[i].byte_end = row[i+1].byte_start
sum(row.byte_end-row.byte_start) = source_file.byte_size
each row's bytes = source_file.raw_bytes[start:end]
coverage rows have no overlap, gap, omission, or zero-length row
```

An empty file emits one typed EMPTY_FILE sentinel with `[0,0)` and a nonempty
empty-byte digest. Invalid UTF-8, binary, unknown grammar, parser failure, and
unsupported syntax emit exact debt coverage/candidate rows; no byte is skipped.
The receipt stores `covered_byte_count`, `source_byte_count`,
`unparsed_remainder_byte_count=0`, and the nonempty digest of the exact empty
remainder. Independent validation reparses from source bytes with the sealed
adapter and requires byte-identical coverage/candidate rows.

Each semantic candidate has an FK to one or more coverage rows and exact source
span bytes. Every coverage row has exactly one disposition:
`SEMANTIC_CANDIDATE`, `NONSEMANTIC_PROVED`, or `PARSE_DEBT`. Candidate omission,
invented candidate, suffix/prefix loss, gap, overlap, invalid-byte skip, or
remainder is blocking.

### 4.3 Immutable rules and exact mode mapping

`R14_MODE_RULES` is immutable module code, not a function parameter. The
fixture freezes the exact rule-row canonical bytes, row count, registry digest,
and model-source location, but never a guessed future model SHA. At load and
every mapping validation, the model recomputes the literal tuple; after
implementation, the GREEN receipts additionally bind the actual model-source
SHA. Validation rejects omitted, extra, reordered, relabeled, or rehashed
rules. No submitted receipt may carry an alternative rule registry.

Every parser candidate receives exactly one mode/classification row by the
literal rules. Unknown candidates become UNRESOLVED typed debt. The exact
candidate multiset equals the exact mode-row multiset by candidate ID and
multiplicity. Rebuilding every descendant after a rule relabel still fails
against fixture-frozen literal rule bytes.

### 4.4 Non-vacuous PROVED_NONE

`PROVED_NONE` requires one `TotalNegativeProof` with exact FKs to:

```text
source vector + parser package/config + all BAKE bindings + coverage rows +
candidate rows + rule registry + mode rows + base rows + all graph/probe edges
+ the target reference identity
```

Its `candidate_ids`, `classification_row_ids`, and `edge_ids` are exact ordered
multisets equal to those independently regenerated for the complete byte
vector. It carries counts, digests, and an absence result from the sealed
negative analyzer. The parser coverage receipt must have zero unparsed bytes
and no unresolved/debt row relevant to the target identity. Empty applicable
sets, a reduced self-reported candidate list, unparsed suffix, parse debt,
missing BAKE debt slot, or any relevant UNRESOLVED row yields
UNRESOLVED_FALLBACK, never PROVED_NONE.

S/P0/D/M/R must eventually bind every source, BAKE, parser, coverage,
candidate, rule, mode, classification, edge, and negative-proof digest from
this one construction. R14 does not authorize that integration.

## 5. Gate C3: reflected dependency DAG and typed journal state machine

### 5.1 Fixture-frozen constructor denominator

Before the model exists, the R14 fixture freezes this exact constructor node
and dependency-edge denominator:

```json
{
  "schema": "cut4.r14.constructor_dependency_denominator.v1",
  "nodes": [
    "PriorEnvelope", "SourceSnapshot", "PrivatePlan", "PredicateEvidence",
    "BaseRequestIntent", "RequestDigest", "InvalidFileFact",
    "JournalStatePreimage", "AttemptAllocation", "InvocationRecord",
    "PayloadRecord", "ExplicitZeroProof", "ProviderReceipt",
    "ProviderPrivateV4", "NormalizerExecutionEvidence",
    "NormalizedSemanticRow", "NormalizerReceipt", "NormalizerOutcome",
    "ExecutionEvidence", "QueryReceipt", "TerminalEnvelope",
    "AbortedUnobserved", "JournalRecord", "PublicationLink",
    "CommittedPublicationReceipt", "DiffSide", "DiffRow", "M4", "R4",
    "CompletionReceipt"
  ],
  "edges": [
    ["PriorEnvelope", "BaseRequestIntent"],
    ["SourceSnapshot", "PrivatePlan"],
    ["SourceSnapshot", "PredicateEvidence"],
    ["PrivatePlan", "BaseRequestIntent"],
    ["PredicateEvidence", "BaseRequestIntent"],
    ["BaseRequestIntent", "RequestDigest"],
    ["RequestDigest", "JournalStatePreimage"],
    ["InvalidFileFact", "JournalStatePreimage"],
    ["JournalStatePreimage", "AttemptAllocation"],
    ["RequestDigest", "AttemptAllocation"],
    ["AttemptAllocation", "InvocationRecord"],
    ["PrivatePlan", "InvocationRecord"],
    ["PredicateEvidence", "InvocationRecord"],
    ["SourceSnapshot", "InvocationRecord"],
    ["InvocationRecord", "PayloadRecord"],
    ["PrivatePlan", "PayloadRecord"],
    ["InvocationRecord", "ExplicitZeroProof"],
    ["PrivatePlan", "ExplicitZeroProof"],
    ["PredicateEvidence", "ExplicitZeroProof"],
    ["PayloadRecord", "ProviderReceipt"],
    ["ExplicitZeroProof", "ProviderReceipt"],
    ["InvocationRecord", "ProviderReceipt"],
    ["PrivatePlan", "ProviderReceipt"],
    ["PredicateEvidence", "ProviderReceipt"],
    ["ProviderReceipt", "ProviderPrivateV4"],
    ["PayloadRecord", "ProviderPrivateV4"],
    ["PrivatePlan", "ProviderPrivateV4"],
    ["PayloadRecord", "NormalizerExecutionEvidence"],
    ["InvocationRecord", "NormalizerExecutionEvidence"],
    ["ProviderReceipt", "NormalizerExecutionEvidence"],
    ["NormalizerExecutionEvidence", "NormalizedSemanticRow"],
    ["PayloadRecord", "NormalizedSemanticRow"],
    ["ProviderReceipt", "NormalizedSemanticRow"],
    ["PrivatePlan", "NormalizedSemanticRow"],
    ["NormalizedSemanticRow", "NormalizerReceipt"],
    ["NormalizerExecutionEvidence", "NormalizerReceipt"],
    ["NormalizerReceipt", "NormalizerOutcome"],
    ["NormalizedSemanticRow", "NormalizerOutcome"],
    ["PayloadRecord", "NormalizerOutcome"],
    ["ProviderReceipt", "ExecutionEvidence"],
    ["NormalizerOutcome", "ExecutionEvidence"],
    ["NormalizedSemanticRow", "ExecutionEvidence"],
    ["InvocationRecord", "ExecutionEvidence"],
    ["ExecutionEvidence", "QueryReceipt"],
    ["RequestDigest", "QueryReceipt"],
    ["ProviderReceipt", "QueryReceipt"],
    ["RequestDigest", "TerminalEnvelope"],
    ["AttemptAllocation", "TerminalEnvelope"],
    ["InvocationRecord", "TerminalEnvelope"],
    ["PrivatePlan", "TerminalEnvelope"],
    ["ProviderReceipt", "TerminalEnvelope"],
    ["ProviderPrivateV4", "TerminalEnvelope"],
    ["NormalizerOutcome", "TerminalEnvelope"],
    ["NormalizedSemanticRow", "TerminalEnvelope"],
    ["ExecutionEvidence", "TerminalEnvelope"],
    ["QueryReceipt", "TerminalEnvelope"],
    ["RequestDigest", "AbortedUnobserved"],
    ["AttemptAllocation", "AbortedUnobserved"],
    ["InvocationRecord", "AbortedUnobserved"],
    ["JournalStatePreimage", "JournalRecord"],
    ["AttemptAllocation", "JournalRecord"],
    ["InvocationRecord", "JournalRecord"],
    ["TerminalEnvelope", "JournalRecord"],
    ["AbortedUnobserved", "JournalRecord"],
    ["TerminalEnvelope", "PublicationLink"],
    ["JournalRecord", "PublicationLink"],
    ["QueryReceipt", "PublicationLink"],
    ["PublicationLink", "CommittedPublicationReceipt"],
    ["TerminalEnvelope", "CommittedPublicationReceipt"],
    ["PrivatePlan", "DiffSide"],
    ["ProviderReceipt", "DiffSide"],
    ["ProviderPrivateV4", "DiffSide"],
    ["NormalizerOutcome", "DiffSide"],
    ["NormalizedSemanticRow", "DiffSide"],
    ["DiffSide", "DiffRow"],
    ["PrivatePlan", "M4"],
    ["ProviderPrivateV4", "M4"],
    ["NormalizerOutcome", "M4"],
    ["NormalizedSemanticRow", "M4"],
    ["DiffRow", "M4"],
    ["CommittedPublicationReceipt", "M4"],
    ["M4", "R4"],
    ["R4", "CompletionReceipt"],
    ["M4", "CompletionReceipt"],
    ["CommittedPublicationReceipt", "CompletionReceipt"]
  ]
}
```

This denominator has exactly 30 unique nodes and 85 unique edges, with every
edge forward in the listed order and zero Kahn remainder. The future fixture
must freeze the exact canonical JSON bytes and digest before the model exists.

### 5.2 Reflection must equal the frozen denominator

Every future model dataclass field that is an ID, digest, FK, embedded typed
row, ordered child roster, prior object, source bytes, or constructor input must
carry immutable metadata `depends_on=<TypeName>` and
`dependency_kind=<ID|DIGEST|FK|EMBEDDED|ROSTER|PREIMAGE>`. Every constructor
is decorated with a literal preimage-field registry. Reflection derives:

```text
ReflectedNodes = every closed dataclass participating in construction
ReflectedEdges = field metadata edges UNION constructor-preimage edges
ContractFields = every dependency-bearing dataclass field and preimage slot
```

The validator requires byte-for-byte ordered-set equality:

```text
ReflectedNodes = FrozenNodes
ReflectedEdges = FrozenEdges
ReflectedContractFields = FrozenContractFields
```

It also rejects an unannotated ID/digest/FK/roster/preimage field, an annotated
field absent from an actual constructor preimage, an extra declared edge,
unknown endpoint, back edge, or nonzero Kahn remainder. ExecutionEvidence and
QueryReceipt are closed dataclasses, never inline free digests. The actual
normalizer direction is `NormalizedSemanticRow -> NormalizerReceipt ->
NormalizerOutcome`; no forward-reference fiction is permitted.

### 5.3 Exact typed journal and CAS

The future reference contract remains one live-shaped fixed artifact:

```text
key: sc/core/evm/codex/recon/transactional_journal_r14
identity: scratchpad:_cut4_r14/private/recon_query_journal_state.v2.json
class/writer/mode: DRIVER_GENERATED / DRIVER / REPLACE
schema: cut4.r14.query_journal_state.v2
consumer: recon/canonical_publication_successor_v2
```

Its registry is fixture-scoped until a future separately authorized production
cutover. The current resolver and ArtifactLedger remain unchanged.

`RecordKind` is exactly `ATTEMPT_ALLOCATION`, `INVOCATION`,
`ABORTED_UNOBSERVED`, `TERMINAL_ENVELOPE`, or `PUBLICATION_LINK`. A closed
kind registry maps each value to one exact dataclass schema, decoder, ID field,
digest field, allowed predecessor kinds, and attempt-lineage rule. Decoding
rejects unknown/extra/missing fields and noncanonical bytes. For every record:

```text
record.request_digest = state.request_digest
decoded object canonical bytes = record.object bytes
decoded ID/digest = record.object ID/digest
decoded request/attempt = record request/attempt where fields apply
record ordinal/previous digest/previous size/SHA = exact prior authority
```

`validate_state_bytes` parses canonical bytes into the exact JournalState type,
reserializes byte-identically, validates header/state digests, invalid-fact
union, every record kind/object, allocation sequence, invocation allocation FK,
abort/retry lineage, unique active attempt, terminal, link, and membership.

`atomic_rewrite` first validates both current and next canonical states. Every
successful write, including an ordinary append and recovery, requires
`next.generation = current.generation + 1`, preserves namespace and request,
and sets `next.prior_state_sha256` to the exact current canonical file SHA. An
ordinary append preserves header authority, invalid facts, and every prior
record byte-for-byte and appends exactly one state-machine-authorized record.
A recovery transition also increments by exactly one, adds exactly the newly
authenticated invalid-fact set once, and starts the one permitted empty
successor chain while retaining the prior state SHA as its history authority.
No +0 rewrite, +2 skip, request/namespace swap, fact deletion, prior-record
substitution, repeated-fact successor, or caller-built alternative next state
is accepted. Before compare-and-swap, any next state containing a terminal or
publication record must pass the same recursive TerminalEnvelope,
PublicationLink, and CommittedPublicationReceipt validation used by replay.

Replay first validates the full current state, decodes and fully validates the
unique TerminalEnvelope, requires its exact TERMINAL_ENVELOPE record and one
matching PUBLICATION_LINK record, validates the committed public receipt, and
only then returns the stored terminal bytes. Terminal validation recomputes
request/allocation/invocation/private-plan/provider/private/normalizer/
normalized/evidence/query-receipt rosters and digests from upstream objects.
The selected active retry allocation must match terminal and records. SUCCESS/
SUCCESS_EMPTY exhausted replay retains the exact nonempty c3 token; terminal
failure/timeout rules remain typed.

## 6. Gate C4: explicit zero, normalized joins, complete diffs, and committed completion

### 6.1 SUCCESS-zero proof

SUCCESS with zero payloads is legal only with an `ExplicitZeroProof`; all
other SUCCESS receipts require it to be absent. SUCCESS_EMPTY is query-level
and remains distinct. The closed proof schema is:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r14.explicit_zero_proof.schema.v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema", "explicit_zero_proof_id", "consumer_row_id", "query_id",
    "query_input_digest", "request_digest", "attempt_id",
    "invocation_digest", "private_plan_row_id", "private_plan_digest",
    "provider_id", "provider_receipt_identity",
    "applicability_predicate_id", "selection_predicate_id",
    "predicate_evidence_digest", "tool_id", "tool_version",
    "tool_configuration_digest", "input_snapshot_digests",
    "bounded_limits_digest", "invocation_exit_class", "stdout_sha256",
    "stderr_sha256", "enumerated_result_count", "exhausted_cursor",
    "zero_evidence_digest", "zero_receipt_digest", "proof_digest"
  ],
  "properties": {
    "schema": {"const": "cut4.r14.explicit_zero_proof.v1"},
    "explicit_zero_proof_id": {"type": "string", "pattern": "^zproof_[0-9a-f]{64}$"},
    "consumer_row_id": {"type": "string", "minLength": 1},
    "query_id": {"type": "string", "minLength": 1},
    "query_input_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "request_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "attempt_id": {"type": "string", "minLength": 1},
    "invocation_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "private_plan_row_id": {"type": "string", "minLength": 1},
    "private_plan_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "provider_id": {"type": "string", "minLength": 1},
    "provider_receipt_identity": {"type": "string", "minLength": 1},
    "applicability_predicate_id": {"type": "string", "minLength": 1},
    "selection_predicate_id": {"type": "string", "minLength": 1},
    "predicate_evidence_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "tool_id": {"type": "string", "minLength": 1},
    "tool_version": {"type": "string", "minLength": 1},
    "tool_configuration_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "input_snapshot_digests": {"type": "array", "minItems": 1, "items": {"type": "string", "pattern": "^[0-9a-f]{64}$"}},
    "bounded_limits_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "invocation_exit_class": {"const": "ZERO"},
    "stdout_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "stderr_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "enumerated_result_count": {"const": 0},
    "exhausted_cursor": {"type": "string", "pattern": "^c3_[0-9a-f]{64}$"},
    "zero_evidence_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "zero_receipt_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "proof_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
  }
}
```

The provider receipt identity must be derived without the proof ID, then the
proof binds that identity and zero evidence; the final provider outcome binds
the proof. This staged rule is acyclic. The validator reconstructs evidence,
receipt, proof ID/digest, cursor exhaustion, predicates, invocation, plan, and
zero count. A free digest, empty object, stale query, or provider-global zero
cannot satisfy it.

### 6.2 Independent normalizer authority and exact joins

Each payload has exactly one NormalizerExecutionEvidence produced from the
independent normalizer invocation/tool output before normalized rows. It binds
payload ID/digest/exact bytes SHA, provider receipt, Kp plan, normalizer binary
ID/version/config/source hash, argv/input snapshots, exit/timeout class,
stdout/stderr exact bytes size/SHA, and evidence digest.

Every NormalizedSemanticRow repeats and equals that payload ID/digest,
provider receipt identity/digest, all twelve Kp fields, plan source snapshot,
and normalizer evidence ID/digest. NormalizerReceipt is then independently
constructed from evidence plus the exact ordered normalized-row roster, count,
digest, status, debt code, and receipt ID/digest. NormalizerOutcome binds the
receipt and repeats the exact roster. ACCEPTED requires count greater than zero
and no debt. REJECTED/DEBT/FAILURE/TIMEOUT/MALFORMED require count zero, empty
row roster, exact status-specific debt, and nonempty evidence/receipt. No free
evidence or self-rehashed substitute is accepted.

Exact one-to-one equations are:

```text
provider payload multiset = provider-private payload multiset
provider payload IDs = normalizer-evidence payload IDs
normalizer receipt row IDs/digest = actual normalized rows by payload
normalizer outcome row IDs/digest = same actual normalized rows by payload
normalized row payload/provider/Kp/evidence fields = joined source fields
```

### 6.3 Complete diff sides and counts

Each `DiffSide` contains all twelve Kp fields plus side, source kind, source
schema, source ID, source canonical body bytes base64, exact byte size/SHA,
source semantic digest, and the closed typed-value union
`ROW_MULTIPLICITY | BOOLEAN | INTEGER | COUNT`. `ROW_MULTIPLICITY` carries an
exact nonnegative integer multiplicity plus the source body; `BOOLEAN` carries
one JSON boolean and no integer/count value; `INTEGER` carries one signed JSON
integer that is explicitly rejected when its runtime type is boolean; `COUNT`
carries one nonnegative JSON integer, also never boolean. Every inactive union
field is absent, not null or defaulted. The body bytes must decode, parse under
the named closed schema when nonempty, and recompute ID/digest/Kp. An empty row
side uses `ROW_MULTIPLICITY`, source kind/schema/ID empty, exact empty bytes,
count zero, and nonempty empty-byte SHA/digest.

`DiffRow` contains exact expected and observed DiffSide objects of the same
typed-value union branch, a closed diff kind/source mapping, exact typed before
and after values, actual non-boolean integer expected/observed multiplicity
counts, signed count delta, row ID, and digest. Boolean, signed integer, count,
and row-multiplicity comparisons have separate diff kinds and serializers; no
cross-type coercion is legal. The multiplicity counts equal multiset
cardinality; `2` can never collapse to boolean `true` or integer `1`. Every
diff row is validated before aggregate construction.

### 6.4 M4/R4/completion from validated children and commit receipt

The M4 builder accepts the actual upstream PrivatePlan, ProviderReceipt,
ProviderPrivateV4 rows, NormalizerExecutionEvidence, NormalizerReceipts,
NormalizerOutcomes, NormalizedSemanticRows, DiffRows, PublicationLink, and
CommittedPublicationReceipt. It validates every child and FK first, derives
the exact sorted arrays/digests, and has no constructor accepting precomputed
aggregate digests alone.

R4 repeats byte-identical validated data arrays, names M4, and derives its
manifest/digest. CompletionReceipt binds M4, R4, all child array digests,
terminal record, publication link, committed public file identity/size/SHA,
commit actor, PhaseIO contract/launch digests, and the independently validated
CommittedPublicationReceipt ID/digest. Completion validation reruns all child
validators from upstream objects. A stale child digest, fabricated Kp,
unanchored normalized row, invalid diff, rebuilt aggregate, missing commit
receipt, or public byte mismatch fails even when M4/R4 self-hashes agree.

## 7. Exact R14 RED mutation denominator

The future fixture must freeze and execute exactly these 64 unique case IDs.
For any case ID `g.x`, the stable expected error code is
`R14_` plus its uppercased ID with `.` replaced by `_`. Extra cases require a
new architecture amendment; omitted, skipped, xfailed, duplicate, or renamed
cases fail RED review.

```json
{
  "schema": "cut4.r14.red_mutation_denominator.v1",
  "chronology": [
    "chronology.arch_accept_missing",
    "chronology.arch_decision_not_accept",
    "chronology.model_present_at_fixture_freeze",
    "chronology.model_present_at_failed_run",
    "chronology.fixture_hash_transcript_mismatch",
    "chronology.node_roster_digest_mismatch",
    "chronology.mutation_roster_digest_mismatch",
    "chronology.environment_identity_missing",
    "chronology.failure_stage_mismatch",
    "chronology.failed_exit_zero",
    "chronology.stdout_digest_mismatch",
    "chronology.stderr_digest_mismatch",
    "chronology.principal_or_key_reuse",
    "chronology.model_started_before_red_accept",
    "chronology.fixture_changed_after_red",
    "chronology.r13_evidence_used_as_authority"
  ],
  "source_parser": [
    "source.raw_spec_omission_rebuild",
    "source.unenumerated_recognized_suffix",
    "source.unenumerated_recognized_prefix",
    "source.coverage_byte_gap",
    "source.coverage_byte_overlap",
    "source.coverage_reordered",
    "source.empty_file_sentinel_missing",
    "source.invalid_utf8_skipped",
    "source.bake_facts_bytes_substitution",
    "source.bake_receipt_wrong_run",
    "source.bake_debt_slot_omitted",
    "source.parser_version_config_swap",
    "source.parser_package_hash_swap",
    "source.rule_registry_rehashed_relabel",
    "source.mode_mapping_omission_rebuild",
    "source.omission_plus_false_proved_none"
  ],
  "dag_journal": [
    "dag.self_declared_required_field_omission",
    "dag.reflected_extra_dependency",
    "dag.normalized_outcome_direction_reversed",
    "dag.inline_untyped_evidence_digest",
    "journal.same_generation_rewrite",
    "journal.next_generation_namespace_swap",
    "journal.next_generation_request_swap",
    "journal.next_generation_invalid_fact_or_prior_record_swap",
    "journal.generation_skip_plus_two",
    "journal.recovery_request_swap",
    "journal.repeated_sealed_fact_new_generation",
    "journal.unregistered_record_kind",
    "journal.record_request_mismatch",
    "journal.self_hashed_untyped_terminal_replay",
    "journal.mismatched_active_retry_allocation",
    "journal.rehashed_invalid_terminal_roster_replay"
  ],
  "private_completion": [
    "private.success_zero_without_proof",
    "private.zero_proof_query_swap",
    "private.zero_proof_receipt_tamper",
    "private.normalized_payload_id_swap",
    "private.normalized_payload_digest_swap",
    "private.normalized_provider_receipt_swap",
    "private.normalized_evidence_swap",
    "private.free_normalizer_evidence",
    "private.free_normalizer_receipt",
    "private.accepted_zero_normalized_rows",
    "private.rejection_with_nonzero_rows",
    "private.diff_count_boolean_collapse",
    "private.diff_kp_field_missing",
    "private.diff_source_body_schema_id_mismatch",
    "private.rebuilt_m4_with_invalid_private_child",
    "private.completion_stale_unanchored_commit_receipt"
  ]
}
```

The group arithmetic is 16 + 16 + 16 + 16 = 64. The fixture must also include
positive deterministic construction/replay cases, but those do not replace or
increase the 64-case mutation denominator recorded by the RED receipt.

## 8. Review and future ownership gates

The independent architecture review first validates predecessor hash, both
R14 files, every JSON root/schema, path registry, 9/14 principal DAG, 30-node
constructor denominator and exact edge count, 64-case denominator, local
references, LF/BOM/fences, principal separation, and authority ceiling. Only
an explicit ACCEPT advances the DAG.

The future fixture owner writes only the exact R14 test/transcript/RED receipt.
The RED reviewer writes only its review. The model implementer writes only the
exact R14 model and GREEN author receipt. The GREEN reviewer writes only its
review. No one may modify predecessor or another principal's artifact.

All future commands are bounded to exact R14 paths with bytecode/cache writes
disabled. No provider, audit, production, ArtifactLedger, G3, commit, push,
install, cutover, or release operation is permitted by any gate.

## 9. Claim ceiling and non-goals

R14 specifies an implementable proof sequence and exact preimplementation
contracts. It does not claim architecture ACCEPT, RED provenance, an R14
fixture/model, production registration, filesystem guarantees, parser
correctness, provider availability, protocol security, audit completion,
cutover, release, or readiness. It intentionally provides no protocol hints or
answers. Part-0 and every operational authority remain false.
