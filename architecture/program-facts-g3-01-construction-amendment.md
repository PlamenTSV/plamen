# Program Facts G3-01 Construction Amendment

Status: `CONTRACT_ONLY_PENDING_INDEPENDENT_REVIEW`

Normative parent: `architecture/program-facts-runtime-cutover-spec.md`, 238,989
bytes, SHA-256
`2f2025cf636ca80df560d7568760f6ebfc114a2c344a895940ea76566c953c79`
(the **PF-R2 contract**).

This amendment resolves only four G3-01 construction ambiguities. It neither
changes the PF-R2 160-case/691-execution denominator nor grants implementation,
provider, publication, release, cutover, consumer, finding, severity,
confidence, refutation, suppression, terminal-negative, or clean-certification
authority. If this amendment and PF-R2 can be read two ways, the interpretation
with less authority and the exact PF-R2 outcome/census wins. No artifact created
under this amendment can accept itself or a later artifact.

## 1. Admission and unresolved inputs

Construction MUST NOT begin until a single accepted G3-00 admission manifest
pins all of the following by `{path,size_bytes,sha256}`: the compact R19 seed
admission and its external acceptance/review; the PF-R2 specification, source
census, and review; graph-v2; ownership-v2; all public-v3 schemas; the public-v3
architecture review; the provider-registry-v2 schema and registry; the
six-component PhaseIO work-unit/RACI/operation-order contract; and every
section-4 schema already accepted at G3-00. The manifest path and identity are
deliberately unresolved until G3-00 produces and independently accepts them.
No filename, branch, commit, working-tree presence, model response, generated
count, or embedded `PASS` substitutes for those identities.

The following values also remain deliberately unresolved until their
predecessors exist: every G3-01 schema/vector/review identity; fixture bytes;
fixture file identities; scope/body/authority IDs; oracle and cross-check
author identities; Python executable identity; expected-member identities and
tree digest; fixture-manifest, denominator, and review identities. They MUST be
computed from stable bytes in the order below and MUST NOT be predicted.

The amendment itself requires a reviewer who authored neither this amendment,
the G3-00 subjects, fixture corpus, oracle/cross-check, nor production modules.
The exact receipt path is
`review_fixtures/program_facts_runtime_gate3/construction/PROGRAM_FACTS_G3_01_CONSTRUCTION_AMENDMENT_INDEPENDENT_REVIEW.v1.json`;
it conforms to the closed
`program_facts_independent_review.v1.schema.json#/$defs/g3_01_construction_amendment_review_v1`
fragment fixed at G3-00, pins this amendment's stable file identity, and has the
exact checks `PFG301-01-PARENT-PIN`, `PFG301-02-LITERAL-MUTATIONS`,
`PFG301-03-SCHEMA-REVIEWS`, `PFG301-04-PROTOCOL-PINS`,
`PFG301-05-ORACLE-INVOCATION`, `PFG301-06-ACYCLIC-AUTHORITY`, and
`PFG301-07-INDEPENDENCE`. All must be `PASS` with nonempty evidence, no open
blocking finding. Its passing disposition is
`PASS_G3_01_CONSTRUCTION_AMENDMENT_FOR_PREIMPLEMENTATION_ONLY`; the receipt
grants no authority other than allowing the PF-R2 G3-01 construction sequence
to start. That receipt is an input to, never an output of, the G3-01 reviews.

## 2. Literal case and mutation binding

### 2.1 Authoritative location and order

Every case fixture MUST contain this canonical file before expected bytes are
created:

```text
review_fixtures/program_facts_runtime_gate3/fixtures/<case_id>/literal_case_binding.v1.json
```

It is a normal `fixture_file` in the PF-R2 fixture manifest and occurs in every
execution's `input_file_identities`. Its closed schema is the fragment
`https://plamen.local/schemas/program_facts_runtime_fixture_manifest.v1.schema.json#/$defs/literal_case_binding_v1`.
The fragment is defined in the section-4 fixture-manifest schema; no new schema
file or JSON-Schema keyword is introduced.

The file contains exactly:

```text
schema_version  const plamen.program_facts_literal_case_binding.v1
specification   exact PF-R2 file_identity
case_id         exact A00..A27|B00..B31|C00..C47|D00..D15|E00..E15|F00..F19
partition       A|B|C|D|E|F
test_node       exact PF-R2 section-12.3 test node
fixture_root    exact review_fixtures/program_facts_runtime_gate3/fixtures/<case_id>/
base_files      sorted unique [literal_base_file]
executions      sorted unique [literal_execution]
binding_body_sha256 SHA-256(CJ(object without binding_body_sha256))
```

`base_files` sorts by UTF-8 path and each row is exactly
`{path,source_bytes_base64,size_bytes,sha256}`. `path` is below the exact
`fixture_root`; Base64 is PF-R2 `Base64BytesV1`; decoded size/hash must match.
It includes every pre-mutation regular file other than
`literal_case_binding.v1.json`. The fixture manifest independently includes the
binding's external file identity and every execution includes that identity;
the binding never embeds its own size or hash. The fixture manifest's
`fixture_files` is exactly the binding identity union the identities derived
from `base_files`, and still equals the union of all execution inputs as PF-R2
requires. Missing or additional content in either projection is invalid.
No mutation may target `literal_case_binding.v1.json`; it is construction
authority metadata, not a mutation carrier.

Executions sort by UTF-8 `execution_id` and contain exactly:

```text
execution_id                 exact PF-R2 execution ID
base_execution_id_or_null    PF-R2 metamorphic base or null
relation_id_or_null          IdentifierV3 or null
invocation_label             NATIVE_DRIVER|LEGACY_CLAUDE_WRAPPER|FUTURE_CODEX_WRAPPER
host_profile_or_null         closed PF-R2 host or null
ecosystem_or_null            closed PF-R2 ecosystem or null
allowed_operations           sorted unique PF-R2 operation set
ordered_mutation_bindings    ordered [literal_mutation_binding]
expected_outcome             exact {exit_class,status,debt_codes,publication_effect,active_head_generation_relation}
```

The execution ordering and names are exactly PF-R2: A/B/D/F have one
`<case>-PRIMARY`; E has one primary except the four named E08 occurrences; each
C case has four trials by `T0,T1,T2,T3`, and within each trial
`NATIVE,CLAUDE,CODEX`. The resulting counts are mechanically 160/691. Case IDs,
test nodes, execution IDs, operation privileges, or outcomes are never inferred
from oracle output.

### 2.2 Closed mutation binding

Each `literal_mutation_binding` contains exactly:

```text
ordinal             uint32, contiguous from zero
operation           one exact PF-R2 section-12.2 mutation-union object
targets             sorted unique [mutation_target]
before              mutation_state
after               mutation_state
relation            NONE|BYTE_REPLACEMENT|FILE_DELETION|FILE_ADDITION|
                    JSON_SET|JSON_DELETE|DUPLICATE_KEY|AUTHORITY_FLIP|
                    TRUNCATION|PATH_ALIAS|STABLE_READ_DRIFT|REVIEWER_SUBSTITUTION|
                    HOST_PROFILE_CHANGE|INVOCATION_CHANGE|CRASH_POINT|ACTIVE_REPLAY
```

`mutation_target` is exactly
`{path,json_pointer_or_null,target_role:PRIMARY|ALIAS_TARGET|ACTIVE_HEAD|ACTIVE_PROJECTION}`.
It uses the PF-R2 mutation-target derivation and ordering; RFC 6901 unescapes
`~1` then `~0`, and a pointer is evaluated against the state produced by every
lower ordinal. No prose alias or display label is a pointer.

`mutation_state` contains exactly:

```text
path_states       sorted unique [{path,state,source_bytes}]
json_values       sorted unique [{path,json_pointer,value_state}]
reviewer_or_null  null|{path,principal_id}
host_profile_or_null closed host|null
invocation_label_or_null closed invocation|null
crash_or_null     null|{marker,occurrence}
replay_or_null    null|{active_head:file_identity,active_projection:file_identity|null}
```

`path_states` sort by UTF-8 path. `state` is
`ABSENT|REGULAR_FILE|DELETED|SYMLINK|REPARSE|HARDLINK|CASEFOLD_ALIAS`.
`source_bytes` is `{kind:ABSENT}` or
`{kind:PRESENT,base64_bytes,size_bytes,sha256}`; it is `PRESENT` exactly for a
regular file and binds the complete old/new bytes, not only their digest.
`json_values` sort by `(UTF8(path),UTF8(json_pointer))`; `value_state` is
`{kind:ABSENT}` or `{kind:PRESENT,value:canonical_fixture_json_value,value_sha256}`,
where the hash is `SHA-256(CJ(value))`. This tagged form distinguishes JSON null
from absence.

`NONE` is the sole binding when used and has empty targets, byte-identical
before/after states, and relation `NONE`. Every other operation has the exact
PF-R2 variant fields and a same-named relation. File/JSON operations bind the
complete target state immediately before and after that ordinal. `ALIAS_PATH`
binds both alias and target; `DRIFT_AFTER_STABLE_READ` binds pre-read and
replacement bytes; reviewer/host/invocation/crash/replay operations bind the
corresponding typed state and do not invent a file target. An operation/state,
target/state, decoded-byte identity, pointer/value, alias-kind, or outcome
disagreement is `ORACLE_OR_DENOMINATOR_INVALID`.

The reference oracle independently applies the serialized operations to a fresh
copy and requires exact equality to every recorded `after`. The cross-check does
the same for its literal 56-execution roster. The fixture manifest and
denominator retain the exact PF-R2 shapes: their `mutations` and
`mutation_targets` are projections of this file, not new fields. Both projections
must be equal in both directions.

## 3. Section-4 schema conformance and review

### 3.1 No custom schema vocabulary

Every section-4 schema keeps exactly the PF-R2 Draft-2020-12 vocabulary and
allowed keyword set. It may use `$defs` to define the two carrier shapes below;
it MUST NOT use `examples`, `x-*`, annotations, formats, dynamic references, or
another vocabulary. The carrier files are external JSON artifacts.

For a schema with basename `<schema_filename>`, the exact paths are:

```text
review_fixtures/program_facts_runtime_gate3/schema_contracts/<schema_filename>/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/<schema_filename>/independent_review.v1.json
```

The subject schema defines exact closed fragments
`#/$defs/gate3_schema_conformance_vectors_v1` and
`#/$defs/gate3_schema_conformance_review_v1`. Their normalized schema bodies
must equal the amendment's reviewed template digest recorded in the G3-00
admission; differing local definitions fail. This supplies per-schema carrier
validation without a recursive additional schema file or forbidden keyword.

### 3.2 Vector carrier

`conformance_vectors.v1.json` contains exactly:

```text
schema_version       const plamen.program_facts_schema_conformance_vectors.v1
subject              exact subject-schema file_identity and $id
vectors              sorted unique [schema_vector]
keyword_occurrences  sorted unique [schema_keyword_occurrence]
vector_count         uint32 equal to vectors length
body_sha256          SHA-256(CJ(object without body_sha256))
```

A `schema_vector` is exactly
`{vector_id,target_schema_pointer,instance,expected:VALID|INVALID,covers:sorted unique [schema_pointer]}`.
A `schema_keyword_occurrence` is exactly
`{schema_pointer,keyword,positive_vector_ids,negative_vector_ids}`. Pointers are
RFC 6901 and vectors sort by ID; occurrences sort by pointer then the PF-R2
keyword-precedence ordinal.

`target_schema_pointer` is the empty string for the subject-schema root or a
canonical RFC 6901 pointer to exactly one subschema in the stable subject. Every
literal `~` must be `~0` or `~1`; resolution unescapes `~1` then `~0`, array
tokens are canonical unsigned decimal indices without a leading zero except
`0`, and re-encoding the resolved tokens must reproduce the input pointer
byte-for-byte. A target is a schema node only when reached from the root through
schema-valued edges: `$defs/<name>`, `properties/<name>`, `propertyNames`,
`additionalProperties` when schema-valued, `prefixItems/<index>`, `items`,
`contains`, `allOf|anyOf|oneOf/<index>`, `not`, `if`, `then`, or `else`.
Pointers into ordinary instance values, keyword arrays/maps themselves, enum or
const values, missing members, noncanonical array indices, or scalar/non-schema
nodes are invalid. Invalid escaping, a missing token, a non-schema target, an
unresolved reference, or a target outside the stable subject makes the vector
carrier invalid before any instance result is considered.

The independent evaluator resolves `target_schema_pointer` against the
stable-read subject bytes and validates `instance` against that exact subschema,
retaining the subject's base `$id` and the same closed, network-disabled registry
for exact `$ref` resolution. It MUST NOT validate the instance against the root
unless the target is the empty pointer, choose a target from `covers`, or retry
against another subschema. A VALID/INVALID disagreement fails the vector and its
review.

Every `covers` member is an exact `keyword_occurrences.schema_pointer` whose
containing schema node is either the target node itself or is reached from it by
the evaluator's actual schema-valued descent/`$ref` trace for that instance.
The target itself is represented by its keyword-occurrence pointer, not by a
synthetic marker. Occurrences outside that evaluated closure, ancestors of the
target, or occurrences reachable only from another target are forbidden. After
mapping each covered keyword to its containing schema node, those nodes must be
equal or pairwise ancestor/descendant along one evaluated schema-node lineage;
keywords on the same node are related, but sibling property/item/composite
branches are unrelated and require distinct vectors. Thus a root vector cannot
claim unevaluated or multiple unrelated branch coverage.

Coverage is mechanical over the stable schema, following every same-document or
contract-pinned exact `$ref`: every occurrence of `type`, `const`, `enum`,
`required`, `additionalProperties`, `propertyNames`, `dependentRequired`,
`contains`/bounds, item/property/length/number bounds, `uniqueItems`, `pattern`,
and every composite/conditional branch has at least one accepting witness and
one rejecting witness where rejection is semantically possible. Every tagged
union branch has a positive vector; zero, multiple, unknown, missing, and extra
branches are negative vectors. Closed objects have missing-required and
additional-field negatives. Array ordering/uniqueness and every enum/const
member are covered. Vector IDs are unique before set conversion. VALID/INVALID
is recomputed by an independent Draft-2020-12 evaluator with network and remote
resolution disabled; production error text/classes are never evidence.

The two carrier definitions are finite schema targets. Their dedicated vectors
use targets exactly `/$defs/gate3_schema_conformance_vectors_v1` and
`/$defs/gate3_schema_conformance_review_v1`; they cannot claim root or other
`$defs` coverage. Each carrier definition permits a finite minimal instance
whose nested vector/check/finding arrays are empty where that individual
subschema does not require a semantic passing review. Positive and one-field
negative instances cover every finite keyword occurrence through the same
target/lineage rules above. No vector instance is required or permitted to
embed another nonempty conformance-vector carrier, so this meta-coverage
terminates rather than recursively reproducing itself.

### 3.3 Per-schema independent review

The review carrier contains exactly:

```text
schema_version   const plamen.program_facts_schema_conformance_review.v1
review_id        pfsr-<32hex>
subject          exact schema file_identity
vectors          exact conformance-vector file_identity
reviewer         {principal_id,organization,role}
independence     {subject_author_separate:true,vector_author_separate:true,
                  production_implementer_separate:true,oracle_author_separate:true,
                  workspace_clean:true,no_self_generated_evidence:true}
checks           exact sorted rows SCHEMA-DRAFT, VOCABULARY-KEYWORDS,
                 CLOSED-OBJECTS, REF-CLOSURE, VECTOR-CARRIER,
                 KEYWORD-OCCURRENCE-COVERAGE, POSITIVE-REPLAY,
                 NEGATIVE-REPLAY, IDENTITY-STABLE-READ; all PASS|FAIL with evidence
findings         sorted closed finding rows
open_findings    exact sorted open IDs
disposition      PASS_SCHEMA_CONTRACT_FOR_GATE3_PREIMPLEMENTATION_ONLY|REJECTED
review_body_sha256 SHA-256(CJ(object without review_body_sha256))
```

`review_id = "pfsr-" || SHA-256(CJ({domain:"PROGRAM_FACTS_SCHEMA_REVIEW_V1",
subject,vectors,reviewer,independence,checks,findings,open_findings,disposition}))[0:32]`.
Passing requires every check PASS, no open blocking finding, stable subject/vector
bytes, and reviewer separation. The review is not encoded with a custom keyword
and grants contract-only authority.

Every section-4 schema has exactly one governing vector/review pair. A schema
already accepted at G3-00 uses the exact pair pinned by G3-00 and is not reviewed
again; G3-00 is invalid if it did not satisfy this contract. Every remaining
schema uses the canonical paths above. G3-01 publishes a sorted, bidirectional
`schema_contract_index.v1.json` under the same `schema_contracts/` directory,
mapping all 51 PF-R2 section-4 paths to schema/vector/review identities and
`accepted_stage:G3_00|G3_01`. It conforms to the closed
`program_facts_independent_review.v1.schema.json#/$defs/schema_contract_index_v1`
fragment fixed at G3-00; the fragment defines exactly
`{schema_version,schemas,schema_count:51,index_body_sha256}` and each sorted row
exactly `{schema,vectors,independent_review,accepted_stage}`. Missing,
additional, duplicate, or dual-stage rows fail. The contract freeze later pins
this index and identities; it does not retroactively create a review.

## 4. WTx and ArtifactLedger predecessor protocol pins

The PF-R2 synthetic-governance `wtx_ledger_protocols` field contains exactly the
following two already-source-pinned identities, sorted by path:

```text
scripts/artifact_ledger.py
  size_bytes: 523963
  sha256: baf2998ab5fc57c8a85d2551c61a4df46094ee907c564f652037cbb75ad8be97
scripts/worker_transaction.py
  size_bytes: 150510
  sha256: 47773f533a5e133626f4c3fb580af1fc53fc931832eab7bf07393c4508b52c35
```

These are PF-R2 S14 current-boundary evidence, not v3 implementation or launch
authority. G3-01 stable-reads them and records their exact identities directly;
it MUST NOT generate a protocol document that claims historical acceptance,
copy their bytes under a new authoritative name, or infer a later module hash.
Drift blocks G3-01 and requires a new reviewed parent amendment; it is never
silently rehashed.

The preimplementation contract freeze pins these two predecessor identities,
the already-reviewed v3 WTx/Ledger schemas, operation-order/RACI digest, and the
explicit status `PREDECESSOR_SOURCE_EVIDENCE_ONLY`. G3-05/G3-07 later implement
v3 behavior. Their actual production module/symbol identities are new
post-contract facts recorded at G3-08 and the release freeze; equality to these
predecessor hashes is neither required nor sufficient. Thus G3-01 freezes what
already exists without retroactive synthesis or pre-authorizing future code.

## 5. Fixed-root oracle and cross-check invocation

The oracle sources retain the PF-R2 import allowlist only. They import no
`sys`, `os`, `argparse`, `subprocess`, `runpy`, `importlib`, production module,
schema helper, network module, or dynamic loader. Each computes the repository
root only as `Path(__file__).resolve(strict=True).parents[3]`, verifies its own
resolved repository-relative path is the exact PF-R2 path, and uses only fixed
repository-relative input/output paths. No CLI arguments or environment values
are read.

Direct invocation contracts are exact:

```text
<python-3.12.10> review_fixtures/program_facts_runtime_gate3/oracle/program_facts_reference_oracle_v1.py
<python-3.12.10> review_fixtures/program_facts_runtime_gate3/oracle/program_facts_oracle_crosscheck_v1.py
```

The reference invocation builds or byte-validates the fixed expected tree and
writes:

```text
review_fixtures/program_facts_runtime_gate3/oracle/run/reference_oracle_result.v1.json
```

The cross-check invocation reads, never rewrites, that tree, recomputes the exact
PF-R2 56-execution roster, and writes:

```text
review_fixtures/program_facts_runtime_gate3/oracle/run/oracle_crosscheck_result.v1.json
```

Each result is closed and contains exactly
`{schema_version,program,source,python,specification,fixture_root,case_count,
execution_count,member_count,member_tree_sha256,status,body_sha256}`. `program`
is `REFERENCE_ORACLE_V1|ORACLE_CROSSCHECK_V1`; `source`, `python`, and
`specification` are file identities; `fixture_root` is the PF-R2 const path;
reference counts are 160/691; cross-check counts are 56/56; `status` is
`PASS|FAIL`; and `body_sha256` omits only itself. The member-tree digest is
`SHA-256(CJ(sorted file identities compared or produced))`. A PASS file is
diagnostic evidence for the independent review and never accepts itself.

The separate deterministic harness is:

```text
scripts/test_program_facts_gate3_oracle_fixed_root.py
```

It owns process invocation, exit-code/timeout capture, AST import denial,
Python-version/executable identity validation, physical-root/alias checks,
before/after tree census, result-schema validation, and read-only enforcement
for the cross-check. It is outside the oracle, excluded from production runtime
closure, and cannot create expected bytes or a review. It launches only the two
literal argv arrays above with shell disabled, an empty allowlisted environment,
repository cwd, closed handles, and bounded resources. An exception/nonzero
exit, timeout, result mismatch, unexpected write, import violation, root alias,
or corpus change by the cross-check fails. Production code and packaging must
neither import nor ship the harness, oracle, results, or expected tree.

## 6. Acyclic construction order and acceptance ceiling

The only valid order is:

1. accept G3-00 and this amendment through independent receipts;
2. create/review remaining section-4 schemas and all conformance pairs, then
   freeze the 51-row schema-contract index;
3. create literal fixture inputs/bindings and the exact 160 red test nodes;
4. create/review synthetic governance from only existing identities;
5. create the 160/691 scope, then authority, then its independent review;
6. separately author reference oracle and cross-check, produce expected bytes,
   fixture manifest, denominator, manifests/results, and independently review
   them; and
7. only then create/review the PF-R2 preimplementation contract freeze.

No step consumes its own hash, an expected result to derive scope/privilege, a
future freeze, production implementation, or generated review. A full expected
receipt or expected provenance envelope remains forbidden. Any change to a
predecessor after a dependent identity exists invalidates the dependent chain;
repair creates a new reviewed version rather than editing frozen evidence.
