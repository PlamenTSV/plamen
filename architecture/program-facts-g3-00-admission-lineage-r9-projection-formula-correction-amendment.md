# Program Facts G3-00 admission-lineage Part-0 r9 projection-formula correction amendment

Status: `CREATE_ONLY_CONTRACT; R7_REJECTED_FROZEN; R8_REPAIR_FROZEN; R8_ROSTER_REJECTED_NEGATIVE; R9_DOWNSTREAM_ABSENT; ALL_AUTHORITY_FALSE`

This amendment is a new, non-retroactive successor to the independently reviewed
r8 architecture attempt. It changes no r1-r8 byte and creates no roster,
observation, review, schema, validator, harness, execution, GREEN, acceptance,
aggregate, production, provider, or runtime artifact. The only artifacts
authorized by this authoring step are this contract and its author receipt. R7
remains historical rejected evidence. R8 remains a `REPAIR` architecture whose
prospective roster was written before the missing formula was repaired. Neither
r7 nor r8 grants r9 authority.

R9 re-states, rather than implicitly inheriting, the complete r8 closure of the
three blocking r7 findings:

1. the governed pre-review object, its recursively closed schema, exact scope
   sets, binary check results, fixed registry, and ordered evidence association
   are all immutable contract values;
2. path states come only from a separately authenticated read-only observer in a
   lease-bound PRE/COMMIT receipt pair, never from a caller, validator default,
   harness constant, nullable parameter, timestamp, or synthetic map; and
3. GREEN is not self-certifying: an independent receipt validator reconstructs
   the frozen oracle and every identity/result tuple from this contract and emits
   a separately signed validation receipt before semantic acceptance review.

R9 adds exactly one semantic correction: it defines the contract-local,
noncircular `separation_projection.projection_body_sha256` preimage, field set,
canonical member order, digest formula, and validation order. Versioned r9 paths
and the mandatory rejected-r8 negative are lineage consequences of that
correction, not a widening of the F001-F003 methodology.

The amendment is Part-0 generic. Protocol names are empty, protocol-specific
branching and semantic shortcuts are false, and every authority value is false.

## 1. Authenticated rejected parents and correction boundary

The following four artifacts were re-read as bytes and remain the mandatory r7
historical boundary:

| Ordinal | Evidence ID | Exact path | Bytes | SHA-256 | Meaning |
|---:|---|---|---:|---|---|
| 0 | `R7_CONTRACT` | `architecture/program-facts-g3-00-admission-lineage-r7-semantic-successor-correction-amendment.md` | 65040 | `f0e1e20976afd27fb20a222ca7f345807d441f914e5b7de4c6c602592d3225de` | frozen r7 contract |
| 1 | `R7_PREIMPLEMENTATION_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PREIMPLEMENTATION_REVIEW.v1.json` | 28538 | `d6b99da439b4dea157eb73c157e4216a67fde353304443eec3a7b1be6756c5dd` | historical governed PASS, not r9 authority |
| 2 | `R7_GREEN_RECEIPT` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_GREEN_RECEIPT.v1.json` | 13588 | `2d6f1bb9a0959e6df8403f8dac9e521c4a5d962237fa226bd2b614f282808515` | historical GREEN claim, rejected by review |
| 3 | `R7_SEMANTIC_ACCEPTANCE_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_ACCEPTANCE_REVIEW.v1.json` | 23737 | `747abf8f6f3659645d56bb73ddb8ab15a8b40fb53fb1b80e0f641ce37e8e1e0f` | exact `REJECTED` disposition |

The r7 acceptance review has eight FAIL rows and exactly three
`BLOCKING/OPEN` findings:

- `ALR7A-R7-F001-RESEALED-NONCONFORMING-REVIEW-ACCEPTED`;
- `ALR7A-R7-F002-SYNTHETIC-STAGE-ORACLE`; and
- `ALR7A-R7-F003-SELF-ORACLED-GREEN-RECEIPT`.

Its `open_findings` and `failure_bindings` are authoritative rejected evidence.
R9 does not turn any r7 FAIL into PASS, repair r7 bytes, or treat r7 GREEN as
semantic acceptance. The F001-F003 rules below are complete local r9 rules; no
r7 formula, schema, prose, or authority is incorporated by implication.

The immediate r8 parent boundary is also exact:

| Ordinal | Evidence ID | Exact path | Bytes | SHA-256 | Meaning |
|---:|---|---|---:|---|---|
| 8 | `R8_CONTRACT` | `architecture/program-facts-g3-00-admission-lineage-r8-semantic-closure-correction-amendment.md` | 72023 | `b080ac7235a46ff41faab66f70ba1a93252d29e4b7e6639ba7205780eb18f464` | frozen r8 architecture |
| 9 | `R8_AUTHOR_RECEIPT` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R8_SEMANTIC_CLOSURE_CORRECTION_AUTHOR_RECEIPT.md` | 7566 | `ee0b559ba7e36b600dbc308372d62f305e3f168f108eb217f39d38013cd43138` | bounded r8 authorship only |
| 10 | `R8_ARCHITECTURE_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R8_ARCHITECTURE_INDEPENDENT_REVIEW_20260810.md` | 4758 | `4a63a21450a9714739fe0e330c8372f546120b78874d03db283ad965bb3f671f` | exact `VERDICT_REPAIR`, sole asserted defect is the missing projection formula |
| 11 | `R8_REJECTED_ROSTER` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R8_BOUND_PRINCIPAL_ROSTER.v1.json` | 7769 | `f53fc414cb8ddf0b7c09c979e92084f6802df3a6add545227afef223b8cf8dfc` | mandatory rejected historical negative; never r9 roster or authority |

The r8 review says exactly `REPAIR` and asserts exactly one defect: r8 requires
`projection_body_sha256` lexically but provides no contract-local semantic
preimage or formula. The r8 roster's supplied digest therefore cannot be proven
from r8 bytes. Its presence cannot bootstrap an observer, review, admission, or
downstream node. R9 authenticates it only as a negative test: accepting its
path, bytes, principals, keys, signatures, projection digest, or record identity
as any r9 object is `R8_REJECTED_ROSTER_SUBSTITUTION` and rejects.

For exact evidence-association testing, these r7 diagnostics and r8 boundary
identities form one ordered, immutable 12-entry catalog and cannot be relabeled
between checks:

```json
{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_HISTORICAL_EVIDENCE_CATALOG_V1","entries":[{"evidence_id":"R7_CONTRACT","path":"architecture/program-facts-g3-00-admission-lineage-r7-semantic-successor-correction-amendment.md","size_bytes":65040,"sha256":"f0e1e20976afd27fb20a222ca7f345807d441f914e5b7de4c6c602592d3225de"},{"evidence_id":"R7_PREIMPLEMENTATION_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PREIMPLEMENTATION_REVIEW.v1.json","size_bytes":28538,"sha256":"d6b99da439b4dea157eb73c157e4216a67fde353304443eec3a7b1be6756c5dd"},{"evidence_id":"R7_GREEN_RECEIPT","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_GREEN_RECEIPT.v1.json","size_bytes":13588,"sha256":"2d6f1bb9a0959e6df8403f8dac9e521c4a5d962237fa226bd2b614f282808515"},{"evidence_id":"R7_SEMANTIC_ACCEPTANCE_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_ACCEPTANCE_REVIEW.v1.json","size_bytes":23737,"sha256":"747abf8f6f3659645d56bb73ddb8ab15a8b40fb53fb1b80e0f641ce37e8e1e0f"},{"evidence_id":"R7_ROSTER","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_BOUND_PRINCIPAL_ROSTER.v1.json","size_bytes":5062,"sha256":"ad325d12c1a1c59dab284ab0f67aadab3cb8cabebdbc595375103a2e9f80e37b"},{"evidence_id":"R7_GREEN_SCHEMA","path":"rules/schemas/program_facts_g3_00_admission_lineage_r7_semantic_green_receipt.v1.schema.json","size_bytes":7595,"sha256":"e4fe8e47abd8169ef58b5755b8ffcc288128f3a5600df7972d6caa88b274b33d"},{"evidence_id":"R7_PRIMARY_VALIDATOR","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r5_ordering_semantics_v1.py","size_bytes":33247,"sha256":"2fe7d7619f0f8e0403ccf0c5ae2e5dc05873a19dbc605ad930f09f3f51567aef"},{"evidence_id":"R7_GREEN_HARNESS","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r7_semantic_successor_green_v1.py","size_bytes":9676,"sha256":"fd3d075ff92f998842d6537017619ffbce6449c294db8318ccb8ed7492329450"},{"evidence_id":"R8_CONTRACT","path":"architecture/program-facts-g3-00-admission-lineage-r8-semantic-closure-correction-amendment.md","size_bytes":72023,"sha256":"b080ac7235a46ff41faab66f70ba1a93252d29e4b7e6639ba7205780eb18f464"},{"evidence_id":"R8_AUTHOR_RECEIPT","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R8_SEMANTIC_CLOSURE_CORRECTION_AUTHOR_RECEIPT.md","size_bytes":7566,"sha256":"ee0b559ba7e36b600dbc308372d62f305e3f168f108eb217f39d38013cd43138"},{"evidence_id":"R8_ARCHITECTURE_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R8_ARCHITECTURE_INDEPENDENT_REVIEW_20260810.md","size_bytes":4758,"sha256":"4a63a21450a9714739fe0e330c8372f546120b78874d03db283ad965bb3f671f"},{"evidence_id":"R8_REJECTED_ROSTER","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R8_BOUND_PRINCIPAL_ROSTER.v1.json","size_bytes":7769,"sha256":"f53fc414cb8ddf0b7c09c979e92084f6802df3a6add545227afef223b8cf8dfc"}]}
```

The catalog array order and every tuple are immutable. The last entry is always
a rejected negative, never a candidate authority. A check's evidence is an
ordered list of catalog IDs; the semantic validator expands IDs from this exact
catalog and requires byte-for-byte file identity. Reorder, swap, relabel,
duplicate, omission, or extra evidence rejects even if every referenced file is
individually authentic.

## 2. Authority ceiling and preserved lineage

R3.13, V8, Cut4, ledger V5/T1, and every earlier G3 artifact retain only their
previously reviewed meanings. No current production, driver, provider, native,
or artifact-ledger identity is pinned here. Candidate code may not import a
production module or earlier candidate module and may not be consumed by
production.

The exact authority ceiling is the following 29-key object, used unchanged in
every r9 record and inline schema:

```json
{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}
```

`Part0` is exactly
`{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}`.

## 3. Eleven prospectively bound and pairwise-distinct principals

The exact r9 role order is:

0. `R9_AMENDMENT_AUTHOR`
1. `R9_ROSTER_BINDER`
2. `R9_READ_ONLY_STAGE_OBSERVER`
3. `R9_INDEPENDENT_PREIMPLEMENTATION_REVIEWER`
4. `R9_INDEPENDENT_PREIMPLEMENTATION_ADMISSION_REVIEWER`
5. `R9_SCHEMA_RENDERER`
6. `R9_PRIMARY_SEMANTIC_VALIDATOR_IMPLEMENTER`
7. `R9_INDEPENDENT_RECEIPT_VALIDATOR_IMPLEMENTER`
8. `R9_GREEN_HARNESS_AUTHOR`
9. `R9_GREEN_EXECUTOR`
10. `R9_INDEPENDENT_SEMANTIC_ACCEPTANCE_REVIEWER`

Ordinal 0 is extracted from this receipt's exact `Author principal:` field and
must equal `Codex:/root/g3_r9_projection_formula_arch`. Ordinals 1-10 are
signed assignments made by ordinal 1. Each record actor is bound to the roster
by ordinal, exact principal ID, Ed25519 public key, role, and signed canonical
preimage. A Boolean `independent` assertion has no meaning.

All 55 unordered internal pairs must be unequal. Every r9 value, including the
author, must be unequal to each member of this exact 24-value prior-producer
set, for exactly 264 cross-version comparisons and no declared continuity. The
last 12 values are extracted from the rejected r8 roster plus its independent
architecture reviewer; their inclusion prevents rejected identities from being
recycled as purportedly independent r9 principals and grants them no authority:

```text
Codex:/root/g3_r3_correction_author_short
Codex:/root/g3_r5_principal_roster_binder_short
Codex:/root/g3_r5_ordering_review_short
Codex:/root/g3_r5_schema_renderer_short
Codex:/root/g3_r5_fixture_author_short
Codex:/root/g3_r6_principal_roster_binder_short
Codex:/root/g3_r6_preimplementation_review_short
Codex:/root/g3_r7_principal_roster_binder_short
Codex:/root/g3_r7_preimplementation_review_short
Codex:/root/g3_r7_semantic_successor_implementer_short
Codex:/root/g3_r7_green_executor_short
Codex:/root/g3_r7_semantic_acceptance_review_short
Codex:/root/g3_r8_semantic_correction_arch
Codex:/root/g3_r8_principal_roster_binder
Codex:/root/g3_r8_stage_observer
Codex:/root/g3_r8_preimplementation_reviewer
Codex:/root/g3_r8_preimplementation_admission_reviewer
Codex:/root/g3_r8_schema_renderer
Codex:/root/g3_r8_primary_semantic_validator_implementer
Codex:/root/g3_r8_independent_receipt_validator_implementer
Codex:/root/g3_r8_green_harness_author
Codex:/root/g3_r8_green_executor
Codex:/root/g3_r8_semantic_acceptance_reviewer
Codex:/root/g3_next_authority_route_short
```

The receipt-validator principal and implementation must be distinct from the
primary validator, harness author, executor, and acceptance reviewer. The stage
observer must be distinct from both preimplementation reviewers and every code
author/executor. Aliasing, ordinal substitution, role relabeling, key reuse,
assignment substitution, or signature substitution rejects.

Canonical JSON (`CJ`) means RFC 8785 JCS UTF-8 bytes after duplicate-member
rejection and NFC validation. No value is normalized or repaired. Exact identity
formulas are:

```text
roster_body_sha256 = SHA256(CJ(roster without only roster_body_sha256))
roster_id = "pfg3alr9pr-" || SHA256(CJ({domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_ROSTER_V1",roster:<roster without roster_id,binding_signature,roster_body_sha256>}))[0:32]
assignment_sha256[i] = SHA256(CJ({domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_ASSIGNMENT_V1",role:roles[i],principal_ordinal:i,principal_id:principal_ids[i],public_key_base64:public_keys[i]}))
binding_signature.signed_preimage_sha256 = SHA256(CJ({domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_BINDING_V1",roster:<roster without roster_id,binding_signature,roster_body_sha256>}))
principal_projection_sha256 = SHA256(CJ({roles:roles,principal_ids:principal_ids,public_keys:public_keys}))
projection_body_sha256 = SHA256(CJ(separation_projection without only projection_body_sha256))

record_body_sha256 = SHA256(CJ(record without only record_body_sha256))
record_id = prefix(record_kind) || SHA256(CJ({domain:domain(record_kind),record:<record without record_id,actor.signature_base64,record_body_sha256>}))[0:32]
actor.signed_preimage_sha256 = SHA256(CJ({domain:signature_domain(record_kind),record:<record without record_id,actor.signature_base64,record_body_sha256>}))
```

The projection formula is contract-local and noncircular. Its input domain is
exactly the `separation_projection` object, not the roster, a wrapper, an r7/r8
object, or an implementation-defined domain tag. Before canonicalization it has
exactly these six fields and no others, in this semantic field order:

```text
internal_pair_count
cross_prior_pair_count
declared_continuity_pairs
unexpected_internal_equal_pairs
unexpected_cross_equal_pairs
principal_projection_sha256
```

RFC 8785 `CJ` serializes those ASCII member names in this exact canonical order:

```text
cross_prior_pair_count
declared_continuity_pairs
internal_pair_count
principal_projection_sha256
unexpected_cross_equal_pairs
unexpected_internal_equal_pairs
```

The value of the canonical input is therefore exactly the parsed
`separation_projection` after deleting only its own
`projection_body_sha256` member. No nulling, empty-string replacement,
recursive deletion, inherited r7 formula, supplied member ordering, or roster
body projection is permitted. Validation order is mandatory: reject duplicate
members/BOM/non-LF/non-NFC; validate the closed roster schema; enforce the exact
six-field projection input and `55`/`264` counts; recompute and compare
`principal_projection_sha256`; delete only `projection_body_sha256`; compute
`SHA256(CJ(...))` and compare its lowercase hex value; only then validate
`roster_body_sha256`, `roster_id`, assignment hashes, and the binding signature.
Because the inner digest excludes itself and the outer roster digest consumes
the completed projection object, neither digest is circular.

Prefixes are exactly `pfg3alr9opre-`, `pfg3alr9pre-`, `pfg3alr9ocommit-`,
`pfg3alr9admit-`, `pfg3alr9exec-`, `pfg3alr9green-`, `pfg3alr9gval-`, and
`pfg3alr9accept-` for observer PRE, pre-review, observer COMMIT, admission,
execution, GREEN, GREEN validation, and acceptance respectively. All hashes
are lowercase hexadecimal. Removing a field removes exactly that field at the
stated object level.

## 4. Complete path registry and stage membership

This literal JSON value is the entire r9 artifact universe. It is not extensible.

```json
{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_PATH_REGISTRY_V1","entries":[{"ordinal":0,"stage":"PRE_REVIEW_REQUIRED_INPUT","kind":"BOUND_ROSTER","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_BOUND_PRINCIPAL_ROSTER.v1.json"},{"ordinal":1,"stage":"PRE_REVIEW_REQUIRED_INPUT","kind":"OBSERVER_PRE_RECEIPT","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_STAGE_OBSERVER_PRE_RECEIPT.v1.json"},{"ordinal":2,"stage":"REVIEW_ATOMIC_OUTPUT","kind":"PREIMPLEMENTATION_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_PREIMPLEMENTATION_REVIEW.v1.json"},{"ordinal":3,"stage":"POST_REVIEW_PRE_ADMISSION_INPUT","kind":"OBSERVER_COMMIT_RECEIPT","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_STAGE_OBSERVER_COMMIT_RECEIPT.v1.json"},{"ordinal":4,"stage":"PREIMPLEMENTATION_ADMISSION_OUTPUT","kind":"PREIMPLEMENTATION_ADMISSION","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_PREIMPLEMENTATION_ADMISSION.v1.json"},{"ordinal":5,"stage":"POST_ADMISSION_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r9_principal_roster.v1.schema.json"},{"ordinal":6,"stage":"POST_ADMISSION_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r9_stage_observation.v1.schema.json"},{"ordinal":7,"stage":"POST_ADMISSION_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r9_preimplementation_review.v1.schema.json"},{"ordinal":8,"stage":"POST_ADMISSION_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r9_preimplementation_admission.v1.schema.json"},{"ordinal":9,"stage":"POST_ADMISSION_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r9_semantic_evidence.v1.schema.json"},{"ordinal":10,"stage":"POST_ADMISSION_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r9_semantic_acceptance.v1.schema.json"},{"ordinal":11,"stage":"POST_ADMISSION_OUTPUT","kind":"PRIMARY_SEMANTIC_VALIDATOR","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r9_review_semantics_v1.py"},{"ordinal":12,"stage":"POST_ADMISSION_OUTPUT","kind":"INDEPENDENT_RECEIPT_VALIDATOR","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r9_green_receipt_semantics_v1.py"},{"ordinal":13,"stage":"POST_ADMISSION_OUTPUT","kind":"GREEN_HARNESS","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r9_semantic_closure_green_v1.py"},{"ordinal":14,"stage":"POST_ADMISSION_OUTPUT","kind":"EXECUTION_RECEIPT","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_EXECUTION_RECEIPT.v1.json"},{"ordinal":15,"stage":"POST_ADMISSION_OUTPUT","kind":"GREEN_RECEIPT","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_SEMANTIC_GREEN_RECEIPT.v1.json"},{"ordinal":16,"stage":"POST_ADMISSION_OUTPUT","kind":"GREEN_VALIDATION_RECEIPT","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_GREEN_VALIDATION_RECEIPT.v1.json"},{"ordinal":17,"stage":"POST_ADMISSION_OUTPUT","kind":"SEMANTIC_ACCEPTANCE_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_SEMANTIC_ACCEPTANCE_REVIEW.v1.json"}]}
```

Entries have exactly four fields. Ordinals are exactly integers `0..17` in
array order. Paths are unique, case-sensitive, NFC repo-relative strings using
`/`; absolute roots, URI syntax/encoding, empty segments, `.`, `..`, colon,
backslash, controls, symlink/reparse aliases, case folding, and normalization
aliases reject. Membership is the ordered projection of the 18 paths. The
pre-review required set is exactly ordinals `0,1`; the review target is exactly
ordinal `2`; the downstream-absent-at-review set is exactly ordinals `3..17`
(15 paths). The post-admission set is exactly ordinals `5..17` (13 paths).

Exact digest formulas are:

```text
path_registry_sha256 = SHA256(CJ(path_registry))
path_membership_sha256 = SHA256(CJ([entry.path for entry in path_registry.entries]))
downstream_at_review_sha256 = SHA256(CJ([entry.path for entry in path_registry.entries[3:18]]))
post_admission_paths_sha256 = SHA256(CJ([entry.path for entry in path_registry.entries[5:18]]))
```

The governed review embeds the literal registry and all four recomputed hashes.
A supplied hash never authenticates a value. Missing, extra, reordered,
aliased, duplicated, or extended entries reject.

## 5. Separately authenticated read-only observation transaction

### 5.1 Exact observer protocol

The observer protocol is this immutable value:

```json
{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_READ_ONLY_OBSERVER_PROTOCOL_V1","root_policy":"OPEN_ROOT_ONCE_AND_PIN_IDENTITY","path_policy":"COMPONENT_WISE_NO_FOLLOW_BENEATH_ROOT","hash_policy":"STABLE_READ_SIZE_HASH_IDENTITY_RESTAT_BEFORE_AFTER","absence_policy":"PIN_PARENT_IDENTITY_AND_PROVE_LEAF_ABSENT_BEFORE_AFTER","mutation_policy":"NO_CREATE_DELETE_RENAME_WRITE_EXCEPT_OWN_ATOMIC_RECEIPT_PATHS","lease_policy":"ONE_EXCLUSIVE_SESSION_FROM_PRE_SNAPSHOT_THROUGH_ADMISSION_ATOMIC_WRITE","windows_policy":{"open":"CreateFileW_OPEN_REPARSE_POINT","identity":"volume_serial_plus_file_id","reject":"ANY_REPARSE_COMPONENT_OR_IDENTITY_DRIFT"},"posix_policy":{"open":"openat2_RESOLVE_BENEATH_NO_SYMLINKS_OR_COMPONENT_OPENAT_O_NOFOLLOW","identity":"st_dev_plus_st_ino","reject":"ANY_SYMLINK_COMPONENT_OR_IDENTITY_DRIFT"},"unsupported_policy":"INDETERMINATE_NO_AUTHORITY","timestamp_authority":false,"caller_path_states_authority":false,"observer_principal_ordinal":2}
```

The observer opens the repository root once, pins its native identity, resolves
each registry path component-by-component without following links/reparse
points, and records two complete ordered snapshots. For a PRESENT row it records
exact path, `state:PRESENT`, size, SHA-256, native root identity, native file
identity, link/reparse classification, and stable-read before/after identity. For
an ABSENT row it records exact path, `state:ABSENT`, pinned parent native
identity, exact leaf name, and two absence probes. Any unstable read, inaccessible
parent, unsupported no-follow primitive, reparse/symlink component, identity
drift, partial enumeration, or observer error yields `INDETERMINATE` and cannot
be represented as PASS.

The PRE snapshot universe is exactly registry ordinals `0..17`. It requires
ordinal 0 PRESENT with its exact file identity and ordinals `1..17` ABSENT at
both probes. The observer atomically creates ordinal 1 with create-new/no-replace
semantics while retaining its exclusive session lease. The review may consume
only that signed PRE receipt and must not accept a path-state parameter.

The reviewer then validates the closed object and atomically creates ordinal 2
while the same observer lease remains held. The observer's COMMIT snapshots
require ordinals `0,1,2` PRESENT with exact identities and ordinals `3..17`
ABSENT at both probes. It atomically creates ordinal 3, signs the exact PRE
receipt identity, review identity, session ID, nonce, path registry digest, both
snapshot digests, root identity, and lease handoff to principal ordinal 4. The
admission reviewer validates that signed pair and atomically creates ordinal 4
before the observer releases the lease. Thus no schema, code, harness, or GREEN
execution can race between review and admission.

`path_states` is mandatory only inside the observer-signed PRE/COMMIT receipts;
it is forbidden in the reviewer API, harness inputs, validator defaults, and
admission caller data. `None`, omitted rows, caller-constructed maps, expected
maps, timestamps, Git mtimes, or a receipt not signed by roster ordinal 2 reject.

### 5.2 Crash, absence, replay, and repair-then-degrade

- Crash before atomic PRE creation leaves ordinal 1 absent and grants nothing.
  Same-session retry may repeat observation.
- A byte-identical replay while the same live lease and process-start identity
  remain valid returns the same deterministic receipt ID and performs no write.
- A PRE receipt with a dead/different lease, nonce, process-start identity, root
  identity, registry digest, or roster identity is `STALE_OBSERVATION`; it cannot
  be refreshed, overwritten, or treated as absence evidence.
- Crash after PRE but before review, or after review but before COMMIT, leaves an
  incomplete historical attempt. No admission can be written. Because boundary
  state cannot be reconstructed after lease loss, continuation requires a new
  successor revision/path set; deletion, replacement, and retroactive resealing
  are forbidden.
- Missing PRE, review, or COMMIT receipt makes admission FAIL. Missing admission
  keeps all post-admission outputs unauthorized.
- Crash after admission but before any render is safely replayable by authenticating
  the immutable admission bytes. Each downstream path remains create-new.
- Any uncertain state produces a typed `INDETERMINATE_NO_AUTHORITY` observer
  failure record outside the authoritative path set for human review; it never
  becomes PASS and never halts unrelated pipeline work.

These rules favor a visible degraded handoff over a false historical proof.

## 6. Closed review semantics and immutable evidence association

The preimplementation review has exactly these 24 ordered checks and evidence
IDs. This value is the oracle; validator constants are not.

```json
{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_PREIMPLEMENTATION_CHECK_REGISTRY_V1","checks":[{"check_id":"ALR9-01-SUBJECT-AUTHOR-ROSTER-EXACT","evidence_ids":["R9_CONTRACT","R9_AUTHOR_RECEIPT","R9_ROSTER"]},{"check_id":"ALR9-02-R7-R8-PARENT-BYTES-EXACT","evidence_ids":["R7_CONTRACT","R7_PREIMPLEMENTATION_REVIEW","R7_GREEN_RECEIPT","R7_SEMANTIC_ACCEPTANCE_REVIEW","R8_CONTRACT","R8_AUTHOR_RECEIPT","R8_ARCHITECTURE_REVIEW","R8_REJECTED_ROSTER"]},{"check_id":"ALR9-03-R7-REJECTED-R8-REPAIR-ROSTER-NEGATIVE-EXACT","evidence_ids":["R7_SEMANTIC_ACCEPTANCE_REVIEW","R8_CONTRACT","R8_ARCHITECTURE_REVIEW","R8_REJECTED_ROSTER"]},{"check_id":"ALR9-04-R7-F001-SEALED-OBJECT-CLOSED","evidence_ids":["R7_CONTRACT","R7_PREIMPLEMENTATION_REVIEW","R7_PRIMARY_VALIDATOR","R7_SEMANTIC_ACCEPTANCE_REVIEW"]},{"check_id":"ALR9-05-R7-F002-OBSERVER-ORIGIN-CLOSED","evidence_ids":["R7_CONTRACT","R7_PREIMPLEMENTATION_REVIEW","R7_PRIMARY_VALIDATOR","R7_GREEN_HARNESS","R7_SEMANTIC_ACCEPTANCE_REVIEW"]},{"check_id":"ALR9-06-R7-F003-INDEPENDENT-ORACLE-CLOSED","evidence_ids":["R7_CONTRACT","R7_GREEN_SCHEMA","R7_PRIMARY_VALIDATOR","R7_GREEN_HARNESS","R7_GREEN_RECEIPT","R7_SEMANTIC_ACCEPTANCE_REVIEW"]},{"check_id":"ALR9-07-ELEVEN-PRINCIPALS-PROJECTION-FORMULA-BOUND","evidence_ids":["R9_CONTRACT","R9_AUTHOR_RECEIPT","R9_ROSTER"]},{"check_id":"ALR9-08-55-INTERNAL-SEPARATIONS","evidence_ids":["R9_ROSTER"]},{"check_id":"ALR9-09-264-CROSS-SEPARATIONS","evidence_ids":["R9_ROSTER","R7_ROSTER","R8_REJECTED_ROSTER","R8_ARCHITECTURE_REVIEW"]},{"check_id":"ALR9-10-PATH-REGISTRY-EXACT","evidence_ids":["R9_CONTRACT"]},{"check_id":"ALR9-11-HISTORICAL-EVIDENCE-CATALOG-EXACT","evidence_ids":["R9_CONTRACT","R7_CONTRACT","R7_PREIMPLEMENTATION_REVIEW","R7_GREEN_RECEIPT","R7_SEMANTIC_ACCEPTANCE_REVIEW","R7_ROSTER","R7_GREEN_SCHEMA","R7_PRIMARY_VALIDATOR","R7_GREEN_HARNESS","R8_CONTRACT","R8_AUTHOR_RECEIPT","R8_ARCHITECTURE_REVIEW","R8_REJECTED_ROSTER"]},{"check_id":"ALR9-12-ORDERED-EVIDENCE-BINDINGS-EXACT","evidence_ids":["R9_CONTRACT"]},{"check_id":"ALR9-13-SCOPE-SETS-EXACT","evidence_ids":["R9_CONTRACT"]},{"check_id":"ALR9-14-BINARY-CHECK-TOTALITY-EXACT","evidence_ids":["R9_CONTRACT"]},{"check_id":"ALR9-15-RECURSIVE-SCHEMA-CLOSURE","evidence_ids":["R9_CONTRACT"]},{"check_id":"ALR9-16-OBSERVER-PROTOCOL-IDENTITY-EXACT","evidence_ids":["R9_CONTRACT","R9_ROSTER","R9_OBSERVER_PRE"]},{"check_id":"ALR9-17-OBSERVER-PRE-SIGNATURE-EXACT","evidence_ids":["R9_ROSTER","R9_OBSERVER_PRE"]},{"check_id":"ALR9-18-PRE-SNAPSHOT-COMPLETE-STABLE","evidence_ids":["R9_OBSERVER_PRE"]},{"check_id":"ALR9-19-REVIEW-TARGET-ABSENT-BEFORE-WRITE","evidence_ids":["R9_OBSERVER_PRE"]},{"check_id":"ALR9-20-ALL-15-DOWNSTREAM-PATHS-ABSENT","evidence_ids":["R9_OBSERVER_PRE"]},{"check_id":"ALR9-21-FROZEN-DENOMINATOR-EXACT","evidence_ids":["R9_CONTRACT"]},{"check_id":"ALR9-22-REVIEW-BEFORE-RENDER-CODE-EXECUTION","evidence_ids":["R9_CONTRACT","R9_OBSERVER_PRE"]},{"check_id":"ALR9-23-PART0-AUTHORITY-EXACT","evidence_ids":["R9_CONTRACT","R9_ROSTER","R9_OBSERVER_PRE"]},{"check_id":"ALR9-24-STOP-BEFORE-IMPLEMENTATION","evidence_ids":["R9_CONTRACT","R9_OBSERVER_PRE"]}]}
```

`R9_*` evidence IDs are exact symbolic joins resolved from the subject, author
receipt, roster, and observer receipt objects; all `R7_*` IDs resolve only from
the literal historical catalog. Evidence arrays must equal the registry's array
at the same check ordinal. Evidence has no set semantics.

Every check object has exactly `check_id`, `result`, and `evidence`; `result` is
only `PASS` or `FAIL`. No third state, unknown member, unknown enum, registry
extension, alias, or reordering is accepted. The top-level review has exactly:

```text
schema_version, record_id, subject, author_receipt, principal_roster,
observer_pre_receipt, actor, path_registry, path_registry_sha256,
path_membership_sha256, downstream_at_review_sha256,
historical_evidence_catalog_sha256, check_registry_sha256,
denominator_sha256, candidate_set_sha256, accepted_scope, rejected_scope,
checks, findings, open_findings, failure_bindings, disposition,
part_0_genericity, authority_ceiling, record_body_sha256
```

`accepted_scope` is exactly
`["AUTHOR_R9_OBSERVER_COMMIT_RECEIPT","AUTHOR_R9_PREIMPLEMENTATION_ADMISSION"]`.
`rejected_scope` is exactly
`["RENDER_SCHEMAS","AUTHOR_VALIDATORS","AUTHOR_HARNESS","EXECUTE_GREEN","AUTHOR_EXECUTION_RECEIPT","AUTHOR_GREEN_RECEIPT","AUTHOR_GREEN_VALIDATION_RECEIPT","AUTHOR_SEMANTIC_ACCEPTANCE_REVIEW","AGGREGATE_ADMISSION","G3_01","PRODUCTION","RUNTIME","NATIVE","PROVIDER","PUBLICATION","ADMISSION","PACKAGE","INSTALL","RELEASE","CUTOVER","COMMIT","PUSH"]`.
Both are ordered immutable arrays; neither is a negotiable set.

For a review, let `F` be FAIL check IDs in registry order and `O` be the
lexicographically ordered IDs of `BLOCKING/OPEN` findings. PASS requires all 24
results PASS and empty findings/open/failure arrays. REJECTED requires `F`
nonempty, every finding exactly `BLOCKING/OPEN`, `open_findings == O`, each
finding's `failed_checks` a nonempty registry-ordered subset of `F`, and
`failure_bindings` exactly the inverse mapping for every member of `F`. Closed,
nonblocking, missing, extra, duplicated, or unrelated projections reject.

The exact preimplementation admission checks are:

```text
ALR9D-01-REVIEW-BYTES-AND-PASS-EXACT
ALR9D-02-OBSERVER-PRE-AND-COMMIT-SIGNATURES-EXACT
ALR9D-03-SESSION-NONCE-LEASE-ROOT-IDENTITY-EQUAL
ALR9D-04-PRE-REVIEW-POST-SNAPSHOT-COMPLETE
ALR9D-05-REVIEW-IDENTITY-IN-COMMIT-EXACT
ALR9D-06-ALL-POST-REVIEW-PATHS-ABSENT-AT-COMMIT
ALR9D-07-LEASE-HANDOFF-TO-ADMISSION-REVIEWER-EXACT
ALR9D-08-NO-RENDER-CODE-OR-EXECUTION-PRESENT
ALR9D-09-ROSTER-AND-PRINCIPAL-SEPARATION-EXACT
ALR9D-10-CANDIDATE-DENOMINATOR-ORACLE-EXACT
ALR9D-11-PART0-AUTHORITY-EXACT
ALR9D-12-STOPPED-POST-ADMISSION-SCOPE-ONLY
```

Admission PASS requires 12/12 PASS, the same exact empty projections, exact
review disposition `PASS_R9_PREIMPLEMENTATION_OBSERVED_STOPPED_ONLY`, and exact
scope
`["RENDER_6_R9_SCHEMAS","AUTHOR_R9_PRIMARY_VALIDATOR","AUTHOR_R9_INDEPENDENT_RECEIPT_VALIDATOR","AUTHOR_R9_GREEN_HARNESS","EXECUTE_BOUND_R9_GREEN","AUTHOR_R9_EXECUTION_RECEIPT","AUTHOR_R9_GREEN_RECEIPT","EXECUTE_INDEPENDENT_GREEN_RECEIPT_VALIDATION","AUTHOR_R9_GREEN_VALIDATION_RECEIPT","AUTHOR_INDEPENDENT_R9_SEMANTIC_ACCEPTANCE_REVIEW"]`.
Its `rejected_scope` is exactly
`["AGGREGATE_ADMISSION","G3_01","PRODUCTION","RUNTIME","NATIVE","PROVIDER","PUBLICATION","ADMISSION","PACKAGE","INSTALL","RELEASE","CUTOVER","COMMIT","PUSH"]`.
It still authorizes no aggregate/G3-01/production/runtime action.

## 7. Fixture-first frozen denominator and independent oracle

The exact denominator is:

```json
{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_RED_GREEN_DENOMINATOR_V1","controls":[{"case_id":"ALC-R9-C01-VALID-PASS-REVIEW","expected":"ACCEPT"},{"case_id":"ALC-R9-C02-TRUTHFUL-REJECTED-REVIEW","expected":"ACCEPT"},{"case_id":"ALC-R9-C03-VALID-OBSERVER-PRE-COMMIT-PAIR","expected":"ACCEPT"},{"case_id":"ALC-R9-C04-VALID-GREEN-AND-INDEPENDENT-VALIDATION","expected":"ACCEPT"}],"mutations":[{"case_id":"ALC-R9-M01-HIDDEN-OPEN-BLOCKER","expected_code":"PASS_OPEN_FINDING_FORBIDDEN"},{"case_id":"ALC-R9-M02-OPEN-ROSTER-MISMATCH","expected_code":"FINDING_PROJECTION_MISMATCH"},{"case_id":"ALC-R9-M03-PRINCIPAL-ALIAS","expected_code":"PRINCIPAL_ALIAS"},{"case_id":"ALC-R9-M04-PRINCIPAL-RELABEL","expected_code":"PRINCIPAL_BINDING_MISMATCH"},{"case_id":"ALC-R9-M05-UNAUTHORIZED-SUCCESSOR","expected_code":"UNAUTHORIZED_SUCCESSOR"},{"case_id":"ALC-R9-M06-FALSE-SEMANTIC-ACCEPTANCE","expected_code":"FALSE_SEMANTIC_ACCEPTANCE"},{"case_id":"ALC-R9-M07-MISSING-ROSTER","expected_code":"MISSING_REQUIRED_ROSTER"},{"case_id":"ALC-R9-M08-PRE-REVIEW-OUTPUT-PRESENT","expected_code":"PRE_REVIEW_OUTPUT_PRESENT"},{"case_id":"ALC-R9-M09-REGISTRY-REORDER","expected_code":"PATH_REGISTRY_ORDER_MISMATCH"},{"case_id":"ALC-R9-M10-REGISTRY-ALIAS","expected_code":"PATH_REGISTRY_ALIAS"},{"case_id":"ALC-R9-M11-REGISTRY-DUPLICATE","expected_code":"PATH_REGISTRY_DUPLICATE"},{"case_id":"ALC-R9-M12-REGISTRY-HASH-MISMATCH","expected_code":"PATH_REGISTRY_HASH_MISMATCH"},{"case_id":"ALC-R9-M13-ACCEPTED-SCOPE-WIDENED","expected_code":"ACCEPTED_SCOPE_MISMATCH"},{"case_id":"ALC-R9-M14-REJECTED-SCOPE-NARROWED","expected_code":"REJECTED_SCOPE_MISMATCH"},{"case_id":"ALC-R9-M15-INDETERMINATE-CHECK-RESULT","expected_code":"CHECK_RESULT_NOT_BINARY"},{"case_id":"ALC-R9-M16-UNKNOWN-TOP-LEVEL-FIELD","expected_code":"SCHEMA_CLOSURE_VIOLATION"},{"case_id":"ALC-R9-M17-UNKNOWN-NESTED-FIELD","expected_code":"SCHEMA_CLOSURE_VIOLATION"},{"case_id":"ALC-R9-M18-REGISTRY-EXTENSION","expected_code":"PATH_REGISTRY_EXTENSION"},{"case_id":"ALC-R9-M19-HISTORICAL-EVIDENCE-SWAP","expected_code":"EVIDENCE_ASSOCIATION_MISMATCH"},{"case_id":"ALC-R9-M20-EVIDENCE-REORDER","expected_code":"EVIDENCE_ORDER_MISMATCH"},{"case_id":"ALC-R9-M21-EVIDENCE-RELABEL","expected_code":"EVIDENCE_ASSOCIATION_MISMATCH"},{"case_id":"ALC-R9-M22-PATH-STATES-OMITTED","expected_code":"OBSERVER_PATH_STATES_INCOMPLETE"},{"case_id":"ALC-R9-M23-PATH-STATES-NULL-OR-SYNTHETIC","expected_code":"OBSERVER_ORIGIN_INVALID"},{"case_id":"ALC-R9-M24-OBSERVER-PRINCIPAL-SPOOF","expected_code":"OBSERVER_PRINCIPAL_MISMATCH"},{"case_id":"ALC-R9-M25-OBSERVER-SIGNATURE-SPOOF","expected_code":"OBSERVER_SIGNATURE_INVALID"},{"case_id":"ALC-R9-M26-OBSERVER-REPLAY","expected_code":"OBSERVER_SESSION_REPLAY"},{"case_id":"ALC-R9-M27-OBSERVER-PRE-ROW-OMISSION","expected_code":"OBSERVER_PRE_INCOMPLETE"},{"case_id":"ALC-R9-M28-OBSERVER-POST-ROW-OMISSION","expected_code":"OBSERVER_POST_INCOMPLETE"},{"case_id":"ALC-R9-M29-CANDIDATE-SET-SUBSTITUTION","expected_code":"CANDIDATE_SET_MISMATCH"},{"case_id":"ALC-R9-M30-RECEIPT-BODY-HASH-SUBSTITUTION","expected_code":"RECORD_BODY_HASH_MISMATCH"},{"case_id":"ALC-R9-M31-RECEIPT-ID-SUBSTITUTION","expected_code":"RECORD_ID_MISMATCH"},{"case_id":"ALC-R9-M32-SELF-ORACLE-IMPORT","expected_code":"ORACLE_PROVENANCE_INVALID"},{"case_id":"ALC-R9-M33-ORACLE-EXPECTED-OUTCOME-SUBSTITUTION","expected_code":"ORACLE_OUTCOME_MISMATCH"},{"case_id":"ALC-R9-M34-ORACLE-CODE-SUBSTITUTION","expected_code":"ORACLE_CODE_MISMATCH"},{"case_id":"ALC-R9-M35-EXECUTION-RECEIPT-SUBSTITUTION","expected_code":"EXECUTION_RECEIPT_MISMATCH"},{"case_id":"ALC-R9-M36-PRIMARY-VALIDATOR-IDENTITY-SUBSTITUTION","expected_code":"PRIMARY_VALIDATOR_IDENTITY_MISMATCH"},{"case_id":"ALC-R9-M37-HARNESS-IDENTITY-SUBSTITUTION","expected_code":"HARNESS_IDENTITY_MISMATCH"},{"case_id":"ALC-R9-M38-OBSERVER-IDENTITY-SUBSTITUTION","expected_code":"OBSERVER_IDENTITY_MISMATCH"},{"case_id":"ALC-R9-M39-UNKNOWN-ENUM","expected_code":"ENUM_CLOSURE_VIOLATION"},{"case_id":"ALC-R9-M40-DENOMINATOR-EXTENSION","expected_code":"DENOMINATOR_MISMATCH"},{"case_id":"ALC-R9-M41-AUTHORITY-FLIP","expected_code":"AUTHORITY_CEILING_VIOLATION"},{"case_id":"ALC-R9-M42-PART0-PROTOCOL-NAME","expected_code":"PART0_VIOLATION"},{"case_id":"ALC-R9-M43-RECEIPT-VALIDATOR-NOT-INDEPENDENT","expected_code":"RECEIPT_VALIDATOR_INDEPENDENCE_VIOLATION"},{"case_id":"ALC-R9-M44-COMMIT-RECEIPT-MISSING","expected_code":"OBSERVER_COMMIT_MISSING"},{"case_id":"ALC-R9-M45-COMMIT-STATE-MISMATCH","expected_code":"OBSERVER_COMMIT_STATE_MISMATCH"},{"case_id":"ALC-R9-M46-GREEN-RESULT-TUPLE-REORDER","expected_code":"GREEN_RESULT_TUPLE_ORDER_MISMATCH"}],"green_oracle":{"control_accept_count":4,"mutation_reject_count":46,"unexpected_accept_count":0,"wrong_rejection_code_count":0,"control_failure_count":0,"process_exit":0,"semantic_acceptance_claimed_by_green_receipt":false},"oracle_provenance":"PARSE_THIS_CONTRACT_DENOMINATOR_AND_INDEPENDENTLY_RECONSTRUCT","forbidden_oracle_sources":["PRIMARY_VALIDATOR_CONSTANTS","RECEIPT_VALIDATOR_CONSTANTS","HARNESS_EXPECTED_VALUES","GREEN_RECEIPT_EXPECTED_VALUES"]}
```

M13-M19 are the five concrete F001 unexpected accepts plus scope narrowing;
M22-M28 close F002; M29-M34 and M43 close F003. M01-M12 preserve the prior
denominator, and M35-M46 close identity, receipt, enum, Part-0, and result-tuple
substitutions. These cases must be written and produce RED before any r9
validator implementation. The harness parses the denominator from the frozen
contract bytes or an independently rendered immutable fixture and independently
reconstructs expected outcomes/codes. Importing any expected value from either
validator under test is itself M32 and must fail.

The candidate-set preimage is exact LF-separated UTF-8 with no terminal LF:

```text
PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_CANDIDATE_SET_V1
path_registry_sha256
path_membership_sha256
downstream_at_review_sha256
post_admission_paths_sha256
historical_evidence_catalog_sha256
observer_protocol_sha256
preimplementation_check_registry_sha256
denominator_sha256
inline_schema_sha256[0]
inline_schema_sha256[1]
inline_schema_sha256[2]
inline_schema_sha256[3]
inline_schema_sha256[4]
inline_schema_sha256[5]
```

The six schema hashes are in registry ordinal `5..10` order. All components are
recomputed from literal contract values. A receipt field alone is never proof.

The author's exact canonical recomputation vector is:

```text
path_registry_sha256 = 8bed7f126c56f63aa057411add9ccf1fdab51e98bad3d8570bfa20eab7508202
path_membership_sha256 = 97a3fe309e67336d60ec2f3224b51b78e919a7893129592896cc451809c24057
downstream_at_review_sha256 = d8f12343b1e770f44c0e8812122528b5466d8700540f992d7d61e473bf5651e7
post_admission_paths_sha256 = d0130b9c15c57d5fba6bf6c016b9440724767d4d5a7e92340d7753a04f674991
historical_evidence_catalog_sha256 = b7617cff7def23277f011b29c7c66589803f0104f541a475cafdc26693fe153f
observer_protocol_sha256 = 5d093590c9afc32e57b1d916927d77cdd676bfad47f43de311f9ac4f9f003067
preimplementation_check_registry_sha256 = 594d6c017fbc713524f6fab42ab6758fba42b8c765aa4d70d86abe489052de50
denominator_sha256 = 5f37e9f4bdf99a4645058e1ebe49f60b659945c6fa186126b29b2d42cddeedda
inline_schema_sha256[0] = d6d1fa4de0378582b0474422288dcb108bdd71dc5d60fe54ac20a39319b36d1a
inline_schema_sha256[1] = 53c5eb63d40cfec36796a9066245acda6d2facf7bd1a0716679b70fb0e854c50
inline_schema_sha256[2] = ed96c75b1445f38dcba4d00953b7d719e385dfbef1392699ffcf69626b2548ee
inline_schema_sha256[3] = f18abc8309d418b68b4e2436086b17aa0a5e81c832683efdd96e5e16f8c20f41
inline_schema_sha256[4] = 6ee3f8e4cc77167e5301d12d0048fae665b0b8833213ae5fbd5e783edfeeb96f
inline_schema_sha256[5] = 5c598edded3bda3bedf50e32aca3ff16a0b708eb36a4295471d1e6076e60729f
candidate_set_sha256 = 0b564a21c57c8a4612913d5c10892e7dd8bf13625a8e2b8c4c4490c4759ad590
```

These values are diagnostic consequences of the literals, not replacement
authorities. Every reviewer and validator must recompute them.

## 8. Exact schema contracts

The six inline schemas below are the sole render candidates. They use Draft
2020-12, only fragment-local references, and recursively close every governed
object. Where a cross-field equality is not expressible in JSON Schema, the
mandatory semantic predicates in sections 3-7 and 9 apply; schema validity is
necessary and never sufficient.

### 8.1 Principal roster schema

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r9_principal_roster.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","roster_id","subject","author_receipt","roles","principal_ids","public_keys","prior_evidence_producer_ids","bindings","binding_signature","separation_projection","part_0_genericity","authority_ceiling","roster_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r9_principal_roster.v1"},"roster_id":{"type":"string","pattern":"^pfg3alr9pr-[0-9a-f]{32}$"},"subject":{"$ref":"#/$defs/file"},"author_receipt":{"$ref":"#/$defs/file"},"roles":{"type":"array","minItems":11,"maxItems":11,"uniqueItems":true,"items":{"$ref":"#/$defs/nonempty"}},"principal_ids":{"type":"array","minItems":11,"maxItems":11,"uniqueItems":true,"items":{"$ref":"#/$defs/principal"}},"public_keys":{"type":"array","minItems":11,"maxItems":11,"uniqueItems":true,"items":{"$ref":"#/$defs/key"}},"prior_evidence_producer_ids":{"type":"array","minItems":24,"maxItems":24,"uniqueItems":true,"items":{"$ref":"#/$defs/principal"}},"bindings":{"type":"array","minItems":11,"maxItems":11,"items":{"$ref":"#/$defs/binding"}},"binding_signature":{"$ref":"#/$defs/signature"},"separation_projection":{"type":"object","additionalProperties":false,"required":["internal_pair_count","cross_prior_pair_count","declared_continuity_pairs","unexpected_internal_equal_pairs","unexpected_cross_equal_pairs","principal_projection_sha256","projection_body_sha256"],"properties":{"internal_pair_count":{"const":55},"cross_prior_pair_count":{"const":264},"declared_continuity_pairs":{"type":"array","maxItems":0},"unexpected_internal_equal_pairs":{"type":"array","maxItems":0},"unexpected_cross_equal_pairs":{"type":"array","maxItems":0},"principal_projection_sha256":{"$ref":"#/$defs/hex"},"projection_body_sha256":{"$ref":"#/$defs/hex"}}},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"roster_body_sha256":{"$ref":"#/$defs/hex"}},"$defs":{"hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"nonempty":{"type":"string","minLength":1,"maxLength":256},"principal":{"type":"string","pattern":"^[A-Za-z][A-Za-z0-9._-]*:/[A-Za-z0-9._/-]+$","minLength":12,"maxLength":256},"key":{"type":"string","pattern":"^[A-Za-z0-9+/]{43}=$"},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"type":"string","minLength":1,"maxLength":4096},"size_bytes":{"type":"integer","minimum":1},"sha256":{"$ref":"#/$defs/hex"}}},"binding":{"type":"object","additionalProperties":false,"required":["role","principal_ordinal","principal_id","public_key_base64","source_kind","assignment_body_sha256"],"properties":{"role":{"$ref":"#/$defs/nonempty"},"principal_ordinal":{"type":"integer","minimum":0,"maximum":10},"principal_id":{"$ref":"#/$defs/principal"},"public_key_base64":{"$ref":"#/$defs/key"},"source_kind":{"enum":["IMMUTABLE_AUTHOR_EXTRACTION","SIGNED_ROSTER_ASSIGNMENT"]},"assignment_body_sha256":{"$ref":"#/$defs/hex"}}},"signature":{"type":"object","additionalProperties":false,"required":["algorithm","signer_principal_ordinal","signed_preimage_sha256","signature_base64"],"properties":{"algorithm":{"const":"ED25519"},"signer_principal_ordinal":{"const":1},"signed_preimage_sha256":{"$ref":"#/$defs/hex"},"signature_base64":{"type":"string","pattern":"^[A-Za-z0-9+/]{86}==$"}}},"part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}}}
```

Semantic validation fixes the exact role/prior arrays, ordinal-to-value joins,
author extraction, assignment hashes, signature, and separation projection,
including the six-field noncircular projection formula and mandatory validation
order in section 3. Schema validity alone never establishes that digest.

### 8.2 Stage-observation PRE/COMMIT receipt schema

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r9_stage_observation.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","record_id","phase","subject","principal_roster","actor","observer_protocol_sha256","path_registry_sha256","session","bound_inputs","snapshot_before","snapshot_after","outcome","part_0_genericity","authority_ceiling","record_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r9_stage_observation.v1"},"record_id":{"type":"string","pattern":"^pfg3alr9o(?:pre|commit)-[0-9a-f]{32}$"},"phase":{"enum":["PRE_REVIEW_PREPARED","POST_REVIEW_COMMITTED"]},"subject":{"$ref":"#/$defs/file"},"principal_roster":{"$ref":"#/$defs/file"},"actor":{"$ref":"#/$defs/actor"},"observer_protocol_sha256":{"$ref":"#/$defs/hex"},"path_registry_sha256":{"$ref":"#/$defs/hex"},"session":{"type":"object","additionalProperties":false,"required":["session_id","nonce_sha256","root_identity","observer_process_start_identity","exclusive_lease_state","handoff_principal_ordinal"],"properties":{"session_id":{"type":"string","pattern":"^pfg3alr9obs-[0-9a-f]{32}$"},"nonce_sha256":{"$ref":"#/$defs/hex"},"root_identity":{"$ref":"#/$defs/native"},"observer_process_start_identity":{"$ref":"#/$defs/nonempty"},"exclusive_lease_state":{"enum":["HELD_FOR_PRE_REVIEW","HELD_FOR_ADMISSION_HANDOFF"]},"handoff_principal_ordinal":{"enum":[3,4]}}},"bound_inputs":{"type":"array","minItems":2,"maxItems":4,"uniqueItems":true,"items":{"$ref":"#/$defs/file"}},"snapshot_before":{"$ref":"#/$defs/snapshot"},"snapshot_after":{"$ref":"#/$defs/snapshot"},"outcome":{"enum":["COMPLETE_STABLE","INDETERMINATE_NO_AUTHORITY"]},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"record_body_sha256":{"$ref":"#/$defs/hex"}},"$defs":{"hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"nonempty":{"type":"string","minLength":1,"maxLength":4096},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/nonempty"},"size_bytes":{"type":"integer","minimum":1},"sha256":{"$ref":"#/$defs/hex"}}},"native":{"type":"object","additionalProperties":false,"required":["os_family","root_or_parent_id","file_id_kind","file_id_value"],"properties":{"os_family":{"enum":["WINDOWS","POSIX"]},"root_or_parent_id":{"$ref":"#/$defs/nonempty"},"file_id_kind":{"enum":["VOLUME_SERIAL_FILE_ID","ST_DEV_ST_INO"]},"file_id_value":{"$ref":"#/$defs/nonempty"}}},"row":{"type":"object","additionalProperties":false,"required":["ordinal","path","state","native_identity","size_bytes","sha256","leaf_name","no_follow","stable"],"properties":{"ordinal":{"type":"integer","minimum":0,"maximum":17},"path":{"$ref":"#/$defs/nonempty"},"state":{"enum":["PRESENT","ABSENT"]},"native_identity":{"$ref":"#/$defs/native"},"size_bytes":{"type":["integer","null"],"minimum":0},"sha256":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"},"leaf_name":{"$ref":"#/$defs/nonempty"},"no_follow":{"const":true},"stable":{"const":true}}},"snapshot":{"type":"object","additionalProperties":false,"required":["probe_ordinal","rows","rows_sha256","complete_count"],"properties":{"probe_ordinal":{"enum":[0,1,2,3]},"rows":{"type":"array","minItems":18,"maxItems":18,"items":{"$ref":"#/$defs/row"}},"rows_sha256":{"$ref":"#/$defs/hex"},"complete_count":{"const":18}}},"actor":{"type":"object","additionalProperties":false,"required":["principal_ordinal","principal_id","public_key_base64","signed_preimage_sha256","signature_base64"],"properties":{"principal_ordinal":{"const":2},"principal_id":{"$ref":"#/$defs/nonempty"},"public_key_base64":{"$ref":"#/$defs/nonempty"},"signed_preimage_sha256":{"$ref":"#/$defs/hex"},"signature_base64":{"$ref":"#/$defs/nonempty"}}},"part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}}}
```

Semantic validation requires exactly 18 ordered rows, exact registry tuples,
state-specific null/non-null fields, equal PRE/POST identities, exact phase
state sets, exact inputs, session continuity, valid ordinal-2 signatures, and
`COMPLETE_STABLE`. `INDETERMINATE_NO_AUTHORITY` is schema-representable for
diagnosis but can never satisfy a PASS/admission predicate.

### 8.3 Preimplementation review schema

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r9_preimplementation_review.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","record_id","subject","author_receipt","principal_roster","observer_pre_receipt","actor","path_registry","path_registry_sha256","path_membership_sha256","downstream_at_review_sha256","historical_evidence_catalog_sha256","check_registry_sha256","denominator_sha256","candidate_set_sha256","accepted_scope","rejected_scope","checks","findings","open_findings","failure_bindings","disposition","part_0_genericity","authority_ceiling","record_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r9_preimplementation_review.v1"},"record_id":{"type":"string","pattern":"^pfg3alr9pre-[0-9a-f]{32}$"},"subject":{"$ref":"#/$defs/file"},"author_receipt":{"$ref":"#/$defs/file"},"principal_roster":{"$ref":"#/$defs/file"},"observer_pre_receipt":{"$ref":"#/$defs/file"},"actor":{"$ref":"#/$defs/actor"},"path_registry":{"type":"object","additionalProperties":false,"required":["domain","entries"],"properties":{"domain":{"const":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_PATH_REGISTRY_V1"},"entries":{"type":"array","minItems":18,"maxItems":18,"items":{"$ref":"#/$defs/registry_row"}}}},"path_registry_sha256":{"$ref":"#/$defs/hex"},"path_membership_sha256":{"$ref":"#/$defs/hex"},"downstream_at_review_sha256":{"$ref":"#/$defs/hex"},"historical_evidence_catalog_sha256":{"$ref":"#/$defs/hex"},"check_registry_sha256":{"$ref":"#/$defs/hex"},"denominator_sha256":{"$ref":"#/$defs/hex"},"candidate_set_sha256":{"$ref":"#/$defs/hex"},"accepted_scope":{"type":"array","minItems":2,"maxItems":2,"items":{"$ref":"#/$defs/nonempty"}},"rejected_scope":{"type":"array","minItems":22,"maxItems":22,"items":{"$ref":"#/$defs/nonempty"}},"checks":{"type":"array","minItems":24,"maxItems":24,"items":{"$ref":"#/$defs/check"}},"findings":{"type":"object","propertyNames":{"$ref":"#/$defs/id"},"additionalProperties":{"$ref":"#/$defs/finding"}},"open_findings":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"failure_bindings":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/failure"}},"disposition":{"enum":["PASS_R9_PREIMPLEMENTATION_OBSERVED_STOPPED_ONLY","REJECTED"]},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"record_body_sha256":{"$ref":"#/$defs/hex"}},"$defs":{"hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"nonempty":{"type":"string","minLength":1,"maxLength":4096},"id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/nonempty"},"size_bytes":{"type":"integer","minimum":1},"sha256":{"$ref":"#/$defs/hex"}}},"actor":{"type":"object","additionalProperties":false,"required":["principal_ordinal","principal_id","public_key_base64","signed_preimage_sha256","signature_base64"],"properties":{"principal_ordinal":{"const":3},"principal_id":{"$ref":"#/$defs/nonempty"},"public_key_base64":{"$ref":"#/$defs/nonempty"},"signed_preimage_sha256":{"$ref":"#/$defs/hex"},"signature_base64":{"$ref":"#/$defs/nonempty"}}},"registry_row":{"type":"object","additionalProperties":false,"required":["ordinal","stage","kind","path"],"properties":{"ordinal":{"type":"integer","minimum":0,"maximum":17},"stage":{"enum":["PRE_REVIEW_REQUIRED_INPUT","REVIEW_ATOMIC_OUTPUT","POST_REVIEW_PRE_ADMISSION_INPUT","PREIMPLEMENTATION_ADMISSION_OUTPUT","POST_ADMISSION_OUTPUT"]},"kind":{"$ref":"#/$defs/nonempty"},"path":{"$ref":"#/$defs/nonempty"}}},"check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"$ref":"#/$defs/id"},"result":{"enum":["PASS","FAIL"]},"evidence":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/file"}}}},"finding":{"type":"object","additionalProperties":false,"required":["severity","status","failed_checks","description","evidence"],"properties":{"severity":{"const":"BLOCKING"},"status":{"const":"OPEN"},"failed_checks":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"description":{"type":"string","minLength":1},"evidence":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/file"}}}},"failure":{"type":"object","additionalProperties":false,"required":["check_id","finding_ids"],"properties":{"check_id":{"$ref":"#/$defs/id"},"finding_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}}}},"part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}}}
```

### 8.4 Independent preimplementation admission schema

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r9_preimplementation_admission.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","record_id","subject","principal_roster","observer_pre_receipt","preimplementation_review","observer_commit_receipt","actor","session_id","checks","findings","open_findings","failure_bindings","disposition","accepted_scope","rejected_scope","part_0_genericity","authority_ceiling","record_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r9_preimplementation_admission.v1"},"record_id":{"type":"string","pattern":"^pfg3alr9admit-[0-9a-f]{32}$"},"subject":{"$ref":"#/$defs/file"},"principal_roster":{"$ref":"#/$defs/file"},"observer_pre_receipt":{"$ref":"#/$defs/file"},"preimplementation_review":{"$ref":"#/$defs/file"},"observer_commit_receipt":{"$ref":"#/$defs/file"},"actor":{"$ref":"#/$defs/actor"},"session_id":{"type":"string","pattern":"^pfg3alr9obs-[0-9a-f]{32}$"},"checks":{"type":"array","minItems":12,"maxItems":12,"items":{"$ref":"#/$defs/check"}},"findings":{"type":"object","propertyNames":{"$ref":"#/$defs/id"},"additionalProperties":{"$ref":"#/$defs/finding"}},"open_findings":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"failure_bindings":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/failure"}},"disposition":{"enum":["PASS_R9_PREIMPLEMENTATION_ADMISSION_FOR_STOPPED_GREEN_ONLY","REJECTED"]},"accepted_scope":{"type":"array","minItems":10,"maxItems":10,"items":{"$ref":"#/$defs/nonempty"}},"rejected_scope":{"type":"array","minItems":14,"maxItems":14,"items":{"$ref":"#/$defs/nonempty"}},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"record_body_sha256":{"$ref":"#/$defs/hex"}},"$defs":{"hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"nonempty":{"type":"string","minLength":1,"maxLength":4096},"id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/nonempty"},"size_bytes":{"type":"integer","minimum":1},"sha256":{"$ref":"#/$defs/hex"}}},"actor":{"type":"object","additionalProperties":false,"required":["principal_ordinal","principal_id","public_key_base64","signed_preimage_sha256","signature_base64"],"properties":{"principal_ordinal":{"const":4},"principal_id":{"$ref":"#/$defs/nonempty"},"public_key_base64":{"$ref":"#/$defs/nonempty"},"signed_preimage_sha256":{"$ref":"#/$defs/hex"},"signature_base64":{"$ref":"#/$defs/nonempty"}}},"check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"$ref":"#/$defs/id"},"result":{"enum":["PASS","FAIL"]},"evidence":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/file"}}},"finding":{"type":"object","additionalProperties":false,"required":["severity","status","failed_checks","description","evidence"],"properties":{"severity":{"const":"BLOCKING"},"status":{"const":"OPEN"},"failed_checks":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"description":{"type":"string","minLength":1},"evidence":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/file"}}},"failure":{"type":"object","additionalProperties":false,"required":["check_id","finding_ids"],"properties":{"check_id":{"$ref":"#/$defs/id"},"finding_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}}},"part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}}}
},"finding":{"$ref":"#/$defs/check/finding"},"failure":{"$ref":"#/$defs/check/finding/failure"},"part0":{"$ref":"#/$defs/check/finding/failure/part0"},"authority":{"$ref":"#/$defs/check/finding/failure/authority"}}}
```

### 8.5 Execution, GREEN, and GREEN-validation evidence schema

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r9_semantic_evidence.v1.schema.json","oneOf":[{"$ref":"#/$defs/execution"},{"$ref":"#/$defs/green"},{"$ref":"#/$defs/validation"}],"$defs":{"hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"nonempty":{"type":"string","minLength":1,"maxLength":4096},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/nonempty"},"size_bytes":{"type":"integer","minimum":1},"sha256":{"$ref":"#/$defs/hex"}}},"actor":{"type":"object","additionalProperties":false,"required":["principal_ordinal","principal_id","public_key_base64","signed_preimage_sha256","signature_base64"],"properties":{"principal_ordinal":{"enum":[7,9]},"principal_id":{"$ref":"#/$defs/nonempty"},"public_key_base64":{"$ref":"#/$defs/nonempty"},"signed_preimage_sha256":{"$ref":"#/$defs/hex"},"signature_base64":{"$ref":"#/$defs/nonempty"}}},"identity":{"type":"object","additionalProperties":false,"required":["observer_principal_ordinal","observer_protocol_sha256","primary_validator","primary_validator_principal_ordinal","receipt_validator","receipt_validator_principal_ordinal","harness","harness_principal_ordinal","execution_receipt"],"properties":{"observer_principal_ordinal":{"const":2},"observer_protocol_sha256":{"$ref":"#/$defs/hex"},"primary_validator":{"$ref":"#/$defs/file"},"primary_validator_principal_ordinal":{"const":6},"receipt_validator":{"$ref":"#/$defs/file"},"receipt_validator_principal_ordinal":{"const":7},"harness":{"$ref":"#/$defs/file"},"harness_principal_ordinal":{"const":8},"execution_receipt":{"oneOf":[{"$ref":"#/$defs/file"},{"type":"null"}]}}},"tuple":{"type":"object","additionalProperties":false,"required":["case_id","expected","observed","rejection_code","evidence_sha256"],"properties":{"case_id":{"$ref":"#/$defs/nonempty"},"expected":{"enum":["ACCEPT","REJECT"]},"observed":{"enum":["ACCEPT","REJECT"]},"rejection_code":{"type":["string","null"]},"evidence_sha256":{"$ref":"#/$defs/hex"}}},"base":{"type":"object","additionalProperties":false,"required":["schema_version","record_id","record_kind","subject","principal_roster","preimplementation_admission","actor","candidate_set_sha256","denominator_sha256","identity_bindings","result_tuples","summary","semantic_acceptance_confirmed","part_0_genericity","authority_ceiling","record_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r9_semantic_evidence.v1"},"record_id":{"type":"string"},"record_kind":{"enum":["EXECUTION_RECEIPT","GREEN_RECEIPT","GREEN_VALIDATION_RECEIPT"]},"subject":{"$ref":"#/$defs/file"},"principal_roster":{"$ref":"#/$defs/file"},"preimplementation_admission":{"$ref":"#/$defs/file"},"actor":{"$ref":"#/$defs/actor"},"candidate_set_sha256":{"$ref":"#/$defs/hex"},"denominator_sha256":{"$ref":"#/$defs/hex"},"identity_bindings":{"$ref":"#/$defs/identity"},"result_tuples":{"type":"array","minItems":50,"maxItems":50,"items":{"$ref":"#/$defs/tuple"}},"summary":{"type":"object","additionalProperties":false,"required":["control_accept_count","mutation_reject_count","unexpected_accept_count","wrong_rejection_code_count","control_failure_count","process_exit"],"properties":{"control_accept_count":{"const":4},"mutation_reject_count":{"const":46},"unexpected_accept_count":{"const":0},"wrong_rejection_code_count":{"const":0},"control_failure_count":{"const":0},"process_exit":{"const":0}}},"semantic_acceptance_confirmed":{"const":false},"part_0_genericity":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority_ceiling":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}},"record_body_sha256":{"$ref":"#/$defs/hex"}}},"execution":{"allOf":[{"$ref":"#/$defs/base"},{"properties":{"record_kind":{"const":"EXECUTION_RECEIPT"},"record_id":{"pattern":"^pfg3alr9exec-[0-9a-f]{32}$"},"actor":{"properties":{"principal_ordinal":{"const":9}}}}}]},"green":{"allOf":[{"$ref":"#/$defs/base"},{"properties":{"record_kind":{"const":"GREEN_RECEIPT"},"record_id":{"pattern":"^pfg3alr9green-[0-9a-f]{32}$"},"actor":{"properties":{"principal_ordinal":{"const":9}}}}}]},"validation":{"allOf":[{"$ref":"#/$defs/base"},{"properties":{"record_kind":{"const":"GREEN_VALIDATION_RECEIPT"},"record_id":{"pattern":"^pfg3alr9gval-[0-9a-f]{32}$"},"actor":{"properties":{"principal_ordinal":{"const":7}}}}}]}}
}
```

The `allOf` refinements never reopen an object; the base owns the exact field
set. Semantic validation requires the 50 tuples in exact denominator order,
exact expected values/codes independently parsed from the contract, exact
observed results from the signed execution receipt, exact evidence digests, and
the exact identity/file references. `execution_receipt` is null only in the
execution receipt itself; GREEN and validation require its exact file object.
GREEN binds the six rendered schemas, both validators, observer PRE/COMMIT,
pre-review, admission, harness, executor, and execution receipt through their
authenticated identities. The independent validation receipt additionally
binds the exact GREEN receipt identity and its validator execution exit 0.

### 8.6 Independent semantic-acceptance review schema

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r9_semantic_acceptance.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","record_id","subject","principal_roster","preimplementation_admission","execution_receipt","green_receipt","green_validation_receipt","actor","checks","findings","open_findings","failure_bindings","disposition","aggregate_admission_authorized","part_0_genericity","authority_ceiling","record_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r9_semantic_acceptance.v1"},"record_id":{"type":"string","pattern":"^pfg3alr9accept-[0-9a-f]{32}$"},"subject":{"$ref":"#/$defs/file"},"principal_roster":{"$ref":"#/$defs/file"},"preimplementation_admission":{"$ref":"#/$defs/file"},"execution_receipt":{"$ref":"#/$defs/file"},"green_receipt":{"$ref":"#/$defs/file"},"green_validation_receipt":{"$ref":"#/$defs/file"},"actor":{"$ref":"#/$defs/actor"},"checks":{"type":"array","minItems":18,"maxItems":18,"items":{"$ref":"#/$defs/check"}},"findings":{"type":"object","propertyNames":{"$ref":"#/$defs/id"},"additionalProperties":{"$ref":"#/$defs/finding"}},"open_findings":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"failure_bindings":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/failure"}},"disposition":{"enum":["PASS_R9_SEMANTIC_CLOSURE_FOR_STOPPED_PART0_ONLY","REJECTED"]},"aggregate_admission_authorized":{"const":false},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"record_body_sha256":{"$ref":"#/$defs/hex"}},"$defs":{"hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"nonempty":{"type":"string","minLength":1,"maxLength":4096},"id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/nonempty"},"size_bytes":{"type":"integer","minimum":1},"sha256":{"$ref":"#/$defs/hex"}}},"actor":{"type":"object","additionalProperties":false,"required":["principal_ordinal","principal_id","public_key_base64","signed_preimage_sha256","signature_base64"],"properties":{"principal_ordinal":{"const":10},"principal_id":{"$ref":"#/$defs/nonempty"},"public_key_base64":{"$ref":"#/$defs/nonempty"},"signed_preimage_sha256":{"$ref":"#/$defs/hex"},"signature_base64":{"$ref":"#/$defs/nonempty"}}},"check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"$ref":"#/$defs/id"},"result":{"enum":["PASS","FAIL"]},"evidence":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/file"}}},"finding":{"type":"object","additionalProperties":false,"required":["severity","status","failed_checks","description","evidence"],"properties":{"severity":{"const":"BLOCKING"},"status":{"const":"OPEN"},"failed_checks":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"description":{"type":"string","minLength":1},"evidence":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/file"}}},"failure":{"type":"object","additionalProperties":false,"required":["check_id","finding_ids"],"properties":{"check_id":{"$ref":"#/$defs/id"},"finding_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}}},"part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}}}
},"finding":{"$ref":"#/$defs/check/finding"},"failure":{"$ref":"#/$defs/check/finding/failure"},"part0":{"$ref":"#/$defs/check/finding/failure/part0"},"authority":{"$ref":"#/$defs/check/finding/failure/authority"}}}
```

The exact acceptance check order is:

```text
ALR9A-01-SUBJECT-ROSTER-ADMISSION-EXACT
ALR9A-02-OBSERVER-PRE-COMMIT-CHAIN-EXACT
ALR9A-03-PREIMPLEMENTATION-ADMISSION-PRECEDES-CODE
ALR9A-04-SIX-RENDERED-SCHEMAS-EXACT
ALR9A-05-PRIMARY-AND-RECEIPT-VALIDATORS-DISTINCT-EXACT
ALR9A-06-HARNESS-AND-EXECUTOR-DISTINCT-EXACT
ALR9A-07-FOUR-CONTROLS-ACCEPT
ALR9A-08-FORTY-SIX-MUTATIONS-REJECT-EXACT-CODES
ALR9A-09-ORACLE-INDEPENDENTLY-RECONSTRUCTED
ALR9A-10-EXECUTION-RECEIPT-IDENTITY-EXACT
ALR9A-11-GREEN-RECEIPT-SEMANTICS-EXACT
ALR9A-12-GREEN-VALIDATION-RECEIPT-EXACT
ALR9A-13-CANDIDATE-DENOMINATOR-REGISTRY-EXACT
ALR9A-14-OBSERVER-VALIDATOR-HARNESS-IDENTITIES-EXACT
ALR9A-15-RESULT-TUPLE-ORDER-AND-EVIDENCE-EXACT
ALR9A-16-NO-SELF-CERTIFICATION
ALR9A-17-PART0-AUTHORITY-EXACT
ALR9A-18-STOP-BEFORE-G3-00-AGGREGATE
```

PASS/REJECTED uses the same binary-totality and exact inverse finding join as
section 6. Even PASS sets `aggregate_admission_authorized:false` and stops.

## 9. Mandatory semantic validators

The primary semantic validator must be pure/offline and accept no optional
`path_states` parameter. It takes only authenticated contract, roster, observer
receipts, review/admission records, and an explicit record kind. It must:

1. reject duplicate JSON members, BOM, non-LF serialization, non-NFC strings,
   nonlocal refs, unknown fields/enums, and schema-invalid objects;
2. parse all literal contract blocks and independently recompute their hashes;
3. authenticate the four governing r7 artifacts, the four r8 boundary artifacts,
   the exact `REPAIR`/sole-defect disposition, the rejected-roster negative, and
   the full 12-entry evidence catalog;
4. enforce exact registry/check/scope/evidence arrays, not membership subsets;
5. verify all signatures, actor/role/key joins, 55/264 separations, the
   noncircular projection digest before all outer roster identities, body hashes,
   IDs, candidate set, and denominator;
6. validate the observer PRE/COMMIT session, native identity, no-follow stable
   probes, exact state matrices, lease handoff, replay rules, and phase order;
7. enforce binary PASS/FAIL totality and exact finding inverse joins; and
8. never render, write, import production, infer runtime authority, or repair a
   supplied record.

The independent GREEN receipt validator is a separate file, principal, source
tree, and execution. It must not import the primary validator or harness. It
parses this contract itself; reconstructs the 50 expected tuples; authenticates
the execution receipt, all six schemas, both validator identities, observer
receipts, harness, and admission; recomputes every record ID/body hash and
summary; and emits a signed GREEN-validation receipt. It rejects any
candidate/denominator/identity/result/evidence/order mismatch. Shared standard
library JSON/SHA/Ed25519 primitives are permitted; shared audit-specific helper
modules, generated constants, or imports are forbidden.

## 10. Exact review-before-code DAG and terminal STOP

The r9 DAG has exactly 26 nodes and 39 edges:

```text
R9N00 R9_CORRECTION_CONTRACT
R9N01 R9_AUTHOR_RECEIPT
R9N02 R9_BOUND_PRINCIPAL_ROSTER
R9N03 OBSERVER_EXCLUSIVE_LEASE_AND_PRE_SNAPSHOT
R9N04 R9_OBSERVER_PRE_RECEIPT
R9N05 R9_PREIMPLEMENTATION_REVIEW
R9N06 R9_OBSERVER_COMMIT_RECEIPT
R9N07 R9_INDEPENDENT_PREIMPLEMENTATION_ADMISSION_PASS
R9N08 R9_ROSTER_SCHEMA_RENDER
R9N09 R9_OBSERVATION_SCHEMA_RENDER
R9N10 R9_PRE_REVIEW_SCHEMA_RENDER
R9N11 R9_ADMISSION_SCHEMA_RENDER
R9N12 R9_SEMANTIC_EVIDENCE_SCHEMA_RENDER
R9N13 R9_ACCEPTANCE_SCHEMA_RENDER
R9N14 R9_PRIMARY_SEMANTIC_VALIDATOR
R9N15 R9_INDEPENDENT_RECEIPT_VALIDATOR
R9N16 R9_GREEN_HARNESS
R9N17 BOUND_R9_GREEN_EXECUTION
R9N18 R9_EXECUTION_RECEIPT
R9N19 R9_GREEN_RECEIPT
R9N20 INDEPENDENT_GREEN_RECEIPT_VALIDATION_EXECUTION
R9N21 R9_GREEN_VALIDATION_RECEIPT
R9N22 R9_INDEPENDENT_SEMANTIC_ACCEPTANCE_REVIEW
R9N23 R9_STOP_BEFORE_G3_00_AGGREGATE
R9N24 R7_REJECTED_AND_R8_REPAIR_PARENT
R9N25 FROZEN_R9_DENOMINATOR

R9N24->R9N00
R9N25->R9N00
R9N00->R9N01
R9N00->R9N02
R9N01->R9N02
R9N02->R9N03
R9N03->R9N04
R9N04->R9N05
R9N05->R9N06
R9N06->R9N07
R9N07->R9N08
R9N07->R9N09
R9N07->R9N10
R9N07->R9N11
R9N07->R9N12
R9N07->R9N13
R9N07->R9N14
R9N07->R9N15
R9N07->R9N16
R9N08->R9N17
R9N09->R9N17
R9N10->R9N17
R9N11->R9N17
R9N12->R9N17
R9N13->R9N17
R9N14->R9N17
R9N15->R9N17
R9N16->R9N17
R9N17->R9N18
R9N18->R9N19
R9N15->R9N20
R9N19->R9N20
R9N20->R9N21
R9N21->R9N22
R9N19->R9N22
R9N18->R9N22
R9N07->R9N22
R9N22->R9N23
R9N24->R9N25
```

The observer evidence-capture transaction is the only pre-review operation; it
is not schema rendering, candidate code authoring, or GREEN execution. All 15
registry paths at ordinals `3..17` are absent when R9N05 is created. All schema,
validator, harness, and execution nodes require R9N07 PASS. R9N23 has no
outgoing edge. A missing/rejected node authorizes nothing downstream.

## 11. Author validation and bounded handoff

Before handoff the author must:

1. authenticate the four requested r7 artifacts and four r8 boundary artifacts
   at the exact hashes in section 1; verify the r7 disposition/eight FAIL/three
   OPEN equality join, exact r8 `REPAIR` sole-defect review, and rejected-r8
   roster negative;
2. parse every JSON fence with duplicate-member rejection;
3. validate all six schema roots against Draft 2020-12 and resolve every
   fragment-local `$ref`, with zero external refs;
4. confirm recursive `additionalProperties:false` closure for every governed
   object and binary review check enums;
5. recompute path-registry, membership, downstream, post-admission, historical
   catalog, observer-protocol, check-registry, denominator, six schema, and
   candidate-set hashes;
6. confirm exactly 18 registry entries, 24 review checks, 12 admission checks,
   four controls, 46 mutations, 18 acceptance checks, 11 principals, 24 prior
   producer identities, 55 internal comparisons, 264 cross-prior comparisons,
   and the exact six-field projection-body input;
7. prove the exact 26-node/39-edge graph is endpoint-closed, duplicate-free,
   acyclic, and terminal at STOP;
8. confirm all 29 authority keys false, exact Part-0, no protocol names, and no
   production/provider/runtime imports or authority; and
9. observe that no r9 registry path exists at author time.

Only roster binding, observer PRE capture, and one independent preimplementation
review are the next prospective actions. Even that review cannot authorize
rendering; observer COMMIT plus the distinct admission reviewer must first PASS.
This contract stops before implementation, aggregate admission, G3-01,
production, runtime, provider, package, install, release, cutover, commit, or
push.
