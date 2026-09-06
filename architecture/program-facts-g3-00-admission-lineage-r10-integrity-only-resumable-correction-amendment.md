# Program Facts G3-00 admission-lineage Part-0 r10 integrity-only resumable correction amendment

Status: `CREATE_ONLY_CONTRACT; R9_FORMULA_ACCEPT_PRESERVED; R9_ROUTE_UNINHABITABLE_FROZEN; R9_ROSTER_REJECTED_NEGATIVE; R10_DOWNSTREAM_ABSENT; ALL_AUTHORITY_FALSE`

This is a new, non-retroactive successor to r9. It changes no r1-r9 byte and
creates no roster, observer receipt, review, schema, validator, harness,
execution, GREEN, acceptance, aggregate, production, provider, runtime, audit,
package, installation, commit, or push artifact. This authoring step may create
only this contract and its author receipt.

R10 preserves r9's independently accepted projection formula and its complete
closure of the r7 F001-F003 semantic failures. It corrects the later independent
operational review's exact finding: the r9 route required signatures under
per-role public keys whose corresponding private keys had been erased, while
the roster proved neither assignee possession nor independent custody. R10 uses
the honest resumable model:

1. one binder Ed25519 envelope authenticates only the transport bytes
   of the roster at binding time;
2. no assignment contains a role public key and no downstream artifact requires
   a role secret, signature, key custody, or proof of possession;
3. separation is enforced and reviewed through exact versioned role, principal,
   task, process-occurrence, path, hash, predecessor, and reviewer joins; and
4. those joins are explicitly **auditable process separation**, not proof of
   natural-person identity, independent key control, or non-collusion.

Session loss cannot strand the lineage on an ephemeral secret. Observation and
review attempts are append-only and versioned by an exact attempt ID. An
incomplete attempt remains immutable evidence; a new lease holder may create a
new successor attempt after independently enumerating and binding the prior
attempt chain. No stale artifact is overwritten or resealed.

The amendment is Part-0 generic. Protocol names are empty, protocol-specific
branching and semantic shortcuts are false, and every authority value is false.

## 1. Authenticated parent boundary and exact correction

The following parent files were re-read in full as bytes before this contract
was authored:

| Evidence ID | Exact path | Bytes | SHA-256 | Status |
|---|---|---:|---|---|
| `R9_CONTRACT` | `architecture/program-facts-g3-00-admission-lineage-r9-projection-formula-correction-amendment.md` | 79104 | `480ee3283fc546c7474aad6b9c057f915132a15d5c5e3140f33a97d525a3027c` | formula architecture frozen |
| `R9_AUTHOR_RECEIPT` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_PROJECTION_FORMULA_CORRECTION_AUTHOR_RECEIPT.md` | 8198 | `b58390d3755189640353a0c6525099b4dd7ba4102fee0e3ad39c92c9d3d398ba` | bounded authorship |
| `R9_ARCHITECTURE_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_ARCHITECTURE_INDEPENDENT_REVIEW_20260810.md` | 12760 | `8bbb25734e9572da85ba27c3156719d7412951e67bf3346555e84dfad51eab4e` | exact `ACCEPT` for formula architecture only |
| `R9_REJECTED_ROSTER` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_BOUND_PRINCIPAL_ROSTER.v1.json` | 8325 | `743c09a5ab1074cb1079b6388752d5721c0e89ddcc73377201288e649c6b9e7f` | mandatory negative, never r10 authority |
| `R9_OPERATIONAL_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_OPERATIONAL_LIVENESS_INDEPENDENT_REVIEW_20260810.md` | 9488 | `f19d4cc742e7a773616e60e2801e604d9576fed8caf24878cb8e793329b5e89b` | exact `REPAIR; ROUTE_UNINHABITABLE` |

The r9 architecture `ACCEPT` remains valid only for its contract-local,
noncircular projection repair. The operational review does not reverse that
conclusion. It admits that one binder generated all r9 keypairs and erased all
private keys, proves the static roster internally consistent, and establishes
that the first required ordinal-2 signature can never be produced. Therefore
r9 is a frozen, immutable dead end. Accepting the r9 roster, its identities,
keys, signatures, digest, path, or record ID as an r10 object is
`R9_REJECTED_ROSTER_SUBSTITUTION` and rejects.

R10 also authenticates the r7/r8 diagnostic boundary used by r9. These exact
identities are immutable historical evidence, not inherited authority:

```json
{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_HISTORICAL_EVIDENCE_CATALOG_V1","entries":[{"evidence_id":"R7_CONTRACT","path":"architecture/program-facts-g3-00-admission-lineage-r7-semantic-successor-correction-amendment.md","size_bytes":65040,"sha256":"f0e1e20976afd27fb20a222ca7f345807d441f914e5b7de4c6c602592d3225de"},{"evidence_id":"R7_PREIMPLEMENTATION_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PREIMPLEMENTATION_REVIEW.v1.json","size_bytes":28538,"sha256":"d6b99da439b4dea157eb73c157e4216a67fde353304443eec3a7b1be6756c5dd"},{"evidence_id":"R7_PRIMARY_VALIDATOR","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r5_ordering_semantics_v1.py","size_bytes":33247,"sha256":"2fe7d7619f0f8e0403ccf0c5ae2e5dc05873a19dbc605ad930f09f3f51567aef"},{"evidence_id":"R7_GREEN_HARNESS","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r7_semantic_successor_green_v1.py","size_bytes":9676,"sha256":"fd3d075ff92f998842d6537017619ffbce6449c294db8318ccb8ed7492329450"},{"evidence_id":"R7_GREEN_RECEIPT","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_GREEN_RECEIPT.v1.json","size_bytes":13588,"sha256":"2d6f1bb9a0959e6df8403f8dac9e521c4a5d962237fa226bd2b614f282808515"},{"evidence_id":"R7_SEMANTIC_ACCEPTANCE_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_ACCEPTANCE_REVIEW.v1.json","size_bytes":23737,"sha256":"747abf8f6f3659645d56bb73ddb8ab15a8b40fb53fb1b80e0f641ce37e8e1e0f"},{"evidence_id":"R8_CONTRACT","path":"architecture/program-facts-g3-00-admission-lineage-r8-semantic-closure-correction-amendment.md","size_bytes":72023,"sha256":"b080ac7235a46ff41faab66f70ba1a93252d29e4b7e6639ba7205780eb18f464"},{"evidence_id":"R8_ARCHITECTURE_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R8_ARCHITECTURE_INDEPENDENT_REVIEW_20260810.md","size_bytes":4758,"sha256":"4a63a21450a9714739fe0e330c8372f546120b78874d03db283ad965bb3f671f"},{"evidence_id":"R8_REJECTED_ROSTER","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R8_BOUND_PRINCIPAL_ROSTER.v1.json","size_bytes":7769,"sha256":"f53fc414cb8ddf0b7c09c979e92084f6802df3a6add545227afef223b8cf8dfc"},{"evidence_id":"R9_CONTRACT","path":"architecture/program-facts-g3-00-admission-lineage-r9-projection-formula-correction-amendment.md","size_bytes":79104,"sha256":"480ee3283fc546c7474aad6b9c057f915132a15d5c5e3140f33a97d525a3027c"},{"evidence_id":"R9_AUTHOR_RECEIPT","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_PROJECTION_FORMULA_CORRECTION_AUTHOR_RECEIPT.md","size_bytes":8198,"sha256":"b58390d3755189640353a0c6525099b4dd7ba4102fee0e3ad39c92c9d3d398ba"},{"evidence_id":"R9_ARCHITECTURE_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_ARCHITECTURE_INDEPENDENT_REVIEW_20260810.md","size_bytes":12760,"sha256":"8bbb25734e9572da85ba27c3156719d7412951e67bf3346555e84dfad51eab4e"},{"evidence_id":"R9_REJECTED_ROSTER","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_BOUND_PRINCIPAL_ROSTER.v1.json","size_bytes":8325,"sha256":"743c09a5ab1074cb1079b6388752d5721c0e89ddcc73377201288e649c6b9e7f"},{"evidence_id":"R9_OPERATIONAL_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R9_OPERATIONAL_LIVENESS_INDEPENDENT_REVIEW_20260810.md","size_bytes":9488,"sha256":"f19d4cc742e7a773616e60e2801e604d9576fed8caf24878cb8e793329b5e89b"}]}
```

Catalog order and every tuple are exact. Evidence arrays use ordered catalog
IDs. Reorder, relabel, duplicate, omission, extension, or byte mismatch rejects.

## 2. Authority ceiling and Part-0

The exact authority ceiling is this 29-key object in every r10 governed record:

```json
{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}
```

`Part0` is exactly:

```json
{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}
```

No current production, driver, provider, native, artifact-ledger, package, or
installed identity is pinned. Candidate code may not import production or a
prior candidate. Nothing here authorizes a pipeline phase.

## 3. Honest trust model and optional external identity profile

The base trust declaration is immutable:

```json
{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_TRUST_MODEL_V1","base_model":"BINDER_SIGNED_TRANSPORT_INTEGRITY_PLUS_AUDITABLE_PROCESS_SEPARATION","binder_signature_proves":["ROSTER_TRANSPORT_BYTES_AUTHENTIC_TO_DECLARED_BINDER_KEY"],"binder_signature_does_not_prove":["ASSIGNEE_IDENTITY","ASSIGNEE_KEY_POSSESSION","ASSIGNEE_KEY_CUSTODY","NATURAL_PERSON_DISTINCTNESS","PROCESS_NON_COLLUSION","ORGANIZATIONAL_INDEPENDENCE"],"per_role_public_keys_present":false,"downstream_role_signatures_required":false,"cryptographic_principal_identity_claimed":false,"cryptographic_independence_claimed":false,"process_separation_claim":"AUDITABLE_LABEL_PATH_PROCESS_AND_REPLAY_SEPARATION_ONLY","optional_external_identity_profile":{"profile_id":null,"state":"NOT_CONFIGURED_NOT_SATISFIED_NOT_CLAIMED","may_be_fabricated_or_inferred":false}}
```

The roster binder may use one Ed25519 key to sign the roster transport
preimage. Its public key and signature are integrity metadata. They are not
copied into assignments and never authorize a downstream actor. Erasure of the
binder private key after roster creation does not affect route liveness because
all later validation is public verification and hashing.

A deployment that wants cryptographic actor identity must supply a separately
governed external profile before roster creation. That profile must define
independently generated per-principal key offers, proof-of-possession challenges
bound to exact contract/role/ordinal/principal/task values, custody and retention
attestations, revocation, expiry, liveness, and a verifier whose authority is
external to this Part-0 fixture. The profile and its evidence must have exact
out-of-tree hashes and an independent review. No r10 base artifact may create,
synthesize, backfill, infer, or claim that evidence. This repository currently
satisfies no such profile. When absent, every cryptographic identity or
independence claim must remain false. The optional profile may strengthen an
external deployment; it cannot weaken or replace the base process-separation
checks.

## 4. Exact assignments and non-cryptographic separation

The exact role-assignment registry is:

```json
{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_ASSIGNMENT_REGISTRY_V1","assignments":[{"ordinal":0,"role":"R10_AMENDMENT_AUTHOR","principal_id":"Codex:/root/g3_r10_integrity_identity_arch","task_id":"g3-r10-integrity-identity-arch"},{"ordinal":1,"role":"R10_ROSTER_INTEGRITY_BINDER","principal_id":"Codex:/root/g3_r10_roster_integrity_binder","task_id":"g3-r10-roster-integrity-binder"},{"ordinal":2,"role":"R10_READ_ONLY_STAGE_OBSERVER","principal_id":"Codex:/root/g3_r10_stage_observer","task_id":"g3-r10-stage-observer"},{"ordinal":3,"role":"R10_INDEPENDENT_PREIMPLEMENTATION_REVIEWER","principal_id":"Codex:/root/g3_r10_preimplementation_reviewer","task_id":"g3-r10-preimplementation-reviewer"},{"ordinal":4,"role":"R10_INDEPENDENT_PREIMPLEMENTATION_ADMISSION_REVIEWER","principal_id":"Codex:/root/g3_r10_preimplementation_admission_reviewer","task_id":"g3-r10-preimplementation-admission-reviewer"},{"ordinal":5,"role":"R10_SCHEMA_RENDERER","principal_id":"Codex:/root/g3_r10_schema_renderer","task_id":"g3-r10-schema-renderer"},{"ordinal":6,"role":"R10_PRIMARY_SEMANTIC_VALIDATOR_IMPLEMENTER","principal_id":"Codex:/root/g3_r10_primary_semantic_validator_implementer","task_id":"g3-r10-primary-semantic-validator-implementer"},{"ordinal":7,"role":"R10_INDEPENDENT_RECEIPT_VALIDATOR_IMPLEMENTER","principal_id":"Codex:/root/g3_r10_independent_receipt_validator_implementer","task_id":"g3-r10-independent-receipt-validator-implementer"},{"ordinal":8,"role":"R10_GREEN_HARNESS_AUTHOR","principal_id":"Codex:/root/g3_r10_green_harness_author","task_id":"g3-r10-green-harness-author"},{"ordinal":9,"role":"R10_GREEN_EXECUTOR","principal_id":"Codex:/root/g3_r10_green_executor","task_id":"g3-r10-green-executor"},{"ordinal":10,"role":"R10_INDEPENDENT_SEMANTIC_ACCEPTANCE_REVIEWER","principal_id":"Codex:/root/g3_r10_semantic_acceptance_reviewer","task_id":"g3-r10-semantic-acceptance-reviewer"}]}
```

All 11 roles, principal labels, and task IDs are pairwise unique. There are 55
internal principal-label comparisons and 55 internal task-ID comparisons.
Every principal label is unequal to the exact 35-value prior set consisting of
r9's 24 prior-producer values followed by its 11 roster principal labels, for
385 cross-prior comparisons. No continuity is declared.

The prior set is this exact ordered literal; it is not extensible and grants no
continuity or authority:

```json
{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_PRIOR_PRODUCER_REGISTRY_V1","principal_ids":["Codex:/root/g3_r3_correction_author_short","Codex:/root/g3_r5_principal_roster_binder_short","Codex:/root/g3_r5_ordering_review_short","Codex:/root/g3_r5_schema_renderer_short","Codex:/root/g3_r5_fixture_author_short","Codex:/root/g3_r6_principal_roster_binder_short","Codex:/root/g3_r6_preimplementation_review_short","Codex:/root/g3_r7_principal_roster_binder_short","Codex:/root/g3_r7_preimplementation_review_short","Codex:/root/g3_r7_semantic_successor_implementer_short","Codex:/root/g3_r7_green_executor_short","Codex:/root/g3_r7_semantic_acceptance_review_short","Codex:/root/g3_r8_semantic_correction_arch","Codex:/root/g3_r8_principal_roster_binder","Codex:/root/g3_r8_stage_observer","Codex:/root/g3_r8_preimplementation_reviewer","Codex:/root/g3_r8_preimplementation_admission_reviewer","Codex:/root/g3_r8_schema_renderer","Codex:/root/g3_r8_primary_semantic_validator_implementer","Codex:/root/g3_r8_independent_receipt_validator_implementer","Codex:/root/g3_r8_green_harness_author","Codex:/root/g3_r8_green_executor","Codex:/root/g3_r8_semantic_acceptance_reviewer","Codex:/root/g3_next_authority_route_short","Codex:/root/g3_r9_projection_formula_arch","Codex:/root/g3_r9_principal_roster_binder","Codex:/root/g3_r9_stage_observer","Codex:/root/g3_r9_preimplementation_reviewer","Codex:/root/g3_r9_preimplementation_admission_reviewer","Codex:/root/g3_r9_schema_renderer","Codex:/root/g3_r9_primary_semantic_validator_implementer","Codex:/root/g3_r9_independent_receipt_validator_implementer","Codex:/root/g3_r9_green_harness_author","Codex:/root/g3_r9_green_executor","Codex:/root/g3_r9_semantic_acceptance_reviewer"]}
```

Each assignment is identified by:

```text
assignment_body_sha256[i] = SHA256(CJ({ordinal,role,principal_id,task_id}))
assignment_projection_sha256 = SHA256(CJ([{ordinal,role,principal_id,task_id,assignment_body_sha256} in ordinal order]))
projection_body_sha256 = SHA256(CJ(separation_projection without only projection_body_sha256))
```

The closed `separation_projection` has exactly nine fields before deletion:
`internal_principal_pair_count`, `internal_task_pair_count`,
`cross_prior_principal_pair_count`, `declared_continuity_pairs`,
`unexpected_internal_principal_equal_pairs`,
`unexpected_internal_task_equal_pairs`, `unexpected_cross_equal_pairs`,
`assignment_projection_sha256`, and `projection_body_sha256`. Deleting only the
last member leaves exactly eight non-self fields. RFC 8785 canonical member
order is `assignment_projection_sha256`, `cross_prior_principal_pair_count`,
`declared_continuity_pairs`, `internal_principal_pair_count`,
`internal_task_pair_count`, `unexpected_cross_equal_pairs`,
`unexpected_internal_principal_equal_pairs`, and
`unexpected_internal_task_equal_pairs`.

Validation first closes the object and pins `55`, `55`, and `385`; recomputes
the assignment projection; deletes only `projection_body_sha256`; recomputes
the projection digest; and only then validates the roster body, ID, and binder
transport signature. There is no self-reference or inherited formula.

The exact roster formulas are:

```text
roster_core = roster without only roster_id, roster_body_sha256, transport_integrity
roster_body_sha256 = SHA256(CJ(roster_core))
roster_id = "pfg3alr10pr-" || SHA256(CJ({domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_ROSTER_ID_V1",roster_body_sha256,subject,author_receipt}))[0:32]
transport_integrity.signed_preimage_sha256 = SHA256(CJ({domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_ROSTER_TRANSPORT_V1",roster_id,roster_body_sha256,subject,author_receipt,binder_assignment_sha256}))
```

The signature verifies only that preimage under the declared binder public key.
Per-role public keys, per-role signatures, custody assertions, or independence
booleans are forbidden in the base roster.

Every governed downstream record contains a closed `actor_binding` with exact
roster file reference and body digest, assignment digest, ordinal, principal
label, role, task ID, process-instance ID, process-start identity, workspace
native identity, and the literal claim
`AUDITABLE_PROCESS_LABEL_ONLY_NOT_CRYPTOGRAPHIC_IDENTITY`. It has no signature
or public-key field. Exact record formulas are:

```text
record_body_sha256 = SHA256(CJ(record without only record_id and record_body_sha256))
record_id = prefix(record_kind) || SHA256(CJ({domain:domain(record_kind),canonical_path,record_body_sha256}))[0:32]
artifact_file_sha256 = SHA256(exact serialized UTF-8 LF-only record bytes)
```

Prefixes are exactly `pfg3alr10decl-`, `pfg3alr10opre-`,
`pfg3alr10pre-`, `pfg3alr10ocommit-`, `pfg3alr10admit-`,
`pfg3alr10exec-`, `pfg3alr10green-`, `pfg3alr10gval-`, and
`pfg3alr10accept-` for declaration, observer PRE, preimplementation review,
observer COMMIT, admission, execution, GREEN, GREEN validation, and semantic
acceptance respectively.

A record is not independently accepted merely because its self-declared actor
fields match. Its distinct successor reviewer must authenticate the exact file
path, byte length, `artifact_file_sha256`, roster/assignment join, predecessor
file references, observed process occurrence, and replay result. A terminal r10
semantic-acceptance record remains non-authoritative until a later, separately
governed aggregate review binds its bytes. Alias, relabel, task reuse,
process-instance reuse across a producer/reviewer edge, self-review, predecessor
omission/reorder/substitution, or file-byte mismatch rejects.

## 5. Versioned path templates and append-only attempt chain

The exact r10 path-template registry is:

```json
{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_PATH_TEMPLATE_REGISTRY_V1","entries":[{"ordinal":0,"stage":"STATIC_PRE_ATTEMPT_INPUT","kind":"BOUND_ROSTER","path_template":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_BOUND_PROCESS_ROSTER.v1.json"},{"ordinal":1,"stage":"ATTEMPT_PRE_REVIEW_INPUT","kind":"ATTEMPT_DECLARATION","path_template":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/r10_attempts/{ATTEMPT_ID}/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_ATTEMPT_DECLARATION.v1.json"},{"ordinal":2,"stage":"ATTEMPT_PRE_REVIEW_INPUT","kind":"OBSERVER_PRE_RECEIPT","path_template":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/r10_attempts/{ATTEMPT_ID}/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_STAGE_OBSERVER_PRE_RECEIPT.v1.json"},{"ordinal":3,"stage":"REVIEW_ATOMIC_OUTPUT","kind":"PREIMPLEMENTATION_REVIEW","path_template":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/r10_attempts/{ATTEMPT_ID}/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_PREIMPLEMENTATION_REVIEW.v1.json"},{"ordinal":4,"stage":"POST_REVIEW_PRE_ADMISSION_INPUT","kind":"OBSERVER_COMMIT_RECEIPT","path_template":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/r10_attempts/{ATTEMPT_ID}/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_STAGE_OBSERVER_COMMIT_RECEIPT.v1.json"},{"ordinal":5,"stage":"PREIMPLEMENTATION_ADMISSION_OUTPUT","kind":"PREIMPLEMENTATION_ADMISSION","path_template":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/r10_attempts/{ATTEMPT_ID}/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_PREIMPLEMENTATION_ADMISSION.v1.json"},{"ordinal":6,"stage":"POST_ADMISSION_OUTPUT","kind":"SCHEMA_RENDER","path_template":"rules/schemas/g3_r10/{ATTEMPT_ID}/program_facts_g3_00_admission_lineage_r10_process_roster.v1.schema.json"},{"ordinal":7,"stage":"POST_ADMISSION_OUTPUT","kind":"SCHEMA_RENDER","path_template":"rules/schemas/g3_r10/{ATTEMPT_ID}/program_facts_g3_00_admission_lineage_r10_stage_observation.v1.schema.json"},{"ordinal":8,"stage":"POST_ADMISSION_OUTPUT","kind":"SCHEMA_RENDER","path_template":"rules/schemas/g3_r10/{ATTEMPT_ID}/program_facts_g3_00_admission_lineage_r10_preimplementation_review.v1.schema.json"},{"ordinal":9,"stage":"POST_ADMISSION_OUTPUT","kind":"SCHEMA_RENDER","path_template":"rules/schemas/g3_r10/{ATTEMPT_ID}/program_facts_g3_00_admission_lineage_r10_preimplementation_admission.v1.schema.json"},{"ordinal":10,"stage":"POST_ADMISSION_OUTPUT","kind":"SCHEMA_RENDER","path_template":"rules/schemas/g3_r10/{ATTEMPT_ID}/program_facts_g3_00_admission_lineage_r10_semantic_evidence.v1.schema.json"},{"ordinal":11,"stage":"POST_ADMISSION_OUTPUT","kind":"SCHEMA_RENDER","path_template":"rules/schemas/g3_r10/{ATTEMPT_ID}/program_facts_g3_00_admission_lineage_r10_semantic_acceptance.v1.schema.json"},{"ordinal":12,"stage":"POST_ADMISSION_OUTPUT","kind":"PRIMARY_SEMANTIC_VALIDATOR","path_template":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/r10_attempts/{ATTEMPT_ID}/validate_admission_lineage_r10_review_semantics_v1.py"},{"ordinal":13,"stage":"POST_ADMISSION_OUTPUT","kind":"INDEPENDENT_RECEIPT_VALIDATOR","path_template":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/r10_attempts/{ATTEMPT_ID}/validate_admission_lineage_r10_green_receipt_semantics_v1.py"},{"ordinal":14,"stage":"POST_ADMISSION_OUTPUT","kind":"GREEN_HARNESS","path_template":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/r10_attempts/{ATTEMPT_ID}/test_admission_lineage_r10_semantic_closure_green_v1.py"},{"ordinal":15,"stage":"POST_ADMISSION_OUTPUT","kind":"EXECUTION_RECEIPT","path_template":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/r10_attempts/{ATTEMPT_ID}/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_EXECUTION_RECEIPT.v1.json"},{"ordinal":16,"stage":"POST_ADMISSION_OUTPUT","kind":"GREEN_RECEIPT","path_template":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/r10_attempts/{ATTEMPT_ID}/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_SEMANTIC_GREEN_RECEIPT.v1.json"},{"ordinal":17,"stage":"POST_ADMISSION_OUTPUT","kind":"GREEN_VALIDATION_RECEIPT","path_template":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/r10_attempts/{ATTEMPT_ID}/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_GREEN_VALIDATION_RECEIPT.v1.json"},{"ordinal":18,"stage":"POST_ADMISSION_OUTPUT","kind":"SEMANTIC_ACCEPTANCE_REVIEW","path_template":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/r10_attempts/{ATTEMPT_ID}/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_SEMANTIC_ACCEPTANCE_REVIEW.v1.json"}]}
```

The registry is closed: exactly 19 entries, ordinals `0..18`, and exactly one
placeholder occurrence in every template except ordinal 0. An `ATTEMPT_ID`
matches `^pfg3alr10try-[0-9a-f]{32}$`. Instantiation replaces only the exact
ASCII token `{ATTEMPT_ID}`. All resulting paths are NFC, case-sensitive,
repo-relative `/` paths. Absolute roots, URI encoding, empty segments, `.`,
`..`, colon, backslash, controls, links/reparse points, case-fold aliases, and
normalization aliases reject.

```text
path_template_registry_sha256 = SHA256(CJ(path_template_registry))
path_template_membership_sha256 = SHA256(CJ([entry.path_template in ordinal order]))
instantiated_path_membership_sha256 = SHA256(CJ([instantiate(entry.path_template,attempt_id) in ordinal order]))
downstream_at_review_sha256 = SHA256(CJ(instantiated paths ordinals 4..18))
post_admission_paths_sha256 = SHA256(CJ(instantiated paths ordinals 6..18))
```

Attempt IDs use public, non-secret values:

```text
attempt_id = "pfg3alr10try-" || SHA256(CJ({domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_ATTEMPT_ID_V1",contract_sha256,roster_file_sha256,observer_assignment_sha256,attempt_nonce_sha256,predecessor_attempt_id}))[0:32]
```

The observer holds one root-wide native exclusive admission lease while it:

1. enumerates both exact r10 attempt roots component-by-component/no-follow;
2. reconstructs the unique append-only predecessor chain and rejects forks,
   hidden attempts, duplicate IDs, aliases, or two nonsuperseded heads;
3. verifies that no prior attempt has semantic acceptance PASS;
4. records every prior attempt declaration and any present admission/terminal
   evidence as exact path/size/SHA rows;
5. atomically creates the new declaration and PRE receipt;
6. keeps the lease through distinct preimplementation review, COMMIT, and
   distinct admission review; and
7. releases only after the admission record is atomically created or the
   attempt is left visibly incomplete.

The two enumeration roots are exactly
`review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/r10_attempts`
and `rules/schemas/g3_r10`. The transient lock path is exactly
`review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/.r10_admission_lease`.
The lease is opened no-follow/create-new and deleted only after its native lock
handle is released; it is never an authoritative artifact, never a path-state
substitute, and never evidence by itself. A pre-existing unlocked lease file is
typed recovery debt: its bytes/native identity are captured, it is quarantined
by no-replace atomic rename under the same parent to exactly
`.r10_admission_lease.stale.` followed by the lowercase SHA-256 of
`CJ({lease_file_sha256,lease_native_identity})`; an existing unequal quarantine
target rejects. A new lease is acquired only after complete attempt enumeration.
A locked, aliased, inaccessible, or unstable lease is
`INDETERMINATE_NO_AUTHORITY`.

An existing attempt may resume after process loss only after a new observer
lease independently authenticates every existing byte and proves that the next
path is absent. It may continue the same attempt after admission when all
existing outputs are exact and the next output is absent. It may not continue a
PRE/COMMIT transaction after its lease/process occurrence is lost. Instead it
creates a new attempt whose declaration binds the incomplete predecessor and
reason `SUPERSEDED_INCOMPLETE_SESSION`. If any existing output is invalid or
partial, it is never overwritten; a new successor attempt binds it as
`SUPERSEDED_INVALID_IMMUTABLE_OUTPUT`. A successful semantic acceptance is
terminal for r10 and forbids another attempt.

All writes are create-new/no-replace, UTF-8 without BOM, LF-only, exactly one
final LF, and atomic rename from an authenticated same-directory temporary file.
The temporary leaf is exactly the target leaf plus `.tmp.` plus the first 32
lowercase hexadecimal characters of
`SHA256(CJ({attempt_id,target_path,record_body_sha256}))`. An existing unequal
temporary, rename collision, or identity drift rejects and remains
non-authoritative typed debt. Unsupported native locking or no-follow primitives
yield `INDETERMINATE_NO_AUTHORITY`, never PASS. This is repair-then-degrade
without false historical proof and without a permanent dead end caused by
secret loss.

## 6. Observer protocol and exact stage states

The immutable observer protocol is:

```json
{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_READ_ONLY_OBSERVER_PROTOCOL_V1","root_policy":"OPEN_ROOT_ONCE_PIN_NATIVE_IDENTITY","path_policy":"COMPONENT_WISE_NO_FOLLOW_BENEATH_ROOT","hash_policy":"STABLE_READ_SIZE_HASH_IDENTITY_RESTAT_BEFORE_AFTER","absence_policy":"PIN_PARENT_IDENTITY_AND_PROVE_LEAF_ABSENT_BEFORE_AFTER","attempt_policy":"APPEND_ONLY_CHAIN_UNDER_ONE_ROOT_WIDE_NATIVE_LEASE","resume_policy":"SAME_ATTEMPT_ONLY_AFTER_ADMISSION_OR_WITH_LIVE_ORIGINAL_LEASE_OTHERWISE_NEW_SUCCESSOR_ATTEMPT","write_policy":"CREATE_NEW_NO_REPLACE_ATOMIC_SAME_DIRECTORY","windows_policy":{"open":"CreateFileW_OPEN_REPARSE_POINT","identity":"volume_serial_plus_file_id","lock":"exclusive_native_handle_lock","reject":"ANY_REPARSE_COMPONENT_OR_IDENTITY_DRIFT"},"posix_policy":{"open":"openat2_RESOLVE_BENEATH_NO_SYMLINKS_OR_COMPONENT_OPENAT_O_NOFOLLOW","identity":"st_dev_plus_st_ino","lock":"fcntl_or_flock_exclusive","reject":"ANY_SYMLINK_COMPONENT_OR_IDENTITY_DRIFT"},"unsupported_policy":"INDETERMINATE_NO_AUTHORITY","timestamp_authority":false,"caller_path_states_authority":false,"cryptographic_actor_identity_authority":false,"observer_assignment_ordinal":2}
```

The declaration snapshot proves ordinal 0 PRESENT and instantiated ordinals
1..18 ABSENT before its create-new write. PRE proves ordinals 0,1 PRESENT and
2..18 ABSENT before writing ordinal 2. The preimplementation reviewer consumes
only the exact declaration/PRE bytes and writes ordinal 3. COMMIT proves
ordinals 0..3 PRESENT with unchanged identities and ordinals 4..18 ABSENT
before writing ordinal 4. Admission authenticates that pair and writes ordinal
5 under the same live lease. No schema, code, harness, or execution output may
exist before admission.

Every PRESENT row records path, state, size, SHA-256, root identity, file native
identity, link/reparse classification, stable-read before/after identity, and
producer binding if governed. Every ABSENT row records the pinned parent native
identity, leaf, and two absence probes. Rows are exact ordinal order and total.
`path_states` is forbidden in reviewer APIs, validator defaults, harness
constants, and admission caller data. Null, caller-generated, expected, or
timestamp-derived maps reject. Only observer-produced snapshots can be
evidence, but observer actor labels still do not prove cryptographic identity.

## 7. Closed preimplementation semantics

The exact check registry is:

```json
{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_PREIMPLEMENTATION_CHECK_REGISTRY_V1","checks":[{"check_id":"ALR10-01-SUBJECT-AUTHOR-ROSTER-EXACT","evidence_ids":["R10_CONTRACT","R10_AUTHOR_RECEIPT","R10_ROSTER"]},{"check_id":"ALR10-02-R7-R8-R9-PARENT-BYTES-EXACT","evidence_ids":["R7_CONTRACT","R7_PREIMPLEMENTATION_REVIEW","R7_GREEN_RECEIPT","R7_SEMANTIC_ACCEPTANCE_REVIEW","R8_CONTRACT","R8_ARCHITECTURE_REVIEW","R8_REJECTED_ROSTER","R9_CONTRACT","R9_AUTHOR_RECEIPT","R9_ARCHITECTURE_REVIEW","R9_REJECTED_ROSTER","R9_OPERATIONAL_REVIEW"]},{"check_id":"ALR10-03-R9-FORMULA-ACCEPT-AND-OPERATIONAL-REPAIR-EXACT","evidence_ids":["R9_CONTRACT","R9_ARCHITECTURE_REVIEW","R9_REJECTED_ROSTER","R9_OPERATIONAL_REVIEW"]},{"check_id":"ALR10-04-R7-F001-SEALED-OBJECT-CLOSED","evidence_ids":["R7_CONTRACT","R7_PREIMPLEMENTATION_REVIEW","R7_PRIMARY_VALIDATOR","R7_SEMANTIC_ACCEPTANCE_REVIEW"]},{"check_id":"ALR10-05-R7-F002-OBSERVER-ORIGIN-CLOSED","evidence_ids":["R7_CONTRACT","R7_PRIMARY_VALIDATOR","R7_GREEN_HARNESS","R7_SEMANTIC_ACCEPTANCE_REVIEW"]},{"check_id":"ALR10-06-R7-F003-INDEPENDENT-ORACLE-CLOSED","evidence_ids":["R7_CONTRACT","R7_PRIMARY_VALIDATOR","R7_GREEN_HARNESS","R7_GREEN_RECEIPT","R7_SEMANTIC_ACCEPTANCE_REVIEW"]},{"check_id":"ALR10-07-HONEST-INTEGRITY-ONLY-TRUST-MODEL","evidence_ids":["R10_CONTRACT","R10_ROSTER"]},{"check_id":"ALR10-08-NO-CRYPTOGRAPHIC-IDENTITY-OR-INDEPENDENCE-CLAIM","evidence_ids":["R10_CONTRACT","R10_ROSTER"]},{"check_id":"ALR10-09-ELEVEN-ASSIGNMENTS-EXACT","evidence_ids":["R10_CONTRACT","R10_ROSTER"]},{"check_id":"ALR10-10-PRINCIPAL-AND-TASK-SEPARATIONS-EXACT","evidence_ids":["R10_CONTRACT","R10_ROSTER"]},{"check_id":"ALR10-11-PRIOR-SEPARATIONS-AND-R9-NEGATIVE-EXACT","evidence_ids":["R10_CONTRACT","R9_REJECTED_ROSTER","R9_OPERATIONAL_REVIEW","R10_ROSTER"]},{"check_id":"ALR10-12-BINDER-TRANSPORT-INTEGRITY-ONLY","evidence_ids":["R10_CONTRACT","R10_ROSTER"]},{"check_id":"ALR10-13-OPTIONAL-EXTERNAL-PROFILE-ABSENT-NOT-CLAIMED","evidence_ids":["R10_CONTRACT","R10_ROSTER"]},{"check_id":"ALR10-14-PATH-TEMPLATE-REGISTRY-EXACT","evidence_ids":["R10_CONTRACT","R10_ATTEMPT_DECLARATION"]},{"check_id":"ALR10-15-ATTEMPT-CHAIN-COMPLETE-UNFORKED","evidence_ids":["R10_ATTEMPT_DECLARATION","R10_OBSERVER_PRE"]},{"check_id":"ALR10-16-OBSERVER-PROTOCOL-AND-NATIVE-LEASE-EXACT","evidence_ids":["R10_CONTRACT","R10_ATTEMPT_DECLARATION","R10_OBSERVER_PRE"]},{"check_id":"ALR10-17-PRE-SNAPSHOT-COMPLETE-STABLE","evidence_ids":["R10_OBSERVER_PRE"]},{"check_id":"ALR10-18-ALL-FIFTEEN-DOWNSTREAM-PATHS-ABSENT","evidence_ids":["R10_OBSERVER_PRE"]},{"check_id":"ALR10-19-ACTOR-ASSIGNMENT-PROCESS-BINDINGS-EXACT","evidence_ids":["R10_ROSTER","R10_ATTEMPT_DECLARATION","R10_OBSERVER_PRE"]},{"check_id":"ALR10-20-NO-DOWNSTREAM-ROLE-KEY-OR-SIGNATURE-REQUIREMENT","evidence_ids":["R10_CONTRACT","R10_ROSTER"]},{"check_id":"ALR10-21-ORDERED-PREDECESSOR-EVIDENCE-EXACT","evidence_ids":["R10_CONTRACT","R10_ATTEMPT_DECLARATION","R10_OBSERVER_PRE"]},{"check_id":"ALR10-22-SCOPE-SETS-EXACT","evidence_ids":["R10_CONTRACT"]},{"check_id":"ALR10-23-BINARY-CHECK-TOTALITY-AND-INVERSE-FINDINGS","evidence_ids":["R10_CONTRACT"]},{"check_id":"ALR10-24-RECURSIVE-SCHEMA-CLOSURE","evidence_ids":["R10_CONTRACT"]},{"check_id":"ALR10-25-FROZEN-DENOMINATOR-AND-ORACLE-EXACT","evidence_ids":["R10_CONTRACT"]},{"check_id":"ALR10-26-REVIEW-BEFORE-RENDER-CODE-EXECUTION","evidence_ids":["R10_CONTRACT","R10_OBSERVER_PRE"]},{"check_id":"ALR10-27-PART0-AUTHORITY-EXACT","evidence_ids":["R10_CONTRACT","R10_ROSTER","R10_OBSERVER_PRE"]},{"check_id":"ALR10-28-STOP-BEFORE-IMPLEMENTATION","evidence_ids":["R10_CONTRACT","R10_OBSERVER_PRE"]}]}
```

Every check object has exactly `check_id`, `result`, and ordered `evidence`;
`result` is only `PASS|FAIL`. The review top level is recursively closed.
`R10_CONTRACT`, `R10_AUTHOR_RECEIPT`, and `R10_ROSTER` resolve only to the exact
r10 subject, author-receipt, and ordinal-0 roster paths; `R10_ATTEMPT_DECLARATION`
and `R10_OBSERVER_PRE` resolve only to the active attempt's instantiated
ordinals 1 and 2. The resolver recomputes path, byte length, and SHA-256. No
caller-supplied evidence map, basename join, or cross-attempt alias is allowed.
`accepted_scope` is exactly
`["AUTHOR_R10_OBSERVER_COMMIT_RECEIPT","AUTHOR_R10_PREIMPLEMENTATION_ADMISSION"]`.
`rejected_scope` is exactly
`["RENDER_SCHEMAS","AUTHOR_VALIDATORS","AUTHOR_HARNESS","EXECUTE_GREEN","AUTHOR_EXECUTION_RECEIPT","AUTHOR_GREEN_RECEIPT","AUTHOR_GREEN_VALIDATION_RECEIPT","AUTHOR_SEMANTIC_ACCEPTANCE_REVIEW","AGGREGATE_ADMISSION","G3_01","PRODUCTION","RUNTIME","NATIVE","PROVIDER","PUBLICATION","ADMISSION","PACKAGE","INSTALL","RELEASE","CUTOVER","COMMIT","PUSH"]`.

Let `F` be FAIL check IDs in registry order and `O` the lexicographically
ordered IDs of `BLOCKING/OPEN` findings. PASS requires 28/28 PASS and empty
findings/open/failure arrays. REJECTED requires nonempty `F`; every finding
exactly blocking/open; `open_findings == O`; each finding's failed checks a
nonempty registry-ordered subset of `F`; and `failure_bindings` the exact inverse
for every `F`. Any missing, extra, closed, nonblocking, reordered, or unrelated
projection rejects.

Admission has exactly these 14 ordered checks:

```text
ALR10D-01-REVIEW-BYTES-AND-PASS-EXACT
ALR10D-02-DECLARATION-PRE-COMMIT-BYTES-EXACT
ALR10D-03-LIVE-LEASE-ROOT-SESSION-EQUAL
ALR10D-04-ATTEMPT-CHAIN-UNFORKED-AND-CURRENT
ALR10D-05-PRE-REVIEW-COMMIT-SNAPSHOTS-COMPLETE
ALR10D-06-REVIEW-IDENTITY-IN-COMMIT-EXACT
ALR10D-07-ALL-POST-REVIEW-PATHS-ABSENT
ALR10D-08-NO-RENDER-CODE-OR-EXECUTION-PRESENT
ALR10D-09-ACTOR-ASSIGNMENT-AND-PROCESS-SEPARATION-EXACT
ALR10D-10-NO-PER-ROLE-SECRET-DEPENDENCY
ALR10D-11-CANDIDATE-DENOMINATOR-ORACLE-EXACT
ALR10D-12-PREDECESSOR-BYTE-JOINS-EXACT
ALR10D-13-PART0-AUTHORITY-EXACT
ALR10D-14-STOPPED-POST-ADMISSION-SCOPE-ONLY
```

PASS requires 14/14 PASS, exact empty projections, review disposition
`PASS_R10_PREIMPLEMENTATION_OBSERVED_STOPPED_ONLY`, and exact accepted scope
`["RENDER_6_R10_SCHEMAS","AUTHOR_R10_PRIMARY_VALIDATOR","AUTHOR_R10_INDEPENDENT_RECEIPT_VALIDATOR","AUTHOR_R10_GREEN_HARNESS","EXECUTE_BOUND_R10_GREEN","AUTHOR_R10_EXECUTION_RECEIPT","AUTHOR_R10_GREEN_RECEIPT","EXECUTE_INDEPENDENT_GREEN_RECEIPT_VALIDATION","AUTHOR_R10_GREEN_VALIDATION_RECEIPT","AUTHOR_INDEPENDENT_R10_SEMANTIC_ACCEPTANCE_REVIEW"]`.
Its rejected scope remains the 14 values from `AGGREGATE_ADMISSION` through
`PUSH` in the review list above. No aggregate or production authority exists.

## 8. Frozen fixture-first denominator

The r10 denominator preserves every r9 control/mutation semantically, replacing
only versioned identifiers, and adds liveness and honest-identity cases:

```json
{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_RED_GREEN_DENOMINATOR_V1","controls":[{"case_id":"ALC-R10-C01-VALID-PASS-REVIEW","expected":"ACCEPT"},{"case_id":"ALC-R10-C02-TRUTHFUL-REJECTED-REVIEW","expected":"ACCEPT"},{"case_id":"ALC-R10-C03-VALID-OBSERVER-PRE-COMMIT-PAIR","expected":"ACCEPT"},{"case_id":"ALC-R10-C04-STALE-SESSION-NEW-ATTEMPT-RESUME","expected":"ACCEPT"},{"case_id":"ALC-R10-C05-VALID-GREEN-AND-INDEPENDENT-VALIDATION","expected":"ACCEPT"},{"case_id":"ALC-R10-C06-BASE-TRUST-WITHOUT-OPTIONAL-IDENTITY-PROFILE","expected":"ACCEPT"}],"mutations":[{"case_id":"ALC-R10-M01-HIDDEN-OPEN-BLOCKER","expected_code":"PASS_OPEN_FINDING_FORBIDDEN"},{"case_id":"ALC-R10-M02-OPEN-ROSTER-MISMATCH","expected_code":"FINDING_PROJECTION_MISMATCH"},{"case_id":"ALC-R10-M03-PRINCIPAL-ALIAS","expected_code":"PRINCIPAL_ALIAS"},{"case_id":"ALC-R10-M04-PRINCIPAL-RELABEL","expected_code":"PRINCIPAL_BINDING_MISMATCH"},{"case_id":"ALC-R10-M05-UNAUTHORIZED-SUCCESSOR","expected_code":"UNAUTHORIZED_SUCCESSOR"},{"case_id":"ALC-R10-M06-FALSE-SEMANTIC-ACCEPTANCE","expected_code":"FALSE_SEMANTIC_ACCEPTANCE"},{"case_id":"ALC-R10-M07-MISSING-ROSTER","expected_code":"MISSING_REQUIRED_ROSTER"},{"case_id":"ALC-R10-M08-PRE-REVIEW-OUTPUT-PRESENT","expected_code":"PRE_REVIEW_OUTPUT_PRESENT"},{"case_id":"ALC-R10-M09-REGISTRY-REORDER","expected_code":"PATH_REGISTRY_ORDER_MISMATCH"},{"case_id":"ALC-R10-M10-REGISTRY-ALIAS","expected_code":"PATH_REGISTRY_ALIAS"},{"case_id":"ALC-R10-M11-REGISTRY-DUPLICATE","expected_code":"PATH_REGISTRY_DUPLICATE"},{"case_id":"ALC-R10-M12-REGISTRY-HASH-MISMATCH","expected_code":"PATH_REGISTRY_HASH_MISMATCH"},{"case_id":"ALC-R10-M13-ACCEPTED-SCOPE-WIDENED","expected_code":"ACCEPTED_SCOPE_MISMATCH"},{"case_id":"ALC-R10-M14-REJECTED-SCOPE-NARROWED","expected_code":"REJECTED_SCOPE_MISMATCH"},{"case_id":"ALC-R10-M15-INDETERMINATE-CHECK-RESULT","expected_code":"CHECK_RESULT_NOT_BINARY"},{"case_id":"ALC-R10-M16-UNKNOWN-TOP-LEVEL-FIELD","expected_code":"SCHEMA_CLOSURE_VIOLATION"},{"case_id":"ALC-R10-M17-UNKNOWN-NESTED-FIELD","expected_code":"SCHEMA_CLOSURE_VIOLATION"},{"case_id":"ALC-R10-M18-REGISTRY-EXTENSION","expected_code":"PATH_REGISTRY_EXTENSION"},{"case_id":"ALC-R10-M19-HISTORICAL-EVIDENCE-SWAP","expected_code":"EVIDENCE_ASSOCIATION_MISMATCH"},{"case_id":"ALC-R10-M20-EVIDENCE-REORDER","expected_code":"EVIDENCE_ORDER_MISMATCH"},{"case_id":"ALC-R10-M21-EVIDENCE-RELABEL","expected_code":"EVIDENCE_ASSOCIATION_MISMATCH"},{"case_id":"ALC-R10-M22-PATH-STATES-OMITTED","expected_code":"OBSERVER_PATH_STATES_INCOMPLETE"},{"case_id":"ALC-R10-M23-PATH-STATES-NULL-OR-SYNTHETIC","expected_code":"OBSERVER_ORIGIN_INVALID"},{"case_id":"ALC-R10-M24-OBSERVER-PRINCIPAL-SPOOF","expected_code":"OBSERVER_PRINCIPAL_MISMATCH"},{"case_id":"ALC-R10-M25-OBSERVER-ACTOR-BINDING-SPOOF","expected_code":"OBSERVER_ACTOR_BINDING_INVALID"},{"case_id":"ALC-R10-M26-OBSERVER-REPLAY","expected_code":"OBSERVER_SESSION_REPLAY"},{"case_id":"ALC-R10-M27-OBSERVER-PRE-ROW-OMISSION","expected_code":"OBSERVER_PRE_INCOMPLETE"},{"case_id":"ALC-R10-M28-OBSERVER-POST-ROW-OMISSION","expected_code":"OBSERVER_POST_INCOMPLETE"},{"case_id":"ALC-R10-M29-CANDIDATE-SET-SUBSTITUTION","expected_code":"CANDIDATE_SET_MISMATCH"},{"case_id":"ALC-R10-M30-RECEIPT-BODY-HASH-SUBSTITUTION","expected_code":"RECORD_BODY_HASH_MISMATCH"},{"case_id":"ALC-R10-M31-RECEIPT-ID-SUBSTITUTION","expected_code":"RECORD_ID_MISMATCH"},{"case_id":"ALC-R10-M32-SELF-ORACLE-IMPORT","expected_code":"ORACLE_PROVENANCE_INVALID"},{"case_id":"ALC-R10-M33-ORACLE-EXPECTED-OUTCOME-SUBSTITUTION","expected_code":"ORACLE_OUTCOME_MISMATCH"},{"case_id":"ALC-R10-M34-ORACLE-CODE-SUBSTITUTION","expected_code":"ORACLE_CODE_MISMATCH"},{"case_id":"ALC-R10-M35-EXECUTION-RECEIPT-SUBSTITUTION","expected_code":"EXECUTION_RECEIPT_MISMATCH"},{"case_id":"ALC-R10-M36-PRIMARY-VALIDATOR-IDENTITY-SUBSTITUTION","expected_code":"PRIMARY_VALIDATOR_IDENTITY_MISMATCH"},{"case_id":"ALC-R10-M37-HARNESS-IDENTITY-SUBSTITUTION","expected_code":"HARNESS_IDENTITY_MISMATCH"},{"case_id":"ALC-R10-M38-OBSERVER-IDENTITY-SUBSTITUTION","expected_code":"OBSERVER_IDENTITY_MISMATCH"},{"case_id":"ALC-R10-M39-UNKNOWN-ENUM","expected_code":"ENUM_CLOSURE_VIOLATION"},{"case_id":"ALC-R10-M40-DENOMINATOR-EXTENSION","expected_code":"DENOMINATOR_MISMATCH"},{"case_id":"ALC-R10-M41-AUTHORITY-FLIP","expected_code":"AUTHORITY_CEILING_VIOLATION"},{"case_id":"ALC-R10-M42-PART0-PROTOCOL-NAME","expected_code":"PART0_VIOLATION"},{"case_id":"ALC-R10-M43-RECEIPT-VALIDATOR-NOT-INDEPENDENT","expected_code":"RECEIPT_VALIDATOR_INDEPENDENCE_VIOLATION"},{"case_id":"ALC-R10-M44-COMMIT-RECEIPT-MISSING","expected_code":"OBSERVER_COMMIT_MISSING"},{"case_id":"ALC-R10-M45-COMMIT-STATE-MISMATCH","expected_code":"OBSERVER_COMMIT_STATE_MISMATCH"},{"case_id":"ALC-R10-M46-GREEN-RESULT-TUPLE-REORDER","expected_code":"GREEN_RESULT_TUPLE_ORDER_MISMATCH"},{"case_id":"ALC-R10-M47-R9-ROSTER-SUBSTITUTION","expected_code":"R9_REJECTED_ROSTER_SUBSTITUTION"},{"case_id":"ALC-R10-M48-PER-ROLE-PUBLIC-KEY-REINTRODUCED","expected_code":"BASE_TRUST_MODEL_VIOLATION"},{"case_id":"ALC-R10-M49-DOWNSTREAM-ROLE-SIGNATURE-REQUIRED","expected_code":"UNINHABITABLE_SECRET_DEPENDENCY"},{"case_id":"ALC-R10-M50-TRANSPORT-SIGNATURE-CLAIMED-AS-IDENTITY","expected_code":"TRANSPORT_INTEGRITY_OVERCALL"},{"case_id":"ALC-R10-M51-CRYPTOGRAPHIC-INDEPENDENCE-CLAIM-FLIP","expected_code":"CRYPTOGRAPHIC_INDEPENDENCE_UNPROVEN"},{"case_id":"ALC-R10-M52-FABRICATED-OPTIONAL-KEY-OFFER","expected_code":"OPTIONAL_IDENTITY_PROFILE_UNGOVERNED"},{"case_id":"ALC-R10-M53-TASK-ID-ALIAS","expected_code":"TASK_ALIAS"},{"case_id":"ALC-R10-M54-TASK-ROLE-RELABEL","expected_code":"TASK_BINDING_MISMATCH"},{"case_id":"ALC-R10-M55-SELF-REVIEW-ACTOR","expected_code":"SELF_REVIEW_FORBIDDEN"},{"case_id":"ALC-R10-M56-PRODUCER-REVIEWER-PROCESS-REUSE","expected_code":"PROCESS_OCCURRENCE_NOT_DISTINCT"},{"case_id":"ALC-R10-M57-ACTOR-ASSIGNMENT-HASH-MISMATCH","expected_code":"ACTOR_ASSIGNMENT_MISMATCH"},{"case_id":"ALC-R10-M58-PREDECESSOR-REFERENCE-OMISSION","expected_code":"PREDECESSOR_SET_MISMATCH"},{"case_id":"ALC-R10-M59-PREDECESSOR-HASH-SUBSTITUTION","expected_code":"PREDECESSOR_BYTES_MISMATCH"},{"case_id":"ALC-R10-M60-CONSUMED-ARTIFACT-BYTES-MISMATCH","expected_code":"ARTIFACT_FILE_HASH_MISMATCH"},{"case_id":"ALC-R10-M61-STALE-LEASE-IN-PLACE-RESUME","expected_code":"STALE_ATTEMPT_REQUIRES_SUCCESSOR"},{"case_id":"ALC-R10-M62-ABANDONED-ATTEMPT-OVERWRITE","expected_code":"IMMUTABLE_ATTEMPT_OVERWRITE"},{"case_id":"ALC-R10-M63-ATTEMPT-CHAIN-FORK","expected_code":"ATTEMPT_CHAIN_FORK"},{"case_id":"ALC-R10-M64-CONCURRENT-ADMITTED-HEADS","expected_code":"MULTIPLE_ADMITTED_HEADS"},{"case_id":"ALC-R10-M65-PRIOR-ATTEMPT-OMITTED","expected_code":"ATTEMPT_ENUMERATION_INCOMPLETE"},{"case_id":"ALC-R10-M66-INVALID-RESUME-CLAIMED-GREEN","expected_code":"INVALID_RESUME_FALSE_GREEN"}],"green_oracle":{"control_accept_count":6,"mutation_reject_count":66,"unexpected_accept_count":0,"wrong_rejection_code_count":0,"control_failure_count":0,"process_exit":0,"semantic_acceptance_claimed_by_green_receipt":false},"oracle_provenance":"PARSE_THIS_CONTRACT_DENOMINATOR_AND_INDEPENDENTLY_RECONSTRUCT","forbidden_oracle_sources":["PRIMARY_VALIDATOR_CONSTANTS","RECEIPT_VALIDATOR_CONSTANTS","HARNESS_EXPECTED_VALUES","GREEN_RECEIPT_EXPECTED_VALUES","ROSTER_BINDER_EXPECTED_VALUES"]}
```

All 72 cases must be written and produce RED before validator implementation.
The harness parses this frozen contract denominator or an independently rendered
immutable fixture. Expected outcomes and codes never come from either validator
under test, the harness, GREEN receipts, or binder output.

The candidate-set preimage is exact LF-separated UTF-8 with no terminal LF:

```text
PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_CANDIDATE_SET_V1
historical_evidence_catalog_sha256
trust_model_sha256
assignment_registry_sha256
prior_producer_registry_sha256
path_template_registry_sha256
path_template_membership_sha256
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

Every component is recomputed from a literal. A supplied digest is never proof.

The author's canonical recomputation vector is:

```text
historical_evidence_catalog_sha256 = ed41253fd6eea2a03e8d89042ac2a8ee8168d5d2533b40dd600a2a72f4faa86b
trust_model_sha256 = e5d5b19972b39304bba85220c1f3dbc02f41cdee7d9b5d61cc13b775aed454b5
assignment_registry_sha256 = d3264802b986b41f9676768376be7f00f1b8db2f8103a107458972e03438b625
prior_producer_registry_sha256 = 860979519dcecd071c0746fea8d0cccb20d1b8f9d2fc3ea0553f63ee81b695c0
path_template_registry_sha256 = a33c7fcd4f1b01a332e2c2e4641bf8cbe11c4fb47d6469e8c763283eaa8a7f8e
path_template_membership_sha256 = 5ee204dd64fa387ca41e0793c233ca8814fc85aa214d8bff4a480cad90b87128
observer_protocol_sha256 = 7764fd9c6c465f5b3c6aafc02799996e3b5e08141013db77b276c9e9ad344690
preimplementation_check_registry_sha256 = d6770a0cf727ead5168ea1dc8c0e52f924e4f6825dfb61f3b672b00e36a02c61
denominator_sha256 = cd66178d1ab485b41f8d91efc09a81a83d502d2eeed333e2e724e6057d109ce4
inline_schema_sha256[0] = 469cbf0cf7592db7dfdc7cf31a2f66596b84068873b760fd382389e72284cffb
inline_schema_sha256[1] = 39f9b74b14de57139b83f0ef18f0c76d71902652aa8d46071cd0d610901a9ef8
inline_schema_sha256[2] = b16a6ff5638ca0bf75faf24e423fd25153a77216a1838244fde07318c0832fa2
inline_schema_sha256[3] = 47af24f2b482e835ba37289177298da50be14ac5446b483c69c24f45da383bd3
inline_schema_sha256[4] = fa54246ef66a545f4bdeab3cc7af1712554b56cf8c9c45044f2684d18ad7b7ac
inline_schema_sha256[5] = 95d1dee15bb6f2219a6b715535bf519e0595c106a474524bdc6a45f84e08eace
candidate_set_sha256 = 974aac22b8f27b0e28cd00afaaf683cd3fdb93a6e516b264bfe31af18b7302fe
```

These are diagnostics derived from the contract literals, never replacement
authorities. Reviewers and validators must recompute them.

## 9. Exact recursively closed schema contracts

The six schema roots below are the sole render candidates. They are Draft
2020-12, use only fragment-local references, and recursively close governed
objects. Cross-field joins remain mandatory semantic predicates.

### 9.1 Process roster

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r10_process_roster.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","roster_id","subject","author_receipt","trust_model","assignments","prior_evidence_producer_ids","separation_projection","transport_integrity","part_0_genericity","authority_ceiling","roster_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r10_process_roster.v1"},"roster_id":{"type":"string","pattern":"^pfg3alr10pr-[0-9a-f]{32}$"},"subject":{"$ref":"#/$defs/file"},"author_receipt":{"$ref":"#/$defs/file"},"trust_model":{"$ref":"#/$defs/trust"},"assignments":{"type":"array","minItems":11,"maxItems":11,"items":{"$ref":"#/$defs/assignment"}},"prior_evidence_producer_ids":{"type":"array","minItems":35,"maxItems":35,"uniqueItems":true,"items":{"$ref":"#/$defs/principal"}},"separation_projection":{"type":"object","additionalProperties":false,"required":["internal_principal_pair_count","internal_task_pair_count","cross_prior_principal_pair_count","declared_continuity_pairs","unexpected_internal_principal_equal_pairs","unexpected_internal_task_equal_pairs","unexpected_cross_equal_pairs","assignment_projection_sha256","projection_body_sha256"],"properties":{"internal_principal_pair_count":{"const":55},"internal_task_pair_count":{"const":55},"cross_prior_principal_pair_count":{"const":385},"declared_continuity_pairs":{"type":"array","maxItems":0},"unexpected_internal_principal_equal_pairs":{"type":"array","maxItems":0},"unexpected_internal_task_equal_pairs":{"type":"array","maxItems":0},"unexpected_cross_equal_pairs":{"type":"array","maxItems":0},"assignment_projection_sha256":{"$ref":"#/$defs/hex"},"projection_body_sha256":{"$ref":"#/$defs/hex"}}},"transport_integrity":{"$ref":"#/$defs/transport"},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"roster_body_sha256":{"$ref":"#/$defs/hex"}},"$defs":{"hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"type":"string","minLength":1},"size_bytes":{"type":"integer","minimum":1},"sha256":{"$ref":"#/$defs/hex"}}},"principal":{"type":"string","pattern":"^[A-Za-z][A-Za-z0-9._-]*:/[A-Za-z0-9._/-]+$"},"assignment":{"type":"object","additionalProperties":false,"required":["ordinal","role","principal_id","task_id","assignment_body_sha256"],"properties":{"ordinal":{"type":"integer","minimum":0,"maximum":10},"role":{"type":"string","minLength":1},"principal_id":{"$ref":"#/$defs/principal"},"task_id":{"type":"string","pattern":"^[a-z0-9][a-z0-9-]+$"},"assignment_body_sha256":{"$ref":"#/$defs/hex"}}},"trust":{"const":{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_TRUST_MODEL_V1","base_model":"BINDER_SIGNED_TRANSPORT_INTEGRITY_PLUS_AUDITABLE_PROCESS_SEPARATION","binder_signature_proves":["ROSTER_TRANSPORT_BYTES_AUTHENTIC_TO_DECLARED_BINDER_KEY"],"binder_signature_does_not_prove":["ASSIGNEE_IDENTITY","ASSIGNEE_KEY_POSSESSION","ASSIGNEE_KEY_CUSTODY","NATURAL_PERSON_DISTINCTNESS","PROCESS_NON_COLLUSION","ORGANIZATIONAL_INDEPENDENCE"],"per_role_public_keys_present":false,"downstream_role_signatures_required":false,"cryptographic_principal_identity_claimed":false,"cryptographic_independence_claimed":false,"process_separation_claim":"AUDITABLE_LABEL_PATH_PROCESS_AND_REPLAY_SEPARATION_ONLY","optional_external_identity_profile":{"profile_id":null,"state":"NOT_CONFIGURED_NOT_SATISFIED_NOT_CLAIMED","may_be_fabricated_or_inferred":false}}},"transport":{"type":"object","additionalProperties":false,"required":["purpose","algorithm","binder_assignment_sha256","binder_public_key_base64","signed_preimage_sha256","signature_base64"],"properties":{"purpose":{"const":"TRANSPORT_INTEGRITY_ONLY_NOT_PRINCIPAL_IDENTITY"},"algorithm":{"const":"ED25519"},"binder_assignment_sha256":{"$ref":"#/$defs/hex"},"binder_public_key_base64":{"type":"string","pattern":"^[A-Za-z0-9+/]{43}=$"},"signed_preimage_sha256":{"$ref":"#/$defs/hex"},"signature_base64":{"type":"string","pattern":"^[A-Za-z0-9+/]{86}==$"}}},"part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}}}
```

### 9.2 Attempt declaration and observer PRE/COMMIT

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r10_stage_observation.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","record_id","record_kind","attempt_id","canonical_path","subject","principal_roster","actor_binding","observer_protocol_sha256","path_template_registry_sha256","session","predecessor_attempts","bound_inputs","snapshot_before","snapshot_after","outcome","part_0_genericity","authority_ceiling","record_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r10_stage_observation.v1"},"record_id":{"type":"string","pattern":"^pfg3alr10(?:decl|opre|ocommit)-[0-9a-f]{32}$"},"record_kind":{"enum":["ATTEMPT_DECLARATION","OBSERVER_PRE_RECEIPT","OBSERVER_COMMIT_RECEIPT"]},"attempt_id":{"type":"string","pattern":"^pfg3alr10try-[0-9a-f]{32}$"},"canonical_path":{"type":"string","minLength":1},"subject":{"$ref":"#/$defs/file"},"principal_roster":{"$ref":"#/$defs/file"},"actor_binding":{"$ref":"#/$defs/actor"},"observer_protocol_sha256":{"$ref":"#/$defs/hex"},"path_template_registry_sha256":{"$ref":"#/$defs/hex"},"session":{"$ref":"#/$defs/session"},"predecessor_attempts":{"type":"array","items":{"$ref":"#/$defs/prior"}},"bound_inputs":{"type":"array","minItems":2,"items":{"$ref":"#/$defs/file"}},"snapshot_before":{"$ref":"#/$defs/snapshot"},"snapshot_after":{"$ref":"#/$defs/snapshot"},"outcome":{"enum":["COMPLETE_STABLE","INDETERMINATE_NO_AUTHORITY"]},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"record_body_sha256":{"$ref":"#/$defs/hex"}},"$defs":{"hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"type":"string","minLength":1},"size_bytes":{"type":"integer","minimum":1},"sha256":{"$ref":"#/$defs/hex"}}},"native":{"type":"object","additionalProperties":false,"required":["os_family","identity_kind","identity_value"],"properties":{"os_family":{"enum":["WINDOWS","POSIX"]},"identity_kind":{"enum":["VOLUME_SERIAL_FILE_ID","ST_DEV_ST_INO","PROCESS_START_NATIVE","WORKSPACE_NATIVE"]},"identity_value":{"type":"string","minLength":1}}},"actor":{"type":"object","additionalProperties":false,"required":["roster_file_sha256","roster_body_sha256","assignment_body_sha256","principal_ordinal","principal_id","role","task_id","process_instance_id","process_start_identity","workspace_identity","identity_claim"],"properties":{"roster_file_sha256":{"$ref":"#/$defs/hex"},"roster_body_sha256":{"$ref":"#/$defs/hex"},"assignment_body_sha256":{"$ref":"#/$defs/hex"},"principal_ordinal":{"const":2},"principal_id":{"type":"string","minLength":1},"role":{"const":"R10_READ_ONLY_STAGE_OBSERVER"},"task_id":{"const":"g3-r10-stage-observer"},"process_instance_id":{"type":"string","minLength":1},"process_start_identity":{"$ref":"#/$defs/native"},"workspace_identity":{"$ref":"#/$defs/native"},"identity_claim":{"const":"AUDITABLE_PROCESS_LABEL_ONLY_NOT_CRYPTOGRAPHIC_IDENTITY"}}},"session":{"type":"object","additionalProperties":false,"required":["session_id","attempt_nonce_sha256","root_identity","observer_process_instance_id","exclusive_lease_state","handoff_assignment_ordinal"],"properties":{"session_id":{"type":"string","pattern":"^pfg3alr10obs-[0-9a-f]{32}$"},"attempt_nonce_sha256":{"$ref":"#/$defs/hex"},"root_identity":{"$ref":"#/$defs/native"},"observer_process_instance_id":{"type":"string","minLength":1},"exclusive_lease_state":{"enum":["HELD_FOR_ATTEMPT_DECLARATION","HELD_FOR_PRE_REVIEW","HELD_FOR_ADMISSION_HANDOFF"]},"handoff_assignment_ordinal":{"enum":[3,4]}}},"prior":{"type":"object","additionalProperties":false,"required":["attempt_id","declaration","terminal_state","terminal_evidence"],"properties":{"attempt_id":{"type":"string","pattern":"^pfg3alr10try-[0-9a-f]{32}$"},"declaration":{"$ref":"#/$defs/file"},"terminal_state":{"enum":["SUPERSEDED_INCOMPLETE_SESSION","SUPERSEDED_INVALID_IMMUTABLE_OUTPUT","ADMITTED_RESUMABLE","SEMANTICALLY_ACCEPTED_TERMINAL"]},"terminal_evidence":{"type":"array","items":{"$ref":"#/$defs/file"}}}},"row":{"type":"object","additionalProperties":false,"required":["ordinal","path","state","native_identity","size_bytes","sha256","leaf_name","no_follow","stable","producer_assignment_sha256"],"properties":{"ordinal":{"type":"integer","minimum":0,"maximum":18},"path":{"type":"string","minLength":1},"state":{"enum":["PRESENT","ABSENT"]},"native_identity":{"$ref":"#/$defs/native"},"size_bytes":{"type":["integer","null"],"minimum":0},"sha256":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"},"leaf_name":{"type":"string","minLength":1},"no_follow":{"const":true},"stable":{"const":true},"producer_assignment_sha256":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"}}},"snapshot":{"type":"object","additionalProperties":false,"required":["probe_ordinal","rows","rows_sha256","complete_count"],"properties":{"probe_ordinal":{"type":"integer","minimum":0,"maximum":5},"rows":{"type":"array","minItems":19,"maxItems":19,"items":{"$ref":"#/$defs/row"}},"rows_sha256":{"$ref":"#/$defs/hex"},"complete_count":{"const":19}}},"part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}}}
```

### 9.3 Preimplementation review

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r10_preimplementation_review.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","record_id","canonical_path","attempt_id","subject","author_receipt","principal_roster","attempt_declaration","observer_pre_receipt","actor_binding","path_template_registry","path_template_registry_sha256","instantiated_path_membership_sha256","historical_evidence_catalog_sha256","check_registry_sha256","denominator_sha256","candidate_set_sha256","accepted_scope","rejected_scope","checks","findings","open_findings","failure_bindings","disposition","predecessor_evidence","part_0_genericity","authority_ceiling","record_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r10_preimplementation_review.v1"},"record_id":{"type":"string","pattern":"^pfg3alr10pre-[0-9a-f]{32}$"},"canonical_path":{"type":"string","minLength":1},"attempt_id":{"type":"string","pattern":"^pfg3alr10try-[0-9a-f]{32}$"},"subject":{"$ref":"#/$defs/file"},"author_receipt":{"$ref":"#/$defs/file"},"principal_roster":{"$ref":"#/$defs/file"},"attempt_declaration":{"$ref":"#/$defs/file"},"observer_pre_receipt":{"$ref":"#/$defs/file"},"actor_binding":{"$ref":"#/$defs/actor"},"path_template_registry":{"$ref":"#/$defs/registry"},"path_template_registry_sha256":{"$ref":"#/$defs/hex"},"instantiated_path_membership_sha256":{"$ref":"#/$defs/hex"},"historical_evidence_catalog_sha256":{"$ref":"#/$defs/hex"},"check_registry_sha256":{"$ref":"#/$defs/hex"},"denominator_sha256":{"$ref":"#/$defs/hex"},"candidate_set_sha256":{"$ref":"#/$defs/hex"},"accepted_scope":{"type":"array","minItems":2,"maxItems":2,"items":{"type":"string"}},"rejected_scope":{"type":"array","minItems":22,"maxItems":22,"items":{"type":"string"}},"checks":{"type":"array","minItems":28,"maxItems":28,"items":{"$ref":"#/$defs/check"}},"findings":{"type":"object","propertyNames":{"$ref":"#/$defs/id"},"additionalProperties":{"$ref":"#/$defs/finding"}},"open_findings":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"failure_bindings":{"type":"array","items":{"$ref":"#/$defs/failure"}},"disposition":{"enum":["PASS_R10_PREIMPLEMENTATION_OBSERVED_STOPPED_ONLY","REJECTED"]},"predecessor_evidence":{"type":"array","minItems":5,"items":{"$ref":"#/$defs/file"}},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"record_body_sha256":{"$ref":"#/$defs/hex"}},"$defs":{"hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"type":"string","minLength":1},"size_bytes":{"type":"integer","minimum":1},"sha256":{"$ref":"#/$defs/hex"}}},"registry":{"type":"object","additionalProperties":false,"required":["domain","entries"],"properties":{"domain":{"const":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R10_PATH_TEMPLATE_REGISTRY_V1"},"entries":{"type":"array","minItems":19,"maxItems":19,"items":{"$ref":"#/$defs/registry_row"}}}},"registry_row":{"type":"object","additionalProperties":false,"required":["ordinal","stage","kind","path_template"],"properties":{"ordinal":{"type":"integer","minimum":0,"maximum":18},"stage":{"enum":["STATIC_PRE_ATTEMPT_INPUT","ATTEMPT_PRE_REVIEW_INPUT","REVIEW_ATOMIC_OUTPUT","POST_REVIEW_PRE_ADMISSION_INPUT","PREIMPLEMENTATION_ADMISSION_OUTPUT","POST_ADMISSION_OUTPUT"]},"kind":{"type":"string","minLength":1},"path_template":{"type":"string","minLength":1}}},"native":{"type":"object","additionalProperties":false,"required":["os_family","identity_kind","identity_value"],"properties":{"os_family":{"enum":["WINDOWS","POSIX"]},"identity_kind":{"type":"string","minLength":1},"identity_value":{"type":"string","minLength":1}}},"actor":{"type":"object","additionalProperties":false,"required":["roster_file_sha256","roster_body_sha256","assignment_body_sha256","principal_ordinal","principal_id","role","task_id","process_instance_id","process_start_identity","workspace_identity","identity_claim"],"properties":{"roster_file_sha256":{"$ref":"#/$defs/hex"},"roster_body_sha256":{"$ref":"#/$defs/hex"},"assignment_body_sha256":{"$ref":"#/$defs/hex"},"principal_ordinal":{"const":3},"principal_id":{"type":"string","minLength":1},"role":{"const":"R10_INDEPENDENT_PREIMPLEMENTATION_REVIEWER"},"task_id":{"const":"g3-r10-preimplementation-reviewer"},"process_instance_id":{"type":"string","minLength":1},"process_start_identity":{"$ref":"#/$defs/native"},"workspace_identity":{"$ref":"#/$defs/native"},"identity_claim":{"const":"AUDITABLE_PROCESS_LABEL_ONLY_NOT_CRYPTOGRAPHIC_IDENTITY"}}},"check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"$ref":"#/$defs/id"},"result":{"enum":["PASS","FAIL"]},"evidence":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/file"}}}},"finding":{"type":"object","additionalProperties":false,"required":["severity","status","failed_checks","description","evidence"],"properties":{"severity":{"const":"BLOCKING"},"status":{"const":"OPEN"},"failed_checks":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"description":{"type":"string","minLength":1},"evidence":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/file"}}}},"failure":{"type":"object","additionalProperties":false,"required":["check_id","finding_ids"],"properties":{"check_id":{"$ref":"#/$defs/id"},"finding_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}}}},"part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}}}
```

The semantically governed `path_template_registry` must equal the literal closed
registry in section 5; schema `type:object` is not permission to extend it.

### 9.4 Independent preimplementation admission

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r10_preimplementation_admission.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","record_id","canonical_path","attempt_id","subject","principal_roster","attempt_declaration","observer_pre_receipt","preimplementation_review","observer_commit_receipt","actor_binding","session_id","checks","findings","open_findings","failure_bindings","disposition","accepted_scope","rejected_scope","predecessor_evidence","part_0_genericity","authority_ceiling","record_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r10_preimplementation_admission.v1"},"record_id":{"type":"string","pattern":"^pfg3alr10admit-[0-9a-f]{32}$"},"canonical_path":{"type":"string","minLength":1},"attempt_id":{"type":"string","pattern":"^pfg3alr10try-[0-9a-f]{32}$"},"subject":{"$ref":"#/$defs/file"},"principal_roster":{"$ref":"#/$defs/file"},"attempt_declaration":{"$ref":"#/$defs/file"},"observer_pre_receipt":{"$ref":"#/$defs/file"},"preimplementation_review":{"$ref":"#/$defs/file"},"observer_commit_receipt":{"$ref":"#/$defs/file"},"actor_binding":{"$ref":"#/$defs/actor"},"session_id":{"type":"string","pattern":"^pfg3alr10obs-[0-9a-f]{32}$"},"checks":{"type":"array","minItems":14,"maxItems":14,"items":{"$ref":"#/$defs/check"}},"findings":{"type":"object","propertyNames":{"$ref":"#/$defs/id"},"additionalProperties":{"$ref":"#/$defs/finding"}},"open_findings":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"failure_bindings":{"type":"array","items":{"$ref":"#/$defs/failure"}},"disposition":{"enum":["PASS_R10_PREIMPLEMENTATION_ADMISSION_FOR_STOPPED_GREEN_ONLY","REJECTED"]},"accepted_scope":{"type":"array","minItems":10,"maxItems":10,"items":{"type":"string"}},"rejected_scope":{"type":"array","minItems":14,"maxItems":14,"items":{"type":"string"}},"predecessor_evidence":{"type":"array","minItems":6,"items":{"$ref":"#/$defs/file"}},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"record_body_sha256":{"$ref":"#/$defs/hex"}},"$defs":{"hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"type":"string","minLength":1},"size_bytes":{"type":"integer","minimum":1},"sha256":{"$ref":"#/$defs/hex"}}},"native":{"type":"object","additionalProperties":false,"required":["os_family","identity_kind","identity_value"],"properties":{"os_family":{"enum":["WINDOWS","POSIX"]},"identity_kind":{"type":"string","minLength":1},"identity_value":{"type":"string","minLength":1}}},"actor":{"type":"object","additionalProperties":false,"required":["roster_file_sha256","roster_body_sha256","assignment_body_sha256","principal_ordinal","principal_id","role","task_id","process_instance_id","process_start_identity","workspace_identity","identity_claim"],"properties":{"roster_file_sha256":{"$ref":"#/$defs/hex"},"roster_body_sha256":{"$ref":"#/$defs/hex"},"assignment_body_sha256":{"$ref":"#/$defs/hex"},"principal_ordinal":{"const":4},"principal_id":{"type":"string","minLength":1},"role":{"const":"R10_INDEPENDENT_PREIMPLEMENTATION_ADMISSION_REVIEWER"},"task_id":{"const":"g3-r10-preimplementation-admission-reviewer"},"process_instance_id":{"type":"string","minLength":1},"process_start_identity":{"$ref":"#/$defs/native"},"workspace_identity":{"$ref":"#/$defs/native"},"identity_claim":{"const":"AUDITABLE_PROCESS_LABEL_ONLY_NOT_CRYPTOGRAPHIC_IDENTITY"}}},"check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"$ref":"#/$defs/id"},"result":{"enum":["PASS","FAIL"]},"evidence":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/file"}}}},"finding":{"type":"object","additionalProperties":false,"required":["severity","status","failed_checks","description","evidence"],"properties":{"severity":{"const":"BLOCKING"},"status":{"const":"OPEN"},"failed_checks":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"description":{"type":"string","minLength":1},"evidence":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/file"}}}},"failure":{"type":"object","additionalProperties":false,"required":["check_id","finding_ids"],"properties":{"check_id":{"$ref":"#/$defs/id"},"finding_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}}}},"part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}}}
```

### 9.5 Execution, GREEN, and independent GREEN validation

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r10_semantic_evidence.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","record_id","record_kind","canonical_path","attempt_id","subject","principal_roster","preimplementation_admission","actor_binding","candidate_set_sha256","denominator_sha256","artifact_lineage","result_tuples","summary","semantic_acceptance_confirmed","part_0_genericity","authority_ceiling","record_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r10_semantic_evidence.v1"},"record_id":{"type":"string","pattern":"^pfg3alr10(?:exec|green|gval)-[0-9a-f]{32}$"},"record_kind":{"enum":["EXECUTION_RECEIPT","GREEN_RECEIPT","GREEN_VALIDATION_RECEIPT"]},"canonical_path":{"type":"string","minLength":1},"attempt_id":{"type":"string","pattern":"^pfg3alr10try-[0-9a-f]{32}$"},"subject":{"$ref":"#/$defs/file"},"principal_roster":{"$ref":"#/$defs/file"},"preimplementation_admission":{"$ref":"#/$defs/file"},"actor_binding":{"$ref":"#/$defs/actor"},"candidate_set_sha256":{"$ref":"#/$defs/hex"},"denominator_sha256":{"$ref":"#/$defs/hex"},"artifact_lineage":{"type":"array","minItems":10,"items":{"$ref":"#/$defs/lineage"}},"result_tuples":{"type":"array","minItems":72,"maxItems":72,"items":{"$ref":"#/$defs/tuple"}},"summary":{"type":"object","additionalProperties":false,"required":["control_accept_count","mutation_reject_count","unexpected_accept_count","wrong_rejection_code_count","control_failure_count","process_exit"],"properties":{"control_accept_count":{"const":6},"mutation_reject_count":{"const":66},"unexpected_accept_count":{"const":0},"wrong_rejection_code_count":{"const":0},"control_failure_count":{"const":0},"process_exit":{"const":0}}},"semantic_acceptance_confirmed":{"const":false},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"record_body_sha256":{"$ref":"#/$defs/hex"}},"$defs":{"hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"type":"string","minLength":1},"size_bytes":{"type":"integer","minimum":1},"sha256":{"$ref":"#/$defs/hex"}}},"native":{"type":"object","additionalProperties":false,"required":["os_family","identity_kind","identity_value"],"properties":{"os_family":{"enum":["WINDOWS","POSIX"]},"identity_kind":{"type":"string","minLength":1},"identity_value":{"type":"string","minLength":1}}},"actor":{"type":"object","additionalProperties":false,"required":["roster_file_sha256","roster_body_sha256","assignment_body_sha256","principal_ordinal","principal_id","role","task_id","process_instance_id","process_start_identity","workspace_identity","identity_claim"],"properties":{"roster_file_sha256":{"$ref":"#/$defs/hex"},"roster_body_sha256":{"$ref":"#/$defs/hex"},"assignment_body_sha256":{"$ref":"#/$defs/hex"},"principal_ordinal":{"enum":[7,9]},"principal_id":{"type":"string","minLength":1},"role":{"enum":["R10_INDEPENDENT_RECEIPT_VALIDATOR_IMPLEMENTER","R10_GREEN_EXECUTOR"]},"task_id":{"enum":["g3-r10-independent-receipt-validator-implementer","g3-r10-green-executor"]},"process_instance_id":{"type":"string","minLength":1},"process_start_identity":{"$ref":"#/$defs/native"},"workspace_identity":{"$ref":"#/$defs/native"},"identity_claim":{"const":"AUDITABLE_PROCESS_LABEL_ONLY_NOT_CRYPTOGRAPHIC_IDENTITY"}}},"lineage":{"type":"object","additionalProperties":false,"required":["artifact","producer_assignment_sha256","producer_principal_id","producer_role","producer_task_id","predecessor_sha256s","independent_review"],"properties":{"artifact":{"$ref":"#/$defs/file"},"producer_assignment_sha256":{"$ref":"#/$defs/hex"},"producer_principal_id":{"type":"string","minLength":1},"producer_role":{"type":"string","minLength":1},"producer_task_id":{"type":"string","minLength":1},"predecessor_sha256s":{"type":"array","items":{"$ref":"#/$defs/hex"}},"independent_review":{"type":["object","null"],"additionalProperties":false,"required":["reviewer_assignment_sha256","review_artifact"],"properties":{"reviewer_assignment_sha256":{"$ref":"#/$defs/hex"},"review_artifact":{"$ref":"#/$defs/file"}}}}},"tuple":{"type":"object","additionalProperties":false,"required":["case_id","expected","observed","rejection_code","evidence_sha256"],"properties":{"case_id":{"type":"string","minLength":1},"expected":{"enum":["ACCEPT","REJECT"]},"observed":{"enum":["ACCEPT","REJECT"]},"rejection_code":{"type":["string","null"]},"evidence_sha256":{"$ref":"#/$defs/hex"}}},"part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}}}
```

Semantic validation fixes the actor ordinal/role/task joins by record kind:
execution and GREEN use ordinal 9; GREEN validation uses ordinal 7. The schema's
enumerations are necessary but not sufficient. `independent_review:null` is
allowed only for the record currently awaiting its distinct successor review;
every consumed predecessor must contain an exact review file reference.

### 9.6 Independent semantic acceptance

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r10_semantic_acceptance.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","record_id","canonical_path","attempt_id","subject","principal_roster","preimplementation_admission","execution_receipt","green_receipt","green_validation_receipt","actor_binding","artifact_lineage","checks","findings","open_findings","failure_bindings","disposition","aggregate_admission_authorized","part_0_genericity","authority_ceiling","record_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r10_semantic_acceptance.v1"},"record_id":{"type":"string","pattern":"^pfg3alr10accept-[0-9a-f]{32}$"},"canonical_path":{"type":"string","minLength":1},"attempt_id":{"type":"string","pattern":"^pfg3alr10try-[0-9a-f]{32}$"},"subject":{"$ref":"#/$defs/file"},"principal_roster":{"$ref":"#/$defs/file"},"preimplementation_admission":{"$ref":"#/$defs/file"},"execution_receipt":{"$ref":"#/$defs/file"},"green_receipt":{"$ref":"#/$defs/file"},"green_validation_receipt":{"$ref":"#/$defs/file"},"actor_binding":{"$ref":"#/$defs/actor"},"artifact_lineage":{"type":"array","minItems":16,"items":{"$ref":"#/$defs/lineage"}},"checks":{"type":"array","minItems":22,"maxItems":22,"items":{"$ref":"#/$defs/check"}},"findings":{"type":"object","propertyNames":{"$ref":"#/$defs/id"},"additionalProperties":{"$ref":"#/$defs/finding"}},"open_findings":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"failure_bindings":{"type":"array","items":{"$ref":"#/$defs/failure"}},"disposition":{"enum":["PASS_R10_SEMANTIC_CLOSURE_FOR_STOPPED_PART0_ONLY","REJECTED"]},"aggregate_admission_authorized":{"const":false},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"record_body_sha256":{"$ref":"#/$defs/hex"}},"$defs":{"hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"type":"string","minLength":1},"size_bytes":{"type":"integer","minimum":1},"sha256":{"$ref":"#/$defs/hex"}}},"native":{"type":"object","additionalProperties":false,"required":["os_family","identity_kind","identity_value"],"properties":{"os_family":{"enum":["WINDOWS","POSIX"]},"identity_kind":{"type":"string","minLength":1},"identity_value":{"type":"string","minLength":1}}},"actor":{"type":"object","additionalProperties":false,"required":["roster_file_sha256","roster_body_sha256","assignment_body_sha256","principal_ordinal","principal_id","role","task_id","process_instance_id","process_start_identity","workspace_identity","identity_claim"],"properties":{"roster_file_sha256":{"$ref":"#/$defs/hex"},"roster_body_sha256":{"$ref":"#/$defs/hex"},"assignment_body_sha256":{"$ref":"#/$defs/hex"},"principal_ordinal":{"const":10},"principal_id":{"type":"string","minLength":1},"role":{"const":"R10_INDEPENDENT_SEMANTIC_ACCEPTANCE_REVIEWER"},"task_id":{"const":"g3-r10-semantic-acceptance-reviewer"},"process_instance_id":{"type":"string","minLength":1},"process_start_identity":{"$ref":"#/$defs/native"},"workspace_identity":{"$ref":"#/$defs/native"},"identity_claim":{"const":"AUDITABLE_PROCESS_LABEL_ONLY_NOT_CRYPTOGRAPHIC_IDENTITY"}}},"lineage":{"type":"object","additionalProperties":false,"required":["artifact","producer_assignment_sha256","producer_principal_id","producer_role","producer_task_id","predecessor_sha256s","independent_replay_sha256"],"properties":{"artifact":{"$ref":"#/$defs/file"},"producer_assignment_sha256":{"$ref":"#/$defs/hex"},"producer_principal_id":{"type":"string","minLength":1},"producer_role":{"type":"string","minLength":1},"producer_task_id":{"type":"string","minLength":1},"predecessor_sha256s":{"type":"array","items":{"$ref":"#/$defs/hex"}},"independent_replay_sha256":{"$ref":"#/$defs/hex"}}},"check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"$ref":"#/$defs/id"},"result":{"enum":["PASS","FAIL"]},"evidence":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/file"}}}},"finding":{"type":"object","additionalProperties":false,"required":["severity","status","failed_checks","description","evidence"],"properties":{"severity":{"const":"BLOCKING"},"status":{"const":"OPEN"},"failed_checks":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"description":{"type":"string","minLength":1},"evidence":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/file"}}}},"failure":{"type":"object","additionalProperties":false,"required":["check_id","finding_ids"],"properties":{"check_id":{"$ref":"#/$defs/id"},"finding_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}}}},"part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}}}
```

The exact 22 acceptance checks are:

```text
ALR10A-01-SUBJECT-ROSTER-ADMISSION-EXACT
ALR10A-02-ATTEMPT-CHAIN-AND-OBSERVER-PAIR-EXACT
ALR10A-03-PREIMPLEMENTATION-ADMISSION-PRECEDES-CODE
ALR10A-04-SIX-RENDERED-SCHEMAS-EXACT
ALR10A-05-PRIMARY-AND-RECEIPT-VALIDATORS-DISTINCT
ALR10A-06-HARNESS-AND-EXECUTOR-DISTINCT
ALR10A-07-SIX-CONTROLS-ACCEPT
ALR10A-08-SIXTY-SIX-MUTATIONS-REJECT-EXACT-CODES
ALR10A-09-ORACLE-INDEPENDENTLY-RECONSTRUCTED
ALR10A-10-EXECUTION-RECEIPT-IDENTITY-EXACT
ALR10A-11-GREEN-RECEIPT-SEMANTICS-EXACT
ALR10A-12-GREEN-VALIDATION-RECEIPT-EXACT
ALR10A-13-CANDIDATE-DENOMINATOR-REGISTRY-EXACT
ALR10A-14-ACTOR-ROLE-PRINCIPAL-TASK-JOINS-EXACT
ALR10A-15-PROCESS-OCCURRENCES-DISTINCT-ON-REVIEW-EDGES
ALR10A-16-ARTIFACT-BYTES-AND-PREDECESSOR-JOINS-EXACT
ALR10A-17-INDEPENDENT-REPLAY-EVIDENCE-EXACT
ALR10A-18-NO-PER-ROLE-SECRET-DEPENDENCY
ALR10A-19-NO-CRYPTOGRAPHIC-IDENTITY-OVERCALL
ALR10A-20-NO-SELF-CERTIFICATION
ALR10A-21-PART0-AUTHORITY-EXACT
ALR10A-22-STOP-BEFORE-G3-00-AGGREGATE
```

PASS/REJECTED uses the exact binary totality and inverse-finding join from
section 7. Even PASS sets `aggregate_admission_authorized:false`.

## 10. Mandatory independent validators and replay

The primary validator is pure/offline and accepts no optional `path_states` or
identity override. It takes authenticated contract, roster, attempt records,
review/admission, and explicit record kind. It must:

1. reject duplicate JSON members, BOM, non-LF, non-NFC, unknown fields/enums,
   nonlocal refs, invalid path templates, and schema-invalid records;
2. parse every literal contract block and recompute all hashes;
3. authenticate the r7/r8/r9 catalog, exact r9 architecture `ACCEPT`, exact r9
   operational `REPAIR; ROUTE_UNINHABITABLE`, and r9 roster negative;
4. enforce exact check/scope/evidence arrays and inverse finding joins;
5. verify roster transport integrity but reject any use of it as actor identity;
6. enforce all assignment/projection/roster formulas in their stated order;
7. validate attempt enumeration, unique predecessor chain, native lease,
   observer snapshots, no-follow stable reads, stage states, and resume rules;
8. validate actor assignment, task, process occurrence, artifact byte, ordered
   predecessor, and distinct-reviewer joins without requiring role secrets;
9. reconstruct the 72-case oracle from this contract; and
10. never write, render, repair, import production, or infer authority.

The independent GREEN receipt validator is a separate file, task, principal
label, process occurrence, source tree, and execution. It must not import the
primary validator or harness. It independently parses this contract,
reconstructs all 72 expected tuples, authenticates exact artifact bytes and
producer/predecessor joins, recomputes every ID/body/summary, and emits the
GREEN-validation record. Shared standard-library JSON, SHA-256, path, and
Ed25519 verification primitives are permitted. Shared audit-specific helpers,
generated constants, or expected-value imports are forbidden.

Independent replay means recomputation from frozen contract literals and exact
artifact bytes by the assigned reviewer process occurrence. Distinct labels are
not enough: the reviewer process-instance ID must differ from every producer it
reviews, its task/role/assignment must be the exact reviewer assignment, and the
observer must capture the occurrence. These are auditable evidence constraints,
not cryptographic proof that humans or organizations did not collude.

## 11. Exact review-before-code DAG and liveness state machine

Each successful attempt instantiates exactly 28 nodes and 43 edges:

```text
R10N00 R9_ACCEPT_AND_OPERATIONAL_REPAIR_PARENTS
R10N01 R10_CORRECTION_CONTRACT
R10N02 R10_AUTHOR_RECEIPT
R10N03 R10_BOUND_PROCESS_ROSTER
R10N04 ROOT_LEASE_AND_ATTEMPT_ENUMERATION
R10N05 R10_ATTEMPT_DECLARATION
R10N06 R10_OBSERVER_PRE_RECEIPT
R10N07 R10_PREIMPLEMENTATION_REVIEW
R10N08 R10_OBSERVER_COMMIT_RECEIPT
R10N09 R10_PREIMPLEMENTATION_ADMISSION_PASS
R10N10 R10_ROSTER_SCHEMA_RENDER
R10N11 R10_OBSERVATION_SCHEMA_RENDER
R10N12 R10_PRE_REVIEW_SCHEMA_RENDER
R10N13 R10_ADMISSION_SCHEMA_RENDER
R10N14 R10_SEMANTIC_EVIDENCE_SCHEMA_RENDER
R10N15 R10_ACCEPTANCE_SCHEMA_RENDER
R10N16 R10_PRIMARY_SEMANTIC_VALIDATOR
R10N17 R10_INDEPENDENT_RECEIPT_VALIDATOR
R10N18 R10_GREEN_HARNESS
R10N19 BOUND_R10_GREEN_EXECUTION
R10N20 R10_EXECUTION_RECEIPT
R10N21 R10_GREEN_RECEIPT
R10N22 INDEPENDENT_GREEN_RECEIPT_VALIDATION_EXECUTION
R10N23 R10_GREEN_VALIDATION_RECEIPT
R10N24 R10_INDEPENDENT_SEMANTIC_ACCEPTANCE_REVIEW
R10N25 R10_STOP_BEFORE_G3_00_AGGREGATE
R10N26 FROZEN_R10_DENOMINATOR
R10N27 APPEND_ONLY_PREDECESSOR_ATTEMPT_CHAIN

R10N00->R10N01
R10N26->R10N01
R10N01->R10N02
R10N01->R10N03
R10N02->R10N03
R10N03->R10N04
R10N27->R10N04
R10N04->R10N05
R10N05->R10N06
R10N06->R10N07
R10N07->R10N08
R10N08->R10N09
R10N09->R10N10
R10N09->R10N11
R10N09->R10N12
R10N09->R10N13
R10N09->R10N14
R10N09->R10N15
R10N09->R10N16
R10N09->R10N17
R10N09->R10N18
R10N10->R10N19
R10N11->R10N19
R10N12->R10N19
R10N13->R10N19
R10N14->R10N19
R10N15->R10N19
R10N16->R10N19
R10N17->R10N19
R10N18->R10N19
R10N19->R10N20
R10N20->R10N21
R10N17->R10N22
R10N21->R10N22
R10N22->R10N23
R10N20->R10N24
R10N21->R10N24
R10N23->R10N24
R10N09->R10N24
R10N05->R10N24
R10N24->R10N25
R10N00->R10N26
R10N00->R10N27
```

All render/code/harness nodes require admission PASS. STOP has no outgoing
edge. Missing/rejected nodes authorize nothing.

On loss before R10N09, the current attempt is an immutable incomplete branch;
a new lease instantiates a new R10N05 whose declaration binds it through N27.
On loss after N09, exact existing outputs may be replayed and the first absent
node created. An invalid existing output forces a successor attempt; overwrite
is forbidden. Native lease serialization and full enumeration prevent two
accepted heads. No transition requires an ephemeral role secret.

## 12. Author validation and bounded handoff

Before handoff the author must:

1. reauthenticate all five requested r9 files at section-1 hashes and preserve
   the formula `ACCEPT`/operational `REPAIR` scope distinction;
2. parse every JSON fence with duplicate-member rejection;
3. validate all six schema roots under Draft 2020-12 and resolve all
   fragment-local refs with zero external or unresolved refs;
4. confirm recursive closure of every governed fixed object and binary checks;
5. recompute catalog, trust, assignment, path-template, observer, check,
   denominator, six schema, and candidate-set hashes;
6. confirm exactly 14 historical entries, 11 assignments, 19 path templates,
   28 review checks, 14 admission checks, six controls, 66 mutations, 22
   acceptance checks, and 72 result tuples;
7. confirm 55 principal, 55 task, and 385 cross-prior comparisons and the exact
   eight-field non-self projection preimage;
8. prove the 28-node/43-edge graph unique, endpoint-closed, acyclic, and terminal
   at STOP;
9. confirm all authority keys false, exact Part-0, no protocol names, no
   per-role keys/signatures, and no cryptographic identity overcall; and
10. observe that no r10 roster or instantiated r10 attempt path exists at author
    time.

Only an independent architecture review may follow. Even architecture ACCEPT
would authorize no roster. Roster binding, attempt creation, observer capture,
review, admission, schemas, code, execution, GREEN, semantic acceptance,
aggregate admission, G3-01, production, runtime, provider, package, install,
release, cutover, commit, and push remain absent and unauthorized.
