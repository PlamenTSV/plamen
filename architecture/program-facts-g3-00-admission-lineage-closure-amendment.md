# Program Facts G3-00 admission-lineage closure amendment r2

Status: `CONTRACT_ONLY_PENDING_FRESH_INDEPENDENT_R2_REVIEW`

This Part-0 amendment closes only three missing joins in the Program Facts
Gate-3 construction graph:

1. the schema-parity CROSSCHECK lineage selects the eventual accepted
   canonical stdlib cross-check v3 source and adoption marker v4, rather than
   treating the launcher contract's historical v2 source pin as admissible;
2. successor public-v3 and compact-seed reviews have immutable versioned paths
   and schemas, rather than overwriting their frozen v1 receipts; and
3. the native-host evidence, live schema-contract promotion, G3-00 aggregate,
   and later G3-01 adoption joins have exact paths, schemas, authority ceilings,
   and an acyclic order.

It creates no schema, fixture, receipt, process, vector, promotion, admission,
implementation, runtime, provider, audit, package, release, commit, push,
cutover, finding, severity, confidence, refutation, suppression, or terminal-
negative authority. Every artifact named below is future work unless it already
exists as an immutable predecessor. This document never predicts a future
artifact's size, digest, content-derived ID, or reviewer principal.

## 0. Precedence, immutable debt, and closed scope

The following contracts remain read-only predecessors. A later independently
accepted identity for either pending contract is consumed through the typed
late-bound mechanism in section 3; no digest is guessed here.

| Contract | Governing scope in this amendment |
|---|---|
| `architecture/program-facts-runtime-cutover-spec.md` | PF-R2 lifecycle and authority floor |
| `architecture/program-facts-g3-00-schema-closure-amendment.md` | 12-subject schema denominator and aggregate semantics, as narrowly superseded in sections 4, 8, and 10 |
| `architecture/program-facts-g3-00-schema-vector-clarification-amendment.md` | parity values, schema-vector semantics, and G1/G2 distinction |
| `architecture/program-facts-g3-00-parity-launcher-runtime-closure-amendment.md` | launcher/runtime/native execution contract, as narrowly superseded in sections 5, 6, and 10 |
| `architecture/program-facts-g3-00-stdlib-crosscheck-v3-recovery-amendment.md` | canonical source v3 and adoption-marker v4 construction chain and native publication profile |
| `architecture/program-facts-g3-01-construction-amendment.md` | G3-01 construction, as narrowly superseded in sections 9 and 10 |

All frozen v1/v2 receipts, failed bindings, failed wrappers, observations,
reviews, source copies, and canonical paths remain historical debt. In
particular, none of the following is overwritten, aliased, reinterpreted, or
silently substituted:

```text
review_fixtures/program_facts_runtime_gate3/architecture/PROGRAM_FACTS_PUBLIC_V3_AMENDMENT_INDEPENDENT_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/seed/PROGRAM_FACTS_R19_COMPACT_SEED_ADMISSION_INDEPENDENT_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SUBJECT_BINDING.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SUBJECT_BINDING.v2.json
```

Content equality, a matching disposition string, a matching basename, working-
tree presence, chronological recency, or a model's statement never upgrades
historical debt. The only valid successor relation is the typed, schema-valid,
published, independently reviewed lineage specified below.

If this amendment and a predecessor permit two readings, the reading with less
authority and more explicit evidence wins. The only supersessions are the exact
ones listed in section 10. All other predecessor requirements remain additive.

## 1. Canonical bytes, common primitives, and authority

`CJ(x)` is RFC-8785 canonical JSON encoded as UTF-8. `CF(x) = CJ(x) || 0x0a`.
All governed JSON rejects duplicate keys, BOM, CR, invalid UTF-8, non-finite
numbers, unsafe integers, unknown members, noncanonical escapes, and trailing
bytes other than the one required LF. Every path is repository-relative,
forward-slash separated, NFC, exact-case, and drawn from the closed registry in
section 2. A path is not an identity.

The exact common primitives are:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_common.v1.schema.json",
  "$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/validation":true},
  "$defs":{
    "hex64":{"type":"string","minLength":64,"maxLength":64,"pattern":"^[0-9a-f]{64}$"},
    "safe_path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},
    "identifier":{"type":"string","minLength":1,"maxLength":256,"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},
    "file_identity":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/safe_path"},"size_bytes":{"type":"integer","minimum":0,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex64"}}},
    "z20":{"type":"string","minLength":20,"maxLength":20,"pattern":"^[0-9]{20}$"},
    "legacy_accepted_ref":{"type":"object","additionalProperties":false,"required":["reference_kind","artifact","acceptance_evidence","stable_read_count","retroactive_completion_claimed"],"properties":{"reference_kind":{"const":"IMMUTABLE_ACCEPTED_LEGACY_IDENTITY"},"artifact":{"$ref":"#/$defs/file_identity"},"acceptance_evidence":{"type":"array","minItems":1,"maxItems":32,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}},"stable_read_count":{"const":3},"retroactive_completion_claimed":{"const":false}}},
    "file_published_ref":{"type":"object","additionalProperties":false,"required":["reference_kind","transport"],"properties":{"reference_kind":{"const":"NEW_FILE_PUBLICATION"},"transport":{"type":"object","additionalProperties":false,"required":["artifact","attempt_ordinal","completion_grade","publication_arm","publication_completion"],"properties":{"artifact":{"$ref":"#/$defs/file_identity"},"attempt_ordinal":{"$ref":"#/$defs/z20"},"completion_grade":{"enum":["LIVE_REVIEWED_EXECUTION","CRASH_RECOVERED_UNIQUE_POSTSTATE"]},"publication_arm":{"$ref":"#/$defs/file_identity"},"publication_completion":{"$ref":"#/$defs/file_identity"}}}}},
    "directory_root_identity":{"type":"object","additionalProperties":false,"required":["path","member_count","directory_count","member_tree_sha256","native_root_identity_sha256"],"properties":{"path":{"$ref":"#/$defs/safe_path"},"member_count":{"type":"integer","minimum":1,"maximum":100000},"directory_count":{"type":"integer","minimum":1,"maximum":100000},"member_tree_sha256":{"$ref":"#/$defs/hex64"},"native_root_identity_sha256":{"$ref":"#/$defs/hex64"}}},
    "directory_published_root_ref":{"type":"object","additionalProperties":false,"required":["reference_kind","root","internal_root_manifest","directory_transport_completion","independent_promotion_review"],"properties":{"reference_kind":{"const":"ATOMIC_DIRECTORY_ROOT_PUBLICATION"},"root":{"$ref":"#/$defs/directory_root_identity"},"internal_root_manifest":{"$ref":"#/$defs/file_identity"},"directory_transport_completion":{"$ref":"#/$defs/file_published_ref"},"independent_promotion_review":{"$ref":"#/$defs/file_published_ref"}}},
    "governed_ref":{"oneOf":[{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/file_published_ref"},{"$ref":"#/$defs/directory_published_root_ref"}]},
    "published_ref":{"$ref":"#/$defs/file_published_ref"},
    "principal":{"type":"object","additionalProperties":false,"required":["principal_id","organization","role"],"properties":{"principal_id":{"type":"string","minLength":12,"maxLength":256,"pattern":"^(author|builder|executor|reviewer|validator|promoter|resolver|adopter):[a-z0-9-]+/[a-z0-9-]+$"},"organization":{"type":"string","minLength":1,"maxLength":256},"role":{"type":"string","minLength":1,"maxLength":256}}},
    "check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"$ref":"#/$defs/identifier"},"result":{"enum":["PASS","FAIL"]},"evidence":{"type":"array","minItems":1,"maxItems":100000,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}}}},
    "pass_check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"$ref":"#/$defs/identifier"},"result":{"const":"PASS"},"evidence":{"type":"array","minItems":1,"maxItems":100000,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}}}},
    "review_vector":{"type":"object","additionalProperties":false,"required":["vector_id","result","evidence"],"properties":{"vector_id":{"$ref":"#/$defs/identifier"},"result":{"enum":["PASS","FAIL"]},"evidence":{"type":"array","minItems":1,"maxItems":100000,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}}}},
    "finding":{"type":"object","additionalProperties":false,"required":["finding_id","severity","status","description","evidence"],"properties":{"finding_id":{"$ref":"#/$defs/identifier"},"severity":{"enum":["BLOCKING","NONBLOCKING"]},"status":{"enum":["OPEN","CLOSED"]},"description":{"type":"string","minLength":1,"maxLength":8192},"evidence":{"type":"array","minItems":1,"maxItems":100000,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}}}},
    "part0":{"type":"object","const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},
    "authority":{"type":"object","const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}},
    "publication_requirements":{"type":"object","const":{"complete_candidate_before_stage_write":true,"content_equality_adoption":false,"direct_final_write":false,"directory_scan":false,"final_collision_terminal":true,"hard_link_publication":false,"no_replace_atomic_rename":true,"parent_and_stage_same_volume":true,"parent_handle_retained":true,"pathless_identity_preserved":true,"registered_paths_only":true,"silent_backfill":false,"stage_and_final_same_parent":true,"unsupported_host_fails_before_edge_paths_touched":true}}
  }
}
```

The `authority` object has exactly 29 members and every value is false. It is
copied into every governed artifact. A narrower accepted-scope string does not
turn any false bit true. A publication completion proves transport only; it
does not prove semantic correctness or grant authority.

The three reference branches are disjoint. `legacy_accepted_ref` never has a
publication arm/completion; its acceptance evidence is contemporaneous frozen
evidence and no later artifact may backfill transport history.
`file_published_ref` is only for a new file created under the accepted r2
arm-bound publication profile. Its `transport` member is byte-for-byte the
accepted crosscheck-v3-r2 `published_ref` value; `reference_kind` is only the
closed-union discriminator and is not injected into or substituted for that
transport value. `directory_published_root_ref` is only for the
atomic root protocol in section 15.6 and cannot be substituted by 25 loose file
references. The short name `published_ref` is retained solely so the rejected
5c600182 candidate schema blocks remain mechanically parseable; it aliases
`file_published_ref` and is forbidden in every normative successor root in
section 15.

### 1.1 Exact ordered review and check rosters

JSON Schema fixes each array's exact length and row shape. Semantic validation
additionally requires `check_id` or `vector_id` to equal the corresponding
ordered roster below, with no duplicate, omission, substitution, or reordering:

```text
LATE_BOUND_REFERENCE_CHECKS =
  LBR-01-CONTRACT-REVIEW-PASS
  LBR-02-ALL-FIFTEEN-PUBLICATIONS
  LBR-03-SOURCE-V3-EXACT
  LBR-04-MARKER-V4-EXACT
  LBR-05-SOURCE-MARKER-JOIN
  LBR-06-TERMINAL-DEBT-NONENABLING
  LBR-07-RESOLVER-INDEPENDENCE
  LBR-08-AUTHORITY-ALL-FALSE

PUBLIC_V3_VECTORS =
  ARCH-V3-01-CLOSED-PUBLIC-SCHEMAS
  ARCH-V3-02-SOURCE-BINDING-GROUP
  ARCH-V3-03-PROVIDER-REGISTRY-CROSS-REFERENCES
  ARCH-V3-04-OWNERSHIP-V1-TO-V2
  ARCH-V3-05-COMPATIBILITY-DISPATCH
  ARCH-V3-06-AUTHORITY-ALL-FALSE
  ARCH-V3-07-IMMUTABLE-SUCCESSOR-LINEAGE

COMPACT_SEED_VECTORS =
  SEED-ADM-01-EXTERNAL-DIGEST-LINK
  SEED-ADM-02-RUNTIME-READ-FORBIDDEN
  SEED-ADM-03-AUTHORITY-CEILING
  SEED-ADM-04-SUBJECT-AND-INPUT-IDENTITIES
  SEED-ADM-05-INDEPENDENCE
  SEED-ADM-06-IMMUTABLE-SUCCESSOR-LINEAGE

NATIVE_HOST_CHECKS =
  NHR-01-HOST-PROFILE-EXACT
  NHR-02-RUNTIME-CLOSURE-EXACT
  NHR-03-SUBJECT-BINDING-EXACT
  NHR-04-ENTRY-BIJECTION
  NHR-05-SOURCE-DELIVERY
  NHR-06-PEER-DENIAL
  NHR-07-NETWORK-FILESYSTEM-CONFINEMENT
  NHR-08-CHILD-PROCESS-DENIAL
  NHR-09-HANDLE-ALLOWLIST
  NHR-10-BOOTSTRAP-PROTOCOL
  NHR-11-QUARANTINE-MOVE-PROFILE
  NHR-12-INDEPENDENCE-NONAUTHORITY

PRE_AGGREGATE_V2_CHECKS =
  LIN2-01-LEGACY-REQUIREMENT-PROJECTIONS
  LIN2-02-V2-COMPLETION-CHAINS
  LIN2-03-EXACT-PARITY-PROJECTION
  LIN2-04-CROSSCHECK-V3-LATE-BOUND-PAIR
  LIN2-05-CROSSCHECK-V4-MARKER-JOIN
  LIN2-06-FOUR-NATIVE-HOST-RECEIPTS
  LIN2-07-LAUNCHER-GREEN-CHAIN
  LIN2-08-ACYCLIC-PUBLICATION
  LIN2-09-NONAUTHORITY-INDEPENDENCE

PROMOTION_CHECKS =
  SCP-01-ROSTER-12
  SCP-02-TRIPLETS-12
  SCP-03-VECTOR-REPLAY
  SCP-04-COVERAGE-BIJECTION
  SCP-05-PER-SCHEMA-INDEPENDENCE
  SCP-06-PRE-AGGREGATE-V2
  SCP-07-CROSSCHECK-V3-V4
  SCP-08-ROOT-CENSUS
  SCP-09-NATIVE-NOREPLACE-PUBLICATION
  SCP-10-NONAUTHORITY-INDEPENDENCE

AGGREGATE_V2_CHECKS =
  G3A2-01-PREDECESSOR-LINEAGE
  G3A2-02-CARRIER-TEMPLATE-EQUALITY
  G3A2-03-SCHEMA-DENOMINATOR-12
  G3A2-04-PROVIDER-REGISTRY-V2
  G3A2-05-PHASE-IO-RACI-OPERATION-ORDER
  G3A2-06-SCHEMA-DRAFT-VOCABULARY-CLOSURE
  G3A2-07-VECTOR-RESULT-REPLAY
  G3A2-08-BIDIRECTIONAL-KEYWORD-ATOM-COVERAGE
  G3A2-09-PER-SCHEMA-REVIEW-INDEPENDENCE
  G3A2-10-CROSSCHECK-V3-V4-LATE-BOUND
  G3A2-11-NATIVE-HOST-RECEIPT-FAMILY
  G3A2-12-PRE-AGGREGATE-V2
  G3A2-13-PROMOTION-LINEAGE
  G3A2-14-SUCCESSOR-REVIEW-LINEAGE
  G3A2-15-AUTHORITY-AND-REVIEWER-INDEPENDENCE

G3_01_ADOPTION_CHECKS =
  ADOPT-01-G3-00-MANIFEST-V2
  ADOPT-02-G3-00-AGGREGATE-REVIEW-V2
  ADOPT-03-PROMOTION-LINEAGE
  ADOPT-04-PRE-AGGREGATE-LINEAGE-V2
  ADOPT-05-CROSSCHECK-V3-V4
  ADOPT-06-SUCCESSOR-REVIEWS-V2
  ADOPT-07-G3-01-AMENDMENT-STABLE
  ADOPT-08-ACYCLIC-NO-PREDICTION
  ADOPT-09-INDEPENDENCE-NONAUTHORITY

AMENDMENT_REVIEW_CHECKS =
  ALR-01-PARENT-PINS
  ALR-02-IMMUTABLE-DEBT
  ALR-03-LATE-BOUND-CROSSCHECK
  ALR-04-VERSIONED-SUCCESSOR-REVIEWS
  ALR-05-NATIVE-HOST-RECEIPT-SPLIT
  ALR-06-PRE-AGGREGATE-V2
  ALR-07-PROMOTION-LINEAGE
  ALR-08-ADMISSION-V2
  ALR-09-G3-01-ACYCLIC-ADOPTION
  ALR-10-NATIVE-PUBLICATION-PROFILE-REUSE
  ALR-11-SCHEMA-REFERENCE-CLOSURE
  ALR-12-FIXTURE-FIRST-DENOMINATOR
  ALR-13-AUTHORITY-INDEPENDENCE-PART0
```

## 2. Exact path and schema registry

The amendment path is exactly:

```text
architecture/program-facts-g3-00-admission-lineage-closure-amendment.md
```

After an independent amendment review passes, the schema builder may create
exactly these self-contained Draft-2020-12 schema files for this closure:

```text
rules/schemas/program_facts_g3_00_admission_lineage_closure_amendment_review.v1.schema.json
rules/schemas/program_facts_g3_00_late_bound_reference.v1.schema.json
rules/schemas/program_facts_public_v3_architecture_review.v2.schema.json
rules/schemas/program_facts_r19_compact_seed_admission_review.v2.schema.json
rules/schemas/program_facts_parity_native_host_receipt.v1.schema.json
rules/schemas/program_facts_parity_pre_aggregate_lineage.v2.schema.json
rules/schemas/program_facts_g3_00_schema_contract_promotion_lineage.v1.schema.json
rules/schemas/program_facts_g3_00_admission_manifest.v2.schema.json
rules/schemas/program_facts_g3_00_aggregate_review.v2.schema.json
rules/schemas/program_facts_g3_01_adoption_lineage.v1.schema.json
```

Each rendered schema has the common `$defs` from section 1 copied in full,
contains exactly one root from sections 3-9, has no remote `$ref`, and uses the
literal `$id` `https://plamen.local/schemas/<basename>`. The renderer performs
only that mechanical copy/substitution and emits `CF`; it may not widen a type,
enum, bound, path, or authority object.

The file/root/version mapping is exact:

| Schema basename | Root section | Instance `schema_version` |
|---|---:|---|
| `program_facts_g3_00_admission_lineage_closure_amendment_review.v1.schema.json` | 13 | `plamen.program_facts_g3_00_admission_lineage_closure_amendment_review.v1` |
| `program_facts_g3_00_late_bound_reference.v1.schema.json` | 3 | `plamen.program_facts_g3_00_late_bound_reference.v1` |
| `program_facts_public_v3_architecture_review.v2.schema.json` | 4.1 | `plamen.program_facts_public_v3_architecture_review.v2` |
| `program_facts_r19_compact_seed_admission_review.v2.schema.json` | 4.2 | `plamen.program_facts_r19_compact_seed_admission_review.v2` |
| `program_facts_parity_native_host_receipt.v1.schema.json` | 5 | `plamen.program_facts_parity_native_host_receipt.v1` |
| `program_facts_parity_pre_aggregate_lineage.v2.schema.json` | 6 | `plamen.program_facts_g3_00_parity_pre_aggregate_lineage.v2` |
| `program_facts_g3_00_schema_contract_promotion_lineage.v1.schema.json` | 7 | `plamen.program_facts_g3_00_schema_contract_promotion_lineage.v1` |
| `program_facts_g3_00_admission_manifest.v2.schema.json` | 8.1 | `plamen.program_facts_g3_00_admission_manifest.v2` |
| `program_facts_g3_00_aggregate_review.v2.schema.json` | 8.2 | `plamen.program_facts_g3_00_aggregate_review.v2` |
| `program_facts_g3_01_adoption_lineage.v1.schema.json` | 9 | `plamen.program_facts_g3_01_adoption_lineage.v1` |

The immutable semantic artifact paths are:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_CLOSURE_AMENDMENT_INDEPENDENT_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/STDLIB_CROSSCHECK_V3_ADMISSION_REFERENCE.v1.json
review_fixtures/program_facts_runtime_gate3/architecture/PROGRAM_FACTS_PUBLIC_V3_AMENDMENT_INDEPENDENT_REVIEW.v2.json
review_fixtures/program_facts_runtime_gate3/seed/PROGRAM_FACTS_R19_COMPACT_SEED_ADMISSION_INDEPENDENT_REVIEW.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_native_host/PROGRAM_FACTS_G3_00_PARITY_NATIVE_HOST_RECEIPT_VECTOR_CAPTURE.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_native_host/PROGRAM_FACTS_G3_00_PARITY_NATIVE_HOST_RECEIPT_GENERATOR.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_native_host/PROGRAM_FACTS_G3_00_PARITY_NATIVE_HOST_RECEIPT_EVALUATOR.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_native_host/PROGRAM_FACTS_G3_00_PARITY_NATIVE_HOST_RECEIPT_CROSSCHECK.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_V3_PRE_AGGREGATE_LINEAGE.v2.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/PROGRAM_FACTS_G3_00_SCHEMA_CONTRACT_PROMOTION_LINEAGE.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00/PROGRAM_FACTS_G3_00_ADMISSION_MANIFEST.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00/PROGRAM_FACTS_G3_00_ADMISSION_MANIFEST_INDEPENDENT_REVIEW.v2.json
review_fixtures/program_facts_runtime_gate3/construction/PROGRAM_FACTS_G3_01_ADOPTION_LINEAGE.v1.json
```

No v1 canonical path is repurposed. The `schema_contracts_v2/` root is a fresh
generation root; it never replaces or merges loose files under the historical
`schema_contracts/` root. Every future artifact and its publication sidecars
are registered before construction. No glob, directory enumeration, newest-
file selection, suffix probing, timestamp, random name, PID, UUID, backup name,
or alternate path is permitted.

### 2.1 Native publication profile reuse

This amendment does not invent another filesystem transaction protocol. Every
new semantic artifact above is published using section 6, **Exact complete-
candidate publication protocol**, of
`architecture/program-facts-g3-00-stdlib-crosscheck-v3-recovery-amendment.md`,
including its host-specific Windows `FileRenameInfoEx` no-replace, Linux
`renameat2(...,RENAME_NOREPLACE)`, and macOS
`renameatx_np|renamex_np(...,RENAME_EXCL)` branches, stable parent handle,
same-parent/same-volume staging, pathless identity continuity, intent/prepared/
completion records, durability barriers, collision rules, and unsupported-host
failure. For each path in section 2, the future path-registry amendment assigns
the same seven deterministic same-parent sidecar leaves and a unique edge key.
That finite path expansion must be independently reviewed before the first
write. Until that accepted expansion exists, all paths in this section remain
write-forbidden.

A dependent references a new artifact only as a `published_ref` and validates
both the final and publication completion. The dependent then independently
reopens and validates the semantic artifact. Publication never self-certifies.

## 3. Typed late-bound cross-check admission reference

The canonical v3 source and v4 adoption marker do not exist merely because
their paths are specified. They become eligible only after the complete
crosscheck-v3 recovery DAG has been published and independently validated. The
single late-bound reference path in section 2 resolves that pair after, never
before, valid predecessor publication.

The exact root schema is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","reference_id","reference_kind","governing_contract","governing_contract_review","required_targets","resolved_targets","resolver","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","reference_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_late_bound_reference.v1"},
    "reference_id":{"type":"string","pattern":"^pfg3lbr-[0-9a-f]{32}$"},
    "reference_kind":{"const":"STDLIB_CROSSCHECK_V3_ADMISSION_PAIR"},
    "governing_contract":{"$ref":"#/$defs/file_identity"},
    "governing_contract_review":{"$ref":"#/$defs/published_ref"},
    "required_targets":{"const":[{"key":"CANONICAL_SOURCE_V3","path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v3.py","required_schema_version":null,"required_disposition":null},{"key":"ADOPTION_MARKER_V4","path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_MARKER.v4.json","required_schema_version":"plamen.program_facts_g3_00_stdlib_crosscheck_adoption_marker.v4","required_disposition":"CANONICAL_V3_CONSTRUCTION_RECORDED_BY_V4_CHAIN_NOT_ADMITTED_NOT_ACTIVE"}]},
    "resolved_targets":{"type":"array","minItems":2,"maxItems":2,"prefixItems":[{"type":"object","additionalProperties":false,"required":["key","published","stable_read_count","semantic_validation","predecessor_chain_validation"],"properties":{"key":{"const":"CANONICAL_SOURCE_V3"},"published":{"$ref":"#/$defs/published_ref"},"stable_read_count":{"const":3},"semantic_validation":{"const":"EXACT_SOURCE_BYTES_AND_SOURCE_REVIEW_V3_REVALIDATED"},"predecessor_chain_validation":{"const":"ALL_V3_RECOVERY_EDGES_VALID"}}},{"type":"object","additionalProperties":false,"required":["key","published","stable_read_count","semantic_validation","predecessor_chain_validation"],"properties":{"key":{"const":"ADOPTION_MARKER_V4"},"published":{"$ref":"#/$defs/published_ref"},"stable_read_count":{"const":3},"semantic_validation":{"const":"MARKER_V4_SCHEMA_FORMULA_PRINCIPAL_AND_RECEIPT_JOINS_VALID"},"predecessor_chain_validation":{"const":"ALL_V3_RECOVERY_EDGES_VALID"}}}],"items":false},
    "resolver":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"no_self_resolution":true,"resolver_separate_from_crosscheck_contract_author":true,"resolver_separate_from_recovery_reviewer":true,"resolver_separate_from_source_author":true,"resolver_separate_from_source_reviewer":true,"resolver_separate_from_adopter":true,"resolver_separate_from_marker_author":true,"resolver_separate_from_launcher_implementer":true,"resolver_separate_from_pre_aggregate_validator":true}},
    "checks":{"type":"array","minItems":8,"maxItems":8,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"PASS_LATE_BOUND_CROSSCHECK_V3_ADMISSION_REFERENCE_ONLY"},
    "accepted_scope":{"const":["REFERENCE_CANONICAL_CROSSCHECK_V3_IN_PRE_AGGREGATE_LINEAGE_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "reference_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The governing contract is the stable, independently accepted file identity of
`program-facts-g3-00-stdlib-crosscheck-v3-recovery-amendment.md`; its review is
the exact valid recovery review. `resolved_targets[i].published.artifact.path`
must equal `required_targets[i].path`. The marker's parsed schema/disposition
must equal its required constants. The source identity must equal the source
published by the marker's validated adoption receipt chain. All 15 fresh edges
and their publication completions are reopened. No current bytes are predicted
by this contract.

Identity is exact:

```text
reference_id = "pfg3lbr-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_LATE_BOUND_REFERENCE_V1",
  reference:<full object without reference_id and reference_body_sha256>
}))[0:32]
reference_body_sha256 = SHA-256(CJ(full object without only reference_body_sha256))
```

The launcher CROSSCHECK row and pre-aggregate lineage may consume only this
resolved pair. The v2 source remains historical parity evidence and may occur
only inside a `legacy_requirement`/debt projection; it cannot be
`successor_source`, executable source, GREEN source, or admission source.

## 4. Immutable successor public-v3 and compact-seed reviews

The two successor reviews use their v2 paths from section 2. They never write
the frozen v1 paths. Both roots copy the common definitions from section 1.

### 4.1 Public-v3 architecture review v2

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject_kind","subjects","input_artifacts","vectors","findings","open_findings","reviewer","independence","supersedes_historical","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_public_v3_architecture_review.v2"},
    "review_id":{"type":"string","pattern":"^pfg3pvr-[0-9a-f]{32}$"},
    "subject_kind":{"const":"PUBLIC_V3_ARCHITECTURE_SUCCESSOR"},
    "subjects":{"type":"array","minItems":8,"maxItems":8,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}},
    "input_artifacts":{"type":"array","minItems":7,"maxItems":100,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}},
    "vectors":{"type":"array","minItems":7,"maxItems":7,"items":{"$ref":"#/$defs/review_vector"}},
    "findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/finding"}},
    "open_findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"no_self_generated_evidence":true,"production_implementer_separate":true,"provider_author_separate":true,"schema_authors_separate":true,"subject_authors_separate":true,"workspace_clean":true}},
    "supersedes_historical":{"type":"object","additionalProperties":false,"required":["historical_review","reason","historical_authority"],"properties":{"historical_review":{"$ref":"#/$defs/file_identity"},"reason":{"const":"SUBJECT_AND_COMMON_SCHEMA_IDENTITIES_CHANGED"},"historical_authority":{"const":"HISTORICAL_READ_ONLY_NOT_ADMISSION_INPUT"}}},
    "disposition":{"enum":["PASS_PUBLIC_V3_SHADOW_CONTRACT_ONLY","REJECTED"]},
    "accepted_scope":{"const":["PUBLIC_V3_SHADOW_SUCCESSOR_REVIEW_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "review_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

`subjects` is exactly graph-v2, OWN-v2, and the six rebuilt public-v3 schemas
listed in schema-closure section 8.1, sorted by
`(UTF8(path),size_bytes,sha256)`. `input_artifacts` contains at least the exact
schema-closure section-8.1 set plus this amendment and its passing review. Each
vector is implemented as the predecessor review's closed
`{vector_id,result,evidence}` row even though the compact notation above lists
the exact vector-ID denominator; all seven must be `PASS` with nonempty stable
evidence. `ARCH-V3-07` proves the v1 receipt is unmodified, the v2 path is
create-only, and every subject is the rebuilt identity.

### 4.2 Compact seed-admission review v2

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject_kind","subjects","input_artifacts","vectors","findings","open_findings","reviewer","independence","supersedes_historical","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_r19_compact_seed_admission_review.v2"},
    "review_id":{"type":"string","pattern":"^pfg3csr-[0-9a-f]{32}$"},
    "subject_kind":{"const":"SEED_ADMISSION_SUCCESSOR"},
    "subjects":{"type":"array","minItems":1,"maxItems":1,"items":{"$ref":"#/$defs/file_identity"}},
    "input_artifacts":{"type":"array","minItems":8,"maxItems":100,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}},
    "vectors":{"type":"array","minItems":6,"maxItems":6,"items":{"$ref":"#/$defs/review_vector"}},
    "findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/finding"}},
    "open_findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"no_self_generated_evidence":true,"oracle_author_separate":true,"production_implementer_separate":true,"public_v3_reviewer_separate":true,"subject_author_separate":true,"workspace_clean":true}},
    "supersedes_historical":{"type":"object","additionalProperties":false,"required":["historical_review","reason","historical_authority"],"properties":{"historical_review":{"$ref":"#/$defs/file_identity"},"reason":{"const":"COMMON_REVIEW_SEED_SCHEMA_AND_PUBLIC_V3_REVIEW_IDENTITIES_CHANGED"},"historical_authority":{"const":"HISTORICAL_READ_ONLY_NOT_ADMISSION_INPUT"}}},
    "disposition":{"enum":["PASS_R19_SEED_ADMISSION_FOR_CONTRACT_FREEZE_ONLY","REJECTED"]},
    "accepted_scope":{"const":["COMPACT_SEED_SUCCESSOR_REVIEW_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "review_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The sole subject is the unchanged compact seed-admission file identity after
three stable reads. Inputs include the external acceptance, PF-R2 and its
review, rebuilt common independent-review schema, rebuilt seed-admission schema,
published public-v3 review v2, this amendment, and its passing review. The six
vector IDs denote the predecessor review's closed vector rows; all must pass.
`SEED-ADM-06` proves create-only v2 publication and frozen-v1 preservation.

For both successor reviews:

```text
review_id = <prefix> || SHA-256(CJ({domain:<domain>,review:<full object without review_id and review_body_sha256>}))[0:32]
review_body_sha256 = SHA-256(CJ(full object without only review_body_sha256))
```

The prefixes are `pfg3pvr-` and `pfg3csr-`; domains are
`PROGRAM_FACTS_PUBLIC_V3_ARCHITECTURE_REVIEW_V2` and
`PROGRAM_FACTS_R19_COMPACT_SEED_ADMISSION_REVIEW_V2`. Arrays sort exactly as
their predecessor review rules require. `open_findings` equals the ordered IDs
of `OPEN` findings. Passing requires no open blocker and reviewer independence.

## 5. Separately governed native-host receipt family

One artifact containing all four roles would be cyclic: VECTOR_CAPTURE must be
proved before the fourth capture, while the three parity roles bind the derived
snapshot created after that capture. Therefore the separately governed receipt
is a four-member, one-schema family with exact role paths from section 2.

The root schema is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","receipt_id","receipt_kind","role","launcher_contract","launcher_contract_review","runtime_closure","runtime_closure_review","host_profile","subject_binding","native_observation","executor","validator","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","receipt_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_parity_native_host_receipt.v1"},
    "receipt_id":{"type":"string","pattern":"^pfg3nhr-[0-9a-f]{32}$"},
    "receipt_kind":{"const":"EXACT_NATIVE_HOST_ISOLATION_OBSERVATION"},
    "role":{"enum":["VECTOR_CAPTURE","GENERATOR","EVALUATOR","CROSSCHECK"]},
    "launcher_contract":{"$ref":"#/$defs/file_identity"},
    "launcher_contract_review":{"$ref":"#/$defs/published_ref"},
    "runtime_closure":{"$ref":"#/$defs/published_ref"},
    "runtime_closure_review":{"$ref":"#/$defs/published_ref"},
    "host_profile":{"type":"object","additionalProperties":false,"required":["host_profile_id","os_family","os_version","os_build","architecture","filesystem_profile","native_publication_profile"],"properties":{"host_profile_id":{"type":"string","pattern":"^pfg3hp-[0-9a-f]{32}$"},"os_family":{"enum":["WINDOWS","LINUX","MACOS"]},"os_version":{"type":"string","minLength":1,"maxLength":256},"os_build":{"type":"string","minLength":1,"maxLength":256},"architecture":{"type":"string","minLength":1,"maxLength":64},"filesystem_profile":{"type":"string","minLength":1,"maxLength":256},"native_publication_profile":{"$ref":"#/$defs/publication_requirements"}}},
    "subject_binding":{"oneOf":[{"type":"object","additionalProperties":false,"required":["kind","base_snapshot","capture_source","bootstrap","execution_plan"],"properties":{"kind":{"const":"VECTOR_CAPTURE"},"base_snapshot":{"$ref":"#/$defs/file_identity"},"capture_source":{"$ref":"#/$defs/file_identity"},"bootstrap":{"$ref":"#/$defs/file_identity"},"execution_plan":{"$ref":"#/$defs/hex64"}}},{"type":"object","additionalProperties":false,"required":["kind","input_snapshot","candidate_set","selected_source","bootstrap","execution_plan"],"properties":{"kind":{"const":"PARITY_ROLE"},"input_snapshot":{"$ref":"#/$defs/file_identity"},"candidate_set":{"$ref":"#/$defs/file_identity"},"selected_source":{"$ref":"#/$defs/file_identity"},"bootstrap":{"$ref":"#/$defs/file_identity"},"execution_plan":{"$ref":"#/$defs/hex64"}}}]},
    "native_observation":{"type":"object","additionalProperties":false,"required":["entry_validation_complete","readable_member_bijection_complete","selected_source_delivery_authenticated","peer_source_denial_complete","network_denied","filesystem_write_confined","child_creation_denied","inherited_handle_allowlist_exact","bootstrap_protocol_exact","quarantine_move_profile_exact","process_tree_observation_supported","stable_observation_reads","observation_body_sha256"],"properties":{"entry_validation_complete":{"const":true},"readable_member_bijection_complete":{"const":true},"selected_source_delivery_authenticated":{"const":true},"peer_source_denial_complete":{"const":true},"network_denied":{"const":true},"filesystem_write_confined":{"const":true},"child_creation_denied":{"const":true},"inherited_handle_allowlist_exact":{"const":true},"bootstrap_protocol_exact":{"const":true},"quarantine_move_profile_exact":{"const":true},"process_tree_observation_supported":{"const":true},"stable_observation_reads":{"const":3},"observation_body_sha256":{"$ref":"#/$defs/hex64"}}},
    "executor":{"$ref":"#/$defs/principal"},
    "validator":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"executor_separate_from_validator":true,"launcher_author_separate":true,"launcher_implementer_separate":true,"native_validator_separate":true,"no_self_generated_evidence":true,"producer_source_authors_separate":true,"runtime_builder_separate":true}},
    "checks":{"type":"array","minItems":12,"maxItems":12,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"PASS_EXACT_NATIVE_HOST_ISOLATION_ONLY"},
    "accepted_scope":{"const":["ONE_EXACT_HOST_PROFILE_AND_SUBJECT_BINDING_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "receipt_body_sha256":{"$ref":"#/$defs/hex64"}
  },
  "allOf":[{"if":{"properties":{"role":{"const":"VECTOR_CAPTURE"}},"required":["role"]},"then":{"properties":{"subject_binding":{"properties":{"kind":{"const":"VECTOR_CAPTURE"}}}}}},{"if":{"properties":{"role":{"enum":["GENERATOR","EVALUATOR","CROSSCHECK"]}},"required":["role"]},"then":{"properties":{"subject_binding":{"properties":{"kind":{"const":"PARITY_ROLE"}}}}}}]
}
```

The full nested launcher `vector_capture_host_receipt` or `host_receipt`
projection remains as specified by the accepted launcher contract; this schema
is its separately governed external carrier and must contain an exact
projection digest in `native_observation.observation_body_sha256`. Semantic
validation requires field-for-field equality between the reopened carrier and
the launcher-consumed projection. The VECTOR_CAPTURE receipt is authored only
after the base snapshot and before the fourth capture. The other three are
authored only after the derived input snapshot/candidate set and before their
respective parity transactions. A receipt for one role cannot authorize or be
relabelled as another.

```text
receipt_id = "pfg3nhr-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_NATIVE_HOST_RECEIPT_V1",
  receipt:<full object without receipt_id and receipt_body_sha256>
}))[0:32]
receipt_body_sha256 = SHA-256(CJ(full object without only receipt_body_sha256))
```

Neither executor nor validator may be the launcher author/implementer, runtime
builder/reviewer, producer-source author, parity transaction executor,
pre-aggregate validator, aggregate author/reviewer, or G3-01 adopter. Native
observation is exact-host evidence only. It grants no general OS capability,
runtime, runner, replay, provider, audit, capture, admission, or promotion
authority.

## 6. Pre-aggregate lineage v2

The historical v1 pre-aggregate lineage schema/path remains frozen. The v2 path
from section 2 is the only lineage eligible for the new aggregate. Its root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","lineage_id","clarification","clarification_review","launcher_contract","launcher_contract_review","scenario_manifest","harness","green_evidence","implementation_review","runtime_closure","crosscheck_admission_reference","role_lineages","native_host_receipts","common_parity_projection","reviewer","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","lineage_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_parity_pre_aggregate_lineage.v2"},
    "lineage_id":{"type":"string","pattern":"^pfg3lin2-[0-9a-f]{32}$"},
    "clarification":{"$ref":"#/$defs/file_identity"},
    "clarification_review":{"$ref":"#/$defs/published_ref"},
    "launcher_contract":{"$ref":"#/$defs/file_identity"},
    "launcher_contract_review":{"$ref":"#/$defs/published_ref"},
    "scenario_manifest":{"$ref":"#/$defs/published_ref"},
    "harness":{"$ref":"#/$defs/published_ref"},
    "green_evidence":{"$ref":"#/$defs/published_ref"},
    "implementation_review":{"$ref":"#/$defs/published_ref"},
    "runtime_closure":{"$ref":"#/$defs/published_ref"},
    "crosscheck_admission_reference":{"$ref":"#/$defs/published_ref"},
    "role_lineages":{"type":"array","minItems":3,"maxItems":3,"prefixItems":[{"$ref":"#/$defs/role_lineage_generator"},{"$ref":"#/$defs/role_lineage_evaluator"},{"$ref":"#/$defs/role_lineage_crosscheck"}],"items":false},
    "native_host_receipts":{"type":"array","minItems":4,"maxItems":4,"prefixItems":[{"$ref":"#/$defs/published_ref"},{"$ref":"#/$defs/published_ref"},{"$ref":"#/$defs/published_ref"},{"$ref":"#/$defs/published_ref"}],"items":false},
    "common_parity_projection":{"type":"object","additionalProperties":false,"required":["parity_body_sha256","all_three_parsed_values_equal","all_three_cj_bytes_equal","accepted_v1_projection_equal"],"properties":{"parity_body_sha256":{"$ref":"#/$defs/hex64"},"all_three_parsed_values_equal":{"const":true},"all_three_cj_bytes_equal":{"const":true},"accepted_v1_projection_equal":{"const":true}}},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"crosscheck_resolver_separate":true,"launcher_implementer_separate":true,"native_host_executors_separate":true,"native_host_validators_separate":true,"no_self_generated_evidence":true,"pre_aggregate_reviewer_separate":true,"producer_authors_separate":true,"transaction_executors_separate":true}},
    "checks":{"type":"array","minItems":9,"maxItems":9,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"PASS_PRE_AGGREGATE_V3_EVIDENCE_LINEAGE_MAPPING_ONLY"},
    "accepted_scope":{"const":["G3_00_AGGREGATE_PREDECESSOR_LINEAGE_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "lineage_body_sha256":{"$ref":"#/$defs/hex64"}
  },
  "$defs":{
    "role_lineage_base":{"type":"object","additionalProperties":false,"required":["role","legacy_requirement","successor_source","successor_source_review","native_host_receipt","evidence","completion","parity_projection","outer_envelope_equal","outer_envelope_equality_required","projection_result"],"properties":{"role":{"enum":["GENERATOR","EVALUATOR","CROSSCHECK"]},"legacy_requirement":{"type":"object","additionalProperties":false,"required":["output_path","principal","role","schema_version","source_path"],"properties":{"output_path":{"$ref":"#/$defs/safe_path"},"principal":{"$ref":"#/$defs/principal"},"role":{"enum":["GENERATOR","EVALUATOR","CROSSCHECK"]},"schema_version":{"const":"plamen.program_facts_gate3_schema_contract_parity_evidence.v1"},"source_path":{"$ref":"#/$defs/safe_path"}}},"successor_source":{"$ref":"#/$defs/published_ref"},"successor_source_review":{"$ref":"#/$defs/published_ref"},"native_host_receipt":{"$ref":"#/$defs/published_ref"},"evidence":{"$ref":"#/$defs/published_ref"},"completion":{"$ref":"#/$defs/published_ref"},"parity_projection":{"$ref":"#/$defs/hex64"},"outer_envelope_equal":{"const":false},"outer_envelope_equality_required":{"const":false},"projection_result":{"const":"EXACT_ACCEPTED_V1_PARITY_VALUE_AND_ROLE_PROVENANCE_WITH_SUCCESSOR_ENVELOPE"}}},
    "role_lineage_generator":{"allOf":[{"$ref":"#/$defs/role_lineage_base"},{"properties":{"role":{"const":"GENERATOR"},"legacy_requirement":{"const":{"output_path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence/generator.parity_evidence.v1.json","principal":{"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-contract-generator","role":"GENERATOR"},"role":"GENERATOR","schema_version":"plamen.program_facts_gate3_schema_contract_parity_evidence.v1","source_path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/generate_schema_contracts_v1.py"}}}}]},
    "role_lineage_evaluator":{"allOf":[{"$ref":"#/$defs/role_lineage_base"},{"properties":{"role":{"const":"EVALUATOR"},"legacy_requirement":{"const":{"output_path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence/evaluator.parity_evidence.v1.json","principal":{"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-semantic-evaluator","role":"EVALUATOR"},"role":"EVALUATOR","schema_version":"plamen.program_facts_gate3_schema_contract_parity_evidence.v1","source_path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/evaluate_schema_contracts_independent_v1.py"}}}}]},
    "role_lineage_crosscheck":{"allOf":[{"$ref":"#/$defs/role_lineage_base"},{"properties":{"role":{"const":"CROSSCHECK"},"legacy_requirement":{"const":{"output_path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence/crosscheck.parity_evidence.v1.json","principal":{"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-stdlib-crosscheck","role":"CROSSCHECK"},"role":"CROSSCHECK","schema_version":"plamen.program_facts_gate3_schema_contract_parity_evidence.v1","source_path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v1.py"}}}}]}
  }
}
```

When rendered, the three local role definitions are merged into—not substituted
for—the complete common `$defs`. No duplicate definition name is allowed.

The four native receipts are ordered VECTOR_CAPTURE, GENERATOR, EVALUATOR,
CROSSCHECK. The three role rows are ordered GENERATOR, EVALUATOR, CROSSCHECK.
GENERATOR and EVALUATOR use the accepted launcher successor sources. CROSSCHECK
must use the canonical source v3 `published_ref` and source-review v3 from the
late-bound reference's validated chain. Its native receipt's selected source,
the launcher transaction source, the evidence source, and the late-bound source
must be parsed-value identical. The marker v4 is not executable source; it is
the construction/adoption provenance leaf and must be validated independently.

```text
lineage_id = "pfg3lin2-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_PRE_AGGREGATE_LINEAGE_V2",
  lineage:<full object without lineage_id and lineage_body_sha256>
}))[0:32]
lineage_body_sha256 = SHA-256(CJ(full object without only lineage_body_sha256))
```

## 7. Live schema-contract promotion lineage

The 12 schema/vector/review triplets are promoted as one fresh immutable root.
The exact root is:

```text
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/
```

The exact 24 child paths, in schema-roster order and vectors-before-review
order, are:

```text
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/mechanical_program_facts.v3.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/mechanical_program_facts.v3.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/mechanical_program_facts_debt.v3.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/mechanical_program_facts_debt.v3.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/mechanical_program_facts_receipt.v3.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/mechanical_program_facts_receipt.v3.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_active_selection.v1.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_active_selection.v1.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_independent_review.v1.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_independent_review.v1.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_phase_io_interface_vector.v1.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_phase_io_interface_vector.v1.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_public_generation.v2.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_public_generation.v2.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_publication_arm.v2.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_publication_arm.v2.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_r19_seed_acceptance.v1.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_r19_seed_acceptance.v1.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_r19_seed_admission.v1.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_r19_seed_admission.v1.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_source_identity_census.v1.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_source_identity_census.v1.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_provider_registry.v2.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/program_facts_provider_registry.v2.schema.json/independent_review.v1.json
```

The same-parent staging root is exactly
`review_fixtures/program_facts_runtime_gate3/.__pfg3_schema_contracts_v2.stage`.
Its only final target is the root above. Directory publication uses the exact
accepted directory branch and host-bound `quarantine_move_profile` primitives
from launcher-runtime closure section 15.3—Linux
`RENAME_NOREPLACE`, macOS `RENAME_EXCL`, or Windows
`FileRenameInfoEx` flags zero—with its same-volume proof, retained parent/root
handles, pathless tree identity, source/destination barriers, and no copy/delete
fallback. This is reuse of the accepted native directory-move profile, not a
new portable-rename assertion. If that launcher contract or its independent
review has not passed, the staging root is write-forbidden.

It contains exactly 12 canonical subject directories, each with one
`conformance_vectors.v1.json` and one `independent_review.v1.json`, plus the one
promotion-lineage file named in section 2. The schemas themselves remain at
their canonical `rules/schemas/` paths and are referenced by identity; they are
not copied into this root. The root has no mutable head.

The promotion-lineage schema is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","promotion_id","generation_root","schema_roster","pre_aggregate_lineage","crosscheck_admission_reference","triplets","root_census","promotion_operation","promoter","validator","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","promotion_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_schema_contract_promotion_lineage.v1"},
    "promotion_id":{"type":"string","pattern":"^pfg3scp-[0-9a-f]{32}$"},
    "generation_root":{"const":"review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/"},
    "schema_roster":{"type":"array","minItems":12,"maxItems":12,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}},
    "pre_aggregate_lineage":{"$ref":"#/$defs/published_ref"},
    "crosscheck_admission_reference":{"$ref":"#/$defs/published_ref"},
    "triplets":{"type":"array","minItems":12,"maxItems":12,"uniqueItems":true,"items":{"type":"object","additionalProperties":false,"required":["schema","schema_id","vectors","independent_review","accepted_stage","keyword_occurrence_count","coverage_atom_count","vector_count"],"properties":{"schema":{"$ref":"#/$defs/file_identity"},"schema_id":{"type":"string","minLength":1,"maxLength":512,"pattern":"^https://plamen\\.local/schemas/[A-Za-z0-9._-]+\\.schema\\.json$"},"vectors":{"$ref":"#/$defs/published_ref"},"independent_review":{"$ref":"#/$defs/published_ref"},"accepted_stage":{"const":"G3_00"},"keyword_occurrence_count":{"type":"integer","minimum":0,"maximum":4294967295},"coverage_atom_count":{"type":"integer","minimum":0,"maximum":4294967295},"vector_count":{"type":"integer","minimum":0,"maximum":4294967295}}}},
    "root_census":{"type":"object","additionalProperties":false,"required":["regular_file_count","directory_count","missing_count","extra_count","nonregular_count","tree_body_sha256"],"properties":{"regular_file_count":{"const":25},"directory_count":{"const":13},"missing_count":{"const":0},"extra_count":{"const":0},"nonregular_count":{"const":0},"tree_body_sha256":{"$ref":"#/$defs/hex64"}}},
    "promotion_operation":{"const":{"atomic_root_rename":true,"create_only":true,"destination_absent_before":true,"marker_inside_staged_root":true,"marker_not_self_hashed_by_root_tree_digest":true,"no_loose_file_adoption":true,"no_overwrite":true,"same_parent":true,"same_volume":true}},
    "promoter":{"$ref":"#/$defs/principal"},
    "validator":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"aggregate_author_separate":true,"aggregate_reviewer_separate":true,"crosscheck_resolver_separate":true,"no_self_generated_evidence":true,"pre_aggregate_validator_separate":true,"promoter_separate_from_validator":true,"schema_authors_separate":true,"vector_and_review_authors_separate":true}},
    "checks":{"type":"array","minItems":10,"maxItems":10,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"PASS_G3_00_SCHEMA_CONTRACT_PROMOTION_LINEAGE_ONLY"},
    "accepted_scope":{"const":["G3_00_ADMISSION_MANIFEST_PREDECESSOR_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "promotion_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The apparent self-reference is avoided as follows. The staged root's tree digest
is computed over the 24 vector/review files only; the complete promotion-lineage
candidate then binds that digest and is added as the 25th file. Its own identity
is not in its ID/body preimage through a tree digest. The native publication
profile atomically renames the already complete 25-file root create-only. After
rename, the independent validator reopens all 25 files and recomputes the
24-file tree digest. A marker written after root promotion, a tree digest that
includes itself, or loose-file promotion is invalid.

```text
promotion_id = "pfg3scp-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_SCHEMA_CONTRACT_PROMOTION_LINEAGE_V1",
  promotion:<full object without promotion_id and promotion_body_sha256>
}))[0:32]
promotion_body_sha256 = SHA-256(CJ(full object without only promotion_body_sha256))
```

## 8. G3-00 admission manifest and aggregate review v2

The historical v1 manifest/review paths remain unused and unmodified. The v2
manifest adds the missing closed-lineage fields and can be authored only after
all predecessors exist.

### 8.1 Admission manifest v2

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","predecessors","successor_reviews","carrier_template","provider_registry","phase_io_contracts","public_v3_schemas","crosscheck_admission_reference","native_host_receipts","pre_aggregate_lineage","schema_contract_promotion","schema_contracts","schema_contract_count","authority_ceiling","part_0_genericity","publication_requirements","admission_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_manifest.v2"},
    "predecessors":{"type":"object","additionalProperties":false,"required":["compact_seed_admission","external_seed_acceptance","specification","specification_review","source_identity_census","graph_v2","ownership_v2","schema_closure_amendment","schema_closure_amendment_review","admission_lineage_amendment","admission_lineage_amendment_review","launcher_contract","launcher_contract_review","crosscheck_v3_contract","crosscheck_v3_contract_review"],"properties":{"compact_seed_admission":{"$ref":"#/$defs/file_identity"},"external_seed_acceptance":{"$ref":"#/$defs/file_identity"},"specification":{"$ref":"#/$defs/file_identity"},"specification_review":{"$ref":"#/$defs/file_identity"},"source_identity_census":{"$ref":"#/$defs/file_identity"},"graph_v2":{"$ref":"#/$defs/file_identity"},"ownership_v2":{"$ref":"#/$defs/file_identity"},"schema_closure_amendment":{"$ref":"#/$defs/file_identity"},"schema_closure_amendment_review":{"$ref":"#/$defs/published_ref"},"admission_lineage_amendment":{"$ref":"#/$defs/file_identity"},"admission_lineage_amendment_review":{"$ref":"#/$defs/published_ref"},"launcher_contract":{"$ref":"#/$defs/file_identity"},"launcher_contract_review":{"$ref":"#/$defs/published_ref"},"crosscheck_v3_contract":{"$ref":"#/$defs/file_identity"},"crosscheck_v3_contract_review":{"$ref":"#/$defs/published_ref"}}},
    "successor_reviews":{"type":"object","additionalProperties":false,"required":["public_v3_architecture_review_v2","compact_seed_review_v2"],"properties":{"public_v3_architecture_review_v2":{"$ref":"#/$defs/published_ref"},"compact_seed_review_v2":{"$ref":"#/$defs/published_ref"}}},
    "carrier_template":{"type":"object","additionalProperties":false,"required":["normalization_id","template_body_sha256"],"properties":{"normalization_id":{"const":"plamen.program_facts_gate3_schema_carrier_template.v1"},"template_body_sha256":{"$ref":"#/$defs/hex64"}}},
    "provider_registry":{"type":"object","additionalProperties":false,"required":["schema","registry"],"properties":{"schema":{"$ref":"#/$defs/file_identity"},"registry":{"$ref":"#/$defs/file_identity"}}},
    "phase_io_contracts":{"type":"array","minItems":2,"maxItems":2,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}},
    "public_v3_schemas":{"type":"array","minItems":6,"maxItems":6,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}},
    "crosscheck_admission_reference":{"$ref":"#/$defs/published_ref"},
    "native_host_receipts":{"type":"array","minItems":4,"maxItems":4,"prefixItems":[{"$ref":"#/$defs/published_ref"},{"$ref":"#/$defs/published_ref"},{"$ref":"#/$defs/published_ref"},{"$ref":"#/$defs/published_ref"}],"items":false},
    "pre_aggregate_lineage":{"$ref":"#/$defs/published_ref"},
    "schema_contract_promotion":{"$ref":"#/$defs/published_ref"},
    "schema_contracts":{"type":"array","minItems":12,"maxItems":12,"uniqueItems":true,"items":{"type":"object","additionalProperties":false,"required":["schema","schema_id","vectors","independent_review","accepted_stage","keyword_occurrence_count","coverage_atom_count","vector_count"],"properties":{"schema":{"$ref":"#/$defs/file_identity"},"schema_id":{"type":"string","minLength":1,"maxLength":512,"pattern":"^https://plamen\\.local/schemas/[A-Za-z0-9._-]+\\.schema\\.json$"},"vectors":{"$ref":"#/$defs/published_ref"},"independent_review":{"$ref":"#/$defs/published_ref"},"accepted_stage":{"const":"G3_00"},"keyword_occurrence_count":{"type":"integer","minimum":0,"maximum":4294967295},"coverage_atom_count":{"type":"integer","minimum":0,"maximum":4294967295},"vector_count":{"type":"integer","minimum":0,"maximum":4294967295}}}},
    "schema_contract_count":{"const":12},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "admission_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The manifest has no ID and does not contain or predict its review. Its body
digest omits only `admission_body_sha256`. The four native receipts and 12
schema-contract rows equal the corresponding pre-aggregate/promotion arrays in
both directions. The crosscheck reference is parsed-value identical everywhere.
The v2 successor reviews are the only public/seed reviews accepted. No v1 review
may appear in `successor_reviews`.

### 8.2 Aggregate review v2

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject","reviewer","independence","checks","findings","open_findings","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_aggregate_review.v2"},
    "review_id":{"type":"string","pattern":"^pfg3ar2-[0-9a-f]{32}$"},
    "subject":{"$ref":"#/$defs/published_ref"},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"aggregate_subject_author_separate":true,"crosscheck_authors_and_resolver_separate":true,"launcher_authors_and_implementer_separate":true,"native_host_executors_and_validators_separate":true,"no_self_generated_evidence":true,"per_schema_reviewers_separate":true,"production_implementer_separate":true,"promotion_principals_separate":true,"schema_authors_separate":true,"successor_reviewers_separate":true,"vector_generator_separate":true,"workspace_clean":true}},
    "checks":{"type":"array","minItems":15,"maxItems":15,"items":{"$ref":"#/$defs/check"}},
    "findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/finding"}},
    "open_findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "disposition":{"enum":["PASS_G3_00_ADMISSION_FOR_G3_01_ADOPTION_REVIEW_ONLY","REJECTED"]},
    "accepted_scope":{"const":["AUTHOR_G3_01_ADOPTION_LINEAGE_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "review_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

Every check is represented as the common closed `{check_id,result,evidence}`
row; the compact schema notation fixes the 15-ID denominator and order. All
must pass with nonempty evidence; no blocker may remain open. The aggregate
review is written after the manifest and is absent from the manifest preimage.

```text
review_id = "pfg3ar2-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_AGGREGATE_REVIEW_V2",
  review:<full object without review_id and review_body_sha256>
}))[0:32]
review_body_sha256 = SHA-256(CJ(full object without only review_body_sha256))
```

## 9. Post-admission G3-01 adoption lineage

The phrase "G3-01 adoption" must not create a cycle. G3-00 admission consumes
the **pre-admission** promotion lineage from section 7. Only after the manifest
and aggregate review pass may a separate principal author the **post-admission**
G3-01 adoption lineage. The admission manifest never contains this later
artifact.

The exact root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","adoption_id","g3_00_manifest","g3_00_aggregate_review","schema_contract_promotion","pre_aggregate_lineage","crosscheck_admission_reference","successor_reviews","g3_01_amendment","adopter","reviewer","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","adoption_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_01_adoption_lineage.v1"},
    "adoption_id":{"type":"string","pattern":"^pfg301ad-[0-9a-f]{32}$"},
    "g3_00_manifest":{"$ref":"#/$defs/published_ref"},
    "g3_00_aggregate_review":{"$ref":"#/$defs/published_ref"},
    "schema_contract_promotion":{"$ref":"#/$defs/published_ref"},
    "pre_aggregate_lineage":{"$ref":"#/$defs/published_ref"},
    "crosscheck_admission_reference":{"$ref":"#/$defs/published_ref"},
    "successor_reviews":{"type":"object","additionalProperties":false,"required":["public_v3_architecture_review_v2","compact_seed_review_v2"],"properties":{"public_v3_architecture_review_v2":{"$ref":"#/$defs/published_ref"},"compact_seed_review_v2":{"$ref":"#/$defs/published_ref"}}},
    "g3_01_amendment":{"$ref":"#/$defs/file_identity"},
    "adopter":{"$ref":"#/$defs/principal"},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"adopter_separate_from_aggregate_author":true,"adopter_separate_from_aggregate_reviewer":true,"g3_01_amendment_author_separate":true,"native_host_principals_separate":true,"no_self_adoption":true,"no_self_generated_evidence":true,"promotion_principals_separate":true,"reviewer_separate_from_adopter":true}},
    "checks":{"type":"array","minItems":9,"maxItems":9,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"PASS_G3_01_ADOPTION_LINEAGE_FOR_CONSTRUCTION_AMENDMENT_REVIEW_ONLY"},
    "accepted_scope":{"const":["REVIEW_G3_01_CONSTRUCTION_AMENDMENT_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "adoption_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The common `checks` row shape, rather than bare strings, is used in the actual
artifact; all nine are PASS with nonempty evidence. The adopter and reviewer
are distinct; the reviewer validates the candidate before publication and the
publisher is neither. No principal certifies its own artifact. The adoption
lineage does not contain or predict the later G3-01 amendment review.

```text
adoption_id = "pfg301ad-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_01_ADOPTION_LINEAGE_V1",
  adoption:<full object without adoption_id and adoption_body_sha256>
}))[0:32]
adoption_body_sha256 = SHA-256(CJ(full object without only adoption_body_sha256))
```

Only after this lineage is valid may the existing G3-01 amendment review be
authored at its already specified v1 path. That review adds this lineage as a
required input and adds check `PFG301-00-ADOPTION-LINEAGE` before its existing
seven checks. Its passing disposition remains preimplementation-only.

## 10. Exact dependency DAG and supersession points

The only valid order is:

```text
stable predecessor contracts
        |
        v
this amendment -> independent amendment review
        |
        +--> render/review this amendment's ten schemas
        |
        +--> accepted crosscheck-v3 recovery contract/review
        |        -> all 15 published recovery edges
        |        -> canonical source v3 + adoption marker v4
        |        -> late-bound crosscheck admission reference
        |
        +--> accepted launcher contract/review -> runtime/RED/GREEN/impl review
                 -> materializer/base snapshot
                 -> VECTOR_CAPTURE native-host receipt
                 -> authenticated fourth capture
                 -> candidate set/derived snapshot
                 -> GENERATOR/EVALUATOR/CROSSCHECK native-host receipts
                 -> three parity transactions
                 -> pre-aggregate lineage v2
        |
        +--> rebuilt schemas/provider pair -> public-v3 review v2
                 -> compact-seed review v2
        |
        +--> 12 complete schema/vector/review triplets
                 + pre-aggregate lineage v2
                 + late-bound crosscheck reference
                 -> schema-contract promotion lineage/root
        |
        v
G3-00 admission manifest v2 -> aggregate review v2
        |
        v
G3-01 adoption lineage -> G3-01 amendment review -> G3-01 construction
```

No arrow is reversible. Every semantic successor consumes a `published_ref`
and revalidates content. No object embeds itself, its publication completion,
or a future reviewer. A review never appears in the subject it reviews. A root
tree digest never includes the marker whose preimage contains that digest.

The following narrow supersessions are exact:

1. **Launcher/runtime closure:** its pre-aggregate section and all CROSSCHECK
   source references are superseded only where they select the admission
   successor. They must consume section-3 canonical source v3 + marker v4 and
   section-6 pre-aggregate v2. Historical v2 remains a legacy parity/debt
   input. Its native-host placeholder is closed by section 5's four paths and
   one schema. Its order is amended by section 10's non-cyclic receipt split.
2. **Schema-closure amendment:** its instruction to reissue either review at an
   existing canonical v1 path is superseded by section 4's immutable v2 paths.
   For the successor construction only, its 24
   `schema_contracts/<schema>/...` vector/review paths are historical candidate
   paths and are superseded as aggregate inputs by section 7's exact 24
   `schema_contracts_v2/<schema>/...` paths. Bytes are regenerated and reviewed
   for the fresh root; they are never copied or inferred from historical loose
   files.
   Its admission-manifest/review v1 schema and paths are superseded for the new
   construction by section 8 v2. Its loose/live promotion prose is superseded
   by section 7's exact root and lineage.
3. **G3-01 construction amendment:** section 1's unresolved single G3-00
   manifest becomes the published manifest-v2 + aggregate-review-v2 + adoption-
   lineage triple. Its amendment review must consume the adoption lineage and
   run the added first check. Its later construction steps are unchanged.

No other schema, count, vector, parity value, PhaseIO key, RACI rule, operation
order, severity rule, provider capability, or lifecycle authority changes.

## 11. Crash, collision, and recovery rules

All new publication uses the accepted native publication profile referenced in
section 2.1. The semantic state machine is:

| State | Required action |
|---|---|
| no edge paths | begin only after all predecessors validate |
| intent only | reconcile exact registered edge; never choose another path |
| complete stage only | validate candidate, publish no-replace, or record terminal unsupported/collision debt |
| final without valid completion | reject as incomplete; never infer completion from bytes |
| final + valid completion | reopen final three times, validate physical identity, bytes, schema, formulas, joins, and principal separation |
| different final already exists | terminal collision even if content-equal |
| unsupported OS/filesystem/API | `UNSUPPORTED_HOST_PUBLICATION_PROFILE`; touch no edge paths |
| ambiguous crash | reconcile from registered intent/prepared/final/completion paths only; no scan or backfill |

An edge failure blocks only its dependent lineage and is emitted as flagged
human-review debt. It does not halt unrelated pipeline work and does not degrade
into permission. Overwrite, replace, hard-link publication, copy fallback,
cross-volume move, edit-in-place, silent cleanup, receipt synthesis, and inferred
substitution are forbidden.

## 12. Fixture-first RED/GREEN requirements

No implementation or governed artifact may be authored until an independent
fixture author creates a closed RED suite for this amendment. The suite is
Part-0 and uses only synthetic file identities, generic JSON, filesystem states,
and principal labels. It contains no ecosystem, language, protocol, contract,
vulnerability, expected finding, or protocol-answer hint.

The minimum exact cases are:

| ID | Mutation | RED result | GREEN result |
|---|---|---|---|
| `ALC-01` | launcher CROSSCHECK selects v2 as successor | reject stale source | v3 source + v4 marker pair passes |
| `ALC-02` | v3 source exists without valid marker chain | reject unresolved pair | all 15 edges and marker join pass |
| `ALC-03` | marker path/schema/disposition mismatch | reject typed reference | exact target constants pass |
| `ALC-04` | reuse public-v3 v1 path | reject overwrite/collision | create-only v2 path passes |
| `ALC-05` | reuse compact-seed v1 path | reject overwrite/collision | create-only v2 path passes |
| `ALC-06` | successor review omits historical identity | reject lineage gap | frozen-v1 identity is recorded as debt |
| `ALC-07` | one native receipt reused for two roles | reject role alias | four exact role paths pass |
| `ALC-08` | all-role receipt depends on post-capture state before capture | reject dependency cycle | split receipt order passes |
| `ALC-09` | executor equals validator | reject self-certification | principals are separate |
| `ALC-10` | host profile/subject differs from launcher projection | reject identity join | exact parsed projection passes |
| `ALC-11` | pre-aggregate v2 CROSSCHECK uses v2 source | reject stale lineage | canonical v3 source passes |
| `ALC-12` | pre-aggregate omits marker v4 | reject incomplete provenance | marker join passes |
| `ALC-13` | promotion tree has 24 or 26 files | reject census | exact 25-file root passes |
| `ALC-14` | tree digest includes its own marker | reject circular preimage | 24-file digest + 25th marker passes |
| `ALC-15` | loose vector/review files substituted | reject non-promoted set | one atomic root promotion passes |
| `ALC-16` | manifest contains v1 public/seed review | reject historical input | both v2 reviews pass |
| `ALC-17` | manifest omits native receipt/pre-aggregate/promotion | reject incomplete lineage | all joins pass |
| `ALC-18` | aggregate review appears in manifest | reject cycle | review follows manifest |
| `ALC-19` | G3-01 adoption appears in G3-00 manifest | reject cycle | post-admission adoption passes |
| `ALC-20` | G3-01 review omits adoption lineage | reject predecessor gap | added first check passes |
| `ALC-21` | artifact final exists without completion | reject incomplete publication | valid published pair passes |
| `ALC-22` | equal-content collision adopted | reject collision | fresh no-replace publication passes |
| `ALC-23` | unsupported publication profile touches stage | reject side effect | fails before edge paths touched |
| `ALC-24` | authority bit true | reject authority escalation | all 29 false passes |
| `ALC-25` | protocol/ecosystem hint appears | reject Part-0 breach | generic fixture passes |

Each case has one positive candidate and at least one negative mutation. The RED
run must execute all 25 cases against missing/unrepaired behavior and fail for
the exact first reason. GREEN must execute the unchanged same case bytes against
the implementation, produce 25 expected outcomes, zero setup errors, zero
unexpected writes, and zero false passes. Fixture author, implementation author,
GREEN executor, and independent reviewer are pairwise separate. No test derived
from a motivating repository is recall evidence.

## 13. Independent amendment review

The review path is the first semantic path in section 2. It is create-only and
published under the native profile after this document is stable. Its exact
schema root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject","normative_parents","reviewer","independence","checks","findings","open_findings","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_closure_amendment_review.v1"},
    "review_id":{"type":"string","pattern":"^pfg3alr-[0-9a-f]{32}$"},
    "subject":{"$ref":"#/$defs/file_identity"},
    "normative_parents":{"type":"array","minItems":6,"maxItems":6,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"aggregate_author_separate":true,"amendment_author_separate":true,"crosscheck_authors_separate":true,"fixture_author_separate":true,"g3_01_author_separate":true,"launcher_authors_separate":true,"native_host_principals_separate":true,"no_self_generated_evidence":true,"production_implementer_separate":true,"promotion_principals_separate":true,"schema_builder_separate":true,"workspace_clean":true}},
    "checks":{"type":"array","minItems":13,"maxItems":13,"items":{"$ref":"#/$defs/check"}},
    "findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/finding"}},
    "open_findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "disposition":{"enum":["PASS_G3_00_ADMISSION_LINEAGE_CLOSURE_FOR_RED_FIXTURES_ONLY","REJECTED"]},
    "accepted_scope":{"const":["AUTHOR_RED_FIXTURES_AND_RENDER_SCHEMAS_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "review_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The six normative parent identities are the exact stable identities of the six
contracts in section 0, sorted by `(UTF8(path),size_bytes,sha256)` at review
time. A parent still being edited makes the review `REJECTED`; the reviewer
cannot guess its eventual identity. The launcher and crosscheck-v3 contracts
must have their bounded independent contract reviews before this review passes.
The G3-01 amendment is required to be byte-stable but its lifecycle review is
deliberately later than G3-00 admission and is not a predecessor here. Every
check is the common closed check row in the actual artifact,
all 13 pass with nonempty evidence, no blocker is open, and every named
independence predicate is true.

```text
review_id = "pfg3alr-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_CLOSURE_REVIEW_V1",
  review:<full object without review_id and review_body_sha256>
}))[0:32]
review_body_sha256 = SHA-256(CJ(full object without only review_body_sha256))
```

A PASS permits only RED fixture authorship and mechanical schema rendering. It
does not authorize GREEN execution, native process launch, construction of any
semantic successor, promotion, admission, G3-01, runtime, provider, audit,
release, commit, push, or cutover.

## 14. Mechanical validation and terminal condition

Before the amendment can be submitted for independent review, a mechanical
validator must prove:

1. UTF-8 without BOM, LF-only, exactly one terminal LF;
2. every fenced JSON block parses with duplicate-key rejection;
3. the common resource and every root are Draft-2020-12 schema-valid after the
   specified `$defs` merge;
4. every `$ref` resolves locally and network resolution is disabled;
5. all path registries are exact, unique, repository-relative, NFC, and case-
   distinct;
6. all schema versions, prefixes, domains, dispositions, accepted scopes,
   counts, and ordered check rosters equal this contract;
7. the dependency graph is acyclic and no identity preimage contains itself or
   a successor;
8. no frozen v1/v2 artifact is listed as a writable target;
9. every governed authority object has exactly 29 false members;
10. the 25 RED/GREEN cases are unique and complete; and
11. no ecosystem, protocol, repository, contract, vulnerability, or expected-
    finding name occurs in a fixture or semantic shortcut.

Until an independent review passes, status remains
`CONTRACT_ONLY_PENDING_INDEPENDENT_REVIEW`. Until all subsequent fixture,
schema, native-host, crosscheck, launcher, promotion, manifest, aggregate, and
adoption reviews pass in the exact order above, no downstream construction or
authority is implied.

## 15. R2 corrective successor: normative admission contract

Sections 0-14 record the rejected candidate `5c600182...`. They remain visible
as design provenance, but their `published_ref` alias, summary native-host
projection, prose-only launcher rebind, per-file treatment of a staged root,
admission-manifest v2, aggregate-review v2, adoption-lineage v1, and proposed
G3-01 review mutation are **non-normative and non-enabling**. This section is the
bounded r2 successor and wins every conflict. It preserves every existing file
and path; no artifact specified only by the rejected candidate may be created.

### 15.1 Exact r2 schema and semantic path registry

Only after the accepted launcher and crosscheck-v3-r2 contract reviews and a
fresh independent review of this whole r2 document may the following 18
self-contained schemas be rendered:

```text
rules/schemas/program_facts_g3_00_admission_lineage_closure_r2_review.v1.schema.json
rules/schemas/program_facts_g3_00_crosscheck_admission_reference.v2.schema.json
rules/schemas/program_facts_g3_00_launcher_lineage_rebind.v1.schema.json
rules/schemas/program_facts_g3_00_launcher_lineage_merged_schema_registry.v1.schema.json
rules/schemas/program_facts_g3_00_launcher_lineage_overlay_replay.v1.schema.json
rules/schemas/program_facts_g3_00_launcher_lineage_overlay_review.v1.schema.json
rules/schemas/program_facts_public_v3_architecture_review.v3.schema.json
rules/schemas/program_facts_r19_compact_seed_admission_review.v3.schema.json
rules/schemas/program_facts_parity_native_host_receipt.v2.schema.json
rules/schemas/program_facts_parity_pre_aggregate_lineage.v3.schema.json
rules/schemas/program_facts_g3_00_schema_contract_root_manifest.v1.schema.json
rules/schemas/program_facts_g3_00_schema_contract_root_publish_arm.v1.schema.json
rules/schemas/program_facts_g3_00_directory_transport_completion.v1.schema.json
rules/schemas/program_facts_g3_00_schema_contract_promotion_review.v1.schema.json
rules/schemas/program_facts_g3_00_admission_manifest.v3.schema.json
rules/schemas/program_facts_g3_00_aggregate_review.v3.schema.json
rules/schemas/program_facts_g3_01_adoption_lineage.v2.schema.json
rules/schemas/program_facts_g3_01_construction_amendment_review.v2.schema.json
```

The renderer registry is closed and exact:

| Ordinal | Schema basename | Only permitted root `schema_version` |
|---:|---|---|
| 0 | `program_facts_g3_00_admission_lineage_closure_r2_review.v1.schema.json` | `plamen.program_facts_g3_00_admission_lineage_closure_r2_review.v1` |
| 1 | `program_facts_g3_00_crosscheck_admission_reference.v2.schema.json` | `plamen.program_facts_g3_00_crosscheck_admission_reference.v2` |
| 2 | `program_facts_g3_00_launcher_lineage_rebind.v1.schema.json` | `plamen.program_facts_g3_00_launcher_lineage_rebind.v1` |
| 3 | `program_facts_g3_00_launcher_lineage_merged_schema_registry.v1.schema.json` | `plamen.program_facts_g3_00_launcher_lineage_merged_schema_registry.v1` |
| 4 | `program_facts_g3_00_launcher_lineage_overlay_replay.v1.schema.json` | `plamen.program_facts_g3_00_launcher_lineage_overlay_replay.v1` |
| 5 | `program_facts_g3_00_launcher_lineage_overlay_review.v1.schema.json` | `plamen.program_facts_g3_00_launcher_lineage_overlay_review.v1` |
| 6 | `program_facts_public_v3_architecture_review.v3.schema.json` | `plamen.program_facts_public_v3_architecture_review.v3` |
| 7 | `program_facts_r19_compact_seed_admission_review.v3.schema.json` | `plamen.program_facts_r19_compact_seed_admission_review.v3` |
| 8 | `program_facts_parity_native_host_receipt.v2.schema.json` | `plamen.program_facts_parity_native_host_receipt.v2` |
| 9 | `program_facts_parity_pre_aggregate_lineage.v3.schema.json` | `plamen.program_facts_g3_00_parity_pre_aggregate_lineage.v3` |
| 10 | `program_facts_g3_00_schema_contract_root_manifest.v1.schema.json` | `plamen.program_facts_g3_00_schema_contract_root_manifest.v1` |
| 11 | `program_facts_g3_00_schema_contract_root_publish_arm.v1.schema.json` | `plamen.program_facts_g3_00_schema_contract_root_publish_arm.v1` |
| 12 | `program_facts_g3_00_directory_transport_completion.v1.schema.json` | `plamen.program_facts_g3_00_directory_transport_completion.v1` |
| 13 | `program_facts_g3_00_schema_contract_promotion_review.v1.schema.json` | `plamen.program_facts_g3_00_schema_contract_promotion_review.v1` |
| 14 | `program_facts_g3_00_admission_manifest.v3.schema.json` | `plamen.program_facts_g3_00_admission_manifest.v3` |
| 15 | `program_facts_g3_00_aggregate_review.v3.schema.json` | `plamen.program_facts_g3_00_aggregate_review.v3` |
| 16 | `program_facts_g3_01_adoption_lineage.v2.schema.json` | `plamen.program_facts_g3_01_adoption_lineage.v2` |
| 17 | `program_facts_g3_01_construction_amendment_review.v2.schema.json` | `plamen.program_facts_g3_01_construction_amendment_review.v2` |

No basename alias, schema-version alias, or additional root is accepted.

The exact future semantic paths, in dependency order, are:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_CLOSURE_R2_INDEPENDENT_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/STDLIB_CROSSCHECK_V3_R2_ADMISSION_REFERENCE.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_LAUNCHER_LINEAGE_REBIND.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_LAUNCHER_LINEAGE_MERGED_SCHEMA_REGISTRY.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_LAUNCHER_LINEAGE_OVERLAY_REPLAY.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_LAUNCHER_LINEAGE_OVERLAY_INDEPENDENT_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/architecture/PROGRAM_FACTS_PUBLIC_V3_AMENDMENT_INDEPENDENT_REVIEW.v3.json
review_fixtures/program_facts_runtime_gate3/seed/PROGRAM_FACTS_R19_COMPACT_SEED_ADMISSION_INDEPENDENT_REVIEW.v3.json
review_fixtures/program_facts_runtime_gate3/g3_00_native_host/PROGRAM_FACTS_G3_00_PARITY_NATIVE_HOST_RECEIPT_VECTOR_CAPTURE.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_native_host/PROGRAM_FACTS_G3_00_PARITY_NATIVE_HOST_RECEIPT_GENERATOR.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_native_host/PROGRAM_FACTS_G3_00_PARITY_NATIVE_HOST_RECEIPT_EVALUATOR.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_native_host/PROGRAM_FACTS_G3_00_PARITY_NATIVE_HOST_RECEIPT_CROSSCHECK.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_V3_PRE_AGGREGATE_LINEAGE.v3.json
review_fixtures/program_facts_runtime_gate3/.__pfg3_schema_contracts_v2.stage/PROGRAM_FACTS_G3_00_SCHEMA_CONTRACT_ROOT_MANIFEST.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_SCHEMA_CONTRACT_ROOT_PUBLISH_ARM.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_SCHEMA_CONTRACT_ROOT_DIRECTORY_TRANSPORT_COMPLETION.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_SCHEMA_CONTRACT_PROMOTION_INDEPENDENT_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00/PROGRAM_FACTS_G3_00_ADMISSION_MANIFEST.v3.json
review_fixtures/program_facts_runtime_gate3/g3_00/PROGRAM_FACTS_G3_00_ADMISSION_MANIFEST_INDEPENDENT_REVIEW.v3.json
review_fixtures/program_facts_runtime_gate3/construction/PROGRAM_FACTS_G3_01_ADOPTION_LINEAGE.v2.json
review_fixtures/program_facts_runtime_gate3/construction/PROGRAM_FACTS_G3_01_CONSTRUCTION_AMENDMENT_INDEPENDENT_REVIEW.v2.json
```

The first r2 review validates against the inline section-15.12 root before
schema materialization. Every other semantic path is created under the accepted
crosscheck-v3-r2 arm-bound file publication profile and is consumed as
`file_published_ref`. Existing specifications, amendments, schemas, source
files, and historical reviews are consumed only as `legacy_accepted_ref`; they
receive no synthetic arm or completion. The promoted directory is consumed
only as `directory_published_root_ref`.

### 15.2 Crosscheck-v3-r2 late-bound admission reference

The r2 reference root is exact:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","reference_id","recovery_contract","recovery_review","canonical_source_v3","source_review_v3","adoption_receipt_v4","adoption_marker_v4","transport_chain","resolver","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","reference_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_crosscheck_admission_reference.v2"},
    "reference_id":{"type":"string","pattern":"^pfg3xbr2-[0-9a-f]{32}$"},
    "recovery_contract":{"$ref":"#/$defs/legacy_accepted_ref"},
    "recovery_review":{"$ref":"#/$defs/file_published_ref"},
    "canonical_source_v3":{"$ref":"#/$defs/file_published_ref"},
    "source_review_v3":{"$ref":"#/$defs/file_published_ref"},
    "adoption_receipt_v4":{"$ref":"#/$defs/file_published_ref"},
    "adoption_marker_v4":{"$ref":"#/$defs/file_published_ref"},
    "transport_chain":{"type":"object","additionalProperties":false,"required":["all_fifteen_edges_revalidated","all_attempts_contiguous","all_arms_prepublication","all_completion_grades_enabling","postcondition_only_count","legacy_completion_backfill_count","source_marker_identity_join"],"properties":{"all_fifteen_edges_revalidated":{"const":true},"all_attempts_contiguous":{"const":true},"all_arms_prepublication":{"const":true},"all_completion_grades_enabling":{"const":true},"postcondition_only_count":{"const":0},"legacy_completion_backfill_count":{"const":0},"source_marker_identity_join":{"const":true}}},
    "resolver":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"no_self_resolution":true,"resolver_separate_from_all_sixteen_crosscheck_principals":true,"resolver_separate_from_launcher_overlay_authors":true,"resolver_separate_from_pre_aggregate_reviewer":true}},
    "checks":{"type":"array","minItems":10,"maxItems":10,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"PASS_CROSSCHECK_V3_R2_ADMISSION_REFERENCE_ONLY"},
    "accepted_scope":{"const":["LAUNCHER_LINEAGE_REBIND_INPUT_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "reference_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The exact check order is `XBR2-01-RECOVERY-CONTRACT-REVIEW`,
`XBR2-02-FIFTEEN-EDGE-CLOSURE`, `XBR2-03-CONTIGUOUS-ATTEMPTS`,
`XBR2-04-ARM-BEFORE-PUBLICATION`, `XBR2-05-ENABLING-COMPLETIONS`,
`XBR2-06-SOURCE-V3`, `XBR2-07-SOURCE-REVIEW-V3`,
`XBR2-08-ADOPTION-RECEIPT-MARKER-V4`, `XBR2-09-NO-LEGACY-BACKFILL`, and
`XBR2-10-INDEPENDENCE-NONAUTHORITY`. The target paths and semantic
dispositions are those in the accepted crosscheck-v3-r2 contract; the resolver
derives identities only after their enabling completions exist. Identity is:

```text
reference_id = "pfg3xbr2-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_CROSSCHECK_ADMISSION_REFERENCE_V2",
  reference:<object without reference_id and reference_body_sha256>
}))[0:32]
reference_body_sha256 = SHA-256(CJ(object without only reference_body_sha256))
```

### 15.3 Exact launcher-lineage overlay and merged schemas

The overlay is not prose substitution. It is a four-artifact reviewed chain:
rebind plan -> 25 merged schemas and registry -> replay evidence -> independent
overlay review. The rebind plan root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","rebind_id","launcher_contract","launcher_review","crosscheck_reference","legacy_crosscheck_binding","accepted_crosscheck_binding","transforms","merged_schema_root","renderer","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","rebind_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_launcher_lineage_rebind.v1"},
    "rebind_id":{"type":"string","pattern":"^pfg3lrb-[0-9a-f]{32}$"},
    "launcher_contract":{"$ref":"#/$defs/legacy_accepted_ref"},
    "launcher_review":{"$ref":"#/$defs/file_published_ref"},
    "crosscheck_reference":{"$ref":"#/$defs/file_published_ref"},
    "legacy_crosscheck_binding":{"type":"object","additionalProperties":false,"required":["source_path","source_review_path","authority"],"properties":{"source_path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py"},"source_review_path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/CROSSCHECK_V2_SOURCE_REVIEW.v1.json"},"authority":{"const":"HISTORICAL_PROPOSED_INPUT_ONLY"}}},
    "accepted_crosscheck_binding":{"type":"object","additionalProperties":false,"required":["canonical_source_v3","source_review_v3","adoption_marker_v4"],"properties":{"canonical_source_v3":{"$ref":"#/$defs/file_published_ref"},"source_review_v3":{"$ref":"#/$defs/file_published_ref"},"adoption_marker_v4":{"$ref":"#/$defs/file_published_ref"}}},
    "transforms":{"const":[{"operation":"REPLACE_EXACT_CONST","semantic_site":"SNAPSHOT_ROLE_SOURCE_PATHS_CROSSCHECK","old_value":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py","new_value_from":"accepted_crosscheck_binding.canonical_source_v3.transport.artifact.path"},{"operation":"REPLACE_EXACT_CONST","semantic_site":"PRE_AGGREGATE_CROSSCHECK_SUCCESSOR_SOURCE","old_value":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py","new_value_from":"accepted_crosscheck_binding.canonical_source_v3.transport.artifact.path"},{"operation":"AUGMENT_CLOSED_OBJECT","semantic_site":"PRE_AGGREGATE_CROSSCHECK_LINEAGE","required_fields":["crosscheck_reference","canonical_source_v3","source_review_v3","adoption_marker_v4"]},{"operation":"REWRITE_SCHEMA_ID","semantic_site":"ALL_25_RENDERED_ROOTS","new_prefix":"https://plamen.local/schemas/g3_00_launcher_lineage_overlay_v1/"}]},
    "merged_schema_root":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/launcher_lineage_overlay_v1/schemas/"},
    "renderer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"launcher_authors_separate":true,"no_self_generated_evidence":true,"overlay_reviewer_separate":true,"renderer_separate_from_crosscheck_resolver":true,"scenario_executor_separate":true}},
    "checks":{"type":"array","minItems":8,"maxItems":8,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"PASS_LAUNCHER_LINEAGE_REBIND_PLAN_ONLY"},
    "accepted_scope":{"const":["RENDER_MERGED_LAUNCHER_SCHEMAS_AND_REPLAY_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "rebind_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The exact checks are `LRB-01-LAUNCHER-CONTRACT-REVIEW`,
`LRB-02-CROSSCHECK-REFERENCE`, `LRB-03-LEGACY-NONENABLING`,
`LRB-04-FOUR-TRANSFORMS`, `LRB-05-NO-OTHER-AST-CHANGE`,
`LRB-06-FRESH-SCHEMA-IDS-PATHS`, `LRB-07-ACYCLIC-LATE-BINDING`, and
`LRB-08-INDEPENDENCE-NONAUTHORITY`.

For `AUGMENT_CLOSED_OBJECT`, the renderer adds exactly this fragment to the
existing CROSSCHECK pre-aggregate lineage object, preserving every existing
property and bound:

```json
{"required_addition":["crosscheck_reference","canonical_source_v3","source_review_v3","adoption_marker_v4"],"properties_addition":{"crosscheck_reference":{"$ref":"#/$defs/file_published_ref"},"canonical_source_v3":{"$ref":"#/$defs/file_published_ref"},"source_review_v3":{"$ref":"#/$defs/file_published_ref"},"adoption_marker_v4":{"$ref":"#/$defs/file_published_ref"}}}
```

The four values are parsed-value equal to the accepted rebind and crosscheck
reference inputs. The old v2 source/review may remain only in historical/debt
fields already present in the launcher schema; it cannot satisfy any of these
four successor fields.

The merged registry root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","registry_id","rebind","source_registry","merged_root","rows","schema_count","transform_census","launcher_projection_fragments","renderer","validator","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","registry_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_launcher_lineage_merged_schema_registry.v1"},
    "registry_id":{"type":"string","pattern":"^pfg3lmr-[0-9a-f]{32}$"},
    "rebind":{"$ref":"#/$defs/file_published_ref"},
    "source_registry":{"$ref":"#/$defs/legacy_accepted_ref"},
    "merged_root":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/launcher_lineage_overlay_v1/schemas/"},
    "rows":{"type":"array","minItems":25,"maxItems":25,"uniqueItems":true,"items":{"type":"object","additionalProperties":false,"required":["ordinal","source_schema","source_schema_id","merged_schema","merged_schema_id","normalized_source_body_sha256","normalized_merged_body_sha256","transform_count","unapproved_difference_count"],"properties":{"ordinal":{"type":"integer","minimum":0,"maximum":24},"source_schema":{"$ref":"#/$defs/legacy_accepted_ref"},"source_schema_id":{"type":"string","minLength":1,"maxLength":512},"merged_schema":{"$ref":"#/$defs/file_published_ref"},"merged_schema_id":{"type":"string","minLength":1,"maxLength":512,"pattern":"^https://plamen\\.local/schemas/g3_00_launcher_lineage_overlay_v1/[A-Za-z0-9._-]+\\.schema\\.json$"},"normalized_source_body_sha256":{"$ref":"#/$defs/hex64"},"normalized_merged_body_sha256":{"$ref":"#/$defs/hex64"},"transform_count":{"type":"integer","minimum":2,"maximum":4},"unapproved_difference_count":{"const":0}}}},
    "schema_count":{"const":25},
    "transform_census":{"type":"object","additionalProperties":false,"required":["exact_const_replacements","closed_object_augmentations","schema_id_rewrites","unexpected_ast_differences"],"properties":{"exact_const_replacements":{"const":50},"closed_object_augmentations":{"const":25},"schema_id_rewrites":{"const":25},"unexpected_ast_differences":{"const":0}}},
    "launcher_projection_fragments":{"type":"object","additionalProperties":false,"required":["vector_capture_host_receipt_schema","parity_host_receipt_schema","fragment_equality"],"properties":{"vector_capture_host_receipt_schema":{"$ref":"#/$defs/hex64"},"parity_host_receipt_schema":{"$ref":"#/$defs/hex64"},"fragment_equality":{"const":"BYTE_IDENTICAL_NORMALIZED_FRAGMENTS_IN_ALL_25_MERGED_SCHEMAS"}}},
    "renderer":{"$ref":"#/$defs/principal"},
    "validator":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"no_self_generated_evidence":true,"renderer_separate_from_validator":true,"reviewer_separate":true,"source_authors_separate":true}},
    "checks":{"type":"array","minItems":10,"maxItems":10,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"PASS_25_MERGED_LAUNCHER_SCHEMAS_FOR_OVERLAY_REPLAY_ONLY"},
    "accepted_scope":{"const":["LAUNCHER_OVERLAY_REPLAY_INPUT_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "registry_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

`source_registry` is the accepted launcher's exact 25-row schema registry as a
legacy accepted identity. `rows` preserve that ordinal roster. For each source
basename `b`, the merged path is exactly
`review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/launcher_lineage_overlay_v1/schemas/b`.
All 25 source schemas contain the complete shared `$defs`; therefore the two
exact old path constants are replaced in each (50 total), the pre-aggregate
closed object gains one exact rebind fragment in each (25 total), and each root
gets a fresh `$id` (25 total). Normalized AST diff permits exactly those 100
changes and nothing else. A source schema not yet accepted is not guessed; the
registry is authored only after all accepted source identities exist.

The accepted source-registry ordinal basenames, and therefore the merged
registry basenames, are exactly:

```text
00 program_facts_g3_00_parity_launcher_runtime_closure_amendment_review.v1.schema.json
01 program_facts_parity_runtime_build_plan_lock.v1.schema.json
02 program_facts_parity_runtime_build_plan_lock_review.v1.schema.json
03 program_facts_parity_runtime_closure.v2.schema.json
04 program_facts_parity_runtime_closure_review.v1.schema.json
05 program_facts_parity_source_review.v1.schema.json
06 program_facts_parity_candidate.v2.schema.json
07 program_facts_parity_evidence.v2.schema.json
08 program_facts_parity_completion.v2.schema.json
09 program_facts_parity_scenario_manifest.v1.schema.json
10 program_facts_parity_scenario_execution_evidence.v1.schema.json
11 program_facts_parity_launcher_implementation_review.v1.schema.json
12 program_facts_parity_transaction_journal.v2.schema.json
13 program_facts_parity_staged_marker.v2.schema.json
14 program_facts_parity_transaction_lock.v2.schema.json
15 program_facts_parity_coordination_lock_quarantine.v1.schema.json
16 program_facts_parity_quarantine.v2.schema.json
17 program_facts_parity_quarantine_locator.v1.schema.json
18 program_facts_parity_transaction_head.v2.schema.json
19 program_facts_parity_attempt.v2.schema.json
20 program_facts_parity_native_image_receipt.v2.schema.json
21 program_facts_parity_vector_bundle_candidate.v1.schema.json
22 program_facts_parity_vector_bundle_capture_receipt.v1.schema.json
23 program_facts_parity_vector_capture_transaction.v2.schema.json
24 program_facts_parity_pre_aggregate_lineage.v1.schema.json
```

For each basename, the source and merged paths are respectively the accepted
launcher registry path and `merged_root || basename`. A missing, extra,
reordered, differently cased, or Unicode-distinct basename is a blocking replay
failure.

The replay evidence root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","evidence_id","rebind","merged_registry","scenario_manifest","harness","launcher_implementation","launcher_scenario_replay","source_selection_replay","executor","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","evidence_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_launcher_lineage_overlay_replay.v1"},
    "evidence_id":{"type":"string","pattern":"^pfg3lor-[0-9a-f]{32}$"},
    "rebind":{"$ref":"#/$defs/file_published_ref"},
    "merged_registry":{"$ref":"#/$defs/file_published_ref"},
    "scenario_manifest":{"$ref":"#/$defs/file_published_ref"},
    "harness":{"$ref":"#/$defs/file_published_ref"},
    "launcher_implementation":{"$ref":"#/$defs/file_published_ref"},
    "launcher_scenario_replay":{"const":{"scenario_count":47,"subcase_count":488,"executed_scenario_count":47,"executed_subcase_count":488,"unexpected_pass_count":0,"unexpected_fail_count":0,"setup_error_count":0,"scenario_bytes_unchanged":true}},
    "source_selection_replay":{"type":"object","additionalProperties":false,"required":["case_ids","case_count","executed_count","unexpected_count","results"],"properties":{"case_ids":{"const":["ALC-01","ALC-02","ALC-03","ALC-11","ALC-12"]},"case_count":{"const":5},"executed_count":{"const":5},"unexpected_count":{"const":0},"results":{"const":["PASS_EXPECTED_REJECTION","PASS_EXPECTED_REJECTION","PASS_EXPECTED_REJECTION","PASS_EXPECTED_REJECTION","PASS_EXPECTED_REJECTION"]}}},
    "executor":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"executor_separate_from_launcher_implementer":true,"executor_separate_from_overlay_renderer":true,"no_self_generated_evidence":true,"overlay_reviewer_separate":true}},
    "checks":{"type":"array","minItems":7,"maxItems":7,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"PASS_LAUNCHER_OVERLAY_REPLAY_FOR_INDEPENDENT_REVIEW_ONLY"},
    "accepted_scope":{"const":["INDEPENDENT_OVERLAY_REVIEW_INPUT_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "evidence_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The overlay review has the ordinary closed review envelope plus exact fields
`subject_rebind:file_published_ref`, `merged_registry:file_published_ref`, and
`replay:file_published_ref`; 12 ordered checks are
`LOR-01-LAUNCHER-REVIEW`, `LOR-02-CROSSCHECK-REFERENCE`,
`LOR-03-TRANSFORM-CENSUS`, `LOR-04-SCHEMA-25-BIJECTION`,
`LOR-05-REF-CLOSURE`, `LOR-06-47-SCENARIO-REPLAY`,
`LOR-07-488-SUBCASE-REPLAY`, `LOR-08-FIVE-SOURCE-SELECTION-CASES`,
`LOR-09-V2-NONENABLING`, `LOR-10-PROJECTION-FRAGMENT-EQUALITY`,
`LOR-11-INDEPENDENCE`, and `LOR-12-AUTHORITY-PART0`. Its only passing
disposition is `PASS_LAUNCHER_LINEAGE_OVERLAY_FOR_NATIVE_AND_PARITY_EXECUTION_ONLY`;
scope is `['NATIVE_RECEIPT_AND_PARITY_EXECUTION_PREDECESSOR_ONLY']`; all 29
authority bits remain false. Its schema is the section-1 common closed review
shape plus these three required fields and exact constants; no optional field
or prose evidence is permitted.

All four identities use the section-1 generic formula with prefixes/domains
`pfg3lrb-/PROGRAM_FACTS_G3_00_LAUNCHER_LINEAGE_REBIND_V1`,
`pfg3lmr-/PROGRAM_FACTS_G3_00_LAUNCHER_MERGED_SCHEMA_REGISTRY_V1`,
`pfg3lor-/PROGRAM_FACTS_G3_00_LAUNCHER_OVERLAY_REPLAY_V1`, and
`pfg3lov-/PROGRAM_FACTS_G3_00_LAUNCHER_OVERLAY_REVIEW_V1`, respectively.

The exact overlay-review root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject_rebind","merged_registry","replay","reviewer","independence","checks","findings","open_findings","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_launcher_lineage_overlay_review.v1"},
    "review_id":{"type":"string","pattern":"^pfg3lov-[0-9a-f]{32}$"},
    "subject_rebind":{"$ref":"#/$defs/file_published_ref"},
    "merged_registry":{"$ref":"#/$defs/file_published_ref"},
    "replay":{"$ref":"#/$defs/file_published_ref"},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"crosscheck_resolver_separate":true,"launcher_authors_and_implementer_separate":true,"no_self_generated_evidence":true,"overlay_renderer_and_validator_separate":true,"replay_executor_separate":true,"reviewer_separate_from_all_subject_principals":true,"workspace_clean":true}},
    "checks":{"type":"array","minItems":12,"maxItems":12,"items":{"$ref":"#/$defs/pass_check"}},
    "findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/finding"}},
    "open_findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "disposition":{"const":"PASS_LAUNCHER_LINEAGE_OVERLAY_FOR_NATIVE_AND_PARITY_EXECUTION_ONLY"},
    "accepted_scope":{"const":["NATIVE_RECEIPT_AND_PARITY_EXECUTION_PREDECESSOR_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "review_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

### 15.4 Exact launcher projection and native-host receipt v2

The native receipt no longer summarizes launcher state. During schema rendering,
the builder extracts the normalized `$defs/vector_capture_host_receipt` and
`$defs/host_receipt` fragments from every one of the 25 merged schemas, proves
all 25 copies byte-identical for each name, and copies those two exact closed
fragments into the native-receipt-v2 schema under names
`launcher_vector_capture_projection` and `launcher_parity_projection`. This
mechanical copy is part of the schema byte preimage; an independently chosen
lookalike schema or digest-only substitute is invalid.

Thus the rendered schema's exact `launcher_projection` definition is:

```json
{
  "oneOf":[
    {"type":"object","additionalProperties":false,"required":["projection_kind","projection"],"properties":{"projection_kind":{"const":"VECTOR_CAPTURE_HOST_RECEIPT"},"projection":{"$ref":"#/$defs/launcher_vector_capture_projection"}}},
    {"type":"object","additionalProperties":false,"required":["projection_kind","projection"],"properties":{"projection_kind":{"const":"PARITY_HOST_RECEIPT"},"projection":{"$ref":"#/$defs/launcher_parity_projection"}}}
  ]
}
```

The two `projection` values validate against the copied launcher fragments
without augmentation, omission, or relaxed keywords. The wrapper contributes
only the disjoint tag and is itself closed. `VECTOR_CAPTURE` selects the first
branch; `GENERATOR`, `EVALUATOR`, and `CROSSCHECK` select the second. Semantic
validation rejects a tag/role disagreement even if the inner JSON happens to
validate against both source fragments.

The copied VECTOR_CAPTURE branch literally includes the merged launcher's full
base-snapshot projection, base entry validation, capture-source binding,
authenticated source-frame identity, bootstrap binding, exact framing contract,
complete quarantine-move profile, network denial, write confinement, child-
creation denial, and process-tree observation support. The copied parity branch
literally includes the full input-snapshot/candidate-set projection, snapshot
entry validation, complete role-readable member view and source-denial
projection, exact bootstrap protocol, and complete quarantine-move profile.
Neither branch contains a summary boolean in place of a nested projection.

The native-host receipt v2 root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","receipt_id","receipt_kind","role","launcher_overlay_review","merged_schema_registry","runtime_closure","runtime_closure_review","host_profile","launcher_projection","launcher_projection_body_sha256","projection_schema_evidence","native_observation","executor","validator","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","receipt_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_parity_native_host_receipt.v2"},
    "receipt_id":{"type":"string","pattern":"^pfg3nhr2-[0-9a-f]{32}$"},
    "receipt_kind":{"const":"EXACT_MERGED_LAUNCHER_PROJECTION_NATIVE_HOST_OBSERVATION"},
    "role":{"enum":["VECTOR_CAPTURE","GENERATOR","EVALUATOR","CROSSCHECK"]},
    "launcher_overlay_review":{"$ref":"#/$defs/file_published_ref"},
    "merged_schema_registry":{"$ref":"#/$defs/file_published_ref"},
    "runtime_closure":{"$ref":"#/$defs/file_published_ref"},
    "runtime_closure_review":{"$ref":"#/$defs/file_published_ref"},
    "host_profile":{"type":"object","additionalProperties":false,"required":["host_profile_id","os_family","os_version","os_build","architecture","filesystem_profile","quarantine_move_profile_id"],"properties":{"host_profile_id":{"type":"string","pattern":"^pfg3hp-[0-9a-f]{32}$"},"os_family":{"enum":["WINDOWS","LINUX","MACOS"]},"os_version":{"type":"string","minLength":1,"maxLength":256},"os_build":{"type":"string","minLength":1,"maxLength":256},"architecture":{"type":"string","minLength":1,"maxLength":64},"filesystem_profile":{"type":"string","minLength":1,"maxLength":256},"quarantine_move_profile_id":{"type":"string","pattern":"^pfg3qmpf-[0-9a-f]{32}$"}}},
    "launcher_projection":{"$ref":"#/$defs/launcher_projection"},
    "launcher_projection_body_sha256":{"$ref":"#/$defs/hex64"},
    "projection_schema_evidence":{"type":"object","additionalProperties":false,"required":["merged_schema_count","vector_fragment_sha256","parity_fragment_sha256","all_merged_fragments_equal","receipt_schema_copies_exact"],"properties":{"merged_schema_count":{"const":25},"vector_fragment_sha256":{"$ref":"#/$defs/hex64"},"parity_fragment_sha256":{"$ref":"#/$defs/hex64"},"all_merged_fragments_equal":{"const":true},"receipt_schema_copies_exact":{"const":true}}},
    "native_observation":{"type":"object","additionalProperties":false,"required":["observation_source","attempt_ordinal","authenticated_launch_token","process_image_identity_sha256","pre_spawn_projection_equal","post_spawn_projection_equal","post_process_tree_projection_equal","stable_observation_reads","observation_body_sha256"],"properties":{"observation_source":{"$ref":"#/$defs/file_published_ref"},"attempt_ordinal":{"$ref":"#/$defs/z20"},"authenticated_launch_token":{"$ref":"#/$defs/hex64"},"process_image_identity_sha256":{"$ref":"#/$defs/hex64"},"pre_spawn_projection_equal":{"const":true},"post_spawn_projection_equal":{"const":true},"post_process_tree_projection_equal":{"const":true},"stable_observation_reads":{"const":3},"observation_body_sha256":{"$ref":"#/$defs/hex64"}}},
    "executor":{"$ref":"#/$defs/principal"},
    "validator":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"executor_separate_from_validator":true,"launcher_authors_and_implementer_separate":true,"native_validator_separate":true,"no_self_generated_evidence":true,"overlay_principals_separate":true,"producer_source_authors_separate":true,"runtime_builder_separate":true}},
    "checks":{"type":"array","minItems":14,"maxItems":14,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"PASS_EXACT_MERGED_LAUNCHER_NATIVE_HOST_PROJECTION_ONLY"},
    "accepted_scope":{"const":["ONE_EXACT_ROLE_HOST_AND_LAUNCHER_PROJECTION_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "receipt_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The exact projection preimage is:

```text
launcher_projection_body_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_NATIVE_HOST_LAUNCHER_PROJECTION_V2",
  role:<role>,
  merged_schema_registry:<file_published_ref>,
  launcher_projection:<complete parsed launcher_projection>
}))
```

The receipt itself uses prefix/domain
`pfg3nhr2-/PROGRAM_FACTS_G3_00_NATIVE_HOST_RECEIPT_V2`. Consumers receive the
receipt only as a `file_published_ref`, including arm and enabling completion;
no bare receipt identity is sufficient. The exact 14 checks are
`NHR2-01-OVERLAY-REVIEW`, `NHR2-02-MERGED-REGISTRY`,
`NHR2-03-RUNTIME-CLOSURE`, `NHR2-04-HOST-PROFILE`,
`NHR2-05-LITERAL-PROJECTION-SCHEMA`, `NHR2-06-PROJECTION-DIGEST`,
`NHR2-07-BASE-OR-INPUT-SNAPSHOT`, `NHR2-08-ENTRY-VALIDATION`,
`NHR2-09-FRAMING-OR-BOOTSTRAP`, `NHR2-10-ISOLATION-READABLE-VIEW`,
`NHR2-11-QUARANTINE-PROFILE`, `NHR2-12-AUTHENTICATED-OBSERVATION`,
`NHR2-13-ROLE-PATH-BIJECTION`, and `NHR2-14-INDEPENDENCE-NONAUTHORITY`.

VECTOR_CAPTURE still precedes the fourth capture; the other three receipts
follow the derived snapshot and precede their role transactions. Each receipt's
role must match its exact v2 path. A digest match without full parsed-value
equality to the copied launcher fragment rejects.

### 15.5 Pre-aggregate lineage v3

Pre-aggregate v3 uses only disjoint reference types. Its exact root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","lineage_id","legacy_parity_requirements","launcher_overlay_review","crosscheck_reference","native_receipts","role_lineages","common_parity_projection","reviewer","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","lineage_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_parity_pre_aggregate_lineage.v3"},
    "lineage_id":{"type":"string","pattern":"^pfg3lin3-[0-9a-f]{32}$"},
    "legacy_parity_requirements":{"type":"array","minItems":3,"maxItems":3,"uniqueItems":true,"items":{"$ref":"#/$defs/legacy_accepted_ref"}},
    "launcher_overlay_review":{"$ref":"#/$defs/file_published_ref"},
    "crosscheck_reference":{"$ref":"#/$defs/file_published_ref"},
    "native_receipts":{"type":"array","minItems":4,"maxItems":4,"prefixItems":[{"$ref":"#/$defs/file_published_ref"},{"$ref":"#/$defs/file_published_ref"},{"$ref":"#/$defs/file_published_ref"},{"$ref":"#/$defs/file_published_ref"}],"items":false},
    "role_lineages":{"type":"array","minItems":3,"maxItems":3,"items":{"type":"object","additionalProperties":false,"required":["role","successor_source","source_review","native_receipt","evidence","completion","parity_projection_sha256","crosscheck_marker"],"properties":{"role":{"enum":["GENERATOR","EVALUATOR","CROSSCHECK"]},"successor_source":{"oneOf":[{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/file_published_ref"}]},"source_review":{"oneOf":[{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/file_published_ref"}]},"native_receipt":{"$ref":"#/$defs/file_published_ref"},"evidence":{"$ref":"#/$defs/file_published_ref"},"completion":{"$ref":"#/$defs/file_published_ref"},"parity_projection_sha256":{"$ref":"#/$defs/hex64"},"crosscheck_marker":{"oneOf":[{"type":"null"},{"$ref":"#/$defs/file_published_ref"}]}}}},
    "common_parity_projection":{"type":"object","additionalProperties":false,"required":["parity_body_sha256","all_three_parsed_values_equal","all_three_cj_bytes_equal","accepted_v1_projection_equal"],"properties":{"parity_body_sha256":{"$ref":"#/$defs/hex64"},"all_three_parsed_values_equal":{"const":true},"all_three_cj_bytes_equal":{"const":true},"accepted_v1_projection_equal":{"const":true}}},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"crosscheck_resolver_separate":true,"launcher_overlay_principals_separate":true,"native_host_principals_separate":true,"no_self_generated_evidence":true,"pre_aggregate_reviewer_separate":true,"transaction_executors_separate":true}},
    "checks":{"type":"array","minItems":11,"maxItems":11,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"PASS_PRE_AGGREGATE_V3_REBOUND_LINEAGE_ONLY"},
    "accepted_scope":{"const":["SCHEMA_ROOT_PROMOTION_PREDECESSOR_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "lineage_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

Semantic validation fixes role order GENERATOR, EVALUATOR, CROSSCHECK; native
receipt order VECTOR_CAPTURE, GENERATOR, EVALUATOR, CROSSCHECK. Generator and
evaluator use their accepted legacy sources/reviews without retroactive
completion. CROSSCHECK must use the exact file-published source-v3,
source-review-v3, and marker-v4 values from the r2 crosscheck reference.
`crosscheck_marker` is null for the first two and exact marker-v4 for the third.
All evidence/completion objects are new file-published references. The 11 checks
are `LIN3-01-LEGACY-REQUIREMENTS`, `LIN3-02-OVERLAY-REVIEW`,
`LIN3-03-CROSSCHECK-REFERENCE`, `LIN3-04-FOUR-NATIVE-RECEIPTS`,
`LIN3-05-THREE-ROLE-TRANSACTIONS`, `LIN3-06-CROSSCHECK-V3-SOURCE`,
`LIN3-07-CROSSCHECK-V4-MARKER`, `LIN3-08-PARITY-BYTE-EQUALITY`,
`LIN3-09-NO-RETROACTIVE-COMPLETIONS`, `LIN3-10-ACYCLIC-JOINS`, and
`LIN3-11-INDEPENDENCE-NONAUTHORITY`. Prefix/domain are
`pfg3lin3-/PROGRAM_FACTS_G3_PARITY_PRE_AGGREGATE_LINEAGE_V3`.

### 15.6 Cycle-free atomic schema-contract root

The exact final root remains
`review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/`; its exact
same-parent stage is
`review_fixtures/program_facts_runtime_gate3/.__pfg3_schema_contracts_v2.stage/`.
The 24 vector/review final paths are exactly the section-7 list. Their staged
paths are obtained only by replacing the final root prefix with the stage-root
prefix. The 25th member is the root manifest; its final path is:

```text
review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/PROGRAM_FACTS_G3_00_SCHEMA_CONTRACT_ROOT_MANIFEST.v1.json
```

The manifest root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","manifest_id","final_root","staged_root","pre_aggregate_lineage","crosscheck_reference","members","member_count","member_tree_sha256","pre_manifest_staged_tree_identity_sha256","builder","validator","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","manifest_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_schema_contract_root_manifest.v1"},
    "manifest_id":{"type":"string","pattern":"^pfg3srm-[0-9a-f]{32}$"},
    "final_root":{"const":"review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/"},
    "staged_root":{"const":"review_fixtures/program_facts_runtime_gate3/.__pfg3_schema_contracts_v2.stage/"},
    "pre_aggregate_lineage":{"$ref":"#/$defs/file_published_ref"},
    "crosscheck_reference":{"$ref":"#/$defs/file_published_ref"},
    "members":{"type":"array","minItems":24,"maxItems":24,"uniqueItems":true,"items":{"type":"object","additionalProperties":false,"required":["ordinal","kind","staged_relative_path","final_identity","staged_native_identity_sha256"],"properties":{"ordinal":{"type":"integer","minimum":0,"maximum":23},"kind":{"enum":["CONFORMANCE_VECTORS","INDEPENDENT_REVIEW"]},"staged_relative_path":{"$ref":"#/$defs/safe_path"},"final_identity":{"$ref":"#/$defs/file_identity"},"staged_native_identity_sha256":{"$ref":"#/$defs/hex64"}}}},
    "member_count":{"const":24},
    "member_tree_sha256":{"$ref":"#/$defs/hex64"},
    "pre_manifest_staged_tree_identity_sha256":{"$ref":"#/$defs/hex64"},
    "builder":{"$ref":"#/$defs/principal"},
    "validator":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"aggregate_principals_separate":true,"builder_separate_from_validator":true,"no_self_generated_evidence":true,"promotion_reviewer_separate":true,"schema_vector_review_principals_separate":true}},
    "checks":{"type":"array","minItems":10,"maxItems":10,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"COMPLETE_STAGED_24_MEMBER_ROOT_MANIFEST_NOT_YET_PROMOTED"},
    "accepted_scope":{"const":["DIRECTORY_ROOT_PUBLISH_ARM_INPUT_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "manifest_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

`members` is exact section-7 path order. Every final path is under the final
root; every staged relative path resolves under the stage root to the same
relative spelling. `member_tree_sha256` hashes exactly the 24
`CJ({ordinal,kind,final_identity})||LF` rows. It excludes the manifest and thus
has no cycle. `pre_manifest_staged_tree_identity_sha256` hashes exactly the
24-member native staged tree before the manifest is written. The later arm
observes the complete 25-member staged tree after manifest bytes are fixed and
calls that value
`complete_staged_tree_identity_sha256`. No field can hash bytes containing
itself.

The root publish arm, written outside the staged root before the native rename,
is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","arm_id","root_manifest","staged_root","final_root","complete_staged_census","complete_staged_tree_identity_sha256","native_profile","publisher_binding","arm_state","publisher","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","arm_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_schema_contract_root_publish_arm.v1"},
    "arm_id":{"type":"string","pattern":"^pfg3sra-[0-9a-f]{32}$"},
    "root_manifest":{"$ref":"#/$defs/file_identity"},
    "staged_root":{"$ref":"#/$defs/directory_root_identity"},
    "final_root":{"type":"object","const":{"path":"review_fixtures/program_facts_runtime_gate3/schema_contracts_v2/","expected_member_count":25,"expected_directory_count":13}},
    "complete_staged_census":{"const":{"member_count":25,"directory_count":13,"missing_count":0,"extra_count":0,"nonregular_count":0}},
    "complete_staged_tree_identity_sha256":{"$ref":"#/$defs/hex64"},
    "native_profile":{"type":"object","additionalProperties":false,"required":["os_family","primitive","same_parent","same_volume","no_replace","retained_source_handle","retained_destination_parent_handle","source_barrier_before","source_and_destination_barrier_after","copy_delete_fallback"],"properties":{"os_family":{"enum":["WINDOWS","LINUX","MACOS"]},"primitive":{"enum":["WINDOWS_FILE_RENAME_INFO_EX_FLAGS_ZERO_V1","LINUX_RENAMEAT2_NOREPLACE_DIRFD_V1","MACOS_RENAMEATX_NP_EXCL_DIRFD_V1"]},"same_parent":{"const":true},"same_volume":{"const":true},"no_replace":{"const":true},"retained_source_handle":{"const":true},"retained_destination_parent_handle":{"const":true},"source_barrier_before":{"const":true},"source_and_destination_barrier_after":{"const":true},"copy_delete_fallback":{"const":false}}},
    "publisher_binding":{"type":"object","additionalProperties":false,"required":["publisher_source","runtime","executable","executor","launch_token"],"properties":{"publisher_source":{"$ref":"#/$defs/legacy_accepted_ref"},"runtime":{"$ref":"#/$defs/legacy_accepted_ref"},"executable":{"$ref":"#/$defs/file_identity"},"executor":{"$ref":"#/$defs/principal"},"launch_token":{"$ref":"#/$defs/hex64"}}},
    "arm_state":{"const":"DURABLE_BEFORE_DIRECTORY_RENAME"},
    "publisher":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"manifest_builder_separate":true,"no_self_generated_evidence":true,"promotion_reviewer_separate":true,"publisher_separate_from_manifest_validator":true}},
    "checks":{"type":"array","minItems":10,"maxItems":10,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"DURABLE_ARM_FOR_ONE_EXACT_ATOMIC_DIRECTORY_PUBLICATION"},
    "accepted_scope":{"const":["ONE_NO_REPLACE_DIRECTORY_RENAME_ATTEMPT_OR_EXACT_RECOVERY_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "arm_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The arm is itself published as a new file before directory rename. The directory
transport completion is written only after a live native success or a unique
arm-bound crash poststate:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","completion_id","root_publish_arm","root_manifest","final_root","native_result","completion_grade","poststate_reads","identity_join","directory_barriers","publisher","validator","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","completion_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_directory_transport_completion.v1"},
    "completion_id":{"type":"string","pattern":"^pfg3dtc-[0-9a-f]{32}$"},
    "root_publish_arm":{"$ref":"#/$defs/file_published_ref"},
    "root_manifest":{"$ref":"#/$defs/file_identity"},
    "final_root":{"$ref":"#/$defs/directory_root_identity"},
    "native_result":{"type":"object","additionalProperties":false,"required":["mode","api","result_kind","result_code","launch_token"],"properties":{"mode":{"enum":["LIVE","RECOVERY"]},"api":{"enum":["SetFileInformationByHandle/FileRenameInfoEx","renameat2","renameatx_np"]},"result_kind":{"enum":["AUTHENTICATED_SUCCESS_RETURN","ARM_BOUND_UNIQUE_RECOVERY"]},"result_code":{"type":["integer","string"]},"launch_token":{"$ref":"#/$defs/hex64"}}},
    "completion_grade":{"enum":["LIVE_REVIEWED_EXECUTION","CRASH_RECOVERED_UNIQUE_POSTSTATE"]},
    "poststate_reads":{"type":"array","minItems":3,"maxItems":3,"items":{"$ref":"#/$defs/directory_root_identity"}},
    "identity_join":{"const":{"complete_staged_tree_equals_final_tree":true,"final_manifest_equals_armed_manifest":true,"final_member_count":25,"final_directory_count":13,"pathless_root_identity_preserved":true,"source_stage_absent":true,"target_preexisted_before_arm":false}},
    "directory_barriers":{"const":{"destination_parent_durable":true,"source_parent_durable":true,"volume_barrier_if_required":true}},
    "publisher":{"$ref":"#/$defs/principal"},
    "validator":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"manifest_principals_separate":true,"no_self_generated_evidence":true,"promotion_reviewer_separate":true,"publisher_separate_from_validator":true}},
    "checks":{"type":"array","minItems":12,"maxItems":12,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"ATOMIC_DIRECTORY_ROOT_TRANSPORT_COMPLETE_NOT_SEMANTICALLY_ADMITTED"},
    "accepted_scope":{"const":["PROMOTION_INDEPENDENT_REVIEW_INPUT_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "completion_body_sha256":{"$ref":"#/$defs/hex64"}
  },
  "allOf":[{"if":{"properties":{"completion_grade":{"const":"LIVE_REVIEWED_EXECUTION"}},"required":["completion_grade"]},"then":{"properties":{"native_result":{"properties":{"mode":{"const":"LIVE"},"result_kind":{"const":"AUTHENTICATED_SUCCESS_RETURN"}}}}}},{"if":{"properties":{"completion_grade":{"const":"CRASH_RECOVERED_UNIQUE_POSTSTATE"}},"required":["completion_grade"]},"then":{"properties":{"native_result":{"properties":{"mode":{"const":"RECOVERY"},"result_kind":{"const":"ARM_BOUND_UNIQUE_RECOVERY"}}}}}}]
}
```

The independent promotion review root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","directory_transport_completion","root_publish_arm","final_root","root_manifest","reopened_members","recomputed_member_tree_sha256","recomputed_complete_tree_sha256","reviewer","independence","checks","findings","open_findings","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_schema_contract_promotion_review.v1"},
    "review_id":{"type":"string","pattern":"^pfg3spr-[0-9a-f]{32}$"},
    "directory_transport_completion":{"$ref":"#/$defs/file_published_ref"},
    "root_publish_arm":{"$ref":"#/$defs/file_published_ref"},
    "final_root":{"$ref":"#/$defs/directory_root_identity"},
    "root_manifest":{"$ref":"#/$defs/file_identity"},
    "reopened_members":{"type":"array","minItems":25,"maxItems":25,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}},
    "recomputed_member_tree_sha256":{"$ref":"#/$defs/hex64"},
    "recomputed_complete_tree_sha256":{"$ref":"#/$defs/hex64"},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"directory_publisher_separate":true,"manifest_builder_and_validator_separate":true,"no_self_generated_evidence":true,"reviewer_separate_from_all_vector_and_review_authors":true,"workspace_clean":true}},
    "checks":{"type":"array","minItems":14,"maxItems":14,"items":{"$ref":"#/$defs/pass_check"}},
    "findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/finding"}},
    "open_findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "disposition":{"const":"PASS_ATOMIC_25_FILE_SCHEMA_CONTRACT_ROOT_FOR_G3_00_MANIFEST_ONLY"},
    "accepted_scope":{"const":["G3_00_ADMISSION_MANIFEST_ROOT_PREDECESSOR_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "review_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The review reopens the 24 members in manifest order then the manifest as ordinal
24. It recomputes the 24-row member digest and the complete 25-file native tree
digest, proves the root no-replace result, final-root physical identity, arm and
completion joins, all vector/review schemas and formulas, and zero extra,
missing, nonregular, alias, mount, or case/Unicode-collision entries. Admission
constructs exactly:

```text
{
  reference_kind:"ATOMIC_DIRECTORY_ROOT_PUBLICATION",
  root:<final directory_root_identity>,
  internal_root_manifest:<final manifest file_identity>,
  directory_transport_completion:<file_published_ref>,
  independent_promotion_review:<file_published_ref>
}
```

The 24 staged vector/review members and the internal manifest are deliberately
exempt from per-file arm/completion sidecars: they are never individually
published and become visible only at the one directory-rename linearization
point. The external root arm, transport completion, and promotion review are
ordinary file publications with their own r2 arm/completion records. A set of
25 loose `file_published_ref` objects cannot substitute for the directory root.

The finite root transport path set is exactly 25 final members, 25 staged
members, one external root-arm final, one external directory-completion final,
one external promotion-review final, and the formula-derived file-publication
attempt prefixes for those three external files. No other stage, backup,
quarantine, head, marker, or recovery path exists. Each external file uses
contiguous `Z20` attempts; the materialized count is `53 + 3 + 5*SUM(A[1..3])`:
53 semantic/staged members, three inert leases, and five attempt leaves per
materialized attempt. Paths are derived only from the three exact final paths
and accepted r2 stem formula; no scan is permitted.

Crash closure is exact:

| Observed state | Result |
|---|---|
| stage incomplete or manifest absent | nonenabling debt; no arm and no rename |
| complete stage, no valid external arm | nonenabling debt; no rename |
| valid arm, stage exact, final absent | execute the one native no-replace rename |
| valid arm, stage absent, final exact/pathless-identical | unique recovery may create completion after barriers and three reads |
| final exists before arm or differs from arm | terminal collision/debt; never equality-adopt |
| both stage and final exist | ambiguous/terminal; no completion |
| completion exists but promotion review absent | transport-only, not an admission root |
| promotion review valid | construct the directory-published-root reference |

Prefix-append repair applies only to already determined canonical external JSON
record bytes, never to directory members or semantic payloads. Nothing is
deleted, overwritten, backfilled, or renamed to an alternate root.

Root identities use prefixes/domains `pfg3srm-/PROGRAM_FACTS_G3_00_SCHEMA_ROOT_MANIFEST_V1`,
`pfg3sra-/PROGRAM_FACTS_G3_00_SCHEMA_ROOT_PUBLISH_ARM_V1`,
`pfg3dtc-/PROGRAM_FACTS_G3_00_DIRECTORY_TRANSPORT_COMPLETION_V1`, and
`pfg3spr-/PROGRAM_FACTS_G3_00_SCHEMA_ROOT_PROMOTION_REVIEW_V1` under the generic
identity/body formula.

### 15.7 Immutable successor public-v3 and seed reviews r3

The rejected candidate's v2 review paths remain absent and non-enabling. The r3
paths in section 15.1 are create-only. Both review roots use
`legacy_accepted_ref` for frozen predecessors and `file_published_ref` for new
review/schema artifacts; neither permits `directory_published_root_ref`.

The public-v3 review r3 root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject_kind","subjects","input_artifacts","vectors","findings","open_findings","reviewer","independence","historical_review","launcher_overlay_review","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_public_v3_architecture_review.v3"},
    "review_id":{"type":"string","pattern":"^pfg3pvr3-[0-9a-f]{32}$"},
    "subject_kind":{"const":"PUBLIC_V3_ARCHITECTURE_SUCCESSOR_R3"},
    "subjects":{"type":"array","minItems":8,"maxItems":8,"uniqueItems":true,"items":{"oneOf":[{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/file_published_ref"}]}},
    "input_artifacts":{"type":"array","minItems":9,"maxItems":100,"uniqueItems":true,"items":{"oneOf":[{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/file_published_ref"}]}},
    "vectors":{"type":"array","minItems":8,"maxItems":8,"items":{"$ref":"#/$defs/review_vector"}},
    "findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/finding"}},
    "open_findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"launcher_overlay_reviewer_separate":true,"no_self_generated_evidence":true,"production_implementer_separate":true,"provider_author_separate":true,"schema_authors_separate":true,"subject_authors_separate":true,"workspace_clean":true}},
    "historical_review":{"$ref":"#/$defs/legacy_accepted_ref"},
    "launcher_overlay_review":{"$ref":"#/$defs/file_published_ref"},
    "disposition":{"enum":["PASS_PUBLIC_V3_SHADOW_CONTRACT_ONLY","REJECTED"]},
    "accepted_scope":{"const":["PUBLIC_V3_SHADOW_SUCCESSOR_R3_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "review_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The exact vector order is the seven section-4.1 IDs followed by
`ARCH-V3-08-LAUNCHER-LINEAGE-OVERLAY`. `subjects` remains graph-v2, OWN-v2,
and the six rebuilt public schemas in the predecessor order. The historical v1
review is preserved as a legacy accepted reference with no completion. The r3
review is new and requires its own file arm/completion.

The compact-seed review r3 root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject_kind","subject","input_artifacts","vectors","findings","open_findings","reviewer","independence","historical_review","public_v3_review_r3","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_r19_compact_seed_admission_review.v3"},
    "review_id":{"type":"string","pattern":"^pfg3csr3-[0-9a-f]{32}$"},
    "subject_kind":{"const":"SEED_ADMISSION_SUCCESSOR_R3"},
    "subject":{"$ref":"#/$defs/legacy_accepted_ref"},
    "input_artifacts":{"type":"array","minItems":9,"maxItems":100,"uniqueItems":true,"items":{"oneOf":[{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/file_published_ref"}]}},
    "vectors":{"type":"array","minItems":7,"maxItems":7,"items":{"$ref":"#/$defs/review_vector"}},
    "findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/finding"}},
    "open_findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"no_self_generated_evidence":true,"oracle_author_separate":true,"production_implementer_separate":true,"public_v3_reviewer_separate":true,"subject_author_separate":true,"workspace_clean":true}},
    "historical_review":{"$ref":"#/$defs/legacy_accepted_ref"},
    "public_v3_review_r3":{"$ref":"#/$defs/file_published_ref"},
    "disposition":{"enum":["PASS_R19_SEED_ADMISSION_FOR_CONTRACT_FREEZE_ONLY","REJECTED"]},
    "accepted_scope":{"const":["COMPACT_SEED_SUCCESSOR_R3_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "review_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

Its exact vector order is the six section-4.2 IDs followed by
`SEED-ADM-07-PUBLIC-V3-R3-AND-NO-LEGACY-BACKFILL`. Prefix/domains are
`pfg3pvr3-/PROGRAM_FACTS_PUBLIC_V3_ARCHITECTURE_REVIEW_V3` and
`pfg3csr3-/PROGRAM_FACTS_R19_COMPACT_SEED_ADMISSION_REVIEW_V3`.

### 15.8 Admission manifest and aggregate review v3

The manifest-v3 root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","predecessors","successor_reviews","launcher_lineage","crosscheck_reference","native_receipts","pre_aggregate_lineage","schema_contract_root","schema_contracts","schema_contract_count","carrier_template","provider_registry","phase_io_contracts","public_v3_schemas","part_0_genericity","authority_ceiling","publication_requirements","admission_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_manifest.v3"},
    "predecessors":{"type":"array","minItems":17,"maxItems":17,"uniqueItems":true,"prefixItems":[{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/file_published_ref"},{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/file_published_ref"},{"$ref":"#/$defs/legacy_accepted_ref"},{"$ref":"#/$defs/file_published_ref"}],"items":false},
    "successor_reviews":{"type":"object","additionalProperties":false,"required":["public_v3_review_r3","compact_seed_review_r3"],"properties":{"public_v3_review_r3":{"$ref":"#/$defs/file_published_ref"},"compact_seed_review_r3":{"$ref":"#/$defs/file_published_ref"}}},
    "launcher_lineage":{"type":"object","additionalProperties":false,"required":["rebind","merged_registry","replay","overlay_review"],"properties":{"rebind":{"$ref":"#/$defs/file_published_ref"},"merged_registry":{"$ref":"#/$defs/file_published_ref"},"replay":{"$ref":"#/$defs/file_published_ref"},"overlay_review":{"$ref":"#/$defs/file_published_ref"}}},
    "crosscheck_reference":{"$ref":"#/$defs/file_published_ref"},
    "native_receipts":{"type":"array","minItems":4,"maxItems":4,"prefixItems":[{"$ref":"#/$defs/file_published_ref"},{"$ref":"#/$defs/file_published_ref"},{"$ref":"#/$defs/file_published_ref"},{"$ref":"#/$defs/file_published_ref"}],"items":false},
    "pre_aggregate_lineage":{"$ref":"#/$defs/file_published_ref"},
    "schema_contract_root":{"$ref":"#/$defs/directory_published_root_ref"},
    "schema_contracts":{"type":"array","minItems":12,"maxItems":12,"uniqueItems":true,"items":{"type":"object","additionalProperties":false,"required":["schema","schema_id","vectors","independent_review","accepted_stage","keyword_occurrence_count","coverage_atom_count","vector_count"],"properties":{"schema":{"$ref":"#/$defs/legacy_accepted_ref"},"schema_id":{"type":"string","minLength":1,"maxLength":512},"vectors":{"$ref":"#/$defs/file_identity"},"independent_review":{"$ref":"#/$defs/file_identity"},"accepted_stage":{"const":"G3_00"},"keyword_occurrence_count":{"type":"integer","minimum":0,"maximum":4294967295},"coverage_atom_count":{"type":"integer","minimum":0,"maximum":4294967295},"vector_count":{"type":"integer","minimum":0,"maximum":4294967295}}}},
    "schema_contract_count":{"const":12},
    "carrier_template":{"type":"object","additionalProperties":false,"required":["normalization_id","template_body_sha256"],"properties":{"normalization_id":{"const":"plamen.program_facts_gate3_schema_carrier_template.v1"},"template_body_sha256":{"$ref":"#/$defs/hex64"}}},
    "provider_registry":{"type":"object","additionalProperties":false,"required":["schema","registry"],"properties":{"schema":{"$ref":"#/$defs/legacy_accepted_ref"},"registry":{"$ref":"#/$defs/legacy_accepted_ref"}}},
    "phase_io_contracts":{"type":"array","minItems":2,"maxItems":2,"uniqueItems":true,"items":{"$ref":"#/$defs/legacy_accepted_ref"}},
    "public_v3_schemas":{"type":"array","minItems":6,"maxItems":6,"uniqueItems":true,"items":{"$ref":"#/$defs/legacy_accepted_ref"}},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "admission_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The 17 predecessor rows are fixed semantically and ordered: external seed
acceptance; compact seed admission; PF-R2; PF-R2 review; source census;
graph-v2; OWN-v2; schema-closure amendment; schema-closure amendment review;
vector clarification; vector clarification review; accepted launcher contract;
accepted launcher contract review; accepted crosscheck-v3-r2 contract; accepted
crosscheck-v3-r2 contract review; this r2 amendment; and this r2 amendment's
independent review. Positions 12, 14, and 16 are new file-publication references;
the other positions are immutable accepted contract/review identities with no
synthetic completion. No renderer correction or substitution step exists.
`schema_contracts` vector/review file identities must be exact members under the
directory root and equal the manifest's 24 members in both directions; they are
not independent file publications. The four native receipts and all launcher/
crosscheck lineage fields are parsed-value equal to their upstream artifacts.
The manifest never contains or predicts its aggregate review.

The aggregate-review-v3 root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject","reviewer","independence","checks","findings","open_findings","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_aggregate_review.v3"},
    "review_id":{"type":"string","pattern":"^pfg3ar3-[0-9a-f]{32}$"},
    "subject":{"$ref":"#/$defs/file_published_ref"},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"aggregate_subject_author_separate":true,"crosscheck_principals_separate":true,"launcher_overlay_principals_separate":true,"native_host_principals_separate":true,"no_self_generated_evidence":true,"promotion_principals_separate":true,"schema_and_vector_principals_separate":true,"successor_reviewers_separate":true,"workspace_clean":true}},
    "checks":{"type":"array","minItems":18,"maxItems":18,"items":{"$ref":"#/$defs/pass_check"}},
    "findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/finding"}},
    "open_findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "disposition":{"const":"PASS_G3_00_ADMISSION_V3_FOR_G3_01_ADOPTION_ONLY"},
    "accepted_scope":{"const":["AUTHOR_G3_01_ADOPTION_LINEAGE_V2_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "review_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

Its exact checks are predecessor lineage, carrier equality, schema denominator,
provider registry, PhaseIO/RACI/order, schema closure, vector replay, atom
coverage, per-schema independence, crosscheck-v3-r2 reference, launcher overlay,
47/488+5 replay, four native projections, pre-aggregate v3, atomic-root
transport, promotion review, successor public/seed reviews, and aggregate
reviewer/authority—18 in that order. Prefix/domain are
`pfg3ar3-/PROGRAM_FACTS_G3_00_AGGREGATE_REVIEW_V3`. Passing still grants no
admission authority bit; it permits only the next separately reviewed lineage.

### 15.9 Post-admission G3-01 adoption and create-only review v2

The frozen v1 construction-amendment review schema, path, bytes, and seven-check
denominator are immutable historical evidence. They are neither edited nor
backfilled. A new adoption lineage is authored only after manifest-v3 and
aggregate-review-v3 are valid. Its exact root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","adoption_id","g3_00_manifest","g3_00_aggregate_review","schema_contract_root","pre_aggregate_lineage","crosscheck_admission_reference","launcher_overlay_review","successor_reviews","g3_01_amendment","adopter","reviewer","independence","checks","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","adoption_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_01_adoption_lineage.v2"},
    "adoption_id":{"type":"string","pattern":"^pfg301ad2-[0-9a-f]{32}$"},
    "g3_00_manifest":{"$ref":"#/$defs/file_published_ref"},
    "g3_00_aggregate_review":{"$ref":"#/$defs/file_published_ref"},
    "schema_contract_root":{"$ref":"#/$defs/directory_published_root_ref"},
    "pre_aggregate_lineage":{"$ref":"#/$defs/file_published_ref"},
    "crosscheck_admission_reference":{"$ref":"#/$defs/file_published_ref"},
    "launcher_overlay_review":{"$ref":"#/$defs/file_published_ref"},
    "successor_reviews":{"type":"object","additionalProperties":false,"required":["public_v3_review_r3","compact_seed_review_r3"],"properties":{"public_v3_review_r3":{"$ref":"#/$defs/file_published_ref"},"compact_seed_review_r3":{"$ref":"#/$defs/file_published_ref"}}},
    "g3_01_amendment":{"$ref":"#/$defs/legacy_accepted_ref"},
    "adopter":{"$ref":"#/$defs/principal"},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"adopter_separate_from_aggregate_author":true,"adopter_separate_from_aggregate_reviewer":true,"g3_01_amendment_author_separate":true,"launcher_and_crosscheck_principals_separate":true,"native_host_principals_separate":true,"no_self_adoption":true,"no_self_generated_evidence":true,"promotion_principals_separate":true,"reviewer_separate_from_adopter":true}},
    "checks":{"type":"array","minItems":11,"maxItems":11,"items":{"$ref":"#/$defs/pass_check"}},
    "disposition":{"const":"PASS_G3_01_ADOPTION_LINEAGE_V2_FOR_CONSTRUCTION_AMENDMENT_REVIEW_V2_ONLY"},
    "accepted_scope":{"const":["REVIEW_G3_01_CONSTRUCTION_AMENDMENT_V2_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "adoption_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The exact ordered adoption checks are `AD2-01-MANIFEST-V3`,
`AD2-02-AGGREGATE-REVIEW-V3`, `AD2-03-DIRECTORY-ROOT`,
`AD2-04-PRE-AGGREGATE-V3`, `AD2-05-CROSSCHECK-R2`,
`AD2-06-LAUNCHER-OVERLAY`, `AD2-07-PUBLIC-REVIEW-R3`,
`AD2-08-SEED-REVIEW-R3`, `AD2-09-G3-01-AMENDMENT-PIN`,
`AD2-10-ACYCLIC-POST-ADMISSION`, and `AD2-11-INDEPENDENCE-NONAUTHORITY`.
Identity prefix/domain are
`pfg301ad2-/PROGRAM_FACTS_G3_01_ADOPTION_LINEAGE_V2`.

The only successor of that lineage is the create-only v2 construction review
at the section-15.1 path. Its exact root is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject","normative_parent","g3_00_admission","reviewer","independence","checks","findings","open_findings","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_01_construction_amendment_review.v2"},
    "review_id":{"type":"string","pattern":"^pfg301r2-[0-9a-f]{32}$"},
    "subject":{"$ref":"#/$defs/legacy_accepted_ref"},
    "normative_parent":{"$ref":"#/$defs/legacy_accepted_ref"},
    "g3_00_admission":{"type":"object","additionalProperties":false,"required":["manifest_v3","aggregate_review_v3","adoption_lineage_v2"],"properties":{"manifest_v3":{"$ref":"#/$defs/file_published_ref"},"aggregate_review_v3":{"$ref":"#/$defs/file_published_ref"},"adoption_lineage_v2":{"$ref":"#/$defs/file_published_ref"}}},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"adoption_adopter_and_reviewer_separate":true,"amendment_author_separate":true,"g3_00_subject_authors_separate":true,"no_self_generated_evidence":true,"oracle_author_separate":true,"production_implementer_separate":true,"workspace_clean":true}},
    "checks":{"type":"array","minItems":8,"maxItems":8,"items":{"$ref":"#/$defs/pass_check"}},
    "findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/finding"}},
    "open_findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "disposition":{"enum":["PASS_G3_01_CONSTRUCTION_AMENDMENT_V2_FOR_PREIMPLEMENTATION_ONLY","REJECTED"]},
    "accepted_scope":{"const":["BEGIN_EXISTING_G3_01_CONSTRUCTION_SEQUENCE_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "review_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The exact check order is `PFG301-00-ADOPTION-LINEAGE`, followed unchanged by
`PFG301-01-PARENT-PIN`, `PFG301-02-LITERAL-MUTATIONS`,
`PFG301-03-SCHEMA-REVIEWS`, `PFG301-04-PROTOCOL-PINS`,
`PFG301-05-ORACLE-INVOCATION`, `PFG301-06-ACYCLIC-AUTHORITY`, and
`PFG301-07-INDEPENDENCE`. Passing requires all eight PASS, no open blocking
finding, and exact parsed-value joins to manifest-v3, aggregate-review-v3, and
adoption-lineage-v2. The v1 review remains byte-stable and can never satisfy
this successor entry.

### 15.10 Exact dependency topology and finite file-publication namespace

The only normative r2 topology is:

```text
accepted launcher contract -> accepted launcher independent review --+
accepted crosscheck-v3-r2 contract -> accepted crosscheck review -----+->
stable r2 amendment bytes -> independent r2 amendment review ---------+
                                                                    |
                                                                    v
crosscheck admission reference -> launcher rebind -> merged registry
  -> overlay replay -> overlay review
  -> native receipt executions + parity executions -> pre-aggregate v3
  -> public-v3 review r3 -> compact-seed review r3
  -> 24-member staged root -> internal manifest -> external root arm
  -> atomic directory rename -> external transport completion
  -> independent 25-file promotion review -> admission manifest v3
  -> aggregate review v3 -> adoption lineage v2
  -> G3-01 construction-amendment review v2 -> unchanged G3-01 construction
```

No node may consume a later node; a subject never embeds its own review; and
the admission manifest never contains the adoption lineage. Launcher and
crosscheck independent reviews therefore precede the r2 amendment review, not
merely overlay execution. Every identity in those three reviewed inputs is
late-bound from stable accepted bytes. This document specifies no hash for a
launcher or crosscheck artifact that may still change.

The exact file-publication edge set is the 18 rendered schema files, the 20
non-directory semantic files in section 15.1 (all except the internal
staged-root manifest), and the 25 merged launcher schemas in the exact ordinal
roster of section 15.3: 63 edges total. Schema files use ordinals `00..17` in
the section-15.1 schema registry; semantic files use `18..37` in section-15.1
path order after removing the internal root manifest; merged schemas use
`38..62` in source-registry order. For any edge with final path `parent/name`,
define:

```text
nn         = two-digit semantic ordinal 00..62
key        = uppercase ASCII basename with each non-alphanumeric run replaced by "_"
stem       = ".__pfg3alr2_" || nn || "_" || key
lease      = parent || "/" || stem || ".lease"
attempt(a) = parent || "/" || stem || ".attempt." || Z20(a) || "."
leaves     = attempt(a) || {attempt.json,payload.stage,publish-arm.json,completion.json,debt.json}
```

`key` is derived from the complete basename including version and extension,
so two registered finals cannot alias. Semantic validation rejects a duplicate
`{nn,key}`, an unregistered final, a noncontiguous attempt prefix, or any sidecar
outside this grammar. The attempt, arm, completion, debt, native host, durability,
collision, and recovery semantics are exactly the accepted crosscheck-v3-r2
profile; its closed record shapes are reused with only the locally closed
integer `edge_ordinal:0..62` and formula-derived `edge_key` registry substituted. That
substitution is mechanical and independently reviewed; it cannot widen any
other field, completion grade, native primitive, or recovery transition.

For materialized attempt-prefix lengths `A[0]..A[62]`, the exact loose-file
publication path count is `63 + 63 + 5*SUM(A[0]..A[62])`: 63 registered finals,
63 inert leases, and five leaves per attempt. The atomic directory root adds
exactly 25 staged members and 25 final members, while its external arm,
completion, and promotion review are already among the 45 edges. Unsupported
hosts fail before any edge path is touched. No scan, random suffix, backup,
alternate root, content-equality adoption, overwrite, or retroactive completion
is permitted.

### 15.11 Fixture-first repair denominator

The normative r2 repair suite has exactly 24 Part-0 cases. Every case has one
valid synthetic candidate and at least one single-mutation negative candidate;
RED and GREEN execute identical candidate bytes.

| ID | Negative mutation | Required rejection / positive invariant |
|---|---|---|
| `ALC-R2-01` | launcher snapshot const still names v2 source | both exact sites name accepted v3 transport artifact |
| `ALC-R2-02` | only one of two source consts rebound | exactly 50 replacements across 25 schemas |
| `ALC-R2-03` | pre-aggregate closed object lacks one lineage field | all four fields present in all 25 copies |
| `ALC-R2-04` | one merged `$id` remains old | all 25 IDs use the fresh prefix |
| `ALC-R2-05` | any fifth transform/other AST difference | exactly 100 approved AST changes, zero other |
| `ALC-R2-06` | merged basename missing/reordered/aliased | exact 25-row ordinal roster |
| `ALC-R2-07` | launcher replay denominator changes | unchanged 47 scenarios/488 subcases |
| `ALC-R2-08` | any ALC-01/02/03/11/12 source case fails | all five pass against the overlay |
| `ALC-R2-09` | new file uses flattened or uncompleted reference | tagged wrapper contains exact accepted transport |
| `ALC-R2-10` | legacy artifact receives synthetic completion | legacy identity remains immutable and unbackfilled |
| `ALC-R2-11` | 25 loose refs substitute for directory root | only typed atomic-root reference passes |
| `ALC-R2-12` | manifest digest includes manifest bytes | 24-member pre-manifest digest is acyclic |
| `ALC-R2-13` | staged/final root has wrong member | exact 24+manifest census passes |
| `ALC-R2-14` | external completion/review is placed inside root | both remain outside the atomic root |
| `ALC-R2-15` | promotion review trusts manifest without reopening | independent exact 25-file reopen passes |
| `ALC-R2-16` | native host receipt carries summary booleans only | literal launcher projection value required |
| `ALC-R2-17` | copied launcher projection differs by one keyword | normalized fragment equality required |
| `ALC-R2-18` | projection tag disagrees with receipt role | closed tagged-union branch must match role |
| `ALC-R2-19` | projection omitted from receipt digest preimage | exact projection digest formula passes |
| `ALC-R2-20` | frozen G3-01 v1 review is edited/reused | create-only v2 path and schema pass |
| `ALC-R2-21` | v2 G3-01 review omits adoption or changes old check order | adoption first plus unchanged seven passes |
| `ALC-R2-22` | adoption precedes aggregate or appears in manifest | post-admission acyclic order passes |
| `ALC-R2-23` | amendment review lacks accepted launcher/crosscheck reviews | exact four-parent reviewed join passes |
| `ALC-R2-24` | authority true, self-certification, or protocol hint | all-false authority, independent principals, Part-0 pass |

Fixture author, contract author, renderer, RED/GREEN executor, and independent
reviewer are separate principals. GREEN requires 24 expected outcomes, zero
unexpected pass/fail, zero setup error, zero unregistered write, and an empty
post-run diff outside registered fixture outputs. These fixtures authorize only
schema rendering and successor construction; they are not recall evidence.

### 15.12 Independent r2 amendment review

The first semantic path in section 15.1 validates this document only after its
bytes are frozen and both upstream contract reviews are accepted. Its exact root
is:

```json
{
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject","normative_parents","reviewer","independence","checks","findings","open_findings","disposition","accepted_scope","part_0_genericity","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_closure_r2_review.v1"},
    "review_id":{"type":"string","pattern":"^pfg3alr2-[0-9a-f]{32}$"},
    "subject":{"$ref":"#/$defs/file_identity"},
    "normative_parents":{"type":"object","additionalProperties":false,"required":["launcher_contract","launcher_review","crosscheck_r2_contract","crosscheck_r2_review"],"properties":{"launcher_contract":{"$ref":"#/$defs/legacy_accepted_ref"},"launcher_review":{"$ref":"#/$defs/file_published_ref"},"crosscheck_r2_contract":{"$ref":"#/$defs/legacy_accepted_ref"},"crosscheck_r2_review":{"$ref":"#/$defs/file_published_ref"}}},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"amendment_author_separate":true,"crosscheck_authors_and_reviewers_separate":true,"fixture_author_separate":true,"g3_01_author_separate":true,"launcher_authors_and_reviewers_separate":true,"native_and_promotion_principals_separate":true,"no_self_generated_evidence":true,"production_implementer_separate":true,"schema_renderer_separate":true,"workspace_clean":true}},
    "checks":{"type":"array","minItems":16,"maxItems":16,"items":{"$ref":"#/$defs/pass_check"}},
    "findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/finding"}},
    "open_findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "disposition":{"enum":["PASS_G3_00_ADMISSION_LINEAGE_R2_FOR_FIXTURES_AND_SCHEMA_RENDERING_ONLY","REJECTED"]},
    "accepted_scope":{"const":["AUTHOR_R2_RED_FIXTURES_AND_RENDER_18_SCHEMAS_ONLY"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "publication_requirements":{"$ref":"#/$defs/publication_requirements"},
    "review_body_sha256":{"$ref":"#/$defs/hex64"}
  }
}
```

The exact ordered checks are `ALR2-01-SUBJECT-STABLE`,
`ALR2-02-LAUNCHER-REVIEWED-PARENT`, `ALR2-03-CROSSCHECK-R2-REVIEWED-PARENT`,
`ALR2-04-DISJOINT-REFERENCE-UNION`, `ALR2-05-LAUNCHER-OVERLAY-EXACT`,
`ALR2-06-LAUNCHER-DENOMINATOR`, `ALR2-07-NATIVE-PROJECTION-EXACT`,
`ALR2-08-NATIVE-DIGEST-PREIMAGE`, `ALR2-09-PREAGGREGATE-LINEAGE`,
`ALR2-10-ROOT-MANIFEST-ACYCLIC`, `ALR2-11-ATOMIC-ROOT-TRANSPORT`,
`ALR2-12-PROMOTION-REOPEN`, `ALR2-13-ADMISSION-AGGREGATE`,
`ALR2-14-G3-01-CREATE-ONLY-SUCCESSOR`, `ALR2-15-FINITE-PATH-CRASH-CLOSURE`,
and `ALR2-16-INDEPENDENCE-AUTHORITY-PART0`. Every check must PASS and no open
blocking finding may remain. This review grants no implementation, publication,
admission, construction, audit, release, or cutover authority.

### 15.13 Mechanical rendering and validation

After the r2 review passes, the renderer copies the complete common `$defs` into
each of the exact 18 roots, gives it only the registered `$id`, emits `CF`, and
performs no other substitution. The one stated exception is the native receipt:
its two launcher projection `$defs` are copied mechanically from the accepted
merged launcher schemas and are part of its byte preimage. Validation MUST:

1. parse every inline JSON block with duplicate-key rejection and Draft-2020-12
   metaschema validation;
2. prove all `$ref` targets local, all objects closed, the 18 file/version map
   bijective, and all common authority values false;
3. compare each rendered root's normalized AST with its inline root and allow
   only common-`$defs`, `$schema`, `$id`, and the two declared native projection
   fragment copies;
4. prove the semantic-path registry, 63-edge publication registry, 25-schema
   launcher roster, 24+1 root roster, check arrays, formulas, and counts exact;
5. build a typed dependency graph from parsed reference fields and reject every
   cycle, future-review edge, legacy backfill, reference-kind substitution, or
   unreviewed parent; and
6. execute all 24 unchanged RED/GREEN candidates plus the launcher 47/488 and
   ALC-01/02/03/11/12 replays.

Failure writes only non-enabling human-review debt at a registered attempt path;
it never guesses bytes, relaxes a schema, silently drops an artifact, or halts
unrelated pipeline work. The bounded r2 successor is Part-0: it encodes generic
identity, lineage, publication, projection, review, and transaction invariants,
and contains no protocol, ecosystem, vulnerability class, target result, or
finding hint.

Status: `CONTRACT_ONLY_PENDING_FRESH_INDEPENDENT_R2_REVIEW`
