# Program Facts G3-00 admission-lineage Part-0 r4 correction amendment

Status: `CONTRACT_ONLY_PENDING_FRESH_INDEPENDENT_R4_REVIEW`

This create-only Part-0 amendment is the narrow successor to the exact r3
correction contract and its independent `REPAIR` review. It fixes only:

1. the governed review predicate and the exact join between the finding ledger,
   `open_findings`, failed checks, and rejection bindings; and
2. principal identity binding and value-derived independence.

Every r3 bundle adoption, completion-grade boundary, post-Cut4 late binding,
authority ceiling, path registry, Part-0 boundary, and accepted DAG result is
inherited without widening. No r2/r3 artifact is edited, completed, reclassified,
or treated as a passing review. This document grants no schema rendering, RED
execution, GREEN implementation, construction, production edit, candidate
import, runtime, native, provider, publication, admission, package,
installation, release, cutover, commit, or push authority.

## 1. Exact predecessor registry and narrow precedence

The closed predecessor registry has exactly three rows:

| Ordinal | Key | Path | Bytes | SHA-256 | Treatment |
|---:|---|---|---:|---|---|
| 0 | `R3_CORRECTION_CONTRACT` | `architecture/program-facts-g3-00-admission-lineage-r3-correction-amendment.md` | 47976 | `517a009f79051092d04e535469c9a116a3f0ae4a4708e02dd9cd5282cf054be1` | immutable inherited contract |
| 1 | `R3_AUTHOR_RECEIPT` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_AUTHOR_RECEIPT.md` | 5144 | `803e8e94f858d5fdfe5cc3c38cf949ab17b7edb64da60039f501c26926bd504b` | authorship evidence only, never acceptance |
| 2 | `R3_REPAIR_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_INDEPENDENT_REVIEW.md` | 16219 | `37ed1997e8f25608147162d4b57d42bdee4044d9ee2044651c5d3bfcf5060eeb` | exact `REPAIR`, two open blockers, no authority |

The r3 review independently accepted 14 of 16 checks. Its exact inherited facts
are: 18 source rows; the indivisible R3.13 legacy-reviewed launcher bundle; the
V8 pure/offline oracle-and-fixture-only bundle; the exact crosscheck bundle and
its bundle-local
`PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION` grade; no launcher
transport backfill; late-bound post-Cut4 ArtifactLedger/driver identities; no
candidate import; two schema paths; four semantic paths; nine RED cases; 29
common and 17 V8-specific false authority members; and a 30-node/44-edge
acyclic DAG ending at no-GREEN/no-implementation. Those facts remain exact.

The r3 review disposition remains `REPAIR`. Its failed checks are exactly
`ALR3-08-CHECK-DISPOSITION-TOTALITY` and
`ALR3-14-INDEPENDENCE-NO-SELF-CERTIFICATION`; its open findings are exactly
`ALR3-R3-F001-OPEN-FINDING-LIST-NOT-ENFORCED` and
`ALR3-R3-F002-SELF-REVIEW-IS-DECLARATIVE-ONLY`. Only sections 3-6 below
supersede the corresponding r3 review-envelope and downstream-governance
definitions. Every other r3 byte remains immutable design input and
non-enabling.

## 2. Canonical bytes and deterministic identities

`CJ(x)` is RFC-8785 canonical JSON encoded as UTF-8. `CF(x) = CJ(x) || 0x0a`.
All governed JSON rejects duplicate keys, BOM, CR, invalid UTF-8, non-finite
numbers, unsafe integers, noncanonical escapes, unknown members, and trailing
bytes other than one LF. Paths are repository-relative, forward-slash
separated, NFC, exact-case, and contain no empty, dot, dot-dot, colon,
backslash, or control component.

```text
review_body_sha256 = SHA-256(CJ(review without only review_body_sha256))
review_id = "pfg3alr4-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_REVIEW_V1",
  review:<review without review_id and review_body_sha256>
}))[0:32]

roster_body_sha256 = SHA-256(CJ(roster without only roster_body_sha256))
roster_id = "pfg3alr4pr-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_PRINCIPAL_ROSTER_V1",
  roster:<roster without roster_id, binding_signature, and roster_body_sha256>
}))[0:32]
for i in [1,2,3,6,7]:
  bindings[i].source.assignment_body_sha256 = SHA-256(CJ({
    domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_PRINCIPAL_ASSIGNMENT_V1",
    role:roles[i],
    principal_ordinal:i,
    principal_id:principal_ids[i]
  }))
binding_preimage_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_PRINCIPAL_BINDING_V1",
  roster:<roster without roster_id, binding_signature, and roster_body_sha256>
}))

principal_ids_sha256 = SHA-256(CJ(principal_ids))
independence_projection_body_sha256 = SHA-256(CJ(
  independence_projection without only projection_body_sha256))

red_receipt_body_sha256 = SHA-256(CJ(RED receipt without only receipt_body_sha256))
red_receipt_id = "pfg3alr4red-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_RED_RECEIPT_V1",
  receipt:<RED receipt without receipt_id and receipt_body_sha256>
}))[0:32]
```

The body formulas commit the already-derived IDs. The roster signature is
Ed25519 over the 32 raw bytes named by `binding_preimage_sha256`; its public key
and signature are canonical Base64. No record embeds or predicts its own file
identity.

The common r3 29-member authority object and V8 17-member authority object are
inherited byte-semantically and remain entirely false. The Part-0 object remains
exactly
`{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}`.

## 3. Exact finding and disposition semantics

R4 uses a finding ledger object keyed by `finding_id`, not an array. JSON object
key uniqueness therefore makes duplicate finding IDs impossible even when
other fields differ. Each finding value contains exactly `severity`, `status`,
`failed_checks`, `description`, and `evidence`.

For every review disposition, the semantic validator performs this exact
algorithm after structural schema validation:

```text
check_ids = the exact 16 check IDs in array order
failed_check_ids = [check_id for each check whose result == FAIL]
finding_ids = UTF8_SORT(keys(findings))
open_ids = UTF8_SORT([id for id in finding_ids if findings[id].status == OPEN])
open_blocker_ids = UTF8_SORT([id for id in open_ids
                              if findings[id].severity == BLOCKING])

require open_findings == open_ids
require every findings[id].failed_checks is UTF8-sorted and duplicate-free
require every failed_checks member is in failed_check_ids

binding_check_ids = [row.check_id for failure_bindings in check-array order]
require binding_check_ids == failed_check_ids
require each binding row has a nonempty UTF8-sorted unique finding_ids array
require every bound finding ID is in open_blocker_ids
require UTF8_SORT(union(all bound finding_ids)) == open_blocker_ids
require for every open_blocker id:
  findings[id].failed_checks == [check IDs whose binding row contains id]

if disposition == PASS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_FOR_BOUND_GOVERNANCE_RED_AND_SCHEMA_RENDERING_ONLY:
  require failed_check_ids == []
  require open_findings == []
  require open_ids == []
  require open_blocker_ids == []
  require failure_bindings == []

if disposition == REJECTED:
  require failed_check_ids is nonempty
  require open_findings == open_ids == open_blocker_ids
  require open_blocker_ids is nonempty
```

Thus PASS requires every exact check `PASS`, `open_findings` exactly empty, and
no finding of any severity with `status:OPEN`; in particular no hidden
`BLOCKING/OPEN` finding can coexist with PASS. `REJECTED` may truthfully carry
FAIL rows and open blockers only when the check/finding/binding/open projections
are exact bijective joins. A Boolean, count, digest, or claimed empty list never
substitutes for recomputation from the parsed finding ledger.

The JSON Schema PASS branch independently rejects any FAIL check, nonempty
`open_findings`, any finding value with `status:OPEN`, and any failure binding.
The semantic algorithm remains mandatory for both dispositions and catches
projection mismatch or relabeling that Draft 2020-12 cannot express as a
cross-member equality.

## 4. Value-bound principal roster and computed independence

The exact ordered role roster is:

```text
0 CORRECTION_AUTHOR
1 CORRECTION_REVIEWER
2 RED_FIXTURE_AUTHOR
3 SCHEMA_RENDERER
4 R313_STATE_NATIVE_REVIEWER
5 R313_WINDOWS_NATIVE_REVIEWER
6 PRODUCTION_IMPLEMENTER
7 PRINCIPAL_ROSTER_BINDER
```

`principal_ids` is an eight-item ordered array with `uniqueItems:true`.
Ordinals, never duplicated free-form IDs, bind roles to principals. Ordinal 0 is
extracted from the exact r4 author receipt label `Author principal:`. Ordinals
4 and 5 are extracted from the exact immutable R3.13 review labels `- Reviewer:`
and equal `Codex:/root/r3_13_state_short` and
`Codex:/root/r3_13_native_short`. Ordinals 1, 2, 3, 6, and 7 are explicit
signed roster assignments under the r4 binding domain. Role order,
`principal_ordinal`, binding kind, artifact path, locator, and assignment domain
are closed; a role relabel or source-locator substitution is invalid even when
the principal string is syntactically valid.

For `MARKDOWN_EXACT_LABEL`, the stable byte parser requires exactly one LF
delimited line equal to `label || " " || "`" || principal_id || "`"`, with
only an optional two-space Markdown hard-break suffix before LF. Zero matches,
multiple matches, any other prefix, or any other suffix rejects. Thus the
author locator is exactly `Author principal:` and each immutable R3.13 locator
is exactly `- Reviewer:`; substring or case-folded matching is forbidden.

The roster binder signs the exact roster preimage. The binder is ordinal 7 and
is also subject to the eight-ID uniqueness rule. The independent reviewer is
not a free `reviewer` object: the review contains only
`reviewer_principal_ordinal:1`, the exact roster file identity, and the computed
projection. The later RED fixture author, schema renderer, and production
implementer must present values exactly equal to roster ordinals 2, 3, and 6.
No role may be silently reassigned after the passing review.

The semantic validator MUST:

1. stable-read and validate the roster and every extraction artifact;
2. verify the Ed25519 signature and preimage digest;
3. extract author and both native reviewer IDs at their exact locators;
4. require each extracted value equal `principal_ids[ordinal]`;
5. recompute each of the five exact assignment-body formulas in section 2 and
   require its digest equal the signed-source digest at the same ordinal;
6. require all eight principal ID strings pairwise unequal by direct value
   comparison; and
7. independently construct `independence_projection` with the exact role array,
   exact principal ID array, `required_separation_pair_count:28`,
   `equal_principal_pairs:[]`, the recomputed principal-array digest, and its
   recomputed projection digest.

There is no `independence` Boolean object and no `*_separate:true` member. The
projection contains values and deterministic digests, not a self-attested
verdict. `uniqueItems` supplies a schema-level alias rejection; the semantic
validator additionally compares every one of the 28 unordered pairs. A
principal alias, case-preserving duplicate, role swap, role relabel, locator
change, signature failure, extracted-value mismatch, projection mismatch, or
later actor mismatch rejects.

The author receipt authenticates authorship only and cannot accept the subject.
The bound roster authenticates role values only and cannot review the subject.
The correction reviewer must be ordinal 1 and distinct from all seven other
values; the roster binder cannot review or self-certify.

## 5. Exact create-only registries and review scope

The r4 author creates only this document and its matching author receipt. The
receipt path is:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_AUTHOR_RECEIPT.md
```

All later paths are create-only and currently absent. The schema registry is:

| Ordinal | Exact future path | Root `schema_version` |
|---:|---|---|
| 0 | `rules/schemas/program_facts_g3_00_admission_lineage_r4_correction_review.v1.schema.json` | `plamen.program_facts_g3_00_admission_lineage_r4_correction_review.v1` |
| 1 | `rules/schemas/program_facts_g3_00_admission_lineage_r4_principal_roster.v1.schema.json` | `plamen.program_facts_g3_00_admission_lineage_r4_principal_roster.v1` |
| 2 | `rules/schemas/program_facts_g3_00_admission_lineage_r4_red_receipt.v1.schema.json` | `plamen.program_facts_g3_00_admission_lineage_r4_red_receipt.v1` |

The semantic output registry is:

| Ordinal | Exact future path | Stage |
|---:|---|---|
| 0 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_BOUND_PRINCIPAL_ROSTER.v1.json` | bound roster before review |
| 1 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_INDEPENDENT_REVIEW.v1.json` | fresh independent review after roster |
| 2 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/admission_lineage_r4_correction_fixture_v1.py` | post-PASS RED fixture authoring |
| 3 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r4_correction_red_v1.py` | post-PASS RED fixture authoring |
| 4 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_RED_RECEIPT.v1.json` | RED evidence only |

The roster and review validate against their inline schemas before schema
rendering. Only a valid review PASS allows three separate schema renders and
the two RED fixture files. Its accepted scope is exactly
`AUTHOR_R4_BOUND_GOVERNANCE_RED_FIXTURES_AND_RENDER_3_SCHEMAS_ONLY`. It never
authorizes GREEN, G3-01 construction, production, candidate import, runtime,
native execution, provider activity, publication, admission, package,
installation, release, cutover, commit, or push.

## 6. Closed inline schemas

### 6.1 Bound principal roster

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r4_principal_roster.v1.schema.json",
  "$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/validation":true},
  "type":"object","additionalProperties":false,
  "required":["schema_version","roster_id","subject","author_receipt","roles","principal_ids","bindings","binding_signature","part_0_genericity","authority_ceiling","roster_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r4_principal_roster.v1"},
    "roster_id":{"type":"string","pattern":"^pfg3alr4pr-[0-9a-f]{32}$"},
    "subject":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-admission-lineage-r4-correction-amendment.md"}}}]},
    "author_receipt":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_AUTHOR_RECEIPT.md"}}}]},
    "roles":{"const":["CORRECTION_AUTHOR","CORRECTION_REVIEWER","RED_FIXTURE_AUTHOR","SCHEMA_RENDERER","R313_STATE_NATIVE_REVIEWER","R313_WINDOWS_NATIVE_REVIEWER","PRODUCTION_IMPLEMENTER","PRINCIPAL_ROSTER_BINDER"]},
    "principal_ids":{"type":"array","minItems":8,"maxItems":8,"uniqueItems":true,"prefixItems":[
      {"const":"Codex:/root/g3_r3_correction_author_short"},
      {"$ref":"#/$defs/principal_id"},{"$ref":"#/$defs/principal_id"},{"$ref":"#/$defs/principal_id"},
      {"const":"Codex:/root/r3_13_state_short"},{"const":"Codex:/root/r3_13_native_short"},
      {"$ref":"#/$defs/principal_id"},{"$ref":"#/$defs/principal_id"}
    ],"items":false},
    "bindings":{"type":"array","minItems":8,"maxItems":8,"prefixItems":[
      {"$ref":"#/$defs/binding_0"},{"$ref":"#/$defs/binding_1"},{"$ref":"#/$defs/binding_2"},{"$ref":"#/$defs/binding_3"},
      {"$ref":"#/$defs/binding_4"},{"$ref":"#/$defs/binding_5"},{"$ref":"#/$defs/binding_6"},{"$ref":"#/$defs/binding_7"}
    ],"items":false},
    "binding_signature":{"type":"object","additionalProperties":false,"required":["algorithm","signer_principal_ordinal","public_key_base64","signed_preimage_sha256","signature_base64"],"properties":{"algorithm":{"const":"ED25519"},"signer_principal_ordinal":{"const":7},"public_key_base64":{"type":"string","pattern":"^[A-Za-z0-9+/]{43}=$"},"signed_preimage_sha256":{"$ref":"#/$defs/hex64"},"signature_base64":{"type":"string","pattern":"^[A-Za-z0-9+/]{86}==$"}}},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "roster_body_sha256":{"$ref":"#/$defs/hex64"}
  },
  "$defs":{
    "hex64":{"type":"string","minLength":64,"maxLength":64,"pattern":"^[0-9a-f]{64}$"},
    "safe_path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},
    "principal_id":{"type":"string","minLength":12,"maxLength":256,"pattern":"^[A-Za-z][A-Za-z0-9._-]*:/[A-Za-z0-9._/-]+$"},
    "file_identity":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/safe_path"},"size_bytes":{"type":"integer","minimum":0,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex64"}}},
    "extracted_source":{"type":"object","additionalProperties":false,"required":["kind","artifact","locator"],"properties":{"kind":{"const":"IMMUTABLE_ARTIFACT_EXTRACTION"},"artifact":{"$ref":"#/$defs/file_identity"},"locator":{"type":"object","additionalProperties":false,"required":["syntax","label"],"properties":{"syntax":{"const":"MARKDOWN_EXACT_LABEL"},"label":{"type":"string","minLength":1,"maxLength":128}}}}},
    "signed_source":{"type":"object","additionalProperties":false,"required":["kind","assignment_domain","assignment_body_sha256"],"properties":{"kind":{"const":"SIGNED_ROSTER_ASSIGNMENT"},"assignment_domain":{"const":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_PRINCIPAL_ASSIGNMENT_V1"},"assignment_body_sha256":{"$ref":"#/$defs/hex64"}}},
    "binding":{"type":"object","additionalProperties":false,"required":["role","principal_ordinal","source"],"properties":{"role":{"type":"string"},"principal_ordinal":{"type":"integer","minimum":0,"maximum":7},"source":{"oneOf":[{"$ref":"#/$defs/extracted_source"},{"$ref":"#/$defs/signed_source"}]}}},
    "binding_0":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"CORRECTION_AUTHOR"},"principal_ordinal":{"const":0},"source":{"allOf":[{"$ref":"#/$defs/extracted_source"},{"properties":{"artifact":{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_AUTHOR_RECEIPT.md"}}},"locator":{"properties":{"label":{"const":"Author principal:"}}}}}]}}}]},
    "binding_1":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"CORRECTION_REVIEWER"},"principal_ordinal":{"const":1},"source":{"$ref":"#/$defs/signed_source"}}}]},
    "binding_2":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"RED_FIXTURE_AUTHOR"},"principal_ordinal":{"const":2},"source":{"$ref":"#/$defs/signed_source"}}}]},
    "binding_3":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"SCHEMA_RENDERER"},"principal_ordinal":{"const":3},"source":{"$ref":"#/$defs/signed_source"}}}]},
    "binding_4":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"R313_STATE_NATIVE_REVIEWER"},"principal_ordinal":{"const":4},"source":{"allOf":[{"$ref":"#/$defs/extracted_source"},{"properties":{"artifact":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_13_STATE_OPERATIONAL_REVIEW_7d1616dedea141ea.md","size_bytes":11434,"sha256":"dce9edb11ec93db0832cb442836639e6f028bd49750a6014c6efb937db894655"}},"locator":{"properties":{"label":{"const":"- Reviewer:"}}}}}]}}}]},
    "binding_5":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"R313_WINDOWS_NATIVE_REVIEWER"},"principal_ordinal":{"const":5},"source":{"allOf":[{"$ref":"#/$defs/extracted_source"},{"properties":{"artifact":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_13_NATIVE_CONTRACT_REVIEW_7d1616dedea141ea.md","size_bytes":10204,"sha256":"7d73204b1c524fc65fcbd9bc3d4831e2828e1e26d80bad65ccd011193effd37b"}},"locator":{"properties":{"label":{"const":"- Reviewer:"}}}}}]}}}]},
    "binding_6":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"PRODUCTION_IMPLEMENTER"},"principal_ordinal":{"const":6},"source":{"$ref":"#/$defs/signed_source"}}}]},
    "binding_7":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"PRINCIPAL_ROSTER_BINDER"},"principal_ordinal":{"const":7},"source":{"$ref":"#/$defs/signed_source"}}}]},
    "part0":{"type":"object","const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},
    "authority":{"type":"object","const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}
  }
}
```

### 6.2 Independent r4 review

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r4_correction_review.v1.schema.json",
  "$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/validation":true},
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject","predecessor_registry","inherited_r3_projection","principal_roster","reviewer_principal_ordinal","independence_projection","checks","findings","open_findings","failure_bindings","disposition","accepted_scope","rejected_scope","part_0_genericity","authority_ceiling","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r4_correction_review.v1"},
    "review_id":{"type":"string","pattern":"^pfg3alr4-[0-9a-f]{32}$"},
    "subject":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-admission-lineage-r4-correction-amendment.md"}}}]},
    "predecessor_registry":{"$ref":"#/$defs/predecessor_registry"},
    "inherited_r3_projection":{"$ref":"#/$defs/inherited_r3_projection"},
    "principal_roster":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_BOUND_PRINCIPAL_ROSTER.v1.json"}}}]},
    "reviewer_principal_ordinal":{"const":1},
    "independence_projection":{"$ref":"#/$defs/independence_projection"},
    "checks":{"type":"array","minItems":16,"maxItems":16,"prefixItems":[
      {"$ref":"#/$defs/check_01"},{"$ref":"#/$defs/check_02"},{"$ref":"#/$defs/check_03"},{"$ref":"#/$defs/check_04"},
      {"$ref":"#/$defs/check_05"},{"$ref":"#/$defs/check_06"},{"$ref":"#/$defs/check_07"},{"$ref":"#/$defs/check_08"},
      {"$ref":"#/$defs/check_09"},{"$ref":"#/$defs/check_10"},{"$ref":"#/$defs/check_11"},{"$ref":"#/$defs/check_12"},
      {"$ref":"#/$defs/check_13"},{"$ref":"#/$defs/check_14"},{"$ref":"#/$defs/check_15"},{"$ref":"#/$defs/check_16"}
    ],"items":false},
    "findings":{"type":"object","propertyNames":{"$ref":"#/$defs/identifier"},"additionalProperties":{"$ref":"#/$defs/finding_value"},"maxProperties":10000},
    "open_findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "failure_bindings":{"type":"array","minItems":0,"maxItems":16,"uniqueItems":true,"items":{"$ref":"#/$defs/failure_binding"}},
    "disposition":{"enum":["PASS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_FOR_BOUND_GOVERNANCE_RED_AND_SCHEMA_RENDERING_ONLY","REJECTED"]},
    "accepted_scope":{"const":["AUTHOR_R4_BOUND_GOVERNANCE_RED_FIXTURES_AND_RENDER_3_SCHEMAS_ONLY"]},
    "rejected_scope":{"const":["ADMISSION","CANDIDATE_IMPORT","COMMIT","CONSTRUCTION","CUTOVER","GREEN_IMPLEMENTATION","INSTALL","NATIVE_EXECUTION","PACKAGE","PRODUCTION_EDIT","PRODUCTION_PUBLICATION","PROVIDER","PUSH","RELEASE","RUNTIME"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "review_body_sha256":{"$ref":"#/$defs/hex64"}
  },
  "allOf":[
    {"if":{"properties":{"disposition":{"const":"PASS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_FOR_BOUND_GOVERNANCE_RED_AND_SCHEMA_RENDERING_ONLY"}},"required":["disposition"]},"then":{"properties":{"checks":{"not":{"contains":{"type":"object","required":["result"],"properties":{"result":{"const":"FAIL"}}}}},"findings":{"additionalProperties":{"not":{"type":"object","required":["status"],"properties":{"status":{"const":"OPEN"}}}}},"open_findings":{"maxItems":0},"failure_bindings":{"maxItems":0}}}},
    {"if":{"properties":{"disposition":{"const":"REJECTED"}},"required":["disposition"]},"then":{"properties":{"checks":{"contains":{"type":"object","required":["result"],"properties":{"result":{"const":"FAIL"}}},"minContains":1},"findings":{"minProperties":1},"open_findings":{"minItems":1},"failure_bindings":{"minItems":1}}}}
  ],
  "$defs":{
    "hex64":{"type":"string","minLength":64,"maxLength":64,"pattern":"^[0-9a-f]{64}$"},
    "identifier":{"type":"string","minLength":1,"maxLength":256,"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},
    "safe_path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},
    "principal_id":{"type":"string","minLength":12,"maxLength":256,"pattern":"^[A-Za-z][A-Za-z0-9._-]*:/[A-Za-z0-9._/-]+$"},
    "file_identity":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/safe_path"},"size_bytes":{"type":"integer","minimum":0,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex64"}}},
    "predecessor_registry":{"type":"array","const":[{"path":"architecture/program-facts-g3-00-admission-lineage-r3-correction-amendment.md","size_bytes":47976,"sha256":"517a009f79051092d04e535469c9a116a3f0ae4a4708e02dd9cd5282cf054be1"},{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_AUTHOR_RECEIPT.md","size_bytes":5144,"sha256":"803e8e94f858d5fdfe5cc3c38cf949ab17b7edb64da60039f501c26926bd504b"},{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_INDEPENDENT_REVIEW.md","size_bytes":16219,"sha256":"37ed1997e8f25608147162d4b57d42bdee4044d9ee2044651c5d3bfcf5060eeb"}]},
    "inherited_r3_projection":{"type":"object","const":{"accepted_check_count":14,"blocked_downstream":true,"common_false_authority_count":29,"crosscheck_completion_grade":"PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION","dag_edge_count":44,"dag_node_count":30,"failed_checks":["ALR3-08-CHECK-DISPOSITION-TOTALITY","ALR3-14-INDEPENDENCE-NO-SELF-CERTIFICATION"],"inherited_bundle_kinds":["IMMUTABLE_LEGACY_REVIEWED_LAUNCHER_R3_13_BUNDLE","IMMUTABLE_V8_PURE_OFFLINE_ORACLE_FIXTURE_PARENT","IMMUTABLE_ACCEPTED_CROSSCHECK_R2_REVIEWED_PUBLICATION_BUNDLE"],"open_findings":["ALR3-R3-F001-OPEN-FINDING-LIST-NOT-ENFORCED","ALR3-R3-F002-SELF-REVIEW-IS-DECLARATIVE-ONLY"],"r3_disposition":"REPAIR","red_case_count":9,"schema_registry_count":2,"semantic_output_count":4,"source_registry_count":18,"v8_false_authority_count":17}},
    "check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"$ref":"#/$defs/identifier"},"result":{"enum":["PASS","FAIL"]},"evidence":{"type":"array","minItems":1,"maxItems":1000,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}}}},
    "check_01":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-01-R3-SUBJECT-REVIEW-EXACT"}}}]},
    "check_02":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-02-R3-ADOPTION-INHERITED-EXACT"}}}]},
    "check_03":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-03-R3-DAG-INHERITED-EXACT"}}}]},
    "check_04":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-04-R3-DOWNSTREAM-ABSENT"}}}]},
    "check_05":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-05-PASS-ALL-CHECKS"}}}]},
    "check_06":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-06-OPEN-FINDING-EQUALITY"}}}]},
    "check_07":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-07-NO-HIDDEN-OPEN-BLOCKER"}}}]},
    "check_08":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-08-REJECTED-FAIL-BLOCKER-BIJECTION"}}}]},
    "check_09":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-09-PRINCIPAL-ROSTER-BOUND"}}}]},
    "check_10":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-10-PRINCIPAL-VALUES-PAIRWISE-DISTINCT"}}}]},
    "check_11":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-11-ROLE-SOURCE-BINDINGS-EXACT"}}}]},
    "check_12":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-12-INDEPENDENCE-PROJECTION-RECOMPUTED"}}}]},
    "check_13":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-13-FOCUSED-RED-DENOMINATOR"}}}]},
    "check_14":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-14-CREATE-ONLY-REGISTRY-DAG"}}}]},
    "check_15":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-15-AUTHORITY-ALL-FALSE"}}}]},
    "check_16":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR4-16-PART0-GENERICITY"}}}]},
    "finding_value":{"type":"object","additionalProperties":false,"required":["severity","status","failed_checks","description","evidence"],"properties":{"severity":{"enum":["BLOCKING","NONBLOCKING"]},"status":{"enum":["OPEN","CLOSED"]},"failed_checks":{"type":"array","minItems":0,"maxItems":16,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},"description":{"type":"string","minLength":1,"maxLength":8192},"evidence":{"type":"array","minItems":1,"maxItems":1000,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}}}},
    "failure_binding":{"type":"object","additionalProperties":false,"required":["check_id","finding_ids"],"properties":{"check_id":{"$ref":"#/$defs/identifier"},"finding_ids":{"type":"array","minItems":1,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}}}},
    "independence_projection":{"type":"object","additionalProperties":false,"required":["roles","principal_ids","principal_ids_sha256","required_separation_pair_count","equal_principal_pairs","projection_body_sha256"],"properties":{"roles":{"const":["CORRECTION_AUTHOR","CORRECTION_REVIEWER","RED_FIXTURE_AUTHOR","SCHEMA_RENDERER","R313_STATE_NATIVE_REVIEWER","R313_WINDOWS_NATIVE_REVIEWER","PRODUCTION_IMPLEMENTER","PRINCIPAL_ROSTER_BINDER"]},"principal_ids":{"type":"array","minItems":8,"maxItems":8,"uniqueItems":true,"items":{"$ref":"#/$defs/principal_id"}},"principal_ids_sha256":{"$ref":"#/$defs/hex64"},"required_separation_pair_count":{"const":28},"equal_principal_pairs":{"type":"array","maxItems":0},"projection_body_sha256":{"$ref":"#/$defs/hex64"}}},
    "part0":{"type":"object","const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},
    "authority":{"type":"object","const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}
  }
}
```

### 6.3 Focused governance RED receipt

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r4_red_receipt.v1.schema.json",
  "$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/validation":true},
  "type":"object","additionalProperties":false,
  "required":["schema_version","receipt_id","contract","governing_review","principal_roster","rendered_schemas","fixture_source","fixture_test","cases","summary","executor_principal_ordinal","scope","part_0_genericity","authority_ceiling","receipt_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r4_red_receipt.v1"},
    "receipt_id":{"type":"string","pattern":"^pfg3alr4red-[0-9a-f]{32}$"},
    "contract":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-admission-lineage-r4-correction-amendment.md"}}}]},
    "governing_review":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_INDEPENDENT_REVIEW.v1.json"}}}]},
    "principal_roster":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_BOUND_PRINCIPAL_ROSTER.v1.json"}}}]},
    "rendered_schemas":{"type":"array","minItems":3,"maxItems":3,"prefixItems":[
      {"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"rules/schemas/program_facts_g3_00_admission_lineage_r4_correction_review.v1.schema.json"}}}]},
      {"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"rules/schemas/program_facts_g3_00_admission_lineage_r4_principal_roster.v1.schema.json"}}}]},
      {"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"rules/schemas/program_facts_g3_00_admission_lineage_r4_red_receipt.v1.schema.json"}}}]}
    ],"items":false},
    "fixture_source":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/admission_lineage_r4_correction_fixture_v1.py"}}}]},
    "fixture_test":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r4_correction_red_v1.py"}}}]},
    "cases":{"type":"array","minItems":4,"maxItems":4,"prefixItems":[{"$ref":"#/$defs/case_01"},{"$ref":"#/$defs/case_02"},{"$ref":"#/$defs/case_03"},{"$ref":"#/$defs/case_04"}],"items":false},
    "summary":{"const":{"red_confirmed_count":4,"setup_error_count":0,"unexpected_pass_count":0}},
    "executor_principal_ordinal":{"const":2},
    "scope":{"const":"FOCUSED_GOVERNANCE_RED_ONLY_NO_GREEN_NO_IMPLEMENTATION"},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "receipt_body_sha256":{"$ref":"#/$defs/hex64"}
  },
  "$defs":{
    "hex64":{"type":"string","minLength":64,"maxLength":64,"pattern":"^[0-9a-f]{64}$"},
    "safe_path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},
    "file_identity":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/safe_path"},"size_bytes":{"type":"integer","minimum":0,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex64"}}},
    "case":{"type":"object","additionalProperties":false,"required":["case_id","mutation","expected_rejection","red_oracle","evidence"],"properties":{"case_id":{"type":"string"},"mutation":{"type":"string","minLength":1,"maxLength":1024},"expected_rejection":{"type":"string","minLength":1,"maxLength":256},"red_oracle":{"const":"RED_CONFIRMED"},"evidence":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}}}},
    "case_01":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R4-01-HIDDEN-OPEN-BLOCKER"},"mutation":{"const":"PASS plus BLOCKING/OPEN finding while open_findings is empty"},"expected_rejection":{"const":"PASS_OPEN_FINDING_FORBIDDEN"}}}]},
    "case_02":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R4-02-OPEN-ROSTER-MISMATCH"},"mutation":{"const":"REJECTED finding ledger open IDs differ from open_findings or failure bindings"},"expected_rejection":{"const":"FINDING_PROJECTION_MISMATCH"}}}]},
    "case_03":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R4-03-PRINCIPAL-ALIAS"},"mutation":{"const":"two required roles carry the same principal ID value"},"expected_rejection":{"const":"PRINCIPAL_ALIAS"}}}]},
    "case_04":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R4-04-PRINCIPAL-RELABEL"},"mutation":{"const":"principal role, ordinal, immutable source locator, or signed assignment is relabeled"},"expected_rejection":{"const":"PRINCIPAL_BINDING_MISMATCH"}}}]},
    "part0":{"type":"object","const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},
    "authority":{"type":"object","const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}
  }
}
```

## 7. Exact review roster, focused RED denominator, and DAG

The r4 review check order is exactly:

```text
ALR4-01-R3-SUBJECT-REVIEW-EXACT
ALR4-02-R3-ADOPTION-INHERITED-EXACT
ALR4-03-R3-DAG-INHERITED-EXACT
ALR4-04-R3-DOWNSTREAM-ABSENT
ALR4-05-PASS-ALL-CHECKS
ALR4-06-OPEN-FINDING-EQUALITY
ALR4-07-NO-HIDDEN-OPEN-BLOCKER
ALR4-08-REJECTED-FAIL-BLOCKER-BIJECTION
ALR4-09-PRINCIPAL-ROSTER-BOUND
ALR4-10-PRINCIPAL-VALUES-PAIRWISE-DISTINCT
ALR4-11-ROLE-SOURCE-BINDINGS-EXACT
ALR4-12-INDEPENDENCE-PROJECTION-RECOMPUTED
ALR4-13-FOCUSED-RED-DENOMINATOR
ALR4-14-CREATE-ONLY-REGISTRY-DAG
ALR4-15-AUTHORITY-ALL-FALSE
ALR4-16-PART0-GENERICITY
```

The focused RED denominator is exactly the four section-6.3 cases in that
order. Each has one valid control and one single-mutation negative. RED and
control consume identical source bytes. The fixture imports no r3/V8/R3.13
candidate or production module and writes only its registered RED evidence.

The complete r3 30-node/44-edge graph remains immutable historical design. Its
downstream N23-N29 branch remains uninstantiated and blocked by the r3 `REPAIR`.
The r4 successor extension is a separate exact 14-node/25-edge DAG:

```text
R4N00 R3_CORRECTION_CONTRACT
R4N01 R3_AUTHOR_RECEIPT
R4N02 R3_REPAIR_REVIEW
R4N03 R4_CORRECTION_CONTRACT
R4N04 R4_AUTHOR_RECEIPT
R4N05 R4_BOUND_PRINCIPAL_ROSTER
R4N06 R4_INDEPENDENT_REVIEW
R4N07 REVIEW_SCHEMA_RENDER
R4N08 PRINCIPAL_ROSTER_SCHEMA_RENDER
R4N09 RED_RECEIPT_SCHEMA_RENDER
R4N10 RED_FIXTURE_SOURCE
R4N11 RED_FIXTURE_TEST
R4N12 RED_RECEIPT
R4N13 STOP_NO_GREEN_IMPLEMENTATION

R4N00->R4N01
R4N00->R4N02
R4N01->R4N02
R4N00->R4N03
R4N02->R4N03
R4N03->R4N04
R4N03->R4N05
R4N04->R4N05
R4N03->R4N06
R4N04->R4N06
R4N05->R4N06
R4N06->R4N07
R4N06->R4N08
R4N06->R4N09
R4N06->R4N10
R4N07->R4N11
R4N08->R4N11
R4N09->R4N11
R4N10->R4N11
R4N07->R4N12
R4N08->R4N12
R4N09->R4N12
R4N10->R4N12
R4N11->R4N12
R4N12->R4N13
```

The r4 graph has no edge to a r3 blocked downstream node. R4N13 is terminal.
No implicit node or edge exists.

## 8. Mandatory mechanical validation and terminal condition

Before author handoff and again before independent review, validation MUST:

1. require UTF-8, no BOM, LF-only bytes, and one final LF;
2. parse every JSON fence with duplicate-key rejection, validate all three
   roots against Draft 2020-12 metaschema, and resolve every local `$ref`;
3. rehash all three predecessor rows and require exact path/size/hash equality;
4. prove the inherited r3 counts and accepted projections equal the exact r3
   contract/review, while retaining `REPAIR` and both open blockers;
5. prove exact counts: three schema paths, five semantic output paths, eight
   roles, eight unique principal values, 28 required separation pairs, 16
   checks, four RED cases, 14 r4 DAG nodes, and 25 r4 DAG edges;
6. topologically sort the r4 graph and reject a cycle, duplicate node/edge,
   missing endpoint, self-edge, or edge after R4N13;
7. execute the exact semantic algorithms in sections 3 and 4 against valid
   PASS, truthful REJECTED, hidden-blocker, open-roster mismatch, principal
   alias, and role/source relabel records;
8. require the author/reviewer/fixture/schema/native/production/binder values to
   come only from the exact immutable extraction or signed roster binding and
   compare all 28 pairs directly;
9. reject every Boolean independence assertion, free reviewer principal,
   findings-array duplicate-ID representation, current production hash,
   candidate import, true authority member, or Part-0 protocol hint; and
10. prove all eight downstream schema/semantic paths are absent before their
    create-only stages and that r2, r3, reviews, production, fixtures, schemas,
    candidates, and manifests were not edited.

Failure creates no successor and grants no authority. The only permissible
next work is the separately bound principal roster and fresh independent r4
governance review. Even PASS is bounded to the registered focused RED fixtures
and three schema renders; no downstream implementation or construction is
authorized.

Status: `CONTRACT_ONLY_PENDING_FRESH_INDEPENDENT_R4_REVIEW`
