# Program Facts G3-00 schema-closure amendment

Status: `CONTRACT_ONLY_PENDING_INDEPENDENT_REVIEW`

Normative parents, each established by three byte-identical stable reads, are:

| Parent | Bytes | SHA-256 |
|---|---:|---|
| `architecture/program-facts-runtime-cutover-spec.md` (PF-R2) | 238,989 | `2f2025cf636ca80df560d7568760f6ebfc114a2c344a895940ea76566c953c79` |
| `architecture/program-facts-g3-01-construction-amendment.md` (G3-01 amendment) | 22,967 | `b1e491f8250ed0927ba446e193dea86e60e2b70b3ed51a2e1cad6e59902266b0` |
| `architecture/ecosystem-graph-provider-contract.v2.md` (graph-v2) | 19,126 | `92a25f0d4506be18868f3b43483d5653cefd6c8cd3e30ae2c59bc5b41b5874c8` |
| `architecture/canonical-requirement-ownership.v2.json` (OWN-v2) | 61,064 | `18126a61679d3687db45b0748d0d010945923c5a21185d9708e58fd8c3222662` |

This amendment closes only the schema mechanics that PF-R2 G3-00 must finish
before the accepted G3-01 amendment can be reviewed or used. It does not amend
the PF-R2 160/691 denominator, implement a production symbol, accept a provider,
or grant runtime, runner, replay, package, publication, active-head, release,
cutover, consumer, finding, severity, confidence, refutation, suppression,
terminal-negative, or clean-certification authority. All authority ceilings in
this document and its artifacts are false. `MUST`, `MUST NOT`, `REQUIRED`,
`SHOULD`, and `MAY` have RFC 2119 meaning.

## 1. Exact closure decisions

| Previously open question | Normative closure |
|---|---|
| G3-00 schema denominator | Exactly the 12 paths in section 2; no discovery or globbing. |
| Carrier representation | The two literal, subject-independent definitions in section 3 are embedded byte-semantically in all 12 schemas. |
| Common fragments | The independent-review schema contains the four G3-01-required definitions, the two aggregate-admission definitions, and the closure-amendment review definition fixed below. |
| Carrier normalization | Raw parsed structural equality and `CJ` only; no `$ref` expansion, annotation removal, array sorting, or subject substitution. |
| Vector identity | The exact `pfsv-` preimage in section 4.1. |
| Review identity | The exact `pfsr-` preimage in section 4.2; specialized review IDs use their separately displayed preimages. |
| Pointer meaning | `schema_pointer`/`covers` name the keyword member; `target_schema_pointer` names its containing schema object. |
| Occurrence order | Containing-node pointer by UTF-16/JCS order, then the individual keyword ordinal in section 4.3, then full keyword pointer by UTF-16/JCS order. |
| Impossible negatives | Only the closed predicates in section 4.5 may have no negative vector; the classification is `SEMANTICALLY_IMPOSSIBLE_WITHIN_GATE3_DOMAIN`. |
| Provider v2 | The exact disabled, additive-only schema and registry in section 7; no dynamic upgrade or alternate adapter. |
| Generator/evaluator trust | Separate source authors; evaluator imports neither generator nor production and has no network/retrieval fallback. |
| Aggregate admission | One closed manifest and one independent review at the exact paths in section 8. |
| Invalidation | Adding the carriers rebuilds all 12 schema identities and every dependent vector/review; the acyclic order in section 9 is mandatory. |

## 2. Closed 12-schema denominator and paths

`G3_00_SCHEMA_ROSTER_V1` is exactly this ordered tuple. The order is a roster
identity, not filesystem order:

```text
rules/schemas/mechanical_program_facts.v3.schema.json
rules/schemas/mechanical_program_facts_debt.v3.schema.json
rules/schemas/mechanical_program_facts_receipt.v3.schema.json
rules/schemas/program_facts_active_selection.v1.schema.json
rules/schemas/program_facts_independent_review.v1.schema.json
rules/schemas/program_facts_phase_io_interface_vector.v1.schema.json
rules/schemas/program_facts_public_generation.v2.schema.json
rules/schemas/program_facts_publication_arm.v2.schema.json
rules/schemas/program_facts_r19_seed_acceptance.v1.schema.json
rules/schemas/program_facts_r19_seed_admission.v1.schema.json
rules/schemas/program_facts_source_identity_census.v1.schema.json
rules/schemas/program_facts_provider_registry.v2.schema.json
```

The last path does not exist in the pre-amendment state. Eleven existing files
is not a denominator success. Each subject `$id` is exactly
`https://plamen.local/schemas/<schema_filename>`. For each roster member, its
vector and review paths are, literally:

```text
review_fixtures/program_facts_runtime_gate3/schema_contracts/mechanical_program_facts.v3.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/mechanical_program_facts.v3.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/mechanical_program_facts_debt.v3.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/mechanical_program_facts_debt.v3.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/mechanical_program_facts_receipt.v3.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/mechanical_program_facts_receipt.v3.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_active_selection.v1.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_active_selection.v1.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_independent_review.v1.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_independent_review.v1.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_phase_io_interface_vector.v1.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_phase_io_interface_vector.v1.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_public_generation.v2.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_public_generation.v2.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_publication_arm.v2.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_publication_arm.v2.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_r19_seed_acceptance.v1.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_r19_seed_acceptance.v1.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_r19_seed_admission.v1.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_r19_seed_admission.v1.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_source_identity_census.v1.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_source_identity_census.v1.schema.json/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_provider_registry.v2.schema.json/conformance_vectors.v1.json
review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_provider_registry.v2.schema.json/independent_review.v1.json
```

The set is exactly 12 subjects and 24 child artifacts. Manifest schema-contract
rows sort by `(UTF8(schema.path),schema.size_bytes,schema.sha256)`; path uniqueness
is checked before set conversion. A different basename, directory, case, or
symlink-equivalent path is not an alias.

## 3. Literal subject-independent carrier definitions

The JSON objects in sections 3.1 and 3.2 are normative parsed JSON values. They
are not pseudocode. Each is inserted at the named key beneath the subject root
`$defs`. They contain no subject-local `$ref`; all primitives are inlined.
`maxLength` is a lexical code-point bound and the semantic validator additionally
applies PF-R2's UTF-8 byte limits. The portable-path lexical form is the existing
PF-R2 expression, its carrier `maxLength` is 4,096 for compatibility with the
existing common `file_identity`, and its semantic maximum remains 2,048 UTF-8
bytes.

### 3.1 `gate3_schema_conformance_vectors_v1`

```json
{
  "additionalProperties": false,
  "properties": {
    "body_sha256": {"maxLength": 64, "minLength": 64, "pattern": "^[0-9a-f]{64}$", "type": "string"},
    "keyword_occurrences": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "keyword": {"enum": ["$ref", "type", "const", "enum", "required", "additionalProperties", "propertyNames", "properties", "dependentRequired", "prefixItems", "items", "contains", "minContains", "maxContains", "minProperties", "maxProperties", "minItems", "maxItems", "uniqueItems", "minLength", "maxLength", "pattern", "minimum", "maximum", "multipleOf", "allOf", "anyOf", "oneOf", "not", "if", "then", "else"], "type": "string"},
          "negative_vector_ids": {"items": {"maxLength": 37, "minLength": 37, "pattern": "^pfsv-[0-9a-f]{32}$", "type": "string"}, "maxItems": 10000000, "minItems": 0, "type": "array", "uniqueItems": true},
          "positive_vector_ids": {"items": {"maxLength": 37, "minLength": 37, "pattern": "^pfsv-[0-9a-f]{32}$", "type": "string"}, "maxItems": 10000000, "minItems": 0, "type": "array", "uniqueItems": true},
          "schema_pointer": {"maxLength": 16384, "minLength": 0, "pattern": "^(?:/(?:[^~/]|~[01])*)*$", "type": "string"}
        },
        "required": ["schema_pointer", "keyword", "positive_vector_ids", "negative_vector_ids"],
        "type": "object"
      },
      "maxItems": 10000000,
      "minItems": 0,
      "type": "array",
      "uniqueItems": true
    },
    "schema_version": {"const": "plamen.program_facts_schema_conformance_vectors.v1", "type": "string"},
    "subject": {
      "additionalProperties": false,
      "properties": {
        "schema": {
          "additionalProperties": false,
          "properties": {
            "path": {"maxLength": 4096, "minLength": 1, "pattern": "^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$", "type": "string"},
            "sha256": {"maxLength": 64, "minLength": 64, "pattern": "^[0-9a-f]{64}$", "type": "string"},
            "size_bytes": {"maximum": 9007199254740991, "minimum": 0, "type": "integer"}
          },
          "required": ["path", "size_bytes", "sha256"],
          "type": "object"
        },
        "schema_id": {"maxLength": 512, "minLength": 1, "pattern": "^https://plamen\\.local/schemas/[A-Za-z0-9._-]+\\.schema\\.json$", "type": "string"}
      },
      "required": ["schema", "schema_id"],
      "type": "object"
    },
    "vector_count": {"maximum": 4294967295, "minimum": 0, "type": "integer"},
    "vectors": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "covers": {"items": {"maxLength": 16384, "minLength": 0, "pattern": "^(?:/(?:[^~/]|~[01])*)*$", "type": "string"}, "maxItems": 10000000, "minItems": 0, "type": "array", "uniqueItems": true},
          "expected": {"enum": ["VALID", "INVALID"], "type": "string"},
          "instance": {},
          "target_schema_pointer": {"maxLength": 16384, "minLength": 0, "pattern": "^(?:/(?:[^~/]|~[01])*)*$", "type": "string"},
          "vector_id": {"maxLength": 37, "minLength": 37, "pattern": "^pfsv-[0-9a-f]{32}$", "type": "string"}
        },
        "required": ["vector_id", "target_schema_pointer", "instance", "expected", "covers"],
        "type": "object"
      },
      "maxItems": 10000000,
      "minItems": 0,
      "type": "array",
      "uniqueItems": true
    }
  },
  "required": ["schema_version", "subject", "vectors", "keyword_occurrences", "vector_count", "body_sha256"],
  "type": "object"
}
```

### 3.2 `gate3_schema_conformance_review_v1`

```json
{
  "additionalProperties": false,
  "properties": {
    "checks": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "check_id": {"enum": ["SCHEMA-DRAFT", "VOCABULARY-KEYWORDS", "CLOSED-OBJECTS", "REF-CLOSURE", "VECTOR-CARRIER", "KEYWORD-OCCURRENCE-COVERAGE", "POSITIVE-REPLAY", "NEGATIVE-REPLAY", "IDENTITY-STABLE-READ"], "type": "string"},
          "evidence": {
            "items": {
              "additionalProperties": false,
              "properties": {
                "path": {"maxLength": 4096, "minLength": 1, "pattern": "^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$", "type": "string"},
                "sha256": {"maxLength": 64, "minLength": 64, "pattern": "^[0-9a-f]{64}$", "type": "string"},
                "size_bytes": {"maximum": 9007199254740991, "minimum": 0, "type": "integer"}
              },
              "required": ["path", "size_bytes", "sha256"],
              "type": "object"
            },
            "maxItems": 10000000,
            "minItems": 0,
            "type": "array",
            "uniqueItems": true
          },
          "result": {"enum": ["PASS", "FAIL"], "type": "string"}
        },
        "required": ["check_id", "result", "evidence"],
        "type": "object"
      },
      "maxItems": 9,
      "minItems": 0,
      "type": "array",
      "uniqueItems": true
    },
    "disposition": {"enum": ["PASS_SCHEMA_CONTRACT_FOR_GATE3_PREIMPLEMENTATION_ONLY", "REJECTED"], "type": "string"},
    "findings": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "description": {"maxLength": 8192, "minLength": 1, "type": "string"},
          "evidence": {
            "items": {
              "additionalProperties": false,
              "properties": {
                "path": {"maxLength": 4096, "minLength": 1, "pattern": "^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$", "type": "string"},
                "sha256": {"maxLength": 64, "minLength": 64, "pattern": "^[0-9a-f]{64}$", "type": "string"},
                "size_bytes": {"maximum": 9007199254740991, "minimum": 0, "type": "integer"}
              },
              "required": ["path", "size_bytes", "sha256"],
              "type": "object"
            },
            "maxItems": 10000000,
            "minItems": 0,
            "type": "array",
            "uniqueItems": true
          },
          "finding_id": {"maxLength": 512, "minLength": 1, "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$", "type": "string"},
          "severity": {"enum": ["BLOCKING", "NONBLOCKING"], "type": "string"},
          "status": {"enum": ["OPEN", "CLOSED"], "type": "string"}
        },
        "required": ["finding_id", "severity", "status", "description", "evidence"],
        "type": "object"
      },
      "maxItems": 10000000,
      "minItems": 0,
      "type": "array",
      "uniqueItems": true
    },
    "independence": {
      "additionalProperties": false,
      "properties": {
        "no_self_generated_evidence": {"const": true, "type": "boolean"},
        "oracle_author_separate": {"const": true, "type": "boolean"},
        "production_implementer_separate": {"const": true, "type": "boolean"},
        "subject_author_separate": {"const": true, "type": "boolean"},
        "vector_author_separate": {"const": true, "type": "boolean"},
        "workspace_clean": {"const": true, "type": "boolean"}
      },
      "required": ["subject_author_separate", "vector_author_separate", "production_implementer_separate", "oracle_author_separate", "workspace_clean", "no_self_generated_evidence"],
      "type": "object"
    },
    "open_findings": {"items": {"maxLength": 512, "minLength": 1, "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$", "type": "string"}, "maxItems": 10000000, "minItems": 0, "type": "array", "uniqueItems": true},
    "review_body_sha256": {"maxLength": 64, "minLength": 64, "pattern": "^[0-9a-f]{64}$", "type": "string"},
    "review_id": {"maxLength": 37, "minLength": 37, "pattern": "^pfsr-[0-9a-f]{32}$", "type": "string"},
    "reviewer": {
      "additionalProperties": false,
      "properties": {
        "organization": {"maxLength": 256, "minLength": 1, "type": "string"},
        "principal_id": {"maxLength": 256, "minLength": 12, "pattern": "^reviewer:[a-z0-9-]+/[a-z0-9-]+$", "type": "string"},
        "role": {"maxLength": 256, "minLength": 1, "type": "string"}
      },
      "required": ["principal_id", "organization", "role"],
      "type": "object"
    },
    "schema_version": {"const": "plamen.program_facts_schema_conformance_review.v1", "type": "string"},
    "subject": {
      "additionalProperties": false,
      "properties": {
        "path": {"maxLength": 4096, "minLength": 1, "pattern": "^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$", "type": "string"},
        "sha256": {"maxLength": 64, "minLength": 64, "pattern": "^[0-9a-f]{64}$", "type": "string"},
        "size_bytes": {"maximum": 9007199254740991, "minimum": 0, "type": "integer"}
      },
      "required": ["path", "size_bytes", "sha256"],
      "type": "object"
    },
    "vectors": {
      "additionalProperties": false,
      "properties": {
        "path": {"maxLength": 4096, "minLength": 1, "pattern": "^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$", "type": "string"},
        "sha256": {"maxLength": 64, "minLength": 64, "pattern": "^[0-9a-f]{64}$", "type": "string"},
        "size_bytes": {"maximum": 9007199254740991, "minimum": 0, "type": "integer"}
      },
      "required": ["path", "size_bytes", "sha256"],
      "type": "object"
    }
  },
  "required": ["schema_version", "review_id", "subject", "vectors", "reviewer", "independence", "checks", "findings", "open_findings", "disposition", "review_body_sha256"],
  "type": "object"
}
```

The schema-level `minItems:0` allowances exist only so the two carrier schemas
can have finite meta-vectors. Semantic validation of a real vector file requires
every vector `covers` array to contain exactly one pointer, every occurrence to
have a nonempty positive set, every check in a passing review to have nonempty
evidence, and the exact nine-check roster. A schema-only validation success does
not satisfy those semantic rules.

## 4. Canonical template, identities, pointers, and occurrence domain

### 4.1 Template normalization and vector identity

Let `V` and `R` be the parsed JSON values in sections 3.1 and 3.2. The sole
template preimage is:

```text
{
  "schema_version":"plamen.program_facts_gate3_schema_carrier_template.v1",
  "gate3_schema_conformance_vectors_v1":V,
  "gate3_schema_conformance_review_v1":R
}
```

`carrier_template_body_sha256 = SHA-256(CJ(template_preimage))` and is exactly
`a022374caccb7dbcdf6bb8fb596e0f81d8cf10c9bca1c5a5e626c3d09bdffc4f`.
The canonical preimage is 7,572 bytes. The value MUST equal the independently
reviewed value placed in the aggregate manifest. For every subject, strict-parse
twice, extract exactly the two named definitions, require parsed-value equality
to `V` and `R`, require byte equality of `CJ({gate3_schema_conformance_vectors_v1:
V,gate3_schema_conformance_review_v1:R})`, and recompute the template digest.
Normalization performs no dereference, annotation removal, array reorder,
subject substitution, Unicode normalization, or schema rewriting.

For a vector row, `covers` is already sorted by UTF-16/JCS string order and has
exactly one member. Its identity is:

```text
vector_id = "pfsv-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_SCHEMA_VECTOR_V1",
  subject_schema_id,
  target_schema_pointer,
  instance,
  expected,
  covers
}))[0:32]
```

The five preimage members after `domain` are exactly those shown (six members
total); the subject
file identity, vector-file identity, generator identity, timestamp, reviewer,
and result text are forbidden. `body_sha256` is
`SHA-256(CJ(vector_carrier_without_body_sha256))`; `CF` is that canonical object
plus one LF. IDs must be unique before array/set conversion. Vectors sort by
UTF-8 `vector_id`; occurrences use section 4.3; each ID list sorts by UTF-8 ID.

### 4.2 Per-schema review identity

The identity from the accepted G3-01 amendment is unchanged:

```text
review_id = "pfsr-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_SCHEMA_REVIEW_V1",
  subject,
  vectors,
  reviewer,
  independence,
  checks,
  findings,
  open_findings,
  disposition
}))[0:32]
```

Checks occur exactly once in this literal order:
`SCHEMA-DRAFT`, `VOCABULARY-KEYWORDS`, `CLOSED-OBJECTS`, `REF-CLOSURE`,
`VECTOR-CARRIER`, `KEYWORD-OCCURRENCE-COVERAGE`, `POSITIVE-REPLAY`,
`NEGATIVE-REPLAY`, `IDENTITY-STABLE-READ`. Findings sort by UTF-8 `finding_id`;
`open_findings` is exactly the IDs of `OPEN` findings in that order. Passing
requires all nine `PASS`, nonempty evidence in every check, no open blocking
finding, and all six independence booleans true. `review_body_sha256` omits only
itself. A per-schema review never embeds its own external file identity.

### 4.3 Keyword members and total order

The coverage-keyword ordinals are individual and closed. There are exactly 32:
PF-R2's 36 allowed keywords minus the four excluded structural/annotation
members `$schema`, `$id`, `$vocabulary`, and `$defs`.

```text
000 $ref
010 type
020 const
030 enum
040 required
050 additionalProperties
060 propertyNames
070 properties
080 dependentRequired
090 prefixItems
100 items
110 contains
111 minContains
112 maxContains
120 minProperties
121 maxProperties
130 minItems
131 maxItems
140 uniqueItems
150 minLength
151 maxLength
160 pattern
170 minimum
171 maximum
180 multipleOf
190 allOf
200 anyOf
210 oneOf
220 not
230 if
231 then
232 else
```

`$schema`, `$id`, `$vocabulary`, and `$defs` are excluded from occurrence
coverage and are checked by `SCHEMA-DRAFT`, `VOCABULARY-KEYWORDS`, and reference
closure. `schema_pointer` is the full pointer to the keyword member (for example
`/properties/foo/type`). `target_schema_pointer` is its containing schema object
(for example `/properties/foo`). `covers` contains the full keyword-member
pointer. Every vector covers exactly one occurrence; sibling or ancestor claims
are forbidden.

The traversal begins at the root and descends only through `$defs/<name>`,
`properties/<name>`, `propertyNames`, schema-valued `additionalProperties`,
`prefixItems/<canonical-index>`, schema-valued `items`, `contains`,
`allOf|anyOf|oneOf/<canonical-index>`, `not`, `if`, `then`, and `else`. It never
descends into `const`/`enum` instance values or boolean schemas. Object-member
names use RFC-6901 escaping. Array tokens are `0` or a nonzero ASCII digit
followed by digits; decode `~1` before `~0`, then re-encode and require byte
identity. Occurrences sort by `(UTF16(containing_schema_node_pointer),
keyword_ordinal,UTF16(full_keyword_pointer))`. Duplicate pointers are rejected
before sorting.

### 4.4 Closed coverage-atom obligations

For each occurrence the generator emits the following singleton-cover atoms.
`ACCEPT` maps to at least one `VALID` ID and `REJECT` to at least one `INVALID`
ID. Every displayed per-member/per-branch atom is distinct and counted in
`coverage_atom_count`.

| Keyword | Required atoms |
|---|---|
| `$ref` | `ACCEPT_RESOLVED`, `REJECT_RESOLVED`; an unresolved ref is schema-invalid, not a vector. |
| `type` | `ACCEPT_<type>` for every permitted member; `REJECT_DISALLOWED_TYPE`. |
| `const` | `ACCEPT_CONST`, `REJECT_UNEQUAL_SAME_TYPE`. |
| `enum` | `ACCEPT_MEMBER_<index>` for every literal member; `REJECT_UNKNOWN_SAME_TYPE`. |
| `required` | `ACCEPT_COMPLETE`; `REJECT_MISSING_<escaped-property>` for every member. |
| `additionalProperties` | false: `ACCEPT_NO_EXTRA`, `REJECT_UNKNOWN_FIELD`; schema-valued: `ACCEPT_EXTRA_VALUE`, `REJECT_EXTRA_VALUE`. |
| `propertyNames` | `ACCEPT_NAME`, `REJECT_NAME`. |
| `properties` | `ACCEPT_PROPERTY_<escaped-name>` and `REJECT_PROPERTY_<escaped-name>` for every child. |
| `dependentRequired` | `ACCEPT_TRIGGER_ABSENT`, `ACCEPT_TRIGGER_COMPLETE`, and `REJECT_<trigger>_MISSING_<dependent>` for every pair. |
| `prefixItems` | `ACCEPT_INDEX_<index>`, `REJECT_INDEX_<index>` for every branch. |
| `items` | `ACCEPT_ITEM`, `REJECT_ITEM`. |
| `contains` | exact-lower and exact-upper `ACCEPT` atoms when the bounds exist; `REJECT_TOO_FEW` and `REJECT_TOO_MANY` when applicable. |
| `minContains`, `maxContains` | boundary `ACCEPT`; one-step-outside `REJECT` when possible. |
| `minProperties`, `maxProperties`, `minItems`, `maxItems`, `minLength`, `maxLength`, `minimum`, `maximum` | boundary `ACCEPT`; one-step-outside `REJECT` when possible. |
| `uniqueItems` | `ACCEPT_DISTINCT_PAIR`, `REJECT_DUPLICATE_PAIR`. |
| `pattern` | `ACCEPT_PATTERN`, `REJECT_PATTERN` from the closed exact-pattern witness table. |
| `multipleOf` | `ACCEPT_MULTIPLE`, `REJECT_NONMULTIPLE`. |
| `allOf` | `ACCEPT_ALL`; `REJECT_BRANCH_<index>` for every branch. |
| `anyOf` | `ACCEPT_BRANCH_<index>` for every branch; `REJECT_ZERO_MATCH`. |
| `oneOf` | `ACCEPT_EXACT_BRANCH_<index>` for every branch; `REJECT_ZERO_MATCH`; `REJECT_MULTIPLE_MATCH` when possible. |
| `not` | `ACCEPT_CHILD_INVALID`, `REJECT_CHILD_VALID`. |
| `if` | `ACCEPT_CONDITION_TRUE`, `ACCEPT_CONDITION_FALSE`; direct rejection is impossible. |
| `then` | `ACCEPT_SELECTED_THEN`, `REJECT_SELECTED_THEN`. |
| `else` | `ACCEPT_SELECTED_ELSE`, `REJECT_SELECTED_ELSE`. |

Tagged closed-object unions additionally require, for each discriminator branch,
a branch positive, empty/zero-branch negative, unknown-tag negative, missing-tag
with branch-shaped payload, valid branch plus unknown field, and valid branch plus
a field exclusive to another branch. A multiple-`oneOf` negative is not claimed
when mutually exclusive const tags make it impossible. Unknown regex patterns
block generation: the pattern witness table is a closed map keyed by every exact
pattern in the 12 stable subjects; its key set must equal the independently
enumerated pattern set in both directions.

### 4.5 Impossible-negative classification

An atom may lack an `INVALID` vector only when the independent evaluator returns
`SEMANTICALLY_IMPOSSIBLE_WITHIN_GATE3_DOMAIN` for exactly one of these syntactic
predicates after resolving the containing schema and all same-document refs:

1. `maxItems == 10000000`;
2. `minItems == 0`;
3. `maxProperties == 4096`;
4. `minProperties == 0`;
5. `maxLength == 16384` (a 16,385-code-point string necessarily exceeds the
   PF-R2 16,384-byte global string ceiling);
6. `minLength == 0`;
7. `maximum == 9007199254740991`;
8. `minimum == -9007199254740991`;
9. `multipleOf == 1` in the integer-only PF-R2 numeric domain;
10. `type` permits all six canonical JSON instance types;
11. the direct `if` occurrence (which selects a branch but never rejects);
12. the `REJECT_MULTIPLE_MATCH` atom of a `oneOf` whose every pair of branches
    requires unequal `const` values for the same required discriminator property;
13. a delegated `REJECT` atom for `properties`, `propertyNames`,
    `additionalProperties`, `prefixItems`, `items`, `$ref`, or a composite branch
    whose exact resolved child is the literal empty schema object `{}` and whose
    path contains no other rejecting keyword.

No size-exceeding witness is constructed merely to prove a global ceiling.
Cases 1-9 are exact numeric comparisons, case 10 is exact set equality, case 11
is keyword identity, case 12 is an all-pairs structural proof over closed
required discriminator properties, and case 13 is exact parsed-value equality
to `{}` plus an empty rejecting-keyword census. No solver, timeout, sampling
result, inferred universal child, generator failure, or absent test may produce this
classification. Every other missing negative atom fails
`KEYWORD-OCCURRENCE-COVERAGE` and `NEGATIVE-REPLAY`.

## 5. Deterministic construction and independent evaluation

The three source identities are created at these exact paths:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/generate_schema_contracts_v1.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/evaluate_schema_contracts_independent_v1.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v1.py
```

All three are invoked with the accepted CPython 3.12 interpreter, an empty
argument list, repository cwd, shell disabled, closed inherited handles, a
secret-free environment, and network denied by the external launcher. Each
derives `REPO = Path(__file__).resolve(strict=True).parents[3]`, verifies its own
exact repository-relative path, and opens only literal paths in this contract.
An argument, environment-selected root, cwd-selected root, glob, directory
discovery, target-supplied schema, remote retrieval, dynamic import, or
`sys.path` mutation is fatal.

### 5.1 Generator

The generator may import only Python 3.12 standard-library modules plus
`jsonschema==4.26.0` and `referencing` as installed dependencies. It MUST NOT
import the independent evaluator, cross-check, a production Plamen module, or a
target repository. Its exact algorithm is:

1. Stable-read every roster subject and the exact registry twice; require strict
   UTF-8, no BOM, no duplicate keys, PF-R2 numeric limits, and identical reads.
2. Require exact Draft-2020-12 `$schema`, `$id`, and three-entry `$vocabulary`;
   reject every keyword outside PF-R2's closed set; run Draft-2020-12 schema
   validity before vector construction.
3. Compare both carrier fragments to section 3 and recompute the template
   digest. Any absent/different fragment blocks all output.
4. Build a closed `referencing.Registry` containing exactly the 12 `$id`/parsed
   subject pairs. Retrieval is a function that always raises. A ref is legal
   only if it is a same-document fragment or one of those exact absolute IDs.
5. Traverse only the schema-valued edges in section 4.3, enumerate occurrences
   and atoms in section 4.4, and sort by the closed order. Detect reference SCCs.
   An SCC blocks generation unless a later independently reviewed amendment
   names the exact subject digest, occurrence pointer, and finite witness; this
   amendment contains no override.
6. Construct minimal local-target witnesses. A vector validates only through an
   absolute wrapper `$ref` equal to `subject_schema_id + "#" +
   target_schema_pointer` (the fragment is omitted when the pointer is empty),
   so the subject base ID is retained. It never synthesizes a complete root when
   the target is a nested schema.
7. The exact 39-pattern witness map in section 5.1.1 is a literal constant in
   generator source.
   Before use, its keys must equal the independently enumerated pattern literals
   from all 12 subjects. An unknown or extra key blocks construction.
8. Carrier self-vectors target only
   `/$defs/gate3_schema_conformance_vectors_v1` or
   `/$defs/gate3_schema_conformance_review_v1`. Their instances use empty nested
   vector/check/finding arrays. A vector instance containing a nonempty
   conformance-vector carrier is rejected before serialization.
9. Build occurrence rows from vectors, then assert both directions: every
   occurrence has exactly one row; every `covers` pointer names a row; each ID
   exists, covers that row, and occurs in every and only its declared row; every
   positive/negative atom is satisfied or has the closed section-4.5
   impossibility proof; and IDs were unique before conversion.
10. Write only the 12 exact `conformance_vectors.v1.json` files as `CF`, after
    verifying `vector_count`, body digest, 16,777,216-byte control ceiling, and
    the exact subject file identity. It cannot write a subject schema, review,
    provider registry, admission manifest, or receipt.

### 5.1.1 Closed pattern witness map

The planned 12-subject pattern census has exactly 39 unique literals: the 32
already present in the 11 existing roster schemas plus exactly these seven
carrier/common-fragment additions: the JSON Pointer pattern, the local schema-ID
pattern, and the `pfsv-`, `pfsr-`, `pfg301r-`, `pfg3ar-`, and `pfg3cr-` patterns.
The following UTF-16/JCS-ordered map is the complete generator constant. Values
are literal Unicode strings after JSON decoding, not regex source fragments.
The generator and evaluator each compile every key with Python `re.fullmatch`,
require every `accept` to match and every `reject` not to match, and require key
set equality with the independently enumerated planned-subject set before any
vector is admitted.

```text
01 pattern = ^(?!/)(?!.*//)(?!.*(?:^|/)\.{1,2}(?:/|$))(?!.*[\\:\x00-\x1f\x7f])[^/]+(?:/[^/]+)*$
   accept  = a/b
   reject  = ../a
02 pattern = ^(?:/(?:[^~/]|~[01])*)*$
   accept  = /properties/a~1b
   reject  = /properties/a~2b
03 pattern = ^G3-(?:0[0-9]|1[0-2])$
   accept  = G3-00
   reject  = G3-13
04 pattern = ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$
   accept  = 2026-08-08T00:00:00Z
   reject  = 2026-08-08T00:00:00z
05 pattern = ^[0-9a-f]{64}$
   accept  = 0000000000000000000000000000000000000000000000000000000000000000
   reject  = 000000000000000000000000000000000000000000000000000000000000000g
06 pattern = ^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$
   accept  = a
   reject  = -a
07 pattern = ^https://plamen\.local/schemas/[A-Za-z0-9._-]+\.schema\.json$
   accept  = https://plamen.local/schemas/a.schema.json
   reject  = https://example.com/schemas/a.schema.json
08 pattern = ^pfal-[0-9a-f]{32}$
   accept  = pfal-00000000000000000000000000000000
   reject  = pfal-0000000000000000000000000000000g
09 pattern = ^pfat-[0-9a-f]{32}$
   accept  = pfat-00000000000000000000000000000000
   reject  = pfat-0000000000000000000000000000000g
10 pattern = ^pfc-[0-9a-f]{32}$
   accept  = pfc-00000000000000000000000000000000
   reject  = pfc-0000000000000000000000000000000g
11 pattern = ^pfcs-[0-9a-f]{32}$
   accept  = pfcs-00000000000000000000000000000000
   reject  = pfcs-0000000000000000000000000000000g
12 pattern = ^pfd-[0-9a-f]{32}$
   accept  = pfd-00000000000000000000000000000000
   reject  = pfd-0000000000000000000000000000000g
13 pattern = ^pfds-[0-9a-f]{32}$
   accept  = pfds-00000000000000000000000000000000
   reject  = pfds-0000000000000000000000000000000g
14 pattern = ^pfdt-[0-9a-f]{32}$
   accept  = pfdt-00000000000000000000000000000000
   reject  = pfdt-0000000000000000000000000000000g
15 pattern = ^pfea-[0-9a-f]{32}$
   accept  = pfea-00000000000000000000000000000000
   reject  = pfea-0000000000000000000000000000000g
16 pattern = ^pfec-[0-9a-f]{32}$
   accept  = pfec-00000000000000000000000000000000
   reject  = pfec-0000000000000000000000000000000g
17 pattern = ^pff-[0-9a-f]{32}$
   accept  = pff-00000000000000000000000000000000
   reject  = pff-0000000000000000000000000000000g
18 pattern = ^pfg-[0-9a-f]{32}$
   accept  = pfg-00000000000000000000000000000000
   reject  = pfg-0000000000000000000000000000000g
19 pattern = ^pfg301r-[0-9a-f]{32}$
   accept  = pfg301r-00000000000000000000000000000000
   reject  = pfg301r-0000000000000000000000000000000g
20 pattern = ^pfg3ar-[0-9a-f]{32}$
   accept  = pfg3ar-00000000000000000000000000000000
   reject  = pfg3ar-0000000000000000000000000000000g
21 pattern = ^pfg3cr-[0-9a-f]{32}$
   accept  = pfg3cr-00000000000000000000000000000000
   reject  = pfg3cr-0000000000000000000000000000000g
22 pattern = ^pfir-[0-9a-f]{32}$
   accept  = pfir-00000000000000000000000000000000
   reject  = pfir-0000000000000000000000000000000g
23 pattern = ^pfn-[0-9a-f]{32}$
   accept  = pfn-00000000000000000000000000000000
   reject  = pfn-0000000000000000000000000000000g
24 pattern = ^pfnc-[0-9a-f]{32}$
   accept  = pfnc-00000000000000000000000000000000
   reject  = pfnc-0000000000000000000000000000000g
25 pattern = ^pfo-[0-9a-f]{32}$
   accept  = pfo-00000000000000000000000000000000
   reject  = pfo-0000000000000000000000000000000g
26 pattern = ^pfps-[0-9a-f]{32}$
   accept  = pfps-00000000000000000000000000000000
   reject  = pfps-0000000000000000000000000000000g
27 pattern = ^pfpv-[0-9a-f]{32}$
   accept  = pfpv-00000000000000000000000000000000
   reject  = pfpv-0000000000000000000000000000000g
28 pattern = ^pfr-[0-9a-f]{32}$
   accept  = pfr-00000000000000000000000000000000
   reject  = pfr-0000000000000000000000000000000g
29 pattern = ^pfr19a-[0-9a-f]{32}$
   accept  = pfr19a-00000000000000000000000000000000
   reject  = pfr19a-0000000000000000000000000000000g
30 pattern = ^pfrs-[0-9a-f]{32}$
   accept  = pfrs-00000000000000000000000000000000
   reject  = pfrs-0000000000000000000000000000000g
31 pattern = ^pfrt-[0-9a-f]{64}$
   accept  = pfrt-0000000000000000000000000000000000000000000000000000000000000000
   reject  = pfrt-000000000000000000000000000000000000000000000000000000000000000g
32 pattern = ^pfs-[0-9a-f]{32}$
   accept  = pfs-00000000000000000000000000000000
   reject  = pfs-0000000000000000000000000000000g
33 pattern = ^pfsa-[0-9a-f]{32}$
   accept  = pfsa-00000000000000000000000000000000
   reject  = pfsa-0000000000000000000000000000000g
34 pattern = ^pfse-[0-9a-f]{32}$
   accept  = pfse-00000000000000000000000000000000
   reject  = pfse-0000000000000000000000000000000g
35 pattern = ^pfsr-[0-9a-f]{32}$
   accept  = pfsr-00000000000000000000000000000000
   reject  = pfsr-0000000000000000000000000000000g
36 pattern = ^pfss-[0-9a-f]{32}$
   accept  = pfss-00000000000000000000000000000000
   reject  = pfss-0000000000000000000000000000000g
37 pattern = ^pfsv-[0-9a-f]{32}$
   accept  = pfsv-00000000000000000000000000000000
   reject  = pfsv-0000000000000000000000000000000g
38 pattern = ^pftx-[0-9a-f]{32}$
   accept  = pftx-00000000000000000000000000000000
   reject  = pftx-0000000000000000000000000000000g
39 pattern = ^reviewer:[a-z0-9-]+/[a-z0-9-]+$
   accept  = reviewer:openai/security
   reject  = reviewer:OpenAI/security
```

### 5.1.2 Closed `type`, `const`, and `enum` witness rules

`type` uses the first different member in the fixed order
`null,boolean,integer,string,array,object`. Define `UNEQUAL_V1(x)` recursively:

- `null -> false`, `false -> true`, and `true -> false`;
- integer `n -> n+1`, except the PF-R2 safe maximum maps to `n-1`;
- string `s -> s+"x"` when the result meets the applicable code-point and UTF-8
  ceilings; otherwise a nonempty string loses its final Unicode scalar; the
  empty string maps to `"x"`;
- the empty array maps to `[null]`; a nonempty array copies the value and applies
  `UNEQUAL_V1` to index zero;
- the empty object maps to `{"x":null}`; a nonempty object copies the value and
  applies `UNEQUAL_V1` to the value of its first UTF-16/JCS-ordered key.

The construction is total only inside PF-R2's bounded JSON domain. Every result
must remain within the global numeric, item, property, string, depth, and byte
ceilings; inability to do so blocks construction. A `const` positive is the
literal value and its negative is `UNEQUAL_V1(const)` except for the one explicit
`accepted_scope` literal override below. For the two nonempty
composite provider constants this fixes the negative mutation exactly:
`P.ecosystems[0]` changes from `"EVM"` to `"EVMx"`, and
`P.providers[0].adapter.module` changes from
`"program_facts_evm_provider"` to `"program_facts_evm_providerx"`. For section
6.3 `accepted_scope`, the positive is exactly
`["G3_00_SCHEMA_CONSTRUCTION"]`, the `const` negative is exactly
`["G3_00_SCHEMA_CONSTRUCTION_INVALID"]`, and the `type` negative is `{}`.

For `enum`, positives are each literal member in source-array order. Negative
candidates are enumerated without discretion: group members by the type order
above while preserving source order within a group, apply `UNEQUAL_V1` to each,
then append the fixed bases `null,false,true,0,1,-1,"", "a",[],{}`. Filter by
the occurrence's declared `type` and all non-enum constraints, then select the
first value not JCS-equal to any member. Exhaustion is an impossible negative
only for the exact finite-domain predicates `type:null` with enum set `{null}`
or `type:boolean` with enum set `{false,true}`; every other exhaustion blocks.

Bounds use the exact bound and one integer/code-point/item/property step.
Properties use the first identifier-safe unknown name `x`, `x0`, `x1`, ... not
already present. A row's singleton `covers` claims only which keyword occurrence
the vector covers; it does not claim that this is the only keyword rejecting the
instance. A positive must satisfy the entire target subschema, and a negative's
expected `INVALID` is evaluated against that entire subschema, so a locally
constructed mutation may also fail sibling keywords. These rules eliminate
generator discretion. If the fixed candidate fails a required positive or
negative condition, generation fails closed; it never invents another witness.

### 5.2 Independent evaluator and stdlib cross-check

The evaluator is separately authored from the subject-schema builder and vector
generator. It MUST NOT import either, any production module, or oracle source.
It independently implements strict parsing, canonical JSON, pointer decoding and
round-trip encoding, schema-node traversal, occurrence/atom enumeration, sort
order, vector/review/body-ID derivation, template normalization, and the closed
impossibility classifier. It constructs its own closed `referencing.Registry`,
whose retrieval callback always raises, and uses Draft-2020-12
`jsonschema==4.26.0` to replay every instance through the exact absolute wrapper
ref. It compares subject and vector stable identities, occurrence sets, atom
sets, ID associations, valid/invalid results, counts, body digests, and ordering
in both directions. It produces process evidence only and MUST NOT write or
amend a vector, subject, per-schema review, aggregate manifest, or acceptance
receipt.

The stdlib cross-check is separately authored from generator and evaluator and
imports only `hashlib`, `json`, `pathlib`, and `typing`. It independently
re-enumerates pointers, ordinals, IDs, counts, body digests, sort order, and the
bidirectional vector/occurrence associations. It does not claim JSON-Schema
semantic replay. A later per-schema reviewer consumes the subject/vector bytes
and both independent process results, performs the nine checks, and alone writes
that schema's review. The aggregate reviewer is separate from all subject,
generator, evaluator, cross-check, per-schema-review, provider, and production
authors.

## 6. Literal common-schema fragments

In addition to the two carrier definitions, the root `$defs` of
`rules/schemas/program_facts_independent_review.v1.schema.json` MUST contain the
five literal fragments in sections 6.1-6.5. References to common definitions
bind their already-present closed parsed values; their stable bodies are still
covered by that subject's vectors. The specialized fragments do not expand the
root review union and cannot be accepted by the root schema accidentally;
callers validate against the exact fragment URI.

For every reviewer object in the carrier and specialized fragments,
`principal_id` has `minLength:12`, `maxLength:256`, and pattern
`^reviewer:[a-z0-9-]+/[a-z0-9-]+$`. `organization` and `role` are human-readable
strings with `minLength:1` and `maxLength:256` and have no pattern. Principal
syntax does not prove independence: every section-specific separation predicate
must still be established from independently identified workspaces and authors.

The specialized reviews in sections 6.1, 6.3, and 6.5 share these exact identity
rules. `identity_body` is the full closed parsed review object excluding exactly
`review_id` and `review_body_sha256`; it therefore includes `schema_version` and
every other schema-required member. For the section's literal domain and prefix:

```text
review_id = prefix || SHA-256(CJ({domain:<literal-domain>,review:identity_body}))[0:32]
review_body_sha256 = SHA-256(CJ(full_review_without_only_review_body_sha256))
review_file = CF(full_review)
```

The domain/prefix pairs are respectively
`PROGRAM_FACTS_G3_01_AMENDMENT_REVIEW_V1`/`pfg301r-`,
`PROGRAM_FACTS_G3_00_SCHEMA_CLOSURE_REVIEW_V1`/`pfg3cr-`, and
`PROGRAM_FACTS_G3_00_AGGREGATE_REVIEW_V1`/`pfg3ar-`. Checks occur exactly once
in their schema enum's displayed numeric order. Each evidence array sorts by
`(UTF8(path),size_bytes,sha256)` and is duplicate-free. Findings sort by UTF-8
`finding_id`, finding IDs are unique before conversion, and `open_findings` is
exactly the ordered projection of IDs whose finding status is `OPEN`. A repeated
review ID paired with unequal `identity_body`, body digest, or `CF` bytes is a
fatal collision; no two byte strings may share a review identity.

### 6.1 `g3_01_construction_amendment_review_v1`

```json
{
  "additionalProperties": false,
  "properties": {
    "authority_ceiling": {
      "additionalProperties": false,
      "properties": {
        "active_head_update": {"const": false, "type": "boolean"}, "clean_certification": {"const": false, "type": "boolean"}, "confidence": {"const": false, "type": "boolean"}, "consumer": {"const": false, "type": "boolean"}, "cutover": {"const": false, "type": "boolean"}, "finding": {"const": false, "type": "boolean"}, "package": {"const": false, "type": "boolean"}, "production_publication": {"const": false, "type": "boolean"}, "provider_launch": {"const": false, "type": "boolean"}, "refutation": {"const": false, "type": "boolean"}, "release": {"const": false, "type": "boolean"}, "replay": {"const": false, "type": "boolean"}, "runner": {"const": false, "type": "boolean"}, "runtime": {"const": false, "type": "boolean"}, "severity": {"const": false, "type": "boolean"}, "suppression": {"const": false, "type": "boolean"}, "terminal_negative": {"const": false, "type": "boolean"}
      },
      "required": ["runtime", "runner", "replay", "provider_launch", "package", "production_publication", "active_head_update", "release", "cutover", "consumer", "finding", "severity", "confidence", "refutation", "suppression", "terminal_negative", "clean_certification"],
      "type": "object"
    },
    "checks": {"items": {"additionalProperties": false, "properties": {"check_id": {"enum": ["PFG301-01-PARENT-PIN", "PFG301-02-LITERAL-MUTATIONS", "PFG301-03-SCHEMA-REVIEWS", "PFG301-04-PROTOCOL-PINS", "PFG301-05-ORACLE-INVOCATION", "PFG301-06-ACYCLIC-AUTHORITY", "PFG301-07-INDEPENDENCE"], "type": "string"}, "evidence": {"items": {"$ref": "#/$defs/file_identity"}, "maxItems": 10000000, "minItems": 1, "type": "array", "uniqueItems": true}, "result": {"enum": ["PASS", "FAIL"], "type": "string"}}, "required": ["check_id", "result", "evidence"], "type": "object"}, "maxItems": 7, "minItems": 7, "type": "array", "uniqueItems": true},
    "disposition": {"enum": ["PASS_G3_01_CONSTRUCTION_AMENDMENT_FOR_PREIMPLEMENTATION_ONLY", "REJECTED"], "type": "string"},
    "findings": {"items": {"additionalProperties": false, "properties": {"description": {"maxLength": 8192, "minLength": 1, "type": "string"}, "evidence": {"items": {"$ref": "#/$defs/file_identity"}, "maxItems": 10000000, "minItems": 1, "type": "array", "uniqueItems": true}, "finding_id": {"$ref": "#/$defs/identifier"}, "severity": {"enum": ["BLOCKING", "NONBLOCKING"], "type": "string"}, "status": {"enum": ["OPEN", "CLOSED"], "type": "string"}}, "required": ["finding_id", "severity", "status", "description", "evidence"], "type": "object"}, "maxItems": 10000000, "minItems": 0, "type": "array", "uniqueItems": true},
    "g3_00_admission": {"additionalProperties": false, "properties": {"independent_review": {"$ref": "#/$defs/file_identity"}, "manifest": {"$ref": "#/$defs/file_identity"}}, "required": ["manifest", "independent_review"], "type": "object"},
    "independence": {"additionalProperties": false, "properties": {"amendment_author_separate": {"const": true, "type": "boolean"}, "g3_00_subject_authors_separate": {"const": true, "type": "boolean"}, "no_self_generated_evidence": {"const": true, "type": "boolean"}, "oracle_author_separate": {"const": true, "type": "boolean"}, "production_implementer_separate": {"const": true, "type": "boolean"}, "workspace_clean": {"const": true, "type": "boolean"}}, "required": ["amendment_author_separate", "g3_00_subject_authors_separate", "production_implementer_separate", "oracle_author_separate", "workspace_clean", "no_self_generated_evidence"], "type": "object"},
    "normative_parent": {"$ref": "#/$defs/file_identity"},
    "open_findings": {"items": {"$ref": "#/$defs/identifier"}, "maxItems": 10000000, "minItems": 0, "type": "array", "uniqueItems": true},
    "review_body_sha256": {"$ref": "#/$defs/hex64"},
    "review_id": {"maxLength": 40, "minLength": 40, "pattern": "^pfg301r-[0-9a-f]{32}$", "type": "string"},
    "reviewer": {"additionalProperties": false, "properties": {"organization": {"maxLength": 256, "minLength": 1, "type": "string"}, "principal_id": {"maxLength": 256, "minLength": 12, "pattern": "^reviewer:[a-z0-9-]+/[a-z0-9-]+$", "type": "string"}, "role": {"maxLength": 256, "minLength": 1, "type": "string"}}, "required": ["principal_id", "organization", "role"], "type": "object"},
    "schema_version": {"const": "plamen.program_facts_g3_01_construction_amendment_review.v1", "type": "string"},
    "subject": {"$ref": "#/$defs/file_identity"}
  },
  "required": ["schema_version", "review_id", "subject", "normative_parent", "g3_00_admission", "reviewer", "independence", "checks", "findings", "open_findings", "disposition", "authority_ceiling", "review_body_sha256"],
  "type": "object"
}
```

Its `subject` is exactly the accepted G3-01 amendment pin; `normative_parent` is
exactly PF-R2; and the G3-00 pair is the completed manifest/review. It uses the
section-6 common identity, ordering, projection, digest, and collision rules
with the G3-01 domain/prefix pair.

### 6.2 `schema_contract_index_v1`

```json
{
  "additionalProperties": false,
  "properties": {
    "index_body_sha256": {"$ref": "#/$defs/hex64"},
    "schema_count": {"const": 51, "type": "integer"},
    "schema_version": {"const": "plamen.program_facts_schema_contract_index.v1", "type": "string"},
    "schemas": {"items": {"additionalProperties": false, "properties": {"accepted_stage": {"enum": ["G3_00", "G3_01"], "type": "string"}, "independent_review": {"$ref": "#/$defs/file_identity"}, "schema": {"$ref": "#/$defs/file_identity"}, "vectors": {"$ref": "#/$defs/file_identity"}}, "required": ["schema", "vectors", "independent_review", "accepted_stage"], "type": "object"}, "maxItems": 51, "minItems": 51, "type": "array", "uniqueItems": true}
  },
  "required": ["schema_version", "schemas", "schema_count", "index_body_sha256"],
  "type": "object"
}
```

Rows sort by `(UTF8(schema.path),schema.size_bytes,schema.sha256)`; schema paths
are unique before conversion; the exact PF-R2 51-path set is equal in both
directions; exactly the section-2 12 have `G3_00` and the other 39 have `G3_01`.
Each vectors/review path is the canonical basename-derived path. The index digest
omits only `index_body_sha256`.

### 6.3 `g3_00_schema_closure_amendment_review_v1`

```json
{
  "additionalProperties": false,
  "properties": {
    "accepted_scope": {"const": ["G3_00_SCHEMA_CONSTRUCTION"], "type": "array"},
    "authority_ceiling": {
      "additionalProperties": false,
      "properties": {
        "active_head_update": {"const": false, "type": "boolean"}, "clean_certification": {"const": false, "type": "boolean"}, "confidence": {"const": false, "type": "boolean"}, "consumer": {"const": false, "type": "boolean"}, "cutover": {"const": false, "type": "boolean"}, "finding": {"const": false, "type": "boolean"}, "package": {"const": false, "type": "boolean"}, "production_publication": {"const": false, "type": "boolean"}, "provider_launch": {"const": false, "type": "boolean"}, "refutation": {"const": false, "type": "boolean"}, "release": {"const": false, "type": "boolean"}, "replay": {"const": false, "type": "boolean"}, "runner": {"const": false, "type": "boolean"}, "runtime": {"const": false, "type": "boolean"}, "severity": {"const": false, "type": "boolean"}, "suppression": {"const": false, "type": "boolean"}, "terminal_negative": {"const": false, "type": "boolean"}
      },
      "required": ["runtime", "runner", "replay", "provider_launch", "package", "production_publication", "active_head_update", "release", "cutover", "consumer", "finding", "severity", "confidence", "refutation", "suppression", "terminal_negative", "clean_certification"],
      "type": "object"
    },
    "checks": {"items": {"additionalProperties": false, "properties": {"check_id": {"enum": ["G3C-01-PARENT-PINS", "G3C-02-DENOMINATOR-12", "G3C-03-LITERAL-CARRIER-TEMPLATES", "G3C-04-COMMON-FRAGMENTS", "G3C-05-IDENTITY-POINTER-RULES", "G3C-06-KEYWORD-ORDER-IMPOSSIBLE-NEGATIVES", "G3C-07-PROVIDER-REGISTRY-V2", "G3C-08-PATHS-GENERATOR-EVALUATOR", "G3C-09-AGGREGATE-ADMISSION", "G3C-10-INVALIDATION-DAG", "G3C-11-AUTHORITY-CEILING", "G3C-12-INDEPENDENCE"], "type": "string"}, "evidence": {"items": {"$ref": "#/$defs/file_identity"}, "maxItems": 10000000, "minItems": 1, "type": "array", "uniqueItems": true}, "result": {"enum": ["PASS", "FAIL"], "type": "string"}}, "required": ["check_id", "result", "evidence"], "type": "object"}, "maxItems": 12, "minItems": 12, "type": "array", "uniqueItems": true},
    "disposition": {"enum": ["PASS_G3_00_SCHEMA_CLOSURE_FOR_CONSTRUCTION_ONLY", "REJECTED"], "type": "string"},
    "findings": {"items": {"additionalProperties": false, "properties": {"description": {"maxLength": 8192, "minLength": 1, "type": "string"}, "evidence": {"items": {"$ref": "#/$defs/file_identity"}, "maxItems": 10000000, "minItems": 1, "type": "array", "uniqueItems": true}, "finding_id": {"$ref": "#/$defs/identifier"}, "severity": {"enum": ["BLOCKING", "NONBLOCKING"], "type": "string"}, "status": {"enum": ["OPEN", "CLOSED"], "type": "string"}}, "required": ["finding_id", "severity", "status", "description", "evidence"], "type": "object"}, "maxItems": 10000000, "minItems": 0, "type": "array", "uniqueItems": true},
    "independence": {"additionalProperties": false, "properties": {"no_self_generated_evidence": {"const": true, "type": "boolean"}, "production_implementer_separate": {"const": true, "type": "boolean"}, "schema_builder_separate": {"const": true, "type": "boolean"}, "subject_author_separate": {"const": true, "type": "boolean"}, "vector_generator_separate": {"const": true, "type": "boolean"}, "workspace_clean": {"const": true, "type": "boolean"}}, "required": ["subject_author_separate", "schema_builder_separate", "vector_generator_separate", "production_implementer_separate", "workspace_clean", "no_self_generated_evidence"], "type": "object"},
    "normative_parents": {"items": {"$ref": "#/$defs/file_identity"}, "maxItems": 4, "minItems": 4, "type": "array", "uniqueItems": true},
    "open_findings": {"items": {"$ref": "#/$defs/identifier"}, "maxItems": 10000000, "minItems": 0, "type": "array", "uniqueItems": true},
    "review_body_sha256": {"$ref": "#/$defs/hex64"},
    "review_id": {"maxLength": 39, "minLength": 39, "pattern": "^pfg3cr-[0-9a-f]{32}$", "type": "string"},
    "reviewer": {"additionalProperties": false, "properties": {"organization": {"maxLength": 256, "minLength": 1, "type": "string"}, "principal_id": {"maxLength": 256, "minLength": 12, "pattern": "^reviewer:[a-z0-9-]+/[a-z0-9-]+$", "type": "string"}, "role": {"maxLength": 256, "minLength": 1, "type": "string"}}, "required": ["principal_id", "organization", "role"], "type": "object"},
    "schema_version": {"const": "plamen.program_facts_g3_00_schema_closure_amendment_review.v1", "type": "string"},
    "subject": {"$ref": "#/$defs/file_identity"}
  },
  "required": ["schema_version", "review_id", "subject", "normative_parents", "reviewer", "independence", "checks", "findings", "open_findings", "disposition", "accepted_scope", "authority_ceiling", "review_body_sha256"],
  "type": "object"
}
```

The fixed receipt path is:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_SCHEMA_CLOSURE_AMENDMENT_INDEPENDENT_REVIEW.v1.json
```

Before the common schema is rebuilt, an independent reviewer validates this
receipt against the literal fragment above as extracted from the stable
amendment bytes. Because that fragment has three common-definition refs, the
bootstrap evaluator stable-reads the pre-amendment common schema (10,255 bytes,
SHA-256 `c912708c1df702528ffa005516c5d855397f6b9c249382caea740071550a0080`),
extracts only its `file_identity`, `identifier`, and `hex64` definitions, and
constructs this in-memory, never-written wrapper: exact PF-R2 `$schema` and
three-entry `$vocabulary`; `$id` const
`https://plamen.local/schemas/program_facts_g3_00_schema_closure_bootstrap.v1.schema.json`;
`$defs` containing those three extracted parsed values plus
`g3_00_schema_closure_amendment_review_v1` equal to the section-6.3 parsed
value; and root `$ref` exactly
`#/$defs/g3_00_schema_closure_amendment_review_v1`. No other definition or
keyword is present. The old common-schema identity is check evidence, not a
normative parent or successor input. After construction, the common schema MUST
embed the same parsed fragment and the receipt MUST also validate against that
fragment URI.
The receipt never names or hashes the not-yet-built common schema, any vector,
aggregate admission, amendment receipt, G3-01 output, freeze, production module,
or its own external identity. This is the only permitted bootstrap and breaks
the review-schema cycle without predicting a future hash.

The exact `normative_parents` array is the four file identities at the top of
this document sorted by `(UTF8(path),size_bytes,sha256)`. Passing requires all 12
checks `PASS`, nonempty evidence, no open blocking finding, exact accepted scope,
every authority bit false, and all six independence values true. It uses the
section-6 common identity, ordering, projection, digest, and collision rules
with the G3-00 schema-closure domain/prefix pair.

### 6.4 `g3_00_admission_manifest_v1`

```json
{
  "additionalProperties": false,
  "properties": {
    "admission_body_sha256": {"$ref": "#/$defs/hex64"},
    "authority_ceiling": {
      "additionalProperties": false,
      "properties": {
        "active_head_update": {"const": false, "type": "boolean"}, "clean_certification": {"const": false, "type": "boolean"}, "confidence": {"const": false, "type": "boolean"}, "consumer": {"const": false, "type": "boolean"}, "cutover": {"const": false, "type": "boolean"}, "finding": {"const": false, "type": "boolean"}, "package": {"const": false, "type": "boolean"}, "production_publication": {"const": false, "type": "boolean"}, "provider_launch": {"const": false, "type": "boolean"}, "refutation": {"const": false, "type": "boolean"}, "release": {"const": false, "type": "boolean"}, "replay": {"const": false, "type": "boolean"}, "runner": {"const": false, "type": "boolean"}, "runtime": {"const": false, "type": "boolean"}, "severity": {"const": false, "type": "boolean"}, "suppression": {"const": false, "type": "boolean"}, "terminal_negative": {"const": false, "type": "boolean"}
      },
      "required": ["runtime", "runner", "replay", "provider_launch", "package", "production_publication", "active_head_update", "release", "cutover", "consumer", "finding", "severity", "confidence", "refutation", "suppression", "terminal_negative", "clean_certification"],
      "type": "object"
    },
    "carrier_template": {"additionalProperties": false, "properties": {"normalization_id": {"const": "plamen.program_facts_gate3_schema_carrier_template.v1", "type": "string"}, "template_body_sha256": {"$ref": "#/$defs/hex64"}}, "required": ["normalization_id", "template_body_sha256"], "type": "object"},
    "phase_io_contracts": {"items": {"$ref": "#/$defs/file_identity"}, "maxItems": 2, "minItems": 2, "type": "array", "uniqueItems": true},
    "predecessors": {"additionalProperties": false, "properties": {"compact_seed_admission": {"$ref": "#/$defs/file_identity"}, "external_seed_acceptance": {"$ref": "#/$defs/file_identity"}, "graph_v2": {"$ref": "#/$defs/file_identity"}, "ownership_v2": {"$ref": "#/$defs/file_identity"}, "public_v3_architecture_review": {"$ref": "#/$defs/file_identity"}, "schema_closure_amendment": {"$ref": "#/$defs/file_identity"}, "schema_closure_amendment_review": {"$ref": "#/$defs/file_identity"}, "seed_admission_review": {"$ref": "#/$defs/file_identity"}, "source_identity_census": {"$ref": "#/$defs/file_identity"}, "specification": {"$ref": "#/$defs/file_identity"}, "specification_review": {"$ref": "#/$defs/file_identity"}}, "required": ["compact_seed_admission", "external_seed_acceptance", "seed_admission_review", "specification", "specification_review", "source_identity_census", "graph_v2", "ownership_v2", "public_v3_architecture_review", "schema_closure_amendment", "schema_closure_amendment_review"], "type": "object"},
    "provider_registry": {"additionalProperties": false, "properties": {"registry": {"$ref": "#/$defs/file_identity"}, "schema": {"$ref": "#/$defs/file_identity"}}, "required": ["schema", "registry"], "type": "object"},
    "public_v3_schemas": {"items": {"$ref": "#/$defs/file_identity"}, "maxItems": 6, "minItems": 6, "type": "array", "uniqueItems": true},
    "schema_contract_count": {"const": 12, "type": "integer"},
    "schema_contracts": {"items": {"additionalProperties": false, "properties": {"accepted_stage": {"const": "G3_00", "type": "string"}, "coverage_atom_count": {"maximum": 4294967295, "minimum": 0, "type": "integer"}, "independent_review": {"$ref": "#/$defs/file_identity"}, "keyword_occurrence_count": {"maximum": 4294967295, "minimum": 0, "type": "integer"}, "schema": {"$ref": "#/$defs/file_identity"}, "schema_id": {"maxLength": 512, "minLength": 1, "pattern": "^https://plamen\\.local/schemas/[A-Za-z0-9._-]+\\.schema\\.json$", "type": "string"}, "vector_count": {"maximum": 4294967295, "minimum": 0, "type": "integer"}, "vectors": {"$ref": "#/$defs/file_identity"}}, "required": ["schema", "schema_id", "vectors", "independent_review", "accepted_stage", "keyword_occurrence_count", "coverage_atom_count", "vector_count"], "type": "object"}, "maxItems": 12, "minItems": 12, "type": "array", "uniqueItems": true},
    "schema_version": {"const": "plamen.program_facts_g3_00_admission_manifest.v1", "type": "string"}
  },
  "required": ["schema_version", "predecessors", "carrier_template", "provider_registry", "phase_io_contracts", "public_v3_schemas", "schema_contracts", "schema_contract_count", "authority_ceiling", "admission_body_sha256"],
  "type": "object"
}
```

### 6.5 `g3_00_aggregate_review_v1`

```json
{
  "additionalProperties": false,
  "properties": {
    "authority_ceiling": {
      "additionalProperties": false,
      "properties": {
        "active_head_update": {"const": false, "type": "boolean"}, "clean_certification": {"const": false, "type": "boolean"}, "confidence": {"const": false, "type": "boolean"}, "consumer": {"const": false, "type": "boolean"}, "cutover": {"const": false, "type": "boolean"}, "finding": {"const": false, "type": "boolean"}, "package": {"const": false, "type": "boolean"}, "production_publication": {"const": false, "type": "boolean"}, "provider_launch": {"const": false, "type": "boolean"}, "refutation": {"const": false, "type": "boolean"}, "release": {"const": false, "type": "boolean"}, "replay": {"const": false, "type": "boolean"}, "runner": {"const": false, "type": "boolean"}, "runtime": {"const": false, "type": "boolean"}, "severity": {"const": false, "type": "boolean"}, "suppression": {"const": false, "type": "boolean"}, "terminal_negative": {"const": false, "type": "boolean"}
      },
      "required": ["runtime", "runner", "replay", "provider_launch", "package", "production_publication", "active_head_update", "release", "cutover", "consumer", "finding", "severity", "confidence", "refutation", "suppression", "terminal_negative", "clean_certification"],
      "type": "object"
    },
    "checks": {"items": {"additionalProperties": false, "properties": {"check_id": {"enum": ["G3A-01-PREDECESSOR-LINEAGE", "G3A-02-CARRIER-TEMPLATE-EQUALITY", "G3A-03-SCHEMA-DENOMINATOR-12", "G3A-04-PROVIDER-REGISTRY-V2", "G3A-05-PHASE-IO-RACI-OPERATION-ORDER", "G3A-06-SCHEMA-DRAFT-VOCABULARY-CLOSURE", "G3A-07-VECTOR-RESULT-REPLAY", "G3A-08-BIDIRECTIONAL-KEYWORD-ATOM-COVERAGE", "G3A-09-PER-SCHEMA-REVIEW-INDEPENDENCE", "G3A-10-AUTHORITY-CEILING", "G3A-11-REVIEWER-INDEPENDENCE"], "type": "string"}, "evidence": {"items": {"$ref": "#/$defs/file_identity"}, "maxItems": 10000000, "minItems": 1, "type": "array", "uniqueItems": true}, "result": {"enum": ["PASS", "FAIL"], "type": "string"}}, "required": ["check_id", "result", "evidence"], "type": "object"}, "maxItems": 11, "minItems": 11, "type": "array", "uniqueItems": true},
    "disposition": {"enum": ["PASS_G3_00_ADMISSION_FOR_G3_01_AMENDMENT_REVIEW_ONLY", "REJECTED"], "type": "string"},
    "findings": {"items": {"additionalProperties": false, "properties": {"description": {"maxLength": 8192, "minLength": 1, "type": "string"}, "evidence": {"items": {"$ref": "#/$defs/file_identity"}, "maxItems": 10000000, "minItems": 1, "type": "array", "uniqueItems": true}, "finding_id": {"$ref": "#/$defs/identifier"}, "severity": {"enum": ["BLOCKING", "NONBLOCKING"], "type": "string"}, "status": {"enum": ["OPEN", "CLOSED"], "type": "string"}}, "required": ["finding_id", "severity", "status", "description", "evidence"], "type": "object"}, "maxItems": 10000000, "minItems": 0, "type": "array", "uniqueItems": true},
    "independence": {"additionalProperties": false, "properties": {"aggregate_subject_author_separate": {"const": true, "type": "boolean"}, "crosscheck_author_separate": {"const": true, "type": "boolean"}, "evaluator_author_separate": {"const": true, "type": "boolean"}, "no_self_generated_evidence": {"const": true, "type": "boolean"}, "per_schema_reviewers_separate": {"const": true, "type": "boolean"}, "production_implementer_separate": {"const": true, "type": "boolean"}, "schema_authors_separate": {"const": true, "type": "boolean"}, "vector_generator_separate": {"const": true, "type": "boolean"}, "workspace_clean": {"const": true, "type": "boolean"}}, "required": ["aggregate_subject_author_separate", "schema_authors_separate", "vector_generator_separate", "evaluator_author_separate", "crosscheck_author_separate", "per_schema_reviewers_separate", "production_implementer_separate", "workspace_clean", "no_self_generated_evidence"], "type": "object"},
    "open_findings": {"items": {"$ref": "#/$defs/identifier"}, "maxItems": 10000000, "minItems": 0, "type": "array", "uniqueItems": true},
    "review_body_sha256": {"$ref": "#/$defs/hex64"},
    "review_id": {"maxLength": 39, "minLength": 39, "pattern": "^pfg3ar-[0-9a-f]{32}$", "type": "string"},
    "reviewer": {"additionalProperties": false, "properties": {"organization": {"maxLength": 256, "minLength": 1, "type": "string"}, "principal_id": {"maxLength": 256, "minLength": 12, "pattern": "^reviewer:[a-z0-9-]+/[a-z0-9-]+$", "type": "string"}, "role": {"maxLength": 256, "minLength": 1, "type": "string"}}, "required": ["principal_id", "organization", "role"], "type": "object"},
    "schema_version": {"const": "plamen.program_facts_g3_00_aggregate_review.v1", "type": "string"},
    "subject": {"$ref": "#/$defs/file_identity"}
  },
  "required": ["schema_version", "review_id", "subject", "reviewer", "independence", "checks", "findings", "open_findings", "disposition", "authority_ceiling", "review_body_sha256"],
  "type": "object"
}
```

This review uses the section-6 common identity, ordering, projection, digest,
and collision rules with the G3-00 aggregate domain/prefix pair. The subject is
only the already-closed manifest; the review cannot appear inside or affect it.

## 7. Exact provider-registry-v2 schema and registry

The only paths are:

```text
rules/schemas/program_facts_provider_registry.v2.schema.json
rules/program-facts-provider-registry.v2.json
```

The following construction is literal value substitution, not implementation
guidance. Object member order is immaterial before `CJ`; every array retains the
displayed order. `AUTHORITY_V2` is exactly:

```json
{"can_certify_clean":false,"can_demote":false,"can_refute":false,"can_suppress":false,"semantic_authority":"ADDITIVE_PROPOSAL_ONLY","terminal_negative_authority":false}
```

The EVM capability array is exactly:

| Capability ID | `allowed_relation_kinds` in literal order | `allowed_provenance_origins` in literal order | `maximum_precision` |
|---|---|---|---|
| `evm.slither.calls.v1` | `MAY_REACH_CHA`, `MAY_REACH_RTA`, `MAY_REACH_VTA`, `RESOLVED_STATIC_CALL`, `UNRESOLVED_DYNAMIC_CALL` | `AST`, `BYTECODE`, `COMPILER_IR` | `EXACT` |
| `evm.slither.cfg.v1` | `EXACT_CFG_DOMINATES`, `EXACT_CFG_EDGE`, `EXACT_CFG_POST_DOMINATES` | `COMPILER_IR`, `SSA` | `EXACT` |
| `evm.slither.dependencies.v1` | `MAY_DEPENDENCY_CONTRACT`, `MAY_DEPENDENCY_FUNCTION` | `AST`, `COMPILER_IR`, `SSA` | `MAY` |
| `evm.slither.sinks.v1` | `AUTH_CHECK_OCCURRENCE`, `CREATE_OCCURRENCE`, `SYNTACTIC_SINK`, `VALUE_TRANSFER_OCCURRENCE` | `AST`, `COMPILER_IR`, `SOURCE_PARSE` | `EXACT` |
| `evm.slither.state.v1` | `READS_STATE`, `WRITES_STATE` | `AST`, `COMPILER_IR`, `SSA` | `EXACT` |
| `evm.slither.structure.v1` | `CONTAINS`, `DECLARES`, `INHERITS_OR_IMPLEMENTS` | `AST`, `INDEX_REFERENCE` | `EXACT` |

Each row expands to the closed object
`{capability_id,implementation_state:"IMPLEMENTED",allowed_relation_kinds,
allowed_provenance_origins,maximum_precision,host_semantic_authority:false}`.
The EVM provider row is the closed object:

```text
{
  provider_id:"evm.slither.typed",
  ecosystem:"EVM",
  implementation_state:"IMPLEMENTED",
  adapter:{
    module:"program_facts_evm_provider",
    symbol:"plan_evm_slither",
    module_file_identity:{
      path:"scripts/program_facts_evm_provider.py",
      size_bytes:124515,
      sha256:"356783aa0cfeac2b7cdd731262dea3748994fc5adec3208d11d6fca6631c4981"
    }
  },
  capabilities:<the exact six rows above>,
  tool_identity_policy:{
    host_manifest_schema_id:"https://plamen.local/schemas/program_facts_host_tool_manifest.v1.schema.json",
    version_policy:"EXACT_SLITHER_ANALYZER_0_11_5_AND_PER_BUILD_SOLC_FULL_IDENTITY",
    network_allowed:false
  },
  authority:AUTHORITY_V2
}
```

The seven placeholder tuples, in literal provider order, are:

```text
(GO,      go.placeholder.not_implemented,      go.program_facts.not_implemented.v1)
(RUST,    rust.placeholder.not_implemented,    rust.program_facts.not_implemented.v1)
(SOLANA,  solana.placeholder.not_implemented,  solana.program_facts.not_implemented.v1)
(SOROBAN, soroban.placeholder.not_implemented, soroban.program_facts.not_implemented.v1)
(APTOS,   aptos.placeholder.not_implemented,   aptos.program_facts.not_implemented.v1)
(SUI,     sui.placeholder.not_implemented,     sui.program_facts.not_implemented.v1)
(DAML,    daml.placeholder.not_implemented,    daml.program_facts.not_implemented.v1)
```

Each `(ecosystem,provider_id,capability_id)` expands to exactly:

```text
{
  provider_id,
  ecosystem,
  implementation_state:"NOT_IMPLEMENTED",
  adapter:null,
  capabilities:[{
    capability_id,
    implementation_state:"NOT_IMPLEMENTED",
    allowed_relation_kinds:[],
    allowed_provenance_origins:[],
    maximum_precision:"NONE",
    host_semantic_authority:false
  }],
  tool_identity_policy:null,
  authority:AUTHORITY_V2
}
```

The registry parsed value is exactly:

```text
{
  schema_version:"plamen.program_facts_provider_registry.v2",
  release_state:"CONTRACT_FROZEN_EXECUTION_DISABLED",
  ecosystems:[EVM,GO,RUST,SOLANA,SOROBAN,APTOS,SUI,DAML],
  providers:[<EVM row>,<seven expanded placeholder rows>],
  registry_body_sha256:"56962c461653c11e76201987e2bc98c7f9d50e4e0db7128e1b7525c70f878d89"
}
```

The displayed digest is `SHA-256(CJ(registry without registry_body_sha256))`.
The registry file is `CF(registry)`; no timestamp, tool probe, review, adapter
discovery, host result, or runtime state is present.

Let `P` be that exact parsed registry, and let `V` and `R` be the literal carrier
definitions from section 3. The provider schema is exactly the following parsed
value after replacing only the three uppercase value tokens with their already
defined parsed JSON values. Substitution does not stringify, merge, dereference,
or reorder them:

```text
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_provider_registry.v2.schema.json",
  "$vocabulary":{
    "https://json-schema.org/draft/2020-12/vocab/core":true,
    "https://json-schema.org/draft/2020-12/vocab/applicator":true,
    "https://json-schema.org/draft/2020-12/vocab/validation":true
  },
  "$defs":{
    "gate3_schema_conformance_vectors_v1":V,
    "gate3_schema_conformance_review_v1":R
  },
  "additionalProperties":false,
  "properties":{
    "schema_version":{"const":"plamen.program_facts_provider_registry.v2","type":"string"},
    "release_state":{"const":"CONTRACT_FROZEN_EXECUTION_DISABLED","type":"string"},
    "ecosystems":{"const":P.ecosystems,"items":{"enum":["EVM","GO","RUST","SOLANA","SOROBAN","APTOS","SUI","DAML"],"type":"string"},"maxItems":8,"minItems":8,"type":"array","uniqueItems":true},
    "providers":{"const":P.providers,"maxItems":8,"minItems":8,"type":"array","uniqueItems":true},
    "registry_body_sha256":{"const":"56962c461653c11e76201987e2bc98c7f9d50e4e0db7128e1b7525c70f878d89","maxLength":64,"minLength":64,"pattern":"^[0-9a-f]{64}$","type":"string"}
  },
  "required":["schema_version","release_state","ecosystems","providers","registry_body_sha256"],
  "type":"object"
}
```

The schema file is `CF` of that expanded value. Its `const` payloads are instance
values and are never traversed as schemas. Registry validation additionally
recomputes the body digest and exact provider/ecosystem/capability order; checks
that every provider authority equals `AUTHORITY_V2`; and rejects a provider,
capability, relation, provenance origin, precision, adapter, tool policy, or
module identity not displayed above. `CONTRACT_FROZEN_EXECUTION_DISABLED` grants
no provider launch. PF-R2's separately reviewed G3-09 row-scoped exception and a
later release/cutover are the only possible external authorizations; neither is
stored in or inferred from this registry.

## 8. Aggregate G3-00 admission and review semantics

The exact paths are:

```text
review_fixtures/program_facts_runtime_gate3/g3_00/PROGRAM_FACTS_G3_00_ADMISSION_MANIFEST.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00/PROGRAM_FACTS_G3_00_ADMISSION_MANIFEST_INDEPENDENT_REVIEW.v1.json
```

The manifest validates only against
`program_facts_independent_review.v1.schema.json#/$defs/g3_00_admission_manifest_v1`;
the review validates only against `#/$defs/g3_00_aggregate_review_v1`.
`admission_body_sha256` omits only itself. The manifest does not contain a
manifest ID and never contains or predicts its external review identity.

The manifest field sets have these exact semantic closures:

- `predecessors` names the literal paths for compact seed admission, external
  seed acceptance, compact seed review, PF-R2, PF-R2 review, source census,
  graph-v2, OWN-v2, public-v3 architecture review, this amendment, and its
  independent review. Every member is a stable file identity.
- `carrier_template` has the exact normalization ID and digest from section 4.1.
- `provider_registry` is exactly the two section-7 paths.
- `phase_io_contracts`, sorted by `(UTF8(path),size_bytes,sha256)`, contains
  exactly `rules/schemas/program_facts_phase_io_interface_vector.v1.schema.json`
  and
  `review_fixtures/program_facts_runtime_gate3/phase_io/canonical_work_unit_key_vectors.v1.json`.
  Together with the already-pinned PF-R2, graph-v2, and OWN-v2 predecessors,
  these bind all 264 six-component keys, `DRIVER` ownership, output RACI, lock
  order, and `MATERIALIZE_IMMUTABLE_V3 -> COMMIT_ACTIVE_HEAD_CAS_V1 ->
  MATERIALIZE_ACTIVE_PROJECTION_V1` exclusive order. No prose-only surrogate is
  allowed.
- `public_v3_schemas`, in the same file-identity sort, is exactly the payload,
  receipt, debt, public-generation-v2, publication-arm-v2, and active-selection
  schema paths from section 2.
- `schema_contracts` is exactly one sorted row for every section-2 subject. Its
  `schema_id` equals the subject `$id`; vector/review identities equal the two
  canonical sibling paths; counts are recomputed before admission; every stage
  is `G3_00`.
- `schema_contract_count` is 12 and all 17 authority booleans are false.

The aggregate review performs exactly these checks in order and with nonempty
file-identity evidence:

1. `G3A-01-PREDECESSOR-LINEAGE`: every predecessor path/size/hash, accepted
   disposition, dependency direction, and stable read is valid; this amendment's
   review has only construction scope.
2. `G3A-02-CARRIER-TEMPLATE-EQUALITY`: all 24 extracted fragment values equal
   section 3 and all 12 recomputed template digests equal section 4.1.
3. `G3A-03-SCHEMA-DENOMINATOR-12`: the roster, `$id` set, 12 rows, 24 canonical
   child paths, and both-direction membership are exact.
4. `G3A-04-PROVIDER-REGISTRY-V2`: section-7 schema expansion, registry bytes,
   digest, eight rows, six EVM capabilities, seven placeholders, and all false
   authority are exact.
5. `G3A-05-PHASE-IO-RACI-OPERATION-ORDER`: the exact two artifacts plus accepted
   parent contracts prove the 264-key/RACI/exclusive-order projection.
6. `G3A-06-SCHEMA-DRAFT-VOCABULARY-CLOSURE`: each subject has exact Draft,
   vocabulary, allowed-keyword, closed-object, schema-valid, and closed-ref
   properties.
7. `G3A-07-VECTOR-RESULT-REPLAY`: the independent evaluator reproduces every
   `VALID|INVALID` result, vector ID, count, body digest, and stable identity.
8. `G3A-08-BIDIRECTIONAL-KEYWORD-ATOM-COVERAGE`: evaluator and stdlib cross-check
   independently reproduce occurrence/atom sets, orders, associations, and only
   the closed impossible-negative classifications.
9. `G3A-09-PER-SCHEMA-REVIEW-INDEPENDENCE`: exactly 12 reviews validate, all nine
   checks pass with evidence, no blocker is open, and authorship predicates hold.
10. `G3A-10-AUTHORITY-CEILING`: every subject/vector/review/registry/manifest
    authority is additive/contract-only and every displayed authority bit is
    false.
11. `G3A-11-REVIEWER-INDEPENDENCE`: the aggregate reviewer is separate from all
    construction/evaluation/review/production principals and has a clean
    independently identified workspace.

The passing disposition permits only an independent review of the already
stable G3-01 amendment. G3-01 construction still requires that separate exact
amendment receipt. Aggregate admission alone cannot start G3-01.

### 8.1 Exact public-v3 successor review

After the six public schemas and provider-v2 pair are rebuilt, the only public-v3
successor review path is:

```text
review_fixtures/program_facts_runtime_gate3/architecture/PROGRAM_FACTS_PUBLIC_V3_AMENDMENT_INDEPENDENT_REVIEW.v1.json
```

It validates against the root
`program_facts_independent_review.v1.schema.json`, uses the root review's exact
ID/body rules, and retains disposition `PASS_PUBLIC_V3_SHADOW_CONTRACT_ONLY`.
Its `subjects`, sorted as file identities by
`(UTF8(path),size_bytes,sha256)`, are exactly graph-v2, OWN-v2, and these six
rebuilt schemas:

```text
rules/schemas/mechanical_program_facts.v3.schema.json
rules/schemas/mechanical_program_facts_debt.v3.schema.json
rules/schemas/mechanical_program_facts_receipt.v3.schema.json
rules/schemas/program_facts_active_selection.v1.schema.json
rules/schemas/program_facts_public_generation.v2.schema.json
rules/schemas/program_facts_publication_arm.v2.schema.json
```

Its `input_artifacts`, under the same sort and exact-set rule, are exactly:

```text
architecture/canonical-requirement-ownership.v1.json
architecture/program-facts-runtime-cutover-spec.md
review_fixtures/program_facts_runtime_gate3/phase_io/canonical_work_unit_key_vectors.v1.json
rules/program-facts-provider-registry.v2.json
rules/schemas/program_facts_provider_registry.v2.schema.json
```

The six vectors occur exactly once in the displayed order, all are `PASS`, and
their evidence arrays are the following exact file-identity path sets,
independently sorted by `(UTF8(path),size_bytes,sha256)`:

```text
ARCH-V3-01-CLOSED-PUBLIC-SCHEMAS
  rules/schemas/mechanical_program_facts.v3.schema.json
  rules/schemas/mechanical_program_facts_debt.v3.schema.json
  rules/schemas/mechanical_program_facts_receipt.v3.schema.json
  rules/schemas/program_facts_active_selection.v1.schema.json
  rules/schemas/program_facts_public_generation.v2.schema.json
  rules/schemas/program_facts_publication_arm.v2.schema.json
ARCH-V3-02-SOURCE-BINDING-GROUP
  architecture/program-facts-runtime-cutover-spec.md
  rules/schemas/mechanical_program_facts.v3.schema.json
  rules/schemas/mechanical_program_facts_debt.v3.schema.json
  rules/schemas/mechanical_program_facts_receipt.v3.schema.json
ARCH-V3-03-PROVIDER-REGISTRY-CROSS-REFERENCES
  architecture/ecosystem-graph-provider-contract.v2.md
  rules/schemas/mechanical_program_facts_receipt.v3.schema.json
  rules/program-facts-provider-registry.v2.json
  rules/schemas/program_facts_provider_registry.v2.schema.json
ARCH-V3-04-OWNERSHIP-V1-TO-V2
  architecture/canonical-requirement-ownership.v1.json
  architecture/canonical-requirement-ownership.v2.json
  architecture/program-facts-runtime-cutover-spec.md
ARCH-V3-05-COMPATIBILITY-DISPATCH
  architecture/ecosystem-graph-provider-contract.v2.md
  rules/schemas/program_facts_active_selection.v1.schema.json
  rules/schemas/program_facts_public_generation.v2.schema.json
  rules/schemas/program_facts_publication_arm.v2.schema.json
ARCH-V3-06-AUTHORITY-ALL-FALSE
  architecture/ecosystem-graph-provider-contract.v2.md
  review_fixtures/program_facts_runtime_gate3/phase_io/canonical_work_unit_key_vectors.v1.json
  rules/schemas/mechanical_program_facts.v3.schema.json
  rules/schemas/mechanical_program_facts_debt.v3.schema.json
  rules/schemas/mechanical_program_facts_receipt.v3.schema.json
```

`ARCH-V3-03` validates the registry against the provider-registry-v2 schema,
recomputes its body digest, proves the exact eight ecosystems/providers, six EVM
capabilities, seven placeholders, registry module identity, and receipt/source/
selection capability cross-references. Both v2 files MUST occur in
`input_artifacts` and in that vector's evidence. A v1 registry path, a v1 schema
path, a split v1/v2 pair, a compatibility fallback, or omission of either v2
identity is invalid even if the remaining semantic projection matches. The
review has no open blocking finding, preserves the root review's exact finding/
open-finding/evidence ordering, and grants no authority beyond the unchanged
shadow-contract disposition.

## 9. Exact invalidation and acyclic build order

The pre-amendment evidence that remains historical and MUST NOT be overwritten is:

| Artifact | Current stable identity and consequence |
|---|---|
| External seed acceptance | 3,354 bytes, `2b90643c5fbd03feffaa081f7a751ceff7746e580d92a1b8aa7bfae2db1b4c00`; preserve. |
| Compact seed admission | 2,006 bytes, `355013cc8c641b8768b1c555bc5edda9fe3bb8abac2c30c7b8f91a01ebb96754`; may remain byte-stable after revalidation. |
| Original G3-00 handoff | 6,129 bytes, `ef84c95d53f7488a9a9f04490edc567095b7ad251c6e0ab12fa3304e155806ab`; historical, pending, excluded from aggregate authority. |
| Original freeze-preparation test | `3d57b76621dee6a509c5c79d3d19ecfb2890354e29da12e60c0ebbf30e39e0cb`; preserve because the seed receipt uses it as narrow independence evidence. |
| PF-R2 review | 8,918 bytes, `51e4fa9c3cdd521def95201142f98aeb9aad4160053a0122342a699815478d20`; remains if its stable subject/input pins remain valid. |
| Source census | 17,954 bytes, `e8c555ce473cfe6ff6c09cf1a2254d94c079562f951242f3e45278e89a4d5b50`; remains if its exact census is unchanged. |
| PhaseIO matrix | 465,657 bytes, `7d359ea8d61b31ffff0ca35e386a889b5bd66cb3913d10303d9ea4e9883f1f84`; remains if revalidated unchanged. |

Adding either carrier changes all 11 existing subject hashes; creating provider
v2 establishes the twelfth. Changing the common independent-review schema and
seed-admission schema, and reissuing the public-v3 review, invalidates the old
compact seed review. Changing the six public-v3 schema subjects invalidates the
old public-v3 architecture review. Therefore the current compact review
`fff5c06ef8f1b50bc32a06c565a0d34048b62d5736f44dddd823f5ce11fb4d8f` and public
review `b2d6d714ecfbc09d2e693d672d7cac1adaff0e3b536d3a43d15d5b99630214fa`
cannot appear in the new aggregate even if their paths are reused for successor
bytes. A stale review is never rescued by an unchanged disposition string.

The only valid order is:

1. stable-read this amendment and create its independent review from the literal
   section-6.3 fragment, before schema changes;
2. keep the original seed evidence/handoff/test immutable and add red-first
   successor closure fixtures at new paths;
3. update the schema builder to embed all required common fragments, build the
   exact provider-v2 schema/registry, and embed `V`/`R` identically in all 12;
4. rebuild all 12 subject schemas and prove exact Draft/vocabulary/keyword/ref/
   closure/template properties before vector generation;
5. generate exactly 12 vector files, run the independent evaluator and stdlib
   cross-check, then have independent principals write exactly 12 per-schema
   reviews;
6. reissue the public-v3 architecture review over the six new identities;
7. revalidate the unchanged external seed acceptance and compact admission,
   then reissue the compact seed review at its exact canonical path against the
   new common/seed-admission/public-review identities;
8. rebuild every other G3-00 dependent whose input identity changed; stable-read
   all predecessor and schema-contract bytes; author the aggregate manifest;
9. an independent aggregate reviewer writes only its later review;
10. a principal independent of the amendment and G3-00 authors writes the exact
    G3-01 amendment receipt from section 6.1; and
11. run the full hash/schema/count/bijection/authority closure. Only then may
    G3-01 begin.

No schema consumes its per-schema review; no vector consumes a review; the
manifest consumes completed schema/vector/review triplets but not itself or its
later review; the aggregate review consumes the manifest; the G3-01 amendment
review consumes both completed aggregate identities but no G3-01 output. Any
predecessor byte change invalidates every transitive successor and requires a
new reviewed version. A builder may not edit a frozen receipt in place.

## 10. Acceptance and authority ceiling

This document is ready only for an independent review of its contract. A
passing section-6.3 receipt permits construction of the bounded G3-00 schema
closure and nothing else. The constructed schemas, vectors, registries,
per-schema reviews, aggregate manifest, aggregate review, and G3-01 amendment
review are preimplementation governance evidence. None is runtime or provider
authority; none is a test pass for G3-01; none is a contract/release freeze; none
can activate PhaseIO, launch a provider, write a production ArtifactLedger head,
publish a v3 generation, select facts, certify absence, score/demote/refute/
suppress a finding, release a package, or cut over the driver.

Implementation code, runtime/provider/package paths, audits, target repositories,
commits, pushes, installs, and cutover are outside this amendment. Failure to
complete any exact identity, roster, vector, review, digest, ordering,
independence, or false-authority requirement leaves G3-00 unaccepted and G3-01
blocked; haltless degradation is not available for governance failure.
