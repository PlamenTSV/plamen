# Program Facts G3-00 schema-vector clarification amendment

Status: `CONTRACT_ONLY_PENDING_INDEPENDENT_REVIEW`

The exact normative parents are:

| Parent | Bytes | SHA-256 |
|---|---:|---|
| `architecture/program-facts-g3-00-schema-closure-amendment.md` | 88,187 | `85534326385e04c73d74f92c3dfa13b0b8702131bd3e97ce97bbd998e685b280` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_SCHEMA_CLOSURE_AMENDMENT_INDEPENDENT_REVIEW.v1.json` | 9,002 | `c3dd6f630b9bd6c2ff73aacd386c35b3201659d2eead45be90bb6835e71edd4f` |

This amendment resolves only the six closed conflict classes A-F in the accepted G3-00
schema-vector contract. It does not modify either parent, any subject schema,
the provider registry, a carrier fragment, a production module, or an artifact
already frozen by a parent. It grants no runtime, runner, replay, provider,
package, publication, active-head, release, cutover, consumer, finding,
severity, confidence, refutation, suppression, terminal-negative, or
clean-certification authority. `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, and
`MAY` have RFC 2119 meaning. Terms `CJ`, `CF`, `UTF8`, `UTF16`, schema pointer,
target schema pointer, occurrence, and coverage atom retain the exact meanings
fixed by the schema-closure parent.

## 1. Precedence and closed result

This document is a narrow semantic successor to parent sections 3.1, 4.4, 4.5,
5.1, 5.1.2, and 5.2. Where one of the following exact rules conflicts with
those sections, this amendment controls. Every other parent requirement remains
unchanged.

The closed result is:

1. the impossible-negative predicate roster contains exactly 16 predicates:
   unchanged parent cases 1-12, narrowed parent case 13, and new cases 14-16;
2. the impossible-positive predicate roster contains exactly three predicates:
   `POS-01-MAXITEMS-CONTROL-CEILING`,
   `POS-02-LOCAL-SCHEMA-ID-MINLENGTH`, and
   `POS-03-ITEMS-FALSE-CHILD-VALID`;
3. the deterministic pattern-positive witness-override roster contains exactly
   one predicate, `WIT-01-DIRECT-HEX64-CONST`;
4. every impossible atom remains in `coverage_atom_count` and in the independently
   enumerated atom denominator; impossibility discharges only the obligation to
   associate a vector ID with that atom;
5. an empty occurrence direction remains fatal except for the one exact
   direction whose every atom is discharged by a matching predicate in this
   closed roster; and
6. no solver result, timeout, allocation failure, sampling result, inferred
   finite domain, generator failure, absent vector, or reviewer discretion can
   create an impossibility classification.

An impossibility proof is atom-scoped, never occurrence-scoped. A predicate that
discharges one atom cannot discharge a sibling atom or the opposite direction.
The generator, independent evaluator, and stdlib cross-check each construct the
same logical proof set independently; they compare it by exact `CJ` value and
set equality after rejecting duplicate proof keys. No implementation imports
another implementation's predicate table or proof result.

The six and only six amendment classes are: A, ten-million-item boundary
positives; B, local-schema-ID one-code-point boundary positives; C, the direct
provider-digest sibling-const pattern witness; D, `items:false` child-valid
positives; E, tagged-union cross-branch-exclusive-field negatives; and F, the
two prospective exact finite-enum negatives. A construction failure outside
A-F is an implementation defect and blocks. It cannot be converted into a new
waiver without a separately reviewed successor amendment.

## 2. Exact matching primitives

For this amendment only, define the following deterministic primitives.

`JSET(A)` is defined only when `A` is a JSON array whose member `CJ` byte strings
are unique. It is the mathematical set of those member `CJ` byte strings. Array
order is not part of set equality. Duplicate enum members are schema-invalid and
block before this primitive is used.

`PURE_LOCAL_REF_RESOLVE_V1(N,D)` starts with schema node `N` in subject document
`D`. If `N` is not an object containing `$ref`, it returns `N`. Otherwise it may
follow the reference only when `N` has exactly the one member `$ref`, the
reference resolves within `D`, RFC-6901 decode/re-encode is byte-identical, and
the target is not already in the chain. It repeats this rule. An absolute URI to
another roster subject, a retrieval fallback, a `$ref` sibling, a cycle, a
missing target, or a boolean target makes the predicate using this primitive
not match. It does not make the schema acceptable by itself.

`CLOSED_BRANCH_V1(N,D)` first applies `PURE_LOCAL_REF_RESOLVE_V1`. It succeeds
only for an object with direct members `"type":"object"`,
`"additionalProperties":false`, `"properties"` whose value is an object, and
`"required"` whose value is an array of unique strings. Its property-name set is
exactly the UTF-16/JCS string set of keys of that direct `properties` object.
No inherited, ancestor, applicator, unevaluated, or inferred property is added.

The proof key used for parity is the exact tuple

```text
(subject_schema_id, schema_pointer, atom_id, direction, predicate_id)
```

ordered by `(UTF16(subject_schema_id),UTF16(schema_pointer),UTF16(atom_id),
UTF16(direction),UTF16(predicate_id))`. The proof value is the exact parsed JSON
value specified by the matching section below. Proof keys and values must be
equal in both directions across generator, evaluator, and cross-check process
evidence. These are process records only; this amendment creates no new artifact
file solely for proof rows and adds no proof member to a vector carrier. The
later receipt and launcher-captured process-evidence files are the explicitly
defined governance artifacts in sections 11 and 13, not standalone proof stores.

For this key, `direction` is the literal string `POSITIVE` for an impossible
positive and `NEGATIVE` for an impossible negative. The witness-decision key is
the exact tuple `(subject_schema_id,schema_pointer,atom_id,predicate_id)`, ordered
by UTF-16/JCS string order over those four components in the displayed order.

## 3. New impossible-negative cases 14 and 15: exact finite enums

Parent case numbering is extended by exactly these two atom-scoped predicates:

14. `NEG-14-ENUM-NULL-CLOSED-DOMAIN` matches only the atom
    `REJECT_UNKNOWN_SAME_TYPE` for an `enum` occurrence whose direct physical
    containing schema object has `"type":"null"` and whose enum satisfies
    `JSET(enum) == {CJ(null)}`.
15. `NEG-15-ENUM-BOOLEAN-CLOSED-DOMAIN` matches only the atom
    `REJECT_UNKNOWN_SAME_TYPE` for an `enum` occurrence whose direct physical
    containing schema object has `"type":"boolean"` and whose enum satisfies
    `JSET(enum) == {CJ(false),CJ(true)}`.

For case 14 the proof value is exactly:

```json
{"enum_jset":["null"],"type":"null"}
```

For case 15 it is exactly:

```json
{"enum_jset":["false","true"],"type":"boolean"}
```

The `enum_jset` strings above are literal member `CJ` byte strings sorted by
UTF-16/JCS string order. Matching examines the physical object that contains the
enumerated `enum` keyword occurrence. It does not accumulate a `type` from a
parent, `$ref`, `allOf`, condition, sibling branch, `const`, bound, or format.
The scalar `type` string is exact; `"type":["null"]` and
`"type":["boolean"]` do not match. No other finite enum is inferred. In
particular, a singleton string/integer enum, an integer interval exhausted by an
enum, a `const`, a subset of booleans, an enum plus a prohibiting `not`, or any
candidate-list exhaustion outside these two exact predicates blocks generation.

All `ACCEPT_MEMBER_<index>` atoms remain required in source-array order. Cases
14-15 permit only the corresponding occurrence row's negative ID set to omit an
ID for `REJECT_UNKNOWN_SAME_TYPE`; they do not waive an enum positive, a `type`
atom, or any sibling constraint. Candidate enumeration in parent section 5.1.2
remains normative for every nonmatching enum and may not itself be interpreted
as an impossibility proof.

## 4. Exact impossible-positive case POS-01: ten-million-item boundary

Parent section 4.4 requires an `ACCEPT_BOUNDARY` atom for every `maxItems`
occurrence. For the exact parsed numeric value 10,000,000, no such vector can fit
inside the parent's 16,777,216-byte control-document ceiling. This is proven
without constructing or allocating the array.

For `N = 10,000,000`, the shortest possible canonical JSON encoding of any JSON
array of exactly `N` elements has:

```text
opening bracket                         1 byte
N shortest JSON values (`0`)            N bytes
N - 1 comma separators                  N - 1 bytes
closing bracket                         1 byte
minimum CJ(instance)              2*N + 1 bytes
                                  20,000,001 bytes
control-document ceiling          16,777,216 bytes
```

Every array element needs at least one byte in canonical JSON, every adjacent
pair needs one comma, and both brackets are mandatory. The enclosing vector row
and carrier can only add bytes. Therefore every candidate `CF(vector_carrier)`
is strictly larger than 20,000,001 bytes and necessarily exceeds 16,777,216.

`POS-01-MAXITEMS-CONTROL-CEILING` matches only when all of these are true:

- the atom is exactly `ACCEPT_BOUNDARY`;
- the occurrence keyword is exactly `maxItems`;
- its parsed value is the JSON integer 10,000,000 (a boolean is not an integer);
- the inherited control-document ceiling is exactly 16,777,216 bytes; and
- the independently recomputed lower bound is exactly 20,000,001 bytes and is
  strictly greater than that ceiling.

Its proof value is exactly:

```json
{"ceiling_bytes":16777216,"comma_bytes":9999999,"element_count":10000000,"minimum_array_cj_bytes":20000001,"minimum_element_bytes":1,"structural_bytes":2}
```

The `ACCEPT_BOUNDARY` atom stays in `coverage_atom_count`. It has no associated
positive vector ID. Because it is the sole positive atom of that `maxItems`
occurrence, this amendment narrowly replaces the parent section-3 semantic
nonempty-positive rule as follows: `positive_vector_ids` is exactly `[]` only
when every positive atom for that occurrence is discharged by a matching closed
impossible-positive proof. At present that means only this exact predicate. The
empty list is not a vector, is not counted in `vector_count`, and is not evidence
that a smaller array satisfies `ACCEPT_BOUNDARY`.

No occurrence-presence surrogate is emitted. In particular, `[]`, `[0]`, a
`minItems` boundary, or a vector constructed for a sibling keyword cannot be
listed as satisfying this atom merely to make `positive_vector_ids` nonempty.
This avoids both a false boundary claim and a new item-synthesis algorithm.

Parent impossible-negative case 1 remains separate and unchanged: only the
one-step-outside negative for `maxItems == 10000000` is discharged by that
negative predicate. POS-01 neither implies nor replaces case 1. A different
`maxItems`, a different ceiling, a non-boundary positive, or failure to allocate
a feasible smaller boundary does not match POS-01 and blocks if its required
witness is absent.

## 5. New impossible-negative case 16: absent cross-branch exclusive field

For a parent tagged closed-object `oneOf` union, assign the previously textual
obligation `valid branch plus a field exclusive to another branch` the exact
per-branch atom ID:

```text
TAGGED_BRANCH_<canonical-index>_REJECT_CROSS_BRANCH_FIELD
```

`canonical-index` is the branch's existing zero-based JSON array index written
as `0` or a nonzero ASCII digit followed by digits. This naming does not add an
atom; it gives the already-required atom an unambiguous identity.

`NEG-16-TAGGED-UNION-NO-EXCLUSIVE-FIELD` matches only that atom and only by the
following proof:

1. The containing keyword is `oneOf` and every branch succeeds under
   `CLOSED_BRANCH_V1`.
2. A discriminator candidate is a property name present and required in every
   branch whose direct property schema is an object containing direct `const`.
   Its branch `CJ(const)` values must be pairwise unequal. Select the first
   candidate by UTF-16/JCS string order. No candidate means no match.
3. For selected branch `B_i`, let `P_i` be its exact property-name set and let
   `X_i = (union of P_j for every j != i) - P_i`.
4. The predicate matches exactly when `X_i` is empty by set equality.

The proof value is:

```text
{
  "branch_index":i,
  "discriminator":<selected property name>,
  "discriminator_const_cj":CJ(the selected branch's const),
  "other_minus_selected":[],
  "property_sets":[<each branch property-name array in branch order>],
  "union_pointer":<full pointer to the oneOf keyword>
}
```

Each property-name array sorts by UTF-16/JCS string order. `other_minus_selected`
must be exactly empty; absence of a synthesizeable value for a nonempty candidate
does not match and instead blocks. An open branch, a branch without direct closed
object proof, an external reference, a `$ref` sibling, a cyclic reference, a
missing/polymorphic discriminator, or a nonunique discriminator const does not
match. This is not a general tagged-union waiver.

The current 12-subject construction has exactly six matching atom instances,
all in `rules/schemas/mechanical_program_facts_receipt.v3.schema.json`:

| Union pointer | Branch indices | Exact property-name set for every branch |
|---|---|---|
| `/properties/nonsemantic_transport/oneOf` | `0`, `1`, `2` | `invocation_label`, `wrapper_file_identity` |
| `/properties/replay/oneOf` | `0`, `1`, `2` | `outcome`, `semantic_source` |

For each selected branch the other-branch union minus the selected set is empty.
The atom remains in the denominator and has no negative vector ID. The other
five tagged-union obligations per branch remain mandatory: branch positive,
zero-branch negative, unknown-tag negative, missing-tag branch-shaped negative,
and valid-branch-plus-unknown-field negative. Case 16 cannot discharge any of
them, nor `REJECT_ZERO_MATCH` or `REJECT_MULTIPLE_MATCH` from the ordinary
`oneOf` roster.

## 6. Exact pattern-positive witness under a direct sibling const

Parent section 5.1.1 normally fixes `ACCEPT_PATTERN` to the table's `accept`
value. That value can be invalid against a direct sibling `const`, even when the
const itself satisfies the pattern. The witness selection precedence is now
exactly:

1. apply `WIT-01-DIRECT-HEX64-CONST` when it matches;
2. otherwise use the exact parent section-5.1.1 table `accept`; and
3. if the selected value does not validate against the entire target subschema,
   block without searching for another value.

`WIT-01-DIRECT-HEX64-CONST` matches only the atom `ACCEPT_PATTERN` and only when
the physical containing schema object has all of these direct parsed members:

```text
pattern == "^[0-9a-f]{64}$"
const is a JSON string
len(const) == 64 Unicode scalar values
every scalar of const is in the literal ASCII set "0123456789abcdef"
```

Its witness is exactly that direct `const` string. These structural tests are
the complete proof that `re.fullmatch(pattern,const)` succeeds for this exact
closed pattern; the stdlib cross-check performs them without importing `re`.
The parent cross-check import boundary remains exactly `hashlib`, `json`,
`pathlib`, and `typing`. Generator and evaluator may additionally replay the
already-required exact pattern, but cannot replace the structural predicate or
delegate it to the cross-check.

The sole current match is:

```text
subject: rules/schemas/program_facts_provider_registry.v2.schema.json
occurrence: /properties/registry_body_sha256/pattern
const: 56962c461653c11e76201987e2bc98c7f9d50e4e0db7128e1b7525c70f878d89
```

All three processes independently emit the logical witness-decision key

```text
(subject_schema_id,/properties/registry_body_sha256/pattern,ACCEPT_PATTERN,WIT-01-DIRECT-HEX64-CONST)
```

with proof value exactly:

```json
{"const":"56962c461653c11e76201987e2bc98c7f9d50e4e0db7128e1b7525c70f878d89","length":64,"pattern":"^[0-9a-f]{64}$"}
```

The key/value participates in the same duplicate rejection, ordering, and
both-direction parity as the impossibility proof set, but is not counted as an
impossible atom.

For this occurrence, the parent table's 64-zero positive is forbidden and the
exact displayed digest is the positive instance. `REJECT_PATTERN` remains the
parent table's exact reject string ending in `g`; the sibling const does not
replace, waive, or generate a negative. The override does not change any atom,
occurrence, or vector count, but it changes the positive instance and therefore
the vector ID and containing vector-body digest relative to a contradictory
draft.

A direct const with a different pattern, a non-string const, a string of a
different length, a non-lowercase-hex scalar, an inherited/ref/applicator const,
an enum member, or any other sibling does not match. A nonmatching sibling const
that makes the fixed table accept invalid causes construction to block. There
is no regex solver, arbitrary sibling override, or candidate search.

### 6.1 Complete current pattern-occurrence and sibling-context closure

The parent's `39` is only the count of unique decoded pattern literals and the
key count of its closed witness table. It is not an occurrence count or a count
of sibling contexts. Across the exact 12 current subjects there are exactly 521
direct `pattern` occurrences and 41 unique exact pattern-plus-sibling contexts.
The per-subject occurrence counts in roster order are exactly
`[48,48,67,58,41,32,54,56,33,31,29,24]`. Of the 521 physical containing nodes,
520 have exactly the direct member-name set
`{type,minLength,maxLength,pattern}` and one has exactly that set plus `const`.
No absence inference is generalized to a future node.

The four canonical streams below use `CJ(row) || LF` for every row, including
one LF after the final row, with no header or trailer. Objects use decoded
UTF-16/JCS member order and arrays preserve their specified order. Every row and
state object has exactly its displayed fields and no others. An explicit member
state is either exactly `{"state":"ABSENT"}` or exactly
`{"state":"PRESENT","value":<exact parsed value>}`.

`pattern_occurrence_context_rows` has exactly 521 rows with exactly:

```text
{
  subject_ordinal,
  subject_path,
  subject_schema_id,
  occurrence_ordinal,
  containing_node_pointer,
  keyword_pointer,
  literal_pattern,
  direct_minLength,
  direct_maxLength,
  direct_const,
  direct_other,
  direct_sibling_keyword_names,
  direct_sibling_schema
}
```

`subject_ordinal` is zero-based roster order. `occurrence_ordinal` is zero-based
and resets for each subject. Within a subject, traversal is pre-order recursive:
emit a row for a dictionary with direct `pattern` before descending, traverse
object schema-child names in decoded UTF-16 order, and array children by
increasing index, using only the parent's schema-valued edges. The two pointers
are the physical containing-object pointer and that pointer plus `/pattern`,
with the inherited exact RFC-6901 escaping.

`direct_minLength`, `direct_maxLength`, and `direct_const` are explicit member
states. `direct_other` is a closed object with exactly the keys `type`, `enum`,
`format`, `$ref`, `allOf`, `anyOf`, `oneOf`, `not`, `if`, `then`, and `else`,
each mapped to an explicit member state. `direct_sibling_keyword_names` is the
duplicate-free decoded UTF-16-sorted array of every direct member name except
`pattern`. `direct_sibling_schema` is the exact parsed containing object with
only its `pattern` member removed. Consequently each occurrence row binds the
complete physical containing-subschema semantics, not merely selected bounds.
Its exact stream identity is:

```json
{"encoding":"CJ_ROW_LF_V1","preimage_size_bytes":553621,"row_count":521,"sha256":"fd49a3e86c7f44f0ccbd8d7ac373d9c5938401816aebe3caf48d80575fb1162c"}
```

`pattern_literal_rows` deduplicates the occurrence stream by decoded literal,
sorts by decoded UTF-16 order, and has exactly one-field rows
`{"literal_pattern":<decoded string>}`. Its exact identity is:

```json
{"encoding":"CJ_ROW_LF_V1","preimage_size_bytes":1837,"row_count":39,"sha256":"a999487cb7040fe4c250c568016dd4eaf14342699013edce1e8a20fbe85d20cd"}
```

`pattern_sibling_context_rows` projects each occurrence to exactly
`{literal_pattern,direct_sibling_schema}`, deduplicates by exact row `CJ` bytes,
and sorts those bytes lexicographically. Its exact identity is:

```json
{"encoding":"CJ_ROW_LF_V1","preimage_size_bytes":5015,"row_count":41,"sha256":"560a11e14db188e537e5b517a1068590edc375aa213c0bc37d8a31f6fde16229"}
```

For every occurrence, independently select the parent table's positive and
check its direct siblings in this exact order: `type`, `minLength`, `maxLength`,
`const`, `enum`. Append the corresponding exact reason string from
`DIRECT_TYPE`, `DIRECT_MINLENGTH`, `DIRECT_MAXLENGTH`, `DIRECT_CONST`, or
`DIRECT_ENUM` for every failure, preserving that order. If any direct sibling
name is outside `{pattern,type,minLength,maxLength,const,enum}`, append one final
reason `UNMODELED_DIRECT_` followed by its decoded UTF-16-sorted names joined by
literal commas. A row with a nonempty reason array is a conflict; the algorithm
cannot silently ignore an unknown sibling. Type uses inherited Draft-2020-12
instance-type semantics, length uses Unicode scalar-value count, and const/enum
equality uses exact `CJ` value equality; a missing modeled member passes its
check without adding a reason.

`pattern_positive_conflict_rows` preserves occurrence-stream order and has
exactly `{subject_path,subject_schema_id,keyword_pointer,literal_pattern,
positive_witness,reasons,direct_sibling_schema}`. It has exactly the one WIT-01
row from section 6, with `reasons:["DIRECT_CONST"]`, and exact identity:

```json
{"encoding":"CJ_ROW_LF_V1","preimage_size_bytes":534,"row_count":1,"sha256":"d88fec0b4309965311a2405ce1c56639f0ba42bf9ddb5e09f210bf18b43eddb3"}
```

The exact sole row before its final LF is:

```json
{"direct_sibling_schema":{"const":"56962c461653c11e76201987e2bc98c7f9d50e4e0db7128e1b7525c70f878d89","maxLength":64,"minLength":64,"type":"string"},"keyword_pointer":"/properties/registry_body_sha256/pattern","literal_pattern":"^[0-9a-f]{64}$","positive_witness":"0000000000000000000000000000000000000000000000000000000000000000","reasons":["DIRECT_CONST"],"subject_path":"rules/schemas/program_facts_provider_registry.v2.schema.json","subject_schema_id":"https://plamen.local/schemas/program_facts_provider_registry.v2.schema.json"}
```

Generator and evaluator additionally validate the selected positive and parent
table negative against the entire target subschema for all 521 rows; the current
result is zero selected-positive failures and zero table-negative unexpected
validations after WIT-01 is applied. Cross-check independently reconstructs all
four exact streams without importing either implementation. Any second conflict,
unknown sibling, row/identity drift, full-target validation failure, or WIT-01
match count other than one blocks. This proves WIT-01 is the sole current closed
override without claiming that 39 literal keys exhaust sibling semantics.

## 7. Exact impossible-positive case POS-02: local schema-ID minimum length

The local schema-ID pattern is exactly:

```text
^https://plamen\.local/schemas/[A-Za-z0-9._-]+\.schema\.json$
```

Every match has the literal 29-code-point prefix
`https://plamen.local/schemas/`, at least one ASCII basename code point, and the
literal 12-code-point suffix `.schema.json`. Its shortest possible length is
therefore exactly `29 + 1 + 12 = 42` code points. No regex solver or sampling is
used.

`POS-02-LOCAL-SCHEMA-ID-MINLENGTH` matches only when:

- the atom is exactly `ACCEPT_BOUNDARY`;
- the occurrence keyword is exactly `minLength` with parsed integer value `1`;
- the physical containing object has direct `"type":"string"`; and
- its direct `pattern` is byte-for-byte the decoded pattern above.

Its proof value is exactly:

```json
{"declared_min_length":1,"literal_prefix":"https://plamen.local/schemas/","literal_prefix_code_points":29,"literal_suffix":".schema.json","literal_suffix_code_points":12,"minimum_basename_code_points":1,"minimum_match_code_points":42}
```

The one-code-point `ACCEPT_BOUNDARY` atom remains in `coverage_atom_count` but
has no positive vector. Its occurrence has `positive_vector_ids:[]` under the
section-1 all-positive-proof exception. A 42-code-point schema ID is not a
one-code-point boundary witness and cannot be inserted as occurrence-presence
support.

There are exactly 13 current matches: the occurrence

```text
/$defs/gate3_schema_conformance_vectors_v1/properties/subject/properties/schema_id/minLength
```

in each of the exact 12 roster subjects, plus

```text
subject: rules/schemas/program_facts_independent_review.v1.schema.json
occurrence: /$defs/g3_00_admission_manifest_v1/properties/schema_contracts/items/properties/schema_id/minLength
```

A different `minLength`, type, or pattern; a parent/ref/applicator-inherited
pattern; a merely similar URI regex; or inability to build some other
minLength witness does not match. The section-6.1 complete 521-occurrence and
41-context census found no other current pattern-bound/const conflict, and this
predicate cannot be generalized from that exact current-row result.

## 8. Exact impossible-positive case POS-03: direct `items:false`

`POS-03-ITEMS-FALSE-CHILD-VALID` matches only this allowed keyword/atom mapping:

```text
keyword: items
atom: ACCEPT_ITEM
direct schema-valued child: boolean false
```

The JSON Schema boolean `false` accepts no instance, so no array item can be a
child-valid witness. The proof is exact parsed-value identity to boolean `false`;
no resolver, solver, inferred universal rejection, or generator failure is used.
Its proof value is exactly:

```json
{"child":false,"keyword":"items"}
```

The `ACCEPT_ITEM` atom remains in `coverage_atom_count`, has no positive vector,
and its occurrence has `positive_vector_ids:[]` only through the section-1
all-positive-proof exception. `REJECT_ITEM` remains feasible and mandatory.

There are exactly 11 current matches. Ten are closed tuple tails with direct
`prefixItems` plus `items:false`; the eleventh is the zero-item active-selection
branch. Their exact `(schema path, occurrence pointer)` pairs, in roster then
occurrence order, are:

```text
rules/schemas/mechanical_program_facts_receipt.v3.schema.json
  /properties/artifacts/items
rules/schemas/program_facts_active_selection.v1.schema.json
  /properties/head_payload/oneOf/0/properties/logical_outputs/items
  /properties/head_payload/oneOf/1/properties/logical_outputs/items
rules/schemas/program_facts_phase_io_interface_vector.v1.schema.json
  /properties/exclusive_operation_order/items
  /properties/lock_order/items
rules/schemas/program_facts_public_generation.v2.schema.json
  /properties/logical_outputs/items
rules/schemas/program_facts_r19_seed_acceptance.v1.schema.json
  /properties/accepted_scope/items
  /properties/construction_inputs/items
  /properties/rejected_scope/items
  /properties/review_vectors/items
rules/schemas/program_facts_r19_seed_admission.v1.schema.json
  /properties/construction_inputs/items
```

The active-selection occurrence ending
`/oneOf/1/properties/logical_outputs/items` has containing schema exactly
`{"items":false,"maxItems":0,"type":"array"}`. For each of the other ten,
the containing schema has direct nonempty `prefixItems` and direct
`items:false`; the `ACCEPT_ITEM` atom refers only to a post-prefix item and
cannot be satisfied by a valid prefix item. Each containing-schema identity and
exact prefix length is independently recomputed by each process before it emits
the corresponding proof row; the exact 11 proof keys are then compared through
the proof stream rather than inferred from the count 10.

This predicate does not apply to `properties`, `propertyNames`,
`additionalProperties`, `prefixItems`, `$ref`, `contains`, a composite branch,
`not`, `if`, `then`, or `else`; nor does it apply to `{}`, `true`, a resolved
false target, an `items` subschema that is merely unsatisfiable, or a failure to
synthesize an item. Any such missing positive blocks pending a separately
reviewed rule.

## 9. Narrowing case 13 and the `not`/`then`/`else` consequences

Parent case 13 is limited to a delegated rejection through exactly one of these
keyword/atom forms:

- `$ref` / `REJECT_RESOLVED`;
- `properties` / `REJECT_PROPERTY_<escaped-name>`;
- `propertyNames` / `REJECT_NAME`;
- schema-valued `additionalProperties` / `REJECT_EXTRA_VALUE`;
- `prefixItems` / `REJECT_INDEX_<index>`;
- schema-valued `items` / `REJECT_ITEM`; or
- `allOf` / `REJECT_BRANCH_<index>`.

For case 13, `applicable path` is atom-specific and means only the selected
delegated child plus its exact same-document, pure-`$ref` resolution chain. For
non-`$ref` forms, the selected child is the named property schema for
`REJECT_PROPERTY_<escaped-name>`; the direct keyword value for
`propertyNames`, schema-valued `additionalProperties`, or schema-valued `items`;
the indexed child for `prefixItems`; or the indexed branch for `allOf`.
For `$ref` / `REJECT_RESOLVED`, the delegated chain instead starts at the exact
containing schema object named by `target_schema_pointer`; that origin MUST be
an object whose sole member is `$ref`, and the first resolved target is the next
chain node. A chain node may be either the terminal literal parsed `{}` or an
object with exactly the sole member `$ref` resolving within the same subject.
RFC-6901 decode/re-encode, cycle, and stable subject rules are inherited. Any
non-`$ref` keyword on an intermediate delegated chain node, any `$ref` sibling,
external subject, cycle, boolean target, or terminal other than exact `{}`
blocks case 13.

For every non-`$ref` form, unrelated siblings of the containing keyword node are
outside this atom-specific path. They neither block a structurally universal
delegated child nor prove its rejection. For `$ref`, the containing node itself
is the chain origin, so any sibling blocks under the sole-`$ref` rule. In
particular, a target-subschema vector that is invalid only because of `required`,
`additionalProperties`, a different property schema, or another out-of-path
sibling MUST NOT be associated with this atom. Case 13 means the delegated child
can never reject; it is not permission to relabel a sibling-invalid vector as
delegated-child evidence.

The phrase `composite branch` in parent case 13 means only the displayed `allOf`
`REJECT_BRANCH_<index>` form. Parent `anyOf` and `oneOf` have no branch-specific
delegated reject atom: their occurrence-wide `REJECT_ZERO_MATCH` and
`REJECT_MULTIPLE_MATCH` atoms cannot match case 13. The phrase never includes
`not`, `if`, `then`, `else`, or `contains`.

The current denominator contains exactly 12 retained case-13 atoms. In every
subject in the parent section-2 roster, the occurrence pointer is exactly

```text
/$defs/gate3_schema_conformance_vectors_v1/properties/vectors/items/properties
```

the atom is exactly `REJECT_PROPERTY_instance`, and its selected child pointer
is exactly

```text
/$defs/gate3_schema_conformance_vectors_v1/properties/vectors/items/properties/instance
```

whose parsed value is `{}`. Each atom remains in `coverage_atom_count`, has an
`IMPOSSIBLE` disposition under exact predicate
`NEG-13-DELEGATED-EMPTY-SCHEMA`, and has no associated negative vector. Other
negative atoms on the same `properties` occurrence remain independent and can
keep the occurrence row's aggregate `negative_vector_ids` nonempty.

Consequently:

- `not:{}` has no possible `ACCEPT_CHILD_INVALID`, because `{}` accepts every
  bounded JSON instance. This is an impossible positive for which the closed
  positive roster has no waiver, so construction blocks. Its
  `REJECT_CHILD_VALID` remains feasible and cannot be waived.
- a selected `then:{}` has no possible `REJECT_SELECTED_THEN`; and a selected
  `else:{}` has no possible `REJECT_SELECTED_ELSE`. Neither negative is on the
  closed whitelist, so either construction blocks. Their selected positives do
  not excuse the missing negative.
- direct `if` remains parent negative case 11 only. Both
  `ACCEPT_CONDITION_TRUE` and `ACCEPT_CONDITION_FALSE` remain required.

No literal empty child outside the exact case-13 list gains a negative waiver,
and no impossible positive outside the exact POS-01/POS-02/POS-03 roster gains
a positive waiver.

## 10. Denominator, identity, count, and digest effects

This amendment changes no subject schema bytes. The following parent values are
unchanged:

- exactly 12 G3-00 subject schema paths and exactly 24 canonical child paths;
- exactly 32 coverage-keyword ordinals;
- exactly 39 unique pattern literals, while section 6.1 separately binds all
  521 occurrences and 41 exact sibling contexts;
- carrier template body SHA-256
  `a022374caccb7dbcdf6bb8fb596e0f81d8cf10c9bca1c5a5e626c3d09bdffc4f`;
- every subject `$id`, provider-registry parsed value, schema identity, and
  keyword occurrence count; and
- every coverage atom, including all atoms discharged by this amendment.

A complete row-level census has independently converged across the separately
authored planner and stdlib cross-check over the current constructed 12 subjects.
The generator and semantic evaluator must still reproduce it before admission:

```text
total keyword occurrences                                 7,517
total coverage atoms                                      21,578
currently present keyword kinds                           19 of 32 allowed
pattern occurrences / unique literals / contexts          521 / 39 / 41
A: maxItems == 10000000 ACCEPT_BOUNDARY conflicts            221
B: local-schema-ID minLength ACCEPT_BOUNDARY conflicts         13
C: direct provider-digest pattern/const witness conflicts       1
D: direct items:false ACCEPT_ITEM conflicts                    11
tagged closed-object unions / branches                       8 / 21
E: case-16 tagged-union branch atoms                            6
F: exact case-14/case-15 enum occurrences                       0
retained parent case-13 REJECT_PROPERTY_instance atoms         12
not:{} / selected then:{} / selected else:{} occurrences        0
```

The exact per-subject counts in the parent section-2 roster order are:

| Subject | Occurrences | Atoms |
|---|---:|---:|
| `mechanical_program_facts.v3.schema.json` | 652 | 1,879 |
| `mechanical_program_facts_debt.v3.schema.json` | 626 | 1,812 |
| `mechanical_program_facts_receipt.v3.schema.json` | 988 | 2,950 |
| `program_facts_active_selection.v1.schema.json` | 769 | 2,283 |
| `program_facts_independent_review.v1.schema.json` | 993 | 2,881 |
| `program_facts_phase_io_interface_vector.v1.schema.json` | 528 | 1,445 |
| `program_facts_public_generation.v2.schema.json` | 678 | 1,959 |
| `program_facts_publication_arm.v2.schema.json` | 693 | 2,018 |
| `program_facts_r19_seed_acceptance.v1.schema.json` | 521 | 1,436 |
| `program_facts_r19_seed_admission.v1.schema.json` | 422 | 1,160 |
| `program_facts_source_identity_census.v1.schema.json` | 366 | 992 |
| `program_facts_provider_registry.v2.schema.json` | 281 | 763 |

The top totals MUST equal the arithmetic sums of these 12 independently
enumerated rows. A hard-coded top total or a count-only comparison is invalid.

The canonical atom-set preimage is constructed by iterating exact roster order,
then parent section-4.3 occurrence order, then section-4.4 atom order. For every
atom, emit exactly `CJ(row) || LF`, where `row` has exactly:

```json
{"atom_id":"<atom ID>","expected":"VALID|INVALID","keyword":"<keyword>","schema_path":"<roster path>","schema_pointer":"<keyword-member pointer>"}
```

Concatenate the 21,578 lines with no header or trailer. The preimage is exactly
5,102,113 bytes and its SHA-256 is exactly
`286aa2a4477aa46f632c590020d3a49e1e147cef0194471d9893f8898a903915`.
These values were mechanically rederived from two independently authored row
enumerators and their complete row lists were compared in order and in both
set-difference directions. Amendment fixtures MUST repeat that derivation and
must fail on a row substitution, duplicate, omission, reorder, path change,
atom-ID change, expected-direction change, same-count replacement, byte-count-
only match, or digest-only sentinel substitution. Impossibility classification
never removes a line from this preimage.

All displayed A-F counts are requirements to reproduce, not acceptance
evidence. Before a vector identity is pinned, the separately authored generator,
evaluator, and cross-check must each independently obtain the exact occurrence,
atom, affected-pointer, and proof sets. The generator and evaluator must also
independently reproduce all 521 pattern-occurrence rows, 39 literal rows, 41
exact sibling-context rows, and the one conflict row, validate every selected
witness against the full target, and prove there is no current conflict beyond
A-F. Disagreement blocks. Planner or cross-check agreement
without the other two independent implementations cannot satisfy a review
check. Count and digest agreement without exact row equality is insufficient.

No accepted G3-00 vector file or vector body digest preceded this clarification.
The first authoritative `vector_count` and `body_sha256` values are computed
under these rules. For the current census, 221 maxItems boundary atoms, 13 local
schema-ID minLength boundary atoms, and 11 direct-`items:false` atoms remain
counted but have no positive vector; six tagged-union atoms and 12 retained
case-13 atoms remain counted but have no negative vector; cases 14-15 cause no
current vector omission. The one pattern conflict retains its positive vector
but uses the exact sibling const, changing that vector ID/body projection from
any table-accept draft. It is forbidden to
describe these proof discharges as removed atoms or a reduced coverage
denominator. Any draft generator, evaluator, cross-check, vector, review, or
handoff based on the contradictory rules is non-authoritative and must be
rebuilt or re-reviewed. Subject schema and carrier-template digests are not
invalidated solely by this amendment.

## 11. Canonical three-way parity evidence and durable capture

Count/digest summaries are not sufficient for generator/discriminator
separation. The generator, semantic evaluator, and stdlib cross-check MUST each
independently emit the same closed `parity` parsed value. The exact parity object
has these members and no others:

```text
{
  schema_version:"plamen.program_facts_gate3_schema_contract_parity.v1",
  contracts:{
    schema_closure_amendment:<file_identity>,
    schema_closure_review:<file_identity>,
    vector_clarification_amendment:<file_identity>,
    vector_clarification_review:<file_identity>
  },
  subject_rows:[...],
  occurrence_rows:[...],
  atom_rows:[...],
  atom_disposition_rows:[...],
  proof_rows:[...],
  vector_identity_rows:[...],
  witness_decision_rows:[...],
  pattern_occurrence_context_rows:[...],
  pattern_literal_rows:[...],
  pattern_sibling_context_rows:[...],
  pattern_positive_conflict_rows:[...],
  totals:{...},
  subject_set_identity:{...},
  occurrence_set_identity:{...},
  atom_set_identity:{...},
  atom_disposition_set_identity:{...},
  proof_set_identity:{...},
  vector_set_identity:{...},
  witness_set_identity:{...},
  pattern_occurrence_context_set_identity:{...},
  pattern_literal_set_identity:{...},
  pattern_sibling_context_set_identity:{...},
  pattern_positive_conflict_set_identity:{...},
  parity_body_sha256:<hex64>
}
```

`contracts` contains the exact two parent identities and the later stable
identities of this amendment and its independent receipt. `subject_rows` has
exactly 12 rows in roster order, each with exactly
`{subject_ordinal,schema,schema_id,vectors,vector_body_sha256,
keyword_occurrence_count,coverage_atom_count,vector_count,
impossible_positive_count,impossible_negative_count,witness_decision_count,
pattern_occurrence_count}`.
`schema` and `vectors` are file identities; `subject_ordinal` is 0 through 11.

`occurrence_rows` is exact roster/section-4.3 order and each row has exactly
`{subject_ordinal,schema_path,schema_pointer,target_schema_pointer,keyword}`.
`atom_rows` is exact section-10 preimage order and every row has exactly:

```json
{"schema_path":"<path>","schema_pointer":"<pointer>","keyword":"<keyword>","atom_id":"<atom ID>","expected":"VALID|INVALID"}
```

For parameterized atoms, `type` members preserve the parent's fixed JSON-type
order; enum, required, dependent-list, prefix, and composite indices preserve
source-array order; object/discriminator names use UTF-16/JCS order. Fixed atoms
use section-4.4 display order. Tagged atoms follow the ordinary `oneOf` atoms,
then branch index, then exactly:

```text
TAGGED_BRANCH_<i>_ACCEPT
TAGGED_BRANCH_<i>_REJECT_ZERO_BRANCH
TAGGED_BRANCH_<i>_REJECT_UNKNOWN_TAG
TAGGED_BRANCH_<i>_REJECT_MISSING_TAG_BRANCH_PAYLOAD
TAGGED_BRANCH_<i>_REJECT_VALID_BRANCH_UNKNOWN_FIELD
TAGGED_BRANCH_<i>_REJECT_CROSS_BRANCH_FIELD
```

`atom_disposition_rows` has exactly one row per atom ordinal, where
`atom_ordinal` is the zero-based index of the identical row in `atom_rows` and
runs contiguously from 0 through 21,577. A witnessed row
has exactly `{atom_ordinal,disposition:"VECTOR",vector_ids}` with a nonempty,
UTF-8-sorted, duplicate-free ID array. An impossible row has exactly
`{atom_ordinal,disposition:"IMPOSSIBLE",predicate_id,proof,vector_ids}` with
`vector_ids:[]`. The exact predicate IDs are `NEG-01-MAXITEMS-10000000`,
`NEG-02-MINITEMS-0`, `NEG-03-MAXPROPERTIES-4096`,
`NEG-04-MINPROPERTIES-0`, `NEG-05-MAXLENGTH-16384`,
`NEG-06-MINLENGTH-0`, `NEG-07-MAXIMUM-SAFE-MAX`,
`NEG-08-MINIMUM-SAFE-MIN`, `NEG-09-MULTIPLEOF-1-INTEGER`,
`NEG-10-TYPE-ALL-SIX`, `NEG-11-IF-DIRECT`,
`NEG-12-ONEOF-MUTUALLY-EXCLUSIVE-CONSTS`,
`NEG-13-DELEGATED-EMPTY-SCHEMA`,
`NEG-14-ENUM-NULL-CLOSED-DOMAIN`,
`NEG-15-ENUM-BOOLEAN-CLOSED-DOMAIN`,
`NEG-16-TAGGED-UNION-NO-EXCLUSIVE-FIELD`, and POS-01/POS-02/POS-03 exactly as
named above. The proof is the exact section-specific parsed value. The complete
closed proof-value schema for parent cases 1-13 is:

| Predicate | Exact proof value |
|---|---|
| `NEG-01-MAXITEMS-10000000` | `{"keyword":"maxItems","value":10000000}` |
| `NEG-02-MINITEMS-0` | `{"keyword":"minItems","value":0}` |
| `NEG-03-MAXPROPERTIES-4096` | `{"keyword":"maxProperties","value":4096}` |
| `NEG-04-MINPROPERTIES-0` | `{"keyword":"minProperties","value":0}` |
| `NEG-05-MAXLENGTH-16384` | `{"global_string_ceiling_bytes":16384,"keyword":"maxLength","value":16384}` |
| `NEG-06-MINLENGTH-0` | `{"keyword":"minLength","value":0}` |
| `NEG-07-MAXIMUM-SAFE-MAX` | `{"keyword":"maximum","value":9007199254740991}` |
| `NEG-08-MINIMUM-SAFE-MIN` | `{"keyword":"minimum","value":-9007199254740991}` |
| `NEG-09-MULTIPLEOF-1-INTEGER` | `{"integer_only_domain":true,"keyword":"multipleOf","value":1}` |
| `NEG-10-TYPE-ALL-SIX` | `{"keyword":"type","permitted_types":["null","boolean","integer","string","array","object"]}` |
| `NEG-11-IF-DIRECT` | `{"keyword":"if"}` |
| `NEG-12-ONEOF-MUTUALLY-EXCLUSIVE-CONSTS` | `{"branch_const_cj":["<branch-0 const CJ>","<branch-1 const CJ>","..."],"discriminator":"<selected property name>"}` |
| `NEG-13-DELEGATED-EMPTY-SCHEMA` | `{"delegated_child_pointer":"<selected child pointer>","resolution_chain":["<child pointer>","<each resolved target pointer>"],"terminal":{}}` |

Angle-bracket labels and the ellipsis in the last two display rows are
metavariables, never serialized strings or members. The instantiated parsed
objects contain only the exact source-derived strings required below.

The case-10 array is the parent's fixed JSON-type order. For case 12,
`branch_const_cj` has exactly one string per source branch in branch-array order;
each string is the literal `CJ` byte sequence of that branch's direct required
discriminator `const`, all are pairwise unequal, and the selected discriminator
is the first valid candidate in UTF-16/JCS property-name order. For case 13,
`resolution_chain` starts with the selected delegated-child pointer and appends
the same-document target pointer for each pure `$ref` hop, including the terminal
pointer; a direct `{}` child therefore produces the singleton array containing
only `delegated_child_pointer`. For `$ref` / `REJECT_RESOLVED`,
`delegated_child_pointer` is instead the occurrence's `target_schema_pointer`
and `resolution_chain` starts with that sole-`$ref` origin before appending its
first target and any later pure-ref targets. No proof object has an unlisted
member.

Cases 14-16 and POS-01-POS-03 use their literal proof values in this amendment.
`proof_rows` is the exact projection of impossible disposition rows into rows
with exactly `{subject_schema_id,schema_pointer,atom_id,direction,predicate_id,
proof}`. `direction` is exactly `"POSITIVE"` for POS-01/POS-02/POS-03 and
`"NEGATIVE"` for NEG-01 through NEG-16. Rows sort by the section-2 proof-key
order. Every proof row joins to exactly one `IMPOSSIBLE` disposition through its
subject/pointer/atom ordinal, and every impossible disposition joins back to
exactly one byte-identical parsed proof row; orphan, duplicate, or conflicting
rows block.

`vector_identity_rows` sorts by `(subject_ordinal,UTF8(vector_id))`. Each row has
exactly `{subject_ordinal,vector_id,target_schema_pointer,expected,covers,
instance_cj_size_bytes,instance_cj_sha256}`. `covers` is the exact singleton
pointer array. These rows, the atom-to-vector joins, each subject's exact vector
file identity/body digest, and normal vector-ID recomputation jointly freeze the
instance semantics without duplicating every instance in this envelope.
`witness_decision_rows` contains the exact WIT-01 key/value/vector join from
section 6 and no other current row. Its one row has exactly
`{subject_schema_id,schema_pointer,atom_id,predicate_id,proof,vector_id}` with
the section-6 subject ID, pointer, `atom_id:"ACCEPT_PATTERN"`,
`predicate_id:"WIT-01-DIRECT-HEX64-CONST"`, literal section-6 proof value, and
the independently recomputed ID of the vector containing that exact const
instance. Later normal witness choices are bound by vector rows and joins, not
prose.

The four `pattern_*_rows` arrays are byte-for-byte the four section-6.1 streams
under their exact row schemas and orders. Their four corresponding
`pattern_*_set_identity` objects are the literal identities displayed there.
`pattern_occurrence_count` in each subject row is respectively
`[48,48,67,58,41,32,54,56,33,31,29,24]` and equals that subject's exact row
projection. The sole conflict row joins the sole WIT-01 witness-decision row by
subject ID and keyword pointer; every occurrence row joins exactly one literal
row and one sibling-context row. The deduplicated occurrence projections must
equal the literal and sibling-context row sets in both directions, and every
deduplicated row must have at least one occurrence preimage. An ambiguous,
orphan, extra, missing, or duplicate-key row blocks. The WIT/conflict join
remains one-to-one.

`totals` has exactly `{subject_count,keyword_occurrence_count,
coverage_atom_count,vector_count,impossible_positive_count,
impossible_negative_count,witness_decision_count,pattern_occurrence_count,
pattern_literal_count,pattern_sibling_context_count,
pattern_positive_conflict_count}`. For each subject and for the
top totals, `impossible_positive_count` and `impossible_negative_count` are
exactly the counts of joined `IMPOSSIBLE` disposition/proof rows whose direction
is respectively `POSITIVE` and `NEGATIVE`; they are atom counts, not predicate,
occurrence, or proof-family counts. `vector_count` is the exact count of joined
`vector_identity_rows`, and `witness_decision_count` is the exact count of joined
`witness_decision_rows`. `subject_count` is exactly 12; each additive top metric
represented in subject rows -- keyword occurrences, atoms, vectors, impossible
positives, impossible negatives, witness decisions, and pattern occurrences --
is the arithmetic sum of its 12 subject values. The first two additive totals
are exactly 7,517 and 21,578. The global deduplicated pattern literal, sibling-
context, and conflict totals are not per-subject sums; the four pattern totals
are exactly 521, 39, 41, and 1 and equal their corresponding complete stream
lengths and identities.
Every row stream has an independent preimage and identity in addition to the
whole-parity digest. Except for the already pinned atom identity below, a stream
identity has exactly `{encoding,row_count,preimage_size_bytes,sha256}`, where
`encoding` is exactly `"CJ_ROW_LF_V1"`. Its preimage is the concatenation of
`CJ(row) || LF` for every row in the normative array order, with no header or
trailer; `row_count` equals the array length, `preimage_size_bytes` is the exact
byte length, and `sha256` is lowercase SHA-256 of those bytes. The mappings are
exactly: `subject_set_identity` to `subject_rows` in roster order;
`occurrence_set_identity` to `occurrence_rows` in roster/section-4.3 order;
`atom_disposition_set_identity` to `atom_disposition_rows` in atom-ordinal
order; `proof_set_identity` to `proof_rows` in proof-key order;
`vector_set_identity` to `vector_identity_rows` in their declared order; and
`witness_set_identity` to `witness_decision_rows` in witness-decision-key order;
`pattern_occurrence_context_set_identity` to
`pattern_occurrence_context_rows`; `pattern_literal_set_identity` to
`pattern_literal_rows`; `pattern_sibling_context_set_identity` to
`pattern_sibling_context_rows`; and `pattern_positive_conflict_set_identity` to
`pattern_positive_conflict_rows`, each in its exact section-6.1 order. The empty
stream, if one existed, would have a zero row count and the SHA-256 of empty
bytes; no current required stream is empty.

`atom_set_identity` has exactly `{encoding,row_count,occurrence_count,
coverage_atom_count,coverage_atom_counts_by_subject,preimage_size_bytes,sha256}`
with `encoding` exactly
`"SCHEMA_ROSTER_ORDER_THEN_OCCURRENCE_ORDER_THEN_SECTION_4_4_ATOM_ORDER;EACH_EXACT_ROW_SCHEMA_PATH_SCHEMA_POINTER_KEYWORD_ATOM_ID_EXPECTED_AS_UTF16_JCS_PLUS_LF;CONCATENATE_WITH_NO_HEADER_OR_TRAILER"`,
and equals section 10, including the 12-count vector, `row_count:21578`,
5,102,113 bytes, and
`286aa2a4477aa46f632c590020d3a49e1e147cef0194471d9893f8898a903915`.
Its preimage is exactly `atom_rows` under the same no-header/no-trailer rule.
Each top-level row stream rejects duplicate logical keys before serialization;
`vector_ids` and every array explicitly declared duplicate-free retain that
rule. Sequence-valued proof arrays preserve their contract order and may repeat
values unless their own predicate forbids repetition: in particular, case-16
`property_sets` may contain identical branch arrays. A row-array mutation,
reorder, duplicate-key row, omission, or substitution MUST change or invalidate
its own stream identity even if a whole-parity digest constant is forged.

`parity_body_sha256 = SHA-256(CJ(parity without only
parity_body_sha256))`. The three parsed parity objects and their `CJ` bytes MUST
be byte-identical. Comparison is in order and in both set-difference directions
for subjects, occurrences, atoms, dispositions, proofs, vectors, witnesses, and
all four pattern streams; each of the 11 stream identities must also be
byte-identical across all three roles and must independently recompute from its
local rows. No majority vote,
count-only equality, digest-only equality, whole-parity-digest-only equality,
or shared imported result is allowed.

Each process emits to stdout one outer object with exactly
`{schema_version,evidence_id,role,principal,launcher,output_path,source,
execution_policy,parity,authority_ceiling,evidence_body_sha256}`.
`schema_version` is
`plamen.program_facts_gate3_schema_contract_parity_evidence.v1`. `principal` is
a closed object with exactly `{principal_id,organization,role}`. The complete
role/principal/path/source bindings are exactly:

| Role | Exact principal | Source path | Launcher-captured stdout path |
|---|---|---|---|
| `GENERATOR` | `{"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-contract-generator","role":"GENERATOR"}` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/generate_schema_contracts_v1.py` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence/generator.parity_evidence.v1.json` |
| `EVALUATOR` | `{"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-semantic-evaluator","role":"EVALUATOR"}` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/evaluate_schema_contracts_independent_v1.py` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence/evaluator.parity_evidence.v1.json` |
| `CROSSCHECK` | `{"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-stdlib-crosscheck","role":"CROSSCHECK"}` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v1.py` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence/crosscheck.parity_evidence.v1.json` |

`launcher` is a closed object with exactly `{principal,source}`. Its exact
principal is
`{"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-parity-launcher","role":"LAUNCHER"}`
and `source` is the stable file identity whose path is exactly
`review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/capture_schema_contract_parity_evidence_v1.py`.
The launcher principal is distinct from all three process principals and every
other independent role at this boundary.

`source` is that source's stable file identity. `output_path` is the literal
path in the table. The outer `role` and `principal.role` equal the mapped role;
the three exact `principal_id` values, principals, and source identities are
pairwise distinct. The launcher stable-reads itself and the selected process
source three times, and binds both identities to their exact mapped principals
before invocation; emitted principal text is not self-authenticating. The
independent downstream reviewer verifies source authorship/provenance and
rejects a claimed binding authored, substituted, or reviewed by any process
peer or by the launcher author. `execution_policy` is exactly
`{"arguments":[],"cwd":"REPOSITORY_ROOT","environment":"EMPTY",
"handles":"CLOSED","network":"DENIED_BY_EXTERNAL_LAUNCHER","shell":false,
"stderr_max_bytes":1048576,"stdout_max_bytes":33554432}`. `authority_ceiling`
is the section-13 exact
all-false object. Let `identity_body` omit only `evidence_id` and
`evidence_body_sha256`; then

```text
evidence_id = "pfg3pe-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_GATE3_SCHEMA_CONTRACT_PARITY_EVIDENCE_V1",
  evidence:identity_body
}))[0:32]
evidence_body_sha256 = SHA-256(CJ(full evidence without only evidence_body_sha256))
stdout = CF(full evidence)
```

The external launcher invokes the accepted absolute CPython 3.12 interpreter
with the exact policy, enforces network denial outside the child, caps stdout
including the final LF at 33,554,432 bytes, rejects any extra stdout, BOM, CR,
noncanonical bytes, secret-bearing environment, nonzero exit, or role/principal/
source/path mismatch, and atomically captures stdout to only the mapped path. The
process does not open or write its evidence path; evaluator and cross-check write
no evidence file themselves. The launcher caps stderr at exactly 1,048,576 bytes
while streaming, accepts only exactly zero stderr bytes, and does not persist or
echo rejected stderr; stderr is never evidence and cannot repair stdout. After
capture the launcher performs
three byte-identical stable reads; later reviews consume the external file
identity. A partial/temp file has no authority. A process source author cannot
also be the launcher author, clarification reviewer, schema builder, production
implementer, any of the 12 per-schema reviewers, or aggregate reviewer for this
boundary; the launcher author has the same exclusions. In every inherited
per-schema review, `vector_author_separate:true` means that reviewer is distinct
from the exact generator principal, and `oracle_author_separate:true` means that
reviewer is distinct from each exact evaluator, cross-check, and launcher
principal. The 12 per-schema reviewers may not substitute one of those four
producer principals under another role label.

The parent's 16,777,216-byte control-document ceiling remains unchanged for
subject schemas, vector carriers, receipts, and the POS-01 proof. Parity evidence
is a distinct, launcher-captured process artifact with the separate exact
33,554,432-byte stdout ceiling above. A mechanical sizing audit of the canonical
pre-pattern-stream shape obtained a complete lower projection of 15,153,152 bytes,
leaving only 1,624,064 bytes under 16 MiB, while the conservative no-dedup
projection was 17,543,964 bytes and therefore exceeded that control ceiling.
The four now-mandatory pattern streams add exactly 561,007 canonical row-preimage
bytes plus their array/envelope bytes, strengthening that separation decision.
Those projections justify separation but do not assert the final output size.

Before admission, each implementation must construct its complete
`CF(full evidence)` in bounded local memory, measure the bytes including the
final LF, and obtain an independently replayed exact size at or below 33,554,432
bytes. Exceeding 32 MiB blocks; truncating rows, replacing a row stream by only
its digest, splitting stdout, or raising the parity-evidence ceiling is forbidden
without a separately reviewed successor amendment.

Every per-schema review includes all three captured evidence identities plus
this amendment and its receipt in `VECTOR-CARRIER`,
`KEYWORD-OCCURRENCE-COVERAGE`, `POSITIVE-REPLAY`, `NEGATIVE-REPLAY`, and
`IDENTITY-STABLE-READ`. Aggregate checks G3A-07 and G3A-08 consume the same five
identities and independently compare the common parity bytes. One missing,
oversized, unstable, mismatched, self-written, or noncanonical evidence artifact
blocks; no process can certify itself or either peer.

## 12. Required red-to-green and no-fire fixtures

The following is the closed minimum fixture matrix; every row is mandatory and
no row may be replaced by a broader-looking surrogate. Additional no-fire tests
may be added. Each required mutation runs against
generator, evaluator, and cross-check independently; a shared helper result is
not evidence.

| ID | Fixture | Required result |
|---|---|---|
| `G3VC-01` | `{"type":"null","enum":[null]}` and only `REJECT_UNKNOWN_SAME_TYPE` absent | case 14 fires; positive member remains required |
| `G3VC-02` | Boolean enum in each source order `[false,true]` and `[true,false]` | case 15 fires with identical `JSET` proof |
| `G3VC-03` | Change scalar `type` to `["boolean"]`, remove one Boolean member, add a member, or remove direct `type` | cases 14-15 do not fire; missing negative blocks |
| `G3VC-04` | Exhaust an integer interval, singleton string domain, `const`, `allOf`, or ref-inherited type | no finite-enum inference; missing negative blocks |
| `G3VC-05` | Exact `maxItems:10000000` boundary positive | POS-01 fires from exact arithmetic without constructing the array; positive ID list is empty |
| `G3VC-06` | Replace 10,000,000 by 9,999,999 or alter the ceiling/lower-bound arithmetic | POS-01 does not fire; absent boundary vector blocks |
| `G3VC-07` | Exact 10,000,000 one-step-outside negative | only parent negative case 1 fires; POS-01 is not used |
| `G3VC-08` | Put `[]`, `[0]`, or a sibling vector in the positive ID list as boundary support | reject; no occurrence-presence surrogate is allowed |
| `G3VC-09` | Each of the six current receipt branches with identical property sets | case 16 fires only for that branch's exclusive-field atom |
| `G3VC-10` | Add one property solely to another closed branch | case 16 does not fire for a selected branch lacking that property; its negative vector is required |
| `G3VC-11` | Make a tagged branch open, remove required discriminator, reuse a discriminator const, add `$ref` siblings, or reference another subject | case 16 does not fire; missing atom blocks |
| `G3VC-12` | Omit any of the other five tagged obligations or ordinary zero/multiple-match atoms | case 16 cannot discharge it; coverage blocks |
| `G3VC-13` | `not:{}` | construction blocks for missing `ACCEPT_CHILD_INVALID`; reject-child-valid is still replayed |
| `G3VC-14` | selected `then:{}` and selected `else:{}` | construction blocks for missing selected-branch negative |
| `G3VC-15` | Case-13 pure local-ref chain or `$ref` origin gains a non-`$ref` sibling, or an `anyOf`/`oneOf` occurrence-wide reject is relabeled as a delegated branch atom | case 13 does not fire |
| `G3VC-16` | Empty positive or negative ID direction for any nonmatching occurrence | coverage and the corresponding replay check fail |
| `G3VC-17` | Remove an impossible atom from `coverage_atom_count` while leaving vectors unchanged | reject denominator/count mismatch |
| `G3VC-18` | Generator/evaluator/cross-check proof key or value differs by one member, order, pointer, atom, or arithmetic value | parity fails closed |
| `G3VC-19` | Exact provider-v2 digest pattern occurrence with its direct 64-lowercase-hex const | the 521/39/41/1 streams and their exact identities reproduce; WIT-01 selects the exact const, vector validates, and its ID derives from that instance |
| `G3VC-20` | Remove the direct const from that node | occurrence/context/conflict identities change, conflict count becomes zero, WIT-01 does not fire, and the exact parent table accept is used |
| `G3VC-21` | Change the const length/character set, change the pattern, move const behind `$ref`/`allOf`, or add an unknown direct sibling | exact occurrence/context/conflict parity changes; WIT-01 does not fire and an invalid or unmodeled fixed-table witness blocks |
| `G3VC-22` | Use the const for `REJECT_PATTERN`, use an enum member, search another sibling, omit a physical pattern occurrence, or collapse 521 occurrences into 39 literals | reject; table reject, complete occurrence/context mapping, and closed precedence remain mandatory |
| `G3VC-23` | All 13 exact local-schema-ID `minLength:1` occurrences | POS-02 fires with the exact 29+1+12 proof; positive ID list is empty |
| `G3VC-24` | Change `minLength` to 42 | POS-02 does not fire; exact 42-code-point local schema-ID boundary witness is required |
| `G3VC-25` | Change/remove the direct pattern or type, or inherit the pattern through a ref/applicator | POS-02 does not fire; no inferred pattern-bound proof is allowed |
| `G3VC-26` | Put a valid 42-code-point schema ID into a `minLength:1` positive ID list | reject; it is not the one-code-point boundary atom |
| `G3VC-27` | All 11 exact direct-`items:false` occurrences | POS-03 fires per pointer only for `ACCEPT_ITEM`; every positive ID list is empty and every `REJECT_ITEM` remains required |
| `G3VC-28` | Replace false by `{}`/true, move false behind a ref, or make a different child merely unsatisfiable | POS-03 does not fire; missing child-valid positive blocks |
| `G3VC-29` | Apply POS-03 to another keyword/atom or omit `REJECT_ITEM` | reject atom/predicate mismatch |
| `G3VC-30` | Change any A-F pointer/count, 7,517/21,578 totals, per-subject sum, 8/21/126 tagged census, 19/32 keyword census, pattern 521/39/41/1 counts or four pinned pattern-stream identities, 5,102,113 bytes, or `286aa2...3915` | exact row parity and admission fail closed |
| `G3VC-31` | Use a valid `prefixItems` element as the `items:false` ACCEPT_ITEM witness in any of the ten tuple rows | reject; `items` applies only to the post-prefix tail |
| `G3VC-32` | Omit one of the 11 POS-03 pointers or treat only the maxItems-zero row as impossible | exact pointer/count parity fails |
| `G3VC-33` | All 12 direct carrier `instance:{}` children | case 13 fires only for `REJECT_PROPERTY_instance`; atom retained with no negative vector |
| `G3VC-34` | Replace one direct `{}` child by a pure same-document `$ref` chain ending in `{}` | case 13 fires with the exact chain proof |
| `G3VC-35` | Make the chain external, cyclic, nonempty-terminal, or add a non-`$ref` sibling to a chain node | case 13 does not fire; missing negative blocks |
| `G3VC-36` | Supply a target-invalid vector rejected only by an unrelated containing-node sibling | it cannot be associated with the case-13 atom |
| `G3VC-37` | Replace `instance:{}` by a directly rejecting child | case 13 does not fire and an actual child-rejection vector is required |
| `G3VC-38` | Substitute/reorder/duplicate one canonical atom row while preserving count, or forge only byte count/digest constants | exact 21,578-line comparison and preimage identity fail |
| `G3VC-39` | Alter/reorder/duplicate/omit one subject, occurrence, disposition, proof, vector, witness, or pattern-stream row; preserve its old stream identity, forge a new stream identity, or preserve only the whole parity digest | the affected CJ+LF stream identity and three-way exact row/identity parity fail |
| `G3VC-40` | Swap an outer role, exact process/launcher principal, principal role/ID, process/launcher source identity, or mapped output path; reuse one producer principal/source across roles or as a per-schema reviewer | launcher, inherited independence checks, provenance review, and evidence identity reject it |
| `G3VC-41` | Add stdout text, omit LF, add BOM/CR, pretty-print, exceed 32 MiB, confuse the separate 16 MiB control ceiling with parity transport, or corrupt either body digest | capture is non-evidence and no stable artifact is admitted |
| `G3VC-42` | Let a process self-write evidence, expose a nonempty environment, allow network, return nonzero, emit any stderr or exceed its 1 MiB cap, or leave partial/unstable bytes | launcher capture and downstream review block |
| `G3VC-43` | Preserve vector ID while changing instance digest/size, or preserve instance while changing atom-to-vector association | vector recomputation/join parity fails |
| `G3VC-44` | Change a per-subject count while keeping a hard-coded top count, or vice versa | arithmetic projection and exact roster rows fail |
| `G3VC-45` | Omit any one of the exact five identities (three captured process artifacts, amendment, or receipt) from a per-schema or aggregate review | review cannot pass |

The fixture author records red execution before modifying the corresponding
source. Green execution alone is insufficient. Tests must demonstrate both the
fire case and every displayed no-fire case. A test that substitutes this
document's expected value for independent construction is self-certification.

## 13. Clarification identity and independent-review receipt

The amendment identity is the stable file identity of exactly:

```text
architecture/program-facts-g3-00-schema-vector-clarification-amendment.md
```

It is not self-hashed inside its own bytes. An independent reviewer performs
three byte-identical reads, requires strict UTF-8, LF line endings, no BOM, and
no CR byte, then places the resulting exact `{path,size_bytes,sha256}` in the
receipt `subject`. A byte change creates a different subject and invalidates the
receipt; a disposition string cannot rescue it.

The only receipt path is:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_SCHEMA_VECTOR_CLARIFICATION_AMENDMENT_INDEPENDENT_REVIEW.v1.json
```

The receipt validates against this literal, self-contained Draft-2020-12 schema
as a parsed JSON value. The schema is used in memory and is never written as a
separate file:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_schema_vector_clarification_amendment_review.v1.schema.json",
  "$vocabulary":{
    "https://json-schema.org/draft/2020-12/vocab/core":true,
    "https://json-schema.org/draft/2020-12/vocab/applicator":true,
    "https://json-schema.org/draft/2020-12/vocab/validation":true
  },
  "$defs":{
    "file_identity":{"additionalProperties":false,"properties":{"path":{"maxLength":4096,"minLength":1,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$","type":"string"},"sha256":{"maxLength":64,"minLength":64,"pattern":"^[0-9a-f]{64}$","type":"string"},"size_bytes":{"maximum":9007199254740991,"minimum":0,"type":"integer"}},"required":["path","size_bytes","sha256"],"type":"object"},
    "finding":{"additionalProperties":false,"properties":{"description":{"maxLength":8192,"minLength":1,"type":"string"},"evidence":{"items":{"$ref":"#/$defs/file_identity"},"maxItems":10000000,"minItems":1,"type":"array","uniqueItems":true},"finding_id":{"maxLength":512,"minLength":1,"pattern":"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$","type":"string"},"severity":{"enum":["BLOCKING","NONBLOCKING"],"type":"string"},"status":{"enum":["OPEN","CLOSED"],"type":"string"}},"required":["finding_id","severity","status","description","evidence"],"type":"object"}
  },
  "additionalProperties":false,
  "properties":{
    "accepted_scope":{"const":["G3_00_SCHEMA_VECTOR_CLARIFICATION"],"type":"array"},
    "authority_ceiling":{"const":{"active_head_update":false,"clean_certification":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"package":false,"production_publication":false,"provider_launch":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false},"type":"object"},
    "checks":{"items":{"additionalProperties":false,"properties":{"check_id":{"enum":["G3VC-R01-PARENT-PINS","G3VC-R02-ENUM-NEGATIVE-CLOSURE","G3VC-R03-MAXITEMS-POSITIVE-LOWER-BOUND","G3VC-R04-TAGGED-UNION-EXCLUSIVE-FIELD","G3VC-R05-PATTERN-DIRECT-CONST-WITNESS","G3VC-R06-MINLENGTH-LOCAL-SCHEMA-ID-POSITIVE","G3VC-R07-ITEMS-FALSE-CHILD-VALID-POSITIVE","G3VC-R08-NOT-THEN-ELSE-CASE13","G3VC-R09-DENOMINATOR-COUNT-DIGEST-IMPACT","G3VC-R10-GENERATOR-EVALUATOR-CROSSCHECK-PARITY","G3VC-R11-MUTATION-NOFIRE-DENOMINATOR","G3VC-R12-AUTHORITY-DAG-INDEPENDENCE"],"type":"string"},"evidence":{"items":{"$ref":"#/$defs/file_identity"},"maxItems":10000000,"minItems":1,"type":"array","uniqueItems":true},"result":{"enum":["PASS","FAIL"],"type":"string"}},"required":["check_id","result","evidence"],"type":"object"},"maxItems":12,"minItems":12,"type":"array","uniqueItems":true},
    "disposition":{"enum":["PASS_G3_00_SCHEMA_VECTOR_CLARIFICATION_FOR_CONSTRUCTION_ONLY","REJECTED"],"type":"string"},
    "findings":{"items":{"$ref":"#/$defs/finding"},"maxItems":10000000,"minItems":0,"type":"array","uniqueItems":true},
    "independence":{"const":{"amendment_author_separate":true,"crosscheck_author_separate":true,"evaluator_author_separate":true,"generator_author_separate":true,"launcher_author_separate":true,"no_self_generated_evidence":true,"production_implementer_separate":true,"schema_builder_separate":true,"workspace_clean":true},"type":"object"},
    "normative_parents":{"const":[{"path":"architecture/program-facts-g3-00-schema-closure-amendment.md","sha256":"85534326385e04c73d74f92c3dfa13b0b8702131bd3e97ce97bbd998e685b280","size_bytes":88187},{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_SCHEMA_CLOSURE_AMENDMENT_INDEPENDENT_REVIEW.v1.json","sha256":"c3dd6f630b9bd6c2ff73aacd386c35b3201659d2eead45be90bb6835e71edd4f","size_bytes":9002}],"type":"array"},
    "open_findings":{"items":{"maxLength":512,"minLength":1,"pattern":"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$","type":"string"},"maxItems":10000000,"minItems":0,"type":"array","uniqueItems":true},
    "review_body_sha256":{"maxLength":64,"minLength":64,"pattern":"^[0-9a-f]{64}$","type":"string"},
    "review_id":{"maxLength":39,"minLength":39,"pattern":"^pfg3vr-[0-9a-f]{32}$","type":"string"},
    "reviewer":{"additionalProperties":false,"properties":{"organization":{"maxLength":256,"minLength":1,"type":"string"},"principal_id":{"maxLength":256,"minLength":12,"pattern":"^reviewer:[a-z0-9-]+/[a-z0-9-]+$","type":"string"},"role":{"maxLength":256,"minLength":1,"type":"string"}},"required":["principal_id","organization","role"],"type":"object"},
    "schema_version":{"const":"plamen.program_facts_g3_00_schema_vector_clarification_amendment_review.v1","type":"string"},
    "subject":{"$ref":"#/$defs/file_identity"}
  },
  "required":["schema_version","review_id","subject","normative_parents","reviewer","independence","checks","findings","open_findings","disposition","accepted_scope","authority_ceiling","review_body_sha256"],
  "type":"object"
}
```

The 12 receipt checks have these exact meanings:

1. `G3VC-R01-PARENT-PINS`: both parent identities, stable reads, dispositions,
   and the absence of parent-byte mutation are exact.
2. `G3VC-R02-ENUM-NEGATIVE-CLOSURE`: cases 14-15 have exact atom scope,
   `JSET` semantics, proof values, no-fire boundary, and no finite-domain
   inference.
3. `G3VC-R03-MAXITEMS-POSITIVE-LOWER-BOUND`: POS-01 recomputes every displayed
   byte term and narrowly closes the empty-positive semantic exception.
4. `G3VC-R04-TAGGED-UNION-EXCLUSIVE-FIELD`: case 16 proves the exact six current
   branch atoms without waiving any other tagged or ordinary `oneOf` atom.
5. `G3VC-R05-PATTERN-DIRECT-CONST-WITNESS`: WIT-01 has exact precedence,
   lowercase-hex structural proof, current pointer/value, table negative,
   complete 521/39/41/1 occurrence/literal/context/conflict closure, sole-
   conflict proof, full-target replay, and four-import cross-check boundary.
6. `G3VC-R06-MINLENGTH-LOCAL-SCHEMA-ID-POSITIVE`: POS-02 recomputes 29+1+12,
   binds all 13 current pointers, and grants no general regex/bound waiver.
7. `G3VC-R07-ITEMS-FALSE-CHILD-VALID-POSITIVE`: POS-03 binds only
   `items`/`ACCEPT_ITEM`/direct `false`, preserves `REJECT_ITEM`, and matches the
   exact 11 current pointers: ten tuple tails and one zero-item row.
8. `G3VC-R08-NOT-THEN-ELSE-CASE13`: case 13 is narrowed exactly and every
   displayed `not`/`then`/`else` consequence blocks as specified.
9. `G3VC-R09-DENOMINATOR-COUNT-DIGEST-IMPACT`: the 12-schema/24-child/32-keyword/
   39-literal/521-occurrence/41-context/1-conflict pattern identities and carrier
   identities remain unchanged, pattern per-subject counts equal their exact
   vector, 7,517 keyword occurrences equal the
   per-subject sum, A-F/case13 counts are exact, and the complete 21,578-row,
   5,102,113-byte, `286aa2...3915` atom-set identity is independently rederived.
10. `G3VC-R10-GENERATOR-EVALUATOR-CROSSCHECK-PARITY`: this contract defines
    exact subject, occurrence, atom, disposition, proof, vector, witness, and
    four pattern-stream row schemas, ordering, CJ+LF identities, projection
    joins, whole-parity identity,
    both-direction equality, and the separate fail-closed 33,554,432-byte parity-
    evidence capture rule while preserving the 16,777,216-byte control ceiling.
    This receipt check attests definition sufficiency only; it does not attest a
    future implementation, parity output, or measured output size.
11. `G3VC-R11-MUTATION-NOFIRE-DENOMINATOR`: section 12 contains all 45 exact
    required fixture designs, including fire, no-fire, direction, count,
    pointer, digest, stream-identity, and principal consequences. This receipt
    check does not claim that a future red or green execution occurred.
12. `G3VC-R12-AUTHORITY-DAG-INDEPENDENCE`: this contract exactly designates the
    process and launcher roles/principals/source/output paths, requires later
    launcher and provenance enforcement, separates the receipt reviewer from
    every designated author role, fixes acyclic downstream adoption and
    all-false authority, and grants no runtime/provider/vector/review/admission/
    cutover authority. Actual future source authorship and execution are checked
    only by the downstream per-schema and aggregate reviews.

Checks occur exactly once in the displayed numeric order. Evidence arrays sort
by `(UTF8(path),size_bytes,sha256)` and are duplicate-free. Findings sort by
UTF-8 `finding_id`; `open_findings` is exactly the ordered projection of IDs
whose status is `OPEN`. Passing requires every check `PASS`, nonempty evidence,
no open blocking finding, exact accepted scope, the exact all-false authority
object, and every independence value true.

Let `identity_body` be the complete receipt object excluding exactly
`review_id` and `review_body_sha256`. The receipt identities are:

```text
review_id = "pfg3vr-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_SCHEMA_VECTOR_CLARIFICATION_AMENDMENT_REVIEW_V1",
  review:identity_body
}))[0:32]
review_body_sha256 = SHA-256(CJ(full_review_without_only_review_body_sha256))
review_file = CF(full_review)
```

The receipt must be strict UTF-8, canonical JSON plus exactly one LF, with no
BOM or CR byte. The reviewer independently validates the schema itself with
Draft 2020-12 before validating the receipt. The receipt does not name or hash
itself, a future source file, vector, per-schema review, aggregate admission,
production module, package, or cutover.

## 14. Acyclic adoption order and authority ceiling

The only valid adoption order is:

1. stable-read both exact parents and preserve them byte-for-byte;
2. stable-read this amendment three times and obtain its external file identity;
3. a principal independent of the amendment, schema builder, vector generator,
   evaluator, cross-check, launcher, production implementer, and future aggregate
   reviewer writes only the section-13 receipt;
4. independently validate the receipt schema, identities, ordering, findings
   projection, exact 12 checks, scope, and all-false authority;
5. fixture authors add and execute the section-12 red fixtures before source
   repair; mutually separate generator, evaluator, cross-check, and launcher
   authors then implement their exact source paths without importing one another;
6. all three reproduce every exact subject, occurrence, atom, disposition,
   impossibility-proof, vector, witness, and four pattern streams and independently
   recompute each CJ+LF identity; only then may the 12 vectors be admitted;
7. every per-schema review includes the exact five identities -- this amendment,
   its receipt, and all three launcher-captured process-evidence files -- in each
   of `VECTOR-CARRIER`, `KEYWORD-OCCURRENCE-COVERAGE`, `POSITIVE-REPLAY`,
   `NEGATIVE-REPLAY`, and `IDENTITY-STABLE-READ`;
8. the aggregate review includes those same exact five identities as evidence for
   `G3A-07-VECTOR-RESULT-REPLAY` and
   `G3A-08-BIDIRECTIONAL-KEYWORD-ATOM-COVERAGE`; and
9. only the already-defined parent DAG may continue toward the separate G3-01
   amendment review.

The closed parent aggregate-manifest schema is not widened solely to add this
clarification. The clarification is pinned by each dependent per-schema review
and by the later aggregate review, which are downstream of it and not its
inputs. The clarification receipt consumes no vector or later review. This
keeps the dependency graph acyclic.

The parent closure receipt remains immutable historical evidence for its exact
subject. It is neither silently rewritten nor treated as proof of this
clarification. Any source or draft vector created before the clarification
receipt is non-authoritative until independently shown to conform and re-run
against the red-to-green denominator.

A passing clarification receipt grants only permission to repair and evaluate
the bounded G3-00 schema-vector construction under this contract. It is not a
schema-construction acceptance, vector pass, per-schema review, aggregate
admission, G3-01 acceptance, runtime test, provider authorization, release,
package, audit, commit, push, install, or cutover. Failure of any exact predicate,
proof, mutation, parity, count, identity, ordering, independence, or authority
condition blocks G3-00 admission; haltless degradation is unavailable for this
governance boundary.
