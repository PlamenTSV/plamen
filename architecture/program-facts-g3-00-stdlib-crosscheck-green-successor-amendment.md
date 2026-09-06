# Program Facts G3-00 stdlib cross-check GREEN-successor amendment

Status: `CONTRACT_ONLY_PENDING_INDEPENDENT_REVIEW`

This is the separately authored successor contract required by lines 617-632 of
the accepted transport-totality amendment. It defines a closed fixture, review,
handoff, candidate-acceptance, and canonical-construction sequence. It does not
perform or attest any step in that sequence. In particular, the presence of this
file is not a passing independent review, a repaired-subject binding, GREEN
execution or evidence, a source re-review, a handoff, candidate acceptance, a
canonical-copy intent, a canonical copy, an adoption receipt, or an adoption
marker.

`MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, and `MAY` have RFC 2119 meanings.
`CJ(x)` is RFC 8785 canonical JSON encoded as strict UTF-8. `CF(x)` is exactly
`CJ(x) || LF`. `SHA-256` returns lowercase hexadecimal. `UTF8(s)` is the strict
UTF-8 encoding of a string. No timestamp, file time, directory order, Git state,
or ambient path is an identity or ordering input.

## 0. Exact stable inputs and narrow effect

The following inputs are exact and immutable for this contract:

| Stable input | Bytes | SHA-256 |
|---|---:|---|
| `architecture/program-facts-g3-00-stdlib-crosscheck-transport-totality-amendment.md` | 53,343 | `e02ae54dd8be9bfeabe6a2eba042710bdef30dd72d7fbf3c1d67bd29db6eed89` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_INDEPENDENT_REVIEW.v1.json` | 10,882 | `f4d07e01a52141c9cf56e4c6d884857f64fb22cbdd516e170b5b6451f02171e0` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_RED_EVIDENCE.v1.json` | 6,944 | `ffbe065c09b1ea979431a2560e59618f6889c34f544907286ca03e7d33e0c18f` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_semantic_suite_v1.py` | 93,657 | `417e4978fe3c4a4c214a98cdce141d970b009665afead896b09aad7157aadf73` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_fixture_child_v1.py` | 2,369 | `72ba62378ca02f02770dc183b4760de8d4ecdc2674faab3d20ccc82694308cb8` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_red.py` | 3,288 | `f7ce4d4153c2058e67686b7459769eb61b494e126b6a6581ad73df3c4e1b9fba` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py` | 196,712 | `ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.PENDING.v1.json` | 12,054 | `e6bb2fa49d8bb7f81d510cc9212532cb3c8ac36ab3781fc2b2e9c48a43fa24e6` |

The accepted RED evidence additionally and immutably binds the pre-repair source
at the same repository path as 190,456 bytes with SHA-256
`e3cdd2599cf05d7f0c2b256d45d88e52f04fe15890d74a38bb296be44c1b5fb5`
both before and after RED execution. That historical content identity is not the
current repaired identity and MUST NOT be reconstructed, rewritten, or copied
over the repaired source. The PENDING handoff remains a historical pre-repair
artifact. It is never renamed, amended, replaced, or treated as an acceptance.

The repaired source remains a candidate at its existing path. This contract
does not authorize another repair. It only permits, after its own independent
acceptance, the closed operations in section 11. Every accepted subject count,
occurrence, atom, proof, vector, predicate, and meaning remains unchanged:

```text
subject schemas                                      12
keyword occurrences                              7,517
coverage atoms                                  21,578
impossibility-proof rows                           891
per-subject atom counts
  [1879,1812,2950,2283,2881,1445,1959,2018,1436,1160,992,763]
atom-set preimage bytes                        5,102,113
atom-set SHA-256
  286aa2a4477aa46f632c590020d3a49e1e147cef0194471d9893f8898a903915
impossibility-proof preimage bytes                338,716
impossibility-proof SHA-256
  0103ea85b210693908f2c7fb7368ca8c823afd959da6e1ae3d65d3563bf746c3
```

## 1. Closed path registry

Exactly the following 20 distinct repository-relative paths are in this
contract's transitive path closure. A `file_identity` anywhere in a governed
artifact MUST name one of these paths, and MUST use the role assigned below.
The same source path has two permitted content identities only because the
accepted RED evidence proves its historical pre-repair identity and this
contract pins its repaired identity. No path alias is permitted.

| Key | Exact path | Role |
|---|---|---|
| `successor_contract` | `architecture/program-facts-g3-00-stdlib-crosscheck-green-successor-amendment.md` | this contract |
| `transport_amendment` | `architecture/program-facts-g3-00-stdlib-crosscheck-transport-totality-amendment.md` | accepted amendment |
| `transport_review` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_INDEPENDENT_REVIEW.v1.json` | accepted amendment review |
| `red_evidence` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_RED_EVIDENCE.v1.json` | accepted RED evidence |
| `semantic_suite` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_semantic_suite_v1.py` | immutable semantic suite |
| `fixture_child` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_fixture_child_v1.py` | immutable fixture child |
| `red_wrapper` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_red.py` | immutable RED wrapper |
| `candidate_source` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py` | historical RED subject and repaired candidate |
| `pending_handoff` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.PENDING.v1.json` | immutable historical handoff |
| `contract_review` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_GREEN_SUCCESSOR_AMENDMENT_INDEPENDENT_REVIEW.v1.json` | independent receipt for this contract |
| `repaired_binding` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SUBJECT_BINDING.v1.json` | repaired-subject binding |
| `green_wrapper` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_green.py` | immutable GREEN wrapper |
| `green_evidence` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_GREEN_EVIDENCE.v1.json` | exact GREEN evidence |
| `source_review` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SOURCE_INDEPENDENT_REVIEW.v1.json` | repaired-source independent re-review |
| `successor_handoff` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.v2.json` | successor handoff |
| `candidate_acceptance` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANDIDATE_ACCEPTANCE.v2.json` | candidate acceptance for construction only |
| `copy_intent` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_COPY_INTENT.v2.json` | durable one-attempt canonical-copy permit |
| `canonical_source` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py` | create-only byte-identical canonical copy |
| `adoption_receipt` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_RECEIPT.v2.json` | canonical-construction receipt |
| `adoption_marker` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_MARKER.v2.json` | terminal construction marker |

There are no wildcard, directory, temporary, backup, lock, quarantine, log,
stdout, stderr, schema-file, alternate-version, or recovery paths. Schemas in
this document are registered and used in memory; they MUST NOT be materialized
as files. Existing-target mismatch therefore uses the fail-closed branch in
section 10 and does not invent a quarantine artifact.

## 2. Canonical encoding and identity calculus

Every governed JSON object is recursively closed: each object rejects unknown
members, each array has an exact cardinality or a stated finite bound, every
string and integer has the stated bound, and every nested file identity is
restricted by the 20-path registry. JSON numbers outside the safe integer range,
duplicate keys, non-UTF-8 input, BOM, CR, noncanonical escaping, non-finite
numbers, and trailing bytes other than the one required LF are invalid.

For each JSON artifact with fields `<id>` and `<body_sha256>`, let
`identity_body` be the complete object after removing exactly those two fields.
Its formulas are:

```text
<id> = <prefix> || SHA-256(CJ({domain:<DOMAIN>,artifact:identity_body}))[0:32]
<body_sha256> = SHA-256(CJ(full_object_without_only_<body_sha256>))
file_bytes = CF(full_object)
file_identity = {path:<registered_path>,size_bytes:len(file_bytes),sha256:SHA-256(file_bytes)}
```

The exact artifact formula assignments are:

| Artifact | ID field / prefix | Body field | Domain |
|---|---|---|---|
| contract review | `review_id` / `pfg3gsr-` | `review_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_GREEN_SUCCESSOR_CONTRACT_REVIEW_V1` |
| repaired binding | `binding_id` / `pfg3gsb-` | `binding_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_REPAIRED_SUBJECT_BINDING_V1` |
| GREEN evidence | `evidence_id` / `pfg3ge-` | `evidence_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_GREEN_EVIDENCE_V1` |
| repaired-source review | `review_id` / `pfg3grr-` | `review_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_REPAIRED_SOURCE_REVIEW_V1` |
| successor handoff | `handoff_id` / `pfg3gsh-` | `handoff_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_SUCCESSOR_HANDOFF_V2` |
| candidate acceptance | `acceptance_id` / `pfg3gca-` | `acceptance_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANDIDATE_ACCEPTANCE_V2` |
| canonical-copy intent | `intent_id` / `pfg3gci-` | `intent_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_COPY_INTENT_V2` |
| adoption receipt | `receipt_id` / `pfg3gar-` | `receipt_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_RECEIPT_V2` |
| adoption marker | `marker_id` / `pfg3gam-` | `marker_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_MARKER_V2` |

The full 64-hex digest is used inside the derivation and only the ID suffix is
truncated. The body digest is computed after the ID. An artifact never embeds
its own `file_identity`. A downstream artifact may embed an upstream external
`file_identity` only after the upstream file is complete, stable-read three
times, schema-valid, and formula-valid. Consequently there is no self-hash or
mutual-hash cycle.

The canonical source is not JSON. Its required identity is exactly:

```json
{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py","size_bytes":196712,"sha256":"ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f"}
```

## 3. Principals, independence, and generator/discriminator separation

Every principal object is exactly
`{principal_id,organization,role}`. `principal_id` matches
`^(author|reviewer|executor|implementer|acceptor|adopter):[a-z0-9-]+/[a-z0-9-]+$`;
`organization` is 1-256 Unicode scalar values; and `role` is one of the exact
roles below:

1. `GREEN successor contract author`;
2. `Independent GREEN successor contract reviewer`;
3. `Independent repaired-subject fixture author and GREEN executor`;
4. `Transport-totality repair implementer`;
5. `Independent repaired-source reviewer`;
6. `Successor handoff author`;
7. `Independent candidate acceptor for canonical construction only`;
8. `Independent canonical-copy adopter`; or
9. `Independent canonical-adoption validator and marker author`.

The contract review binds roles 1 and 2. The repaired binding binds roles 1-4.
GREEN evidence binds roles 1-4. Source review, handoff, acceptance, and adoption
extend the same roster without changing any earlier principal. Across the final
roster, all nine `principal_id` values MUST be pairwise different. They also
MUST differ from the accepted amendment reviewer
`reviewer:openai-codex/g3-00-crosscheck-transport-totality-review-20260809` and
the accepted RED executor
`executor:openai-codex/g3-00-crosscheck-transport-totality-red-fixtures`.
Organization equality does not defeat independence, but a role-label change,
session change, or agent restart does not establish a different principal.

At minimum, the repaired-source reviewer is distinct from the repair
implementer, fixture author, GREEN executor, and this contract's author. The
canonical adopter is distinct from every generator, reviewer, handoff author,
and acceptor. The marker author is distinct from the adopter and every earlier
principal. The contract reviewer cannot later fill any other role. The candidate
acceptor cannot write the handoff or canonical copy. No principal reviews,
accepts, adopts, validates, or marks its own output.

The repair implementer is the source generator. The fixture author is the
fixture/evidence generator. The contract reviewer, repaired-source reviewer,
and candidate acceptor are independent discriminators at different boundaries.
The canonical adopter is a downstream constructor, not a substitute
discriminator; the distinct marker author independently discriminates the
adopter's receipt. A generator's statement, a majority vote, or successful test
exit cannot replace the required discriminator artifact.

## 4. Exact acyclic order and chronology joins

The only permitted order is the following content-addressed DAG:

```text
accepted amendment + accepted amendment review
                    |
                    +--> accepted RED evidence --> historical pre-repair source
                    |             |                         |
this contract --> contract review |                         v
                    |             +--------------> repaired binding --> GREEN wrapper
                    |                                      |                 |
immutable suite + child + RED wrapper ---------------------+-----------------+
                                                                           |
                                                                           v
                                                                    GREEN evidence
                                                                           |
                                                                           v
                                                              repaired-source review
                                                                           |
                                                                           v
                                                                  successor handoff
                                                                           |
                                                                           v
                                                               candidate acceptance
                                                                           |
                                                                           v
                                                        durable copy intent/permit
                                                                           |
                                                                           v
                                                       create-only canonical v2 copy
                                                                           |
                                                                           v
                                                                adoption receipt
                                                                           |
                                                                           v
                                                                 adoption marker
```

The semantic RED-before-repair-before-GREEN ordering and the artifact dependency
DAG are proved by identity joins, never by timestamps:

1. the accepted RED evidence embeds the old source identity as both
   `frozen_candidate_source` and `post_run_candidate_source`;
2. the repaired binding embeds that exact RED-evidence identity, projects those
   two exact old-source identities, and separately embeds the repaired identity;
3. the GREEN wrapper embeds the repaired-binding external identity and repaired
   source identity, and imports the exact semantic-suite identity;
4. GREEN evidence embeds the binding, wrapper, suite, repaired source, and RED
   evidence identities, and proves all protected RED artifacts unchanged;
5. source review embeds the exact GREEN evidence and repaired source;
6. handoff embeds the source review; acceptance embeds the handoff; a freshly
   created copy intent embeds acceptance and an exact absent-target observation;
   the adoption receipt embeds the intent, acceptance, and canonical-copy
   identity; and the marker embeds the intent and receipt.

Those content joins prove dependency and acyclicity, not historical creator or
physical-order facts. Intent-before-copy-before-receipt physical ordering is
accepted only when one uninterrupted adopter attempt freshly creates the intent,
freshly creates the target, and commits the valid receipt before returning. A
hash, equality boolean, preexisting exact file, timestamp, or later artifact can
never reconstruct that physical provenance after a crash or restart. A complete
valid receipt is the explicit contractual commit boundary for later read-only
validation; it is not cryptographic proof of who historically wrote the bytes.

The old and repaired source identities differ at the same path. That inequality,
combined with the joins above, proves RED-before-repair-before-GREEN. A clock
claim cannot repair a missing join. GREEN creation or execution MUST NOT open
the amendment, accepted review, RED evidence, suite, child, RED wrapper, or
historical PENDING handoff for write, rename, replacement, truncation, metadata-
driven substitution, or deletion. In particular, GREEN can never rewrite or
"upgrade" a RED file.

## 5. Draft-2020-12 common schema and exact path fragments

The following Draft-2020-12 schema is the normative shared in-memory registry.
Each artifact schema in sections 6-9 is registered with this schema under the
shown `$id`. References MUST resolve only to this literal schema; network
resolution is forbidden.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json",
  "$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/validation":true},
  "$defs":{
    "hex64":{"type":"string","pattern":"^[0-9a-f]{64}$","minLength":64,"maxLength":64},
    "safe_path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},
    "file_identity":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/safe_path"},"size_bytes":{"type":"integer","minimum":0,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex64"}}},
    "principal":{"type":"object","additionalProperties":false,"required":["principal_id","organization","role"],"properties":{"principal_id":{"type":"string","minLength":12,"maxLength":256,"pattern":"^(author|reviewer|executor|implementer|acceptor|adopter):[a-z0-9-]+/[a-z0-9-]+$"},"organization":{"type":"string","minLength":1,"maxLength":256},"role":{"enum":["GREEN successor contract author","Independent GREEN successor contract reviewer","Independent repaired-subject fixture author and GREEN executor","Transport-totality repair implementer","Independent repaired-source reviewer","Successor handoff author","Independent candidate acceptor for canonical construction only","Independent canonical-copy adopter","Independent canonical-adoption validator and marker author"]}}},
    "authority":{"type":"object","const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}},
    "part0":{"type":"object","const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},
    "scope_contract_review":{"type":"array","const":["REVIEW_SUCCESSOR_CONTRACT_ONLY"]},
    "scope_fixture":{"type":"array","const":["BIND_REPAIRED_SUBJECT","CREATE_IMMUTABLE_GREEN_WRAPPER","EXECUTE_EXACT_20_CASE_GREEN_FIXTURE","WRITE_GREEN_EVIDENCE"]},
    "scope_source_review":{"type":"array","const":["REVIEW_REPAIRED_SOURCE_FOR_SUCCESSOR_HANDOFF_ONLY"]},
    "scope_handoff":{"type":"array","const":["CONSTRUCT_SUCCESSOR_HANDOFF_FOR_CANDIDATE_REVIEW_ONLY"]},
    "scope_acceptance":{"type":"array","const":["ACCEPT_CANDIDATE_FOR_CANONICAL_CONSTRUCTION_ONLY"]},
    "scope_copy_intent":{"type":"array","const":["CREATE_DURABLE_ONE_ATTEMPT_CANONICAL_COPY_INTENT","PERMIT_ONE_CREATE_ONLY_CANONICAL_COPY_ATTEMPT"]},
    "scope_adoption":{"type":"array","const":["CREATE_BYTE_IDENTICAL_CANONICAL_COPY","WRITE_CANONICAL_CONSTRUCTION_RECEIPT"]},
    "scope_marker":{"type":"array","const":["INDEPENDENTLY_VALIDATE_CANONICAL_CONSTRUCTION_RECEIPT","WRITE_CANONICAL_CONSTRUCTION_MARKER"]},
    "successor_contract":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-stdlib-crosscheck-green-successor-amendment.md"}}}]},
    "transport_amendment":{"const":{"path":"architecture/program-facts-g3-00-stdlib-crosscheck-transport-totality-amendment.md","size_bytes":53343,"sha256":"e02ae54dd8be9bfeabe6a2eba042710bdef30dd72d7fbf3c1d67bd29db6eed89"}},
    "transport_review":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_INDEPENDENT_REVIEW.v1.json","size_bytes":10882,"sha256":"f4d07e01a52141c9cf56e4c6d884857f64fb22cbdd516e170b5b6451f02171e0"}},
    "red_evidence":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_RED_EVIDENCE.v1.json","size_bytes":6944,"sha256":"ffbe065c09b1ea979431a2560e59618f6889c34f544907286ca03e7d33e0c18f"}},
    "semantic_suite":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_semantic_suite_v1.py","size_bytes":93657,"sha256":"417e4978fe3c4a4c214a98cdce141d970b009665afead896b09aad7157aadf73"}},
    "fixture_child":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_fixture_child_v1.py","size_bytes":2369,"sha256":"72ba62378ca02f02770dc183b4760de8d4ecdc2674faab3d20ccc82694308cb8"}},
    "red_wrapper":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_red.py","size_bytes":3288,"sha256":"f7ce4d4153c2058e67686b7459769eb61b494e126b6a6581ad73df3c4e1b9fba"}},
    "old_source":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py","size_bytes":190456,"sha256":"e3cdd2599cf05d7f0c2b256d45d88e52f04fe15890d74a38bb296be44c1b5fb5"}},
    "repaired_source":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py","size_bytes":196712,"sha256":"ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f"}},
    "pending_handoff":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.PENDING.v1.json","size_bytes":12054,"sha256":"e6bb2fa49d8bb7f81d510cc9212532cb3c8ac36ab3781fc2b2e9c48a43fa24e6"}},
    "contract_review":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_GREEN_SUCCESSOR_AMENDMENT_INDEPENDENT_REVIEW.v1.json"}}}]},
    "repaired_binding":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SUBJECT_BINDING.v1.json"}}}]},
    "green_wrapper":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_green.py"}}}]},
    "green_evidence":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_GREEN_EVIDENCE.v1.json"}}}]},
    "source_review":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SOURCE_INDEPENDENT_REVIEW.v1.json"}}}]},
    "successor_handoff":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.v2.json"}}}]},
    "candidate_acceptance":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANDIDATE_ACCEPTANCE.v2.json"}}}]},
    "copy_intent":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_COPY_INTENT.v2.json"}}}]},
    "canonical_target_plan":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py","expected_size_bytes":196712,"expected_sha256":"ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f"}},
    "canonical_source":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py","size_bytes":196712,"sha256":"ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f"}},
    "adoption_receipt":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_RECEIPT.v2.json"}}}]},
    "adoption_marker":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_MARKER.v2.json"}}}]},
    "finding":{"type":"object","additionalProperties":false,"required":["finding_id","severity","status","description","evidence"],"properties":{"finding_id":{"type":"string","minLength":1,"maxLength":512,"pattern":"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$"},"severity":{"enum":["BLOCKING","NONBLOCKING"]},"status":{"enum":["OPEN","CLOSED"]},"description":{"type":"string","minLength":1,"maxLength":8192},"evidence":{"type":"array","minItems":1,"maxItems":20,"uniqueItems":true,"items":{"$ref":"#/$defs/governed_identity"}}}},
    "governed_identity":{"oneOf":[{"$ref":"#/$defs/successor_contract"},{"$ref":"#/$defs/transport_amendment"},{"$ref":"#/$defs/transport_review"},{"$ref":"#/$defs/red_evidence"},{"$ref":"#/$defs/semantic_suite"},{"$ref":"#/$defs/fixture_child"},{"$ref":"#/$defs/red_wrapper"},{"$ref":"#/$defs/old_source"},{"$ref":"#/$defs/repaired_source"},{"$ref":"#/$defs/pending_handoff"},{"$ref":"#/$defs/contract_review"},{"$ref":"#/$defs/repaired_binding"},{"$ref":"#/$defs/green_wrapper"},{"$ref":"#/$defs/green_evidence"},{"$ref":"#/$defs/source_review"},{"$ref":"#/$defs/successor_handoff"},{"$ref":"#/$defs/candidate_acceptance"},{"$ref":"#/$defs/copy_intent"},{"$ref":"#/$defs/canonical_source"},{"$ref":"#/$defs/adoption_receipt"},{"$ref":"#/$defs/adoption_marker"}]}
  }
}
```

The `oneOf` has 21 identity alternatives because the one candidate path has two
permitted content identities; the registry still has exactly 20 distinct paths.
For a dynamic future identity, schema validation fixes its path and semantic
validation fixes its size/digest to the stable-read external identity of the
unique predecessor artifact. A later artifact MUST reproduce that full triple,
not merely the path.

## 6. Contract receipt and repaired-subject binding

### 6.1 Independent successor-contract receipt

The only receipt path is `contract_review` from section 1. Before publishing it,
the reviewer stable-reads each of the subject contract and eight stable inputs
three times, then repeats the three reads after review. All six reads per path
MUST be byte-identical, and the pre/post external identities MUST agree. The
review observation window permits a create-only write only to the receipt path.
The receipt validates against this exact Draft-2020-12 schema:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_contract_review.v1.schema.json",
  "$defs":{
    "pass_check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"enum":["G3GS-R01-EXACT-PINS","G3GS-R02-CLOSED-PATHS-SCHEMAS","G3GS-R03-IDENTITY-FORMULAS","G3GS-R04-RED-REPAIR-GREEN-JOINS","G3GS-R05-IMMUTABLE-SUITE-WRAPPERS","G3GS-R06-EXACT-GREEN-PROJECTION","G3GS-R07-REPAIR-REVIEW-HANDOFF-ACCEPTANCE","G3GS-R08-CANONICAL-INTENT-COPY-ADOPTION","G3GS-R09-NO-OVERWRITE-RECOVERY","G3GS-R10-PRINCIPAL-INDEPENDENCE","G3GS-R11-PART-0-GENERICITY","G3GS-R12-AUTHORITY-CEILING"]},"result":{"const":"PASS"},"evidence":{"type":"array","minItems":1,"maxItems":20,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/governed_identity"}}}}
  },
  "type":"object",
  "additionalProperties":false,
  "required":["schema_version","review_id","subject","pinned_inputs","protected_input_validation","contract_author","reviewer","independence","checks","findings","open_findings","part_0_genericity","disposition","accepted_scope","authority_ceiling","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_green_successor_contract_review.v1"},
    "review_id":{"type":"string","pattern":"^pfg3gsr-[0-9a-f]{32}$"},
    "subject":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/successor_contract"},
    "pinned_inputs":{"type":"array","minItems":9,"maxItems":9,"prefixItems":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/successor_contract"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/transport_amendment"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/transport_review"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/red_evidence"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/semantic_suite"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/fixture_child"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/red_wrapper"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_source"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/pending_handoff"}],"items":false},
    "protected_input_validation":{"type":"object","additionalProperties":false,"required":["protected_inputs","pre_review_reads_each","post_review_reads_each","pre_post_identities_equal","write_operations_observed","writes_permitted","predicate"],"properties":{"protected_inputs":{"type":"array","minItems":9,"maxItems":9,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/governed_identity"},"uniqueItems":true},"pre_review_reads_each":{"const":3},"post_review_reads_each":{"const":3},"pre_post_identities_equal":{"const":true},"write_operations_observed":{"const":[]},"writes_permitted":{"const":[]},"predicate":{"const":"EXACT_NINE_PINNED_INPUTS_READ_THREE_TIMES_BEFORE_AND_AFTER_REVIEW;ALL_SIX_READS_BYTE_IDENTICAL_PER_PATH;PRE_IDENTITY_EQUALS_POST_IDENTITY;NO_WRITE_OPEN_OR_MUTATION_API_TARGETED_A_PROTECTED_PATH"}}},
    "contract_author":{"allOf":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},{"properties":{"role":{"const":"GREEN successor contract author"}}}]},
    "reviewer":{"allOf":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},{"properties":{"role":{"const":"Independent GREEN successor contract reviewer"}}}]},
    "independence":{"const":{"accepted_amendment_reviewer_separate":true,"accepted_red_executor_separate":true,"contract_author_separate":true,"fixture_author_separate":true,"handoff_author_separate":true,"no_future_role_for_reviewer":true,"no_self_approval":true,"no_self_certification":true,"repair_implementer_separate":true,"source_reviewer_separate":true,"canonical_adopter_separate":true,"marker_author_separate":true}},
    "checks":{"type":"array","minItems":12,"maxItems":12,"uniqueItems":true,"items":{"$ref":"#/$defs/pass_check"}},
    "findings":{"type":"array","maxItems":0},
    "open_findings":{"type":"array","maxItems":0},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/part0"},
    "disposition":{"const":"PASS_GREEN_SUCCESSOR_CONTRACT_FOR_CLOSED_FIXTURE_REVIEW_AND_CANONICAL_CONSTRUCTION_ONLY"},
    "accepted_scope":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/scope_contract_review"},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/authority"},
    "review_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/hex64"}
  }
}
```

The `checks` order is the enum order shown, each ID occurs exactly once, and each
evidence list is sorted by `(UTF8(path),size_bytes,sha256)`. These order and set
constraints are mandatory semantic validation after JSON Schema validation.
`protected_inputs` equals `pinned_inputs` byte-semantically and in the same
order. `subject` equals `pinned_inputs[0]`. A passing receipt has no findings;
review working notes and failures are not published to this pass-only path.

The reviewer independently verifies all exact pins; 20-path/21-identity closure;
all schemas and formulas; all nine governed JSON artifact types; the immutable
semantic-suite reuse; the 20-case projection; identity-join chronology; the
principal separation; create-only recovery; Part-0 genericity; and all 29 false
authority flags. JSON Schema validation alone is insufficient. The receipt uses
the section-2 formula. Until it exists and independently validates, every later
path remains unauthorized.

### 6.2 Repaired-subject binding

After a passing contract receipt, the independent fixture author may create only
the `repaired_binding` object. It joins already accepted RED evidence to the
already existing repaired source; it is not authority to edit that source. Its
schema is:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_repaired_subject_binding.v1.schema.json",
  "type":"object",
  "additionalProperties":false,
  "required":["schema_version","binding_id","successor_contract","contract_review","transport_amendment","transport_review","red_evidence","historical_red_subject","historical_red_post_run_subject","repaired_source","historical_pending_handoff","fixture_child","semantic_suite","red_wrapper","chronology_join","principals","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","binding_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_repaired_subject_binding.v1"},
    "binding_id":{"type":"string","pattern":"^pfg3gsb-[0-9a-f]{32}$"},
    "successor_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/successor_contract"},
    "contract_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/contract_review"},
    "transport_amendment":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/transport_amendment"},
    "transport_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/transport_review"},
    "red_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/red_evidence"},
    "historical_red_subject":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/old_source"},
    "historical_red_post_run_subject":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/old_source"},
    "repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_source"},
    "historical_pending_handoff":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/pending_handoff"},
    "fixture_child":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/fixture_child"},
    "semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/semantic_suite"},
    "red_wrapper":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/red_wrapper"},
    "chronology_join":{"type":"object","additionalProperties":false,"required":["red_evidence_projects_frozen_subject","red_evidence_projects_post_run_subject","old_and_repaired_share_path","old_and_repaired_content_differ","red_evidence_identity_joined","repair_precedes_green_by_binding_dependency","timestamps_used"],"properties":{"red_evidence_projects_frozen_subject":{"const":true},"red_evidence_projects_post_run_subject":{"const":true},"old_and_repaired_share_path":{"const":true},"old_and_repaired_content_differ":{"const":true},"red_evidence_identity_joined":{"const":true},"repair_precedes_green_by_binding_dependency":{"const":true},"timestamps_used":{"const":false}}},
    "principals":{"type":"object","additionalProperties":false,"required":["contract_author","contract_reviewer","fixture_author","repair_implementer"],"properties":{"contract_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"contract_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"fixture_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"repair_implementer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"}}},
    "independence":{"const":{"contract_author_separate":true,"contract_reviewer_separate":true,"fixture_author_separate":true,"no_self_binding":true,"repair_implementer_separate":true}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/part0"},
    "disposition":{"const":"REPAIRED_SUBJECT_BOUND_FOR_EXACT_GREEN_FIXTURE_ONLY"},
    "accepted_scope":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/scope_fixture"},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/authority"},
    "binding_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/hex64"}
  }
}
```

The binding MUST independently parse the accepted RED evidence and require its
`frozen_candidate_source` and `post_run_candidate_source` to equal the two old-
source fields, its amendment/review/suite/child/RED-wrapper/PENDING identities
to equal the pins above, its result projection to be exactly 16 `RED` plus four
`PASS_UNCHANGED`, and its disposition to be
`RED_CONFIRMED_FIXTURE_FIRST_CROSSCHECK_REPAIR_MAY_BEGIN`. It then stable-reads
the repaired source three times and requires the exact 196,712/
`ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f`
identity. Contract principals reproduce the contract receipt byte-semantically;
roles are exact; all four IDs are pairwise distinct and satisfy section 3.

## 7. Immutable GREEN wrapper and exact GREEN evidence

### 7.1 Wrapper construction and behavior

Only after the repaired binding is complete and independently validated may the
fixture author create the one `green_wrapper` path. The wrapper is strict UTF-8
Python source with LF line endings and one final LF. It is immutable after its
first successful create-only publication. Its external identity is established
only after that publication and is then pinned in GREEN evidence; no earlier
artifact predicts or embeds that file identity.

The wrapper has only binding and orchestration logic. It MUST:

1. import the module at `semantic_suite` and verify that module's complete file
   identity is exactly 93,657/
   `417e4978fe3c4a4c214a98cdce141d970b009665afead896b09aad7157aadf73`
   before accessing `CASE_IDS` or `run_case`;
2. stable-read the repaired binding three times, validate its schema, ID/body
   formulas, disposition, principals, chronology joins, and external identity;
3. bind only the exact repaired source identity 196,712/
   `ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f`,
   stable-read it three times before the first case, and fail before case
   execution on any difference;
4. require the suite's ordered `CASE_IDS` to be exactly the 20 IDs below, call
   `semantic_suite.run_case(case_id, repaired_binding)` exactly once per ID in
   that order, and require every returned value to be exactly `True`;
5. contain no semantic assertion copied from, substituted for, or added to the
   suite; no `RED`/`GREEN` branch; no skip, expected-failure, retry, xfail,
   filtering, case mutation, alternate subject, or environment-dependent result;
6. expose exactly 20 `unittest` methods, one for each ordered case, and record
   exactly one `CF` result object
   `{fixture_id,expected_repaired_result:"PASS",observed_repaired_result:"PASS"}`
   for each successful method;
7. use the same one-write/one-flush/full-count result-record boundary as the RED
   wrapper, fail on `None`, non-`int`, partial, or short write, and write no
   governed file; and
8. restore every fixture-owned process object in `finally` and confer no child,
   launcher, provider, runner, runtime, capture, or evidence-publication power.

The wrapper may import only `hashlib`, `json`, `sys`, `unittest`, `pathlib.Path`,
and the exact semantic-suite module. An AST check enforces that closed import
set and the absence of subprocess, socket, network, dynamic import, reflection,
arbitrary filesystem traversal, code generation, source editing, and write APIs
other than the one test-result stdout buffer operation. The suite and child are
reused byte-for-byte; no GREEN copy, patched suite, subclass override, monkey-
patched method, or semantic adapter exists.

The exact one-command invocation is:

```text
python -m unittest review_fixtures.program_facts_runtime_gate3.g3_00_schema_crosscheck.test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_green
```

### 7.2 Exact 20-case all-pass projection

The command and evidence use this exact order. Although the immutable IDs retain
their fixture-first `G3CT-RED-` spelling, that spelling is an identifier, not a
phase branch. Every repaired expectation and observation is `PASS`.

| Ordinal | Fixture ID | Expected | Observed |
|---:|---|---|---|
| 1 | `G3CT-RED-01-WINDOWS-RAW-CRLF` | `PASS` | `PASS` |
| 2 | `G3CT-RED-02-CP1252-NONASCII` | `PASS` | `PASS` |
| 3 | `G3CT-RED-03-OVERSIZE-PLUS-ONE` | `PASS` | `PASS` |
| 4 | `G3CT-RED-04-EXACT-CAP` | `PASS` | `PASS` |
| 5 | `G3CT-RED-05-PARTIAL-WRITE` | `PASS` | `PASS` |
| 6 | `G3CT-RED-06-NONE-WRITE` | `PASS` | `PASS` |
| 7 | `G3CT-RED-07-SHORT-COUNT` | `PASS` | `PASS` |
| 8 | `G3CT-RED-08-FLUSH-FAILURE` | `PASS` | `PASS` |
| 9 | `G3CT-RED-09-ONE-WRITE-ONE-FLUSH` | `PASS` | `PASS` |
| 10 | `G3CT-RED-10-IMPORT-SYS-CONFINEMENT` | `PASS` | `PASS` |
| 11 | `G3CT-RED-11-ZERO-ATOM-VALID` | `PASS` | `PASS` |
| 12 | `G3CT-RED-12-ZERO-ATOM-INVALID` | `PASS` | `PASS` |
| 13 | `G3CT-RED-13-NONZERO-ALL-IMPOSSIBLE` | `PASS` | `PASS` |
| 14 | `G3CT-RED-14-NONZERO-ONE-VECTOR` | `PASS` | `PASS` |
| 15 | `G3CT-RED-15-NONZERO-UNPROVED` | `PASS` | `PASS` |
| 16 | `G3CT-RED-16-NONZERO-MISSING-DISPOSITION` | `PASS` | `PASS` |
| 17 | `G3CT-RED-17-DUPLICATE-DISPOSITION` | `PASS` | `PASS` |
| 18 | `G3CT-RED-18-UNKNOWN-DISPOSITION-ATOM` | `PASS` | `PASS` |
| 19 | `G3CT-RED-19-DIRECT-IF-SYMMETRY` | `PASS` | `PASS` |
| 20 | `G3CT-RED-20-CURRENT-12-SCHEMA-REGRESSION` | `PASS` | `PASS` |

`PASS` means the underlying semantic method returned `True`; it does not mean a
former failure was inverted by an expected-result wrapper. All 20 methods run.
There is no unexpected-result, waiver, missing, duplicate, reorder, explanation,
skip, or reviewer-discretion state. The final case must independently reproduce
the exact 12/7,517/21,578/891 census, per-subject vector, and two stream digests
from section 0. A mismatch prevents formation of GREEN evidence.

### 7.3 GREEN-evidence schema

The only evidence path is `green_evidence`. It validates against this exact
Draft-2020-12 schema:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_transport_totality_green_evidence.v1.schema.json",
  "$defs":{
    "case":{"type":"object","additionalProperties":false,"required":["fixture_id","expected_repaired_result","observed_repaired_result"],"properties":{"fixture_id":{"enum":["G3CT-RED-01-WINDOWS-RAW-CRLF","G3CT-RED-02-CP1252-NONASCII","G3CT-RED-03-OVERSIZE-PLUS-ONE","G3CT-RED-04-EXACT-CAP","G3CT-RED-05-PARTIAL-WRITE","G3CT-RED-06-NONE-WRITE","G3CT-RED-07-SHORT-COUNT","G3CT-RED-08-FLUSH-FAILURE","G3CT-RED-09-ONE-WRITE-ONE-FLUSH","G3CT-RED-10-IMPORT-SYS-CONFINEMENT","G3CT-RED-11-ZERO-ATOM-VALID","G3CT-RED-12-ZERO-ATOM-INVALID","G3CT-RED-13-NONZERO-ALL-IMPOSSIBLE","G3CT-RED-14-NONZERO-ONE-VECTOR","G3CT-RED-15-NONZERO-UNPROVED","G3CT-RED-16-NONZERO-MISSING-DISPOSITION","G3CT-RED-17-DUPLICATE-DISPOSITION","G3CT-RED-18-UNKNOWN-DISPOSITION-ATOM","G3CT-RED-19-DIRECT-IF-SYMMETRY","G3CT-RED-20-CURRENT-12-SCHEMA-REGRESSION"]},"expected_repaired_result":{"const":"PASS"},"observed_repaired_result":{"const":"PASS"}}}
  },
  "type":"object",
  "additionalProperties":false,
  "required":["schema_version","evidence_id","successor_contract","contract_review","repaired_subject_binding","transport_amendment","transport_review","red_evidence","historical_pending_handoff","fixture_child","semantic_suite","red_wrapper","green_wrapper","repaired_source","executor","repair_implementer","independence","platform","commands","case_results","green_case_count","failed_case_count","chronology_join","immutable_pre_execution","immutable_post_execution","post_run_repaired_source","post_run_green_wrapper","part_0_genericity","disposition","accepted_scope","authority_ceiling","evidence_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_transport_totality_green_evidence.v1"},
    "evidence_id":{"type":"string","pattern":"^pfg3ge-[0-9a-f]{32}$"},
    "successor_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/successor_contract"},
    "contract_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/contract_review"},
    "repaired_subject_binding":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_binding"},
    "transport_amendment":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/transport_amendment"},
    "transport_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/transport_review"},
    "red_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/red_evidence"},
    "historical_pending_handoff":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/pending_handoff"},
    "fixture_child":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/fixture_child"},
    "semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/semantic_suite"},
    "red_wrapper":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/red_wrapper"},
    "green_wrapper":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/green_wrapper"},
    "repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_source"},
    "executor":{"allOf":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},{"properties":{"role":{"const":"Independent repaired-subject fixture author and GREEN executor"}}}]},
    "repair_implementer":{"allOf":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},{"properties":{"role":{"const":"Transport-totality repair implementer"}}}]},
    "independence":{"const":{"accepted_amendment_reviewer_separate":true,"accepted_red_executor_separate":true,"contract_author_separate":true,"contract_reviewer_separate":true,"fixture_author_separate":true,"no_self_generated_acceptance":true,"repair_implementer_separate":true}},
    "platform":{"const":{"implementation":"CPython","operating_system":"WINDOWS","python_version":"3.12.10","stdout_capture_mode":"RAW_BYTES"}},
    "commands":{"type":"array","minItems":1,"maxItems":1,"prefixItems":[{"type":"object","additionalProperties":false,"required":["command_ordinal","argv","exit_code","fixture_ids","stdout_size_bytes","stdout_sha256","stderr_size_bytes","stderr_sha256"],"properties":{"command_ordinal":{"const":0},"argv":{"const":["python","-m","unittest","review_fixtures.program_facts_runtime_gate3.g3_00_schema_crosscheck.test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_green"]},"exit_code":{"const":0},"fixture_ids":{"const":["G3CT-RED-01-WINDOWS-RAW-CRLF","G3CT-RED-02-CP1252-NONASCII","G3CT-RED-03-OVERSIZE-PLUS-ONE","G3CT-RED-04-EXACT-CAP","G3CT-RED-05-PARTIAL-WRITE","G3CT-RED-06-NONE-WRITE","G3CT-RED-07-SHORT-COUNT","G3CT-RED-08-FLUSH-FAILURE","G3CT-RED-09-ONE-WRITE-ONE-FLUSH","G3CT-RED-10-IMPORT-SYS-CONFINEMENT","G3CT-RED-11-ZERO-ATOM-VALID","G3CT-RED-12-ZERO-ATOM-INVALID","G3CT-RED-13-NONZERO-ALL-IMPOSSIBLE","G3CT-RED-14-NONZERO-ONE-VECTOR","G3CT-RED-15-NONZERO-UNPROVED","G3CT-RED-16-NONZERO-MISSING-DISPOSITION","G3CT-RED-17-DUPLICATE-DISPOSITION","G3CT-RED-18-UNKNOWN-DISPOSITION-ATOM","G3CT-RED-19-DIRECT-IF-SYMMETRY","G3CT-RED-20-CURRENT-12-SCHEMA-REGRESSION"]},"stdout_size_bytes":{"type":"integer","minimum":1,"maximum":9007199254740991},"stdout_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/hex64"},"stderr_size_bytes":{"type":"integer","minimum":0,"maximum":9007199254740991},"stderr_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/hex64"}}}],"items":false},
    "case_results":{"type":"array","minItems":20,"maxItems":20,"uniqueItems":true,"items":{"$ref":"#/$defs/case"}},
    "green_case_count":{"const":20},
    "failed_case_count":{"const":0},
    "chronology_join":{"const":{"green_binds_repaired_binding":true,"green_binds_repaired_source":true,"green_binds_red_evidence":true,"old_source_differs_from_repaired_source":true,"red_evidence_precedes_repair_by_identity_join":true,"repair_precedes_green_by_identity_join":true,"timestamps_used":false}},
    "immutable_pre_execution":{"type":"array","minItems":10,"maxItems":10,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/governed_identity"}},
    "immutable_post_execution":{"type":"array","minItems":10,"maxItems":10,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/governed_identity"}},
    "post_run_repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_source"},
    "post_run_green_wrapper":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/green_wrapper"},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/part0"},
    "disposition":{"const":"GREEN_CONFIRMED_FOR_INDEPENDENT_REPAIRED_SOURCE_REVIEW_ONLY"},
    "accepted_scope":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/scope_fixture"},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/authority"},
    "evidence_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/hex64"}
  }
}
```

`case_results` is in the table order and its fixture-ID projection equals the
command's literal `fixture_ids` array. The command's raw stdout consists of the
20 wrapper records and is independently decoded into exactly those 20 rows;
stderr is retained only as size/digest. `immutable_pre_execution` and
`immutable_post_execution` are byte-identical, in this exact order:
`successor_contract`, `contract_review`, `repaired_subject_binding`,
`transport_amendment`, `transport_review`, `red_evidence`, `pending_handoff`,
`fixture_child`, `semantic_suite`, `red_wrapper`. The repaired source and GREEN
wrapper also equal their respective post-run identities. Each path is stable-
read three times before and after execution. There are zero writes, renames,
replaces, deletes, or truncations to those 12 protected paths.

Independent evidence validation checks the schema, section-2 formulas, exact
command, raw capture, 20 records, all-pass projection, platform, case arithmetic,
suite/child identity, wrapper AST, repaired binding, chronology joins, protected
pre/post identities, principals, Part-0 object, disposition, scope, and all-false
authority. The evidence is fixture regression evidence only. It is not source
review, candidate acceptance, parity capture, runtime observation, provider or
runner evidence, an audit, a finding, admission, release, or cutover.

## 8. Repaired-source review, successor handoff, and candidate acceptance

### 8.1 Independent repaired-source re-review

Only after independently valid GREEN evidence may the repaired-source reviewer
write `source_review`. The reviewer stable-reads the repaired source, contract,
contract receipt, binding, GREEN wrapper/evidence, accepted amendment pair, RED
evidence, suite, child, RED wrapper, and PENDING handoff three times before and
after review. All protected external identities remain equal. The reviewer does
not execute a second oracle, alter fixtures, repair the source, or create the
handoff. The pass-only receipt schema is:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_repaired_source_review.v1.schema.json",
  "$defs":{"pass_check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"enum":["G3GS-SR01-EXACT-UPSTREAM-JOINS","G3GS-SR02-REPAIRED-SUBJECT-STABILITY","G3GS-SR03-REPAIR-SCOPE","G3GS-SR04-IMPORT-SYS-CONFINEMENT","G3GS-SR05-CANONICAL-BINARY-STDOUT","G3GS-SR06-CAP-AND-FAIL-CLOSED-WRITES","G3GS-SR07-ZERO-ATOM-TOTALITY","G3GS-SR08-NONZERO-DISPOSITION-TOTALITY","G3GS-SR09-DIRECT-IF-G3VC16","G3GS-SR10-CENSUS-VECTOR-SEMANTICS","G3GS-SR11-EXACT-GREEN-PROJECTION","G3GS-SR12-RED-ARTIFACT-IMMUTABILITY","G3GS-SR13-PART-0-NO-PROTOCOL-NAMES","G3GS-SR14-PRINCIPAL-INDEPENDENCE","G3GS-SR15-AUTHORITY-CEILING"]},"result":{"const":"PASS"},"evidence":{"type":"array","minItems":1,"maxItems":20,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/governed_identity"}}}}},
  "type":"object",
  "additionalProperties":false,
  "required":["schema_version","review_id","successor_contract","contract_review","repaired_subject_binding","green_wrapper","green_evidence","red_evidence","semantic_suite","repaired_source","historical_pending_handoff","principals","independence","protected_input_validation","reviewed_subject_validation","checks","findings","open_findings","part_0_genericity","disposition","accepted_scope","authority_ceiling","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_repaired_source_review.v1"},
    "review_id":{"type":"string","pattern":"^pfg3grr-[0-9a-f]{32}$"},
    "successor_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/successor_contract"},
    "contract_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/contract_review"},
    "repaired_subject_binding":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_binding"},
    "green_wrapper":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/green_wrapper"},
    "green_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/green_evidence"},
    "red_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/red_evidence"},
    "semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/semantic_suite"},
    "repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_source"},
    "historical_pending_handoff":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/pending_handoff"},
    "principals":{"type":"object","additionalProperties":false,"required":["contract_author","contract_reviewer","fixture_author","repair_implementer","source_reviewer"],"properties":{"contract_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"contract_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"fixture_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"repair_implementer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"source_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"}}},
    "independence":{"const":{"accepted_amendment_reviewer_separate":true,"accepted_red_executor_separate":true,"contract_author_separate":true,"contract_reviewer_separate":true,"fixture_author_separate":true,"no_self_approval":true,"repair_implementer_separate":true,"source_reviewer_separate":true}},
    "protected_input_validation":{"type":"object","additionalProperties":false,"required":["protected_inputs","pre_review_reads_each","post_review_reads_each","pre_post_identities_equal","write_operations_observed","writes_permitted","predicate"],"properties":{"protected_inputs":{"type":"array","minItems":12,"maxItems":12,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/governed_identity"}},"pre_review_reads_each":{"const":3},"post_review_reads_each":{"const":3},"pre_post_identities_equal":{"const":true},"write_operations_observed":{"const":[]},"writes_permitted":{"const":[]},"predicate":{"const":"EXACT_TWELVE_REVIEW_INPUTS_STABLE_READ_THREE_TIMES_BEFORE_AND_AFTER;PRE_IDENTITY_EQUALS_POST_IDENTITY;NO_PROTECTED_PATH_WRITE_RENAME_REPLACE_TRUNCATE_OR_DELETE"}}},
    "reviewed_subject_validation":{"type":"object","additionalProperties":false,"required":["pre_review_subject","post_review_subject","pre_review_reads_each","post_review_reads_each","all_six_reads_byte_equal","pre_post_identities_equal","stable","resolved_path_exact","no_follow","no_alias","write_operation_count","write_operations_observed","writes_permitted","predicate"],"properties":{"pre_review_subject":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_source"},"post_review_subject":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_source"},"pre_review_reads_each":{"const":3},"post_review_reads_each":{"const":3},"all_six_reads_byte_equal":{"const":true},"pre_post_identities_equal":{"const":true},"stable":{"const":true},"resolved_path_exact":{"const":true},"no_follow":{"const":true},"no_alias":{"const":true},"write_operation_count":{"const":0},"write_operations_observed":{"const":[]},"writes_permitted":{"const":[]},"predicate":{"const":"REPAIRED_SOURCE_READ_THREE_TIMES_BEFORE_AND_THREE_TIMES_AFTER_REVIEW;ALL_SIX_RAW_BYTE_READS_EQUAL;PRE_AND_POST_IDENTITIES_EQUAL_EXACT_REPAIRED_SOURCE;RESOLVED_REPOSITORY_PATH_EXACT;NO_FOLLOW;NO_ALIAS;ZERO_WRITE_RENAME_REPLACE_TRUNCATE_OR_DELETE_OPERATIONS"}}},
    "checks":{"type":"array","minItems":15,"maxItems":15,"uniqueItems":true,"items":{"$ref":"#/$defs/pass_check"}},
    "findings":{"type":"array","maxItems":0},
    "open_findings":{"type":"array","maxItems":0},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/part0"},
    "disposition":{"const":"PASS_REPAIRED_SOURCE_FOR_SUCCESSOR_HANDOFF_ONLY"},
    "accepted_scope":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/scope_source_review"},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/authority"},
    "review_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/hex64"}
  }
}
```

The `protected_inputs` list is exactly these 12 predecessor artifacts, in this
order: contract, accepted amendment, accepted amendment review, RED evidence,
suite, child, RED wrapper, PENDING handoff, contract review, repaired binding,
GREEN wrapper, and GREEN evidence. The reviewed repaired source is not a hidden
thirteenth array member: it is mechanically and separately closed by
`reviewed_subject_validation`, whose two literal identities, six equal raw-byte
reads, exact resolved path, no-follow/no-alias facts, and zero writes are required
by both schema and semantic validation. The review therefore covers exactly 12
predecessor array paths plus one separately bound subject path with no count
contradiction. `checks` has exactly 15 rows in enum order, and evidence lists follow
the section-6 sort rule. The reviewer reproduces the GREEN evidence's exact
20-pass command/result join, not merely its zero exit status.

The receipt's contract author, contract reviewer, fixture author, and repair
implementer equal their predecessor bindings. `source_reviewer.role` is exact.
All five are pairwise distinct, and the source reviewer also satisfies every
explicit separation in section 3. Failure creates no pass receipt at this path
and blocks the handoff; there is no `REPAIR`-as-pass disposition.

### 8.2 Successor handoff

Only after the pass source review may the handoff author create
`successor_handoff`. It is a construction handoff, not an admission or release.
It neither edits nor replaces the historical PENDING handoff. Its schema is:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_successor_handoff.v2.schema.json",
  "type":"object",
  "additionalProperties":false,
  "required":["schema_version","handoff_id","successor_contract","contract_review","repaired_subject_binding","green_evidence","source_review","candidate_source","historical_pending_handoff","semantic_suite","repair_projection","principals","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","handoff_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_successor_handoff.v2"},
    "handoff_id":{"type":"string","pattern":"^pfg3gsh-[0-9a-f]{32}$"},
    "successor_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/successor_contract"},
    "contract_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/contract_review"},
    "repaired_subject_binding":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_binding"},
    "green_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/green_evidence"},
    "source_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/source_review"},
    "candidate_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_source"},
    "historical_pending_handoff":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/pending_handoff"},
    "semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/semantic_suite"},
    "repair_projection":{"const":{"atom_set_sha256":"286aa2a4477aa46f632c590020d3a49e1e147cef0194471d9893f8898a903915","coverage_atom_count":21578,"green_case_count":20,"impossibility_proof_count":891,"impossibility_proof_sha256":"0103ea85b210693908f2c7fb7368ca8c823afd959da6e1ae3d65d3563bf746c3","keyword_occurrence_count":7517,"semantic_suite_byte_identical":true,"subject_schema_count":12,"transport_and_zero_atom_totality_only":true}},
    "principals":{"type":"object","additionalProperties":false,"required":["contract_author","contract_reviewer","fixture_author","repair_implementer","source_reviewer","handoff_author"],"properties":{"contract_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"contract_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"fixture_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"repair_implementer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"source_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"handoff_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"}}},
    "independence":{"const":{"all_predecessor_principals_preserved":true,"handoff_author_separate":true,"no_self_approval":true,"source_reviewer_separate":true}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/part0"},
    "disposition":{"const":"READY_FOR_INDEPENDENT_CANDIDATE_ACCEPTANCE_FOR_CANONICAL_CONSTRUCTION_ONLY"},
    "accepted_scope":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/scope_handoff"},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/authority"},
    "handoff_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/hex64"}
  }
}
```

All predecessor identities and principals are byte-semantically equal to their
validated source artifacts. The historical handoff is a provenance input only;
the v2 handoff does not claim it was accepted or superseded in place. The
handoff author is a sixth distinct principal. The exact source/suite/census
projection is data copied from validated predecessors and confers no new fact.

### 8.3 Candidate acceptance for canonical construction only

The candidate acceptor may write `candidate_acceptance` only after validating
the complete DAG through the handoff. This acceptance is deliberately narrower
than admission: its sole positive effect is permission for a distinct adopter
to construct the byte-identical canonical path and two construction records.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_candidate_acceptance.v2.schema.json",
  "$defs":{"pass_check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"enum":["G3GS-CA01-CONTRACT-RECEIPT","G3GS-CA02-RED-REPAIR-GREEN-JOIN","G3GS-CA03-EXACT-20-PASS","G3GS-CA04-SUITE-BYTE-IDENTITY","G3GS-CA05-SOURCE-REVIEW","G3GS-CA06-SUCCESSOR-HANDOFF","G3GS-CA07-HISTORICAL-ARTIFACT-IMMUTABILITY","G3GS-CA08-PRINCIPAL-INDEPENDENCE","G3GS-CA09-PART-0-GENERICITY","G3GS-CA10-CONSTRUCTION-ONLY-AUTHORITY"]},"result":{"const":"PASS"},"evidence":{"type":"array","minItems":1,"maxItems":20,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/governed_identity"}}}}},
  "type":"object",
  "additionalProperties":false,
  "required":["schema_version","acceptance_id","successor_contract","contract_review","red_evidence","repaired_subject_binding","green_evidence","source_review","successor_handoff","candidate_source","semantic_suite","historical_pending_handoff","principals","independence","checks","findings","open_findings","part_0_genericity","disposition","accepted_scope","authority_ceiling","acceptance_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_candidate_acceptance.v2"},
    "acceptance_id":{"type":"string","pattern":"^pfg3gca-[0-9a-f]{32}$"},
    "successor_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/successor_contract"},
    "contract_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/contract_review"},
    "red_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/red_evidence"},
    "repaired_subject_binding":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_binding"},
    "green_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/green_evidence"},
    "source_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/source_review"},
    "successor_handoff":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/successor_handoff"},
    "candidate_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_source"},
    "semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/semantic_suite"},
    "historical_pending_handoff":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/pending_handoff"},
    "principals":{"type":"object","additionalProperties":false,"required":["contract_author","contract_reviewer","fixture_author","repair_implementer","source_reviewer","handoff_author","candidate_acceptor"],"properties":{"contract_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"contract_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"fixture_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"repair_implementer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"source_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"handoff_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"candidate_acceptor":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"}}},
    "independence":{"const":{"all_predecessor_principals_preserved":true,"candidate_acceptor_separate":true,"generator_discriminator_separation":true,"no_self_approval":true}},
    "checks":{"type":"array","minItems":10,"maxItems":10,"uniqueItems":true,"items":{"$ref":"#/$defs/pass_check"}},
    "findings":{"type":"array","maxItems":0},
    "open_findings":{"type":"array","maxItems":0},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/part0"},
    "disposition":{"const":"PASS_CANDIDATE_ACCEPTED_FOR_CREATE_ONLY_CANONICAL_CONSTRUCTION_NOT_ADMISSION"},
    "accepted_scope":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/scope_acceptance"},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/authority"},
    "acceptance_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/hex64"}
  }
}
```

The ten checks occur in enum order, each once, with sorted unique evidence.
Their evidence union contains every predecessor required by the DAG. All seven
principal IDs are pairwise distinct and reproduce predecessor roles exactly.
The pass-only findings projection is empty. An invalid, incomplete, or failed
review publishes no acceptance at this path and cannot be interpreted as
conditional permission.

## 9. Durable copy intent, create-only canonical copy, receipt, and marker

### 9.1 Create-only canonical-copy intent and one-attempt permit

Candidate acceptance alone cannot authorize an ambient or preexisting target.
After candidate acceptance, the independent canonical adopter first checks that
the exact canonical target path is absent without following aliases. Only while
it is absent may that adopter create the one `copy_intent` file. Its durable
linearization is an operational precondition inside the same uninterrupted
attempt, not a retrospective fact inferred from content identity. Its exact
Draft-2020-12 schema is:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_canonical_copy_intent.v2.schema.json",
  "type":"object",
  "additionalProperties":false,
  "required":["schema_version","intent_id","successor_contract","contract_review","green_evidence","source_review","successor_handoff","candidate_acceptance","repaired_source","canonical_target_plan","target_observation","publication_requirement","copy_attempt_policy","predecessor_principals","canonical_adopter","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","intent_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_canonical_copy_intent.v2"},
    "intent_id":{"type":"string","pattern":"^pfg3gci-[0-9a-f]{32}$"},
    "successor_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/successor_contract"},
    "contract_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/contract_review"},
    "green_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/green_evidence"},
    "source_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/source_review"},
    "successor_handoff":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/successor_handoff"},
    "candidate_acceptance":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/candidate_acceptance"},
    "repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_source"},
    "canonical_target_plan":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/canonical_target_plan"},
    "target_observation":{"type":"object","additionalProperties":false,"required":["mapped_path","mapped_parent","mapped_leaf","parent_path_reads_each","absence_checks_each","all_observations_equal","target_absent","no_follow","no_alias","preexisting_target_accepted","write_operation_count","timestamps_used"],"properties":{"mapped_path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py"},"mapped_parent":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure"},"mapped_leaf":{"const":"crosscheck_schema_contracts_stdlib_v2.py"},"parent_path_reads_each":{"const":3},"absence_checks_each":{"const":3},"all_observations_equal":{"const":true},"target_absent":{"const":true},"no_follow":{"const":true},"no_alias":{"const":true},"preexisting_target_accepted":{"const":false},"write_operation_count":{"const":0},"timestamps_used":{"const":false}}},
    "publication_requirement":{"const":{"copy_open_forbidden_before_intent_barriers_and_readback":true,"create_only":true,"exclusive_create":true,"file_fsync_required":true,"intent_post_barrier_reads":3,"linearization_point":"PARENT_DIRECTORY_FSYNC_THEN_THREE_EQUAL_FINAL_PATH_READS_IN_SAME_UNINTERRUPTED_ATTEMPT","no_follow":true,"parent_directory_fsync_required":true,"receipt_commit_required_before_attempt_return":true,"same_uninterrupted_attempt_required":true}},
    "copy_attempt_policy":{"const":{"attempt_limit":1,"attempt_ordinal":0,"automatic_recovery_after_intent_publication":false,"crash_or_restart_before_valid_receipt_terminal_human_review":true,"exclusive_target_create_only":true,"intent_id_is_logical_attempt_id":true,"preexisting_intent_at_operation_entry_terminal":true,"preexisting_target_at_exclusive_open_terminal":true,"receipt_required_before_success":true,"retarget_forbidden":true,"same_uninterrupted_attempt_required":true,"second_intent_forbidden":true,"target_recheck_after_intent_durability_before_open":true}},
    "predecessor_principals":{"type":"object","additionalProperties":false,"required":["contract_author","contract_reviewer","fixture_author","repair_implementer","source_reviewer","handoff_author","candidate_acceptor"],"properties":{"contract_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"contract_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"fixture_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"repair_implementer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"source_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"handoff_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"candidate_acceptor":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"}}},
    "canonical_adopter":{"allOf":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},{"properties":{"role":{"const":"Independent canonical-copy adopter"}}}]},
    "independence":{"const":{"all_predecessor_principals_preserved":true,"canonical_adopter_separate":true,"candidate_acceptor_separate":true,"generator_discriminator_separation":true,"no_self_adoption":true}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/part0"},
    "disposition":{"const":"ONE_UNINTERRUPTED_INTENT_COPY_RECEIPT_ATTEMPT_PERMITTED_NO_PRE_RECEIPT_RECOVERY"},
    "accepted_scope":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/scope_copy_intent"},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/authority"},
    "intent_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/hex64"}
  }
}
```

The adopter must prepare and validate the complete intent `CF` in memory, create
the intent path exclusively with no-follow, perform full-count write, file fsync,
close, parent-directory fsync, then stable-read the final intent three times and
revalidate its schema, section-2 ID/body formulas, predecessor identities,
principal roster, target mapping, absent-target observation, scope, disposition,
Part-0 object, and all-false authority. Without leaving, restarting, handing off,
or returning from that same operation, the adopter must then recheck that the
target is still absent and issue the exclusive target create-open belonging to
this one logical intent. The intent ID is the logical copy-attempt ID; no second
ordinal, intent, target, retry identity, or automatic resume is defined. Success
is impossible until the same uninterrupted operation has also durably published
the adoption receipt.

`canonical_target_plan` is a closed plan with `expected_size_bytes` and
`expected_sha256`; it is deliberately not a `file_identity` and makes no claim
that the future target already exists. The first external `canonical_source`
identity appears only in the later adoption receipt. The intent embeds neither
its own external identity nor any downstream receipt/marker identity, so its
formula is acyclic and it cannot self-certify publication or copy completion.

If any object already occupies the canonical target before intent publication,
even with the exact desired bytes, intent formation is forbidden and the terminal
disposition is `PROVENANCE_UNRESOLVABLE_HUMAN_REVIEW` with reason
`UNPERMITTED_PREEXISTING_TARGET`. Because the intent path is create-only and
its schema requires the prior absent observation, a later actor can never create
an intent to legitimize or replay that target. At operation entry, any existing
intent without an already-complete valid adoption receipt is terminal
`PROVENANCE_UNRESOLVABLE_HUMAN_REVIEW`, whether the intent is malformed,
mismatched, or exact and whether the target is absent or exact. It is preserved
and cannot be acknowledged, regenerated, deleted, retried, promoted, or combined
with a later receipt. An existing intent is read only as a predecessor when an
already-valid adoption receipt commits the complete intent/copy/receipt chain.

### 9.2 Canonical-copy construction

Only the eighth, independent canonical adopter may perform this step, in the
same uninterrupted operation that has just freshly created, durably published,
stable-read, and validated the intent after candidate acceptance. An intent
found at operation entry without an already-valid receipt is not this fresh
predecessor and never authorizes copy creation. The sole source and target are:

```text
source  review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py
target  review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py
bytes   196,712
sha256  ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f
```

Without a restart, return, exception escape, or principal/process handoff, the
adopter stable-reads the intent again after its durability barriers, requires
its exact external identity, rechecks the mapped target as absent, stable-reads
the source three times, requires all source reads byte-equal and exactly the
pinned identity, holds the complete bytes in memory, and opens the target using
a create-new/exclusive/no-follow primitive belonging to that intent's sole
logical attempt. The primitive fails if any filesystem object already names the
target. The adopter writes the complete
source bytes without transformation, verifies full write count, flushes the
file, applies the host durability barrier, closes it, stable-reads the target
three times without following an alias, and requires direct byte equality with
the in-memory source as well as the exact target identity in section 2. There is
no formatter, import rewrite, version-string rewrite, newline conversion,
metadata-derived content, copy-from-ambient, or source mutation. The same
operation must then construct and durably publish the exact adoption receipt
before it returns success.

If the exclusive target create-open returns `EXISTS`, the operation becomes
terminal `PROVENANCE_UNRESOLVABLE_HUMAN_REVIEW` without reading equality as a
success condition. This is true for exact desired bytes, a target created in the
intent-to-open race, or any preexisting object. If the attempt crashes or returns
after intent creation or target creation but before a valid receipt commit, the
surviving intent and/or target are preserved as the same terminal state. No
automatic recovery, exact-equal adoption, new intent, retry, or later receipt is
permitted. Any nonregular, linked/aliased, unstable, partial, longer, shorter, or
different target is likewise terminal under section 10.
It is never overwritten, truncated, repaired in place, deleted, renamed aside,
or selected by modification time. The canonical copy is repository fixture
construction only, not installation, promotion, activation, or cutover.

### 9.3 Canonical-adoption receipt

After the freshly created target has the exact identity, and without leaving the
same uninterrupted operation that freshly created the intent and target, the
adopter must create `adoption_receipt`. Its schema is:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_canonical_adoption_receipt.v2.schema.json",
  "$defs":{"pass_check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"enum":["G3GS-AR01-CANDIDATE-ACCEPTANCE","G3GS-AR02-FRESH-DURABLE-COPY-INTENT","G3GS-AR03-SOURCE-STABLE-IDENTITY","G3GS-AR04-TARGET-EXCLUSIVE-CREATED","G3GS-AR05-DIRECT-BYTE-EQUALITY","G3GS-AR06-SAME-ATTEMPT-RECEIPT-COMMIT-NO-RECOVERY","G3GS-AR07-ADOPTER-INDEPENDENCE","G3GS-AR08-NO-ACTIVATION-OR-INSTALL","G3GS-AR09-AUTHORITY-CEILING"]},"result":{"const":"PASS"},"evidence":{"type":"array","minItems":1,"maxItems":20,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/governed_identity"}}}}},
  "type":"object",
  "additionalProperties":false,
  "required":["schema_version","receipt_id","successor_contract","contract_review","green_evidence","source_review","successor_handoff","candidate_acceptance","copy_intent","repaired_source","canonical_source","copy_operation","copy_outcome","principals","independence","checks","part_0_genericity","disposition","accepted_scope","authority_ceiling","receipt_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_canonical_adoption_receipt.v2"},
    "receipt_id":{"type":"string","pattern":"^pfg3gar-[0-9a-f]{32}$"},
    "successor_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/successor_contract"},
    "contract_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/contract_review"},
    "green_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/green_evidence"},
    "source_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/source_review"},
    "successor_handoff":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/successor_handoff"},
    "candidate_acceptance":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/candidate_acceptance"},
    "copy_intent":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/copy_intent"},
    "repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/repaired_source"},
    "canonical_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/canonical_source"},
    "copy_operation":{"const":{"automatic_recovery_used":false,"canonical_bytes_equal_source":true,"canonical_reads":3,"canonical_stable":true,"content_identity_alone_proves_physical_order":false,"copy_attempt_count":1,"copy_intent_durable_before_target_open":true,"create_only":true,"direct_byte_comparison":true,"exclusive_target_create_result":"CREATED","exclusive_target_exists_observed":false,"fresh_intent_created_in_same_attempt":true,"historical_creator_proof_claimed":false,"intent_identity_equal":true,"intent_is_logical_attempt_id":true,"intent_linearization_point_verified":true,"intent_post_barrier_reads":3,"intent_target_mapping_equal":true,"no_follow":true,"overwrite_operations":0,"preexisting_intent_or_target_used":false,"receipt_commit_before_attempt_return":true,"receipt_exclusive_create_result":"CREATED","receipt_exists_observed":false,"same_uninterrupted_attempt":true,"source_reads":3,"source_stable":true,"target_absent_after_intent_before_open":true,"target_absent_before_intent":true,"timestamps_used":false}},
    "copy_outcome":{"const":"CREATED_EXCLUSIVE_SAME_UNINTERRUPTED_ATTEMPT"},
    "principals":{"type":"object","additionalProperties":false,"required":["contract_author","contract_reviewer","fixture_author","repair_implementer","source_reviewer","handoff_author","candidate_acceptor","canonical_adopter"],"properties":{"contract_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"contract_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"fixture_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"repair_implementer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"source_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"handoff_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"candidate_acceptor":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},"canonical_adopter":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"}}},
    "independence":{"const":{"all_predecessor_principals_preserved":true,"canonical_adopter_separate":true,"candidate_acceptor_separate":true,"generator_discriminator_separation":true,"no_self_adoption":true}},
    "checks":{"type":"array","minItems":9,"maxItems":9,"uniqueItems":true,"items":{"$ref":"#/$defs/pass_check"}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/part0"},
    "disposition":{"const":"CANONICAL_V2_COPY_CONSTRUCTED_NOT_ADMITTED_NOT_INSTALLED"},
    "accepted_scope":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/scope_adoption"},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/authority"},
    "receipt_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/hex64"}
  }
}
```

The nine checks occur in enum order, once each, with sorted unique evidence.
All predecessor identities and seven predecessor principals reproduce their
validated sources. `canonical_adopter.role` is exact; all eight IDs are pairwise
distinct and satisfy section 3. There is exactly one copy outcome: exclusive
creation of a previously absent target in the same uninterrupted operation that
freshly created the intent and durably commits this receipt before returning.
No recovery outcome, preexisting intent/target branch, equality adoption, or
second attempt is representable.

An already-complete, formula/schema-valid receipt may later be reopened and
acknowledged read-only as the contractual commit boundary, but only together
with its exact intent, source, target, acceptance, and principal joins. This
permits independent marker validation; it does not claim that content hashes or
booleans cryptographically prove a historical creator. If no complete valid
receipt exists when a later operation encounters intent or target bytes, the
state is terminal human-review debt and no receipt may be backfilled.

### 9.4 Canonical-adoption marker

After independently validating the adoption receipt, a marker author distinct
from the canonical adopter and all earlier principals may create the terminal
`adoption_marker`. This marker records that the bounded
repository construction sequence is complete; "adoption" here does not mean
runtime selection, package installation, admission, release, or active-head
change. Its schema is:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_canonical_adoption_marker.v2.schema.json",
  "type":"object",
  "additionalProperties":false,
  "required":["schema_version","marker_id","successor_contract","contract_review","candidate_acceptance","copy_intent","canonical_source","adoption_receipt","adoption_receipt_id","adoption_receipt_body_sha256","canonical_adopter","marker_author","independence","construction_state","identity_join","part_0_genericity","disposition","accepted_scope","authority_ceiling","marker_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_canonical_adoption_marker.v2"},
    "marker_id":{"type":"string","pattern":"^pfg3gam-[0-9a-f]{32}$"},
    "successor_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/successor_contract"},
    "contract_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/contract_review"},
    "candidate_acceptance":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/candidate_acceptance"},
    "copy_intent":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/copy_intent"},
    "canonical_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/canonical_source"},
    "adoption_receipt":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/adoption_receipt"},
    "adoption_receipt_id":{"type":"string","pattern":"^pfg3gar-[0-9a-f]{32}$"},
    "adoption_receipt_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/hex64"},
    "canonical_adopter":{"allOf":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},{"properties":{"role":{"const":"Independent canonical-copy adopter"}}}]},
    "marker_author":{"allOf":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/principal"},{"properties":{"role":{"const":"Independent canonical-adoption validator and marker author"}}}]},
    "independence":{"const":{"all_receipt_principals_preserved_by_identity_join":true,"canonical_adopter_separate":true,"marker_author_separate":true,"no_self_certification":true}},
    "construction_state":{"const":"VALID_ADOPTION_RECEIPT_COMMIT_READ_ONLY_MARKER_CONTINUATION"},
    "identity_join":{"const":{"adoption_receipt_commit_boundary_valid":true,"adoption_receipt_formula_valid":true,"adoption_receipt_identity_equal":true,"adoption_receipt_independently_validated":true,"candidate_acceptance_identity_equal":true,"canonical_source_identity_equal":true,"content_identity_used_as_historical_creator_proof":false,"copy_intent_formula_valid":true,"copy_intent_identity_equal":true,"marker_created_after_receipt_by_dependency":true,"no_pre_receipt_automatic_recovery":true,"physical_order_inferred_from_hashes_or_booleans":false,"read_only_commit_acknowledgement":true,"timestamps_used":false}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/part0"},
    "disposition":{"const":"CANONICAL_V2_CONSTRUCTION_RECORDED_NOT_ADMITTED_NOT_ACTIVE"},
    "accepted_scope":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/scope_marker"},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/authority"},
    "marker_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_successor_common.v1.schema.json#/$defs/hex64"}
  }
}
```

The marker's intent identity equals the exact parsed intent pinned by the
receipt; its receipt ID/body digest equal the parsed receipt; its adopter equals
the intent and receipt adopter; its marker author is a ninth principal distinct
from all eight receipt principals; and all external identities are stable-read
triples. The receipt creator cannot create or validate this marker. The marker
does not embed its own identity and no earlier object embeds the marker.
It is therefore the terminal leaf of the section-4 hash DAG, not a self-hash.

## 10. Exact no-overwrite and recovery state machine

All 11 new final paths after this contract -- receipt, binding, GREEN wrapper,
GREEN evidence, source review, handoff, acceptance, copy intent, canonical
source, adoption receipt, and marker -- are create-only. No governed operation
uses replace, truncate, append, rename-over, delete-and-retry, or a temporary
final-name swap.

Before a JSON write, the complete `CF` bytes, ID, and body digest are calculated
in memory and independently validated. Before wrapper publication, the complete
source bytes are calculated and AST-validated in memory. Publication uses a
create-new/exclusive/no-follow open and full-count write followed by file and
directory durability barriers. The copy intent follows section 9.1 and the
canonical source follows section 9.2.

For each exact final path, recovery has only these states:

| Observed state | Exact action |
|---|---|
| absent, all predecessors valid | create exclusively; verify complete stable identity; then and only then permit its immediate successor |
| existing, regular, unique/nonaliased, stable, schema/formula-valid where JSON, and byte-identical to the complete intended bytes | for pre-canonical artifacts through candidate acceptance, or a complete valid marker, `IDEMPOTENT_EQUAL`; perform no write and acknowledge the step; copy intent, canonical source, and adoption receipt instead use the strict special states below |
| existing but partial, malformed, noncanonical, wrong identity, wrong predecessor join, wrong principal, wrong result, wrong authority, aliased, linked, nonregular, or unstable | `MISMATCH_EXISTING_TARGET`; preserve bytes in place, fail closed, and block this and every successor |
| create/open/write/flush/fsync/close/readback result is ambiguous or fails | `AMBIGUOUS_PUBLICATION`; pre-canonical artifacts use their exact branch, while any intent/copy/receipt object without a complete valid receipt becomes terminal human-review debt |
| a later artifact exists while any predecessor is absent or invalid | `ORPHAN_SUCCESSOR`; never use it to backfill the predecessor; fail closed |

Canonical intent/copy/receipt processing additionally has this exhaustive entry-
state partition. It overrides every generic equality branch for `copy_intent`,
`canonical_source`, and `adoption_receipt`:

| Intent state | Canonical target state | Receipt/marker state | Exact disposition |
|---|---|---|---|
| absent | absent | absent | after valid candidate acceptance, one fresh uninterrupted operation may exclusively create intent, exclusively create target, and durably create receipt; success is returned only after the receipt commit |
| absent | any existing object, including exact desired bytes | absent | `PROVENANCE_UNRESOLVABLE_HUMAN_REVIEW`; preserve target, forbid intent creation forever, and fail terminal |
| any existing intent, including complete exact intent | absent | absent | `PROVENANCE_UNRESOLVABLE_HUMAN_REVIEW`; a restart cannot resume after intent publication |
| any existing intent, including complete exact intent | any existing target, including exact desired bytes | absent | `PROVENANCE_UNRESOLVABLE_HUMAN_REVIEW`; preserve both and never backfill receipt |
| any | any | partial, malformed, unstable, mismatched, or orphan receipt | `PROVENANCE_UNRESOLVABLE_HUMAN_REVIEW`; preserve every object and never create marker |
| exact intent | exact stable byte-identical target | complete formula/schema-valid receipt with the exact full predecessor/principal/body joins | `READ_ONLY_COMMITTED_ACKNOWLEDGEMENT`; perform no intent/copy/receipt write and permit only independent marker validation/creation |
| absent, invalid, or mismatched intent/target | any | any purported complete receipt | receipt is not valid at this boundary; `PROVENANCE_UNRESOLVABLE_HUMAN_REVIEW` |
| exact intent | exact target | exact valid receipt and exact valid marker | `READ_ONLY_COMMITTED_ACKNOWLEDGEMENT`; no governed write or replay |

An intent-existing/copy-absent state is terminal, not resumable permission. An
intent+copy/receipt-absent state is terminal even when every byte is exact. An
early exact target without intent is terminal. An exclusive target create-open
that reports `EXISTS` is terminal. Once any such entry state is observed, no
later exact intent, target, receipt, marker, or identity equality can reclassify,
legitimize, or promote it. No schema-valid receipt may be created after that
observation under this contract.

The exact crash seams are:

1. before intent create: if intent, target, and receipt remain absent, a later
   fresh operation may begin after revalidating acceptance and absence;
2. during intent create/barriers/readback: if no intent object was created, the
   operation failed before the provenance boundary and a later fresh operation
   may begin; if any intent object exists and receipt does not, restart is
   terminal `PROVENANCE_UNRESOLVABLE_HUMAN_REVIEW` even when intent is exact;
3. after valid intent durability and before/during target open or write: any
   interruption sacrifices automatic recovery; surviving intent/target objects
   are preserved as terminal human-review debt;
4. if exclusive target create-open reports `EXISTS`, the same terminal state is
   returned without using an equality read to continue;
5. after exact target durability and before/during receipt publication: absence,
   partiality, or invalidity of the receipt at restart is terminal; exact intent
   and target do not permit receipt backfill;
6. the first complete formula/schema-valid receipt with exact joins is the
   durable commit boundary; only that already-complete state may later be
   acknowledged read-only and offered to the independent marker author; and
7. after receipt commit, marker creation may recover read-only from the valid
   receipt chain; a partial/invalid marker remains terminal, while an exact valid
   marker is acknowledged read-only.

Because section 1 defines no quarantine path, "fail closed" is the required
mismatch disposition: preserve the conflicting object in place, create nothing
later, and flag `PROVENANCE_UNRESOLVABLE_HUMAN_REVIEW` for separately governed
human resolution outside this contract.
No mismatch may be hidden as absence. No recovery scans a directory, trusts a
filename discovered from content, selects newest bytes, or imports an artifact
from another root.

`PROVENANCE_UNRESOLVABLE_HUMAN_REVIEW` is a flagged human-review item and a
terminal state for this construction branch, not silent continuation, a retry
loop, or permission to halt unrelated work. It may be surfaced only through an
already-authorized external human-review channel; this contract defines no debt
file or write for it. The flag grants no runtime, provider, runner, finding,
audit, admission, release, install, or cutover authority. Until separately
governed humans resolve the preserved state outside this contract, every
downstream governed operation remains blocked.

A partial GREEN wrapper cannot run. A partial or invalid GREEN evidence object
cannot enable source review. A partial review, handoff, or acceptance cannot
enable intent creation. A partial or preexisting intent cannot enable canonical
construction. An intent or canonical copy observed without a valid receipt
cannot enable or later acquire the adoption receipt. A partial receipt cannot
enable the marker. A marker is valid only if the complete valid receipt and its
entire predecessor chain are reopened, stable-read, and revalidated. Thus
recovery cannot promote partial or pre-receipt evidence, and only a valid
committed receipt/marker is acknowledged read-only without rewriting any
predecessor.

## 11. Granted operations and exact all-false authority ceiling

While status is `CONTRACT_ONLY_PENDING_INDEPENDENT_REVIEW`, this document grants
only the ability of an independent reviewer to perform a read-only review and,
if every check passes, create the one section-6.1 receipt. It grants no authority
to create or execute any later artifact. After a valid receipt, authority advances
only through the exact predecessor joins and operations below:

| Principal | Predecessor required | Only permitted governed operations |
|---|---|---|
| contract reviewer | this stable contract and eight exact inputs | read-only semantic review; create the contract receipt |
| fixture author / GREEN executor | valid contract receipt, then valid repaired binding/wrapper as applicable | create repaired binding; create immutable GREEN wrapper; execute the exact one-command/20-case fixture once; create GREEN evidence |
| repaired-source reviewer | valid GREEN evidence | read-only source review; create source-review receipt |
| handoff author | valid source review | create successor handoff |
| candidate acceptor | valid successor handoff | read-only candidate review; create construction-only acceptance |
| canonical adopter | valid candidate acceptance with intent, target, and receipt all absent at fresh operation entry | in one uninterrupted operation exclusively create and durably read back intent, exclusively create and durably read back the byte-identical target, then exclusively create and durably commit receipt before returning; any preexistence/crash before receipt is terminal human-review debt; stop after receipt |
| independent marker author | already-complete valid adoption receipt and full reopened predecessor chain | acknowledge the committed receipt read-only without claiming historical creator proof; independently validate intent/copy/receipt content joins; create only the terminal marker |

The repair implementer receives no operation from this contract because the
repaired source is already an exact stable input. No principal may borrow another
row's operation. Every allowed write is limited to the exact path owned by that
row, create-only, and terminates at the next independent boundary.

Every governed JSON artifact contains exactly this 29-member object:

```json
{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}
```

All 29 flags are false. The narrow operation table is not evidence for, and
cannot be widened into, parity capture, process capture, runtime execution,
provider or provider-launch authority, runner authority, audit authority,
finding/confidence/severity/refutation/suppression authority, admission, active-
head update, canonical promotion or installation, consumer use, production
publication, package, replay, release, commit, push, install, clean
certification, vector acceptance, terminal-negative inference, three-way parity,
or cutover. In particular:

- a GREEN fixture pass is not parity capture, runtime or provider evidence;
- a source review is not an audit, finding, admission, or release;
- a successor handoff is not a commit, push, install, or package instruction;
- candidate acceptance permits canonical construction only;
- a copy intent, canonical copy, receipt, or marker does not select an active implementation,
  modify a registry/import, certify cleanliness, admit G3-00, or authorize a
  later cutover; and
- no artifact makes a claim about worktree cleanliness or production behavior.

Any consumer requiring one of those powers needs a later separately authored,
independently reviewed contract and new evidence. Nothing here may be cited as
an implicit bridge.

## 12. Part-0 genericity and no protocol names

Every governed JSON artifact contains exactly:

```json
{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}
```

The GREEN wrapper and evidence retain only the accepted generic JSON values,
occurrence pointers, directions, coverage atoms, dispositions, byte streams,
failure-injection buffers, and current 12-subject identity/count regression.
They MUST contain no ecosystem-, language-, provider-, protocol-, contract-,
instruction-, or vulnerability-specific hints, seeds, names, expected findings,
or semantic shortcuts. The fixture IDs, G3 labels, file paths, and schema-version
strings are governance identifiers, not protocol names. `protocol_names` is
always the empty array and there is no extension member by which to add one.

No GREEN wrapper may derive new semantics from the repaired source or the RED
projection. The exact 93,657-byte semantic suite is the sole GREEN oracle. The
wrapper selects only the repaired binding; all 20 method bodies, child bytes,
case order, and meanings remain unchanged. The current 12-subject regression is
an identity/count preservation check and MUST NOT be mined for domain-specific
fixture guidance.

## 13. Mandatory validation and stop condition

At every edge, a validator MUST perform all of the following before permitting
the successor edge:

1. stable-read the predecessor three times and verify exact path, size, and
   SHA-256;
2. for JSON, require strict `CF`, validate the applicable Draft-2020-12 schema,
   recompute the ID and body formula, and reject unknown or missing content;
3. enforce every cross-field order, projection, equality, identity join, count,
   and disposition stated outside JSON Schema;
4. reproduce every predecessor principal and verify the cumulative pairwise-
   distinct roster, including separation from the accepted amendment reviewer
   and RED executor;
5. require the exact Part-0 object and 29-member all-false authority ceiling;
6. reject any unregistered path, self identity, timestamp ordering claim,
   alternate semantic suite, RED-file mutation, write-scope breach, exclusive
   target-create `EXISTS`, pre-receipt restart, any intent or canonical target
   observed at operation entry without an already-complete valid receipt, or any
   invalid/orphan receipt or successor, even when observed bytes are exact; and
7. permit only the immediate operation in section 11.

An invalid artifact is not downgraded to a warning, incomplete receipt, pending
approval, or reviewer discretion. Absence retains the predecessor state. A
mismatch fails closed as section 10 specifies. Artifact existence alone never
proves validity. Content identity never proves physical order or historical
creator. Only an already-complete valid receipt is the read-only contractual
commit boundary for marker validation; it cannot cure an earlier terminal
pre-receipt observation.

This contract stops at definition. Its author MUST NOT create the independent
receipt, repaired binding, GREEN wrapper, GREEN evidence, source review,
successor handoff, candidate acceptance, copy intent, canonical copy, adoption
receipt, or adoption marker, and MUST NOT execute GREEN. The next possible action is an
independent read-only review of this exact contract identity. Until a passing
receipt exists, the terminal state remains
`CONTRACT_ONLY_PENDING_INDEPENDENT_REVIEW` with every authority flag false.
