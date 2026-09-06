# Program Facts G3-00 stdlib cross-check binding-recovery amendment

Status: `CONTRACT_ONLY_PENDING_INDEPENDENT_RECOVERY_REVIEW`

This contract repairs only the create-only artifact namespace and schema joins
after a malformed repaired-subject binding was published. It does not repair,
replace, delete, accept, or validate that binding. It does not execute GREEN or
create any receipt, wrapper, evidence, review, handoff, acceptance, canonical
source, receipt, or marker. Every authority flag remains false.

`MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, and `MAY` have RFC 2119 meanings.
`CJ(x)` is RFC 8785 canonical JSON encoded as strict UTF-8. `CF(x)` is exactly
`CJ(x) || LF`. `SHA-256` returns lowercase hexadecimal. `UTF8(s)` is strict
UTF-8. A stable read is three direct, no-alias, no-follow reads whose complete
bytes are equal. Timestamps, file times, directory order, Git state, and ambient
paths are never identity or chronology inputs.

## 0. Frozen state and narrow supersession

The following identities are immutable inputs:

| Input | Bytes | SHA-256 |
|---|---:|---|
| `architecture/program-facts-g3-00-stdlib-crosscheck-green-successor-amendment.md` | 121,167 | `4d94fb76c7905971a0ae620d6c74511ef907822eae3d3e32ee00fcb79aea36e9` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_GREEN_SUCCESSOR_AMENDMENT_INDEPENDENT_REVIEW.v1.json` | 15,843 | `b82a0cbf8595e2f7595d0e473363551a041e5e00055073be085f21ec597dc35d` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SUBJECT_BINDING.v1.json` | 5,327 | `83326de23beda097387906db349df798f82e8058a04319621092eb7cef471622` |
| `architecture/program-facts-g3-00-stdlib-crosscheck-transport-totality-amendment.md` | 53,343 | `e02ae54dd8be9bfeabe6a2eba042710bdef30dd72d7fbf3c1d67bd29db6eed89` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_INDEPENDENT_REVIEW.v1.json` | 10,882 | `f4d07e01a52141c9cf56e4c6d884857f64fb22cbdd516e170b5b6451f02171e0` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_RED_EVIDENCE.v1.json` | 6,944 | `ffbe065c09b1ea979431a2560e59618f6889c34f544907286ca03e7d33e0c18f` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_semantic_suite_v1.py` | 93,657 | `417e4978fe3c4a4c214a98cdce141d970b009665afead896b09aad7157aadf73` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_fixture_child_v1.py` | 2,369 | `72ba62378ca02f02770dc183b4760de8d4ecdc2674faab3d20ccc82694308cb8` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_red.py` | 3,288 | `f7ce4d4153c2058e67686b7459769eb61b494e126b6a6581ad73df3c4e1b9fba` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py` | 196,712 | `ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.PENDING.v1.json` | 12,054 | `e6bb2fa49d8bb7f81d510cc9212532cb3c8ac36ab3781fc2b2e9c48a43fa24e6` |

The accepted RED evidence also freezes the historical pre-repair source at the
same source path as 190,456 bytes with SHA-256
`e3cdd2599cf05d7f0c2b256d45d88e52f04fe15890d74a38bb296be44c1b5fb5`.
It remains history and MUST NOT be reconstructed over the repaired source.

The 5,327-byte v1 binding contains this observed path:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendMENT_red.py
```

The accepted contract and frozen file identity require:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_red.py
```

Those strings are not byte-equal. Repository-relative identities are
case-sensitive even on a case-insensitive host. Therefore the v1 binding is
`MISMATCH_EXISTING_TARGET_TERMINAL_PROVENANCE_DEBT`. It is never a valid
binding, predecessor, receipt, or authority source. It MUST remain at its exact
path and identity forever: no deletion, overwrite, truncation, rename, case
normalization, patch, acknowledgement-as-equal, quarantine move, or replacement
is permitted. Its other fields, including any internally consistent formula,
cannot cure the path mismatch. Intended corrected v1 bytes or hashes are not
facts, MUST NOT be inferred, and MUST NOT be reconstructed or published.

At this contract's authoring boundary the original GREEN wrapper/evidence and
all original downstream paths through the canonical marker are absent; GREEN
has not run. Absence conveys no success. This amendment supersedes only the
accepted successor contract's post-binding path registry, version assignments,
schema references, publication mechanics, and recovery mechanics from its
section 6.2 onward. It does not supersede the accepted amendment/review, RED
evidence, repair bytes, semantic meanings, semantic suite, fixture child, RED
wrapper, historical handoff, case count/order, census/counts/digests, or role
separation. The accepted successor contract and its receipt remain accepted
predecessors; their branch through the v1 binding is permanently terminal.

The following semantic projection remains exact and unchanged:

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

## 1. Closed path registry and exact successor namespace

Exactly these 24 repository-relative paths are in the closure. The one source
path has historical and repaired identities; no other alias is permitted.

| Key | Exact path | Role |
|---|---|---|
| `recovery_contract` | `architecture/program-facts-g3-00-stdlib-crosscheck-binding-recovery-amendment.md` | this contract |
| `successor_contract` | `architecture/program-facts-g3-00-stdlib-crosscheck-green-successor-amendment.md` | accepted successor contract |
| `successor_contract_review` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_GREEN_SUCCESSOR_AMENDMENT_INDEPENDENT_REVIEW.v1.json` | accepted successor-contract receipt |
| `malformed_binding_v1` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SUBJECT_BINDING.v1.json` | preserved terminal provenance debt only |
| `transport_amendment` | `architecture/program-facts-g3-00-stdlib-crosscheck-transport-totality-amendment.md` | accepted amendment |
| `transport_review` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_INDEPENDENT_REVIEW.v1.json` | accepted amendment review |
| `red_evidence` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_RED_EVIDENCE.v1.json` | accepted RED evidence |
| `semantic_suite` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_semantic_suite_v1.py` | immutable semantic suite |
| `fixture_child` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_fixture_child_v1.py` | immutable fixture child |
| `red_wrapper` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_red.py` | immutable RED wrapper |
| `repaired_source` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py` | historical RED subject and repaired candidate |
| `pending_handoff` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.PENDING.v1.json` | immutable historical handoff |
| `recovery_review` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_BINDING_RECOVERY_AMENDMENT_INDEPENDENT_REVIEW.v1.json` | independent recovery-contract receipt |
| `debt_observation` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_REPAIRED_SUBJECT_BINDING_MISMATCH_OBSERVATION.v1.json` | create-only mismatch/debt observation |
| `repaired_binding_v2` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SUBJECT_BINDING.v2.json` | repaired-subject binding successor |
| `green_wrapper_v2` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_green_v2.py` | immutable GREEN wrapper successor |
| `green_evidence_v2` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_GREEN_EVIDENCE.v2.json` | exact GREEN evidence successor |
| `source_review_v2` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SOURCE_INDEPENDENT_REVIEW.v2.json` | repaired-source review successor |
| `successor_handoff_v3` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.v3.json` | successor handoff |
| `candidate_acceptance_v3` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANDIDATE_ACCEPTANCE.v3.json` | construction-only acceptance |
| `copy_intent_v3` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_COPY_INTENT.v3.json` | one-attempt copy intent |
| `canonical_source_v2` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py` | future create-only byte-identical source |
| `adoption_receipt_v3` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_RECEIPT.v3.json` | canonical-construction receipt |
| `adoption_marker_v3` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_MARKER.v3.json` | terminal construction marker |

There are no wildcard, backup, quarantine, lock, log, alternate-root, schema-file,
or recovery paths. Schema resources exist only in the in-memory registry below.
An implementation may use an ungoverned unique staging object solely under the
publication rule in section 8; it is never a registered artifact, predecessor,
recovery input, or substitute final path.

The absent `canonical_source_v2` path is safely reusable because its expected
bytes and identity remain exactly the repaired source's bytes and identity and
because it has never existed. Its `v2.py` name is a content target, not a JSON
schema generation. It is governed only by the fresh v3 intent and v3 receipt.
Any object appearing there before that fresh intent attempt, even exact bytes,
makes the path terminal and destroys this safe-reuse condition.

## 2. Identity formulas, principals, and exact DAG

For every new JSON artifact, remove exactly its ID field and body field to form
`identity_body`, then compute:

```text
<id> = <prefix> || SHA-256(CJ({domain:<DOMAIN>,artifact:identity_body}))[0:32]
<body_sha256> = SHA-256(CJ(full_object_without_only_<body_sha256>))
file_bytes = CF(full_object)
external_identity = {path:<registered-final-path>,size_bytes:len(file_bytes),sha256:SHA-256(file_bytes)}
```

RFC 8785 key ordering applies to the domain wrapper. The 64-hex digest is
truncated only for the ID suffix. The ID is inserted before the body digest is
computed. No artifact embeds its own external identity and no predecessor embeds
a successor, so no self-hash or mutual-hash cycle exists.

| Artifact | ID field / prefix | Body field | Domain |
|---|---|---|---|
| recovery review | `review_id` / `pfg3brr-` | `review_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_BINDING_RECOVERY_AMENDMENT_REVIEW_V1` |
| debt observation | `observation_id` / `pfg3bdo-` | `observation_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_BINDING_MISMATCH_OBSERVATION_V1` |
| repaired binding v2 | `binding_id` / `pfg3brb-` | `binding_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_REPAIRED_SUBJECT_BINDING_V2` |
| GREEN evidence v2 | `evidence_id` / `pfg3brg-` | `evidence_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_GREEN_EVIDENCE_V2` |
| source review v2 | `review_id` / `pfg3brs-` | `review_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_REPAIRED_SOURCE_REVIEW_V2` |
| handoff v3 | `handoff_id` / `pfg3brh-` | `handoff_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_SUCCESSOR_HANDOFF_V3` |
| acceptance v3 | `acceptance_id` / `pfg3bra-` | `acceptance_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANDIDATE_ACCEPTANCE_V3` |
| copy intent v3 | `intent_id` / `pfg3bri-` | `intent_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_COPY_INTENT_V3` |
| adoption receipt v3 | `receipt_id` / `pfg3brc-` | `receipt_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_RECEIPT_V3` |
| adoption marker v3 | `marker_id` / `pfg3brm-` | `marker_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_MARKER_V3` |

Every principal is exactly `{principal_id,organization,role}`. All twelve new
chain-role principal IDs are pairwise distinct and are also distinct from the
accepted amendment reviewer and accepted RED executor. Organization equality
does not defeat independence; a restarted session or changed role string does
not create a new principal. The exact roles are encoded by the common schema.
The recovery reviewer and debt observer have no later role. The fixture executor
is distinct from both repair implementer and every reviewer. The source reviewer,
handoff author, acceptor, adopter, and marker author are successively distinct.
The adopter is distinct from all generators and discriminators; the marker
author is distinct from the adopter and all predecessors. No principal reviews,
observes, accepts, adopts, or marks its own output.

The only identity DAG is:

```text
accepted successor contract + accepted successor review
       + malformed v1 binding (terminal debt, never an enabling edge)
       + accepted amendment/review + RED evidence + immutable inputs + repaired source
                                      |
this recovery contract --> recovery review --> debt observation
                                      |               |
                                      +---------------+--> repaired binding v2
                                                               |
                                                               v
                                                        GREEN wrapper v2
                                                               |
                       exact semantic suite + repaired source --+
                                                               v
                                                        GREEN evidence v2
                                                               |
                                                               v
                                                         source review v2
                                                               |
                                                               v
                                                             handoff v3
                                                               |
                                                               v
                                                          acceptance v3
                                                               |
                                                               v
                                                            intent v3
                                                               |
                                                               v
                                      create-only canonical source v2.py
                                                               |
                                                               v
                                                           receipt v3
                                                               |
                                                               v
                                                            marker v3
```

The malformed v1 binding has a dashed provenance-only relationship to the debt
observation and v2 binding; it has no enabling edge to GREEN or later artifacts.
From GREEN evidence onward, no artifact schema contains a field or `$ref` for
the malformed v1 binding. Chronology is established only by full external
identity joins. RED embeds the old source; binding v2 separately joins that RED
identity, the repaired source, the recovery review, and the debt observation;
GREEN evidence embeds binding v2 and the exact wrapper/source/suite identities;
each later JSON embeds its immediate valid predecessor. Canonical physical
intent-before-copy-before-receipt order additionally requires one uninterrupted
attempt and cannot be inferred from timestamps, equality, or later backfill.

## 3. Draft-2020-12 common schema

All schemas are registered in memory by exact `$id`; network resolution is
forbidden. Every `$ref` below resolves only to this literal common resource.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json",
  "$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/validation":true},
  "$defs":{
    "hex64":{"type":"string","pattern":"^[0-9a-f]{64}$","minLength":64,"maxLength":64},
    "safe_path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},
    "file_identity":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/safe_path"},"size_bytes":{"type":"integer","minimum":0,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex64"}}},
    "principal":{"type":"object","additionalProperties":false,"required":["principal_id","organization","role"],"properties":{"principal_id":{"type":"string","minLength":12,"maxLength":256,"pattern":"^(author|reviewer|observer|executor|implementer|acceptor|adopter):[a-z0-9-]+/[a-z0-9-]+$"},"organization":{"type":"string","minLength":1,"maxLength":256},"role":{"enum":["GREEN successor contract author","Independent GREEN successor contract reviewer","Binding-recovery amendment author","Independent binding-recovery amendment reviewer","Independent binding-mismatch and provenance-debt observer","Independent repaired-subject fixture author and GREEN executor","Transport-totality repair implementer","Independent repaired-source reviewer","Successor handoff author","Independent candidate acceptor for canonical construction only","Independent canonical-copy adopter","Independent canonical-adoption validator and marker author"]}}},
    "contract_author":{"allOf":[{"$ref":"#/$defs/principal"},{"properties":{"role":{"const":"GREEN successor contract author"}}}]},
    "contract_reviewer":{"allOf":[{"$ref":"#/$defs/principal"},{"properties":{"role":{"const":"Independent GREEN successor contract reviewer"}}}]},
    "recovery_author":{"allOf":[{"$ref":"#/$defs/principal"},{"properties":{"role":{"const":"Binding-recovery amendment author"}}}]},
    "recovery_reviewer":{"allOf":[{"$ref":"#/$defs/principal"},{"properties":{"role":{"const":"Independent binding-recovery amendment reviewer"}}}]},
    "debt_observer":{"allOf":[{"$ref":"#/$defs/principal"},{"properties":{"role":{"const":"Independent binding-mismatch and provenance-debt observer"}}}]},
    "fixture_executor":{"allOf":[{"$ref":"#/$defs/principal"},{"properties":{"role":{"const":"Independent repaired-subject fixture author and GREEN executor"}}}]},
    "repair_implementer":{"allOf":[{"$ref":"#/$defs/principal"},{"properties":{"role":{"const":"Transport-totality repair implementer"}}}]},
    "source_reviewer":{"allOf":[{"$ref":"#/$defs/principal"},{"properties":{"role":{"const":"Independent repaired-source reviewer"}}}]},
    "handoff_author":{"allOf":[{"$ref":"#/$defs/principal"},{"properties":{"role":{"const":"Successor handoff author"}}}]},
    "candidate_acceptor":{"allOf":[{"$ref":"#/$defs/principal"},{"properties":{"role":{"const":"Independent candidate acceptor for canonical construction only"}}}]},
    "canonical_adopter":{"allOf":[{"$ref":"#/$defs/principal"},{"properties":{"role":{"const":"Independent canonical-copy adopter"}}}]},
    "marker_author":{"allOf":[{"$ref":"#/$defs/principal"},{"properties":{"role":{"const":"Independent canonical-adoption validator and marker author"}}}]},
    "roster7":{"type":"array","minItems":7,"maxItems":7,"uniqueItems":true,"prefixItems":[{"$ref":"#/$defs/contract_author"},{"$ref":"#/$defs/contract_reviewer"},{"$ref":"#/$defs/recovery_author"},{"$ref":"#/$defs/recovery_reviewer"},{"$ref":"#/$defs/debt_observer"},{"$ref":"#/$defs/fixture_executor"},{"$ref":"#/$defs/repair_implementer"}],"items":false},
    "roster8":{"type":"array","minItems":8,"maxItems":8,"uniqueItems":true,"prefixItems":[{"$ref":"#/$defs/contract_author"},{"$ref":"#/$defs/contract_reviewer"},{"$ref":"#/$defs/recovery_author"},{"$ref":"#/$defs/recovery_reviewer"},{"$ref":"#/$defs/debt_observer"},{"$ref":"#/$defs/fixture_executor"},{"$ref":"#/$defs/repair_implementer"},{"$ref":"#/$defs/source_reviewer"}],"items":false},
    "roster9":{"type":"array","minItems":9,"maxItems":9,"uniqueItems":true,"prefixItems":[{"$ref":"#/$defs/contract_author"},{"$ref":"#/$defs/contract_reviewer"},{"$ref":"#/$defs/recovery_author"},{"$ref":"#/$defs/recovery_reviewer"},{"$ref":"#/$defs/debt_observer"},{"$ref":"#/$defs/fixture_executor"},{"$ref":"#/$defs/repair_implementer"},{"$ref":"#/$defs/source_reviewer"},{"$ref":"#/$defs/handoff_author"}],"items":false},
    "roster10":{"type":"array","minItems":10,"maxItems":10,"uniqueItems":true,"prefixItems":[{"$ref":"#/$defs/contract_author"},{"$ref":"#/$defs/contract_reviewer"},{"$ref":"#/$defs/recovery_author"},{"$ref":"#/$defs/recovery_reviewer"},{"$ref":"#/$defs/debt_observer"},{"$ref":"#/$defs/fixture_executor"},{"$ref":"#/$defs/repair_implementer"},{"$ref":"#/$defs/source_reviewer"},{"$ref":"#/$defs/handoff_author"},{"$ref":"#/$defs/candidate_acceptor"}],"items":false},
    "authority":{"type":"object","const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}},
    "part0":{"type":"object","const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},
    "recovery_contract":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-stdlib-crosscheck-binding-recovery-amendment.md"}}}]},
    "successor_contract":{"const":{"path":"architecture/program-facts-g3-00-stdlib-crosscheck-green-successor-amendment.md","size_bytes":121167,"sha256":"4d94fb76c7905971a0ae620d6c74511ef907822eae3d3e32ee00fcb79aea36e9"}},
    "successor_contract_review":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_GREEN_SUCCESSOR_AMENDMENT_INDEPENDENT_REVIEW.v1.json","size_bytes":15843,"sha256":"b82a0cbf8595e2f7595d0e473363551a041e5e00055073be085f21ec597dc35d"}},
    "malformed_binding_v1":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SUBJECT_BINDING.v1.json","size_bytes":5327,"sha256":"83326de23beda097387906db349df798f82e8058a04319621092eb7cef471622"}},
    "transport_amendment":{"const":{"path":"architecture/program-facts-g3-00-stdlib-crosscheck-transport-totality-amendment.md","size_bytes":53343,"sha256":"e02ae54dd8be9bfeabe6a2eba042710bdef30dd72d7fbf3c1d67bd29db6eed89"}},
    "transport_review":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_INDEPENDENT_REVIEW.v1.json","size_bytes":10882,"sha256":"f4d07e01a52141c9cf56e4c6d884857f64fb22cbdd516e170b5b6451f02171e0"}},
    "red_evidence":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_RED_EVIDENCE.v1.json","size_bytes":6944,"sha256":"ffbe065c09b1ea979431a2560e59618f6889c34f544907286ca03e7d33e0c18f"}},
    "semantic_suite":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_semantic_suite_v1.py","size_bytes":93657,"sha256":"417e4978fe3c4a4c214a98cdce141d970b009665afead896b09aad7157aadf73"}},
    "fixture_child":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_fixture_child_v1.py","size_bytes":2369,"sha256":"72ba62378ca02f02770dc183b4760de8d4ecdc2674faab3d20ccc82694308cb8"}},
    "red_wrapper":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_red.py","size_bytes":3288,"sha256":"f7ce4d4153c2058e67686b7459769eb61b494e126b6a6581ad73df3c4e1b9fba"}},
    "old_source":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py","size_bytes":190456,"sha256":"e3cdd2599cf05d7f0c2b256d45d88e52f04fe15890d74a38bb296be44c1b5fb5"}},
    "repaired_source":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py","size_bytes":196712,"sha256":"ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f"}},
    "pending_handoff":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.PENDING.v1.json","size_bytes":12054,"sha256":"e6bb2fa49d8bb7f81d510cc9212532cb3c8ac36ab3781fc2b2e9c48a43fa24e6"}},
    "recovery_review":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_BINDING_RECOVERY_AMENDMENT_INDEPENDENT_REVIEW.v1.json"}}}]},
    "debt_observation":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_REPAIRED_SUBJECT_BINDING_MISMATCH_OBSERVATION.v1.json"}}}]},
    "repaired_binding_v2":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SUBJECT_BINDING.v2.json"}}}]},
    "green_wrapper_v2":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_green_v2.py"}}}]},
    "green_evidence_v2":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_GREEN_EVIDENCE.v2.json"}}}]},
    "source_review_v2":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SOURCE_INDEPENDENT_REVIEW.v2.json"}}}]},
    "successor_handoff_v3":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.v3.json"}}}]},
    "candidate_acceptance_v3":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANDIDATE_ACCEPTANCE.v3.json"}}}]},
    "copy_intent_v3":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_COPY_INTENT.v3.json"}}}]},
    "canonical_target_plan":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py","expected_size_bytes":196712,"expected_sha256":"ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f"}},
    "canonical_source_v2":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py","size_bytes":196712,"sha256":"ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f"}},
    "adoption_receipt_v3":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_RECEIPT.v3.json"}}}]},
    "adoption_marker_v3":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_MARKER.v3.json"}}}]},
    "semantic_projection":{"type":"object","const":{"atom_set_preimage_bytes":5102113,"atom_set_sha256":"286aa2a4477aa46f632c590020d3a49e1e147cef0194471d9893f8898a903915","coverage_atom_count":21578,"green_case_count":20,"impossibility_proof_count":891,"impossibility_proof_preimage_bytes":338716,"impossibility_proof_sha256":"0103ea85b210693908f2c7fb7368ca8c823afd959da6e1ae3d65d3563bf746c3","keyword_occurrence_count":7517,"per_subject_atom_counts":[1879,1812,2950,2283,2881,1445,1959,2018,1436,1160,992,763],"semantic_suite_byte_identical":true,"subject_schema_count":12,"transport_and_zero_atom_totality_only":true}},
    "publication_requirements":{"type":"object","const":{"candidate_complete_before_final_publication":true,"candidate_location":"MEMORY_OR_UNGOVERNED_UNIQUE_STAGING_ONLY","candidate_reads":3,"each_candidate_read_byte_equal":true,"encoding_json_schema_formula_path_and_pin_validation_each_read":true,"final_collision_terminal":true,"final_direct_partial_write_forbidden":true,"final_publication":"EXCLUSIVE_CREATE_ONLY_ATOMIC_COMPLETE_BYTES","post_publication_final_reads":3,"post_publication_full_validation":true,"predecessors_revalidated_immediately_before_publication":true,"timestamps_used":false}}
  }
}
```

`old_source` is permitted only where historical RED chronology is explicitly
projected. `malformed_binding_v1` is permitted only in the recovery review and
debt observation. It is intentionally absent from binding v2 and every later
schema; binding v2 joins only the valid debt-observation identity. Dynamic external
identities are semantically fixed to the complete stable-read predecessor file,
not merely to their path.

## 4. Independent recovery review and debt observation schemas

The recovery reviewer stable-reads this contract and all eleven frozen inputs
three times before and after review. The reviewer validates every schema against
the Draft-2020-12 meta-schema using only the in-memory registry, every `$ref`,
formula assignment, path, pin, count, DAG edge, principal rule, publication rule,
Part-0 object, and the 29 false flags. A passing receipt alone may enable the
independent debt observer.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_amendment_review.v1.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject","accepted_successor_contract","accepted_successor_contract_review","malformed_binding_v1","pinned_inputs","protected_input_validation","recovery_author","reviewer","independence","checks","findings","open_findings","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_binding_recovery_amendment_review.v1"},
    "review_id":{"type":"string","pattern":"^pfg3brr-[0-9a-f]{32}$"},
    "subject":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/recovery_contract"},
    "accepted_successor_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/successor_contract"},
    "accepted_successor_contract_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/successor_contract_review"},
    "malformed_binding_v1":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/malformed_binding_v1"},
    "pinned_inputs":{"type":"array","minItems":12,"maxItems":12,"prefixItems":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/recovery_contract"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/successor_contract"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/successor_contract_review"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/malformed_binding_v1"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/transport_amendment"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/transport_review"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/red_evidence"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/semantic_suite"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/fixture_child"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/red_wrapper"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_source"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/pending_handoff"}],"items":false},
    "protected_input_validation":{"type":"object","const":{"all_six_reads_byte_equal_per_path":true,"post_review_reads_each":3,"pre_post_identities_equal":true,"pre_review_reads_each":3,"protected_input_count":12,"write_operation_count":0}},
    "recovery_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/recovery_author"},
    "reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/recovery_reviewer"},
    "independence":{"const":{"all_prior_principals_separate":true,"no_future_role_for_reviewer":true,"no_self_review":true,"reviewer_separate_from_recovery_author":true}},
    "checks":{"const":["G3BR-R01-EXACT-FROZEN-PINS","G3BR-R02-V1-MISMATCH-TERMINAL-DEBT","G3BR-R03-NO-V1-RECONSTRUCTION","G3BR-R04-CLOSED-PATHS-AND-SCHEMAS","G3BR-R05-IDENTITY-DAG-AND-FORMULAS","G3BR-R06-EXACT-20-CASE-SEMANTICS","G3BR-R07-PRINCIPAL-INDEPENDENCE","G3BR-R08-ATOMIC-CREATE-ONLY-PUBLICATION","G3BR-R09-CRASH-NO-BACKFILL","G3BR-R10-PART0-AND-AUTHORITY"]},
    "findings":{"const":[]},"open_findings":{"const":[]},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/part0"},
    "disposition":{"const":"PASS_BINDING_RECOVERY_AMENDMENT_FOR_MISMATCH_OBSERVATION_ONLY"},
    "accepted_scope":{"const":["REVIEW_BINDING_RECOVERY_AMENDMENT_ONLY"]},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/authority"},
    "publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/publication_requirements"},
    "review_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/hex64"}
  }
}
```

The `pinned_inputs` order is schema order and `subject == pinned_inputs[0]`.
The ten checks occur once in the literal order. The recovery author's principal
is declared by the receipt; it is not inferred from filesystem ownership.

After the receipt is valid, a separate observer may create only the observation
receipt below. The observer performs no correction and treats the malformed
object only as immutable byte evidence of the mismatch.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_mismatch_observation.v1.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","observation_id","recovery_contract","recovery_review","accepted_successor_contract","accepted_successor_contract_review","malformed_binding_v1","expected_red_wrapper","observed_red_wrapper_path","mismatch","observer","recovery_author","recovery_reviewer","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","observation_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_binding_mismatch_observation.v1"},
    "observation_id":{"type":"string","pattern":"^pfg3bdo-[0-9a-f]{32}$"},
    "recovery_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/recovery_contract"},
    "recovery_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/recovery_review"},
    "accepted_successor_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/successor_contract"},
    "accepted_successor_contract_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/successor_contract_review"},
    "malformed_binding_v1":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/malformed_binding_v1"},
    "expected_red_wrapper":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/red_wrapper"},
    "observed_red_wrapper_path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendMENT_red.py"},
    "mismatch":{"type":"object","const":{"case_folded_strings_equal":true,"case_sensitive_path_identity_required":true,"classification":"MISMATCH_EXISTING_TARGET_TERMINAL_PROVENANCE_DEBT","delete_overwrite_rename_or_reconstruct_permitted":false,"expected_and_observed_utf8_equal":false,"field":"red_wrapper.path","formula_validity_can_cure":false,"invalid_v1_can_enable_successor":false,"later_exact_bytes_can_cure":false,"no_backfill":true,"observation_only":true}},
    "observer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/debt_observer"},
    "recovery_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/recovery_author"},
    "recovery_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/recovery_reviewer"},
    "independence":{"const":{"no_future_role_for_observer":true,"no_self_observation":true,"observer_separate_from_all_authors_and_reviewers":true,"prior_principals_preserved":true}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/part0"},
    "disposition":{"const":"V1_BINDING_PRESERVED_AS_TERMINAL_DEBT_V2_BINDING_MAY_BE_INDEPENDENTLY_CONSTRUCTED"},
    "accepted_scope":{"const":["OBSERVE_AND_RECORD_TERMINAL_V1_BINDING_MISMATCH_ONLY"]},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/authority"},
    "publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/publication_requirements"},
    "observation_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/hex64"}
  }
}
```

## 5. Repaired binding v2 and immutable GREEN wrapper v2

Only after both receipts above are independently valid may the independent
fixture author assemble binding v2. The v2 object independently binds accepted
RED evidence, the exact repaired source, and the correct lowercase RED-wrapper
identity. Equality of a v2 principal value with text found in malformed v1 is at
most a consistency observation; no authority is inherited from malformed v1.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_repaired_subject_binding.v2.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","binding_id","recovery_contract","recovery_review","debt_observation","accepted_successor_contract","accepted_successor_contract_review","transport_amendment","transport_review","red_evidence","historical_red_subject","historical_red_post_run_subject","repaired_source","historical_pending_handoff","fixture_child","semantic_suite","red_wrapper","semantic_projection","chronology_join","principals","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","binding_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_repaired_subject_binding.v2"},
    "binding_id":{"type":"string","pattern":"^pfg3brb-[0-9a-f]{32}$"},
    "recovery_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/recovery_contract"},
    "recovery_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/recovery_review"},
    "debt_observation":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/debt_observation"},
    "accepted_successor_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/successor_contract"},
    "accepted_successor_contract_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/successor_contract_review"},
    "transport_amendment":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/transport_amendment"},
    "transport_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/transport_review"},
    "red_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/red_evidence"},
    "historical_red_subject":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/old_source"},
    "historical_red_post_run_subject":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/old_source"},
    "repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_source"},
    "historical_pending_handoff":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/pending_handoff"},
    "fixture_child":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/fixture_child"},
    "semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/semantic_suite"},
    "red_wrapper":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/red_wrapper"},
    "semantic_projection":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/semantic_projection"},
    "chronology_join":{"type":"object","const":{"old_and_repaired_content_differ":true,"old_and_repaired_share_path":true,"recovery_review_identity_joined":true,"red_evidence_identity_joined":true,"red_evidence_projects_frozen_subject":true,"red_evidence_projects_post_run_subject":true,"repair_precedes_green_by_v2_binding_dependency":true,"terminal_v1_debt_not_used_as_predecessor":true,"timestamps_used":false}},
    "principals":{"type":"object","additionalProperties":false,"required":["contract_author","contract_reviewer","recovery_author","recovery_reviewer","debt_observer","fixture_executor","repair_implementer"],"properties":{"contract_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/contract_author"},"contract_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/contract_reviewer"},"recovery_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/recovery_author"},"recovery_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/recovery_reviewer"},"debt_observer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/debt_observer"},"fixture_executor":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/fixture_executor"},"repair_implementer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repair_implementer"}}},
    "independence":{"const":{"all_seven_principals_pairwise_distinct":true,"fixture_executor_separate":true,"no_self_binding":true,"observer_and_reviewers_have_no_later_role":true,"repair_implementer_separate":true}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/part0"},
    "disposition":{"const":"REPAIRED_SUBJECT_BOUND_V2_FOR_EXACT_GREEN_FIXTURE_ONLY"},
    "accepted_scope":{"const":["BIND_REPAIRED_SUBJECT_V2","CREATE_IMMUTABLE_GREEN_WRAPPER_V2","EXECUTE_EXACT_20_CASE_GREEN_FIXTURE","WRITE_GREEN_EVIDENCE_V2"]},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/authority"},
    "publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/publication_requirements"},
    "binding_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/hex64"}
  }
}
```

Semantic validation additionally parses the accepted RED evidence and requires
its frozen/post-run source identities, amendment pair, suite, child, lowercase
RED wrapper, and historical handoff to equal the pins above; its projection is
exactly 16 `RED` plus four `PASS_UNCHANGED`; and its disposition remains
`RED_CONFIRMED_FIXTURE_FIRST_CROSSCHECK_REPAIR_MAY_BEGIN`. The repaired source is
stable-read and must equal its exact repaired identity. The contract author and
reviewer exactly reproduce the accepted successor receipt; the recovery author
and reviewer exactly reproduce the recovery receipt; the observer exactly
reproduces the debt observation; the fixture executor and repair implementer
occupy only their exact roles. All seven IDs are pairwise distinct and separate
from the accepted amendment reviewer and RED executor.

The wrapper at `green_wrapper_v2` is strict UTF-8 Python with LF and one final
LF. It is assembled, AST-validated, and published under section 8. It imports
only `hashlib`, `json`, `sys`, `unittest`, `pathlib.Path`, and the exact semantic
suite. Before cases, it stable-reads and fully validates binding v2, the semantic
suite, and repaired source. It embeds the exact binding-v2 external identity and
correct lowercase RED identity; it never imports, parses, or accepts malformed
v1. It calls `run_case(case_id,repaired_binding_v2)` exactly once for each exact
ordered ID in section 6, requires exact `True`, emits one canonical result record
per case, restores fixture-owned process state in `finally`, and adds no semantic
assertions, skips, retries, adapters, expected failures, runtime/provider calls,
or governed writes. Its only command is:

```text
python -m unittest review_fixtures.program_facts_runtime_gate3.g3_00_schema_crosscheck.test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_green_v2
```

## 6. Exact GREEN evidence v2 schema

The immutable case IDs remain spelling-preserved identifiers; every repaired
expectation and observation is `PASS`, in this exact order:

```text
G3CT-RED-01-WINDOWS-RAW-CRLF
G3CT-RED-02-CP1252-NONASCII
G3CT-RED-03-OVERSIZE-PLUS-ONE
G3CT-RED-04-EXACT-CAP
G3CT-RED-05-PARTIAL-WRITE
G3CT-RED-06-NONE-WRITE
G3CT-RED-07-SHORT-COUNT
G3CT-RED-08-FLUSH-FAILURE
G3CT-RED-09-ONE-WRITE-ONE-FLUSH
G3CT-RED-10-IMPORT-SYS-CONFINEMENT
G3CT-RED-11-ZERO-ATOM-VALID
G3CT-RED-12-ZERO-ATOM-INVALID
G3CT-RED-13-NONZERO-ALL-IMPOSSIBLE
G3CT-RED-14-NONZERO-ONE-VECTOR
G3CT-RED-15-NONZERO-UNPROVED
G3CT-RED-16-NONZERO-MISSING-DISPOSITION
G3CT-RED-17-DUPLICATE-DISPOSITION
G3CT-RED-18-UNKNOWN-DISPOSITION-ATOM
G3CT-RED-19-DIRECT-IF-SYMMETRY
G3CT-RED-20-CURRENT-12-SCHEMA-REGRESSION
```

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_transport_totality_green_evidence.v2.schema.json",
  "$defs":{"case":{"type":"object","additionalProperties":false,"required":["fixture_id","expected_repaired_result","observed_repaired_result"],"properties":{"fixture_id":{"type":"string"},"expected_repaired_result":{"const":"PASS"},"observed_repaired_result":{"const":"PASS"}}}},
  "type":"object","additionalProperties":false,
  "required":["schema_version","evidence_id","repaired_subject_binding_v2","green_wrapper_v2","red_evidence","semantic_suite","fixture_child","red_wrapper","repaired_source","executor","repair_implementer","platform","command","case_results","green_case_count","failed_case_count","semantic_projection","chronology_join","protected_pre_execution","protected_post_execution","post_run_repaired_source","post_run_green_wrapper","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","evidence_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_transport_totality_green_evidence.v2"},
    "evidence_id":{"type":"string","pattern":"^pfg3brg-[0-9a-f]{32}$"},
    "repaired_subject_binding_v2":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_binding_v2"},
    "green_wrapper_v2":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/green_wrapper_v2"},
    "red_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/red_evidence"},
    "semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/semantic_suite"},
    "fixture_child":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/fixture_child"},
    "red_wrapper":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/red_wrapper"},
    "repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_source"},
    "executor":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/fixture_executor"},
    "repair_implementer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repair_implementer"},
    "platform":{"const":{"implementation":"CPython","operating_system":"WINDOWS","python_version":"3.12.10","stdout_capture_mode":"RAW_BYTES"}},
    "command":{"type":"object","additionalProperties":false,"required":["argv","exit_code","fixture_ids","stdout_size_bytes","stdout_sha256","stderr_size_bytes","stderr_sha256"],"properties":{"argv":{"const":["python","-m","unittest","review_fixtures.program_facts_runtime_gate3.g3_00_schema_crosscheck.test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_green_v2"]},"exit_code":{"const":0},"fixture_ids":{"const":["G3CT-RED-01-WINDOWS-RAW-CRLF","G3CT-RED-02-CP1252-NONASCII","G3CT-RED-03-OVERSIZE-PLUS-ONE","G3CT-RED-04-EXACT-CAP","G3CT-RED-05-PARTIAL-WRITE","G3CT-RED-06-NONE-WRITE","G3CT-RED-07-SHORT-COUNT","G3CT-RED-08-FLUSH-FAILURE","G3CT-RED-09-ONE-WRITE-ONE-FLUSH","G3CT-RED-10-IMPORT-SYS-CONFINEMENT","G3CT-RED-11-ZERO-ATOM-VALID","G3CT-RED-12-ZERO-ATOM-INVALID","G3CT-RED-13-NONZERO-ALL-IMPOSSIBLE","G3CT-RED-14-NONZERO-ONE-VECTOR","G3CT-RED-15-NONZERO-UNPROVED","G3CT-RED-16-NONZERO-MISSING-DISPOSITION","G3CT-RED-17-DUPLICATE-DISPOSITION","G3CT-RED-18-UNKNOWN-DISPOSITION-ATOM","G3CT-RED-19-DIRECT-IF-SYMMETRY","G3CT-RED-20-CURRENT-12-SCHEMA-REGRESSION"]},"stdout_size_bytes":{"type":"integer","minimum":1,"maximum":9007199254740991},"stdout_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/hex64"},"stderr_size_bytes":{"type":"integer","minimum":0,"maximum":9007199254740991},"stderr_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/hex64"}}},
    "case_results":{"type":"array","minItems":20,"maxItems":20,"prefixItems":[{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-01-WINDOWS-RAW-CRLF"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-02-CP1252-NONASCII"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-03-OVERSIZE-PLUS-ONE"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-04-EXACT-CAP"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-05-PARTIAL-WRITE"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-06-NONE-WRITE"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-07-SHORT-COUNT"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-08-FLUSH-FAILURE"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-09-ONE-WRITE-ONE-FLUSH"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-10-IMPORT-SYS-CONFINEMENT"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-11-ZERO-ATOM-VALID"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-12-ZERO-ATOM-INVALID"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-13-NONZERO-ALL-IMPOSSIBLE"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-14-NONZERO-ONE-VECTOR"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-15-NONZERO-UNPROVED"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-16-NONZERO-MISSING-DISPOSITION"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-17-DUPLICATE-DISPOSITION"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-18-UNKNOWN-DISPOSITION-ATOM"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-19-DIRECT-IF-SYMMETRY"}}},{"$ref":"#/$defs/case","properties":{"fixture_id":{"const":"G3CT-RED-20-CURRENT-12-SCHEMA-REGRESSION"}}}],"items":false},
    "green_case_count":{"const":20},"failed_case_count":{"const":0},
    "semantic_projection":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/semantic_projection"},
    "chronology_join":{"const":{"green_binds_repaired_binding_v2":true,"green_binds_repaired_source":true,"green_binds_red_evidence":true,"red_precedes_repair_by_identity_join":true,"repair_precedes_green_by_identity_join":true,"terminal_debt_predecessor_used":false,"timestamps_used":false}},
    "protected_pre_execution":{"type":"array","minItems":6,"maxItems":6,"prefixItems":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_binding_v2"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/green_wrapper_v2"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/red_evidence"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/semantic_suite"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/fixture_child"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/red_wrapper"}],"items":false},
    "protected_post_execution":{"type":"array","minItems":6,"maxItems":6,"prefixItems":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_binding_v2"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/green_wrapper_v2"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/red_evidence"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/semantic_suite"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/fixture_child"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/red_wrapper"}],"items":false},
    "post_run_repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_source"},
    "post_run_green_wrapper":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/green_wrapper_v2"},
    "independence":{"const":{"executor_separate_from_all_reviewers_observer_and_implementer":true,"no_self_generated_acceptance":true,"predecessor_principals_preserved":true}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/part0"},
    "disposition":{"const":"GREEN_V2_CONFIRMED_FOR_INDEPENDENT_REPAIRED_SOURCE_REVIEW_ONLY"},
    "accepted_scope":{"const":["EXECUTE_EXACT_20_CASE_GREEN_FIXTURE","WRITE_GREEN_EVIDENCE_V2"]},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/authority"},
    "publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/publication_requirements"},
    "evidence_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/hex64"}
  }
}
```

The two protected arrays are byte-semantically equal in schema order and each
contains the same six ordered entries. The protected projection has exactly
eight ordered identity positions: those six entries, `post_run_repaired_source`,
and `post_run_green_wrapper`. Those positions cover exactly seven distinct
protected paths because `green_wrapper_v2` is intentionally both the second
array entry and the repeated post-run wrapper identity. Each of the seven
distinct paths is read three times before and after execution with zero governed
writes. `case_results` and `command.fixture_ids` have the same exact ordered
projection. Raw stdout decodes to exactly those 20 canonical records; stderr is
retained only by size/digest. Case 20 independently reproduces the full semantic
projection.

## 7. Source review, handoff, and acceptance successor schemas

Only a new independent source reviewer may create the v2 source-review receipt.
The review is read-only and reproduces all semantic and identity joins; it does
not execute an alternate oracle or change the repaired source.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_repaired_source_review.v2.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","green_evidence_v2","repaired_subject_binding_v2","green_wrapper_v2","repaired_source","semantic_suite","source_reviewer","predecessor_principals","protected_validation","checks","findings","open_findings","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_repaired_source_review.v2"},"review_id":{"type":"string","pattern":"^pfg3brs-[0-9a-f]{32}$"},
    "green_evidence_v2":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/green_evidence_v2"},
    "repaired_subject_binding_v2":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_binding_v2"},
    "green_wrapper_v2":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/green_wrapper_v2"},
    "repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_source"},
    "semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/semantic_suite"},
    "source_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/source_reviewer"},
    "predecessor_principals":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/roster7"},
    "protected_validation":{"type":"object","const":{"all_reads_byte_equal":true,"post_review_reads_each":3,"pre_post_identities_equal":true,"pre_review_reads_each":3,"reviewed_subject_exact":true,"write_operation_count":0}},
    "checks":{"const":["G3BR-SR01-VALID-V2-PREDECESSORS","G3BR-SR02-REPAIRED-SOURCE-STABILITY","G3BR-SR03-EXACT-REPAIR-SCOPE","G3BR-SR04-TRANSPORT-TOTALITY","G3BR-SR05-ZERO-ATOM-TOTALITY","G3BR-SR06-EXACT-20-PASS","G3BR-SR07-CENSUS-AND-DIGESTS","G3BR-SR08-HISTORICAL-IMMUTABILITY","G3BR-SR09-PRINCIPAL-INDEPENDENCE","G3BR-SR10-PART0-AND-AUTHORITY"]},
    "findings":{"const":[]},"open_findings":{"const":[]},
    "independence":{"const":{"all_eight_principals_pairwise_distinct":true,"no_self_review":true,"source_reviewer_separate_from_executor_and_implementer":true}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/part0"},
    "disposition":{"const":"PASS_REPAIRED_SOURCE_FOR_SUCCESSOR_HANDOFF_V3_ONLY"},"accepted_scope":{"const":["REVIEW_REPAIRED_SOURCE_FOR_SUCCESSOR_HANDOFF_V3_ONLY"]},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/publication_requirements"},"review_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/hex64"}
  }
}
```

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_successor_handoff.v3.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","handoff_id","source_review_v2","green_evidence_v2","repaired_subject_binding_v2","candidate_source","historical_pending_handoff","semantic_suite","semantic_projection","handoff_author","predecessor_principals","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","handoff_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_successor_handoff.v3"},"handoff_id":{"type":"string","pattern":"^pfg3brh-[0-9a-f]{32}$"},
    "source_review_v2":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/source_review_v2"},"green_evidence_v2":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/green_evidence_v2"},"repaired_subject_binding_v2":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_binding_v2"},"candidate_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_source"},"historical_pending_handoff":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/pending_handoff"},"semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/semantic_suite"},"semantic_projection":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/semantic_projection"},
    "handoff_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/handoff_author"},"predecessor_principals":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/roster8"},"independence":{"const":{"all_nine_principals_pairwise_distinct":true,"handoff_author_separate":true,"no_self_approval":true,"predecessor_principals_preserved":true}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/part0"},"disposition":{"const":"READY_FOR_INDEPENDENT_CANDIDATE_ACCEPTANCE_V3_FOR_CANONICAL_CONSTRUCTION_ONLY"},"accepted_scope":{"const":["CONSTRUCT_SUCCESSOR_HANDOFF_V3_FOR_CANDIDATE_REVIEW_ONLY"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/publication_requirements"},"handoff_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/hex64"}
  }
}
```

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_candidate_acceptance.v3.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","acceptance_id","successor_handoff_v3","source_review_v2","green_evidence_v2","repaired_subject_binding_v2","candidate_source","semantic_suite","candidate_acceptor","predecessor_principals","checks","findings","open_findings","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","acceptance_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_candidate_acceptance.v3"},"acceptance_id":{"type":"string","pattern":"^pfg3bra-[0-9a-f]{32}$"},
    "successor_handoff_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/successor_handoff_v3"},"source_review_v2":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/source_review_v2"},"green_evidence_v2":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/green_evidence_v2"},"repaired_subject_binding_v2":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_binding_v2"},"candidate_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_source"},"semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/semantic_suite"},
    "candidate_acceptor":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/candidate_acceptor"},"predecessor_principals":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/roster9"},
    "checks":{"const":["G3BR-CA01-V3-HANDOFF","G3BR-CA02-V2-BINDING-CHAIN","G3BR-CA03-EXACT-20-PASS","G3BR-CA04-SUITE-BYTE-IDENTITY","G3BR-CA05-SOURCE-REVIEW","G3BR-CA06-HISTORICAL-IMMUTABILITY","G3BR-CA07-V1-DEBT-NONENABLING","G3BR-CA08-PRINCIPAL-INDEPENDENCE","G3BR-CA09-PART0","G3BR-CA10-CONSTRUCTION-ONLY-AUTHORITY"]},"findings":{"const":[]},"open_findings":{"const":[]},"independence":{"const":{"all_ten_principals_pairwise_distinct":true,"candidate_acceptor_separate":true,"generator_discriminator_separation":true,"no_self_acceptance":true}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/part0"},"disposition":{"const":"PASS_CANDIDATE_ACCEPTED_V3_FOR_CREATE_ONLY_CANONICAL_CONSTRUCTION_NOT_ADMISSION"},"accepted_scope":{"const":["ACCEPT_CANDIDATE_V3_FOR_CANONICAL_CONSTRUCTION_ONLY"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/publication_requirements"},"acceptance_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/hex64"}
  }
}
```

Every predecessor identity and principal is byte-semantically reproduced from
the immediate valid predecessor. The source review has seven predecessor
principals plus the eighth source reviewer; the handoff has those eight plus the
ninth handoff author; acceptance has those nine plus the tenth acceptor. Each
schema's count statement refers to the cumulative recovery roster, not the two
separate accepted RED/amendment historical principals.

## 8. Complete-candidate publication, collision, crash, and recovery

Every one of the twelve new final paths after this contract is create-only. For
each JSON or Python final, the owner MUST first assemble the complete candidate
bytes in memory or in one ungoverned unique staging object. A staging object is
never placed at, linked from, renamed over, or treated as the final. The owner
MUST read the complete candidate three times, require all bytes equal, and on
each read validate strict UTF-8/LF rules; for JSON, strict CF, duplicate-key
rejection, canonical JSON, the full Draft-2020-12 schema, every `$ref`, ID/body
formula, external predecessor identity, cross-field projection, path registry,
pin, principal, Part-0, authority, and immediate predecessor; for Python, its
exact path-bearing literals, AST/import closure, and required semantic-neutral
wrapper or exact canonical-source bytes. A candidate validation failure exposes
no final path.

Immediately before publication, all predecessors are stable-read and fully
revalidated. Publication then uses one exclusive create-only primitive whose
success atomically makes the already-complete candidate bytes visible at the
exact final name. The final MUST NOT be opened and authored by incremental,
partial, append, truncate, replace, rename-over, or delete-and-retry writes. If
the environment cannot supply an exclusive create-only complete-byte publication
primitive, the operation is unsupported and stops before touching the final.
On success, the final is stable-read three times and fully revalidated before it
can become a predecessor. Any final-name collision is terminal even when the
existing bytes are exact. No idempotent-equal write/retry branch exists.

The exhaustive ordinary-artifact state machine is:

| State at the current edge | Disposition |
|---|---|
| final absent; all predecessors valid | build/validate candidate three times, revalidate predecessors, publish exactly once, stable-read/validate final three times |
| final exists when its creation is attempted | `FINAL_COLLISION_TERMINAL_PROVENANCE_DEBT`; preserve it and every predecessor; no write, equality adoption, retry, alternate version, or successor |
| publication returns failure or ambiguous result | inspect only to classify; if final is absent, stop with no successor and a later fresh attempt may start; if any final object exists, preserve it as terminal collision debt |
| complete final exists as an already-validated predecessor from a completed earlier edge | downstream reads may validate it; no actor may reopen its creation step or claim that content proves a historical creator |
| successor exists while predecessor is absent/invalid | `ORPHAN_SUCCESSOR_TERMINAL_PROVENANCE_DEBT`; never backfill the predecessor |
| malformed, partial, noncanonical, wrong-formula, wrong-join, wrong-principal, wrong-path, aliased, linked, nonregular, or unstable final | preserve in place; terminal debt; no repair or successor |

A crash before atomic publication that leaves the final absent permits a fresh
attempt after complete revalidation. A crash or ambiguous return that leaves any
final object is terminal for that edge; readback equality cannot recover creator
provenance. A completed edge is usable downstream only after its same operation
performed the required three final reads and validation; no later artifact may
be created to backfill a failed or ambiguous edge. No final is ever deleted,
rewritten, renamed, or reconstructed to manufacture absence.

Canonical construction is stricter. After valid acceptance v3, one fresh adopter
operation observes `copy_intent_v3`, `canonical_source_v2`, and
`adoption_receipt_v3` all absent; atomically publishes and validates intent v3;
rechecks the canonical target absent; stable-reads the repaired source three
times; atomically publishes the complete byte-identical canonical source; reads
it three times; then atomically publishes, reads, and validates receipt v3 before
returning. Any crash, return, collision, or ambiguity after intent publication
but before a complete valid receipt is terminal. No restart, new intent, target
equality adoption, receipt backfill, or retry exists. Only an already-complete
valid receipt with its full exact chain is a read-only commit boundary from which
an independent marker operation may proceed. An invalid/partial marker is
terminal; an exact valid marker is read-only terminal success.

## 9. Canonical intent, receipt, and marker schemas

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_canonical_copy_intent.v3.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","intent_id","candidate_acceptance_v3","candidate_source","canonical_target_plan","target_observation","attempt_policy","predecessor_principals","canonical_adopter","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","intent_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_canonical_copy_intent.v3"},"intent_id":{"type":"string","pattern":"^pfg3bri-[0-9a-f]{32}$"},"candidate_acceptance_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/candidate_acceptance_v3"},"candidate_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_source"},"canonical_target_plan":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/canonical_target_plan"},
    "target_observation":{"type":"object","const":{"all_observations_equal":true,"intent_absence_checks":3,"intent_absent":true,"mapped_leaf":"crosscheck_schema_contracts_stdlib_v2.py","mapped_parent":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure","mapped_path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py","no_alias":true,"no_follow":true,"preexisting_target_accepted":false,"receipt_absence_checks":3,"receipt_absent":true,"target_absence_checks":3,"target_absent":true,"timestamps_used":false}},
    "attempt_policy":{"type":"object","const":{"attempt_limit":1,"automatic_recovery_after_intent_publication":false,"collision_is_terminal_even_if_equal":true,"intent_copy_receipt_same_uninterrupted_attempt":true,"no_backfill":true,"receipt_commit_required_before_return":true,"retarget_forbidden":true,"target_recheck_after_intent":true}},
    "predecessor_principals":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/roster10"},"canonical_adopter":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/canonical_adopter"},"independence":{"const":{"all_eleven_principals_pairwise_distinct":true,"canonical_adopter_separate":true,"no_self_adoption":true,"predecessor_principals_preserved":true}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/part0"},"disposition":{"const":"ONE_FRESH_UNINTERRUPTED_V3_INTENT_COPY_RECEIPT_ATTEMPT_PERMITTED"},"accepted_scope":{"const":["CREATE_DURABLE_V3_COPY_INTENT","PERMIT_ONE_CREATE_ONLY_CANONICAL_COPY_ATTEMPT"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/publication_requirements"},"intent_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/hex64"}
  }
}
```

`canonical_target_plan` is not a file identity and does not claim the target
exists. After fresh intent publication, the adopter publishes the exact 196,712
repaired-source bytes without transformation. No formatter, import rewrite,
newline conversion, version-string rewrite, or metadata-derived bytes exist.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_canonical_adoption_receipt.v3.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","receipt_id","candidate_acceptance_v3","copy_intent_v3","repaired_source","canonical_source_v2","copy_operation","copy_outcome","predecessor_principals","canonical_adopter","checks","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","receipt_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_canonical_adoption_receipt.v3"},"receipt_id":{"type":"string","pattern":"^pfg3brc-[0-9a-f]{32}$"},"candidate_acceptance_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/candidate_acceptance_v3"},"copy_intent_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/copy_intent_v3"},"repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/repaired_source"},"canonical_source_v2":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/canonical_source_v2"},
    "copy_operation":{"type":"object","const":{"automatic_recovery_used":false,"canonical_bytes_equal_source":true,"canonical_reads":3,"canonical_stable":true,"collision_observed":false,"copy_attempt_count":1,"direct_byte_comparison":true,"direct_partial_final_write_used":false,"fresh_intent_created_in_same_attempt":true,"historical_creator_proof_claimed":false,"intent_identity_equal":true,"no_alias":true,"no_backfill":true,"no_follow":true,"overwrite_operations":0,"receipt_committed_before_attempt_return":true,"same_uninterrupted_attempt":true,"source_reads":3,"source_stable":true,"target_absent_after_intent_before_publish":true,"target_absent_before_intent":true,"target_publication":"EXCLUSIVE_CREATE_ONLY_ATOMIC_COMPLETE_BYTES","timestamps_used":false}},
    "copy_outcome":{"const":"CREATED_EXCLUSIVE_COMPLETE_BYTES_SAME_UNINTERRUPTED_ATTEMPT"},"predecessor_principals":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/roster10"},"canonical_adopter":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/canonical_adopter"},
    "checks":{"const":["G3BR-CR01-V3-ACCEPTANCE","G3BR-CR02-FRESH-V3-INTENT","G3BR-CR03-SOURCE-STABLE-IDENTITY","G3BR-CR04-TARGET-ABSENT-AND-EXCLUSIVE","G3BR-CR05-DIRECT-BYTE-EQUALITY","G3BR-CR06-SAME-ATTEMPT-RECEIPT-COMMIT","G3BR-CR07-NO-RECOVERY-OR-BACKFILL","G3BR-CR08-ADOPTER-INDEPENDENCE","G3BR-CR09-NO-ACTIVATION-AUTHORITY"]},"independence":{"const":{"all_eleven_principals_pairwise_distinct":true,"canonical_adopter_separate":true,"no_self_adoption":true,"predecessor_principals_preserved":true}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/part0"},"disposition":{"const":"CANONICAL_V2_COPY_CONSTRUCTED_BY_V3_CHAIN_NOT_ADMITTED_NOT_INSTALLED"},"accepted_scope":{"const":["CREATE_BYTE_IDENTICAL_CANONICAL_V2_COPY","WRITE_CANONICAL_CONSTRUCTION_RECEIPT_V3"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/publication_requirements"},"receipt_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/hex64"}
  }
}
```

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_canonical_adoption_marker.v3.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","marker_id","candidate_acceptance_v3","copy_intent_v3","canonical_source_v2","adoption_receipt_v3","adoption_receipt_id","adoption_receipt_body_sha256","canonical_adopter","marker_author","identity_join","independence","construction_state","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","marker_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_canonical_adoption_marker.v3"},"marker_id":{"type":"string","pattern":"^pfg3brm-[0-9a-f]{32}$"},"candidate_acceptance_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/candidate_acceptance_v3"},"copy_intent_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/copy_intent_v3"},"canonical_source_v2":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/canonical_source_v2"},"adoption_receipt_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/adoption_receipt_v3"},"adoption_receipt_id":{"type":"string","pattern":"^pfg3brc-[0-9a-f]{32}$"},"adoption_receipt_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/hex64"},"canonical_adopter":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/canonical_adopter"},"marker_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/marker_author"},
    "identity_join":{"type":"object","const":{"candidate_acceptance_identity_equal":true,"canonical_source_identity_equal":true,"content_identity_used_as_historical_creator_proof":false,"copy_intent_formula_valid":true,"copy_intent_identity_equal":true,"marker_created_after_receipt_by_dependency":true,"no_pre_receipt_recovery":true,"receipt_body_equal":true,"receipt_commit_boundary_valid":true,"receipt_formula_valid":true,"receipt_identity_equal":true,"timestamps_used":false}},"independence":{"const":{"all_receipt_principals_preserved":true,"all_twelve_principals_pairwise_distinct":true,"marker_author_separate":true,"no_self_certification":true}},"construction_state":{"const":"VALID_V3_RECEIPT_COMMIT_READ_ONLY_MARKER_CONTINUATION"},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/part0"},"disposition":{"const":"CANONICAL_V2_CONSTRUCTION_RECORDED_BY_V3_CHAIN_NOT_ADMITTED_NOT_ACTIVE"},"accepted_scope":{"const":["INDEPENDENTLY_VALIDATE_CANONICAL_CONSTRUCTION_RECEIPT_V3","WRITE_CANONICAL_CONSTRUCTION_MARKER_V3"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/publication_requirements"},"marker_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_binding_recovery_common.v2.schema.json#/$defs/hex64"}
  }
}
```

The marker author stable-reads and validates the full committed chain three
times. Receipt ID/body values equal the parsed receipt. The marker is the only
leaf; no earlier artifact embeds it.

## 10. Exact operation order and authority ceiling

Only these operations exist, in order:

| Principal | Required predecessor | Only permitted operation |
|---|---|---|
| recovery reviewer | stable contract and eleven frozen inputs | read-only review; create recovery review |
| debt observer | valid recovery review | read-only mismatch observation; create debt observation |
| fixture author / GREEN executor | valid debt observation | create binding v2; create wrapper v2; execute the one exact 20-case command once; create evidence v2 |
| source reviewer | valid evidence v2 | read-only source review; create source-review v2 |
| handoff author | valid source-review v2 | create handoff v3 |
| candidate acceptor | valid handoff v3 | read-only candidate review; create acceptance v3 |
| canonical adopter | valid acceptance v3 and all three canonical paths freshly absent | in one uninterrupted operation create intent v3, canonical source v2, and receipt v3 under section 8; stop after receipt |
| marker author | already-complete valid receipt v3 and full chain | read-only validation; create marker v3 |

The recovery author stops after this contract. The repair implementer receives
no operation because the repaired source is already frozen. No row may borrow
another row's power and no step may be combined across principals.

Every governed JSON contains exactly this 29-member authority object:

```json
{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}
```

All 29 flags are false. The narrow construction operations do not grant runtime,
provider, provider-launch, runner, admission, audit, finding, severity,
confidence, suppression, refutation, release, replay, installation, promotion,
active-head, consumer, production, package, commit, push, cutover, capture,
certification, vector-acceptance, or terminal-negative authority. GREEN is only
the exact closed fixture result. Canonical construction does not activate or
select the source.

## 11. Part-0 genericity and mandatory validation

Every governed JSON contains exactly:

```json
{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}
```

The immutable suite remains the sole oracle. The wrapper and evidence contain no
ecosystem, protocol, provider, contract, instruction, vulnerability, expected-
finding, or semantic-shortcut data. Governance labels and fixture IDs are not
protocol names. No semantic assertion is copied from the repaired source or RED
projection into the wrapper.

Before every edge, a validator MUST:

1. stable-read and verify the immediate predecessor's exact path, size, and
   SHA-256;
2. reject BOM, CR, invalid UTF-8, duplicate keys, noncanonical JSON, missing or
   unknown members, unsafe integers, and any bytes after the single final LF;
3. validate the exact Draft-2020-12 schema and local `$ref` closure, then
   recompute the assigned ID and body formulas;
4. enforce every ordered case/check projection, external identity join, semantic
   count/digest, disposition, role, cumulative principal separation, and the
   exact Part-0/authority objects;
5. reject the malformed v1 binding as an enabling predecessor, any old schema or
   path generation after its terminal branch, any alternate suite/source/wrapper,
   any unregistered path, and any timestamp or content-equality chronology;
6. enforce the complete-candidate triple validation and atomic exclusive
   create-only final publication protocol; and
7. stop at the next independent boundary.

Schema validation alone is insufficient. Artifact existence alone never proves
validity. Content identity never proves a historical creator or physical order.
Failure cannot be downgraded to pending, warning, repair, or reviewer discretion.

## 12. Stop condition

This document stops at definition. Its author MUST NOT create the recovery
review, debt observation, binding v2, wrapper v2, GREEN evidence v2, source
review v2, handoff v3, acceptance v3, intent v3, canonical source, receipt v3,
or marker v3, and MUST NOT execute GREEN. The next possible action is an
independent read-only review of this exact contract identity. Until a passing
recovery review exists, the terminal state is
`CONTRACT_ONLY_PENDING_INDEPENDENT_RECOVERY_REVIEW`; the preserved v1 mismatch
remains terminal provenance debt and every authority flag is false.
