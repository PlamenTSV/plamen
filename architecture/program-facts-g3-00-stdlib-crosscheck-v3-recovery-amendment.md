# Program Facts G3-00 stdlib cross-check v3-r2 recovery amendment

Status: `CONTRACT_ONLY_PENDING_FRESH_INDEPENDENT_V3_R2_RECOVERY_REVIEW`

This is a recovery-of-recovery contract. It closes two independently observable
defects in the failed v2 GREEN construction branch and replaces that branch with
a fresh, create-only v3 namespace. Its r2 transport also removes the reviewed
draft's crash-permanent one-shot namespace, unobservable live-owner distinction,
and self-attested primitive-history defect. It does not validate, repair, delete, rename,
overwrite, quarantine, execute, accept, promote, install, or use either failed
v2 artifact. It does not create fixtures, run GREEN, publish a provider artifact,
or grant runtime authority. The only next operation this document can enable is
an independent read-only review of this exact document.

`MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, and `MAY` have RFC 2119 meanings.
`CJ(x)` is RFC 8785 canonical JSON encoded as strict UTF-8. `CF(x)` is exactly
`CJ(x) || LF`. `SHA-256` returns lowercase hexadecimal. `UTF8(s)` is strict
UTF-8. A stable read is three direct, no-follow, no-alias reads whose complete
bytes and physical identity are equal. No timestamp, file time, directory order,
ambient path, Git state, process ID, or content equality is chronology evidence.

## 0. Exact frozen state and two terminal v2 defects

The following existing identities are immutable inputs:

| Key | Bytes | SHA-256 | Exact path |
|---|---:|---|---|
| `successor_contract` | 121,167 | `4d94fb76c7905971a0ae620d6c74511ef907822eae3d3e32ee00fcb79aea36e9` | `architecture/program-facts-g3-00-stdlib-crosscheck-green-successor-amendment.md` |
| `successor_review` | 15,843 | `b82a0cbf8595e2f7595d0e473363551a041e5e00055073be085f21ec597dc35d` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_GREEN_SUCCESSOR_AMENDMENT_INDEPENDENT_REVIEW.v1.json` |
| `binding_recovery_contract` | 95,837 | `b4daf10559c54e77431b759b1970dd6ca0af7ae18b80301707e41cf568d235a7` | `architecture/program-facts-g3-00-stdlib-crosscheck-binding-recovery-amendment.md` |
| `binding_recovery_review` | 6,510 | `c28a306af3ddad52f6297b84984a78f739e94df51cfd29e8be53d1017ed6fb34` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_BINDING_RECOVERY_AMENDMENT_INDEPENDENT_REVIEW.v1.json` |
| `v1_debt_observation` | 4,554 | `1639028fecf818b0c147dc9d6815e6b946f0af29eec81ad25dd7ca8b8ac76b8f` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_REPAIRED_SUBJECT_BINDING_MISMATCH_OBSERVATION.v1.json` |
| `malformed_binding_v1` | 5,327 | `83326de23beda097387906db349df798f82e8058a04319621092eb7cef471622` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SUBJECT_BINDING.v1.json` |
| `failed_binding_v2` | 7,892 | `9cda8c864715c04f846d5283d52c8fa5fc44e36bd633228966937119acb391ee` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SUBJECT_BINDING.v2.json` |
| `failed_wrapper_v2` | 16,779 | `590ccc697c483c656c5661828cf5ac6f26907da5fca4b941ad853cab444b3656` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_green_v2.py` |
| `transport_amendment` | 53,343 | `e02ae54dd8be9bfeabe6a2eba042710bdef30dd72d7fbf3c1d67bd29db6eed89` | `architecture/program-facts-g3-00-stdlib-crosscheck-transport-totality-amendment.md` |
| `transport_review` | 10,882 | `f4d07e01a52141c9cf56e4c6d884857f64fb22cbdd516e170b5b6451f02171e0` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_INDEPENDENT_REVIEW.v1.json` |
| `red_evidence` | 6,944 | `ffbe065c09b1ea979431a2560e59618f6889c34f544907286ca03e7d33e0c18f` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_RED_EVIDENCE.v1.json` |
| `semantic_suite` | 93,657 | `417e4978fe3c4a4c214a98cdce141d970b009665afead896b09aad7157aadf73` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_semantic_suite_v1.py` |
| `fixture_child` | 2,369 | `72ba62378ca02f02770dc183b4760de8d4ecdc2674faab3d20ccc82694308cb8` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_fixture_child_v1.py` |
| `red_wrapper` | 3,288 | `f7ce4d4153c2058e67686b7459769eb61b494e126b6a6581ad73df3c4e1b9fba` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_red.py` |
| `repaired_source` | 196,712 | `ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py` |
| `pending_handoff` | 12,054 | `e6bb2fa49d8bb7f81d510cc9212532cb3c8ac36ab3781fc2b2e9c48a43fa24e6` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.PENDING.v1.json` |

The accepted RED evidence also fixes the historical pre-repair source at the
same source path as 190,456 bytes with SHA-256
`e3cdd2599cf05d7f0c2b256d45d88e52f04fe15890d74a38bb296be44c1b5fb5`.
That identity is history only and MUST NOT be reconstructed over the repaired
source.

The v2 GREEN evidence path is absent at this boundary:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_GREEN_EVIDENCE.v2.json
```

Its absence is not a pass. A future structural observation performs three
direct no-follow absence checks before and after its read-only inspection. It
MUST NOT execute or re-execute the v2 one-shot command to establish this fact.

### 0.1 Defect V2-D1: governed-object/subject-identity type mismatch

The immutable suite's `_stable_bound_bytes` accepts a binding only when
`set(binding) == {"path","size_bytes","sha256"}`. Every one of its 20 methods
eventually consumes that exact three-field subject identity. The frozen v2
wrapper instead binds the complete governed binding document to
`REPAIRED_BINDING` and calls:

```python
semantic_suite.run_case(case_id, REPAIRED_BINDING)
```

The v2 document has many governed fields and therefore cannot satisfy the
suite's exact three-field subject identity. This is a structural contradiction,
not a test result. The wrapper AST, suite AST, exact file identities, and exact
closed key set prove it without executing the command. The v2 wrapper could not
produce the contract's 20-pass projection as published.

### 0.2 Defect V2-D2: internally unrealizable publication abstraction

The accepted binding-recovery contract required a complete candidate in memory
or an ungoverned staging object, said the staging object was never linked from
or renamed over the final, forbade direct partial final writes, and also required
one generic primitive that atomically made already-complete bytes visible at an
exclusive final name. For ordinary filesystem files, those clauses define no
implementable primitive: direct exclusive final creation exposes a name before
all bytes are written, while atomic complete-candidate namespace publication is
a no-replace rename or link operation. The same contract prohibited both.

The prior executor reported using a hard-link create-new pattern to bridge that
contradiction. The raw stderr/transcript was not retained. Consequently that
historical implementation report, and any reported command stdout/stderr
digests, may appear in the v2 debt observation only under classification
`NON_AUTHORITATIVE_EXECUTOR_REPORT_RAW_TRANSCRIPT_NOT_RETAINED`. It is not proof,
cannot enable a successor, and cannot be promoted by digest equality. The
contract-text contradiction itself is authoritative because the contract bytes
are pinned. The replacement below does not treat any historical namespace
operation as admission evidence.

### 0.3 Terminal treatment

`malformed_binding_v1`, `failed_binding_v2`, and `failed_wrapper_v2` are terminal
provenance debt. They MUST remain byte-for-byte at their exact paths. They MUST
NOT be deleted, overwritten, truncated, patched, renamed, case-normalized,
quarantined, copied into a successor, acknowledged as equal, or used as an
enabling predecessor. The v3 branch may name them only inside the independently
reviewed v2 structural-debt observation. Every later v3 schema excludes them.
No GREEN v2 evidence, source review, handoff, acceptance, intent, canonical
construction, receipt, or marker may ever be backfilled.

## 1. Narrow supersession and unchanged semantic projection

This contract supersedes only the post-v2-debt namespace, the GREEN wrapper's
subject argument, and the prior publication abstraction. It does not change any
transport-totality semantics, source bytes, suite bytes, case meaning, count,
predicate, vector, atom, proof, or RED chronology. The following projection is
exact:

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
GREEN case count                                      20
failed GREEN case count                                0
```

The accepted RED projection remains exactly 16 `RED` plus four
`PASS_UNCHANGED`. No old or failed artifact can be interpreted as a new RED or
GREEN result.

## 2. Deterministic r2 path language, attempt prefix, and counts

### 2.1 Fresh final paths and order

The fresh branch has exactly 15 ordered edges and final paths:

| Edge | Key | Exact final path |
|---:|---|---|
| 1 | `RECOVERY_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_V3_RECOVERY_AMENDMENT_INDEPENDENT_REVIEW.v1.json` |
| 2 | `V2_DEBT_OBSERVATION` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_V2_BINDING_WRAPPER_FAILURE_OBSERVATION.v1.json` |
| 3 | `RECOVERY_FIXTURE_SUITE` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_v3_recovery_fixture_suite_v1.py` |
| 4 | `RECOVERY_RED_WRAPPER` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_v3_recovery_red.py` |
| 5 | `RECOVERY_RED_EVIDENCE` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_V3_RECOVERY_RED_EVIDENCE.v1.json` |
| 6 | `REPAIRED_BINDING_V3` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SUBJECT_BINDING.v3.json` |
| 7 | `GREEN_WRAPPER_V3` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_green_v3.py` |
| 8 | `GREEN_EVIDENCE_V3` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_GREEN_EVIDENCE.v3.json` |
| 9 | `SOURCE_REVIEW_V3` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SOURCE_INDEPENDENT_REVIEW.v3.json` |
| 10 | `HANDOFF_V4` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.v4.json` |
| 11 | `ACCEPTANCE_V4` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANDIDATE_ACCEPTANCE.v4.json` |
| 12 | `CANONICAL_INTENT_V4` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_COPY_INTENT.v4.json` |
| 13 | `CANONICAL_SOURCE_V3` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v3.py` |
| 14 | `ADOPTION_RECEIPT_V4` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_RECEIPT.v4.json` |
| 15 | `ADOPTION_MARKER_V4` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_ADOPTION_MARKER.v4.json` |

The new contract path is exactly:

```text
architecture/program-facts-g3-00-stdlib-crosscheck-v3-recovery-amendment.md
```

### 2.2 Inert lease and exact monotonic attempt namespace

For each edge, let `parent` be the exact final path without its last segment,
`nn` its two-digit decimal ordinal, and `key` its lowercase edge key. Define:

```text
stem       = ".__pfg3xv3r2_" || nn || "_" || key
lease      = parent || "/" || stem || ".lease"
attempt(a) = parent || "/" || stem || ".attempt." || Z20(a) || "."
```

`Z20(a)` is the unique 20-digit, zero-padded decimal encoding of integer
`0 <= a <= 99999999999999999999`. An attempt namespace contains exactly these
five leaves:

```text
attempt(a) + "attempt.json"
attempt(a) + "payload.stage"
attempt(a) + "publish-arm.json"
attempt(a) + "completion.json"
attempt(a) + "debt.json"
```

The zero-byte lease is an inert kernel mutual-exclusion object. It never carries
semantic or transport evidence and never enables a successor. It is opened
no-follow as a regular, singly linked file and locked with the host's exclusive
kernel file-lock operation. A crash merely releases the kernel lock. Creating or
reopening the exact empty lease is not content-equality adoption; any nonempty,
linked, aliased, or nonregular lease blocks that edge for human review.

Attempt discovery is exact-prefix probing under the held lease: start at ordinal
zero and open only the five formula-derived leaves for each successive ordinal.
There is no directory enumeration, glob, wildcard, basename search, newest-file
selection, timestamp, process ID, UUID, random suffix, alternate root, cleanup,
quarantine, or invented recovery name. Ordinals form one contiguous prefix. A
gap is the next unused ordinal; a later collision is handled when that exact
ordinal becomes current and never makes an earlier object authoritative.

Each record is create-only and append-only. If a crash leaves bytes that are an
exact prefix of already determined canonical bytes, the missing suffix may be
appended and durably flushed. Bytes are never overwritten, truncated, deleted,
renamed between attempts, or accepted merely because content matches. Any
non-prefix mismatch may advance only after a formula-valid `debt.json` durably
binds the stable observed identity and three current target-absence observations.
If the semantic final exists, no mismatch may advance.
If ordinal `99999999999999999999` has valid debt and no enabling completion,
the edge becomes `ATTEMPT_ORDINAL_EXHAUSTED_HUMAN_REVIEW`; arithmetic never
wraps and no wider or alternate suffix is invented.

The static path set contains exactly 48 formula-distinct paths:

```text
17 predecessor/debt paths, including the required-absent GREEN-v2 evidence path
 1 v3-r2 recovery-contract path
15 unchanged semantic final paths
15 inert lease paths
--------------------------------
48 static paths
```

For attempt-prefix lengths `A[1]..A[15]`, the exact materializable path count is
`48 + 5 * SUM(A[i])`. A validator derives that set from the 15 exact rows and
each contiguous ordinal prefix; it does not scan. The repaired-source path has
two permitted historical/current content identities and the absent GREEN-v2
path has none. Identity validation is therefore by exact path, size, digest,
semantic role, attempt ordinal, and record type—not by a stale fixed union count.

## 3. Canonical identities, formulas, and published references

Every governed JSON rejects duplicate keys, unknown members, unsafe integers,
non-UTF-8, BOM, CR, noncanonical escaping, non-finite numbers, and trailing
bytes other than one LF. Each object and array is recursively closed.

For a semantic JSON artifact with fields `<id>` and `<body_sha256>`, let
`identity_body` omit exactly those two fields:

```text
<id> = <prefix> || SHA-256(CJ({domain:<DOMAIN>,artifact:identity_body}))[0:32]
<body_sha256> = SHA-256(CJ(full_object_without_only_<body_sha256>))
file_bytes = CF(full_object)
```

| Artifact | ID / prefix | Body field | Domain |
|---|---|---|---|
| recovery review | `review_id` / `pfg3xrr-` | `review_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_V3_RECOVERY_REVIEW_V1` |
| v2 debt observation | `observation_id` / `pfg3xdo-` | `observation_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_V2_FAILURE_OBSERVATION_V1` |
| recovery RED evidence | `evidence_id` / `pfg3xre-` | `evidence_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_V3_RECOVERY_RED_EVIDENCE_V1` |
| repaired binding v3 | `binding_id` / `pfg3xrb-` | `binding_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_REPAIRED_SUBJECT_BINDING_V3` |
| GREEN evidence v3 | `evidence_id` / `pfg3xge-` | `evidence_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_GREEN_EVIDENCE_V3` |
| source review v3 | `review_id` / `pfg3xsr-` | `review_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_REPAIRED_SOURCE_REVIEW_V3` |
| handoff v4 | `handoff_id` / `pfg3xsh-` | `handoff_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_HANDOFF_V4` |
| acceptance v4 | `acceptance_id` / `pfg3xca-` | `acceptance_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_ACCEPTANCE_V4` |
| canonical intent v4 | `intent_id` / `pfg3xci-` | `intent_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_CANONICAL_INTENT_V4` |
| adoption receipt v4 | `receipt_id` / `pfg3xar-` | `receipt_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_ADOPTION_RECEIPT_V4` |
| adoption marker v4 | `marker_id` / `pfg3xam-` | `marker_body_sha256` | `PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_ADOPTION_MARKER_V4` |

Each r2 attempt, durable publish arm, completion, and debt record uses the same
calculus with prefixes `pfg3xat-`, `pfg3xpa-`, `pfg3xpc-`, and `pfg3xpd-`; body
fields are `attempt_body_sha256`, `arm_body_sha256`,
`completion_body_sha256`, and `debt_body_sha256`; and domains are respectively
`PROGRAM_FACTS_G3_00_V3_R2_ATTEMPT_V1::<EDGE_KEY>::<Z20>`,
`PROGRAM_FACTS_G3_00_V3_R2_PUBLISH_ARM_V1::<EDGE_KEY>::<Z20>`,
`PROGRAM_FACTS_G3_00_V3_R2_COMPLETION_V1::<EDGE_KEY>::<Z20>`, and
`PROGRAM_FACTS_G3_00_V3_R2_DEBT_V1::<EDGE_KEY>::<Z20>`.

A downstream reference to a fresh artifact is exactly:

```json
{"artifact":{"path":"registered final","size_bytes":0,"sha256":"64 lowercase hex"},"attempt_ordinal":"00000000000000000000","completion_grade":"PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION","publication_arm":{"path":"formula-derived publish-arm.json","size_bytes":0,"sha256":"64 lowercase hex"},"publication_completion":{"path":"formula-derived completion.json","size_bytes":0,"sha256":"64 lowercase hex"}}
```

All identities and the grade are externally derived after completion. A fresh
artifact is not a predecessor unless its attempt and arm are independently
schema/formula-valid, the threat-model boundary validates, the arm durably
predates materialization under the exclusive lease, the final exact bytes and
physical-identity joins validate, the completion marker is the last created
record, the closed namespace-poststate digest recomputes from its exact bound
preimage, and the immediate downstream discriminator revalidates the semantic
artifact itself. Only
`PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION` can enable;
`POSTCONDITION_ONLY` never can. The single enabling grade describes the
normalized arm-bound final poststate, not the uninterrupted or recovery branch
that observed it, and does not prove which internal filesystem primitive ran.
A completion is transport evidence only. It never
certifies semantic truth and cannot self-certify its author's artifact.

## 4. Principal roster and generator/discriminator separation

The accepted prior roster is reproduced exactly from valid predecessors:

1. `author:codex/green-successor-contract` — `GREEN successor contract author`;
2. `reviewer:codex/green-successor-contract-review` — `Independent GREEN successor contract reviewer`;
3. `author:codex/binding-recovery-contract` — `Binding-recovery amendment author`;
4. `reviewer:codex/binding-recovery-review` — `Independent binding-recovery amendment reviewer`;
5. `observer:codex/binding-mismatch-debt` — `Independent binding-mismatch and provenance-debt observer`;
6. `executor:codex/crosscheck-green-fixture` — `Independent repaired-subject fixture author and GREEN executor`;
7. `implementer:codex/crosscheck-transport-repair` — `Transport-totality repair implementer`.

The fresh chain adds exactly these nine roles in order:

8. `V3 recovery amendment author`;
9. `Independent V3 recovery amendment reviewer`;
10. `Independent V2 structural-failure and provenance-debt observer`;
11. `Independent V3 recovery fixture author and GREEN executor`;
12. `Independent V3 repaired-source reviewer`;
13. `V4 successor handoff author`;
14. `Independent V4 candidate acceptor for canonical construction only`;
15. `Independent V4 canonical-copy adopter`;
16. `Independent V4 canonical-adoption validator and marker author`.

The nine fresh principal IDs are declared by the first artifact that binds each
role. All 16 cumulative IDs are pairwise distinct and are also distinct from
`reviewer:openai-codex/g3-00-crosscheck-transport-totality-review-20260809`
and `executor:openai-codex/g3-00-crosscheck-transport-totality-red-fixtures`.
Changing a role label, process, session, or model does not establish a new
principal. Organization equality does not defeat independence.

The v3 author stops after this document. The v3 reviewer has no later role. The
v2 observer has no later role. The v3 fixture author may create edges 3-8 and
execute only the exact fixture commands, but cannot review or accept its own
outputs. The source reviewer, handoff author, acceptor, adopter, and marker
author are successively distinct. The marker author is distinct from the
adopter. No semantic generator writes its discriminator. The edge owner supplies
the fully determined candidate and owner identity but cannot write the protected
transport namespace directly. The trusted driver alone creates attempt, stage,
arm, completion, or debt leaves under the lease. Completion grades are derived
from the valid threat-model boundary and observable filesystem postconditions;
none confers semantic acceptance or historical-execution authority.

## 5. Common Draft-2020-12 schema

All schemas are registered in memory under their exact `$id`. Network resolution
and schema-file materialization are forbidden. The common resource is:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json",
  "$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/validation":true},
  "$defs":{
    "hex64":{"type":"string","pattern":"^[0-9a-f]{64}$","minLength":64,"maxLength":64},
    "z20":{"type":"string","pattern":"^[0-9]{20}$","minLength":20,"maxLength":20},
    "safe_path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},
    "file_identity":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/safe_path"},"size_bytes":{"type":"integer","minimum":0,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex64"}}},
    "completion_grade":{"enum":["PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION","POSTCONDITION_ONLY"]},
    "published_ref":{"type":"object","additionalProperties":false,"required":["artifact","attempt_ordinal","completion_grade","publication_arm","publication_completion"],"properties":{"artifact":{"$ref":"#/$defs/file_identity"},"attempt_ordinal":{"$ref":"#/$defs/z20"},"completion_grade":{"const":"PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION"},"publication_arm":{"$ref":"#/$defs/file_identity"},"publication_completion":{"$ref":"#/$defs/file_identity"}}},
    "principal":{"type":"object","additionalProperties":false,"required":["principal_id","organization","role"],"properties":{"principal_id":{"type":"string","minLength":12,"maxLength":256,"pattern":"^(author|reviewer|observer|executor|implementer|acceptor|adopter):[a-z0-9-]+/[a-z0-9-]+$"},"organization":{"type":"string","minLength":1,"maxLength":256},"role":{"enum":["GREEN successor contract author","Independent GREEN successor contract reviewer","Binding-recovery amendment author","Independent binding-recovery amendment reviewer","Independent binding-mismatch and provenance-debt observer","Independent repaired-subject fixture author and GREEN executor","Transport-totality repair implementer","V3 recovery amendment author","Independent V3 recovery amendment reviewer","Independent V2 structural-failure and provenance-debt observer","Independent V3 recovery fixture author and GREEN executor","Independent V3 repaired-source reviewer","V4 successor handoff author","Independent V4 candidate acceptor for canonical construction only","Independent V4 canonical-copy adopter","Independent V4 canonical-adoption validator and marker author"]}}},
    "authority":{"type":"object","const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"execution_trace_attestation":false,"finding":false,"historical_primitive_proof":false,"host_compromise_tolerance":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}},
    "part0":{"type":"object","const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},
    "semantic_projection":{"type":"object","const":{"atom_set_preimage_bytes":5102113,"atom_set_sha256":"286aa2a4477aa46f632c590020d3a49e1e147cef0194471d9893f8898a903915","coverage_atom_count":21578,"green_case_count":20,"impossibility_proof_count":891,"impossibility_proof_preimage_bytes":338716,"impossibility_proof_sha256":"0103ea85b210693908f2c7fb7368ca8c823afd959da6e1ae3d65d3563bf746c3","keyword_occurrence_count":7517,"per_subject_atom_counts":[1879,1812,2950,2283,2881,1445,1959,2018,1436,1160,992,763],"semantic_suite_byte_identical":true,"subject_schema_count":12,"transport_and_zero_atom_totality_only":true}},
    "physical_identity":{"oneOf":[{"type":"object","additionalProperties":false,"required":["kind","volume_serial_number","file_id_128","number_of_links"],"properties":{"kind":{"const":"WINDOWS_FILE_ID_128"},"volume_serial_number":{"type":"string","pattern":"^[0-9a-f]{16}$","minLength":16,"maxLength":16},"file_id_128":{"type":"string","pattern":"^[0-9a-f]{32}$","minLength":32,"maxLength":32},"number_of_links":{"type":"integer","minimum":1,"maximum":9007199254740991}}},{"type":"object","additionalProperties":false,"required":["kind","st_dev","st_ino","st_nlink"],"properties":{"kind":{"enum":["LINUX_STAT","MACOS_STAT"]},"st_dev":{"type":"integer","minimum":0,"maximum":9007199254740991},"st_ino":{"type":"integer","minimum":0,"maximum":9007199254740991},"st_nlink":{"type":"integer","minimum":1,"maximum":9007199254740991}}}]},
    "threat_model":{"type":"object","const":{"consumers_require_valid_completion":true,"exclusive_kernel_lease_required":true,"filesystem_honors_declared_local_durability":true,"host_kernel_compromised":false,"namespace_root_protected_from_untrusted_writers":true,"private_stage_names_nonconsumable":true,"single_trusted_driver_writer":true,"trusted_driver_enforces_transition":true}},
    "platform":{"oneOf":[{"const":{"admission_authority":"NONE","host":"WINDOWS","parent_relative":true,"preferred_api":"SetFileInformationByHandle/FileRenameInfoEx","preferred_flag":"FILE_RENAME_REPLACE_IF_EXISTS_UNSET"}},{"const":{"admission_authority":"NONE","host":"LINUX","parent_relative":true,"preferred_api":"renameat2","preferred_flag":"RENAME_NOREPLACE"}},{"const":{"admission_authority":"NONE","host":"MACOS","parent_relative":true,"preferred_api":"renameatx_np","preferred_flag":"RENAME_EXCL"}}]},
    "durable_arm_protocol":{"oneOf":[{"const":{"host":"WINDOWS","ordered_checkpoints":["ARM_COMPLETE","FlushFileBuffers/arm","FlushFileBuffers/parent","ARM_STABLE_REREAD","MATERIALIZATION_MAY_BEGIN"]}},{"const":{"host":"LINUX","ordered_checkpoints":["ARM_COMPLETE","fsync/armfd","fsync/parentfd","ARM_STABLE_REREAD","MATERIALIZATION_MAY_BEGIN"]}},{"const":{"host":"MACOS","ordered_checkpoints":["ARM_COMPLETE","fcntl/F_FULLFSYNC/armfd","fcntl/F_FULLFSYNC/parentfd","ARM_STABLE_REREAD","MATERIALIZATION_MAY_BEGIN"]}}]},
    "completion_protocol":{"oneOf":[{"const":{"host":"WINDOWS","ordered_checkpoints":["OBSERVABLE_POSTSTATE_VALID","FlushFileBuffers/parent","THREE_FINAL_READS","THREE_STAGE_ABSENCE_OBSERVATIONS","COMPLETION_CREATE_ONLY","FlushFileBuffers/completion","FlushFileBuffers/parent","DOWNSTREAM_REVALIDATION"]}},{"const":{"host":"LINUX","ordered_checkpoints":["OBSERVABLE_POSTSTATE_VALID","fsync/parentfd","THREE_FINAL_READS","THREE_STAGE_ABSENCE_OBSERVATIONS","COMPLETION_CREATE_ONLY","fsync/completionfd","fsync/parentfd","DOWNSTREAM_REVALIDATION"]}},{"const":{"host":"MACOS","ordered_checkpoints":["OBSERVABLE_POSTSTATE_VALID","fcntl/F_FULLFSYNC/parentfd","THREE_FINAL_READS","THREE_STAGE_ABSENCE_OBSERVATIONS","COMPLETION_CREATE_ONLY","fcntl/F_FULLFSYNC/completionfd","fcntl/F_FULLFSYNC/parentfd","DOWNSTREAM_REVALIDATION"]}}]},
    "absence_observation":{"type":"object","additionalProperties":false,"required":["ordinal","target","parent_physical_identity","result"],"properties":{"ordinal":{"type":"integer","minimum":1,"maximum":3},"target":{"$ref":"#/$defs/safe_path"},"parent_physical_identity":{"$ref":"#/$defs/physical_identity"},"result":{"const":"ABSENT_NOFOLLOW_EXACT_LEAF"}}},
    "namespace_poststate_preimage":{"type":"object","additionalProperties":false,"required":["domain","edge_ordinal","edge_key","attempt_ordinal","publish_arm","lease_physical_identity","planned_final","final_physical_identity","final_link_count","armed_stage_physical_identity","armed_stage_link_count","stage_path","stage_state","stage_absence_observations","parent_physical_identity","volume_join","poststate_reads","stable_read_count","threat_model","normalized_poststate"],"properties":{"domain":{"const":"PROGRAM_FACTS_G3_V3_NAMESPACE_POSTSTATE_V1"},"edge_ordinal":{"type":"integer","minimum":1,"maximum":15},"edge_key":{"enum":["RECOVERY_REVIEW","V2_DEBT_OBSERVATION","RECOVERY_FIXTURE_SUITE","RECOVERY_RED_WRAPPER","RECOVERY_RED_EVIDENCE","REPAIRED_BINDING_V3","GREEN_WRAPPER_V3","GREEN_EVIDENCE_V3","SOURCE_REVIEW_V3","HANDOFF_V4","ACCEPTANCE_V4","CANONICAL_INTENT_V4","CANONICAL_SOURCE_V3","ADOPTION_RECEIPT_V4","ADOPTION_MARKER_V4"]},"attempt_ordinal":{"$ref":"#/$defs/z20"},"publish_arm":{"$ref":"#/$defs/file_identity"},"lease_physical_identity":{"$ref":"#/$defs/physical_identity"},"planned_final":{"$ref":"#/$defs/file_identity"},"final_physical_identity":{"$ref":"#/$defs/physical_identity"},"final_link_count":{"const":1},"armed_stage_physical_identity":{"$ref":"#/$defs/physical_identity"},"armed_stage_link_count":{"const":1},"stage_path":{"$ref":"#/$defs/safe_path"},"stage_state":{"const":"ABSENT_NOFOLLOW_EXACT_LEAF"},"stage_absence_observations":{"type":"array","minItems":3,"maxItems":3,"items":{"$ref":"#/$defs/absence_observation"}},"parent_physical_identity":{"$ref":"#/$defs/physical_identity"},"volume_join":{"type":"object","additionalProperties":false,"required":["parent","stage","target_parent"],"properties":{"parent":{"$ref":"#/$defs/physical_identity"},"stage":{"$ref":"#/$defs/physical_identity"},"target_parent":{"$ref":"#/$defs/physical_identity"}}},"poststate_reads":{"type":"array","minItems":3,"maxItems":3,"items":{"$ref":"#/$defs/file_identity"}},"stable_read_count":{"const":3},"threat_model":{"$ref":"#/$defs/threat_model"},"normalized_poststate":{"const":"ARM_BOUND_FINAL_ONLY"}}},
    "publication_requirements":{"type":"object","const":{"append_only_exact_prefix_resume":true,"completion_marker_last":true,"content_equality_adoption":false,"debt_required_before_advance":true,"direct_final_write":false,"directory_scan":false,"implementation_primitive_is_admission_evidence":false,"immutable_final_after_completion":true,"monotonic_zero_padded_attempts":true,"no_overwrite_of_pre_arm_final":true,"parent_and_stage_same_volume":true,"parent_handle_retained":true,"pathless_identity_preserved":true,"postcondition_only_enables":false,"private_stage_alias_nonconsumable":true,"private_stage_alias_reconciliation_only":true,"protected_namespace_required":true,"reconciliation_history_identity_critical":false,"silent_backfill":false,"single_canonical_enabling_completion":true,"stage_and_final_same_parent":true,"unsupported_host_fails_before_attempt_paths_touched":true}}
  }
}
```

Semantic validation restricts every `safe_path` to section 0, the exact 15
semantic finals, the 15 leases, or a formula-derived member of a contiguous
attempt prefix. There is no external execution-identity root.
The regex is not authority to introduce a new path.
`physical_identity` is never derived from a pathname alone. Windows obtains
`FILE_ID_INFO` and link count from an open handle. Its unsigned 64-bit
`VolumeSerialNumber` is encoded losslessly as exactly 16 lowercase hexadecimal
digits, most-significant nibble first, with leading zeroes retained; equivalently,
`format(native_uint64, "016x")`. It is never emitted as a JSON number or decimal
string. `FileId.Identifier` remains the exact 16 returned bytes rendered as 32
lowercase hexadecimal digits, and link count remains an integer. Decimal,
uppercase, signed, prefixed, short, long, truncated, or narrowed encodings are
invalid even if they would compare equal after a lossy conversion. Linux and
macOS continue to obtain the unchanged `st_dev`, `st_ino`, and `st_nlink`
integer fields from `fstat` on an open file descriptor. The durable-arm stage and every
enabling final MUST have link count exactly one. Recovery may observe exactly
two private names for the same armed file object, but that state is nonenabling
until the stage alias is deterministically removed and the final again has link
count one. The held parent directory may have a larger native link count, which
is recorded without being confused with file aliasing. A digest is not a
substitute for physical identity.

## 6. Recoverable r2 complete-candidate publication protocol

### 6.1 Explicit threat model and evidence authority

This transport is sound only inside the exact common-schema threat model. The
driver is trusted to enforce this contract; the host kernel is not compromised;
the repository root and formula-derived namespace are protected from untrusted
writers; one driver owns the exact kernel lease; and consumers refuse every
semantic final lacking a valid last-written completion. A filesystem that lies
about the declared local durability or physical-identity operations is outside
the model. Any failed threat-model predicate stops this edge at nonenabling debt
or human review; it is never repaired by an artifact assertion.

The trusted-driver boundary includes lossless host-identity capture. On Windows,
the driver and every independent validator must read the native unsigned 64-bit
volume serial from each retained handle and independently derive its canonical
16-lowercase-hex representation before comparing or recording it. A runtime,
FFI, serializer, or adapter that first coerces that value through an I-JSON,
floating-point, signed, 32-bit, or other narrowing representation is outside the
valid boundary and must fail before an enabling record is written.

The evidence authority is deliberately narrower than the implementation. A
valid chain establishes only
`PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION`: a durable arm
recorded exact target absence and a singly linked staged object under the
protected lease, and the admitted final is the same physical object with the
exact planned bytes after the stage name is absent. The grade and its bytes do
not distinguish uninterrupted observation, final-only restart, or private-alias
reconciliation. They do not establish which syscall, library, runtime,
executable, instruction sequence, or intermediate namespace operation produced
that state. No command digest, callback result, process identity, or source
review can raise that ceiling.

The protected-root and single-writer predicates are load-bearing. They make the
three arm-time target-absence observations stable against an untrusted creator
until the driver changes the namespace, so a pre-arm existing final cannot be
overwritten. They also make every transient stage/final double-name state
private and nonconsumable. A deployment that cannot enforce those predicates
does not qualify for the enabling grade.

Before creating an attempt leaf, the trusted driver:

1. derives the exact lease and current five-leaf prefix without scanning,
   acquires the inert kernel lease, and retains it through completion or debt;
2. stable-opens the exact protected parent and retains its handle/descriptor;
3. rejects symlink, junction, reparse, mount, case/Unicode, alternate-stream, or
   nonregular ambiguity at every formula-derived name;
4. requires one local filesystem/volume for parent, stage, and final;
5. validates the exact threat-model object and the host implementation-preference
   profile; and
6. fixes each canonical record's complete bytes after its required physical
   observations exist and before writing that record's first byte.

### 6.2 Implementation preferences are not admission facts

The preferred Windows implementation uses parent-relative
`SetFileInformationByHandle(FileRenameInfoEx)` with
`FILE_RENAME_REPLACE_IF_EXISTS` unset. The preferred Linux implementation uses
parent-relative `renameat2(...,RENAME_NOREPLACE)`. The preferred macOS
implementation uses parent-relative `renameatx_np(...,RENAME_EXCL)`; there is
no `renamex_np` preference. Each implementation is separately reviewed and
tested for collisions, same-volume behavior, barriers, and crash seams.

Those choices reduce implementation risk but are not evidence fields and do not
select an enabling grade. The validator never infers a historical primitive
from the final inode, a return code, source bytes, or an implementation label.
An implementation may use another reviewed local identity-preserving technique
inside the protected namespace. Its admission result is identical only if the
observable contract below holds. No implementation may overwrite, mutate, or
delete a pre-arm final, write partial bytes directly to the semantic final,
adopt an ambient equal file, or mutate an immutable completed final.

The durability preference is: fully flush the staged candidate; after the arm is
complete, flush the arm and its parent and stable-reread the arm; perform the
private materialization; then flush the parent again before poststate reads.
Windows uses `FlushFileBuffers`, Linux uses `fsync`, and macOS requires
`fcntl(F_FULLFSYNC)` where declared. If the host/filesystem cannot honor the
declared barriers and pathless identity observations, it is unsupported before
materialization. The arm stores the prospective host protocol, not a claimed
historical trace.

### 6.3 Attempt, durable arm, materialization, and completion

Windows creates a current leaf with `CreateFileW(...,CREATE_NEW)` plus
`FILE_FLAG_OPEN_REPARSE_POINT` and resumes it with `OPEN_EXISTING` without
truncation. Linux/macOS use same-parent
`openat(...,O_CREAT|O_EXCL|O_NOFOLLOW)` and a nontruncating append open for a
verified prefix. The held lease excludes a concurrent appender; pre/post handle
identity must remain stable.

Under that lease, the trusted driver performs only the next deterministic
state-machine action:

1. append or exact-prefix resume canonical `attempt.json`, binding the
   candidate, predecessors, parent, threat model, host preference, and owner;
2. append or exact-prefix resume `payload.stage`, durably flush it, read it
   three times, and capture its singly linked pathless identity;
3. observe the exact semantic final absent three times through the retained
   parent;
4. create or exact-prefix resume `publish-arm.json`; bind its own pathless
   identity, the attempt, candidate, parent/stage identities, target-absence
   observations, same-volume join, threat model, and durability protocol; flush
   arm and parent and stable-reread the complete arm before materialization;
5. materialize inside the protected namespace while retaining the lease. The
   internal primitive is deliberately outside artifact authority;
6. if recovery observes both stage and final as the same armed physical object
   with exactly two links, treat both names as private and nonenabling, remove
   only the formula-derived stage alias, flush the parent, and re-observe. Any
   different identity, unexpected link count, or failed reconciliation is
   nonenabling debt or human review. The entry branch and reconciliation history
   are advisory only and never enter completion, preimage, digest, ID, or body
   bytes;
7. require the stage absent three times, the final singly linked, the final
   physical identity equal to the armed stage identity, three exact planned-byte
   reads, and unchanged parent/volume; construct the one exact section-6.4
   normalized namespace-poststate preimage and digest from the reopened arm and
   those observations, without any branch selector. Only then create
   `completion.json` as the last record, durably flush it and its parent, and
   revalidate the complete chain; or
8. if the final remains absent and a mismatch or unsupported state prevents
   progress, append/resume formula-valid nonenabling `debt.json` before moving
   to the next ordinal. A final-present ambiguity never advances.

The completion marker is create-only and immutable. Its absence makes the
semantic final nonconsumable even when the final bytes and identity look right.
Its presence does not prove an internal execution history: a downstream
discriminator independently rechecks the arm, threat boundary, normalized
final/stage poststate, canonical completion bytes, completion-last rule, and
semantic bytes.

Every newly created attempt leaf is followed by a parent-directory barrier and
every appended suffix by the host file barrier. Losing power yields no name, a
resumable exact prefix, a durable arm with a classifiable namespace poststate,
or a valid last-written completion—never an inferred full record.

The exact r2 record schemas are:
```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_v3_r2_attempt.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","attempt_id","edge_ordinal","edge_key","attempt_ordinal","record_paths","final_plan","owner","parent_physical_identity","threat_model","platform","predecessor_publications","advance_policy","part_0_genericity","authority_ceiling","publication_requirements","attempt_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_v3_r2_attempt.v1"},"attempt_id":{"type":"string","pattern":"^pfg3xat-[0-9a-f]{32}$"},"edge_ordinal":{"type":"integer","minimum":1,"maximum":15},"edge_key":{"enum":["RECOVERY_REVIEW","V2_DEBT_OBSERVATION","RECOVERY_FIXTURE_SUITE","RECOVERY_RED_WRAPPER","RECOVERY_RED_EVIDENCE","REPAIRED_BINDING_V3","GREEN_WRAPPER_V3","GREEN_EVIDENCE_V3","SOURCE_REVIEW_V3","HANDOFF_V4","ACCEPTANCE_V4","CANONICAL_INTENT_V4","CANONICAL_SOURCE_V3","ADOPTION_RECEIPT_V4","ADOPTION_MARKER_V4"]},"attempt_ordinal":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/z20"},"record_paths":{"type":"object","additionalProperties":false,"required":["attempt","payload_stage","publish_arm","completion","debt"],"properties":{"attempt":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/safe_path"},"payload_stage":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/safe_path"},"publish_arm":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/safe_path"},"completion":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/safe_path"},"debt":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/safe_path"}}},"final_plan":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"owner":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"parent_physical_identity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"},"threat_model":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/threat_model"},"platform":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/platform"},"predecessor_publications":{"type":"array","minItems":0,"maxItems":20,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"}},"advance_policy":{"const":"ADVANCE_ONLY_AFTER_FORMULA_VALID_DEBT_AND_THREE_FINAL_ABSENCE_OBSERVATIONS"},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"attempt_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}}
```
```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_v3_r2_publish_arm.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","arm_id","edge_ordinal","edge_key","attempt_ordinal","attempt","payload_stage","planned_final","lease_physical_identity","arm_physical_identity","parent_physical_identity","stage_physical_identity","target_absence_observations","volume_join","threat_model","platform","arm_protocol","owner","part_0_genericity","authority_ceiling","publication_requirements","arm_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_v3_r2_publish_arm.v1"},"arm_id":{"type":"string","pattern":"^pfg3xpa-[0-9a-f]{32}$"},"edge_ordinal":{"type":"integer","minimum":1,"maximum":15},"edge_key":{"type":"string","minLength":3,"maxLength":64},"attempt_ordinal":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/z20"},"attempt":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"payload_stage":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"planned_final":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"lease_physical_identity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"},"arm_physical_identity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"},"parent_physical_identity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"},"stage_physical_identity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"},"target_absence_observations":{"type":"array","minItems":3,"maxItems":3,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/absence_observation"}},"volume_join":{"type":"object","additionalProperties":false,"required":["parent","stage","target_parent"],"properties":{"parent":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"},"stage":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"},"target_parent":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"}}},"threat_model":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/threat_model"},"platform":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/platform"},"arm_protocol":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/durable_arm_protocol"},"owner":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"arm_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}}
```
```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_v3_r2_completion.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","completion_id","edge_ordinal","edge_key","attempt_ordinal","attempt","publish_arm","final_artifact","parent_physical_identity","stage_physical_identity","final_physical_identity","stage_absence_observations","threat_model","platform","completion_grade","observation_class","materialization_observation","poststate_reads","completion_protocol","completion_marker_rule","owner","disposition","part_0_genericity","authority_ceiling","publication_requirements","completion_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_v3_r2_completion.v1"},"completion_id":{"type":"string","pattern":"^pfg3xpc-[0-9a-f]{32}$"},"edge_ordinal":{"type":"integer","minimum":1,"maximum":15},"edge_key":{"type":"string","minLength":3,"maxLength":64},"attempt_ordinal":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/z20"},"attempt":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"publish_arm":{"oneOf":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},{"const":{"status":"ABSENT_OR_INVALID"}}]},"final_artifact":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"parent_physical_identity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"},"stage_physical_identity":{"oneOf":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"},{"const":{"status":"UNOBSERVED"}}]},"final_physical_identity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"},"stage_absence_observations":{"type":"array","minItems":3,"maxItems":3,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/absence_observation"}},"threat_model":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/threat_model"},"platform":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/platform"},"completion_grade":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/completion_grade"},"observation_class":{"enum":["NORMALIZED_ARM_BOUND_FINAL_POSTSTATE","UNBOUND_POSTCONDITION"]},"materialization_observation":{"oneOf":[{"type":"object","additionalProperties":false,"required":["mode","armed_stage_identity","final_identity","namespace_poststate_preimage","namespace_poststate_sha256"],"properties":{"mode":{"const":"NORMALIZED_ARM_BOUND_FINAL_POSTSTATE"},"armed_stage_identity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"},"final_identity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"},"namespace_poststate_preimage":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/namespace_poststate_preimage"},"namespace_poststate_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}},{"type":"object","additionalProperties":false,"required":["mode","reason"],"properties":{"mode":{"const":"POSTCONDITION"},"reason":{"enum":["MISSING_OR_INVALID_ARM","THREAT_MODEL_BOUNDARY_INVALID","AMBIGUOUS_CREATOR","IDENTITY_MISMATCH","PRE_ARM_FINAL","PROTECTED_NAMESPACE_VIOLATION","POSTSTATE_INCOMPLETE"]}}}]},"poststate_reads":{"type":"array","minItems":3,"maxItems":3,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"}},"completion_protocol":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/completion_protocol"},"completion_marker_rule":{"const":"CREATE_ONLY_LAST_AFTER_OBSERVABLE_POSTSTATE_VALIDATION"},"owner":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"disposition":{"const":"OBSERVABLE_TRANSPORT_POSTSTATE_NOT_EXECUTION_TRACE_NOT_SEMANTIC_CERTIFICATION"},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"completion_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}},"allOf":[{"if":{"properties":{"completion_grade":{"const":"PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION"}}},"then":{"properties":{"publish_arm":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"stage_physical_identity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/physical_identity"},"observation_class":{"const":"NORMALIZED_ARM_BOUND_FINAL_POSTSTATE"},"materialization_observation":{"properties":{"mode":{"const":"NORMALIZED_ARM_BOUND_FINAL_POSTSTATE"},"namespace_poststate_preimage":{"properties":{"normalized_poststate":{"const":"ARM_BOUND_FINAL_ONLY"}}}}}}}},{"if":{"properties":{"completion_grade":{"const":"POSTCONDITION_ONLY"}}},"then":{"properties":{"observation_class":{"const":"UNBOUND_POSTCONDITION"},"materialization_observation":{"properties":{"mode":{"const":"POSTCONDITION"}}}}}}]}
```

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_v3_r2_debt.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","debt_id","edge_ordinal","edge_key","attempt_ordinal","attempt","reason","observed_objects","final_absence_observations","advance_disposition","owner","part_0_genericity","authority_ceiling","publication_requirements","debt_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_v3_r2_debt.v1"},"debt_id":{"type":"string","pattern":"^pfg3xpd-[0-9a-f]{32}$"},"edge_ordinal":{"type":"integer","minimum":1,"maximum":15},"edge_key":{"type":"string","minLength":3,"maxLength":64},"attempt_ordinal":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/z20"},"attempt":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"reason":{"enum":["NONPREFIX_RECORD_BYTES","CANDIDATE_MISMATCH","THREAT_MODEL_BOUNDARY_INVALID","ARM_PROTOCOL_INVALID","UNSUPPORTED_PROFILE","STAGE_MISSING_WITH_FINAL_ABSENT","AMBIGUOUS_PREPUBLICATION_STATE","PRIVATE_ALIAS_RECONCILIATION_FAILED","PROTECTED_NAMESPACE_VIOLATION","FINAL_PRESENT_NONENABLING","COMPLETION_MISMATCH","ATTEMPT_ORDINAL_EXHAUSTED"]},"observed_objects":{"type":"array","minItems":1,"maxItems":5,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"}},"final_absence_observations":{"type":"array","minItems":0,"maxItems":3,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/absence_observation"}},"advance_disposition":{"enum":["FORMULA_VALID_DEBT_FINAL_ABSENT_ADVANCE_ONE","FINAL_PRESENT_OR_UNPROVEN_DO_NOT_ADVANCE","ORDINAL_EXHAUSTED_DO_NOT_ADVANCE"]},"owner":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"debt_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}},"allOf":[{"if":{"properties":{"advance_disposition":{"const":"FORMULA_VALID_DEBT_FINAL_ABSENT_ADVANCE_ONE"}}},"then":{"properties":{"final_absence_observations":{"minItems":3,"maxItems":3}}}}]}
```

For stage identity, `path` is the formula-derived `payload.stage`; for
`planned_final` and `final_artifact`, it is the unchanged edge final. Semantic
validation requires ordinal/key/path/suffix consistency, strict monotonic
prefix, arm-file physical identity, the exact threat model, host preference and
durability-protocol pairing, all record formulas, and the platform-specific
physical-identity shape. `volume_join` must have exact byte-for-byte equality of
the independently rederived canonical 16-lowercase-hex Windows volume serials,
or equal unchanged POSIX `st_dev` integers, across parent/stage/target parent.
No parser may compare a decimal, narrowed, truncated, case-folded, or variably
padded Windows representation; the object itself is not a same-volume assertion.
Enabling validation additionally requires all three
stage-absence observations to name the formula stage, all three final reads to
equal the planned final identity, arm-stage/final pathless identity equality,
final link count one, stable parent/volume, and the completion marker last. A
schema-valid self-claim or implementation label is insufficient.

### 6.4 Closed namespace-poststate preimage and digest formula

Every enabling materialization observation stores one complete
`namespace_poststate_preimage` that validates against the closed common-schema
definition. Let `N` be exactly that parsed object. Its domain is exactly
`PROGRAM_FACTS_G3_V3_NAMESPACE_POSTSTATE_V1`, and:

```text
namespace_poststate_sha256 = SHA-256(CJ(N))
```

`N` is non-self-referential. It contains neither
`namespace_poststate_sha256`, `completion_id`, `completion_body_sha256`, nor any
completion file identity. No omitted default, insertion order, whitespace,
native structure layout, path lookup, or serializer-specific byte sequence is
part of the preimage. Object members use RFC-8785 canonical order through
`CJ`; the three-element observation arrays retain the displayed ordinal order.
Consequently a permutation of object insertion order produces the same digest,
while omission or substitution of any bound member does not.

The exact closed members of `N` are:

```text
domain,edge_ordinal,edge_key,attempt_ordinal,publish_arm,lease_physical_identity,
planned_final,final_physical_identity,final_link_count,armed_stage_physical_identity,
armed_stage_link_count,stage_path,stage_state,stage_absence_observations,
parent_physical_identity,volume_join,poststate_reads,stable_read_count,
threat_model,normalized_poststate
```

The two OS-neutral link-count members are both the integer `1` and must equal
the platform-native `number_of_links` or `st_nlink` member of their respective
physical identities. `stage_state` is
`ABSENT_NOFOLLOW_EXACT_LEAF`; `stable_read_count` is `3`.
`normalized_poststate` is exactly `ARM_BOUND_FINAL_ONLY`. No uninterrupted,
restart, pre-reconciliation, alias-removal, or other branch-history member is
permitted. For the same reopened durable arm and the same normalized observable
final-only poststate, protected completion, final-only restart, and restart
after private-alias removal therefore construct byte-identical `N`, digest,
completion ID, completion body hash, and complete `CF(completion)`.

Reconciliation remains an operational eligibility step: the alias branch cannot
construct `N` until the formula stage is absent, the final has link count one,
and all final-only joins revalidate. A diagnostic may describe the earlier
double-name state only outside every governed path and authority graph. Such a
description is advisory, is not durably required, and MUST NOT affect any
attempt, arm, completion, debt, preimage, digest, body, ID, or predecessor byte.

### 6.5 Mandatory preimage joins and recomputation

Schema validity is necessary but not sufficient. Before writing or accepting
an enabling completion, the trusted driver and every independent validator
reconstruct and compare every member of `N` from the reopened records and
current observations:

1. edge ordinal/key and attempt ordinal equal the completion and arm;
2. `publish_arm` equals the completion's arm identity,
   `lease_physical_identity` equals the reopened arm's held-lease identity, and
   `planned_final` equals both the arm plan and `final_artifact`;
3. final and armed-stage physical identities equal the completion observation,
   the outer completion fields, and the reopened arm; their native link counts
   equal the two explicit link-count members and are exactly one;
4. `stage_path` is the formula `payload.stage`; the three absence observations
   are byte-semantically equal to the outer array, ordered ordinals `[1,2,3]`,
   name that exact stage, retain the same parent identity, and all report the
   exact absent state;
5. parent identity equals the completion and arm, while `volume_join` equals
   the reopened arm and satisfies its platform-specific same-volume join. For
   Windows, every participating open handle independently rederives the exact
   16-lowercase-hex uint64 serial and all three strings are equal before any join
   can pass; no lossy numeric normalization or case folding is permitted;
6. the three poststate reads are byte-semantically equal to the outer array in
   observation order and each equals `planned_final`;
7. threat model equals both outer records; `normalized_poststate` is the exact
   final-only constant; the outer observation class and mode are the one
   normalized enabling values; and no branch or reconciliation-history member
   exists in `N` or the completion; and
8. the validator recomputes `SHA-256(CJ(N))` and requires exact equality to
   `namespace_poststate_sha256` before the completion may enable.

Any missing member, extra member, array reordering, inconsistent duplicate,
wrong domain, failed join, or digest substitution makes the completion
nonenabling. The full deterministic completion bytes, including this digest,
are fixed before their first byte is written and are invariant across the three
entry histories. Therefore zero-byte, short, and every pre-first-difference
exact prefix has one unique remaining suffix. A prefix containing a
branch-specific divergent byte is a stable non-prefix mismatch; while the final
exists it is terminal and cannot advance to another attempt.

### 6.6 Exhaustive crash, collision, and recovery states

Recovery holds the inert lease and opens only the current exact-prefix attempt
leaves plus the semantic final. It never scans and never reasons about a live
owner. The state table is exhaustive:

| Observed exact state | Disposition |
|---|---|
| lease absent or present as exact empty singly linked regular file | create/open exact lease without truncation, acquire kernel lock, then derive the prefix; lease state never enables |
| `attempt.json` absent at first gap and final absent | append canonical attempt zero-to-complete; this is the current ordinal |
| any append-only record or payload is an exact prefix of its already determined canonical bytes | append only the missing suffix, flush, and revalidate; this is resume, not equality adoption |
| current record/payload bytes are a stable non-prefix mismatch and final absent | append formula-valid debt binding observed identities and three fresh absence observations; after durable debt advance exactly one ordinal |
| mismatch exists but debt is absent, partial, invalid, or final absence is unproven | remain on current ordinal; no advance and no backfill |
| maximum Z20 ordinal has valid debt and no enabling completion | `ATTEMPT_ORDINAL_EXHAUSTED_HUMAN_REVIEW`; do not wrap or invent a path |
| valid attempt, no payload, final absent | create/append exact payload stage and flush |
| valid payload, no arm, final absent | capture arm/stage pathless identities and three absence observations; append the complete arm, apply its file/parent barriers, and stable-reread it before materialization |
| arm is a partial exact prefix | append the uniquely determined missing suffix and apply the arm durability protocol; do not materialize before complete arm validation |
| valid durable arm, stage exists singly linked, final absent | trusted driver may materialize while retaining the protected-root lease; implementation primitive is outside evidence authority |
| trusted driver completes materialization and observes stage absent, final equal to armed stage identity and planned bytes, final nlink one, parent/volume stable | construct and recompute the exact namespace-poststate preimage/digest, apply the completion protocol, and write `PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION` last; eligible only after downstream semantic revalidation |
| recovery enters with valid durable arm, stage absent, and a singly linked final equal to the armed stage identity and planned bytes | after barriers and stable reads, construct and recompute the same normalized namespace-poststate preimage/digest and the same canonical `PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION` completion bytes as an uninterrupted observation; make no historical primitive claim |
| recovery enters with valid durable arm and stage/final are the same physical object with exactly two links | both names are private and nonenabling; remove only the formula stage alias, flush parent, require the normalized final-only poststate, then construct the same canonical enabling completion bytes; reconciliation history is advisory and cannot select a grade, field, digest, ID, or body byte |
| stage and final both exist with different identities or unexpected link counts | no reconciliation, adoption, replacement, or advance; final-present terminal human review |
| arm valid, stage absent, final absent | materialization cannot be established; debt may advance only after three final-absence observations |
| final exists before valid arm | record at most `POSTCONDITION_ONLY`; never enable or advance, even when bytes match |
| final bytes match but physical identity differs from arm stage, nlink is not one, or parent/volume drifted | `POSTCONDITION_ONLY` plus nonenabling debt; never enable or advance |
| final postconditions hold but the protected-root, exclusive-lease, single-writer, trusted-driver, or completion-last boundary is invalid | `POSTCONDITION_ONLY`; postconditions outside the threat model never enable |
| completion is an exact prefix of the one cross-history canonical byte string, including the normalized namespace-poststate digest | append the unique missing suffix, flush, and revalidate; zero-byte, short, and every pre-first-difference prefix follow this rule |
| completion is a stable non-prefix while the semantic final exists | terminal nonenabling debt or human review; do not truncate, replace, append speculative bytes, or advance |
| enabling completion exists with exact arm/threat-model/final/poststate joins and a recomputed namespace-poststate digest | read-only acknowledge; immediate downstream discriminator revalidates semantics and the completion-last rule |
| `POSTCONDITION_ONLY` or invalid completion exists | preserve as nonenabling debt; no successor |
| successor exists without an enabling immediate predecessor reference | `ORPHAN_SUCCESSOR_TERMINAL_DEBT`; never backfill |
| unsupported profile, nonregular object, protected-root failure, unexpected alias/link state, or ambiguous result while final absent | formula-valid debt may advance; while final exists it is terminal human review |

This is repair-then-degrade without permanent bricking from ordinary crashes:
exact-prefix writes resume, a prepublication mismatch becomes explicit debt and
advances only while the final is absent, and every qualifying postmaterialization
history converges on one narrow normalized arm-bound grade and one canonical
completion byte string. There is no final overwrite,
final cleanup, truncation, content-equality adoption, silent backfill, or
postcondition-only success. The sole permitted removal is the private formula
stage alias after same-object/two-link reconciliation under the lease. Unrelated
pipeline work may continue while a final-present ambiguity is flagged for an
already-authorized external human-review channel.

Writing the single canonical enabling grade after restart is not generic
backfill. It is allowed only for a preexisting valid durable arm under the exact
threat model whose armed stage file object is now the singly linked final file
object, whose formula stage is absent, and whose current parent, volume, byte,
identity, and link-count joins all revalidate. A deterministic private-alias
reconciliation may make that normalized poststate eligible, but its history does
not alter the completion bytes. No arm may be synthesized after materialization,
and no equality-only final can obtain this grade.

## 7. Independent v3 contract review and v2 debt observation

### 7.1 Recovery review

The independent reviewer stable-reads this contract and every existing identity
in section 0 three times before and after review, checks the required-absent v2
GREEN-evidence path three times before and after, and validates every schema,
formula, path expansion, count, principal rule, OS branch, crash state, fixture
projection, Part-0 rule, and authority flag. It independently challenges the
trusted-driver/non-host-compromise boundary, protected-root enforcement,
exclusive lease, completion-last consumer rule, arm durability protocol,
   lossless Windows uint64 volume-serial capture and canonical encoding,
   observable identity/byte postconditions, the closed normalized namespace-
   poststate preimage/digest formula and joins, one canonical completion across
   uninterrupted/final-only/alias-reconciled histories, partial-prefix recovery
   across those histories, and private double-name eligibility recovery. It
reviews and tests the three preferred host primitives as implementation-risk
controls while requiring their admission authority to remain `NONE`. It does
not create an implementation source/runtime/executable/trace/return identity or
historical-syscall claim. The reviewer creates only edge 1 after a pass.

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_review.v1.schema.json","type":"object","additionalProperties":false,"required":["schema_version","review_id","subject","pinned_existing_inputs","required_absent_paths","protected_validation","threat_model","implementation_preferences","evidence_authority_review","prior_principals","recovery_author","reviewer","independence","checks","findings","open_findings","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","review_body_sha256"],"properties":{"schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_v3_recovery_review.v1"},"review_id":{"type":"string","pattern":"^pfg3xrr-[0-9a-f]{32}$"},"subject":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"pinned_existing_inputs":{"type":"array","minItems":17,"maxItems":17,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"}},"required_absent_paths":{"const":["review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_GREEN_EVIDENCE.v2.json"]},"protected_validation":{"const":{"all_six_reads_byte_equal_per_existing_path":true,"all_six_absence_checks_equal":true,"existing_path_count":17,"post_review_reads_or_checks_each":3,"pre_post_equal":true,"pre_review_reads_or_checks_each":3,"write_operation_count":0}},"threat_model":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/threat_model"},"implementation_preferences":{"type":"array","minItems":3,"maxItems":3,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/platform"}},"evidence_authority_review":{"const":{"admission_is_observable_poststate_only":true,"implementation_label_enables":false,"namespace_poststate_digest_recomputed":true,"private_double_name_reconciliation_reviewed":true,"preferred_primitive_enables":false,"reconciliation_history_identity_critical":false,"single_canonical_completion_reviewed":true,"windows_volume_serial_encoding_reviewed":true}},"prior_principals":{"type":"array","minItems":7,"maxItems":7,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"}},"recovery_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"independence":{"const":{"all_nine_principals_pairwise_distinct":true,"no_future_role_for_reviewer":true,"no_self_review":true,"reviewer_separate_from_all_prior_principals":true}},"checks":{"const":["G3X-R01-EXACT-PINS-AND-ABSENCE","G3X-R02-V1-V2-TERMINAL-DEBT","G3X-R03-V2-ARGUMENT-MISMATCH","G3X-R04-V2-PUBLICATION-CONTRADICTION","G3X-R05-R2-PREFIX-AND-COUNT-FORMULA","G3X-R06-OS-IDENTITY-ENCODING-AND-IMPLEMENTATION-PREFERENCES-NONAUTHORITATIVE","G3X-R07-EXPLICIT-THREAT-MODEL-BOUNDARY","G3X-R08-DURABLE-ARM-AND-COMPLETION-LAST","G3X-R09-CRASH-AND-PRIVATE-ALIAS-RECONCILIATION","G3X-R10-PREFIX-RESUME-AND-DEBT-ADVANCE","G3X-R11-SINGLE-CANONICAL-ENABLING-COMPLETION","G3X-R12-NO-EQUALITY-ADOPTION-OR-BACKFILL","G3X-R13-FIXTURE-FIRST-PROJECTION","G3X-R14-EXACT-20-CASE-GREEN","G3X-R15-FRESH-DAG-PRINCIPALS-PART0","G3X-R16-AUTHORITY-CEILING","G3X-R17-NORMALIZED-POSTSTATE-PREIMAGE-AND-DIGEST"]},"findings":{"const":[]},"open_findings":{"const":[]},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"disposition":{"const":"PASS_V3_R2_RECOVERY_CONTRACT_FOR_STRUCTURAL_DEBT_OBSERVATION_AND_FIXTURE_AUTHORSHIP_ONLY"},"accepted_scope":{"const":["REVIEW_V3_R2_RECOVERY_CONTRACT_THREAT_MODEL_AND_OBSERVABLE_POSTSTATE_ONLY"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"review_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}}
```

Semantic validation fixes `subject` to this contract's external identity and
`pinned_existing_inputs` to this contract plus the 16 exact existing identities
in section 0, in registry order. The review has no findings because this is a
pass-only path; a failed review publishes nothing there.

### 7.2 Create-only v2 structural-debt observation

After a valid edge-1 arm-bound enabling reference, a new observer performs read-only AST and
schema inspection. The observer does not import the wrapper or suite, does not
run the v2 command, and does not create GREEN evidence. It creates only edge 2.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v2_failure_observation.v1.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","observation_id","recovery_contract","recovery_review","failed_binding_v2","failed_wrapper_v2","semantic_suite","binding_recovery_contract","required_absent_green_v2","structural_defects","executor_report","observer","predecessor_principals","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","observation_body_sha256"],
  "properties":{"schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_v2_failure_observation.v1"},"observation_id":{"type":"string","pattern":"^pfg3xdo-[0-9a-f]{32}$"},"recovery_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"recovery_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"failed_binding_v2":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_REPAIRED_SUBJECT_BINDING.v2.json","size_bytes":7892,"sha256":"9cda8c864715c04f846d5283d52c8fa5fc44e36bd633228966937119acb391ee"}},"failed_wrapper_v2":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_green_v2.py","size_bytes":16779,"sha256":"590ccc697c483c656c5661828cf5ac6f26907da5fca4b941ad853cab444b3656"}},"semantic_suite":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_semantic_suite_v1.py","size_bytes":93657,"sha256":"417e4978fe3c4a4c214a98cdce141d970b009665afead896b09aad7157aadf73"}},"binding_recovery_contract":{"const":{"path":"architecture/program-facts-g3-00-stdlib-crosscheck-binding-recovery-amendment.md","size_bytes":95837,"sha256":"b4daf10559c54e77431b759b1970dd6ca0af7ae18b80301707e41cf568d235a7"}},"required_absent_green_v2":{"const":{"absence_checks_after":3,"absence_checks_before":3,"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_GREEN_EVIDENCE.v2.json","remained_absent":true,"v2_command_executed":false}},"structural_defects":{"const":[{"defect_id":"V2-D1-GOVERNED-OBJECT-PASSED-AS-SUBJECT-IDENTITY","proof":{"suite_exact_binding_keys":["path","sha256","size_bytes"],"v2_second_argument_ast":"Name(id='REPAIRED_BINDING')","v2_binding_key_count_greater_than_three":true,"v2_binding_passed_whole":true},"terminal":true},{"defect_id":"V2-D2-PUBLICATION-CONTRACT-INTERNALLY-UNREALIZABLE","proof":{"atomic_complete_namespace_publication_required":true,"direct_partial_final_write_forbidden":true,"generic_primitive_named":false,"hard_link_forbidden":true,"rename_over_final_forbidden":true},"terminal":true}]},"executor_report":{"type":"object","additionalProperties":false,"required":["classification","raw_stderr_retained","reported_operation","reported_command_digests"],"properties":{"classification":{"const":"NON_AUTHORITATIVE_EXECUTOR_REPORT_RAW_TRANSCRIPT_NOT_RETAINED"},"raw_stderr_retained":{"const":false},"reported_operation":{"const":"HARD_LINK_CREATE_NEW_PATTERN_CONTRARY_TO_LITERAL_NO_LINK_CLAUSE"},"reported_command_digests":{"type":"array","minItems":0,"maxItems":8,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}}},"observer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"predecessor_principals":{"type":"array","minItems":9,"maxItems":9,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"}},"independence":{"const":{"all_ten_principals_pairwise_distinct":true,"no_future_role_for_observer":true,"no_self_observation":true,"observer_separate_from_failed_v2_executor":true}},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"disposition":{"const":"V1_AND_V2_ARTIFACTS_PRESERVED_AS_TERMINAL_DEBT_V3_FIXTURE_FIRST_BRANCH_MAY_BEGIN"},"accepted_scope":{"const":["OBSERVE_V2_STRUCTURAL_FAILURES_WITHOUT_EXECUTION"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"observation_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}
}
```

The `reported_command_digests` array may remain empty. A populated value is
still non-authoritative because the raw stream is unavailable. Neither that
array nor the report can satisfy either structural proof.

## 8. Fixture-first recovery requirements

Only after valid published edges 1-2 may the independent v3 fixture author
create edges 3-5. Fixture source is strict UTF-8/LF/one-final-LF Python. The
suite contains no implementation repair. The wrapper contains orchestration
only. Both are immutable after their publication completion.

The RED fixture suite defines exactly these 47 ordered recovery IDs:

```text
G3X-RED-01-V2-BINDING-IDENTITY
G3X-RED-02-V2-WRAPPER-IDENTITY
G3X-RED-03-WHOLE-GOVERNED-BINDING-ARGUMENT
G3X-RED-04-SUITE-EXACT-THREE-FIELD-SUBJECT
G3X-RED-05-GREEN-V2-ABSENT-NO-RERUN
G3X-RED-06-V1-V2-IMMUTABLE-NONENABLING
G3X-RED-07-PUBLICATION-CONTRACT-CONTRADICTION
G3X-RED-08-HARDLINK-REPORT-NONAUTHORITATIVE
G3X-RED-09-INERT-LEASE-CRASH-RELEASE
G3X-RED-10-TRUSTED-DRIVER-SINGLE-WRITER-BOUNDARY
G3X-RED-11-Z20-CONTIGUOUS-PREFIX-NO-SCAN
G3X-RED-12-EXACT-PREFIX-ATTEMPT-RESUME
G3X-RED-13-EXACT-PREFIX-PAYLOAD-RESUME
G3X-RED-14-NONPREFIX-MISMATCH-DEBT-ADVANCE
G3X-RED-15-DEBT-INVALID-NO-ADVANCE
G3X-RED-16-FINAL-PRESENT-NO-ADVANCE
G3X-RED-17-WINDOWS-PREFERRED-NOREPLACE-NONAUTHORITATIVE
G3X-RED-18-WINDOWS-COLLISION
G3X-RED-19-LINUX-PREFERRED-NOREPLACE-NONAUTHORITATIVE
G3X-RED-20-LINUX-COLLISION
G3X-RED-21-MACOS-PREFERRED-EXCL-NONAUTHORITATIVE
G3X-RED-22-MACOS-NO-PATH-FALLBACK
G3X-RED-23-CROSS-VOLUME-OR-MOUNT
G3X-RED-24-PARENT-PHYSICAL-IDENTITY-DRIFT
G3X-RED-25-PATHLESS-STAGE-FINAL-IDENTITY-DRIFT
G3X-RED-26-ARM-DURABLE-BEFORE-MATERIALIZATION
G3X-RED-27-THREAT-MODEL-BOUNDARY-INVALID
G3X-RED-28-PROTECTED-NAMESPACE-BROKEN
G3X-RED-29-IMPLEMENTATION-TRACE-NOT-ADMISSION
G3X-RED-30-CRASH-PARTIAL-ATTEMPT-RESUME
G3X-RED-31-CRASH-PARTIAL-ARM-RESUME
G3X-RED-32-CRASH-AFTER-ARM-BEFORE-MATERIALIZATION
G3X-RED-33-CANONICAL-COMPLETION-PARTIAL-PREFIX-RESTART-MATRIX
G3X-RED-34-PRIVATE-DOUBLE-NAME-DETERMINISTIC-RECONCILIATION
G3X-RED-35-RECOVERY-IDENTITY-MISMATCH
G3X-RED-36-PROTECTED-NAMESPACE-MATERIALIZATION-ENABLES
G3X-RED-37-SINGLE-NORMALIZED-POSTSTATE-GRADE-ENABLES
G3X-RED-38-POSTCONDITION-ONLY-NONENABLING
G3X-RED-39-EQUAL-AMBIENT-FINAL-NOT-ADOPTED
G3X-RED-40-SCAN-NEWEST-BACKFILL-FORBIDDEN
G3X-RED-41-CANONICAL-EDGES-USE-SAME-R2-TRANSPORT
G3X-RED-42-COUNT-FORMULA-AND-ORDINAL-EXHAUSTION
G3X-RED-43-AUTHORITY-FALSE-AND-ORPHAN-NONENABLING
G3X-RED-44-NAMESPACE-POSTSTATE-DIGEST-FORMULA
G3X-RED-45-NAMESPACE-POSTSTATE-CJ-FIELD-ORDER
G3X-RED-46-NAMESPACE-POSTSTATE-OMISSION
G3X-RED-47-JOINED-NAMESPACE-POSTSTATE-SUBSTITUTION
```

Cases 1-8 are pure static observations over pinned v2 bytes. Cases 9-29 use a
deterministic adapter model for all OS branches and a native same-volume
temporary test only for the executing host's declared profile. Preferred-
primitive results never feed admission. Cases 30-39 inject failure at each exact
seam, including the private double-name state, and assert the grade/state table.
Without changing the exact 47-case denominator, case 23 contains a Windows
volume-identity encoding and join submatrix. For native unsigned 64-bit values at
`0`, `2^53-1`, `2^53`, `2^63-1`, `2^63`, and `2^64-1`, the adapter must
produce exactly `format(v, "016x")`, round-trip to
the same uint64, and preserve leading zeroes. It rejects JSON numbers, decimal
strings, uppercase hex, `0x` prefixes, signs, whitespace, nonhex characters, and
every string length other than 16. For each high-bit value it also supplies
schema-shaped but semantically false low-32-bit, low-53-bit, and truncated
representations, recomputes every containing digest/ID/body/file identity, and
requires native-handle-to-record validation to reject them rather than a stale
checksum. A pair of native serials with distinct high bits but equal low 32 bits
must fail the Windows parent/stage/target-parent join; three independently
rederived identical canonical strings must pass. `FileId.Identifier` remains
exactly 32 lowercase hex, `number_of_links` remains an integer, and the unchanged
Linux/macOS identity branches are exercised as regression controls.

Case 33 contains a mandatory cross-history partial-completion submatrix without
changing the exact 47-case denominator. Let the three histories be
`PROTECTED_OBSERVATION`, `FINAL_ONLY_RESTART`, and
`PRIVATE_ALIAS_RECONCILED_RESTART`. For the same reopened arm and normalized
current final-only poststate, the fixture constructs `C(h)` for every history and
requires all three canonical completion byte strings to be byte-identical. For
every origin-history by resume-history pair and every exact cut
`k in range(0, len(C)+1)`, the fixture persists `C[:k]` and requires recovery to
produce exactly `C`. When `k < len(C)`, it appends exactly the unique suffix
`C[k:]` and no other byte; when `k == len(C)`, it performs no write and only
revalidates the already complete record. Thus empty, every partial, and complete
prefixes are exhaustively covered rather than sampled. For each branch-sensitive
mutant that injects a forbidden
former grade, observation class, mode, reconciliation field, or branch selector,
let `d` be each pairwise first-difference offset from `C`: `C[:d]` must resume to
the same unique suffix, while the mutant prefix through the divergent byte
(`mutant[:d+1]`) is a stable non-prefix and, because the final is present, must be
terminal with no advance. Correct `C(h)` values have no real first difference;
the mutants make that historical-discriminator seam observable to regression.

Cases 40-43 are static containment/count/authority checks. Cases 44-47 require
the exact namespace-poststate formula, prove RFC-8785 object-field-order
invariance, and reject an omitted or substituted bound member. Case 47 mutates
every joined class in `N`: edge/attempt, arm/lease, planned final, final and armed-
stage physical identity plus link count, stage path/state/absence observations,
parent/volume, poststate reads, threat model, and normalized poststate. It uses a
schema-valid alternative wherever the member's schema admits one and a forbidden
alternative for a constant-bound member; after every substitution it recomputes
`namespace_poststate_sha256`,
`completion_id`, `completion_body_sha256`, and the complete `CF(completion)` file
size, SHA-256, and published identity. A schema-valid `N`-only mutation must fail
an outer or reopened-arm join; mutation of its duplicate outer value too must
still fail a reopened-arm or current-poststate join. A fully recomputed constant-
member mutation or attempt to inject any former grade/class/mode/reconciliation
discriminator must fail the closed schema, the single normalized grade/mode rule,
or reconciliation eligibility. Advisory
alias history cannot bypass stage absence, link-count, identity, or current-
poststate joins and never changes canonical bytes. A stale-checksum rejection may
be retained only as a control and never satisfies case 47. Fixtures never touch
a governed final, lease, or attempt path, never import a provider, and never run
an audit. Native temporary fixtures live outside the repository and are not
evidence or predecessors.

The initial RED command is exactly:

```text
python -m unittest review_fixtures.program_facts_runtime_gate3.g3_00_schema_crosscheck.test_crosscheck_v3_recovery_red
```

Before a publication implementation or v3 binding exists, the exact expected
projection is fixed by the fixture suite: structural cases 1-8 pass as observed
debt; every successor-capability case that requires the absent replacement
implementation records `RED`; no case is skipped, xfailed, inverted, retried, or
filtered. The evidence schema fixes all 47 rows, their expectations, raw command
capture digest/size, platform profile, suite/wrapper identities, unchanged v1/v2
identities, and all-false authority. A mismatch prevents edge 5.

The recovery RED-evidence JSON uses the section-3 `pfg3xre-` formula and this
closed field schema:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_red_evidence.v1.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","evidence_id","recovery_contract","recovery_review","v2_debt_observation","fixture_suite","fixture_wrapper","executor","command","case_results","case_count","unchanged_terminal_debt","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","evidence_body_sha256"],
  "properties":{"schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_v3_recovery_red_evidence.v1"},"evidence_id":{"type":"string","pattern":"^pfg3xre-[0-9a-f]{32}$"},"recovery_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"recovery_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"v2_debt_observation":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"fixture_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"fixture_wrapper":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"executor":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"command":{"type":"object","additionalProperties":false,"required":["argv","exit_code","fixture_ids","stdout_size_bytes","stdout_sha256","stderr_size_bytes","stderr_sha256"],"properties":{"argv":{"const":["python","-m","unittest","review_fixtures.program_facts_runtime_gate3.g3_00_schema_crosscheck.test_crosscheck_v3_recovery_red"]},"exit_code":{"const":0},"fixture_ids":{"type":"array","minItems":47,"maxItems":47,"uniqueItems":true,"items":{"type":"string"}},"stdout_size_bytes":{"type":"integer","minimum":1,"maximum":9007199254740991},"stdout_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"},"stderr_size_bytes":{"type":"integer","minimum":0,"maximum":9007199254740991},"stderr_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}},"case_results":{"type":"array","minItems":47,"maxItems":47,"uniqueItems":true,"items":{"type":"object","additionalProperties":false,"required":["fixture_id","expected_initial_result","observed_initial_result"],"properties":{"fixture_id":{"type":"string"},"expected_initial_result":{"enum":["PASS_DEBT_OBSERVED","RED"]},"observed_initial_result":{"enum":["PASS_DEBT_OBSERVED","RED"]}}}},"case_count":{"const":47},"unchanged_terminal_debt":{"const":{"binding_v1":true,"binding_v2":true,"green_evidence_v2_absent":true,"wrapper_v2":true}},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"disposition":{"const":"V3_R2_RECOVERY_FIXTURE_FIRST_RED_CONFIRMED_BINDING_V3_CONSTRUCTION_MAY_BEGIN"},"accepted_scope":{"const":["FIXTURE_FIRST_V3_R2_RECOVERY_ONLY"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"evidence_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}
}
```

Semantic validation fixes both 47-ID arrays to the displayed order and requires
expected equals observed for every row. Schema validation alone is insufficient.

## 9. Independently reconstructed binding v3 and GREEN wrapper v3

After valid edge 5, the v3 fixture executor reconstructs binding v3 only from
accepted valid predecessors: the accepted successor pair; accepted binding-
recovery pair and v1 debt observation; accepted transport pair and RED evidence;
immutable suite, child, lowercase RED wrapper, repaired source, historical
handoff; this v3 contract/review; v2 structural-debt observation; and recovery
RED evidence. The malformed v1 binding and failed v2 binding/wrapper do not
appear in the binding-v3 schema.

Binding v3 has exactly these fields:

```text
schema_version,binding_id,recovery_contract,recovery_review,v2_debt_observation,
recovery_red_evidence,accepted_successor_contract,accepted_successor_review,
accepted_binding_recovery_contract,accepted_binding_recovery_review,
accepted_v1_debt_observation,transport_amendment,transport_review,red_evidence,
historical_red_subject,historical_red_post_run_subject,repaired_source,
historical_pending_handoff,fixture_child,semantic_suite,red_wrapper,
semantic_projection,chronology_join,principals,independence,part_0_genericity,
disposition,accepted_scope,authority_ceiling,publication_requirements,
binding_body_sha256
```

Its literal Draft-2020-12 schema is:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_repaired_subject_binding.v3.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","binding_id","recovery_contract","recovery_review","v2_debt_observation","recovery_red_evidence","accepted_successor_contract","accepted_successor_review","accepted_binding_recovery_contract","accepted_binding_recovery_review","accepted_v1_debt_observation","transport_amendment","transport_review","red_evidence","historical_red_subject","historical_red_post_run_subject","repaired_source","historical_pending_handoff","fixture_child","semantic_suite","red_wrapper","semantic_projection","chronology_join","principals","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","binding_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_repaired_subject_binding.v3"},
    "binding_id":{"type":"string","pattern":"^pfg3xrb-[0-9a-f]{32}$"},
    "recovery_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "recovery_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},
    "v2_debt_observation":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},
    "recovery_red_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},
    "accepted_successor_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "accepted_successor_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "accepted_binding_recovery_contract":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "accepted_binding_recovery_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "accepted_v1_debt_observation":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "transport_amendment":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "transport_review":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "red_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "historical_red_subject":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "historical_red_post_run_subject":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "historical_pending_handoff":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "fixture_child":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "red_wrapper":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "semantic_projection":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/semantic_projection"},
    "chronology_join":{"const":{"failed_v1_or_v2_predecessor_used":false,"old_and_repaired_content_differ":true,"old_and_repaired_share_path":true,"recovery_red_evidence_joined":true,"red_evidence_projects_frozen_and_post_run_subject":true,"repair_precedes_green_by_binding_v3_dependency":true,"timestamps_used":false,"v2_debt_observation_joined":true}},
    "principals":{"type":"array","minItems":11,"maxItems":11,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"}},
    "independence":{"const":{"all_eleven_principals_pairwise_distinct":true,"failed_v2_executor_not_reused":true,"fixture_executor_separate_from_all_authors_reviewers_observers_and_implementer":true,"no_self_binding":true}},
    "part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},
    "disposition":{"const":"REPAIRED_SUBJECT_BOUND_V3_FOR_EXACT_GREEN_FIXTURE_ONLY"},
    "accepted_scope":{"const":["BIND_REPAIRED_SUBJECT_V3","CREATE_IMMUTABLE_GREEN_WRAPPER_V3","EXECUTE_EXACT_20_CASE_GREEN_FIXTURE","WRITE_GREEN_EVIDENCE_V3"]},
    "authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},
    "publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},
    "binding_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}
  }
}
```

`additionalProperties:false` applies. Every identity is either an exact section-
0 identity or a validated fresh `published_ref`. `historical_red_subject` and
`historical_red_post_run_subject` are the old 190,456-byte identity.
`repaired_source` is exactly the three-field current identity. `chronology_join`
is exactly:

```json
{"failed_v1_or_v2_predecessor_used":false,"old_and_repaired_content_differ":true,"old_and_repaired_share_path":true,"recovery_red_evidence_joined":true,"red_evidence_projects_frozen_and_post_run_subject":true,"repair_precedes_green_by_binding_v3_dependency":true,"timestamps_used":false,"v2_debt_observation_joined":true}
```

Its schema version is
`plamen.program_facts_g3_00_stdlib_crosscheck_repaired_subject_binding.v3`, ID
pattern is `^pfg3xrb-[0-9a-f]{32}$`, disposition is
`REPAIRED_SUBJECT_BOUND_V3_FOR_EXACT_GREEN_FIXTURE_ONLY`, and accepted scope is
exactly
`["BIND_REPAIRED_SUBJECT_V3","CREATE_IMMUTABLE_GREEN_WRAPPER_V3","EXECUTE_EXACT_20_CASE_GREEN_FIXTURE","WRITE_GREEN_EVIDENCE_V3"]`.
The cumulative principal roster has 11 pairwise-distinct entries through the v3
fixture executor plus the prior repair implementer; prior values reproduce their
validated sources byte-semantically.

The v3 wrapper is immutable strict UTF-8/LF Python and contains binding and
orchestration logic only. It MUST:

1. stable-read and fully validate binding v3 and its publication completion;
2. stable-read and require the exact suite and repaired-source identities;
3. require `tuple(semantic_suite.CASE_IDS)` to equal the exact 20-ID order in
   section 10;
4. for every ordered case, call exactly once:

```python
semantic_suite.run_case(case_id, repaired_binding_v3["repaired_source"])
```

5. require the return value to be exactly `True` and emit one canonical PASS
   record;
6. expose exactly 20 `unittest` methods and no skip, xfail, retry, filtering,
   adapter, alternate source, semantic assertion, provider call, audit call, or
   governed write; and
7. restore fixture-owned stdout/stderr state in `finally`.

An AST/mechanical check locates every `semantic_suite.run_case` call and requires
exactly two positional arguments, no keywords, first argument the loop/method
`case_id`, and second argument exactly a `Subscript` of the bound governed object
with literal key `"repaired_source"`. It rejects a `Name` second argument,
including `REPAIRED_BINDING`, `repaired_binding_v3`, or any alias of the whole
governed object. It rejects `.get`, unpacking, dict copying, synthesized identity,
or any three-field object not byte-semantically equal to the binding's exact
`repaired_source` value. The suite separately enforces the key set
`{"path","size_bytes","sha256"}`. Both checks must pass before GREEN executes.

## 10. Exact 20-case v3 GREEN execution and evidence

The sole command is:

```text
python -m unittest review_fixtures.program_facts_runtime_gate3.g3_00_schema_crosscheck.test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_green_v3
```

Its case projection is exactly:

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

Every expected and observed result is `PASS`. All 20 run exactly once. The raw
stdout decodes to exactly 20 canonical records in that order; stderr is retained
by bytes/digest, not copied into evidence. Case 20 independently reproduces the
full semantic projection. Zero exit without the record projection is invalid.

GREEN evidence v3 has exactly these fields:

```text
schema_version,evidence_id,repaired_binding_v3,green_wrapper_v3,red_evidence,
recovery_red_evidence,semantic_suite,fixture_child,red_wrapper,repaired_source,
executor,repair_implementer,platform,command,case_results,green_case_count,
failed_case_count,semantic_projection,chronology_join,protected_pre_execution,
protected_post_execution,post_run_repaired_source,post_run_green_wrapper,
independence,part_0_genericity,disposition,accepted_scope,authority_ceiling,
publication_requirements,evidence_body_sha256
```

Its literal Draft-2020-12 schema is:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_green_evidence.v3.schema.json",
  "$defs":{"case":{"type":"object","additionalProperties":false,"required":["fixture_id","expected_repaired_result","observed_repaired_result"],"properties":{"fixture_id":{"enum":["G3CT-RED-01-WINDOWS-RAW-CRLF","G3CT-RED-02-CP1252-NONASCII","G3CT-RED-03-OVERSIZE-PLUS-ONE","G3CT-RED-04-EXACT-CAP","G3CT-RED-05-PARTIAL-WRITE","G3CT-RED-06-NONE-WRITE","G3CT-RED-07-SHORT-COUNT","G3CT-RED-08-FLUSH-FAILURE","G3CT-RED-09-ONE-WRITE-ONE-FLUSH","G3CT-RED-10-IMPORT-SYS-CONFINEMENT","G3CT-RED-11-ZERO-ATOM-VALID","G3CT-RED-12-ZERO-ATOM-INVALID","G3CT-RED-13-NONZERO-ALL-IMPOSSIBLE","G3CT-RED-14-NONZERO-ONE-VECTOR","G3CT-RED-15-NONZERO-UNPROVED","G3CT-RED-16-NONZERO-MISSING-DISPOSITION","G3CT-RED-17-DUPLICATE-DISPOSITION","G3CT-RED-18-UNKNOWN-DISPOSITION-ATOM","G3CT-RED-19-DIRECT-IF-SYMMETRY","G3CT-RED-20-CURRENT-12-SCHEMA-REGRESSION"]},"expected_repaired_result":{"const":"PASS"},"observed_repaired_result":{"const":"PASS"}}}},
  "type":"object","additionalProperties":false,
  "required":["schema_version","evidence_id","repaired_binding_v3","green_wrapper_v3","red_evidence","recovery_red_evidence","semantic_suite","fixture_child","red_wrapper","repaired_source","executor","repair_implementer","platform","command","case_results","green_case_count","failed_case_count","semantic_projection","chronology_join","protected_pre_execution","protected_post_execution","post_run_repaired_source","post_run_green_wrapper","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","evidence_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_green_evidence.v3"},"evidence_id":{"type":"string","pattern":"^pfg3xge-[0-9a-f]{32}$"},
    "repaired_binding_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"green_wrapper_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},
    "red_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"recovery_red_evidence":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"fixture_child":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"red_wrapper":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},
    "executor":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"repair_implementer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},
    "platform":{"type":"object","additionalProperties":false,"required":["implementation","operating_system","python_version","stdout_capture_mode"],"properties":{"implementation":{"const":"CPython"},"operating_system":{"enum":["WINDOWS","LINUX","MACOS"]},"python_version":{"type":"string","pattern":"^3\\.12\\.[0-9]+$"},"stdout_capture_mode":{"const":"RAW_BYTES"}}},
    "command":{"type":"object","additionalProperties":false,"required":["argv","exit_code","fixture_ids","stdout_size_bytes","stdout_sha256","stderr_size_bytes","stderr_sha256"],"properties":{"argv":{"const":["python","-m","unittest","review_fixtures.program_facts_runtime_gate3.g3_00_schema_crosscheck.test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_green_v3"]},"exit_code":{"const":0},"fixture_ids":{"const":["G3CT-RED-01-WINDOWS-RAW-CRLF","G3CT-RED-02-CP1252-NONASCII","G3CT-RED-03-OVERSIZE-PLUS-ONE","G3CT-RED-04-EXACT-CAP","G3CT-RED-05-PARTIAL-WRITE","G3CT-RED-06-NONE-WRITE","G3CT-RED-07-SHORT-COUNT","G3CT-RED-08-FLUSH-FAILURE","G3CT-RED-09-ONE-WRITE-ONE-FLUSH","G3CT-RED-10-IMPORT-SYS-CONFINEMENT","G3CT-RED-11-ZERO-ATOM-VALID","G3CT-RED-12-ZERO-ATOM-INVALID","G3CT-RED-13-NONZERO-ALL-IMPOSSIBLE","G3CT-RED-14-NONZERO-ONE-VECTOR","G3CT-RED-15-NONZERO-UNPROVED","G3CT-RED-16-NONZERO-MISSING-DISPOSITION","G3CT-RED-17-DUPLICATE-DISPOSITION","G3CT-RED-18-UNKNOWN-DISPOSITION-ATOM","G3CT-RED-19-DIRECT-IF-SYMMETRY","G3CT-RED-20-CURRENT-12-SCHEMA-REGRESSION"]},"stdout_size_bytes":{"type":"integer","minimum":1,"maximum":9007199254740991},"stdout_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"},"stderr_size_bytes":{"type":"integer","minimum":0,"maximum":9007199254740991},"stderr_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}},
    "case_results":{"type":"array","minItems":20,"maxItems":20,"uniqueItems":true,"items":{"$ref":"#/$defs/case"}},"green_case_count":{"const":20},"failed_case_count":{"const":0},"semantic_projection":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/semantic_projection"},
    "chronology_join":{"const":{"failed_v1_or_v2_predecessor_used":false,"green_binds_repaired_binding_v3":true,"green_binds_repaired_source":true,"green_binds_valid_red_evidence":true,"repair_precedes_green_by_identity_join":true,"timestamps_used":false}},
    "protected_pre_execution":{"type":"array","minItems":7,"maxItems":7,"uniqueItems":true,"items":{"oneOf":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"}]}},"protected_post_execution":{"type":"array","minItems":7,"maxItems":7,"uniqueItems":true,"items":{"oneOf":[{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"}]}},
    "post_run_repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"post_run_green_wrapper":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},
    "independence":{"const":{"executor_separate_from_failed_v2_executor_and_all_reviewers":true,"no_self_generated_acceptance":true,"predecessor_principals_preserved":true}},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"disposition":{"const":"GREEN_V3_CONFIRMED_FOR_INDEPENDENT_REPAIRED_SOURCE_REVIEW_ONLY"},"accepted_scope":{"const":["EXECUTE_EXACT_20_CASE_GREEN_FIXTURE","WRITE_GREEN_EVIDENCE_V3"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"evidence_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}
  }
}
```

It is `additionalProperties:false`; schema version is
`plamen.program_facts_g3_00_stdlib_crosscheck_green_evidence.v3`; ID pattern is
`^pfg3xge-[0-9a-f]{32}$`; `green_case_count:20`;
`failed_case_count:0`; disposition
`GREEN_V3_CONFIRMED_FOR_INDEPENDENT_REPAIRED_SOURCE_REVIEW_ONLY`; and scope
`["EXECUTE_EXACT_20_CASE_GREEN_FIXTURE","WRITE_GREEN_EVIDENCE_V3"]`.
`command.argv` is the literal command array above and `fixture_ids` is the exact
displayed order. `case_results` has exactly 20 closed rows
`{fixture_id,expected_repaired_result:"PASS",observed_repaired_result:"PASS"}`.
The two protected arrays are byte-semantically equal and contain, in order,
binding v3, wrapper v3, accepted RED evidence, recovery RED evidence, suite,
child, and lowercase RED wrapper. Repaired source and wrapper are also bound by
their exact post-run identities. Each distinct path is stable-read three times
before and after with zero governed writes. The failed v1/v2 artifacts are not
GREEN predecessors.

## 11. Source review, handoff, and acceptance schemas

Only after valid GREEN evidence may a new source reviewer publish edge 9. The
review is read-only and checks exact upstream arm/completion references,
including every recomputed namespace-poststate preimage/digest; repaired-source
stability; wrapper AST subject projection; 20-pass record projection; semantic
counts/digests; repair scope; historical immutability; cumulative principal
separation; Part-0; and authority.

The source-review schema is recursively closed with fields:

```text
schema_version,review_id,green_evidence_v3,repaired_binding_v3,green_wrapper_v3,
repaired_source,semantic_suite,source_reviewer,predecessor_principals,
protected_validation,checks,findings,open_findings,independence,
part_0_genericity,disposition,accepted_scope,authority_ceiling,
publication_requirements,review_body_sha256
```

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_repaired_source_review.v3.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","green_evidence_v3","repaired_binding_v3","green_wrapper_v3","repaired_source","semantic_suite","source_reviewer","predecessor_principals","protected_validation","checks","findings","open_findings","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","review_body_sha256"],
  "properties":{"schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_repaired_source_review.v3"},"review_id":{"type":"string","pattern":"^pfg3xsr-[0-9a-f]{32}$"},"green_evidence_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"repaired_binding_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"green_wrapper_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"source_reviewer":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"predecessor_principals":{"type":"array","minItems":11,"maxItems":11,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"}},"protected_validation":{"const":{"all_reads_byte_equal":true,"post_review_reads_each":3,"pre_post_identities_equal":true,"pre_review_reads_each":3,"reviewed_subject_exact":true,"write_operation_count":0}},"checks":{"const":["G3X-SR01-VALID-V3-PREDECESSORS","G3X-SR02-SOURCE-STABILITY","G3X-SR03-REPAIR-SCOPE","G3X-SR04-EXACT-SUBJECT-IDENTITY-ARGUMENT","G3X-SR05-EXACT-20-PASS","G3X-SR06-CENSUS-DIGESTS","G3X-SR07-V1-V2-DEBT-NONENABLING","G3X-SR08-R2-ARM-COMPLETION-CHAIN","G3X-SR09-PRINCIPAL-INDEPENDENCE","G3X-SR10-PART0-AUTHORITY"]},"findings":{"const":[]},"open_findings":{"const":[]},"independence":{"const":{"all_twelve_principals_pairwise_distinct":true,"no_self_review":true,"source_reviewer_separate_from_executor_and_implementer":true}},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"disposition":{"const":"PASS_REPAIRED_SOURCE_FOR_V4_HANDOFF_ONLY"},"accepted_scope":{"const":["REVIEW_REPAIRED_SOURCE_FOR_V4_HANDOFF_ONLY"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"review_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}
}
```

Its version is `plamen.program_facts_g3_00_stdlib_crosscheck_repaired_source_review.v3`;
ID matches `^pfg3xsr-[0-9a-f]{32}$`; checks are exactly
`["G3X-SR01-VALID-V3-PREDECESSORS","G3X-SR02-SOURCE-STABILITY","G3X-SR03-REPAIR-SCOPE","G3X-SR04-EXACT-SUBJECT-IDENTITY-ARGUMENT","G3X-SR05-EXACT-20-PASS","G3X-SR06-CENSUS-DIGESTS","G3X-SR07-V1-V2-DEBT-NONENABLING","G3X-SR08-R2-ARM-COMPLETION-CHAIN","G3X-SR09-PRINCIPAL-INDEPENDENCE","G3X-SR10-PART0-AUTHORITY"]`;
findings and open findings are empty; disposition is
`PASS_REPAIRED_SOURCE_FOR_V4_HANDOFF_ONLY`; and scope is
`["REVIEW_REPAIRED_SOURCE_FOR_V4_HANDOFF_ONLY"]`.

The handoff-v4 schema is recursively closed with fields:

```text
schema_version,handoff_id,source_review_v3,green_evidence_v3,
repaired_binding_v3,candidate_source,historical_pending_handoff,semantic_suite,
semantic_projection,handoff_author,predecessor_principals,independence,
part_0_genericity,disposition,accepted_scope,authority_ceiling,
publication_requirements,handoff_body_sha256
```

Its version is `plamen.program_facts_g3_00_stdlib_crosscheck_handoff.v4`; ID
matches `^pfg3xsh-[0-9a-f]{32}$`; disposition is
`READY_FOR_INDEPENDENT_V4_CANDIDATE_ACCEPTANCE_FOR_CANONICAL_CONSTRUCTION_ONLY`;
and scope is `["CONSTRUCT_V4_HANDOFF_FOR_CANDIDATE_REVIEW_ONLY"]`.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_handoff.v4.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","handoff_id","source_review_v3","green_evidence_v3","repaired_binding_v3","candidate_source","historical_pending_handoff","semantic_suite","semantic_projection","handoff_author","predecessor_principals","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","handoff_body_sha256"],
  "properties":{"schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_handoff.v4"},"handoff_id":{"type":"string","pattern":"^pfg3xsh-[0-9a-f]{32}$"},"source_review_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"green_evidence_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"repaired_binding_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"candidate_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"historical_pending_handoff":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"semantic_projection":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/semantic_projection"},"handoff_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"predecessor_principals":{"type":"array","minItems":12,"maxItems":12,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"}},"independence":{"const":{"all_thirteen_principals_pairwise_distinct":true,"handoff_author_separate":true,"no_self_approval":true,"predecessor_principals_preserved":true}},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"disposition":{"const":"READY_FOR_INDEPENDENT_V4_CANDIDATE_ACCEPTANCE_FOR_CANONICAL_CONSTRUCTION_ONLY"},"accepted_scope":{"const":["CONSTRUCT_V4_HANDOFF_FOR_CANDIDATE_REVIEW_ONLY"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"handoff_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}
}
```

The acceptance-v4 schema is recursively closed with fields:

```text
schema_version,acceptance_id,handoff_v4,source_review_v3,green_evidence_v3,
repaired_binding_v3,candidate_source,semantic_suite,candidate_acceptor,
predecessor_principals,checks,findings,open_findings,independence,
part_0_genericity,disposition,accepted_scope,authority_ceiling,
publication_requirements,acceptance_body_sha256
```

Its version is `plamen.program_facts_g3_00_stdlib_crosscheck_acceptance.v4`; ID
matches `^pfg3xca-[0-9a-f]{32}$`; checks are exactly
`["G3X-CA01-V4-HANDOFF","G3X-CA02-V3-BINDING-CHAIN","G3X-CA03-EXACT-20-PASS","G3X-CA04-SUITE-BYTE-IDENTITY","G3X-CA05-SOURCE-REVIEW","G3X-CA06-V1-V2-DEBT-NONENABLING","G3X-CA07-R2-ARM-BOUND-ENABLING-COMPLETIONS","G3X-CA08-PRINCIPAL-INDEPENDENCE","G3X-CA09-PART0","G3X-CA10-CONSTRUCTION-ONLY-AUTHORITY"]`;
findings/open findings are empty; disposition is
`PASS_CANDIDATE_ACCEPTED_V4_FOR_CREATE_ONLY_CANONICAL_CONSTRUCTION_NOT_ADMISSION`;
and scope is `["ACCEPT_V4_CANDIDATE_FOR_CANONICAL_CONSTRUCTION_ONLY"]`.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_acceptance.v4.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","acceptance_id","handoff_v4","source_review_v3","green_evidence_v3","repaired_binding_v3","candidate_source","semantic_suite","candidate_acceptor","predecessor_principals","checks","findings","open_findings","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","acceptance_body_sha256"],
  "properties":{"schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_acceptance.v4"},"acceptance_id":{"type":"string","pattern":"^pfg3xca-[0-9a-f]{32}$"},"handoff_v4":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"source_review_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"green_evidence_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"repaired_binding_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"candidate_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"semantic_suite":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"candidate_acceptor":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"predecessor_principals":{"type":"array","minItems":13,"maxItems":13,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"}},"checks":{"const":["G3X-CA01-V4-HANDOFF","G3X-CA02-V3-BINDING-CHAIN","G3X-CA03-EXACT-20-PASS","G3X-CA04-SUITE-BYTE-IDENTITY","G3X-CA05-SOURCE-REVIEW","G3X-CA06-V1-V2-DEBT-NONENABLING","G3X-CA07-R2-ARM-BOUND-ENABLING-COMPLETIONS","G3X-CA08-PRINCIPAL-INDEPENDENCE","G3X-CA09-PART0","G3X-CA10-CONSTRUCTION-ONLY-AUTHORITY"]},"findings":{"const":[]},"open_findings":{"const":[]},"independence":{"const":{"all_fourteen_principals_pairwise_distinct":true,"candidate_acceptor_separate":true,"generator_discriminator_separation":true,"no_self_acceptance":true}},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"disposition":{"const":"PASS_CANDIDATE_ACCEPTED_V4_FOR_CREATE_ONLY_CANONICAL_CONSTRUCTION_NOT_ADMISSION"},"accepted_scope":{"const":["ACCEPT_V4_CANDIDATE_FOR_CANONICAL_CONSTRUCTION_ONLY"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"acceptance_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}
}
```

Every identity to a fresh artifact in these schemas is a `published_ref`. Every
predecessor principal is byte-semantically reproduced. The cumulative roster is
12 at source review, 13 at handoff, and 14 at acceptance, with all IDs pairwise
distinct and the exact roles from section 4. A transport completion never
substitutes for the source reviewer or acceptor.

## 12. Fresh canonical-construction namespace

The old absent v2 canonical target remains unused by this branch. The only
canonical target is fresh `CANONICAL_SOURCE_V3`, planned as:

```json
{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v3.py","expected_size_bytes":196712,"expected_sha256":"ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f"}
```

After valid acceptance v4, the independent adopter advances edges 12-14 in
order. Each edge independently uses the same section-6 r2 lease, monotonic
attempt namespace, durable arm, protected-root threat model, the single canonical
enabling completion grade, and debt rules. A crash may exact-prefix resume or
recover the normalized arm-bound final poststate; it does not require a fictional uninterrupted
three-edge owner. Edge 13's arm binds the stable repaired-source identity and
the planned canonical bytes before materialization. Edge 14 revalidates the
enabling arm/completion/threat-model joins; it does not encode operation history.

Canonical intent v4 is recursively closed with fields:

```text
schema_version,intent_id,acceptance_v4,candidate_source,canonical_target_plan,
transport_contract,predecessor_principals,canonical_adopter,
independence,part_0_genericity,disposition,accepted_scope,authority_ceiling,
publication_requirements,intent_body_sha256
```

Its version is `plamen.program_facts_g3_00_stdlib_crosscheck_canonical_intent.v4`;
ID matches `^pfg3xci-[0-9a-f]{32}$`; `transport_contract` is
`R2_ARM_BOUND_MONOTONIC_ATTEMPTS_NO_EQUALITY_ADOPTION`; target absence,
same-volume mapping, protected-namespace state, and completion-last chronology
exist only in edge-specific arms/completions and are rederived; implementation
preference never becomes admission evidence; disposition is
`FRESH_V4_INTENT_PERMITS_R2_CANONICAL_CONSTRUCTION`; and scope is
`["CREATE_DURABLE_V4_CANONICAL_INTENT","PERMIT_R2_CREATE_ONLY_V3_CANONICAL_COPY"]`.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_canonical_intent.v4.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","intent_id","acceptance_v4","candidate_source","canonical_target_plan","transport_contract","predecessor_principals","canonical_adopter","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","intent_body_sha256"],
  "properties":{"schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_canonical_intent.v4"},"intent_id":{"type":"string","pattern":"^pfg3xci-[0-9a-f]{32}$"},"acceptance_v4":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"candidate_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"canonical_target_plan":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v3.py","expected_size_bytes":196712,"expected_sha256":"ccb80f957c702619c2dc9d7c7f689ea5b86dc4074efcfd16c212e31d82fbe89f"}},"transport_contract":{"const":"R2_ARM_BOUND_MONOTONIC_ATTEMPTS_NO_EQUALITY_ADOPTION"},"predecessor_principals":{"type":"array","minItems":14,"maxItems":14,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"}},"canonical_adopter":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"independence":{"const":{"all_fifteen_principals_pairwise_distinct":true,"canonical_adopter_separate":true,"no_self_adoption":true,"predecessor_principals_preserved":true}},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"disposition":{"const":"FRESH_V4_INTENT_PERMITS_R2_CANONICAL_CONSTRUCTION"},"accepted_scope":{"const":["CREATE_DURABLE_V4_CANONICAL_INTENT","PERMIT_R2_CREATE_ONLY_V3_CANONICAL_COPY"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"intent_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}
}
```

Adoption receipt v4 is recursively closed with fields:

```text
schema_version,receipt_id,acceptance_v4,canonical_intent_v4,repaired_source,
canonical_source_v3,transport_evidence,copy_outcome,predecessor_principals,
canonical_adopter,checks,independence,part_0_genericity,disposition,
accepted_scope,authority_ceiling,publication_requirements,receipt_body_sha256
```

Its version is `plamen.program_facts_g3_00_stdlib_crosscheck_adoption_receipt.v4`;
ID matches `^pfg3xar-[0-9a-f]{32}$`; `transport_evidence` contains the exact edge-
13 attempt ordinal, arm, completion, and the single canonical enabling completion
grade. Validators reopen those records and rederive source/final byte equality,
pathless identity, same volume, protected-root threat boundary, target-absence
chronology, the complete namespace-poststate preimage/digest, and completion-last
ordering. The receipt contains no
operation-history fields. Checks are exactly
`["G3X-AR01-V4-ACCEPTANCE","G3X-AR02-FRESH-V4-INTENT","G3X-AR03-SOURCE-STABLE","G3X-AR04-R2-ARM-AND-ENABLING-COMPLETION","G3X-AR05-DIRECT-BYTE-EQUALITY","G3X-AR06-PATHLESS-IDENTITY-JOIN","G3X-AR07-PROTECTED-POSTSTATE-BOUNDARY","G3X-AR08-NO-EQUALITY-ADOPTION-OR-BACKFILL","G3X-AR09-ADOPTER-INDEPENDENCE","G3X-AR10-NO-ACTIVATION-AUTHORITY"]`;
`copy_outcome` is `R2_ARM_BOUND_CANONICAL_BYTES_CONSTRUCTED`;
disposition is `CANONICAL_V3_COPY_CONSTRUCTED_BY_V4_CHAIN_NOT_ADMITTED_NOT_INSTALLED`;
and scope is `["CREATE_BYTE_IDENTICAL_CANONICAL_V3_COPY","WRITE_CANONICAL_CONSTRUCTION_RECEIPT_V4"]`.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_adoption_receipt.v4.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","receipt_id","acceptance_v4","canonical_intent_v4","repaired_source","canonical_source_v3","transport_evidence","copy_outcome","predecessor_principals","canonical_adopter","checks","independence","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","receipt_body_sha256"],
  "properties":{"schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_adoption_receipt.v4"},"receipt_id":{"type":"string","pattern":"^pfg3xar-[0-9a-f]{32}$"},"acceptance_v4":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"canonical_intent_v4":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"repaired_source":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"canonical_source_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"transport_evidence":{"type":"object","additionalProperties":false,"required":["attempt_ordinal","publish_arm","completion","completion_grade"],"properties":{"attempt_ordinal":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/z20"},"publish_arm":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"completion":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/file_identity"},"completion_grade":{"const":"PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION"}}},"copy_outcome":{"const":"R2_ARM_BOUND_CANONICAL_BYTES_CONSTRUCTED"},"predecessor_principals":{"type":"array","minItems":14,"maxItems":14,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"}},"canonical_adopter":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"checks":{"const":["G3X-AR01-V4-ACCEPTANCE","G3X-AR02-FRESH-V4-INTENT","G3X-AR03-SOURCE-STABLE","G3X-AR04-R2-ARM-AND-ENABLING-COMPLETION","G3X-AR05-DIRECT-BYTE-EQUALITY","G3X-AR06-PATHLESS-IDENTITY-JOIN","G3X-AR07-PROTECTED-POSTSTATE-BOUNDARY","G3X-AR08-NO-EQUALITY-ADOPTION-OR-BACKFILL","G3X-AR09-ADOPTER-INDEPENDENCE","G3X-AR10-NO-ACTIVATION-AUTHORITY"]},"independence":{"const":{"all_fifteen_principals_pairwise_distinct":true,"canonical_adopter_separate":true,"no_self_adoption":true,"predecessor_principals_preserved":true}},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"disposition":{"const":"CANONICAL_V3_COPY_CONSTRUCTED_BY_V4_CHAIN_NOT_ADMITTED_NOT_INSTALLED"},"accepted_scope":{"const":["CREATE_BYTE_IDENTICAL_CANONICAL_V3_COPY","WRITE_CANONICAL_CONSTRUCTION_RECEIPT_V4"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"receipt_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}
}
```

Only after a complete valid receipt and entire reopened chain may the independent
marker author publish edge 15. Marker v4 is recursively closed with fields:

```text
schema_version,marker_id,acceptance_v4,canonical_intent_v4,canonical_source_v3,
adoption_receipt_v4,adoption_receipt_id,adoption_receipt_body_sha256,
canonical_adopter,marker_author,validated_transport_chain,independence,construction_state,
part_0_genericity,disposition,accepted_scope,authority_ceiling,
publication_requirements,marker_body_sha256
```

Its version is `plamen.program_facts_g3_00_stdlib_crosscheck_adoption_marker.v4`;
ID matches `^pfg3xam-[0-9a-f]{32}$`; receipt ID/body values equal the parsed
receipt; every fresh predecessor uses an exact arm-bound enabling r2 reference;
the validator reopens the attempt, arm, completion, and final rather than
trusting creator-history booleans, and reconstructs every namespace-poststate
preimage member before recomputing its digest; all 16 principal
IDs are pairwise distinct; `construction_state` is
`VALID_V4_RECEIPT_COMMIT_READ_ONLY_MARKER_CONTINUATION`; disposition is
`CANONICAL_V3_CONSTRUCTION_RECORDED_BY_V4_CHAIN_NOT_ADMITTED_NOT_ACTIVE`; and
scope is `["INDEPENDENTLY_VALIDATE_CANONICAL_CONSTRUCTION_RECEIPT_V4","WRITE_CANONICAL_CONSTRUCTION_MARKER_V4"]`.
The marker is the sole leaf. It grants no active selection.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_adoption_marker.v4.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","marker_id","acceptance_v4","canonical_intent_v4","canonical_source_v3","adoption_receipt_v4","adoption_receipt_id","adoption_receipt_body_sha256","canonical_adopter","marker_author","validated_transport_chain","independence","construction_state","part_0_genericity","disposition","accepted_scope","authority_ceiling","publication_requirements","marker_body_sha256"],
  "properties":{"schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_adoption_marker.v4"},"marker_id":{"type":"string","pattern":"^pfg3xam-[0-9a-f]{32}$"},"acceptance_v4":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"canonical_intent_v4":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"canonical_source_v3":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"adoption_receipt_v4":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"},"adoption_receipt_id":{"type":"string","pattern":"^pfg3xar-[0-9a-f]{32}$"},"adoption_receipt_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"},"canonical_adopter":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"marker_author":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/principal"},"validated_transport_chain":{"type":"object","additionalProperties":false,"required":["canonical_source_grade","receipt_grade","revalidated_refs"],"properties":{"canonical_source_grade":{"const":"PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION"},"receipt_grade":{"const":"PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION"},"revalidated_refs":{"type":"array","minItems":4,"maxItems":4,"uniqueItems":true,"items":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/published_ref"}}}},"independence":{"const":{"all_receipt_principals_preserved":true,"all_sixteen_principals_pairwise_distinct":true,"marker_author_separate":true,"no_self_certification":true}},"construction_state":{"const":"VALID_V4_RECEIPT_COMMIT_READ_ONLY_MARKER_CONTINUATION"},"part_0_genericity":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/part0"},"disposition":{"const":"CANONICAL_V3_CONSTRUCTION_RECORDED_BY_V4_CHAIN_NOT_ADMITTED_NOT_ACTIVE"},"accepted_scope":{"const":["INDEPENDENTLY_VALIDATE_CANONICAL_CONSTRUCTION_RECEIPT_V4","WRITE_CANONICAL_CONSTRUCTION_MARKER_V4"]},"authority_ceiling":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/authority"},"publication_requirements":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/publication_requirements"},"marker_body_sha256":{"$ref":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_v3_recovery_common.v1.schema.json#/$defs/hex64"}}
}
```

## 13. Exact acyclic order and stop boundaries

The mechanically authoritative edge dependency vector, indexed 1 through 15,
is exactly:

```text
[[],[1],[2],[3],[3,4],[5],[6],[6,7],[6,7,8],[9],[10],[11],[12],[11,12,13],[11,12,13,14]]
```

Every referenced ordinal is strictly smaller than its consumer ordinal; Kahn's
algorithm visits exactly `[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]`. Attempt,
arm, completion, and debt records point only within their own edge/ordinal or to
that edge's declared predecessors. Immutable section-0 inputs are roots, not
graph vertices; there is no execution-attestation root.

The only valid order is:

```text
accepted valid predecessors + preserved terminal v1/v2 debt
this contract -> independent recovery review
                         |
                         v
             v2 structural-debt observation (read-only, no v2 rerun)
                         |
                         v
        recovery fixture suite -> RED wrapper -> RED evidence
                         |
                         v
                 repaired binding v3
                         |
                         v
                  GREEN wrapper v3
                         |
            exact immutable suite + repaired source
                         |
                         v
                  GREEN evidence v3
                         |
                         v
                   source review v3
                         |
                         v
                       handoff v4
                         |
                         v
                    acceptance v4
                         |
                         v
 canonical intent v4 -> canonical source v3 -> adoption receipt v4
                                                   |
                                                   v
                                          adoption marker v4
```

Every arrow to a fresh artifact is a join to final identity, attempt ordinal,
durable arm, enabling completion grade, and completion identity. No artifact
embeds itself or a successor. The malformed/failed v1/v2 artifacts have
observation-only dashed provenance; they have no enabling edge. Implementation
source, runtime, executable, return, and syscall history are absent from the
authority graph.

Each edge owner stops after the exact operation assigned in sections 4 and 13.
No principal may combine a discriminator with the artifact it discriminates.
No publication failure degrades into successor permission. Terminal debt is
flagged for external human review without halting unrelated work.

## 14. Authority ceiling and Part-0 genericity

Every governed JSON contains exactly this 32-member object:

```json
{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"execution_trace_attestation":false,"finding":false,"historical_primitive_proof":false,"host_compromise_tolerance":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}
```

All 32 flags are false. Fixture execution is not runtime, provider, parity,
process capture, audit, replay, or finding authority. Transport evidence does
not attest an execution trace, historical primitive, or compromised host.
Source review and candidate
acceptance are not admission. Canonical construction and its marker are not
promotion, installation, active-head selection, packaging, release, commit,
push, clean certification, consumer use, or cutover.

Every governed JSON also contains exactly:

```json
{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}
```

The fixtures and wrapper contain only generic bytes, filesystem states, JSON
identities, occurrence directions, coverage atoms, dispositions, failure seams,
and the accepted identity/count regression. They MUST contain no ecosystem,
language, provider, protocol, contract, instruction, vulnerability, expected-
finding, or protocol-answer hint. File paths, case IDs, and governance labels
are control identifiers, not protocol names. The current 12-subject regression
cannot be mined for domain-specific guidance.

## 15. Mandatory validation and terminal condition

Before every edge, an independent validator MUST:

1. derive the exact 48 static paths and `48 + 5 * SUM(A[i])` current-prefix
   paths without scanning; reject every non-formula branch path;
2. stable-read every immediate predecessor's final, arm, and enabling completion
   identities and validate its attempt ordinal;
3. for JSON, validate strict CF, duplicate-key rejection, exact local Draft-
   2020-12 schema, ID/body formulas, and all cross-field projections;
4. validate the trusted-driver/non-host-compromise threat model, protected root,
   exclusive lease, parent/volume identity, durable pre-materialization arm,
   stage/final pathless identity, exact bytes, link count, stage absence, every
   closed normalized namespace-poststate preimage join and recomputed digest,
   completion-last rule, one canonical cross-history completion byte string, and
   exact reconciliation eligibility. For Windows, reject every volume serial not
   exactly the independently rederived 16-lowercase-hex encoding of the native
   uint64 and reject any decimal, uppercase, variable-width, truncated, or
   narrowed form before comparing the parent/stage/target-parent join; preferred platform
   primitives remain review/test inputs with zero admission authority;
5. reject final overwrite or deletion, direct final writes, unvalidated aliases,
   equality adoption, silent backfill, self-certification, orphan successors,
   and every terminal v1/v2 artifact as an enabling predecessor; permit only the
   explicit same-object/two-link private stage-alias reconciliation;
6. enforce the contiguous Z20 prefix, exact-prefix append rule, formula-valid
   debt-before-advance, the single canonical enabling grade, exact case/check orders, counts,
   semantic digests, roles, cumulative
   principal separation, Part-0, scopes, dispositions, and 32 false flags; and
7. permit only the immediate next operation, then stop at the next independent
   boundary.

Artifact existence, schema validity, content equality, a command digest, zero
exit, transport completion, or a majority vote is never sufficient alone.
Unsupported host capability fails before an attempt path is touched. An exact
prefix of the one already determined cross-history canonical byte string may
append its unique missing suffix. A stable non-prefix mismatch, invalid threat
boundary, collision, unexpected alias/link state, or orphan is never repaired by
equality: it either becomes formula-valid nonenabling debt and advances while the
final is absent, or remains final-present terminal debt with no advance.

This document stops at definition. Its author MUST NOT create or execute any
edge, lease, attempt, arm, completion, debt, fixture, observation, binding,
wrapper, evidence, review, handoff,
acceptance, intent, canonical source, receipt, or marker. It MUST NOT run the v2
or v3 command. Until an independently valid edge-1 review exists, the state is
`CONTRACT_ONLY_PENDING_FRESH_INDEPENDENT_V3_R2_RECOVERY_REVIEW`; all authority flags are
false, v1/v2 debt remains terminal, and no successor operation is authorized.
